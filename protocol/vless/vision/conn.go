package vision

import (
	"bytes"
	"crypto/subtle"
	gotls "crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"

	"github.com/google/uuid"
	utls "github.com/refraction-networking/utls"
)

var (
	_ io.Writer = (*writeWrapper)(nil)
	_ io.Reader = (*readWrapper)(nil)
	// _ io.ReaderFrom = (*Conn)(nil)
	_ io.WriterTo = (*Conn)(nil)
)

type readWrapper struct {
	directRead bool
	vision     *Conn
}

func (r *readWrapper) Read(p []byte) (n int, err error) {
	if r.directRead {
		// logrus.Println("direct read")
		return r.vision.Conn.Read(p)
	}
	return r.vision.overlayConn.Read(p)
}

type writeWrapper struct {
	writeDirect bool
	vision      *Conn
}

func (w *writeWrapper) Write(p []byte) (int, error) {
	// logrus.Println("write wrapper", "w.writeDirect", w.writeDirect)
	if w.writeDirect {
		return w.vision.Conn.Write(p)
	}
	return w.vision.overlayConn.Write(p)
}

type Conn struct {
	net.Conn                  // underlay conn (net.Conn/net.PacketConn)
	overlayConn netproxy.Conn // (vless.Conn)
	userUUID    []byte

	tlsConn  netproxy.Conn
	input    *bytes.Reader
	rawInput *bytes.Buffer

	needHandshake              bool
	handshakeTimer             *time.Timer
	readRemainingContent       int
	readRemainingPadding       int
	readFilterUUID             bool
	readLastCommand            byte
	writeFilterApplicationData bool
	writer                     *writeWrapper
	reader                     *readWrapper
	toWriteDirect              bool
	toReadDirect               bool

	muWrite sync.Mutex
	muRead  sync.Mutex

	// filterMu guards the TLS-sniffing state machine below. FilterTLS mutates
	// these fields and is invoked from both the read path (under muRead) and
	// the write path (under muWrite); without a dedicated lock the two paths
	// race on the shared state. Acquired only inside FilterTLS/filterSnapshot,
	// never nested with muRead/muWrite, so lock ordering is single-level.
	filterMu             sync.Mutex
	packetsToFilter      int
	isTLS                bool
	isTLS12orAbove       bool
	enableXTLS           bool
	cipher               uint16
	remainingServerHello uint16
}

func (vc *Conn) Read(b []byte) (int, error) {
	vc.muRead.Lock()
	defer vc.muRead.Unlock()
	if vc.toReadDirect {
		return vc.reader.Read(b)
	}
	return vc.read(b)
}

func (vc *Conn) Close() error {
	if vc.handshakeTimer != nil {
		vc.handshakeTimer.Stop()
	}
	return vc.Conn.Close()
}

func (vc *Conn) CloseWrite() error {
	vc.muWrite.Lock()
	defer vc.muWrite.Unlock()
	if vc.toWriteDirect {
		// Direct mode hands the payload to the underlay conn itself (see
		// writeWrapper.Write), so the half-close has to reach that same conn.
		// Asserting *net.TCPConn here never matched: the underlay is the TLS
		// conn's NetConn(), i.e. the record coalescer or a FakeNetConn, so the
		// FIN was silently dropped while the socket stayed open.
		return netproxy.ForwardCloseWrite(vc.Conn)
	}
	return netproxy.ForwardCloseWrite(vc.overlayConn)
}

func isTCPConnUnixConn(conn any) bool {
	if _, ok := conn.(*net.TCPConn); ok {
		return true
	} else if _, ok := conn.(*net.UnixConn); ok {
		return true
	}
	return false
}

// getUnderlayTCPConnUnixConn gets the underlay TCPConn and UnixConn.
// Use it carefully!
func getUnderlayTCPConnUnixConn(conn any) (any, bool) {
	// log.Printf("Type: %T", conn)
	val := reflect.ValueOf(conn)
	for {
		if !val.IsValid() {
			return conn, false
		}
		if val.CanInterface() && isTCPConnUnixConn(val.Interface()) {
			// log.Printf("Type: %T", val.Interface())
			return val.Interface(), true
		}
		switch val.Kind() {
		case reflect.Interface, reflect.Pointer:
			if val.IsNil() {
				return conn, false
			}
			val = val.Elem()
		case reflect.Struct:
			field := val.FieldByName("Conn")
			if !field.IsValid() {
				return conn, false
			}
			val = field
		default:
			return conn, false
		}
	}
}

// WriteTo implements io.WriterTo.
func (vc *Conn) WriteTo(w io.Writer) (n int64, err error) {
	if !vc.reader.directRead {
		b := pool.Get(4096)
		for {
			_n, err := vc.Read(b)
			if err != nil {
				b.Put()
				return n, err
			}
			if _, err = w.Write(b[:_n]); err != nil {
				b.Put()
				return n, err
			}
			n += int64(_n)
			if vc.reader.directRead {
				b.Put()
				break
			}
		}
	}
	// It is safe to get the TCPConn here, because directRead == true.
	conn, _ := getUnderlayTCPConnUnixConn(vc.Conn)
	// w is *sniffing.ConnSniffer.
	// It is safe to get the TCPConn here, because we are downloading something and sniffing is over.
	w_, _ := getUnderlayTCPConnUnixConn(w)
	_n, err := conn.(io.WriterTo).WriteTo(w_.(io.Writer))
	// log.Println("Read", n, _n)
	n += _n
	return n, err
}

func (vc *Conn) read(b []byte) (int, error) {
	var headerScratch []byte
	for {
		if vc.readRemainingContent > 0 {
			n, err := vc.reader.Read(b[:min(len(b), vc.readRemainingContent)])
			vc.readRemainingContent -= n
			vc.FilterTLS(b[:n])
			return n, err
		}
		if vc.readRemainingPadding > 0 {
			n, err := io.CopyN(io.Discard, vc.reader, int64(vc.readRemainingPadding))
			vc.readRemainingPadding -= int(n)
			if err != nil {
				return 0, err
			}
		}
		if vc.toReadDirect {
			return vc.reader.Read(b)
		}

		switch vc.readLastCommand {
		case commandPaddingContinue:
			need := PaddingHeaderLen - len(uuid.Nil)
			if vc.readFilterUUID {
				need = PaddingHeaderLen
			}
			header := b[:min(len(b), need)]
			if len(header) < need {
				if headerScratch == nil {
					headerScratch = make([]byte, PaddingHeaderLen)
				}
				header = headerScratch[:need]
			}
			if _, err := io.ReadFull(vc.reader, header); err != nil {
				return 0, err
			}
			if vc.readFilterUUID {
				vc.readFilterUUID = false
				if subtle.ConstantTimeCompare(vc.userUUID[:], header[:len(uuid.Nil)]) != 1 {
					id, err := uuid.FromBytes(header[:len(uuid.Nil)])
					return 0, fmt.Errorf("XTLS Vision server responded unknown UUID: %s: %w", id.String(), err)
				}
				header = header[len(uuid.Nil):]
			}
			vc.readRemainingPadding = int(binary.BigEndian.Uint16(header[3:]))
			vc.readRemainingContent = int(binary.BigEndian.Uint16(header[1:]))
			vc.readLastCommand = header[0]
			// A frame may contain only padding. Advance without growing the stack.
		case commandPaddingEnd:
			vc.toReadDirect = true
		case commandPaddingDirect:
			n := 0
			needReturn := false
			if vc.input != nil {
				if vc.input.Len() > 0 {
					_n, err := vc.input.Read(b)
					if err != nil {
						return 0, err
					}
					n += _n
				}
				if vc.input.Len() == 0 {
					needReturn = true
					vc.input = nil
				} else { // buffer is full
					return len(b), nil
				}
			}
			if vc.rawInput != nil {
				if vc.rawInput.Len() > 0 {
					_n, err := vc.rawInput.Read(b[n:])
					if err != nil {
						return n + _n, err
					}
					n += _n
				}
				needReturn = true
				if vc.rawInput.Len() == 0 {
					vc.rawInput = nil
				}
			}
			if vc.input == nil && vc.rawInput == nil {
				vc.toReadDirect = true
				vc.reader.directRead = true
			}
			if needReturn {
				return n, nil
			}
			return vc.reader.Read(b)
		default:
			return 0, fmt.Errorf("XTLS Vision read unknown command: %d", vc.readLastCommand)
		}
	}
}

func (vc *Conn) Write(p []byte) (int, error) {
	vc.muWrite.Lock()
	defer vc.muWrite.Unlock()
	// logrus.Println("VISION CONN WRITE", hex.EncodeToString(p), "vc.writeFilterApplicationData", vc.writeFilterApplicationData)
	if vc.writeFilterApplicationData {
		err := vc.write(p)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return vc.writer.Write(p)
}

// flushHandshakeIfNeeded sends an empty-content, long-padded Vision handshake
// frame if the client has not written any payload within handshakeFlushDelay
// (for server-speaks-first TCP protocols), mirroring vless.NewConn's 100ms
// header flush without emitting an unpadded VLESS header on a Vision stream.
func (vc *Conn) flushHandshakeIfNeeded() error {
	vc.muWrite.Lock()
	defer vc.muWrite.Unlock()
	if !vc.needHandshake {
		return nil
	}
	return vc.write(nil)
}

// // ReadFrom implements io.ReaderFrom.
// func (vc *Conn) ReadFrom(r io.Reader) (n int64, err error) {
// 	if !vc.writer.writeDirect {
// 		b := pool.Get(4096)
// 		for {
// 			_n, err := r.Read(b)
// 			if err != nil {
// 				b.Put()
// 				return n, err
// 			}
// 			if _, err = vc.Write(b[:_n]); err != nil {
// 				b.Put()
// 				return n, err
// 			}
// 			n += int64(_n)
// 			if vc.writer.writeDirect {
// 				b.Put()
// 				break
// 			}
// 		}
// 	}
// 	// It is safe to get the TCPConn here, because writeDirect == true.
// 	conn, _ := getUnderlayTCPConnUnixConn(vc.Conn)
//  // Unsafe
// 	r_, _ := getUnderlayTCPConnUnixConn(r)
// 	_n, err := conn.(io.ReaderFrom).ReadFrom(r_.(io.Reader))
// 	// log.Println("Write", n, _n)
// 	n += _n
// 	return n, err
// }

// writePadding encodes one Vision frame ([UUID][command][contentLen][paddingLen][p][padding])
// and writes it to w in a single Write call. Invariant: one Vision frame must
// be emitted with one Write so the TLS transports below emit one TLS record per
// frame instead of iout.MultiWrite splitting frames <= 4096 bytes into three
// records.
func writePadding(w io.Writer, p []byte, command byte, userUUID []byte, longPadding bool) error {
	frame := ApplyPaddingFromPool(p, command, userUUID, longPadding)
	defer frame.Put()
	_, err := iout.WriteFull(w, frame)
	return err
}

func (vc *Conn) write(p []byte) (err error) {
	if vc.needHandshake {
		vc.needHandshake = false
		longPadding := false
		if len(p) == 0 {
			longPadding = true
		} else {
			vc.FilterTLS(p)
			// logrus.Println("isTLS", vc.isTLS)
			longPadding = vc.filterSnapshot().isTLS
		}
		if err = writePadding(vc.writer, p, commandPaddingContinue, vc.userUUID, longPadding); err != nil {
			return err
		}
		if tlsConn, ok := vc.tlsConn.(*gotls.Conn); ok {
			if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
				return ErrNotTLS13
			}
		} else if utlsConn, ok := vc.tlsConn.(*utls.UConn); ok {
			if utlsConn.ConnectionState().Version != utls.VersionTLS13 {
				return ErrNotTLS13
			}
		} else {
			return fmt.Errorf("unsupported tls connection type: %T", vc.tlsConn)
		}
		vc.tlsConn = nil
		return nil
	}

	if vc.writeFilterApplicationData {
		isCompleteAppData := isCompleteAppDataRecords(p)
		p, p2 := ReshapeBytes(p)
		vc.FilterTLS(p)
		if p2 != nil {
			vc.FilterTLS(p2)
		}
		// logrus.Println("isTLS2:", vc.isTLS, len(p), len(p2))
		sn := vc.filterSnapshot()
		if !sn.isTLS {
			// disable XTLS
			//vc.readProcess = false
			vc.writeFilterApplicationData = false
			vc.stopFilteringLocked()
			if err = writePadding(vc.writer, p, commandPaddingEnd, nil, false); err != nil {
				return err
			}
			if p2 != nil {
				_, err = iout.WriteFull(vc.writer, p2)
			}
			return err
		}

		endCommand := commandPaddingEnd
		if sn.enableXTLS {
			endCommand = commandPaddingDirect
		}
		startsWithAppData := func(b []byte) bool {
			return len(b) >= 6 && bytes.Equal(b[:3], tlsApplicationDataStart)
		}
		finishEarlyForLegacyTLS := !sn.isTLS12orAbove && sn.packetsToFilter <= 1

		if p2 == nil {
			switch {
			case isCompleteAppData && startsWithAppData(p):
				vc.toWriteDirect = sn.enableXTLS
				vc.writeFilterApplicationData = false
				err = writePadding(vc.writer, p, endCommand, nil, true)
			case finishEarlyForLegacyTLS:
				vc.writeFilterApplicationData = false
				err = writePadding(vc.writer, p, commandPaddingEnd, nil, sn.isTLS)
			default:
				err = writePadding(vc.writer, p, commandPaddingContinue, nil, sn.isTLS)
			}
		} else {
			switch {
			case isCompleteAppData && startsWithAppData(p):
				vc.toWriteDirect = sn.enableXTLS
				vc.writeFilterApplicationData = false
				if err = writePadding(vc.writer, p, commandPaddingContinue, nil, true); err != nil {
					return err
				}
				err = writePadding(vc.writer, p2, endCommand, nil, startsWithAppData(p2))
			case finishEarlyForLegacyTLS:
				vc.writeFilterApplicationData = false
				if err = writePadding(vc.writer, p, commandPaddingEnd, nil, sn.isTLS); err != nil {
					return err
				}
				_, err = iout.WriteFull(vc.writer, p2)
			default:
				if err = writePadding(vc.writer, p, commandPaddingContinue, nil, sn.isTLS); err != nil {
					return err
				}
				err = writePadding(vc.writer, p2, commandPaddingContinue, nil, sn.isTLS)
			}
		}
		if vc.toWriteDirect {
			vc.writer.writeDirect = true
		}
		return err
	}
	// if vc.toWriteDirect {
	// 	// logrus.Infof("XTLS Vision Direct write, payloadLen=%d", len(p))
	// }
	_, err = vc.writer.Write(p)
	return err
}
