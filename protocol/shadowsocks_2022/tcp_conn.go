package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"github.com/samber/oops"
	"lukechampine.com/blake3"
)

const (
	TCPChunkMaxLen = (1 << 16) - 1

	HeaderTypeClientStream = 0
	HeaderTypeServerStream = 1
	MinPaddingLength       = 0
	MaxPaddingLength       = 900

	maxReusableWriteFrameSize = 128 << 10
	tcpHandshakeTimeout       = 30 * time.Second
)

// TCPConn represents a Shadowsocks TCP connection.
// It embeds SS2022Core for shared logic (identity header, cipher cache).
type TCPConn struct {
	*SS2022Core // Embedded core for shared logic

	net.Conn
	addr *socks5.AddressInfo
	sg   *shadowsocks.RandomSaltGenerator

	cipherRead  cipher.AEAD
	cipherWrite cipher.AEAD
	onceRead    bool
	onceWrite   bool
	writeBroken bool
	nonceRead   []byte
	nonceWrite  []byte

	readMutex  sync.Mutex
	writeMutex sync.Mutex

	// Deadline setters must reach the underlay while Read or Write is blocked.
	deadlineMu    sync.Mutex
	readDeadline  tcpDeadline
	writeDeadline tcpDeadline

	// requestSalt is the salt this client sent with its request stream. The
	// response fixed-length header echoes it and SIP022 §3.1.3 requires the
	// client to check the echoed value against the request salt, which binds
	// a response stream to this request. Guarded by saltMu because the first
	// Read and first Write may run on different goroutines.
	requestSalt []byte
	saltMu      sync.RWMutex

	leftToRead    []byte
	indexToRead   int
	readCipherBuf []byte
	writeFrame    []byte

	bloom *disk_bloom.FilterGroup
}

func NewTCPConn(conn net.Conn, core *SS2022Core, sg *shadowsocks.RandomSaltGenerator, addr *socks5.AddressInfo, bloom *disk_bloom.FilterGroup) net.Conn {
	tcpConn := &TCPConn{
		SS2022Core: core,
		Conn:       conn,
		addr:       addr,
		sg:         sg,
		nonceRead:  make([]byte, core.CipherConf().NonceLen),
		nonceWrite: make([]byte, core.CipherConf().NonceLen),
		bloom:      bloom,
	}
	return tcpConn
}

func (c *TCPConn) CloseWrite() error {
	return netproxy.ForwardCloseWrite(c.Conn)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped conn. Embedding the conn interface
// promotes SetWriteDeadline but not this optional method, so without the
// forward a session-closing inner conn (TUIC, hysteria2) would be invisible to
// deadline-arming callers and they would arm a destructive timer believing it
// was an ordinary write deadline.
func (c *TCPConn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.Conn)
}

func (c *TCPConn) Close() error {
	err := c.Conn.Close()

	c.readMutex.Lock()
	c.leftToRead = nil
	c.indexToRead = 0
	c.readCipherBuf = nil
	c.readMutex.Unlock()

	c.writeMutex.Lock()
	c.writeFrame = nil
	c.writeMutex.Unlock()
	return err
}

type tcpDeadline struct {
	caller    time.Time
	handshake time.Time
}

func (d *tcpDeadline) effective(caller time.Time) time.Time {
	if !d.handshake.IsZero() && (caller.IsZero() || d.handshake.Before(caller)) {
		return d.handshake
	}
	return caller
}

func (d *tcpDeadline) setCaller(t time.Time, apply func(time.Time) error) error {
	if err := apply(d.effective(t)); err != nil {
		return err
	}
	d.caller = t
	return nil
}

func (c *TCPConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	read := c.readDeadline.effective(t)
	write := c.writeDeadline.effective(t)
	if read.Equal(write) {
		if err := c.Conn.SetDeadline(read); err != nil {
			return err
		}
		c.readDeadline.caller = t
		c.writeDeadline.caller = t
		return nil
	}
	return errors.Join(
		c.readDeadline.setCaller(t, c.Conn.SetReadDeadline),
		c.writeDeadline.setCaller(t, c.Conn.SetWriteDeadline),
	)
}

func (c *TCPConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.readDeadline.setCaller(t, c.Conn.SetReadDeadline)
}

func (c *TCPConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.writeDeadline.setCaller(t, c.Conn.SetWriteDeadline)
}

// setHandshakeDeadline arms, refreshes, or removes a handshake deadline. Caller
// updates and cleanup use the same lock so cleanup restores the latest deadline.
func (c *TCPConn) setHandshakeDeadline(d *tcpDeadline, t time.Time, apply func(time.Time) error) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	previous := d.effective(d.caller)
	d.handshake = t
	if effective := d.effective(d.caller); !effective.Equal(previous) {
		_ = apply(effective)
	}
}

func encryptedPayloadLen(payloadLen, tagLen int) int {
	if payloadLen <= 0 {
		return 0
	}
	chunks := payloadLen / TCPChunkMaxLen
	if payloadLen%TCPChunkMaxLen > 0 {
		chunks++
	}
	return payloadLen + chunks*(2+tagLen+tagLen)
}

func addrInfoEncodedLen(addr *socks5.AddressInfo) (int, error) {
	if addr == nil {
		return 0, fmt.Errorf("nil address info")
	}
	switch addr.Type {
	case socks5.AddressTypeIPv4:
		if !addr.IP.Is4() {
			return 0, fmt.Errorf("invalid ipv4 address")
		}
		return 1 + 4 + 2, nil
	case socks5.AddressTypeIPv6:
		if !addr.IP.Is6() {
			return 0, fmt.Errorf("invalid ipv6 address")
		}
		return 1 + 16 + 2, nil
	case socks5.AddressTypeDomain:
		if len(addr.Hostname) > 255 {
			return 0, fmt.Errorf("domain name too long: %d", len(addr.Hostname))
		}
		return 1 + 1 + len(addr.Hostname) + 2, nil
	default:
		return 0, fmt.Errorf("unsupported address type: %v", addr.Type)
	}
}

func writeAddrInfoTo(dst []byte, addr *socks5.AddressInfo) (int, error) {
	addrLen, err := addrInfoEncodedLen(addr)
	if err != nil {
		return 0, err
	}
	if len(dst) < addrLen {
		return 0, io.ErrShortBuffer
	}
	dst[0] = byte(addr.Type)
	switch addr.Type {
	case socks5.AddressTypeIPv4:
		ip := addr.IP.AsSlice()
		copy(dst[1:1+4], ip)
		binary.BigEndian.PutUint16(dst[1+4:1+4+2], addr.Port)
		return 1 + 4 + 2, nil
	case socks5.AddressTypeIPv6:
		ip := addr.IP.AsSlice()
		copy(dst[1:1+16], ip)
		binary.BigEndian.PutUint16(dst[1+16:1+16+2], addr.Port)
		return 1 + 16 + 2, nil
	case socks5.AddressTypeDomain:
		domainLen := len(addr.Hostname)
		dst[1] = byte(domainLen)
		copy(dst[2:2+domainLen], addr.Hostname)
		binary.BigEndian.PutUint16(dst[2+domainLen:2+domainLen+2], addr.Port)
		return 1 + 1 + domainLen + 2, nil
	default:
		return 0, fmt.Errorf("unsupported address type: %v", addr.Type)
	}
}

func (c *TCPConn) ensureReadCipherBuf(size int) []byte {
	if cap(c.readCipherBuf) < size {
		c.readCipherBuf = make([]byte, size)
	}
	return c.readCipherBuf[:size]
}

func (c *TCPConn) borrowWriteFrame(size int) []byte {
	if size <= maxReusableWriteFrameSize {
		if cap(c.writeFrame) < size {
			c.writeFrame = make([]byte, size)
		}
		return c.writeFrame[:size]
	}
	return make([]byte, size)
}

func (c *TCPConn) writeIdentityHeaderTo(dst []byte, offset int, salt []byte) (int, error) {
	for i := 0; i < len(c.PSKList())-1; i++ {
		if offset+aes.BlockSize > len(dst) {
			return 0, io.ErrShortBuffer
		}
		identitySubkey := GenerateSubKey(c.PSKList()[i], salt, Shadowsocks2022IdentityHeaderInfo)
		b, err := c.CipherConf().NewBlockCipher(identitySubkey)
		if err != nil {
			PutSubKey(identitySubkey)
			return 0, err
		}
		plaintext := blake3.Sum512(c.PSKList()[i+1])
		b.Encrypt(dst[offset:offset+aes.BlockSize], plaintext[:aes.BlockSize])
		PutSubKey(identitySubkey)
		offset += aes.BlockSize
	}
	return offset, nil
}

func (c *TCPConn) sealPayload(dst []byte, payload []byte) int {
	offset := 0
	var chunkLengthBuf [2]byte
	for i := 0; i < len(payload); i += TCPChunkMaxLen {
		chunkLength := common.Min(TCPChunkMaxLen, len(payload)-i)
		binary.BigEndian.PutUint16(chunkLengthBuf[:], uint16(chunkLength))
		_ = c.cipherWrite.Seal(dst[offset:offset], c.nonceWrite, chunkLengthBuf[:], nil)
		offset += 2 + c.CipherConf().TagLen
		common.BytesIncLittleEndian(c.nonceWrite)
		_ = c.cipherWrite.Seal(dst[offset:offset], c.nonceWrite, payload[i:i+chunkLength], nil)
		offset += chunkLength + c.CipherConf().TagLen
		common.BytesIncLittleEndian(c.nonceWrite)
	}
	return offset
}

func (c *TCPConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if c.indexToRead < len(c.leftToRead) {
		n = copy(b, c.leftToRead[c.indexToRead:])
		c.indexToRead += n
		if c.indexToRead >= len(c.leftToRead) {
			c.leftToRead = nil
			c.indexToRead = 0
		}
		return n, nil
	}

	var payloadLength uint16

	if !c.onceRead {
		c.setHandshakeDeadline(&c.readDeadline, time.Now().Add(tcpHandshakeTimeout), c.Conn.SetReadDeadline)
		defer c.setHandshakeDeadline(&c.readDeadline, time.Time{}, c.Conn.SetReadDeadline)
		var saltBuf [32]byte
		salt := saltBuf[:c.CipherConf().SaltLen]
		n, err = io.ReadFull(c.Conn, salt)
		if err != nil {
			return 0, err
		}
		c.cipherRead, err = CreateCipher(c.UPSK(), salt, c.CipherConf())
		if err != nil {
			return 0, oops.Wrapf(err, "fail to initiate cipher")
		}

		c.setHandshakeDeadline(&c.readDeadline, time.Now().Add(tcpHandshakeTimeout), c.Conn.SetReadDeadline)
		var headerBuf [11 + 32 + 16]byte
		header := headerBuf[:11+c.CipherConf().SaltLen+c.CipherConf().TagLen]
		if _, err := io.ReadFull(c.Conn, header); err != nil {
			return 0, err
		}
		header, err := c.cipherRead.Open(header[:0], c.nonceRead, header, nil)
		if err != nil {
			return 0, protocol.ErrFailAuth
		}
		common.BytesIncLittleEndian(c.nonceRead)
		offset := 0
		typ := uint8(header[offset])
		offset += 1
		timestamp := time.Unix(int64(binary.BigEndian.Uint64(header[offset:offset+8])), 0)
		offset += 8

		if typ != HeaderTypeServerStream {
			return 0, fmt.Errorf("received unexpected header type: %d", typ)
		}

		if err := validateTimestamp(timestamp, time.Now()); err != nil {
			return 0, err
		}

		// SIP022 §3.1.3: the client MUST check the request salt echoed in
		// the response header against the salt it sent, which binds the
		// response stream to this request.
		c.saltMu.RLock()
		sent := c.requestSalt
		matched := len(sent) == c.CipherConf().SaltLen &&
			bytes.Equal(sent, header[offset:offset+c.CipherConf().SaltLen])
		c.saltMu.RUnlock()
		if !matched {
			return 0, protocol.ErrFailAuth
		}

		// Best-effort replay protection fallback for environments that provide bloom.
		if c.bloom != nil {
			if c.bloom.ExistOrAdd(salt) {
				return 0, protocol.ErrReplayAttack
			}
		}

		// Skip request salt
		offset += c.CipherConf().SaltLen

		payloadLength = binary.BigEndian.Uint16(header[offset : offset+2])

		c.onceRead = true
	} else {
		var payloadLengthBuf [2 + 16]byte
		payloadLengthRaw := payloadLengthBuf[:2+c.CipherConf().TagLen]
		if _, err := io.ReadFull(c.Conn, payloadLengthRaw); err != nil {
			return 0, err
		}
		payloadLengthPlain, err := c.cipherRead.Open(payloadLengthRaw[:0], c.nonceRead, payloadLengthRaw, nil)
		if err != nil {
			return 0, protocol.ErrFailAuth
		}
		common.BytesIncLittleEndian(c.nonceRead)

		payloadLength = binary.BigEndian.Uint16(payloadLengthPlain)
	}

	if c.cipherRead == nil {
		return 0, oops.New("cipher is not initialized")
	}

	payload := c.ensureReadCipherBuf(int(payloadLength) + c.CipherConf().TagLen)
	if _, err = io.ReadFull(c.Conn, payload); err != nil {
		return 0, err
	}
	payload, err = c.cipherRead.Open(payload[:0], c.nonceRead, payload, nil)
	if err != nil {
		return 0, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)

	n = copy(b, payload)
	if len(payload) > n {
		c.leftToRead = payload
		c.indexToRead = n
	} else {
		c.leftToRead = nil
		c.indexToRead = 0
	}
	return n, nil
}

func (c *TCPConn) Write(b []byte) (n int, err error) {
	n = len(b)
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeBroken {
		return 0, net.ErrClosed
	}
	if !c.onceWrite {
		// Generate salt
		salt := c.sg.Get()
		defer pool.Put(salt)

		c.saltMu.Lock()
		c.requestSalt = append(c.requestSalt[:0], salt...)
		c.saltMu.Unlock()

		// Setup encryption
		c.cipherWrite, err = CreateCipher(c.UPSK(), salt, c.CipherConf())
		if err != nil {
			return 0, oops.Wrapf(err, "fail to initiate cipher")
		}

		addrLen, err := addrInfoEncodedLen(c.addr)
		if err != nil {
			return 0, oops.Wrapf(err, "fail to calculate address length")
		}

		initialPayloadMaxLength := TCPChunkMaxLen - (addrLen + 2)
		initialPayloadLen := len(b)
		if initialPayloadLen > initialPayloadMaxLength {
			initialPayloadLen = initialPayloadMaxLength
		}
		firstVarHeaderLen := addrLen + 2 + initialPayloadLen
		remainingPayload := b[initialPayloadLen:]
		totalSize := len(salt) +
			(len(c.PSKList())-1)*aes.BlockSize +
			(11 + c.CipherConf().TagLen) +
			(firstVarHeaderLen + c.CipherConf().TagLen) +
			encryptedPayloadLen(len(remainingPayload), c.CipherConf().TagLen)
		frame := c.borrowWriteFrame(totalSize)
		offset := 0
		copy(frame[offset:], salt)
		offset += len(salt)

		offset, err = c.writeIdentityHeaderTo(frame, offset, salt)
		if err != nil {
			return 0, oops.Wrapf(err, "fail to write identity header")
		}

		fixedHeaderOffset := offset
		fixedHeaderPlain := frame[offset : offset+11]
		fixedHeaderPlain[0] = HeaderTypeClientStream
		binary.BigEndian.PutUint64(fixedHeaderPlain[1:9], uint64(time.Now().Unix()))
		binary.BigEndian.PutUint16(fixedHeaderPlain[9:11], uint16(firstVarHeaderLen))
		sealed := c.cipherWrite.Seal(frame[:fixedHeaderOffset], c.nonceWrite, fixedHeaderPlain, nil)
		offset = len(sealed)
		common.BytesIncLittleEndian(c.nonceWrite)

		varHeaderOffset := offset
		varHeaderPlain := frame[offset : offset+firstVarHeaderLen]
		addrWritten, err := writeAddrInfoTo(varHeaderPlain, c.addr)
		if err != nil {
			return 0, oops.Wrapf(err, "fail to encode request address")
		}
		binary.BigEndian.PutUint16(varHeaderPlain[addrWritten:addrWritten+2], 0)
		copy(varHeaderPlain[addrWritten+2:], b[:initialPayloadLen])
		sealed = c.cipherWrite.Seal(frame[:varHeaderOffset], c.nonceWrite, varHeaderPlain, nil)
		offset = len(sealed)
		common.BytesIncLittleEndian(c.nonceWrite)

		offset += c.sealPayload(frame[offset:], remainingPayload)
		c.setHandshakeDeadline(&c.writeDeadline, time.Now().Add(tcpHandshakeTimeout), c.Conn.SetWriteDeadline)
		defer c.setHandshakeDeadline(&c.writeDeadline, time.Time{}, c.Conn.SetWriteDeadline)
		if _, err = iout.WriteFull(c.Conn, frame[:offset]); err != nil {
			c.writeBroken = true
			return 0, err
		}
		c.onceWrite = true
		return n, nil
	}
	if c.cipherWrite == nil {
		return 0, fmt.Errorf("cipher is not initialized")
	}
	frameSize := encryptedPayloadLen(len(b), c.CipherConf().TagLen)
	frame := c.borrowWriteFrame(frameSize)
	offset := c.sealPayload(frame, b)
	if _, err = iout.WriteFull(c.Conn, frame[:offset]); err != nil {
		c.writeBroken = true
		return 0, err
	}
	return n, nil
}
