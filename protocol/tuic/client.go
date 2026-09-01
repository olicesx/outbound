package tuic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/olicesx/quic-go"
)

const Ver5 = 0x5

// uniStreamReadIdleTimeout bounds how long a server-opened uni stream may
// stall before the relay goroutine gives up. Each uni stream carries exactly
// one packet command, so this only fires on a wedged or hostile peer; without
// it such streams would pin uni-stream semaphore slots forever.
const uniStreamReadIdleTimeout = 30 * time.Second

type ClientOption struct {
	TlsConfig             *tls.Config
	QuicConfig            *quic.Config
	Uuid                  [16]byte
	Password              string
	UdpRelayMode          common.UdpRelayMode
	MaxUdpRelayPacketSize int
	CongestionController  string
	ReduceRtt             bool
	// CWND carries the brutal controller's target bandwidth (bytes per
	// second); ignored by other controllers.
	CWND uint64
}

type clientImpl struct {
	*ClientOption
	udp bool

	underConn net.PacketConn
	quicConn  quic.Connection
	connMutex sync.Mutex

	// closed is read without connMutex on the per-dial fast path and set
	// under it in forceClose; atomicity keeps those entry checks race-free.
	closed atomic.Bool

	udpIncomingPacketsMap sync.Map

	streamSem chan struct{}

	onClose func()
}

func (t *clientImpl) acquireUniStreamSlot(ctx context.Context) error {
	if t.streamSem == nil {
		return nil
	}
	select {
	case t.streamSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *clientImpl) releaseUniStreamSlot() {
	if t.streamSem == nil {
		return
	}
	<-t.streamSem
}

func (t *clientImpl) getQuicConn(ctx context.Context, dialer netproxy.Dialer, dialFn common.DialFunc) (quic.Connection, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	return t.getQuicConnLocked(ctx, dialer, dialFn)
}

func (t *clientImpl) getQuicConnLocked(ctx context.Context, dialer netproxy.Dialer, dialFn common.DialFunc) (quic.Connection, error) {
	if t.quicConn != nil {
		return t.quicConn, nil
	}
	transport, addr, err := dialFn(ctx, dialer)
	if err != nil {
		return nil, err
	}
	var quicConn quic.Connection
	if t.ReduceRtt {
		quicConn, err = transport.DialEarly(ctx, addr, t.TlsConfig, t.QuicConfig)
	} else {
		quicConn, err = transport.Dial(ctx, addr, t.TlsConfig, t.QuicConfig)
	}
	if err != nil {
		_ = transport.Close()
		_ = transport.Conn.Close()
		return nil, err
	}

	common.SetCongestionController(quicConn, t.CongestionController, t.CWND)

	if err = t.sendAuthentication(quicConn); err != nil {
		_ = quicConn.CloseWithError(ProtocolError, err.Error())
		_ = transport.Close()
		_ = transport.Conn.Close()
		return nil, err
	}

	if t.udp && t.UdpRelayMode == common.QUIC {
		go func() {
			_ = t.handleUniStream(quicConn)
		}()
	}
	go func() {
		_ = t.handleMessage(quicConn) // always handleMessage because tuicV5 using datagram to send the Heartbeat
	}()
	t.underConn = transport.Conn

	t.quicConn = quicConn
	return quicConn, nil
}

func (t *clientImpl) sendAuthentication(quicConn quic.Connection) (err error) {
	// The caller holds connMutex until authentication succeeds and owns cleanup
	// on failure. Calling deferQuicConn here would re-enter forceClose and
	// deadlock on that mutex.
	stream, err := quicConn.OpenUniStream()
	if err != nil {
		return err
	}
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	token, err := GenToken(quicConn.ConnectionState(), t.Uuid, t.Password)
	if err != nil {
		return err
	}
	err = NewAuthenticate(t.Uuid, token, Ver5).WriteTo(buf)
	if err != nil {
		return err
	}
	_, err = buf.WriteTo(stream)
	if err != nil {
		return err
	}
	err = stream.Close()
	if err != nil {
		return
	}
	return nil
}

func (t *clientImpl) handleUniStream(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	for {
		var stream quic.ReceiveStream
		stream, err = quicConn.AcceptUniStream(quicConn.Context())
		if err != nil {
			return err
		}
		if err = t.acquireUniStreamSlot(quicConn.Context()); err != nil {
			stream.CancelRead(0)
			return err
		}
		go func(stream quic.ReceiveStream) {
			defer t.releaseUniStreamSlot()
			var err error
			var assocId uint16
			defer func() {
				t.deferQuicConn(quicConn, err)
				if err != nil && assocId != 0 {
					if val, loaded := t.udpIncomingPacketsMap.LoadAndDelete(assocId); loaded {
						_ = val.(*Packets).Close()
					}
				}
				stream.CancelRead(0)
			}()
			// Each uni stream carries exactly one packet command; parse it
			// incrementally instead of wrapping the stream in a fresh
			// bufio.Reader and routing every field through binary.Read.
			// A non-Packet command is a spec violation: readPacketFromStream
			// errors and deferQuicConn forceCloses the tunnel.
			_ = stream.SetReadDeadline(time.Now().Add(uniStreamReadIdleTimeout))
			var packet *Packet
			packet, err = readPacketFromStream(stream)
			if err != nil {
				var nErr net.Error
				if errors.As(err, &nErr) && nErr.Timeout() {
					// The stream stalled past the idle timeout. Reclaim the
					// slot without tearing down the tunnel: treat it like a
					// benign dropped stream (CancelRead runs in the defer),
					// not like a protocol violation.
					err = nil
				}
				return
			}
			if t.udp && t.UdpRelayMode == common.QUIC {
				assocId = packet.ASSOC_ID
				if val, ok := t.udpIncomingPacketsMap.Load(assocId); ok {
					packets := val.(*Packets)
					packets.PushBack(packet)
					return
				}
			}
			packet.releaseData()
		}(stream)
	}
}

func (t *clientImpl) handleMessage(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	for {
		// Use context.Background() instead of fixed timeout
		// QUIC's keepalive mechanism will handle connection health
		message, err := quicConn.ReceiveDatagram(context.Background())
		if err != nil {
			if outbounderrors.IsTemporaryError(err) {
				// Some temporary errors (notably stateless reset) are
				// delivered after the datagram queue is already closed, so
				// Receive returns immediately from then on. Exit via the
				// connection context instead of spinning in a tight loop.
				if ctxErr := quicConn.Context().Err(); ctxErr != nil {
					return ctxErr
				}
				continue
			}
			return err
		}
		// processDatagram copies everything it keeps (packet DATA is
		// copied by readPacketFromMessage), so the datagram buffer can be
		// returned to the pool immediately after processing.
		t.processDatagram(quicConn, message)
		quicConn.ReleaseDatagram(message)
	}
}

func (t *clientImpl) processDatagram(quicConn quic.Connection, message []byte) {
	var err error
	var assocId uint16
	defer func() {
		t.deferQuicConn(quicConn, err)
		if err != nil && assocId != 0 {
			if val, loaded := t.udpIncomingPacketsMap.LoadAndDelete(assocId); loaded {
				_ = val.(*Packets).Close()
			}
		}
	}()
	if len(message) < 2 {
		return
	}
	switch CommandType(message[1]) {
	case PacketType:
		packet, parseErr := readPacketFromMessage(message)
		if parseErr != nil {
			err = parseErr
			return
		}
		if t.udp && t.UdpRelayMode == common.NATIVE {
			assocId = packet.ASSOC_ID
			if val, ok := t.udpIncomingPacketsMap.Load(assocId); ok {
				val.(*Packets).PushBack(packet)
				return
			}
		}
		// Dropped (no matching association / not datagram mode): return the
		// pool-backed DATA so the buffer is not leaked.
		packet.releaseData()
	case HeartbeatType:
		// Fixed 2-byte command (VER+TYPE); no further bytes to consume.
	}
}

func (t *clientImpl) deferQuicConn(quicConn quic.Connection, err error) {
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		return
	}
	// A closed QUIC connection can surface as a temporary net.Error
	// (stateless reset) or context.Canceled. Those must still retire the
	// shared tunnel; otherwise getQuicConn keeps handing out the dead conn.
	if quicConn != nil && quicConn.Context().Err() != nil {
		t.forceClose(quicConn, err)
		return
	}
	// Only close connection on non-temporary errors. Stream exhaustion is a
	// per-attempt condition: quic-go reports it as *quic.StreamLimitReachedError
	// ("too many open streams"), which IsStreamExhausted matches, so the shared
	// tunnel survives and callers fall back instead of tearing it down.
	if err != nil &&
		!outbounderrors.IsTemporaryError(err) &&
		!outbounderrors.IsStreamExhausted(err) {
		t.forceClose(quicConn, err)
	}
}

func (t *clientImpl) forceClose(quicConn quic.Connection, err error) {
	t.connMutex.Lock()
	if t.closed.Load() {
		t.connMutex.Unlock()
		return
	}
	t.closed.Store(true)
	if t.onClose != nil {
		go t.onClose()
		t.onClose = nil
	}
	t.connMutex.Unlock()
	// Tear the association queues down immediately: polling ReadFrom
	// callers must not stay blocked in PopFrontBlock for the whole 10s
	// grace period after the transport is already dead. The QUIC and
	// underlay closes below still get their grace period.
	t.udpIncomingPacketsMap.Range(func(key, value any) bool {
		_ = value.(*Packets).Close()
		t.udpIncomingPacketsMap.Delete(key)
		return true
	})
	// Give 10s for closing.
	time.AfterFunc(10*time.Second, func() {
		t.connMutex.Lock()
		defer t.connMutex.Unlock()
		if quicConn == nil {
			quicConn = t.quicConn
		}
		if quicConn != nil {
			if quicConn == t.quicConn {
				t.quicConn = nil
			}
		}
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		if quicConn != nil {
			_ = quicConn.CloseWithError(ProtocolError, errStr)
		}
		if t.underConn != nil {
			_ = t.underConn.Close()
			t.underConn = nil
		}
	})
}

func (t *clientImpl) Close() error {
	t.forceClose(nil, common.ErrClientClosed)
	return nil
}

func tuicContextCause(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return context.Canceled
}

func checkImmediateTUICConnectFailure(ctx context.Context, quicConn quic.Connection, stream quic.Stream) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-quicConn.Context().Done():
		return tuicContextCause(quicConn.Context())
	case <-stream.Context().Done():
		return tuicContextCause(stream.Context())
	default:
		return nil
	}
}

func (t *clientImpl) DialContextWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (netproxy.Conn, error) {
	if t.closed.Load() {
		return nil, common.ErrClientClosed
	}
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		return nil, err
	}
	stream, err := func() (stream net.Conn, err error) {
		defer func() {
			t.deferQuicConn(quicConn, err)
		}()
		connect := NewConnect(NewAddress(metadata), Ver5)
		buf := pool.Get(connect.BytesLen())
		defer buf.Put()
		n := connect.WriteToBytes(buf)
		if n != len(buf) {
			return nil, fmt.Errorf("n != len(buf)")
		}
		quicStream, err := quicConn.OpenStream()
		if err != nil {
			return nil, err
		}
		if _, err = quicStream.Write(buf); err != nil {
			_ = quicStream.Close()
			return nil, err
		}
		if err = checkImmediateTUICConnectFailure(ctx, quicConn, quicStream); err != nil {
			_ = quicStream.Close()
			return nil, err
		}
		stream = common.NewSafeStreamConn(
			quicStream,
			quicConn.LocalAddr(),
			quicConn.RemoteAddr(),
			nil,
		)
		return stream, err
	}()
	if err != nil {
		return nil, err
	}

	return stream, nil
}

func (t *clientImpl) ListenPacketWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (*quicStreamPacketConn, error) {
	if t.closed.Load() {
		return nil, common.ErrClientClosed
	}
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.closed.Load() {
		return nil, common.ErrClientClosed
	}
	quicConn, err := t.getQuicConnLocked(ctx, dialer, dialFn)
	if err != nil {
		return nil, err
	}

	var connId uint16
	incomingPackets := NewPackets()
	for {
		connId = uint16(fastrand.Intn(0xFFFF))
		_, loaded := t.udpIncomingPacketsMap.LoadOrStore(connId, incomingPackets)
		if !loaded {
			break
		}
	}
	pc := &quicStreamPacketConn{
		connId:                connId,
		quicConn:              quicConn,
		incomingPackets:       incomingPackets,
		udpRelayMode:          t.UdpRelayMode,
		maxUdpRelayPacketSize: t.MaxUdpRelayPacketSize,
		deferQuicConnFn:       t.deferQuicConn,
		closeDeferFn: func() {
			t.udpIncomingPacketsMap.CompareAndDelete(connId, incomingPackets)
		},
	}
	return pc, nil
}

func (t *clientImpl) setOnClose(f func()) {
	t.onClose = f
}
