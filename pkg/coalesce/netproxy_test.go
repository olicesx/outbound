package coalesce

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// capabilityConn records which optional capabilities a wrapper reached on the
// conn it wraps.
type capabilityConn struct {
	intrinsic      netproxy.Conn
	closeWrites    int
	localAddr      net.Addr
	remoteAddr     net.Addr
	deadlineCloses bool
}

func (c *capabilityConn) Read([]byte) (int, error)         { return 0, nil }
func (c *capabilityConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *capabilityConn) Close() error                     { return nil }
func (c *capabilityConn) SetDeadline(time.Time) error      { return nil }
func (c *capabilityConn) SetReadDeadline(time.Time) error  { return nil }
func (c *capabilityConn) SetWriteDeadline(time.Time) error { return nil }

func (c *capabilityConn) IntrinsicConn() netproxy.Conn     { return c.intrinsic }
func (c *capabilityConn) CloseWrite() error                { c.closeWrites++; return nil }
func (c *capabilityConn) LocalAddr() net.Addr              { return c.localAddr }
func (c *capabilityConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *capabilityConn) WriteDeadlineClosesSession() bool { return c.deadlineCloses }

var (
	_ netproxy.Conn                  = (*capabilityConn)(nil)
	_ net.Conn                       = (*capabilityConn)(nil)
	_ netproxy.WriteCloser           = (*capabilityConn)(nil)
	_ netproxy.WriteDeadlineBehavior = (*capabilityConn)(nil)
)

// TestFlushConnForwardsWrappedCapabilities is the regression guard for the
// coalescer layer: transport/tls used to hand the *tls.Conn itself to callers,
// so every duck-typed capability has to survive the extra wrapper.
func TestFlushConnForwardsWrappedCapabilities(t *testing.T) {
	target := &capabilityConn{}
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	inner := &capabilityConn{
		intrinsic:      target,
		localAddr:      local,
		remoteAddr:     remote,
		deadlineCloses: true,
	}
	fc := NewFlushConn(inner, New(inner))

	if got := fc.IntrinsicConn(); got != netproxy.Conn(target) {
		t.Fatalf("IntrinsicConn() = %T, want the wrapped conn's intrinsic target %T", got, target)
	}
	if err := fc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite(): %v", err)
	}
	if inner.closeWrites != 1 {
		t.Fatalf("inner CloseWrite calls = %d, want 1", inner.closeWrites)
	}
	if got := fc.LocalAddr(); got != local {
		t.Fatalf("LocalAddr() = %v, want %v", got, local)
	}
	if got := fc.RemoteAddr(); got != remote {
		t.Fatalf("RemoteAddr() = %v, want %v", got, remote)
	}
	if !fc.WriteDeadlineClosesSession() {
		t.Fatal("WriteDeadlineClosesSession() = false, want the wrapped declaration")
	}
}

// TestFlushConnCloseWriteFlushesCoalescedClose guards the flush half of the
// forwarded half-close contract: CloseWrite's close_notify goes through the
// coalescer like any other record, so the forward is only complete once the
// buffer has been pushed (Write behaves the same way).
func TestFlushConnCloseWriteFlushesCoalescedClose(t *testing.T) {
	inner := &capabilityConn{}
	co := New(inner)
	fc := NewFlushConn(inner, co)

	if _, err := co.Write([]byte("close-notify")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if co.Pending() == 0 {
		t.Fatal("expected the alert buffered before CloseWrite")
	}
	if err := fc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if inner.closeWrites != 1 {
		t.Fatalf("inner CloseWrite calls = %d, want 1", inner.closeWrites)
	}
	if got := co.Pending(); got != 0 {
		t.Fatalf("pending after CloseWrite = %d, want the coalescer flushed", got)
	}
}

// bareConn implements only netproxy.Conn (plus the net.Conn address surface),
// so a wrapper over it must fall back to the wrapped conn itself instead of
// inventing an intrinsic target.
type bareConn struct{ netproxy.Conn }

func (*bareConn) Read([]byte) (int, error)         { return 0, nil }
func (*bareConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*bareConn) Close() error                     { return nil }
func (*bareConn) LocalAddr() net.Addr              { return nil }
func (*bareConn) RemoteAddr() net.Addr             { return nil }
func (*bareConn) SetDeadline(time.Time) error      { return nil }
func (*bareConn) SetReadDeadline(time.Time) error  { return nil }
func (*bareConn) SetWriteDeadline(time.Time) error { return nil }

var (
	_ netproxy.Conn = (*bareConn)(nil)
	_ net.Conn      = (*bareConn)(nil)
)

func TestFlushConnIntrinsicConnFallsBackToWrapped(t *testing.T) {
	inner := &bareConn{}
	fc := NewFlushConn(inner, New(inner))

	if got := fc.IntrinsicConn(); got != netproxy.Conn(inner) {
		t.Fatalf("IntrinsicConn() = %T, want the wrapped bareConn itself", got)
	}
	if got := fc.LocalAddr(); got != nil {
		t.Fatalf("LocalAddr() = %v, want nil for a conn without addresses", got)
	}
	if got := fc.RemoteAddr(); got != nil {
		t.Fatalf("RemoteAddr() = %v, want nil for a conn without addresses", got)
	}
	if got := fc.UnderlyingConn(); got != nil {
		t.Fatalf("UnderlyingConn() = %v, want nil for a conn without a raw-socket accessor", got)
	}
	if got := fc.WriteDeadlineClosesSession(); got {
		t.Fatal("WriteDeadlineClosesSession() = true for a conn without the declaration")
	}
}

// tlsCloseNotifySelfSigned mints a throwaway server certificate.
func tlsCloseNotifySelfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// teeConn records every byte read off the socket once the handshake has
// completed. crypto/tls may pre-read records past the handshake into its own
// buffer, so observing on the raw socket would miss exactly those bytes; the
// tee sees them all.
type teeConn struct {
	net.Conn
	handshakeDone *atomic.Bool
	mu            sync.Mutex
	post          []byte
}

func (c *teeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.handshakeDone.Load() {
		c.mu.Lock()
		c.post = append(c.post, p[:n]...)
		c.mu.Unlock()
	}
	return n, err
}

func (c *teeConn) postHandshakeBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.post...)
}

// tlsCloseNotifyPair builds the fae1e14 client stack (coalescer below a TLS
// conn wrapped in an UnderlyingConnForwarder below a FlushConn) against an
// in-test TLS server. The returned channel reports the TLS-layer outcome of
// the server's next Read after the client half-closes; the returned tee
// holds every post-handshake byte that actually arrived on the wire. The
// caller must wait for the extra channel (closed once the server's handshake
// completed) before half-closing, so the alert cannot be swallowed by the
// handshake's own read-ahead.
func tlsCloseNotifyPair(t *testing.T) (*FlushConn, *teeConn, <-chan error, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	tee := &teeConn{handshakeDone: &atomic.Bool{}}
	tlsRead := make(chan error, 1)
	serverReady := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			tlsRead <- err
			return
		}
		defer c.Close()
		tee.Conn = c
		tc := tls.Server(tee, &tls.Config{Certificates: []tls.Certificate{tlsCloseNotifySelfSigned(t)}})
		if err := tc.Handshake(); err != nil {
			tlsRead <- err
			return
		}
		tee.handshakeDone.Store(true)
		close(serverReady)
		_ = tc.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, rerr := tc.Read(make([]byte, 64))
		tlsRead <- rerr
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	tcp := raw.(*net.TCPConn)
	co := New(&netproxy.FakeNetConn{Conn: tcp, LAddr: nil, RAddr: nil})
	tlsConn := tls.Client(co, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := co.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	fwd := netproxy.NewUnderlyingConnForwarder(tlsConn, func() net.Conn { return tcp })
	return NewFlushConn(fwd, co), tee, tlsRead, serverReady
}

// TestFlushConnCloseWriteSendsCloseNotifyThroughForwarder pins the relay
// half-close contract of the fae1e14 TLS stack: CloseWrite must reach
// tls.Conn.CloseWrite so a close_notify record actually goes out on the
// wire, and the peer's TLS layer observes a clean half-close. Before the
// forwarder learned to forward CloseWrite, ForwardCloseWrite peeled
// straight to the forwarder's raw socket and the record layer's alert was
// never sent: a bare FIN, and the peer saw EOF without a graceful shutdown
// record. The tee distinguishes the two even when crypto/tls pre-reads the
// alert into its own buffer.
func TestFlushConnCloseWriteSendsCloseNotifyThroughForwarder(t *testing.T) {
	fc, tee, tlsRead, serverReady := tlsCloseNotifyPair(t)
	// Half-close only after the server's handshake fully drained: an alert
	// racing the handshake can be pre-read into the TLS layer's buffer and
	// would then never appear on the observable wire.
	<-serverReady
	if err := fc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	// A close_notify surfaces to the peer TLS layer as a clean half-close.
	// A bare FIN also reads as EOF there, so the wire-level tee below is
	// the discriminator; this assertion alone only rules out corruption.
	if err := <-tlsRead; !errors.Is(err, io.EOF) {
		t.Fatalf("server TLS layer did not observe a clean half-close: %v", err)
	}
	got := tee.postHandshakeBytes()
	if len(got) == 0 || (got[0] != 21 && got[0] != 23) {
		// 21 (0x15): TLS 1.2 plaintext alert record; 23 (0x17): TLS 1.3
		// close_notify wrapped in an application_data record. An empty tee
		// means no record was sent at all — the bare-FIN regression.
		t.Fatalf("no close_notify record on the wire (first byte = %d, %d bytes recorded); an empty tee is the bare-FIN regression", firstByteOr(got, -1), len(got))
	}
}

func firstByteOr(b []byte, or int) int {
	if len(b) == 0 {
		return or
	}
	return int(b[0])
}
