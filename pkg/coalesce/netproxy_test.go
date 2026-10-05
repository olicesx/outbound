package coalesce

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
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

// tlsCloseNotifyPair builds the fae1e14 client stack (coalescer below a TLS
// conn wrapped in an UnderlyingConnForwarder below a FlushConn) against an
// in-test TLS server, and reports what the server's socket observed after the
// client half-closed: 21 (0x15, TLS alert record) means a close_notify
// arrived, -1 means a raw TCP FIN with no alert.
func tlsCloseNotifyPair(t *testing.T) (*FlushConn, <-chan int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	observed := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			observed <- -2
			return
		}
		defer c.Close()
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{tlsCloseNotifySelfSigned(t)}})
		if err := tc.Handshake(); err != nil {
			observed <- -3
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if n > 0 {
			observed <- int(buf[0])
			return
		}
		if err != nil {
			observed <- -1
			return
		}
		observed <- -4
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
	return NewFlushConn(fwd, co), observed
}

// TestFlushConnCloseWriteSendsCloseNotifyThroughForwarder pins the relay
// half-close contract of the fae1e14 TLS stack: CloseWrite must reach
// tls.Conn.CloseWrite so the peer receives a close_notify alert, not a bare
// TCP FIN. Before the forwarder learned to forward CloseWrite,
// ForwardCloseWrite peeled straight to the forwarder's raw socket and the
// record layer's alert was never sent; a TLS server saw EOF without a
// graceful shutdown record.
func TestFlushConnCloseWriteSendsCloseNotifyThroughForwarder(t *testing.T) {
	fc, observed := tlsCloseNotifyPair(t)
	if err := fc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	// The alert record type depends on the negotiated version: TLS 1.2 sends
	// it as a plaintext alert record (21, 0x15), TLS 1.3 wraps the encrypted
	// close_notify in an application_data record (23, 0x17). Both prove the
	// record layer participated; only -1 (a bare TCP FIN with no record at
	// all) is the regression.
	if got := <-observed; got != 21 && got != 23 {
		t.Fatalf("server observed first post-close byte = %d, want 21 (TLS 1.2 alert) or 23 (TLS 1.3 app-data close_notify); -1 would mean a bare FIN", got)
	}
}
