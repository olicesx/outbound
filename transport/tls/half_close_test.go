package tls_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	tlstransport "github.com/daeuniverse/outbound/transport/tls"
)

type readCountingConn struct {
	net.Conn
	readBytes int
}

func (c *readCountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.readBytes += n
	return n, err
}

func TestDialContextPreservesTLSBufferAndHalfClose(t *testing.T) {
	for _, implementation := range []string{"tls", "utls"} {
		t.Run(implementation, func(t *testing.T) {
			cert, err := selfSignedCert()
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			if err := listener.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			tlsDialer, _, err := tlstransport.NewTls(&dialer.ExtraOption{
				TlsImplementation: implementation,
				UtlsImitate:       "chrome_auto",
				AllowInsecure:     true,
			}, direct.SymmetricDirect, "tls://"+listener.Addr().String()+"?sni=underlay.test")
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				conn netproxy.Conn
				err  error
			}
			dialed := make(chan result, 1)
			go func() {
				conn, err := tlsDialer.DialContext(ctx, "tcp", "underlay.test:443")
				dialed <- result{conn, err}
				close(dialed)
			}()
			defer func() {
				cancel()
				if r := <-dialed; r.conn != nil {
					_ = r.conn.Close()
				}
			}()

			raw, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = raw.Close() }()
			if err := raw.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			wire := &readCountingConn{Conn: raw}
			server := tls.Server(wire, &tls.Config{Certificates: []tls.Certificate{cert}})
			if err := server.HandshakeContext(ctx); err != nil {
				t.Fatalf("server handshake: %v", err)
			}
			r := <-dialed
			if r.err != nil {
				t.Fatalf("dial: %v", r.err)
			}
			conn := r.conn
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if got := netproxy.NewBufferedReaderConn(conn, 0); got != conn {
				t.Fatalf("read buffer wrapper = %T, want original TLS transport", got)
			}
			if _, ok := conn.(net.Conn); !ok {
				t.Fatalf("TLS transport %T lacks net.Conn address methods", conn)
			}
			if _, ok := netproxy.UnwrapTCPConn(conn); !ok {
				t.Fatal("TLS forwarder lost access to the TCP socket")
			}

			if _, err := conn.Write([]byte("x")); err != nil {
				t.Fatalf("client Write: %v", err)
			}
			var buf [1]byte
			if _, err := io.ReadFull(server, buf[:]); err != nil || buf[0] != 'x' {
				t.Fatalf("server Read = %q, %v, want x", buf, err)
			}
			before := wire.readBytes
			if err := netproxy.ForwardCloseWrite(conn); err != nil {
				t.Fatalf("ForwardCloseWrite: %v", err)
			}
			if n, err := server.Read(buf[:]); n != 0 || err != io.EOF {
				t.Fatalf("server Read after half-close = %d, %v, want EOF", n, err)
			}
			// TLS can also report EOF for a bare FIN at a record boundary.
			if wire.readBytes == before {
				t.Fatal("server got EOF without reading a TLS close_notify record")
			}
			if _, err := server.Write([]byte("y")); err != nil {
				t.Fatalf("server Write after close_notify: %v", err)
			}
			if _, err := io.ReadFull(conn, buf[:]); err != nil || buf[0] != 'y' {
				t.Fatalf("client Read after close_notify = %q, %v, want y", buf, err)
			}
		})
	}
}
