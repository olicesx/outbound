package shadowsocks_stream

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
)

// obfsStub stands in for transport/shadowsocksr/obfs.Conn: it records the
// cipher and address length handed down by the shadowsocks stream layer.
type obfsStub struct {
	netproxy.Conn
	cipher  *ciphers.StreamCipher
	addrLen int
}

func (o *obfsStub) SetCipher(cipher *ciphers.StreamCipher) { o.cipher = cipher }
func (o *obfsStub) SetAddrLen(addrLen int)                 { o.addrLen = addrLen }

type discardConn struct{ net.Conn }

func (discardConn) Read(p []byte) (int, error)      { return 0, io.EOF }
func (discardConn) Write(p []byte) (int, error)     { return len(p), nil }
func (discardConn) Close() error                    { return nil }
func (discardConn) SetDeadline(time.Time) error     { return nil }
func (discardConn) SetReadDeadline(time.Time) error { return nil }
func (discardConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func newStubChain(t *testing.T, wrap bool) (*TcpConn, *obfsStub) {
	t.Helper()
	cipher, err := ciphers.NewStreamCipher("aes-256-cfb", "p@ssw0rd")
	if err != nil {
		t.Fatal(err)
	}
	stub := &obfsStub{Conn: discardConn{}}
	var under netproxy.Conn = stub
	if wrap {
		under = netproxy.NewBufferedReaderConn(stub, 0)
	}
	return NewTcpConn(under, cipher), stub
}

func TestSSRObfsReceivesCipherWithoutWrapper(t *testing.T) {
	conn, stub := newStubChain(t, false)
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if stub.cipher == nil {
		t.Fatal("obfs conn did not receive the cipher")
	}
	if stub.addrLen != len("hello") {
		t.Fatalf("addrLen = %d, want %d", stub.addrLen, len("hello"))
	}
}

func TestSSRObfsReceivesCipherThroughBufferedReaderConn(t *testing.T) {
	conn, stub := newStubChain(t, true)
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if stub.cipher == nil {
		t.Fatal("obfs conn behind BufferedReaderConn did not receive the cipher")
	}
	if stub.addrLen != len("hello") {
		t.Fatalf("addrLen = %d, want %d", stub.addrLen, len("hello"))
	}
}
