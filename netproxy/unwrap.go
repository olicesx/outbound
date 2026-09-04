package netproxy

import "net"

// UnderlyingConnProvider exposes the wrapped inner net.Conn.
// Wrappers that want to participate in transport capability checks
// (for example TCP fast-path / offload) should implement this interface.
type UnderlyingConnProvider interface {
	UnderlyingConn() net.Conn
}

// WriteCloser is the optional half-close surface. dae's relay type-asserts
// the same method; TLS-wrapped conns typically do not implement it.
type WriteCloser interface {
	CloseWrite() error
}

// ForwardCloseWrite half-closes c. Protocol wrappers that implement
// WriteCloser are preferred; otherwise a *net.TCPConn is unwrapped via
// UnderlyingConnProvider. crypto/tls.Conn is not a WriteCloser and is not
// peeled to TCP, so TLS-wrapped chains no-op.
func ForwardCloseWrite(c Conn) error {
	if c == nil {
		return nil
	}
	if wc, ok := c.(WriteCloser); ok {
		return wc.CloseWrite()
	}
	if tcp, ok := UnwrapTCPConn(c); ok {
		return tcp.CloseWrite()
	}
	return nil
}

const unwrapTCPConnMaxDepth = 8

// UnwrapTCPConn resolves a concrete *net.TCPConn from a possibly wrapped
// connection by following UnderlyingConnProvider.
func UnwrapTCPConn(conn any) (*net.TCPConn, bool) {
	return unwrapTCPConnDepth(conn, 0)
}

func unwrapTCPConnDepth(conn any, depth int) (*net.TCPConn, bool) {
	if conn == nil || depth >= unwrapTCPConnMaxDepth {
		return nil, false
	}

	switch c := conn.(type) {
	case *net.TCPConn:
		return c, true
	case UnderlyingConnProvider:
		return unwrapTCPConnDepth(c.UnderlyingConn(), depth+1)
	default:
		return nil, false
	}
}
