package shadowsocks_stream

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

// TcpConn the struct that override the netproxy.Conn methods
type TcpConn struct {
	netproxy.Conn
	cipher *ciphers.StreamCipher

	init        bool
	writeBroken bool
	readMutex   sync.Mutex
	writeMutex  sync.Mutex
}

func NewTcpConn(c netproxy.Conn, cipher *ciphers.StreamCipher) *TcpConn {
	return &TcpConn{
		Conn:   c,
		cipher: cipher,
	}
}

func (c *TcpConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if !c.cipher.DecryptInited() {
		buf := b
		if len(buf) < c.cipher.InfoIVLen() {
			buf = pool.Get(c.cipher.InfoIVLen() + len(b))
			defer pool.Put(buf)
		}
		n, err = io.ReadAtLeast(c.Conn, buf, c.cipher.InfoIVLen())
		if err != nil {
			return 0, fmt.Errorf("invalid ivLen:%v, actual length:%v: %w", c.cipher.InfoIVLen(), n, err)
		}
		//log.Println("n1", n)
		iv := buf[:c.cipher.InfoIVLen()]
		if err = c.cipher.InitDecrypt(iv); err != nil {
			return 0, err
		}

		if c.cipher.IV() == nil {
			c.cipher.SetIV(iv)
		}
		if n == c.cipher.InfoIVLen() && len(b) > 0 {
			// The first read may stop exactly at the IV boundary. Returning
			// (0, nil) here violates the io.Reader contract for non-empty
			// buffers (many callers treat it as EOF), so keep reading until
			// at least one payload byte arrives.
			m, rerr := io.ReadAtLeast(c.Conn, buf[n:], 1)
			n += m
			if rerr != nil {
				return 0, rerr
			}
		}
		n = copy(b, buf[c.cipher.InfoIVLen():n])
		c.cipher.Decrypt(b[:n], b[:n])
		//log.Println("n2", n)
	} else {
		n, err = c.Conn.Read(b)
		if err != nil {
			return n, err
		}
		c.cipher.Decrypt(b[:n], b[:n])
	}
	return n, nil
}

func (c *TcpConn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeBroken {
		return 0, net.ErrClosed
	}
	lenToWrite := len(b)
	ivLen := 0
	firstWrite := !c.init
	if !c.cipher.EncryptInited() {
		_, err = c.cipher.InitEncrypt()
		if err != nil {
			return 0, err
		}
	}
	if firstWrite {
		iv := c.cipher.IV()
		buf := pool.Get(len(b) + len(iv))
		defer pool.Put(buf)
		ivLen = len(iv)
		copy(buf, iv)
		copy(buf[ivLen:], b)
		b = buf

		// For SSR obfs.
		if innerConn, ok := c.Conn.(interface {
			SetCipher(cipher *ciphers.StreamCipher)
		}); ok {
			innerConn.SetCipher(c.cipher)
		}
		if innerConn, ok := c.Conn.(interface {
			SetAddrLen(addrLen int)
		}); ok {
			innerConn.SetAddrLen(lenToWrite)
		}
	}
	c.cipher.Encrypt(b[ivLen:], b[ivLen:])
	if _, err = iout.WriteFull(c.Conn, b); err != nil {
		c.writeBroken = true
		return 0, err
	}
	if firstWrite {
		c.init = true
	}
	return lenToWrite, nil
}

func (c *TcpConn) Cipher() *ciphers.StreamCipher {
	return c.cipher
}
