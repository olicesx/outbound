package shadowsocks_2022

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type tcpTestDialer struct{ underlay netproxy.Conn }

func (d tcpTestDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return d.underlay, nil
}

func dialTCPTestConn(t *testing.T, underlay netproxy.Conn) *TCPConn {
	t.Helper()
	dialer, err := NewDialer(tcpTestDialer{underlay}, protocol.Header{
		ProxyAddress: "proxy.test:443",
		Cipher:       "2022-blake3-aes-128-gcm",
		Password:     base64.StdEncoding.EncodeToString(make([]byte, 16)),
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(context.Background(), "tcp", "target.test:443")
	if err != nil {
		t.Fatal(err)
	}
	return conn.(*TCPConn)
}

func TestTCPDialRetainsTLSForwarder(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	records := tls.Client(client, &tls.Config{ServerName: "proxy.test"})
	underlay := netproxy.NewUnderlyingConnForwarder(records, func() net.Conn { return client })
	conn := dialTCPTestConn(t, underlay)
	defer conn.Close()

	if conn.Conn != underlay {
		t.Fatalf("TCP underlay = %T, want the original TLS forwarder", conn.Conn)
	}
	if conn.LocalAddr() != client.LocalAddr() || conn.RemoteAddr() != client.RemoteAddr() {
		t.Fatal("TCP dial lost the TLS underlay addresses")
	}
}

// exchangeTCPTestHandshake advances the two I/O directions past their initial
// protocol frames so the next calls exercise steady-state chunk I/O.
func exchangeTCPTestHandshake(t *testing.T, conn *TCPConn, peer net.Conn) {
	t.Helper()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatalf("first Write: %v", err)
	}

	conf := conn.CipherConf()
	salt := make([]byte, conf.SaltLen)
	cipher, err := CreateCipher(conn.UPSK(), salt, conf)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, conf.NonceLen)
	header := make([]byte, 11+len(conn.requestSalt))
	header[0] = HeaderTypeServerStream
	binary.BigEndian.PutUint64(header[1:9], uint64(time.Now().Unix()))
	copy(header[9:], conn.requestSalt)
	binary.BigEndian.PutUint16(header[len(header)-2:], 1)
	response := cipher.Seal(salt, nonce, header, nil)
	common.BytesIncLittleEndian(nonce)
	response = cipher.Seal(response, nonce, []byte("x"), nil)
	go func() { _, _ = peer.Write(response) }()
	var buf [1]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil || buf[0] != 'x' {
		t.Fatalf("first Read = %q, %v, want x", buf, err)
	}
}

func startTCPTestRead(conn net.Conn) <-chan error {
	done := make(chan error, 1)
	go func() {
		var buf [1]byte
		_, err := conn.Read(buf[:])
		done <- err
	}()
	return done
}

func startTCPTestWrite(conn net.Conn) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("x"))
		done <- err
	}()
	return done
}

func requireTCPTestTimeout(t *testing.T, operation string, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("%s error = %v, want deadline exceeded", operation, err)
		}
	default:
		t.Errorf("%s is still blocked after its deadline", operation)
	}
}

func TestTCPConnHonorsPresetDeadlines(t *testing.T) {
	for _, stage := range []string{"handshake", "steady state"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, peer := net.Pipe()
				defer peer.Close()
				underlay := &tcpDeadlineRecorder{Conn: client}
				conn := dialTCPTestConn(t, underlay)
				defer conn.Close()
				if stage == "steady state" {
					exchangeTCPTestHandshake(t, conn, peer)
					requireTCPTestDeadlines(t, underlay, time.Time{}, time.Time{})
				}
				if err := conn.SetDeadline(time.Now()); err != nil {
					t.Fatal(err)
				}
				_, _, sets := underlay.snapshot()
				read, write := startTCPTestRead(conn), startTCPTestWrite(conn)
				synctest.Wait()
				requireTCPTestTimeout(t, "Read", read)
				requireTCPTestTimeout(t, "Write", write)
				if _, _, after := underlay.snapshot(); stage == "steady state" && after != sets {
					t.Errorf("steady-state I/O rewrote deadlines %d times", after-sets)
				}
			})
		})
	}
}

type tcpDeadlineRecorder struct {
	net.Conn
	mu    sync.Mutex
	read  time.Time
	write time.Time
	sets  int
}

func (c *tcpDeadlineRecorder) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sets++
	c.read, c.write = t, t
	return c.Conn.SetDeadline(t)
}

func (c *tcpDeadlineRecorder) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sets++
	c.read = t
	return c.Conn.SetReadDeadline(t)
}

func (c *tcpDeadlineRecorder) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sets++
	c.write = t
	return c.Conn.SetWriteDeadline(t)
}

func (c *tcpDeadlineRecorder) snapshot() (read, write time.Time, sets int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.read, c.write, c.sets
}

func requireTCPTestDeadlines(t *testing.T, c *tcpDeadlineRecorder, wantRead, wantWrite time.Time) {
	t.Helper()
	if read, write, _ := c.snapshot(); !read.Equal(wantRead) || !write.Equal(wantWrite) {
		t.Fatalf("underlay deadlines = %v, %v, want %v, %v", read, write, wantRead, wantWrite)
	}
}

func TestTCPConnUpdatesBlockedHandshakeDeadlines(t *testing.T) {
	for _, update := range []string{"shorten", "extend", "clear"} {
		t.Run(update, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, peer := net.Pipe()
				defer peer.Close()
				underlay := &tcpDeadlineRecorder{Conn: client}
				conn := dialTCPTestConn(t, underlay)
				defer conn.Close()
				start := time.Now()
				initial := start.Add(10 * time.Second)
				if err := conn.SetDeadline(initial); err != nil {
					t.Fatal(err)
				}
				read := startTCPTestRead(conn)
				synctest.Wait()
				// Stagger the two handshakes so their caps require distinct read
				// and write deadlines when SetDeadline updates both directions.
				time.Sleep(time.Second)
				writeStart := time.Now()
				write := startTCPTestWrite(conn)
				synctest.Wait()
				requireTCPTestDeadlines(t, underlay, initial, initial)

				var latest time.Time
				switch update {
				case "shorten":
					latest = time.Now()
					if err := conn.SetReadDeadline(latest); err != nil {
						t.Fatal(err)
					}
					if err := conn.SetWriteDeadline(latest); err != nil {
						t.Fatal(err)
					}
				case "extend":
					latest = start.Add(time.Minute)
					if err := conn.SetDeadline(latest); err != nil {
						t.Fatal(err)
					}
				case "clear":
					if err := conn.SetDeadline(latest); err != nil {
						t.Fatal(err)
					}
				}
				if update != "shorten" {
					readCap, writeCap := start.Add(tcpHandshakeTimeout), writeStart.Add(tcpHandshakeTimeout)
					requireTCPTestDeadlines(t, underlay, readCap, writeCap)
					time.Sleep(time.Until(writeCap))
				}
				synctest.Wait()
				requireTCPTestTimeout(t, "Read", read)
				requireTCPTestTimeout(t, "Write", write)
				requireTCPTestDeadlines(t, underlay, latest, latest)
			})
		})
	}
}
