package shadowsocks

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type udpPollingConn struct {
	wbUnderlayBase
	packets [][]byte
}

func (c *udpPollingConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	if len(c.packets) == 0 {
		return 0, netip.AddrPort{}, io.EOF
	}
	packet := c.packets[0]
	c.packets = c.packets[1:]
	return copy(p, packet), netip.AddrPort{}, nil
}

func TestUdpConnReadFromDatagramSizes(t *testing.T) {
	for _, cipherName := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(cipherName, func(t *testing.T) {
			const size = 1500
			addr4 := netip.MustParseAddrPort("198.51.100.7:443")
			addr6 := netip.MustParseAddrPort("[2001:db8::7]:443")
			payload := bytes.Repeat([]byte{0x75}, size)
			underlay := &udpPollingConn{}
			key := make([]byte, ciphers.AeadCiphersConf[cipherName].KeyLen)
			conn, err := NewUdpConn(underlay, "127.0.0.1:8388", protocol.Metadata{Cipher: cipherName}, key, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, addr := range []netip.AddrPort{addr4, addr6} {
				if _, err := conn.WriteTo(payload, addr.String()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := conn.WriteTo(bytes.Repeat([]byte{0x68}, 6000), addr6.String()); err != nil {
				t.Fatal(err)
			}
			wire4, wire6, oversized := underlay.datagram(0), underlay.datagram(1), underlay.datagram(2)
			bad := bytes.Clone(wire6)
			bad[len(bad)-1] ^= 1
			underlay.packets = [][]byte{wire4, bad, wire6, oversized, wire4}

			assertRead := func(buf []byte, wantAddr netip.AddrPort) {
				t.Helper()
				n, addr, err := conn.ReadFrom(buf)
				if err != nil || n != size || addr != wantAddr || !bytes.Equal(buf[:n], payload) {
					t.Fatalf("ReadFrom: n=%d addr=%v err=%v, want %d bytes from %v", n, addr, err, size, wantAddr)
				}
			}
			buf := make([]byte, size)
			assertRead(buf, addr4)
			if n, _, err := conn.ReadFrom(buf); n != 0 || err == nil || errors.Is(err, io.ErrShortBuffer) {
				t.Fatalf("ReadFrom tampered datagram: n=%d err=%v, want authentication error", n, err)
			}
			assertRead(buf, addr6)
			n, addr, err := conn.ReadFrom(buf)
			var dropped *netproxy.ErrDatagramDropped
			if n != 0 || addr != addr6 || !errors.As(err, &dropped) || !errors.Is(err, io.ErrShortBuffer) {
				t.Fatalf("ReadFrom oversized datagram: n=%d addr=%v err=%v, want typed short-buffer drop from %v", n, addr, err, addr6)
			}
			assertRead(make([]byte, 65536), addr4)
		})
	}
}
