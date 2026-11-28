package tuic_test

import (
	"bytes"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// UDP placement over a real QUIC connection: the association-count gate
// that decides which connection carries an association, and the proof that
// an association is not subject to the gate that places TCP. The in-test
// server listens on whichever loopback address answers UDP on this host.

var (
	udpLoopbackOnce sync.Once
	udpLoopbackIP   string
)

// udpLoopbackHost returns a loopback IP on which a UDP datagram sent to
// self comes back. 127.0.0.1 is preferred, to match the other e2e tests; a
// host that policy-routes it onto a relay device drops the replies, and
// ::1 is used instead when it answers. The addresses are probed in turn a
// few times, so one lost datagram on a loaded machine decides nothing.
func udpLoopbackHost(t *testing.T) string {
	t.Helper()
	udpLoopbackOnce.Do(func() {
		for range 3 {
			for _, host := range []string{"127.0.0.1", "::1"} {
				if udpEchoAnswers(host) {
					udpLoopbackIP = host
					return
				}
			}
		}
	})
	if udpLoopbackIP == "" {
		// Losing the whole e2e suite silently is worse locally than a
		// failure is on CI, where loopback is part of the contract.
		if os.Getenv("CI") != "" {
			t.Fatal("no loopback address answers UDP on this host")
		}
		t.Skip("no loopback address answers UDP on this host")
	}
	return udpLoopbackIP
}

func udpEchoAnswers(host string) bool {
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		return false
	}
	defer func() { _ = pc.Close() }()
	if err := pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		return false
	}
	if _, err := pc.WriteTo([]byte{1}, pc.LocalAddr()); err != nil {
		return false
	}
	_, _, err = pc.ReadFrom(make([]byte, 1))
	return err == nil
}

func ringLen(t *testing.T, d netproxy.Dialer) int {
	t.Helper()
	h, ok := d.(interface{ RingLenForTest() int })
	if !ok {
		t.Fatalf("%T does not expose RingLenForTest", d)
	}
	return h.RingLenForTest()
}

func setUDPCap(t *testing.T, d netproxy.Dialer, n int64) {
	t.Helper()
	h, ok := d.(interface{ SetUDPAssociationsCapForTest(int64) })
	if !ok {
		t.Fatalf("%T does not expose SetUDPAssociationsCapForTest", d)
	}
	h.SetUDPAssociationsCapForTest(n)
}

// waitForCapability returns the stream headroom the ring's current
// connection reported, once the first report has arrived.
func waitForCapability(t *testing.T, d netproxy.Dialer, timeout time.Duration) int64 {
	t.Helper()
	h, ok := d.(interface{ RingCapabilityForTest() int64 })
	if !ok {
		t.Fatalf("%T does not expose RingCapabilityForTest", d)
	}
	deadline := time.Now().Add(timeout)
	for {
		if capability := h.RingCapabilityForTest(); capability >= 0 {
			return capability
		}
		if time.Now().After(deadline) {
			t.Fatalf("the client did not learn the server's stream limit within %v", timeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitForServerConnections returns once the server has accepted want
// connections. A 0-RTT dial returns before the server's accept loop sees
// the connection, so the count is polled instead of read once.
func waitForServerConnections(t *testing.T, s *tuicE2EServer, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		n := 0
		s.conns.Range(func(_, _ any) bool {
			n++
			return true
		})
		if n == want {
			return
		}
		if n > want || time.Now().After(deadline) {
			t.Fatalf("server accepted %d connections, want %d", n, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func udpRoundTrip(t *testing.T, c netproxy.PacketConn, target net.Addr) {
	t.Helper()
	payload := []byte("association placement")
	if _, err := c.WriteTo(payload, target.String()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 65535)
	n, from, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("reply = %q, want %q", buf[:n], payload)
	}
	if want := target.(*net.UDPAddr).AddrPort(); from != want {
		t.Fatalf("reply source = %v, want %v", from, want)
	}
}

// TestE2ETuicUDPAssociationsSpreadOverConnections fills a connection to its
// association cap and checks that the next association opens a second
// connection, that both carry traffic, and that closed associations give
// their places back.
func TestE2ETuicUDPAssociationsSpreadOverConnections(t *testing.T) {
	host := udpLoopbackHost(t)
	server := startTUICE2EServerWithOptions(t, tuicE2EServerOptions{host: host, password: e2eTUICPassword})
	target := startUDPEchoTarget(t)
	d := newTuicE2EDialerFromLink(t, server.Addr(), e2eTUICUUIDStr, e2eTUICPassword)
	const assocCap = 4
	setUDPCap(t, d, assocCap)
	ctx := deadlineCtx(t)

	dial := func() netproxy.PacketConn {
		t.Helper()
		c, err := d.DialContext(ctx, "udp", target.String())
		if err != nil {
			t.Fatalf("UDP dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c.(netproxy.PacketConn)
	}

	first := make([]netproxy.PacketConn, 0, assocCap)
	for range assocCap {
		first = append(first, dial())
	}
	if n := ringLen(t, d); n != 1 {
		t.Fatalf("ring holds %d connections after %d associations, want 1", n, assocCap)
	}

	// One past the cap: a second connection, seen from both sides, and
	// both connections carry traffic.
	second := []netproxy.PacketConn{dial()}
	if n := ringLen(t, d); n != 2 {
		t.Fatalf("ring holds %d connections after the first association past the cap, want 2", n)
	}
	waitForServerConnections(t, server, 2)
	udpRoundTrip(t, first[0], target)
	udpRoundTrip(t, second[0], target)

	// Closing associations gives their places back. With the second
	// connection filled to the cap as well, the next association must
	// reuse the first one instead of opening a third.
	for _, c := range first {
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	for len(second) < assocCap {
		second = append(second, dial())
	}
	if n := ringLen(t, d); n != 2 {
		t.Fatalf("ring holds %d connections after the second one filled up, want 2", n)
	}
	reused := dial()
	if n := ringLen(t, d); n != 2 {
		t.Fatalf("ring holds %d connections after the first connection's associations were closed, want 2: their places must be reused", n)
	}
	udpRoundTrip(t, reused, target)
}

// TestE2ETuicUDPAssociationsIgnoreStreamReserve runs against a server that
// allows two bidirectional streams, fewer than the ten TCP keeps in
// reserve. That limit moves TCP to a fresh connection; UDP associations
// must stay, because an association never opens a bidirectional stream.
func TestE2ETuicUDPAssociationsIgnoreStreamReserve(t *testing.T) {
	host := udpLoopbackHost(t)
	server := startTUICE2EServerWithOptions(t, tuicE2EServerOptions{
		host:           host,
		password:       e2eTUICPassword,
		maxBidiStreams: 2,
	})
	target := startUDPEchoTarget(t)
	d := newTuicE2EDialerFromLink(t, server.Addr(), e2eTUICUUIDStr, e2eTUICPassword)
	ctx := deadlineCtx(t)

	var assocs []netproxy.PacketConn
	dial := func() netproxy.PacketConn {
		t.Helper()
		c, err := d.DialContext(ctx, "udp", target.String())
		if err != nil {
			t.Fatalf("UDP dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c.(netproxy.PacketConn)
	}
	assocs = append(assocs, dial())
	// No bidi stream has been opened on this connection, so the headroom
	// is the server's limit exactly.
	if capability := waitForCapability(t, d, 10*time.Second); capability != 2 {
		t.Fatalf("stream headroom = %d, want the server's limit of 2", capability)
	}
	// From here on the learned limit would hold TCP off this connection.
	for range 5 {
		assocs = append(assocs, dial())
	}
	if n := ringLen(t, d); n != 1 {
		t.Fatalf("ring holds %d connections after %d UDP associations, want 1: UDP must not be placed by stream headroom", n, len(assocs))
	}
	waitForServerConnections(t, server, 1)
	udpRoundTrip(t, assocs[len(assocs)-1], target)

	// The control: the same limit holds TCP off this connection.
	echo := loopbackEchoTarget(t)
	tcp, err := d.DialContext(ctx, "tcp", echo.String())
	if err != nil {
		t.Fatalf("TCP dial: %v", err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	if n := ringLen(t, d); n != 2 {
		t.Fatalf("ring holds %d connections after a TCP dial under a two-stream limit, want 2", n)
	}
	if _, err := tcp.Write([]byte("hello")); err != nil {
		t.Fatalf("TCP write: %v", err)
	}
	if err := tcp.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(tcp, reply); err != nil {
		t.Fatalf("TCP read: %v", err)
	}
	if string(reply) != "hello" {
		t.Fatalf("TCP reply = %q, want %q", reply, "hello")
	}
}
