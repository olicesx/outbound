package direct

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestDirectPacketConnWriteToUsesDialTargetCache(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	target := serverConn.LocalAddr().String()
	conn := &directPacketConn{
		UDPConn:  clientConn,
		FullCone: true,
		dialTgt:  target,
		resolver: net.DefaultResolver,
	}

	oldResolve := resolveUDPAddr
	defer func() { resolveUDPAddr = oldResolve }()

	var calls atomic.Int32
	resolveUDPAddr = func(resolver *net.Resolver, hostport string) (*net.UDPAddr, error) {
		calls.Add(1)
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			uint16(serverConn.LocalAddr().(*net.UDPAddr).Port),
		)), nil
	}

	for i := 0; i < 2; i++ {
		if _, err := conn.WriteTo([]byte("ping"), target); err != nil {
			t.Fatalf("WriteTo() error = %v", err)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("resolveUDPAddr() call count = %d, want 1", got)
	}
}

func TestDirectPacketConnWriteToCachesAlternateTarget(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	target := serverConn.LocalAddr().String()
	conn := &directPacketConn{
		UDPConn:  clientConn,
		FullCone: true,
		dialTgt:  "127.0.0.1:1",
		resolver: net.DefaultResolver,
	}

	oldResolve := resolveUDPAddr
	defer func() { resolveUDPAddr = oldResolve }()

	var calls atomic.Int32
	resolveUDPAddr = func(resolver *net.Resolver, hostport string) (*net.UDPAddr, error) {
		calls.Add(1)
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			uint16(serverConn.LocalAddr().(*net.UDPAddr).Port),
		)), nil
	}

	for i := 0; i < 2; i++ {
		if _, err := conn.WriteTo([]byte("ping"), target); err != nil {
			t.Fatalf("WriteTo() error = %v", err)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("resolveUDPAddr() call count = %d, want 1", got)
	}
}

// TestDirectPacketConnWriteBatchAlternatingPeersResolveOnce pins the
// FullCone multi-peer contract: a relay whose client alternates between
// several non-dial targets must resolve each target exactly once, and every
// datagram must land on the server its address maps to.
func TestDirectPacketConnWriteBatchAlternatingPeersResolveOnce(t *testing.T) {
	const peers = 3
	servers := make([]*net.UDPConn, peers)
	targets := make([]string, peers)
	for i := range servers {
		server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("ListenUDP(server %d): %v", i, err)
		}
		t.Cleanup(func() { _ = server.Close() })
		servers[i] = server
		targets[i] = fmt.Sprintf("peer-%d.invalid:53", i)
	}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	conn := &directPacketConn{
		UDPConn:  client,
		FullCone: true,
		dialTgt:  "127.0.0.1:1",
		resolver: net.DefaultResolver,
	}

	oldResolve := resolveUDPAddr
	defer func() { resolveUDPAddr = oldResolve }()

	var calls atomic.Int32
	resolveUDPAddr = func(_ *net.Resolver, hostport string) (*net.UDPAddr, error) {
		calls.Add(1)
		for i, target := range targets {
			if hostport == target {
				return (*net.UDPAddr)(servers[i].LocalAddr().(*net.UDPAddr)), nil
			}
		}
		return nil, fmt.Errorf("unexpected target %q", hostport)
	}

	payload := []byte("payload-0123456789")
	for round := 0; round < 16; round++ {
		items := make([]netproxy.BatchItem, peers)
		for i := range items {
			items[i] = netproxy.BatchItem{Data: payload, Addr: targets[i]}
		}
		if n, err := conn.WriteBatch(items); err != nil || n != peers {
			t.Fatalf("WriteBatch() = %d, %v; want %d, nil", n, err, peers)
		}
	}

	if got := calls.Load(); got != peers {
		t.Fatalf("resolveUDPAddr() call count = %d, want %d (one per peer)", got, peers)
	}

	// Every datagram must have landed on the peer its address resolved to.
	for i, server := range servers {
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(payload))
		for round := 0; round < 16; round++ {
			n, _, err := server.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("server %d round %d ReadFromUDP: %v", i, round, err)
			}
			if string(buf[:n]) != string(payload) {
				t.Fatalf("server %d round %d payload = %q", i, round, buf[:n])
			}
		}
	}
}

// TestDirectPacketConnWriteTgtCacheBounded pins the eviction contract: the
// resolved-target cache never exceeds its capacity no matter how many
// distinct peers the relay writes to.
func TestDirectPacketConnWriteTgtCacheBounded(t *testing.T) {
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	conn := &directPacketConn{
		UDPConn:  client,
		FullCone: true,
		dialTgt:  "127.0.0.1:1",
		resolver: net.DefaultResolver,
	}

	oldResolve := resolveUDPAddr
	defer func() { resolveUDPAddr = oldResolve }()

	resolveUDPAddr = func(_ *net.Resolver, _ string) (*net.UDPAddr, error) {
		return (*net.UDPAddr)(server.LocalAddr().(*net.UDPAddr)), nil
	}

	for i := 0; i < writeTgtCacheCapacity+5; i++ {
		if _, err := conn.WriteTo([]byte("x"), fmt.Sprintf("peer-%d.invalid:53", i)); err != nil {
			t.Fatalf("WriteTo(peer %d): %v", i, err)
		}
	}

	conn.cacheMu.Lock()
	size := len(conn.writeTgtCache)
	conn.cacheMu.Unlock()
	if size > writeTgtCacheCapacity {
		t.Fatalf("writeTgtCache size = %d, want <= %d", size, writeTgtCacheCapacity)
	}
}

// BenchmarkDirectWriteBatchAlternatingPeers measures the FullCone write path
// with a realistic resolver stub (parsing only, no network): the metric that
// matters is resolutions per operation, which the bounded cache drops from
// one-per-datagram to one-per-target.
func BenchmarkDirectWriteBatchAlternatingPeers(b *testing.B) {
	for _, peers := range []int{2, 4} {
		b.Run(fmt.Sprintf("peers=%d", peers), func(b *testing.B) {
			client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
			if err != nil {
				b.Fatalf("ListenUDP(client): %v", err)
			}
			defer func() { _ = client.Close() }()

			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
			if err != nil {
				b.Fatalf("ListenUDP(server): %v", err)
			}
			defer func() { _ = server.Close() }()

			conn := &directPacketConn{
				UDPConn:  client,
				FullCone: true,
				dialTgt:  "127.0.0.1:1",
				resolver: net.DefaultResolver,
			}
			targets := make([]string, peers)
			for i := range targets {
				targets[i] = fmt.Sprintf("peer-%d.invalid:53", i)
			}

			oldResolve := resolveUDPAddr
			defer func() { resolveUDPAddr = oldResolve }()
			var calls atomic.Int64
			resolveUDPAddr = func(_ *net.Resolver, _ string) (*net.UDPAddr, error) {
				calls.Add(1)
				return (*net.UDPAddr)(server.LocalAddr().(*net.UDPAddr)), nil
			}

			payload := []byte("payload-0123456789")
			items := make([]netproxy.BatchItem, peers)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := range items {
					items[j] = netproxy.BatchItem{Data: payload, Addr: targets[j]}
				}
				if _, err := conn.WriteBatch(items); err != nil {
					b.Fatalf("WriteBatch: %v", err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(calls.Load())/float64(b.N), "resolves/op")
		})
	}
}
