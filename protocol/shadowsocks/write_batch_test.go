package shadowsocks

import (
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

// wbUnderlayBase records every datagram that reached the fake socket.
type wbUnderlayBase struct {
	mu        sync.Mutex
	datagrams [][]byte
	addrs     []string

	// failAt simulates a partial batched send: the first failAt items are
	// accepted, then failErr fires. Negative means never fail.
	failAt  int
	failErr error
}

func (c *wbUnderlayBase) record(p []byte, addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.datagrams = append(c.datagrams, append([]byte(nil), p...))
	c.addrs = append(c.addrs, addr)
}

func (c *wbUnderlayBase) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.datagrams)
}

func (c *wbUnderlayBase) datagram(i int) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.datagrams[i]
}

func (c *wbUnderlayBase) addrAt(i int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addrs[i]
}

func (c *wbUnderlayBase) Read([]byte) (int, error) { return 0, io.EOF }
func (c *wbUnderlayBase) Write(p []byte) (int, error) {
	return c.WriteTo(p, "")
}
func (c *wbUnderlayBase) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (c *wbUnderlayBase) WriteTo(p []byte, addr string) (int, error) {
	c.record(p, addr)
	return len(p), nil
}
func (c *wbUnderlayBase) Close() error                     { return nil }
func (c *wbUnderlayBase) SetDeadline(time.Time) error      { return nil }
func (c *wbUnderlayBase) SetReadDeadline(time.Time) error  { return nil }
func (c *wbUnderlayBase) SetWriteDeadline(time.Time) error { return nil }

// wbBatchUnderlay exposes the batched-writer capability.
type wbBatchUnderlay struct {
	wbUnderlayBase
}

func (c *wbBatchUnderlay) WriteBatch(items []netproxy.BatchItem) (int, error) {
	accepted := len(items)
	if c.failAt >= 0 && accepted > c.failAt {
		accepted = c.failAt
	}
	for _, item := range items[:accepted] {
		c.record(item.Data, item.Addr)
	}
	if accepted < len(items) {
		return accepted, c.failErr
	}
	return accepted, nil
}

// wbSeqUnderlay has no batched writer, forcing WriteBatch's sequential
// fallback.
type wbSeqUnderlay struct {
	wbUnderlayBase
}

// newWbBatchUnderlay returns a batched fake whose default is to accept every
// item (failAt < 0).
func newWbBatchUnderlay() *wbBatchUnderlay {
	return &wbBatchUnderlay{wbUnderlayBase{failAt: -1}}
}

func newWriteBatchUdpConn(t *testing.T, underlay netproxy.PacketConn) *UdpConn {
	t.Helper()
	metadata := protocol.Metadata{
		Type:     protocol.MetadataTypeIPv4,
		Hostname: "127.0.0.1",
		Port:     8080,
		Cipher:   "aes-128-gcm",
	}
	conn, err := NewUdpConn(underlay, "127.0.0.1:8388", metadata, make([]byte, 16), nil)
	if err != nil {
		t.Fatalf("NewUdpConn() error = %v", err)
	}
	return conn
}

// TestWriteBatchDecryptsPerItemWithTargets verifies the wire format: every
// item leaves as its own sealed datagram addressed to the proxy, and each
// decrypts back to its own payload and destination, so full-cone Addr
// alternation survives the batch.
func TestWriteBatchDecryptsPerItemWithTargets(t *testing.T) {
	underlay := newWbBatchUnderlay()
	conn := newWriteBatchUdpConn(t, underlay)

	addrA := netip.MustParseAddrPort("203.0.113.10:443")
	addrB := netip.MustParseAddrPort("198.51.100.20:53")
	items := []netproxy.BatchItem{
		{Data: []byte("to-a"), Addr: addrA.String()},
		{Data: []byte("to-b"), Addr: addrB.String()},
		{Data: []byte("to-a-again"), Addr: addrA.String()},
	}
	n, err := conn.WriteBatch(items)
	if err != nil || n != len(items) {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}
	if got := underlay.count(); got != len(items) {
		t.Fatalf("underlay received %d datagrams, want %d", got, len(items))
	}
	for i, item := range items {
		if got := underlay.addrAt(i); got != "127.0.0.1:8388" {
			t.Fatalf("datagram %d addressed to %q, want the proxy address", i, got)
		}
		payload, from, err := splitDecryptedUdp(mustDecryptUDP(t, conn, underlay.datagram(i)))
		if err != nil {
			t.Fatalf("datagram %d: split: %v", i, err)
		}
		if string(payload) != string(item.Data) {
			t.Fatalf("datagram %d payload = %q, want %q", i, payload, item.Data)
		}
		if from != netip.MustParseAddrPort(item.Addr) {
			t.Fatalf("datagram %d target = %v, want %v", i, from, item.Addr)
		}
	}
}

// TestWriteBatchSequentialFallbackCoversNonBatchedUnderlay verifies the
// fallback path: without a batched writer underlay, items still leave in
// order as ordinary WriteTo sends.
func TestWriteBatchSequentialFallbackCoversNonBatchedUnderlay(t *testing.T) {
	underlay := &wbSeqUnderlay{}
	conn := newWriteBatchUdpConn(t, underlay)
	items := []netproxy.BatchItem{
		{Data: []byte("one"), Addr: "203.0.113.10:443"},
		{Data: []byte("two"), Addr: "203.0.113.10:443"},
	}
	n, err := conn.WriteBatch(items)
	if err != nil || n != len(items) {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}
	if got := underlay.count(); got != len(items) {
		t.Fatalf("underlay received %d datagrams, want %d", got, len(items))
	}
	for i, item := range items {
		payload, _, err := splitDecryptedUdp(mustDecryptUDP(t, conn, underlay.datagram(i)))
		if err != nil {
			t.Fatalf("datagram %d: split: %v", i, err)
		}
		if string(payload) != string(item.Data) {
			t.Fatalf("datagram %d payload = %q, want %q", i, payload, item.Data)
		}
	}
}

// TestWriteBatchPartialSuccessPassesThrough verifies partial-success
// semantics: the underlay's accepted prefix count and error surface verbatim.
func TestWriteBatchPartialSuccessPassesThrough(t *testing.T) {
	underlay := newWbBatchUnderlay()
	underlay.failAt = 2
	underlay.failErr = io.ErrShortWrite
	conn := newWriteBatchUdpConn(t, underlay)
	items := []netproxy.BatchItem{
		{Data: []byte("one"), Addr: "203.0.113.10:443"},
		{Data: []byte("two"), Addr: "203.0.113.10:443"},
		{Data: []byte("three"), Addr: "203.0.113.10:443"},
		{Data: []byte("four"), Addr: "203.0.113.10:443"},
	}
	n, err := conn.WriteBatch(items)
	if err == nil || n != 2 {
		t.Fatalf("want n=2 with error, got n=%d err=%v", n, err)
	}
	if got := underlay.count(); got != 2 {
		t.Fatalf("underlay received %d datagrams, want 2", got)
	}
}

// TestWriteBatchInvalidAddrSendsNothing: per the PacketBatchWriter contract,
// a destination that cannot be parsed must fail the whole batch before
// anything is sealed or sent (n == 0).
func TestWriteBatchInvalidAddrSendsNothing(t *testing.T) {
	underlay := newWbBatchUnderlay()
	conn := newWriteBatchUdpConn(t, underlay)
	n, err := conn.WriteBatch([]netproxy.BatchItem{
		{Data: []byte("ok"), Addr: "203.0.113.10:443"},
		{Data: []byte("bad"), Addr: "!!!"},
	})
	if err == nil || n != 0 {
		t.Fatalf("want error and n=0, got n=%d err=%v", n, err)
	}
	if got := underlay.count(); got != 0 {
		t.Fatalf("%d datagrams left despite address failure", got)
	}
}

func mustDecryptUDP(t *testing.T, conn *UdpConn, wire []byte) []byte {
	t.Helper()
	key := &Key{
		CipherConf: conn.cipherConf,
		MasterKey:  conn.masterKey,
	}
	plain := make([]byte, len(wire))
	n, err := DecryptUDP(plain, key, wire, ShadowsocksReusedInfo)
	if err != nil {
		t.Fatalf("DecryptUDP: %v", err)
	}
	return plain[:n]
}
