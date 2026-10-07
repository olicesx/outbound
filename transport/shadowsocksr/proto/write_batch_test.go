package proto

import (
	"io"
	"sync"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// wbBatchInner exposes the batched-writer capability underneath the SSR
// wrapper, like shadowsocks_stream's UdpTransportConn now does.
type wbBatchInner struct {
	recordingPacketConn

	mu     sync.Mutex
	items  []netproxy.BatchItem
	failAt int
	err    error
}

func (c *wbBatchInner) WriteBatch(items []netproxy.BatchItem) (int, error) {
	accepted := len(items)
	if c.failAt >= 0 && accepted > c.failAt {
		accepted = c.failAt
	}
	c.mu.Lock()
	c.items = append(c.items, items[:accepted]...)
	c.mu.Unlock()
	if accepted < len(items) {
		return accepted, c.err
	}
	return accepted, nil
}

func (c *wbBatchInner) batchCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func newWriteBatchPacketConn(inner netproxy.PacketConn) *PacketConn {
	return &PacketConn{
		PacketConn: inner,
		Protocol:   &noOpProtocol{},
		tgt:        "203.0.113.10:443",
	}
}

// TestWriteBatchEncodesPerItemAndForwards verifies the wrapper forwards the
// batch to the inner transport's batched writer, with every item encoded in
// order and prefixed by its own socks address.
func TestWriteBatchEncodesPerItemAndForwards(t *testing.T) {
	inner := &wbBatchInner{}
	inner.failAt = -1
	c := newWriteBatchPacketConn(inner)

	addrA := "203.0.113.10:443"
	addrB := "198.51.100.20:53"
	items := []netproxy.BatchItem{
		{Data: []byte("to-a"), Addr: addrA},
		{Data: []byte("to-b"), Addr: addrB},
		{Data: []byte("to-a-again"), Addr: addrA},
	}
	n, err := c.WriteBatch(items)
	if err != nil || n != len(items) {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}
	if got := inner.batchCount(); got != len(items) {
		t.Fatalf("inner transport received %d datagrams, want %d", got, len(items))
	}
	for i, item := range items {
		want, err := socks.ParseAddr(item.Addr)
		if err != nil {
			t.Fatalf("ParseAddr(%d): %v", i, err)
		}
		got := inner.items[i].Data
		if len(got) < len(want) || string(got[:len(want)]) != string(want) {
			t.Fatalf("datagram %d does not start with its socks address: %v", i, got)
		}
		if string(got[len(want):]) != string(item.Data) {
			t.Fatalf("datagram %d payload = %q, want %q", i, got[len(want):], item.Data)
		}
	}
}

// TestWriteBatchSequentialFallbackCoversNonBatchedInner verifies the
// fallback path: without a batched writer the items still leave in order as
// ordinary writes.
func TestWriteBatchSequentialFallbackCoversNonBatchedInner(t *testing.T) {
	inner := &recordingPacketConn{}
	c := newWriteBatchPacketConn(inner)
	items := []netproxy.BatchItem{
		{Data: []byte("one"), Addr: "203.0.113.10:443"},
		{Data: []byte("two"), Addr: "203.0.113.10:443"},
	}
	n, err := c.WriteBatch(items)
	if err != nil || n != len(items) {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}
	if got := len(inner.writes); got != len(items) {
		t.Fatalf("inner transport received %d datagrams, want %d", got, len(items))
	}
	for i, item := range items {
		want, err := socks.ParseAddr(item.Addr)
		if err != nil {
			t.Fatalf("ParseAddr(%d): %v", i, err)
		}
		got := inner.writes[i].data
		if string(got[len(want):]) != string(item.Data) {
			t.Fatalf("datagram %d payload = %q, want %q", i, got[len(want):], item.Data)
		}
	}
}

// TestWriteBatchPartialSuccessPassesThrough verifies partial-success
// semantics: the inner transport's accepted prefix count and error surface
// verbatim.
func TestWriteBatchPartialSuccessPassesThrough(t *testing.T) {
	inner := &wbBatchInner{}
	inner.failAt = 1
	inner.err = io.ErrShortWrite
	c := newWriteBatchPacketConn(inner)
	items := []netproxy.BatchItem{
		{Data: []byte("one"), Addr: "203.0.113.10:443"},
		{Data: []byte("two"), Addr: "203.0.113.10:443"},
		{Data: []byte("three"), Addr: "203.0.113.10:443"},
	}
	n, err := c.WriteBatch(items)
	if err == nil || n != 1 {
		t.Fatalf("want n=1 with error, got n=%d err=%v", n, err)
	}
	if got := inner.batchCount(); got != 1 {
		t.Fatalf("inner transport received %d datagrams, want 1", got)
	}
}

// TestWriteBatchInvalidAddrSendsNothing: per the PacketBatchWriter contract,
// a destination that cannot be parsed must fail the whole batch before
// anything is encoded or sent (n == 0).
func TestWriteBatchInvalidAddrSendsNothing(t *testing.T) {
	inner := &wbBatchInner{}
	inner.failAt = -1
	c := newWriteBatchPacketConn(inner)
	n, err := c.WriteBatch([]netproxy.BatchItem{
		{Data: []byte("ok"), Addr: "203.0.113.10:443"},
		{Data: []byte("bad"), Addr: "!!!"},
	})
	if err == nil || n != 0 {
		t.Fatalf("want error and n=0, got n=%d err=%v", n, err)
	}
	if got := inner.batchCount(); got != 0 {
		t.Fatalf("%d datagrams left despite address failure", got)
	}
}
