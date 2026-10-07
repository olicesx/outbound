package client

import (
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

// wbSendRecorder captures the serialized form of every datagram handed to
// the QUIC layer, and can fail a chosen send to exercise partial-success
// semantics.
type wbSendRecorder struct {
	mu       sync.Mutex
	messages [][]byte
	// failAt makes the send with that zero-based index return failErr.
	failAt  int
	failErr error
}

func (r *wbSendRecorder) send(buf []byte, msg *protocol.UDPMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := len(r.messages)
	if idx == r.failAt {
		return r.failErr
	}
	cp := make([]byte, msg.Size())
	n := msg.Serialize(cp)
	r.messages = append(r.messages, cp[:n])
	return nil
}

func (r *wbSendRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.messages)
}

func (r *wbSendRecorder) message(i int) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.messages[i]
}

func newWriteBatchUDPConn(rec *wbSendRecorder) *udpConn {
	u := &udpConn{
		ID:        7,
		ReceiveCh: make(chan *protocol.UDPMessage, 4),
		SendBuf:   make([]byte, protocol.MaxUDPSize),
		SendFunc:  rec.send,
	}
	return u
}

// TestWriteBatchSendsPerItemWithTargets verifies the wire format and full-cone
// Addr alternation: each item leaves as its own serialized UDPMessage whose
// address and payload match the item, in order.
func TestWriteBatchSendsPerItemWithTargets(t *testing.T) {
	rec := &wbSendRecorder{failAt: -1}
	u := newWriteBatchUDPConn(rec)

	addrA := netip.MustParseAddrPort("203.0.113.10:443")
	addrB := netip.MustParseAddrPort("198.51.100.20:53")
	items := []netproxy.BatchItem{
		{Data: []byte("to-a"), Addr: addrA.String()},
		{Data: []byte("to-b"), Addr: addrB.String()},
		{Data: []byte("to-a-again"), Addr: addrA.String()},
	}
	n, err := u.WriteBatch(items)
	if err != nil || n != len(items) {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}
	if got := rec.count(); got != len(items) {
		t.Fatalf("transport sent %d datagrams, want %d", got, len(items))
	}
	for i, item := range items {
		msg, err := protocol.ParseUDPMessage(rec.message(i))
		if err != nil {
			t.Fatalf("datagram %d: ParseUDPMessage: %v", i, err)
		}
		if string(msg.Data) != string(item.Data) {
			t.Fatalf("datagram %d payload = %q, want %q", i, msg.Data, item.Data)
		}
		got, err := netip.ParseAddrPort(string(msg.Addr))
		if err != nil {
			t.Fatalf("datagram %d: addr bytes %q: %v", i, msg.Addr, err)
		}
		if got != netip.MustParseAddrPort(item.Addr) {
			t.Fatalf("datagram %d addr = %v, want %v", i, got, item.Addr)
		}
	}
}

// TestWriteBatchPartialSuccessCountsPrefix pins the sequential-loop contract:
// a send failing mid-batch reports the accepted prefix together with the
// error.
func TestWriteBatchPartialSuccessCountsPrefix(t *testing.T) {
	rec := &wbSendRecorder{failAt: 2, failErr: errors.New("boom")}
	u := newWriteBatchUDPConn(rec)
	items := []netproxy.BatchItem{
		{Data: []byte("one"), Addr: "203.0.113.10:443"},
		{Data: []byte("two"), Addr: "203.0.113.10:443"},
		{Data: []byte("three"), Addr: "203.0.113.10:443"},
		{Data: []byte("four"), Addr: "203.0.113.10:443"},
	}
	n, err := u.WriteBatch(items)
	if err == nil || n != 2 {
		t.Fatalf("want n=2 with error, got n=%d err=%v", n, err)
	}
	if got := rec.count(); got != 2 {
		t.Fatalf("transport sent %d datagrams, want 2", got)
	}
}

// TestWriteBatchEmptyIsNoOp verifies the interface convention for empty
// batches.
func TestWriteBatchEmptyIsNoOp(t *testing.T) {
	rec := &wbSendRecorder{failAt: -1}
	u := newWriteBatchUDPConn(rec)
	n, err := u.WriteBatch(nil)
	if err != nil || n != 0 {
		t.Fatalf("want n=0 nil, got n=%d err=%v", n, err)
	}
	if got := rec.count(); got != 0 {
		t.Fatalf("transport sent %d datagrams, want 0", got)
	}
}
