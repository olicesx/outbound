package vless

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

// wbRecConn records every write for byte-equivalence comparison.
type wbRecConn struct {
	mu     sync.Mutex
	writes [][]byte
}

func (r *wbRecConn) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	r.writes = append(r.writes, cp)
	return len(p), nil
}
func (r *wbRecConn) Read(p []byte) (int, error)  { time.Sleep(time.Hour); return 0, nil }
func (r *wbRecConn) Close() error                { return nil }
func (r *wbRecConn) SetDeadline(time.Time) error { return nil }
func (r *wbRecConn) SetReadDeadline(time.Time) error {
	return nil
}
func (r *wbRecConn) SetWriteDeadline(time.Time) error { return nil }

func (r *wbRecConn) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []byte
	for _, w := range r.writes {
		out = append(out, w...)
	}
	return out
}

func (r *wbRecConn) writeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.writes)
}

func newWriteBatchTestConn(rc netproxy.Conn, isClient bool) *Conn {
	c := &Conn{
		Conn: rc,
		metadata: Metadata{Metadata: vmess.Metadata{
			Metadata: protocol.Metadata{
				IsClient: isClient,
				Type:     protocol.MetadataTypeIPv4,
				Hostname: "203.0.113.10",
				Port:     443,
			},
			Network: "udp",
		}},
		cmdKey: make([]byte, 16),
	}
	if !isClient {
		// Skip the request-header first-write path for framing-only tests,
		// mirroring how the server side behaves after the header was consumed.
		c.onceWrite = true
	}
	return c
}

// TestWriteBatchMatchesSequentialWriteTo verifies the batched datagram path
// emits byte-identical framing to the per-datagram path, in ONE underlying
// write instead of two per datagram.
func TestWriteBatchMatchesSequentialWriteTo(t *testing.T) {
	const target = "203.0.113.10:443"
	payloads := [][]byte{
		bytes.Repeat([]byte{0xAA}, 1200),
		bytes.Repeat([]byte{0xBB}, 64),
		bytes.Repeat([]byte{0xCC}, 4500),
	}

	// Sequential reference.
	seqConn := &wbRecConn{}
	seq := newWriteBatchTestConn(seqConn, false)
	for _, p := range payloads {
		if _, err := seq.WriteTo(p, target); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

	// Batched.
	batConn := &wbRecConn{}
	bat := newWriteBatchTestConn(batConn, false)
	if n, err := bat.WriteBatch([]netproxy.BatchItem{
		{Data: payloads[0], Addr: target},
		{Data: payloads[1], Addr: target},
		{Data: payloads[2], Addr: target},
	}); err != nil || n != 3 {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}

	if !bytes.Equal(seqConn.bytes(), batConn.bytes()) {
		t.Fatalf("batched framing differs from sequential: seq=%d bytes, batch=%d bytes",
			len(seqConn.bytes()), len(batConn.bytes()))
	}
	if got := batConn.writeCount(); got != 1 {
		t.Fatalf("batched path used %d socket writes, want 1", got)
	}
	if got := seqConn.writeCount(); got != 2*len(payloads) {
		t.Fatalf("sequential path used %d writes, want %d", got, 2*len(payloads))
	}
}

// TestWriteBatchClientHeaderRidesWithBatch verifies the first client write
// still carries the VLESS request header ahead of every frame, and that the
// whole batch leaves as one header+payload burst (net.Buffers: one writev on
// a TCP underlay, at most two writes through a generic conn) instead of one
// burst per datagram.
func TestWriteBatchClientHeaderRidesWithBatch(t *testing.T) {
	const target = "203.0.113.10:443"
	payloads := [][]byte{[]byte("first"), []byte("second")}

	seqConn := &wbRecConn{}
	seq := newWriteBatchTestConn(seqConn, true)
	for _, p := range payloads {
		if _, err := seq.WriteTo(p, target); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

	batConn := &wbRecConn{}
	bat := newWriteBatchTestConn(batConn, true)
	if n, err := bat.WriteBatch([]netproxy.BatchItem{
		{Data: payloads[0], Addr: target},
		{Data: payloads[1], Addr: target},
	}); err != nil || n != 2 {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}

	if !bytes.Equal(seqConn.bytes(), batConn.bytes()) {
		t.Fatalf("batched client framing differs from sequential: seq=%d bytes, batch=%d bytes",
			len(seqConn.bytes()), len(batConn.bytes()))
	}
	if got := batConn.writeCount(); got > 2 {
		t.Fatalf("client batch used %d socket writes, want <= 2", got)
	}
	if got := seqConn.writeCount(); got != 2*len(payloads)+1 {
		// Sequential: header+len (one net.Buffers burst on the recording
		// conn's fallback path counts as two writes) is 3 writes for the
		// first datagram, then 2 per datagram.
		t.Fatalf("sequential path used %d writes, want %d", got, 2*len(payloads)+1)
	}
	out := batConn.bytes()
	wantHeaderLen := 1 + 16 + 1 + 1 + 2 + 1 + 4
	if len(out) != wantHeaderLen+2+len("first")+2+len("second") {
		t.Fatalf("wire length = %d, want %d", len(out), wantHeaderLen+2+len("first")+2+len("second"))
	}
	if !bytes.HasSuffix(out, append([]byte{10}, []byte("\x00\x05first\x00\x06second")...)) {
		t.Fatalf("unexpected wire tail: %q", out[len(out)-16:])
	}
}

// TestWriteBatchRejectsOversizedAllOrNothing: per the PacketBatchWriter
// contract, a pre-send validation failure must send nothing (n == 0).
func TestWriteBatchRejectsOversizedAllOrNothing(t *testing.T) {
	rc := &wbRecConn{}
	c := newWriteBatchTestConn(rc, false)
	n, err := c.WriteBatch([]netproxy.BatchItem{
		{Data: make([]byte, 64), Addr: "203.0.113.10:443"},
		{Data: make([]byte, 0x10000), Addr: "203.0.113.10:443"},
	})
	if err == nil || n != 0 {
		t.Fatalf("want error and n=0, got n=%d err=%v", n, err)
	}
	if rc.writeCount() != 0 {
		t.Fatalf("%d writes left despite validation failure", rc.writeCount())
	}
}

// TestWriteBatchWriteErrorReportsZeroDatagrams pins the merged-write error
// contract: a failed write cannot attribute complete datagrams, so n == 0
// together with the error.
func TestWriteBatchWriteErrorReportsZeroDatagrams(t *testing.T) {
	c := newWriteBatchTestConn(failingConn{}, false)
	n, err := c.WriteBatch([]netproxy.BatchItem{
		{Data: []byte("a"), Addr: "203.0.113.10:443"},
		{Data: []byte("b"), Addr: "203.0.113.10:443"},
	})
	if err == nil || n != 0 {
		t.Fatalf("want error and n=0, got n=%d err=%v", n, err)
	}
}

type failingConn struct{}

func (failingConn) Write(p []byte) (int, error) { return 0, net.ErrClosed }
func (failingConn) Read(p []byte) (int, error)  { return 0, net.ErrClosed }
func (failingConn) Close() error                { return nil }
func (failingConn) SetDeadline(time.Time) error { return nil }
func (failingConn) SetReadDeadline(time.Time) error {
	return nil
}
func (failingConn) SetWriteDeadline(time.Time) error { return nil }
