package trojanc

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
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

func newWriteBatchPacketConn(rc netproxy.Conn) *PacketConn {
	c := &Conn{
		Conn: rc,
		metadata: Metadata{Metadata: protocol.Metadata{
			IsClient: true,
		}, Network: "udp"},
	}
	// Skip the trojan request-header first-write path for framing-only
	// tests, mirroring the round-trip test pair.
	c.onceWrite.Store(true)
	return &PacketConn{Conn: c}
}

// TestWriteBatchMatchesSequentialWriteTo verifies the batched datagram path
// emits byte-identical trojan UDP frames to the per-datagram path, in ONE
// underlying write instead of one per datagram.
func TestWriteBatchMatchesSequentialWriteTo(t *testing.T) {
	const target = "203.0.113.10:443"
	payloads := [][]byte{
		bytes.Repeat([]byte{0xAA}, 1200),
		[]byte("tiny"),
		bytes.Repeat([]byte{0xCC}, 3000),
	}

	seqConn := &wbRecConn{}
	seq := newWriteBatchPacketConn(seqConn)
	for _, p := range payloads {
		if _, err := seq.WriteTo(p, target); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

	batConn := &wbRecConn{}
	bat := newWriteBatchPacketConn(batConn)
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
	if got := seqConn.writeCount(); got != len(payloads) {
		t.Fatalf("sequential path used %d writes, want %d", got, len(payloads))
	}
}

// TestWriteBatchAlternatingAddrRoundTrips verifies full-cone Addr
// alternation end to end: a batch whose items target different addresses is
// framed so the receiving side decodes each datagram with its own address.
func TestWriteBatchAlternatingAddrRoundTrips(t *testing.T) {
	a, b := newStreamPipe()
	md := Metadata{Metadata: protocol.Metadata{IsClient: true}, Network: "udp"}
	leftConn := &Conn{Conn: a, metadata: md}
	rightConn := &Conn{Conn: b, metadata: md}
	leftConn.onceWrite.Store(true)
	rightConn.onceWrite.Store(true)
	left := &PacketConn{Conn: leftConn}
	right := &PacketConn{Conn: rightConn}
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})

	addrA := netip.MustParseAddrPort("203.0.113.10:443")
	addrB := netip.MustParseAddrPort("198.51.100.20:53")
	writeDone := make(chan error, 1)
	go func() {
		n, err := left.WriteBatch([]netproxy.BatchItem{
			{Data: []byte("to-a"), Addr: addrA.String()},
			{Data: []byte("to-b"), Addr: addrB.String()},
			{Data: []byte("to-a-again"), Addr: addrA.String()},
		})
		if err == nil && n != 3 {
			err = errShortBatch(n, 3)
		}
		writeDone <- err
	}()

	want := []struct {
		addr netip.AddrPort
		data string
	}{
		{addrA, "to-a"},
		{addrB, "to-b"},
		{addrA, "to-a-again"},
	}
	buf := make([]byte, 2048)
	for i, w := range want {
		if err := right.Conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, addr, err := right.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom(%d): %v", i, err)
		}
		if addr != w.addr {
			t.Fatalf("datagram %d addr = %v, want %v", i, addr, w.addr)
		}
		if string(buf[:n]) != w.data {
			t.Fatalf("datagram %d payload = %q, want %q", i, buf[:n], w.data)
		}
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
}

// errShortBatch reports a WriteBatch datagram-count mismatch from the writer
// goroutine of a round-trip test.
func errShortBatch(got, want int) error {
	return fmt.Errorf("WriteBatch sent %d datagrams, want %d", got, want)
}

// TestWriteBatchRejectsOversizedAllOrNothing: per the PacketBatchWriter
// contract, a pre-send validation failure must send nothing (n == 0).
func TestWriteBatchRejectsOversizedAllOrNothing(t *testing.T) {
	rc := &wbRecConn{}
	pc := newWriteBatchPacketConn(rc)
	n, err := pc.WriteBatch([]netproxy.BatchItem{
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

// TestWriteBatchInvalidAddrSendsNothing verifies that an unparseable
// destination anywhere in the batch fails the whole batch before writing.
func TestWriteBatchInvalidAddrSendsNothing(t *testing.T) {
	rc := &wbRecConn{}
	pc := newWriteBatchPacketConn(rc)
	n, err := pc.WriteBatch([]netproxy.BatchItem{
		{Data: []byte("ok"), Addr: "203.0.113.10:443"},
		{Data: []byte("bad"), Addr: "!!!"},
	})
	if err == nil || n != 0 {
		t.Fatalf("want error and n=0, got n=%d err=%v", n, err)
	}
	if rc.writeCount() != 0 {
		t.Fatalf("%d writes left despite address failure", rc.writeCount())
	}
}

// TestWriteBatchWriteErrorReportsZeroDatagrams pins the merged-write error
// contract: a failed write cannot attribute complete datagrams, so n == 0
// together with the error.
func TestWriteBatchWriteErrorReportsZeroDatagrams(t *testing.T) {
	pc := newWriteBatchPacketConn(failingWbConn{})
	n, err := pc.WriteBatch([]netproxy.BatchItem{
		{Data: []byte("a"), Addr: "203.0.113.10:443"},
		{Data: []byte("b"), Addr: "203.0.113.10:443"},
	})
	if err == nil || n != 0 {
		t.Fatalf("want error and n=0, got n=%d err=%v", n, err)
	}
}

type failingWbConn struct{}

func (failingWbConn) Write(p []byte) (int, error) { return 0, net.ErrClosed }
func (failingWbConn) Read(p []byte) (int, error)  { return 0, net.ErrClosed }
func (failingWbConn) Close() error                { return nil }
func (failingWbConn) SetDeadline(time.Time) error { return nil }
func (failingWbConn) SetReadDeadline(time.Time) error {
	return nil
}
func (failingWbConn) SetWriteDeadline(time.Time) error { return nil }
