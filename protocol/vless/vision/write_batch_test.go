package vision

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
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
func (r *wbRecConn) Read(p []byte) (int, error) { time.Sleep(time.Hour); return 0, nil }
func (r *wbRecConn) Close() error               { return nil }
func (r *wbRecConn) LocalAddr() net.Addr        { return nil }
func (r *wbRecConn) RemoteAddr() net.Addr       { return nil }
func (r *wbRecConn) SetDeadline(time.Time) error {
	return nil
}
func (r *wbRecConn) SetReadDeadline(time.Time) error  { return nil }
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

func newWriteBatchPacketConn(rc net.Conn, needHandshake bool) *PacketConn {
	vc := &Conn{
		Conn:          rc,
		needHandshake: needHandshake,
	}
	vc.writer = &writeWrapper{vision: vc, writeDirect: true}
	return &PacketConn{Conn: vc, network: "udp", addr: "203.0.113.10:443"}
}

// TestWriteBatchMatchesSequentialWriteTo verifies the batched datagram path
// emits byte-identical XUDP framing to the per-datagram path, in ONE
// underlying write instead of one per datagram.
func TestWriteBatchMatchesSequentialWriteTo(t *testing.T) {
	const target = "203.0.113.10:443"
	payloads := [][]byte{
		bytes.Repeat([]byte{0xAA}, 1200),
		[]byte("tiny"),
		bytes.Repeat([]byte{0xCC}, 3000),
	}

	// Sequential reference, starting from the handshake frame.
	seqConn := &wbRecConn{}
	seq := newWriteBatchPacketConn(seqConn, true)
	for _, p := range payloads {
		if _, err := seq.WriteTo(p, target); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

	// Batched, also starting from the handshake frame.
	batConn := &wbRecConn{}
	bat := newWriteBatchPacketConn(batConn, true)
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
	// MultiWrite on a small total issues one write per part; the exact count
	// only needs to be strictly worse than the batch for the assertion to be
	// meaningful.
	if got := seqConn.writeCount(); got <= 1 {
		t.Fatalf("sequential path used %d writes, want more than the batch's 1", got)
	}
}

// TestWriteBatchAlternatingAddrKeepsPerFrameTargets verifies full-cone Addr
// alternation at the wire level: each XUDP frame carries its own destination,
// and parsing the merged write back yields the per-item targets in order.
func TestWriteBatchAlternatingAddrKeepsPerFrameTargets(t *testing.T) {
	addrA := netip.MustParseAddrPort("203.0.113.10:443")
	addrB := netip.MustParseAddrPort("198.51.100.20:53")
	batConn := &wbRecConn{}
	pc := newWriteBatchPacketConn(batConn, true)
	if n, err := pc.WriteBatch([]netproxy.BatchItem{
		{Data: []byte("to-a"), Addr: addrA.String()},
		{Data: []byte("to-b"), Addr: addrB.String()},
		{Data: []byte("to-a-again"), Addr: addrA.String()},
	}); err != nil || n != 3 {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}

	wire := batConn.bytes()
	wantPayloads := []string{"to-a", "to-b", "to-a-again"}
	wantAddrs := []netip.AddrPort{addrA, addrB, addrA}
	offset := 0
	for i := range wantPayloads {
		if len(wire)-offset < 2 {
			t.Fatalf("frame %d: truncated at offset %d", i, offset)
		}
		frameLen := int(binary.BigEndian.Uint16(wire[offset : offset+2]))
		offset += 2
		header := wire[offset : offset+frameLen]
		if len(header) < 5 {
			t.Fatalf("frame %d: short header %d bytes", i, len(header))
		}
		if i == 0 && header[2] != 1 {
			t.Fatalf("first frame type = %d, want 1 (new)", header[2])
		}
		if i > 0 && header[2] != 2 {
			t.Fatalf("frame %d type = %d, want 2 (keep)", i, header[2])
		}
		addr, err := ReadPacketAddr(header[4:])
		if err != nil {
			t.Fatalf("frame %d: ReadPacketAddr: %v", i, err)
		}
		if addr != wantAddrs[i] {
			t.Fatalf("frame %d addr = %v, want %v", i, addr, wantAddrs[i])
		}
		offset += frameLen
		dataLen := int(binary.BigEndian.Uint16(wire[offset : offset+2]))
		offset += 2
		if got := string(wire[offset : offset+dataLen]); got != wantPayloads[i] {
			t.Fatalf("frame %d payload = %q, want %q", i, got, wantPayloads[i])
		}
		offset += dataLen
	}
	if offset != len(wire) {
		t.Fatalf("consumed %d of %d wire bytes", offset, len(wire))
	}
}

// TestWriteBatchRejectsOversizedAllOrNothing: per the PacketBatchWriter
// contract, a pre-send validation failure must send nothing (n == 0).
func TestWriteBatchRejectsOversizedAllOrNothing(t *testing.T) {
	batConn := &wbRecConn{}
	pc := newWriteBatchPacketConn(batConn, true)
	n, err := pc.WriteBatch([]netproxy.BatchItem{
		{Data: make([]byte, 64), Addr: "203.0.113.10:443"},
		{Data: make([]byte, 0x10000), Addr: "203.0.113.10:443"},
	})
	if err == nil || n != 0 {
		t.Fatalf("want error and n=0, got n=%d err=%v", n, err)
	}
	if batConn.writeCount() != 0 {
		t.Fatalf("%d writes left despite validation failure", batConn.writeCount())
	}
}

// TestWriteBatchInvalidAddrLeavesHandshakeUntouched verifies that a failing
// destination does not consume the session handshake: the next WriteBatch
// must still open with the "new" frame.
func TestWriteBatchInvalidAddrLeavesHandshakeUntouched(t *testing.T) {
	batConn := &wbRecConn{}
	pc := newWriteBatchPacketConn(batConn, true)
	if n, err := pc.WriteBatch([]netproxy.BatchItem{
		{Data: []byte("ok"), Addr: "203.0.113.10:443"},
		{Data: []byte("bad"), Addr: "not an addr"},
	}); err == nil || n != 0 {
		t.Fatalf("want error and n=0, got n=%d err=%v", n, err)
	}
	if batConn.writeCount() != 0 {
		t.Fatalf("%d writes left despite address failure", batConn.writeCount())
	}
	if n, err := pc.WriteBatch([]netproxy.BatchItem{
		{Data: []byte("after"), Addr: "203.0.113.10:443"},
	}); err != nil || n != 1 {
		t.Fatalf("WriteBatch after failure: n=%d err=%v", n, err)
	}
	wire := batConn.bytes()
	if len(wire) < 7 || wire[4] != 1 {
		t.Fatalf("frame after failed batch is not the handshake frame: %v", wire[:min(7, len(wire))])
	}
}
