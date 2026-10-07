package vmess

import (
	"bytes"
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
func (r *wbRecConn) Read(p []byte) (int, error) { time.Sleep(time.Hour); return 0, nil }
func (r *wbRecConn) Close() error               { return nil }
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

// newWriteBatchTestConn builds a client-side vmess Conn with a fully
// deterministic chunk-cipher state installed up front: the zero-valued
// body key, the plain size parser, the plain padding generator and a nonce
// counter starting at zero. The lazy first-write initialization is then a
// no-op (client mode), so sequential and batched runs over such conns share
// the nonce sequence and produce comparable wire bytes with no request or
// response header in between.
func newWriteBatchTestConn(rc netproxy.Conn, packetAddr bool) *Conn {
	c := &Conn{
		Conn: rc,
		metadata: Metadata{
			Metadata: protocol.Metadata{
				IsClient: true,
				Type:     protocol.MetadataTypeIPv4,
				Hostname: "203.0.113.10",
				Port:     443,
			},
			Network: "udp",
		},
		dialTgt: "203.0.113.10:443",
		NewAEAD: NewAesGcm,
	}
	if packetAddr {
		c.metadata.Type = protocol.MetadataTypeDomain
		c.metadata.Hostname = SeqPacketMagicAddress
	}
	c.writeBodyCipher, _ = NewAesGcm(make([]byte, 16))
	c.writeChunkSizeParser = PlainChunkSizeParser{}
	c.writePaddingGenerator = PlainPaddingGenerator{}
	c.writeNonceGenerator = GenerateChunkNonce(c.requestBodyIV[:], uint32(c.writeBodyCipher.NonceSize()))
	return c
}

// TestWriteBatchMatchesSequentialWriteTo verifies the batched datagram path
// emits byte-identical AEAD chunks to the per-datagram path (same plaintext,
// same nonce order), in ONE underlying write instead of one per datagram.
func TestWriteBatchMatchesSequentialWriteTo(t *testing.T) {
	const target = "203.0.113.10:443"
	payloads := [][]byte{
		bytes.Repeat([]byte{0xAA}, 1200),
		[]byte("tiny"),
		bytes.Repeat([]byte{0xCC}, 3000),
	}

	seqConn := &wbRecConn{}
	seq := newWriteBatchTestConn(seqConn, false)
	for _, p := range payloads {
		if _, err := seq.WriteTo(p, target); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

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
		t.Fatalf("batched chunks differ from sequential: seq=%d bytes, batch=%d bytes",
			len(seqConn.bytes()), len(batConn.bytes()))
	}
	if got := batConn.writeCount(); got != 1 {
		t.Fatalf("batched path used %d socket writes, want 1", got)
	}
	if got := seqConn.writeCount(); got != len(payloads) {
		t.Fatalf("sequential path used %d writes, want %d", got, len(payloads))
	}
}

// TestWriteBatchPacketAddrAlternatesDestinations verifies the packet-addr
// mode: each sealed chunk decrypts back to its own destination and payload,
// so full-cone Addr alternation keeps working through the batch.
func TestWriteBatchPacketAddrAlternatesDestinations(t *testing.T) {
	type frame struct {
		addr string
		data []byte
	}
	frames := []frame{
		{"203.0.113.10:443", []byte("to-a")},
		{"198.51.100.20:53", []byte("to-b")},
		{"203.0.113.10:443", []byte("to-a-again")},
	}
	items := make([]netproxy.BatchItem, len(frames))
	for i, f := range frames {
		items[i] = netproxy.BatchItem{Data: f.data, Addr: f.addr}
	}

	// A batch and a per-item sequence over identically-initialized conns
	// share the nonce sequence, so the two wire streams must be equal; that
	// equality is the wire-format proof (each item's address prefix rides in
	// its own sealed chunk, in order).
	seqConn := &wbRecConn{}
	seq := newWriteBatchTestConn(seqConn, true)
	batConn := &wbRecConn{}
	bat := newWriteBatchTestConn(batConn, true)
	for i, f := range frames {
		if _, err := seq.WriteTo(f.data, f.addr); err != nil {
			t.Fatalf("WriteTo(%d): %v", i, err)
		}
	}
	if n, err := bat.WriteBatch(items); err != nil || n != len(frames) {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}
	if !bytes.Equal(seqConn.bytes(), batConn.bytes()) {
		t.Fatalf("batched packet-addr chunks differ from sequential")
	}
	if got := batConn.writeCount(); got != 1 {
		t.Fatalf("batched path used %d socket writes, want 1", got)
	}

	// Decrypt the batched wire back and check per-chunk destinations.
	wire := batConn.bytes()
	bodyCipher, err := NewAesGcm(make([]byte, 16))
	if err != nil {
		t.Fatalf("NewAesGcm(body): %v", err)
	}
	offset := 0
	nonceCounter := uint16(0)
	for i := range frames {
		if len(wire)-offset < 2 {
			t.Fatalf("chunk %d: truncated", i)
		}
		size := int(wire[offset])<<8 | int(wire[offset+1])
		offset += 2
		chunk := wire[offset : offset+size]
		offset += size
		var nonce [12]byte
		nonce[0] = byte(nonceCounter >> 8)
		nonce[1] = byte(nonceCounter)
		nonceCounter++
		plain, err := bodyCipher.Open(nil, nonce[:], chunk, nil)
		if err != nil {
			t.Fatalf("chunk %d: Open: %v", i, err)
		}
		_, addrPort, err := ExtractPacketAddr(plain)
		if err != nil {
			t.Fatalf("chunk %d: ExtractPacketAddr: %v", i, err)
		}
		// The write path may encode IPv4 literals in their mapped form
		// (net.ResolveUDPAddr keeps ::ffff:), matching WriteTo; unmap for
		// the comparison.
		got := netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()).String()
		if got != frames[i].addr {
			t.Fatalf("chunk %d addr = %v, want %v", i, got, frames[i].addr)
		}
		addrLen := PacketAddrLength(ParsePacketAddrType(plain[0]))
		if got := string(plain[addrLen:]); got != string(frames[i].data) {
			t.Fatalf("chunk %d payload = %q, want %q", i, got, frames[i].data)
		}
	}
	if offset != len(wire) {
		t.Fatalf("consumed %d of %d chunk bytes", offset, len(wire))
	}
}

// TestWriteBatchRejectsOversizedAllOrNothing: per the PacketBatchWriter
// contract, a pre-send validation failure must send nothing (n == 0).
func TestWriteBatchRejectsOversizedAllOrNothing(t *testing.T) {
	batConn := &wbRecConn{}
	c := newWriteBatchTestConn(batConn, false)
	n, err := c.WriteBatch([]netproxy.BatchItem{
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

// TestWriteBatchWriteErrorReportsZeroDatagrams pins the merged-write error
// contract: a failed write cannot attribute complete datagrams, so n == 0
// together with the error.
func TestWriteBatchWriteErrorReportsZeroDatagrams(t *testing.T) {
	c := newWriteBatchTestConn(failingWbConn{}, false)
	n, err := c.WriteBatch([]netproxy.BatchItem{
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
