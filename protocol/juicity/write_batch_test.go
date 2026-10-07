package juicity

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/trojanc"
	"github.com/olicesx/quic-go"
)

// wbRecStream records every write for byte-equivalence comparison.
type wbRecStream struct {
	juicityTestStream
	mu     sync.Mutex
	writes [][]byte
}

func newWbRecStream() *wbRecStream {
	s := &wbRecStream{}
	s.writeFn = s.record
	return s
}

func (s *wbRecStream) record(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	s.writes = append(s.writes, cp)
	return len(p), nil
}

func (s *wbRecStream) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []byte
	for _, w := range s.writes {
		out = append(out, w...)
	}
	return out
}

func (s *wbRecStream) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.writes)
}

func newWriteBatchPacketConn(stream quic.Stream) *PacketConn {
	c := NewConn(stream, &trojanc.Metadata{
		Metadata: protocol.Metadata{IsClient: true},
		Network:  "udp",
	}, nil, nil)
	// Skip the request-header first-write path for framing-only tests.
	c.onceWrite = true
	return &PacketConn{Conn: c}
}

// TestStreamPacketConnWriteBatchMatchesSequentialWriteTo verifies the
// batched datagram path emits byte-identical juicity UDP frames to the
// per-datagram path, in ONE stream write instead of one per datagram.
func TestStreamPacketConnWriteBatchMatchesSequentialWriteTo(t *testing.T) {
	const target = "203.0.113.10:443"
	payloads := [][]byte{
		bytes.Repeat([]byte{0xAA}, 1200),
		[]byte("tiny"),
		bytes.Repeat([]byte{0xCC}, 3000),
	}

	seqStream := newWbRecStream()
	seq := newWriteBatchPacketConn(seqStream)
	for _, p := range payloads {
		if _, err := seq.WriteTo(p, target); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

	batStream := newWbRecStream()
	bat := newWriteBatchPacketConn(batStream)
	if n, err := bat.WriteBatch([]netproxy.BatchItem{
		{Data: payloads[0], Addr: target},
		{Data: payloads[1], Addr: target},
		{Data: payloads[2], Addr: target},
	}); err != nil || n != 3 {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}

	if !bytes.Equal(seqStream.bytes(), batStream.bytes()) {
		t.Fatalf("batched framing differs from sequential: seq=%d bytes, batch=%d bytes",
			len(seqStream.bytes()), len(batStream.bytes()))
	}
	if got := batStream.writeCount(); got != 1 {
		t.Fatalf("batched path used %d stream writes, want 1", got)
	}
	if got := seqStream.writeCount(); got != len(payloads) {
		t.Fatalf("sequential path used %d writes, want %d", got, len(payloads))
	}
}

// wbPipeStream is a synchronous duplex stream over an io.Pipe pair.
type wbPipeStream struct {
	juicityTestStream
	r *io.PipeReader
	w *io.PipeWriter
}

func (s *wbPipeStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *wbPipeStream) Write(p []byte) (int, error) { return s.w.Write(p) }

func newWbPipePair() (*wbPipeStream, *wbPipeStream) {
	ar, aw := io.Pipe()
	br, bw := io.Pipe()
	return &wbPipeStream{r: ar, w: bw}, &wbPipeStream{r: br, w: aw}
}

// TestStreamPacketConnWriteBatchAlternatingAddrRoundTrips verifies full-cone
// Addr alternation end to end: the receiving side decodes each datagram of
// the batch with its own address, in order.
func TestStreamPacketConnWriteBatchAlternatingAddrRoundTrips(t *testing.T) {
	leftStream, rightStream := newWbPipePair()
	left := newWriteBatchPacketConn(leftStream)
	right := newWriteBatchPacketConn(rightStream)
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})

	const addrA = "203.0.113.10:443"
	const addrB = "198.51.100.20:53"
	writeDone := make(chan error, 1)
	go func() {
		n, err := left.WriteBatch([]netproxy.BatchItem{
			{Data: []byte("to-a"), Addr: addrA},
			{Data: []byte("to-b"), Addr: addrB},
			{Data: []byte("to-a-again"), Addr: addrA},
		})
		if err == nil && n != 3 {
			err = io.ErrShortWrite
		}
		writeDone <- err
	}()

	want := []struct {
		addr string
		data string
	}{{addrA, "to-a"}, {addrB, "to-b"}, {addrA, "to-a-again"}}
	type received struct {
		data []byte
		addr string
		err  error
	}
	reads := make(chan received)
	go func() {
		// One private buffer per read: the main goroutine keeps comparing a
		// received value while the next read already runs.
		for range want {
			buf := make([]byte, 2048)
			n, addr, err := right.ReadFrom(buf)
			r := received{err: err}
			if err == nil {
				r.data = buf[:n]
				r.addr = addr.String()
			}
			reads <- r
		}
		close(reads)
	}()
	for i, w := range want {
		select {
		case r, ok := <-reads:
			if !ok {
				t.Fatalf("reader stopped early at datagram %d", i)
			}
			if r.err != nil {
				t.Fatalf("ReadFrom(%d): %v", i, r.err)
			}
			if r.addr != w.addr {
				t.Fatalf("datagram %d addr = %v, want %v", i, r.addr, w.addr)
			}
			if string(r.data) != w.data {
				t.Fatalf("datagram %d payload = %q, want %q", i, r.data, w.data)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("ReadFrom(%d) timed out", i)
		}
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
}

// TestStreamPacketConnWriteBatchRejectsOversizedAllOrNothing: per the
// PacketBatchWriter contract, a pre-send validation failure must send
// nothing (n == 0).
func TestStreamPacketConnWriteBatchRejectsOversizedAllOrNothing(t *testing.T) {
	stream := newWbRecStream()
	pc := newWriteBatchPacketConn(stream)
	n, err := pc.WriteBatch([]netproxy.BatchItem{
		{Data: make([]byte, 64), Addr: "203.0.113.10:443"},
		{Data: make([]byte, 0x10000), Addr: "203.0.113.10:443"},
	})
	if err == nil || n != 0 {
		t.Fatalf("want error and n=0, got n=%d err=%v", n, err)
	}
	if stream.writeCount() != 0 {
		t.Fatalf("%d writes left despite validation failure", stream.writeCount())
	}
}

// TestStreamPacketConnWriteBatchInvalidAddrSendsNothing verifies that an
// unparseable destination anywhere in the batch fails the whole batch
// before writing.
func TestStreamPacketConnWriteBatchInvalidAddrSendsNothing(t *testing.T) {
	stream := newWbRecStream()
	pc := newWriteBatchPacketConn(stream)
	n, err := pc.WriteBatch([]netproxy.BatchItem{
		{Data: []byte("ok"), Addr: "203.0.113.10:443"},
		{Data: []byte("bad"), Addr: "!!!"},
	})
	if err == nil || n != 0 {
		t.Fatalf("want error and n=0, got n=%d err=%v", n, err)
	}
	if stream.writeCount() != 0 {
		t.Fatalf("%d writes left despite address failure", stream.writeCount())
	}
}

// TestStreamPacketConnWriteBatchWriteErrorReportsZeroDatagrams pins the
// merged-write error contract for the QUIC stream path.
func TestStreamPacketConnWriteBatchWriteErrorReportsZeroDatagrams(t *testing.T) {
	stream := newWbRecStream()
	stream.writeFn = func([]byte) (int, error) { return 0, net.ErrClosed }
	pc := newWriteBatchPacketConn(stream)
	n, err := pc.WriteBatch([]netproxy.BatchItem{
		{Data: []byte("a"), Addr: "203.0.113.10:443"},
		{Data: []byte("b"), Addr: "203.0.113.10:443"},
	})
	if err == nil || n != 0 {
		t.Fatalf("want error and n=0, got n=%d err=%v", n, err)
	}
}

// TestTransportPacketConnWriteBatchSendsInOrder drives the raw-underlay
// sequential loop over a real localhost UDP socket pair: every datagram
// must arrive sealed with its own salt, in order, and decrypt back to the
// original payload.
func TestTransportPacketConnWriteBatchSendsInOrder(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer func() { _ = server.Close() }()
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	defer func() { _ = client.Close() }()

	transport := &quic.Transport{Conn: client}
	defer func() { _ = transport.Close() }()
	key := &shadowsocks.Key{
		CipherConf: CipherConf,
		MasterKey:  bytes.Repeat([]byte{7}, CipherConf.KeyLen),
	}
	c := &TransportPacketConn{
		Transport: transport,
		proxyAddr: server.LocalAddr().(*net.UDPAddr),
		tgt:       netip.MustParseAddrPort("203.0.113.10:443"),
		key:       key,
	}

	payloads := []string{"first", "second", "third"}
	items := make([]netproxy.BatchItem, len(payloads))
	for i, p := range payloads {
		items[i] = netproxy.BatchItem{Data: []byte(p), Addr: "203.0.113.10:443"}
	}
	n, err := c.WriteBatch(items)
	if err != nil || n != len(payloads) {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}

	buf := make([]byte, 2048)
	scratch := make([]byte, 64)
	for i, want := range payloads {
		_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
		rn, _, err := server.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("ReadFromUDP(%d): %v", i, err)
		}
		plainLen, err := shadowsocks.DecryptUDPWithScratch(
			buf[:0], key, buf[:rn], ciphers.JuicityReusedInfo, scratch)
		if err != nil {
			t.Fatalf("decrypt(%d): %v", i, err)
		}
		if string(buf[:plainLen]) != want {
			t.Fatalf("datagram %d = %q, want %q", i, buf[:plainLen], want)
		}
	}
}
