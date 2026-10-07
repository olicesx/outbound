package shadowsocks_2022

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

// wbNetConn is a fake connected UDP socket that records every datagram and
// can expose the optional batched-writer capability.
type wbNetConnBase struct {
	mu        sync.Mutex
	datagrams [][]byte

	// failAt simulates a partial batched send: the first failAt items are
	// accepted, then failErr fires. Negative means never fail.
	failAt  int
	failErr error
}

func (c *wbNetConnBase) record(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.datagrams = append(c.datagrams, append([]byte(nil), p...))
}

func (c *wbNetConnBase) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.datagrams)
}

func (c *wbNetConnBase) datagram(i int) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.datagrams[i]
}

func (c *wbNetConnBase) Read(p []byte) (int, error)       { return 0, io.EOF }
func (c *wbNetConnBase) Close() error                     { return nil }
func (c *wbNetConnBase) LocalAddr() net.Addr              { return nil }
func (c *wbNetConnBase) RemoteAddr() net.Addr             { return nil }
func (c *wbNetConnBase) SetDeadline(time.Time) error      { return nil }
func (c *wbNetConnBase) SetReadDeadline(time.Time) error  { return nil }
func (c *wbNetConnBase) SetWriteDeadline(time.Time) error { return nil }

// wbBatchNetConn exposes the batched-writer capability like a direct UDP
// socket with sendmmsg does.
type wbBatchNetConn struct {
	wbNetConnBase
}

func (c *wbBatchNetConn) Write(p []byte) (int, error) {
	c.record(p)
	return len(p), nil
}

func (c *wbBatchNetConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	accepted := len(items)
	if c.failAt >= 0 && accepted > c.failAt {
		accepted = c.failAt
	}
	for _, item := range items[:accepted] {
		c.record(item.Data)
	}
	if accepted < len(items) {
		return accepted, c.failErr
	}
	return accepted, nil
}

// wbSeqNetConn has no batched writer, forcing WriteBatch's sequential
// fallback.
type wbSeqNetConn struct {
	wbNetConnBase
}

func (c *wbSeqNetConn) Write(p []byte) (int, error) {
	c.record(p)
	return len(p), nil
}

func newWriteBatch2022Conn(t *testing.T, conn net.Conn) *UdpConn {
	t.Helper()
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}
	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x11
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}
	u, err := NewUdpConn(conn, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// decodeClientBlockPacket decodes a datagram sealed by the client's block
// write path. Client messages do not echo a session ID, so the receive-side
// decoder (server layout) cannot parse them; mirror the client layout:
// separate header (16B) + EIH + sealed [type][timestamp][paddingLen][addr][payload].
func decodeClientBlockPacket(t *testing.T, conn *UdpConn, wire []byte) ([]byte, netip.AddrPort) {
	t.Helper()
	if len(wire) < 16 {
		t.Fatalf("short client datagram: %d bytes", len(wire))
	}
	separate := make([]byte, 16)
	copy(separate, wire[:16])
	conn.BlockCipherDecrypt().Decrypt(separate, separate)
	var sessionID [8]byte
	copy(sessionID[:], separate[:8])

	cipher, err := CreateCipher(conn.UPSK(), sessionID[:], conn.CipherConf())
	if err != nil {
		t.Fatalf("CreateCipher: %v", err)
	}
	// The EIH block sits between the separate header and the sealed message.
	eihLen := conn.IdentityHeaderLen()
	payload, err := cipher.Open(nil, separate[4:16], wire[16+eihLen:], nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if payload[0] != HeaderTypeClientStream {
		t.Fatalf("header type = %d, want %d", payload[0], HeaderTypeClientStream)
	}
	paddingLen := binary.BigEndian.Uint16(payload[9:11])
	reader := bytes.NewReader(payload[11+paddingLen:])
	netAddr, err := socks5.ReadAddr(reader)
	if err != nil {
		t.Fatalf("ReadAddr: %v", err)
	}
	udpAddr, ok := netAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("addr type %T, want *net.UDPAddr", netAddr)
	}
	addrPort := netip.MustParseAddrPort(udpAddr.String())
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	return rest, addrPort
}

// TestWriteBatchDecodesPerItemWithTargets verifies the wire format: every
// item leaves as its own sealed datagram, and each decodes back to its own
// payload and destination, so full-cone Addr alternation survives the batch.
func TestWriteBatchDecodesPerItemWithTargets(t *testing.T) {
	underlay := &wbBatchNetConn{}
	underlay.failAt = -1
	conn := newWriteBatch2022Conn(t, underlay)

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
		payload, addr := decodeClientBlockPacket(t, conn, underlay.datagram(i))
		if string(payload) != string(item.Data) {
			t.Fatalf("datagram %d payload = %q, want %q", i, payload, item.Data)
		}
		want := netip.MustParseAddrPort(item.Addr)
		if addr != want {
			t.Fatalf("datagram %d target = %v, want %v", i, addr, want)
		}
	}
}

// TestWriteBatchSequentialFallbackCoversNonBatchedUnderlay verifies the
// fallback path: without a batched writer underlay, items still leave in
// order as ordinary connected writes.
func TestWriteBatchSequentialFallbackCoversNonBatchedUnderlay(t *testing.T) {
	underlay := &wbSeqNetConn{}
	conn := newWriteBatch2022Conn(t, underlay)
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
		payload, _ := decodeClientBlockPacket(t, conn, underlay.datagram(i))
		if string(payload) != string(item.Data) {
			t.Fatalf("datagram %d payload = %q, want %q", i, payload, item.Data)
		}
	}
}

// TestWriteBatchPartialSuccessPassesThrough verifies partial-success
// semantics: the underlay's accepted prefix count and error surface verbatim.
func TestWriteBatchPartialSuccessPassesThrough(t *testing.T) {
	underlay := &wbBatchNetConn{}
	underlay.failAt = 1
	underlay.failErr = io.ErrShortWrite
	conn := newWriteBatch2022Conn(t, underlay)
	items := []netproxy.BatchItem{
		{Data: []byte("one"), Addr: "203.0.113.10:443"},
		{Data: []byte("two"), Addr: "203.0.113.10:443"},
		{Data: []byte("three"), Addr: "203.0.113.10:443"},
	}
	n, err := conn.WriteBatch(items)
	if err == nil || n != 1 {
		t.Fatalf("want n=1 with error, got n=%d err=%v", n, err)
	}
	if got := underlay.count(); got != 1 {
		t.Fatalf("underlay received %d datagrams, want 1", got)
	}
}

// TestWriteBatchInvalidAddrSendsNothing: per the PacketBatchWriter contract,
// a destination that cannot be parsed must fail the whole batch before
// anything is sealed or sent (n == 0).
func TestWriteBatchInvalidAddrSendsNothing(t *testing.T) {
	underlay := &wbBatchNetConn{}
	underlay.failAt = -1
	conn := newWriteBatch2022Conn(t, underlay)
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

// TestFakeNetPacketConnForwardsWriteBatch verifies the net.Conn compatibility
// wrapper forwards the optional batched writer: without the forward, the
// dae aggregator's dial-time capability assertion would not see it.
func TestFakeNetPacketConnForwardsWriteBatch(t *testing.T) {
	underlay := &wbBatchNetConn{}
	underlay.failAt = -1
	conn := newWriteBatch2022Conn(t, underlay)
	wrapped := &FakeNetPacketConn{PacketConn: conn, Addr: "203.0.113.10:443"}

	var wrappedConn netproxy.Conn = wrapped
	bw, ok := wrappedConn.(netproxy.PacketBatchWriter)
	if !ok {
		t.Fatal("FakeNetPacketConn does not expose PacketBatchWriter")
	}
	n, err := bw.WriteBatch([]netproxy.BatchItem{
		{Data: []byte("one"), Addr: "203.0.113.10:443"},
		{Data: []byte("two"), Addr: "203.0.113.10:443"},
	})
	if err != nil || n != 2 {
		t.Fatalf("WriteBatch through wrapper: n=%d err=%v", n, err)
	}
	if got := underlay.count(); got != 2 {
		t.Fatalf("underlay received %d datagrams, want 2", got)
	}

	// A wrapped conn without the capability falls back to ordered
	// synchronous sends instead of failing.
	seqWrapped := &FakeNetPacketConn{PacketConn: &noBatchConn{}, Addr: "203.0.113.10:443"}
	var seqWrappedConn netproxy.Conn = seqWrapped
	bw2, ok := seqWrappedConn.(netproxy.PacketBatchWriter)
	if !ok {
		t.Fatal("FakeNetPacketConn does not expose PacketBatchWriter")
	}
	n, err = bw2.WriteBatch([]netproxy.BatchItem{
		{Data: []byte("one"), Addr: "203.0.113.10:443"},
		{Data: []byte("bad"), Addr: "!!!"},
	})
	if err == nil || n != 1 {
		t.Fatalf("fallback path: want n=1 with error, got n=%d err=%v", n, err)
	}
}

// noBatchConn is a PacketConn without a batched writer.
type noBatchConn struct {
	writes int
	failed bool
}

func (c *noBatchConn) Read(p []byte) (int, error) { return 0, io.EOF }
func (c *noBatchConn) Write(p []byte) (int, error) {
	c.writes++
	return len(p), nil
}
func (c *noBatchConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}
func (c *noBatchConn) WriteTo(p []byte, addr string) (int, error) {
	if addr == "!!!" {
		c.failed = true
		return 0, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	c.writes++
	return len(p), nil
}
func (c *noBatchConn) Close() error                     { return nil }
func (c *noBatchConn) SetDeadline(time.Time) error      { return nil }
func (c *noBatchConn) SetReadDeadline(time.Time) error  { return nil }
func (c *noBatchConn) SetWriteDeadline(time.Time) error { return nil }
