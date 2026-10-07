package shadowsocks_stream

import (
	"fmt"
	"net/netip"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// UdpConn the struct that override the netproxy.Conn methods
type UdpConn struct {
	netproxy.PacketConn
	cipher      *ciphers.StreamCipher
	defaultAddr socks.Addr
	proxyAddr   string
	targetAddr  common.LastStringValue[socks.Addr]
}

var _ netproxy.PacketReceiver = (*UdpConn)(nil)

func (c *UdpConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	receiver, ok := c.PacketConn.(netproxy.PacketReceiver)
	if !ok {
		return nil, false
	}
	return netproxy.RegisterMappedPacketReceiver(receiver, handler, c.mapReceivedPacket)
}

// decryptAndSplitUdp decrypts one stream-cipher UDP datagram in place and
// splits it into the reply payload and its source address. Shared by the
// polling ReadFrom and the push-mode receiver so the two decode paths
// cannot drift.
func (c *UdpConn) decryptAndSplitUdp(data []byte) (payload []byte, from netip.AddrPort, err error) {
	if len(data) < c.cipher.InfoIVLen() {
		return nil, netip.AddrPort{}, fmt.Errorf("packet too short")
	}
	dec, err := c.cipher.NewDecryptor(data[:c.cipher.InfoIVLen()])
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	body := data[c.cipher.InfoIVLen():]
	dec.XORKeyStream(body, body)
	addr := socks.SplitAddr(body)
	if addr == nil {
		return nil, netip.AddrPort{}, fmt.Errorf("no addr present")
	}
	from, ok := addr.AddrPort()
	if !ok {
		if from, err = netip.ParseAddrPort(addr.String()); err != nil {
			return nil, netip.AddrPort{}, fmt.Errorf("bad addr: %w", err)
		}
	}
	return body[len(addr):], from, nil
}

func (c *UdpConn) mapReceivedPacket(packet *netproxy.ReceivedPacket) (*netproxy.ReceivedPacket, bool) {
	if packet.Err != nil {
		return packet, true
	}
	payload, from, err := c.decryptAndSplitUdp(packet.Data)
	if err != nil {
		packet.Err = err
		packet.Data = nil
		return packet, true
	}
	packet.Data = payload
	packet.From = from
	return packet, true
}

var parseSocksAddr = socks.ParseAddr

func NewUdpConn(c netproxy.PacketConn, cipher *ciphers.StreamCipher, defaultAddr socks.Addr, proxyAddr string) *UdpConn {
	return &UdpConn{
		PacketConn:  c,
		cipher:      cipher,
		defaultAddr: defaultAddr,
		proxyAddr:   proxyAddr,
	}
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped transport: SetWriteDeadline is
// delegated to the underlying PacketConn unchanged, so the semantics — and
// the declaration — belong to that transport, not to this wrapper. The
// UdpTransportConn dialer wrapper embeds *UdpConn and inherits this forward.
func (c *UdpConn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.PacketConn)
}

func (c *UdpConn) Cipher() *ciphers.StreamCipher {
	return c.cipher
}

func (c *UdpConn) ReadFrom(b []byte) (n int, from netip.AddrPort, err error) {
	n, _, err = c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, netip.AddrPort{}, err
	}

	payload, from, err := c.decryptAndSplitUdp(b[:n])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	n = copy(b, payload)

	return n, from, nil
}

// sealToPool seals one datagram (IV + socks address + payload, stream-cipher
// keystream) into a pool buffer owned by the caller. Shared by WriteTo and
// WriteBatch so the two send paths cannot drift.
func (c *UdpConn) sealToPool(p []byte, addr socks.Addr) (pool.PB, error) {
	infoIvLen := c.cipher.InfoIVLen()
	buf := pool.Get(infoIvLen + len(addr) + len(p))
	enc, err := c.cipher.NewEncryptorInto(buf)
	if err != nil {
		pool.Put(buf)
		return nil, err
	}
	copy(buf[infoIvLen:], addr)
	copy(buf[infoIvLen+len(addr):], p)
	enc.XORKeyStream(buf[infoIvLen:], buf[infoIvLen:])
	return buf, nil
}

func (c *UdpConn) writeTo(p []byte, addr socks.Addr) (n int, err error) {
	buf, err := c.sealToPool(p, addr)
	if err != nil {
		return 0, err
	}
	defer pool.Put(buf)
	if _, err = c.PacketConn.WriteTo(buf, c.proxyAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *UdpConn) WriteTo(p []byte, to string) (n int, err error) {
	addr, err := c.cachedTargetAddr(to)
	if err != nil {
		return 0, err
	}
	return c.writeTo(p, addr)
}

// WriteBatch implements netproxy.PacketBatchWriter: seal every datagram
// independently (each is its own UDP datagram with its own IV) and hand the
// sealed batch to the underlying transport's batched writer in one call,
// amortizing the per-item syscall. When the underlay has no batched writer
// the items fall back to sequential synchronous sends, preserving order.
// Every destination is resolved and sealed before anything is sent, so a
// pre-send failure is all-or-nothing (n == 0).
func (c *UdpConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	addrs := make([]socks.Addr, len(items))
	for i, item := range items {
		addr, err := c.cachedTargetAddr(item.Addr)
		if err != nil {
			return 0, err
		}
		addrs[i] = addr
	}
	sealed := make([]pool.PB, len(items))
	for i, item := range items {
		s, err := c.sealToPool(item.Data, addrs[i])
		if err != nil {
			for _, prev := range sealed[:i] {
				pool.Put(prev)
			}
			return 0, err
		}
		sealed[i] = s
	}
	if bw, ok := c.PacketConn.(netproxy.PacketBatchWriter); ok {
		defer func() {
			for _, s := range sealed {
				pool.Put(s)
			}
		}()
		enc := make([]netproxy.BatchItem, len(items))
		for i, s := range sealed {
			enc[i] = netproxy.BatchItem{Data: s, Addr: c.proxyAddr}
		}
		return bw.WriteBatch(enc)
	}
	// No batched underlay: sequential synchronous sends in order. Each sealed
	// datagram returns to the pool right after its send.
	sent := 0
	for i := range items {
		_, err := c.PacketConn.WriteTo(sealed[i], c.proxyAddr)
		pool.Put(sealed[i])
		sealed[i] = nil
		if err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func (c *UdpConn) cachedTargetAddr(addr string) (socks.Addr, error) {
	if cached, ok := c.targetAddr.Load(addr); ok {
		return cached, nil
	}
	target, err := parseSocksAddr(addr)
	if err != nil {
		return nil, err
	}
	target = append(socks.Addr(nil), target...)
	c.targetAddr.Store(addr, target)
	return target, nil
}

func (c *UdpConn) Write(b []byte) (n int, err error) {
	return c.writeTo(b, c.defaultAddr)
}

func (c *UdpConn) WriteTransport(p []byte) (n int, err error) {
	buf, err := c.sealTransportToPool(p)
	if err != nil {
		return 0, err
	}
	defer pool.Put(buf)
	if _, err = c.PacketConn.WriteTo(buf, c.proxyAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// sealTransportToPool seals one transport-mode datagram (IV + payload, no
// socks address: the tunnel target is fixed at dial time) into a pool buffer
// owned by the caller.
func (c *UdpConn) sealTransportToPool(p []byte) (pool.PB, error) {
	infoIvLen := c.cipher.InfoIVLen()
	buf := pool.Get(infoIvLen + len(p))
	enc, err := c.cipher.NewEncryptorInto(buf)
	if err != nil {
		pool.Put(buf)
		return nil, err
	}
	copy(buf[infoIvLen:], p)
	enc.XORKeyStream(buf[infoIvLen:], buf[infoIvLen:])
	return buf, nil
}

func (c *UdpConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *UdpConn) ReadTransport(b []byte) (n int, err error) {

	n, _, err = c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, err
	}

	if n < c.cipher.InfoIVLen() {
		return 0, fmt.Errorf("packet too short")
	}
	dec, err := c.cipher.NewDecryptor(b[:c.cipher.InfoIVLen()])
	if err != nil {
		return 0, err
	}
	data := b[c.cipher.InfoIVLen():n]
	dec.XORKeyStream(data, data)

	n = copy(b, data)

	return n, err
}

type UdpTransportConn struct {
	*UdpConn
}

var _ netproxy.PacketReceiver = (*UdpTransportConn)(nil)

func (c *UdpTransportConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	receiver, ok := c.PacketConn.(netproxy.PacketReceiver)
	if !ok {
		return nil, false
	}
	return netproxy.RegisterMappedPacketReceiver(receiver, handler, c.mapTransportPacket)
}

func (c *UdpTransportConn) mapTransportPacket(packet *netproxy.ReceivedPacket) (*netproxy.ReceivedPacket, bool) {
	if packet.Err != nil {
		return packet, true
	}
	if len(packet.Data) < c.cipher.InfoIVLen() {
		packet.Err = fmt.Errorf("packet too short")
		packet.Data = nil
		return packet, true
	}
	dec, err := c.cipher.NewDecryptor(packet.Data[:c.cipher.InfoIVLen()])
	if err != nil {
		packet.Err = err
		packet.Data = nil
		return packet, true
	}
	data := packet.Data[c.cipher.InfoIVLen():]
	dec.XORKeyStream(data, data)
	packet.Data = data
	packet.From = netip.AddrPort{}
	return packet, true
}

func (c *UdpTransportConn) WriteTo(p []byte, to string) (n int, err error) {
	return c.WriteTransport(p)
}

// WriteBatch implements netproxy.PacketBatchWriter for transport mode: seal
// every datagram independently (its own IV) and hand the sealed batch to the
// underlying transport's batched writer when it has one, else send them
// sequentially. The tunnel target is fixed at dial time, so item addresses
// are irrelevant here exactly as in WriteTo.
func (c *UdpTransportConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	sealed := make([]pool.PB, len(items))
	for i, item := range items {
		s, err := c.sealTransportToPool(item.Data)
		if err != nil {
			for _, prev := range sealed[:i] {
				pool.Put(prev)
			}
			return 0, err
		}
		sealed[i] = s
	}
	if bw, ok := c.PacketConn.(netproxy.PacketBatchWriter); ok {
		defer func() {
			for _, s := range sealed {
				pool.Put(s)
			}
		}()
		enc := make([]netproxy.BatchItem, len(items))
		for i, s := range sealed {
			enc[i] = netproxy.BatchItem{Data: s, Addr: c.proxyAddr}
		}
		return bw.WriteBatch(enc)
	}
	sent := 0
	for i := range items {
		_, err := c.PacketConn.WriteTo(sealed[i], c.proxyAddr)
		pool.Put(sealed[i])
		sealed[i] = nil
		if err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func (c *UdpTransportConn) Write(b []byte) (n int, err error) {
	return c.WriteTransport(b)
}

func (c *UdpTransportConn) Read(b []byte) (n int, err error) {
	return c.ReadTransport(b)
}

func (c *UdpTransportConn) ReadFrom(b []byte) (n int, from netip.AddrPort, err error) {
	n, err = c.ReadTransport(b)
	return n, netip.AddrPort{}, err
}
