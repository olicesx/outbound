package shadowsocks_2022

import (
	"bytes"
	"encoding/binary"
	stderrors "errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	"golang.org/x/crypto/chacha20poly1305"
)

type udpReadBufferConn struct {
	packet []byte
	read   bool
}

type udpReceiverConn struct {
	*udpReadBufferConn
	handler netproxy.PacketReceiveHandler
}

func (c *udpReceiverConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	c.handler = handler
	return func() { c.handler = nil }, true
}

func (c *udpReceiverConn) emit(packet *netproxy.ReceivedPacket) bool {
	if c.handler == nil {
		return false
	}
	return c.handler(packet)
}

func (c *udpReadBufferConn) Read(p []byte) (int, error) {
	if c.read {
		return 0, io.EOF
	}
	c.read = true
	return copy(p, c.packet), nil
}

func (c *udpReadBufferConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *udpReadBufferConn) Close() error                       { return nil }
func (c *udpReadBufferConn) LocalAddr() net.Addr                { return udpConnTestAddr("local") }
func (c *udpReadBufferConn) RemoteAddr() net.Addr               { return udpConnTestAddr("remote") }
func (c *udpReadBufferConn) SetDeadline(_ time.Time) error      { return nil }
func (c *udpReadBufferConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *udpReadBufferConn) SetWriteDeadline(_ time.Time) error { return nil }

type udpReceiverUnderlay struct {
	netproxy.Conn
	netproxy.PacketReceiver
}

type udpConnTestAddr string

func (a udpConnTestAddr) Network() string { return "udp-test" }
func (a udpConnTestAddr) String() string  { return string(a) }

func buildServerPacket(t *testing.T, core *SS2022Core, serverSessionID, clientSessionID [8]byte, packetID uint64, addr string, payload []byte) []byte {
	t.Helper()
	return buildServerPacketWithPadding(t, core, serverSessionID, clientSessionID, packetID, addr, payload, 0)
}

func buildServerPacketWithPadding(t *testing.T, core *SS2022Core, serverSessionID, clientSessionID [8]byte, packetID uint64, addr string, payload []byte, paddingLen int) []byte {
	t.Helper()

	var separateHeader [16]byte
	copy(separateHeader[:8], serverSessionID[:])
	binary.BigEndian.PutUint64(separateHeader[8:], packetID)

	var separateHeaderEncrypted [16]byte
	core.BlockCipherDecrypt().Encrypt(separateHeaderEncrypted[:], separateHeader[:])

	addrInfo, err := socks5.AddressFromString(addr)
	if err != nil {
		t.Fatalf("AddressFromString: %v", err)
	}
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		t.Fatalf("addrInfoEncodedLen: %v", err)
	}

	messageLen := 1 + 8 + 8 + 2 + paddingLen + addrLen + len(payload)
	message := make([]byte, messageLen)
	message[0] = HeaderTypeServerStream
	binary.BigEndian.PutUint64(message[1:9], uint64(time.Now().Unix()))
	copy(message[9:17], clientSessionID[:])
	binary.BigEndian.PutUint16(message[17:19], uint16(paddingLen))
	addrOffset := 19 + paddingLen
	addrWritten, err := writeAddrInfoTo(message[addrOffset:], addrInfo)
	if err != nil {
		t.Fatalf("writeAddrInfoTo: %v", err)
	}
	copy(message[addrOffset+addrWritten:], payload)

	sessionCipher, err := CreateCipher(core.UPSK(), serverSessionID[:], core.CipherConf())
	if err != nil {
		t.Fatalf("CreateCipher: %v", err)
	}
	return sessionCipher.Seal(separateHeaderEncrypted[:], separateHeader[4:16], message, nil)
}

func buildServerPacketChacha(t *testing.T, core *SS2022Core, serverSessionID, clientSessionID [8]byte, packetID uint64, addr string, payload []byte) []byte {
	t.Helper()
	return buildServerPacketChachaWithPadding(t, core, serverSessionID, clientSessionID, packetID, addr, payload, 0)
}

func buildServerPacketChachaWithPadding(t *testing.T, core *SS2022Core, serverSessionID, clientSessionID [8]byte, packetID uint64, addr string, payload []byte, paddingLen int) []byte {
	t.Helper()

	addrInfo, err := socks5.AddressFromString(addr)
	if err != nil {
		t.Fatalf("AddressFromString: %v", err)
	}
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		t.Fatalf("addrInfoEncodedLen: %v", err)
	}

	messageLen := 16 + 1 + 8 + 8 + 2 + paddingLen + addrLen + len(payload)
	message := make([]byte, messageLen)
	copy(message[:8], serverSessionID[:])
	binary.BigEndian.PutUint64(message[8:16], packetID)
	message[16] = HeaderTypeServerStream
	binary.BigEndian.PutUint64(message[17:25], uint64(time.Now().Unix()))
	copy(message[25:33], clientSessionID[:])
	binary.BigEndian.PutUint16(message[33:35], uint16(paddingLen))
	addrOffset := 35 + paddingLen
	addrWritten, err := writeAddrInfoTo(message[addrOffset:], addrInfo)
	if err != nil {
		t.Fatalf("writeAddrInfoTo: %v", err)
	}
	copy(message[addrOffset+addrWritten:], payload)

	udpCipher, err := chacha20poly1305.NewX(core.UPSK())
	if err != nil {
		t.Fatalf("NewX: %v", err)
	}

	nonce := make([]byte, udpPacketNonceSize)
	binary.BigEndian.PutUint64(nonce[16:], packetID)

	packet := make([]byte, udpPacketNonceSize, udpPacketNonceSize+messageLen+core.CipherConf().TagLen)
	copy(packet, nonce)
	return udpCipher.Seal(packet, nonce, message, nil)
}

func TestValidateTimestamp(t *testing.T) {
	now := time.Now()
	if err := validateTimestamp(now, now); err != nil {
		t.Fatalf("now should pass: %v", err)
	}
	if err := validateTimestamp(now.Add(ciphers.TimestampTolerance-time.Millisecond), now); err != nil {
		t.Fatalf("near-future timestamp should pass: %v", err)
	}
	if err := validateTimestamp(now.Add(-ciphers.TimestampTolerance+time.Millisecond), now); err != nil {
		t.Fatalf("near-past timestamp should pass: %v", err)
	}
	if err := validateTimestamp(now.Add(ciphers.TimestampTolerance+time.Millisecond), now); err != protocol.ErrTimestampExpired {
		t.Fatalf("too-far future timestamp should fail with an expired timestamp, got: %v", err)
	}
	if err := validateTimestamp(now.Add(-ciphers.TimestampTolerance-time.Millisecond), now); err != protocol.ErrTimestampExpired {
		t.Fatalf("too-old timestamp should fail with an expired timestamp, got: %v", err)
	}
}

// TestTimestampExpiryIsDistinguishableFromReplay pins the classification split:
// a rejected timestamp reports its own cause, and a replayed packet ID keeps
// reporting a replay. A consumer that reacts to one of them must therefore say
// so explicitly instead of inheriting the other's behaviour.
func TestTimestampExpiryIsDistinguishableFromReplay(t *testing.T) {
	now := time.Now()
	stale := validateTimestamp(now.Add(-ciphers.TimestampTolerance-time.Second), now)
	if stale == nil {
		t.Fatal("a stale timestamp must be rejected")
	}
	if !stderrors.Is(stale, protocol.ErrTimestampExpired) {
		t.Fatalf("stale timestamp error = %v, want ErrTimestampExpired", stale)
	}
	if stderrors.Is(stale, protocol.ErrReplayAttack) {
		t.Fatalf("stale timestamp error = %v, must not be classified as a replay", stale)
	}

	replay := protocol.ErrReplayAttack
	if !stderrors.Is(replay, protocol.ErrReplayAttack) || stderrors.Is(replay, protocol.ErrTimestampExpired) {
		t.Fatalf("replay error = %v, want it classified as a replay only", replay)
	}

	// The UDP replay window keeps reporting a plain replay: the split moved the
	// timestamp rejection out of ErrReplayAttack and left this decision intact.
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
	sessionID := [8]byte{1, 1, 1, 1, 1, 1, 1, 1}
	conn, err := NewUdpConn(&udpReadBufferConn{}, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !conn.checkAndUpdateReplay(sessionID, 7, now) {
		t.Fatal("the first packet of a session must be accepted")
	}
	if conn.checkAndUpdateReplay(sessionID, 7, now) {
		t.Fatal("a repeated packet ID must be rejected")
	}
}

func TestUdpConn_NextPacketID_ConcurrentUnique(t *testing.T) {
	u := &UdpConn{}
	const n = 2000

	ids := make(chan uint64, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids <- u.nextPacketID()
		}()
	}
	wg.Wait()
	close(ids)

	seen := make(map[uint64]struct{}, n)
	var minID = ^uint64(0)
	var maxID uint64
	for id := range ids {
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate packetID: %d", id)
		}
		seen[id] = struct{}{}
		if id < minID {
			minID = id
		}
		if id > maxID {
			maxID = id
		}
	}

	if len(seen) != n {
		t.Fatalf("unexpected unique count: got %d, want %d", len(seen), n)
	}
	if minID != 1 {
		t.Fatalf("unexpected min packetID: got %d, want 1", minID)
	}
	if maxID != n {
		t.Fatalf("unexpected max packetID: got %d, want %d", maxID, n)
	}
}

func TestUdpConn_ReplayWindow_PerSessionAndExpiry(t *testing.T) {
	u := &UdpConn{}
	now := time.Now()

	var sid1 [8]byte
	copy(sid1[:], []byte{1, 1, 1, 1, 1, 1, 1, 1})
	var sid2 [8]byte
	copy(sid2[:], []byte{2, 2, 2, 2, 2, 2, 2, 2})

	if !u.checkAndUpdateReplay(sid1, 1, now) {
		t.Fatalf("sid1 packet 1 should pass")
	}
	if u.checkAndUpdateReplay(sid1, 1, now) {
		t.Fatalf("sid1 duplicate packet 1 should fail")
	}
	if !u.checkAndUpdateReplay(sid1, 2, now) {
		t.Fatalf("sid1 packet 2 should pass")
	}
	if !u.checkAndUpdateReplay(sid2, 1, now) {
		t.Fatalf("sid2 packet 1 should pass independently")
	}

	if !u.checkAndUpdateReplay(sid1, 5000, now) {
		t.Fatalf("sid1 packet 5000 should pass")
	}
	if u.checkAndUpdateReplay(sid1, 1, now) {
		t.Fatalf("sid1 old packet should fail after large jump")
	}

	future := now.Add(ciphers.SaltStorageDuration + time.Second)
	if !u.checkAndUpdateReplay(sid1, 1, future) {
		t.Fatalf("sid1 should reset after expiry and accept packet 1")
	}
}

func TestUdpConn_ReadFromUsesRemoteSessionCipher(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}

	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x23
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	localSessionID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	remoteSessionID := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	wantAddr := netip.MustParseAddrPort("203.0.113.9:853")
	wantPayload := []byte("ss2022-udp-remote-session")

	packet := buildServerPacket(t, core, remoteSessionID, localSessionID, 1, wantAddr.String(), wantPayload)
	conn, err := NewUdpConn(&udpReadBufferConn{packet: packet}, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.sessionID = localSessionID

	buf := make([]byte, 128)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if addr != wantAddr {
		t.Fatalf("unexpected addr: got %v want %v", addr, wantAddr)
	}
	if got := string(buf[:n]); got != string(wantPayload) {
		t.Fatalf("unexpected payload: got %q want %q", got, string(wantPayload))
	}
}

func TestUdpConn_ReadFromChacha2022(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-chacha20-poly1305"]
	if conf == nil {
		t.Fatal("missing ss2022 chacha cipher config")
	}

	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x31
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	localSessionID := [8]byte{1, 3, 5, 7, 9, 11, 13, 15}
	remoteSessionID := [8]byte{2, 4, 6, 8, 10, 12, 14, 16}
	wantAddr := netip.MustParseAddrPort("198.51.100.7:443")
	wantPayload := []byte("ss2022-chacha-udp")

	packet := buildServerPacketChacha(t, core, remoteSessionID, localSessionID, 1, wantAddr.String(), wantPayload)
	conn, err := NewUdpConn(&udpReadBufferConn{packet: packet}, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.sessionID = localSessionID

	buf := make([]byte, 128)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if addr != wantAddr {
		t.Fatalf("unexpected addr: got %v want %v", addr, wantAddr)
	}
	if got := string(buf[:n]); got != string(wantPayload) {
		t.Fatalf("unexpected payload: got %q want %q", got, string(wantPayload))
	}
}

func TestUdpConnPacketReceiverDecodesBlockAndChachaPackets(t *testing.T) {
	tests := []struct {
		name       string
		cipherName string
		serverID   [8]byte
		clientID   [8]byte
		addr       string
		payload    []byte
		build      func(*testing.T, *SS2022Core, [8]byte, [8]byte, uint64, string, []byte) []byte
	}{
		{
			name:       "block",
			cipherName: "2022-blake3-aes-256-gcm",
			serverID:   [8]byte{8, 7, 6, 5, 4, 3, 2, 1},
			clientID:   [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
			addr:       "203.0.113.9:853",
			payload:    []byte("receiver-block"),
			build:      buildServerPacket,
		},
		{
			name:       "chacha",
			cipherName: "2022-blake3-chacha20-poly1305",
			serverID:   [8]byte{2, 4, 6, 8, 10, 12, 14, 16},
			clientID:   [8]byte{1, 3, 5, 7, 9, 11, 13, 15},
			addr:       "198.51.100.7:443",
			payload:    []byte("receiver-chacha"),
			build:      buildServerPacketChacha,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := ciphers.Aead2022CiphersConf[tc.cipherName]
			if conf == nil {
				t.Fatalf("missing cipher config %q", tc.cipherName)
			}
			receiver := &udpReceiverConn{udpReadBufferConn: &udpReadBufferConn{}}
			underlay := &udpReceiverUnderlay{Conn: receiver, PacketReceiver: receiver}
			dialer, err := NewDialer(recordingPacketDialer{conn: underlay}, protocol.Header{
				Cipher:       tc.cipherName,
				Password:     pskBase64(conf.KeyLen, 0x20),
				ProxyAddress: "127.0.0.1:8388",
			})
			if err != nil {
				t.Fatal(err)
			}
			packet := tc.build(t, dialer.(*Dialer).core, tc.serverID, tc.clientID, 1, tc.addr, tc.payload)
			conn, err := dialer.DialContext(t.Context(), "udp", tc.addr)
			if err != nil {
				t.Fatal(err)
			}
			conn.(*FakeNetPacketConn).PacketConn.(*UdpConn).sessionID = tc.clientID
			registrar, ok := conn.(netproxy.PacketReceiver)
			if !ok {
				t.Fatal("dialed UDP connection does not expose PacketReceiver")
			}

			var got *netproxy.ReceivedPacket
			stop, ok := registrar.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
				got = packet
				return true
			})
			if !ok || stop == nil {
				t.Fatal("RegisterPacketReceiver() did not register")
			}
			var released atomic.Int32
			if !receiver.emit(netproxy.NewReceivedPacket(append([]byte(nil), packet...), netip.AddrPort{}, nil, func() {
				released.Add(1)
			})) {
				t.Fatal("receiver did not consume packet")
			}
			if got == nil || string(got.Data) != string(tc.payload) || got.From != netip.MustParseAddrPort(tc.addr) {
				t.Fatalf("decoded packet = %+v, want payload %q from %s", got, tc.payload, tc.addr)
			}
			got.Release()
			if released.Load() != 1 {
				t.Fatalf("raw release count = %d, want 1", released.Load())
			}
			stop()
		})
	}
}

func TestUdpConn_DecryptCipherCacheDropsToLowWatermarkAfterBurst(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}

	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x42
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := NewUdpConn(&udpReadBufferConn{}, core, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i <= maxDecryptCipherEntries; i++ {
		var sessionID [8]byte
		sessionID[0] = byte(i)
		sessionID[1] = byte(i >> 8)
		if _, err := conn.decryptCipherFor(sessionID); err != nil {
			t.Fatalf("decryptCipherFor(%d): %v", i, err)
		}
	}

	if got := len(conn.decryptCiphers); got > decryptCipherLowWatermark {
		t.Fatalf("decrypt cipher cache size = %d, want <= %d after burst trimming", got, decryptCipherLowWatermark)
	}
}

func TestUdpConnReadFromDatagramSizes(t *testing.T) {
	for _, cipherName := range []string{
		"2022-blake3-aes-128-gcm",
		"2022-blake3-aes-256-gcm",
		"2022-blake3-chacha20-poly1305",
	} {
		t.Run(cipherName, func(t *testing.T) {
			conf := ciphers.Aead2022CiphersConf[cipherName]
			psk := bytes.Repeat([]byte{0x41}, conf.KeyLen)
			core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
			if err != nil {
				t.Fatal(err)
			}
			underlay := &recordingPacketNetConn{}
			conn, err := NewUdpConn(underlay, core, nil)
			if err != nil {
				t.Fatal(err)
			}
			build := buildServerPacketWithPadding
			if !core.IsUsingBlockCipher() {
				build = buildServerPacketChachaWithPadding
			}
			remoteID := [8]byte{2, 4, 6, 8, 10, 12, 14, 16}
			addr4 := netip.MustParseAddrPort("198.51.100.7:443")
			addr6 := netip.MustParseAddrPort("[2001:db8::7]:443")
			const size = 1500
			exact := bytes.Repeat([]byte{0x5a}, size)
			oversized := bytes.Repeat([]byte{0x6b}, 6000)
			wire4 := build(t, core, remoteID, conn.sessionID, 1, addr4.String(), exact, 0)
			wire6 := build(t, core, remoteID, conn.sessionID, 2, addr6.String(), exact, 1024)
			wireOversized := build(t, core, remoteID, conn.sessionID, 3, addr6.String(), oversized, 1024)
			bad := bytes.Clone(wire6)
			bad[len(bad)-1] ^= 1
			underlay.readBufs = [][]byte{
				wire4, bad, wire6, wireOversized, wireOversized,
				build(t, core, remoteID, conn.sessionID, 4, addr4.String(), exact, 0),
			}

			assertRead := func(buf []byte, wantAddr netip.AddrPort) {
				t.Helper()
				n, addr, err := conn.ReadFrom(buf)
				if err != nil || n != size || addr != wantAddr || !bytes.Equal(buf[:n], exact) {
					t.Fatalf("ReadFrom: n=%d addr=%v err=%v, want %d bytes from %v", n, addr, err, size, wantAddr)
				}
			}
			buf := make([]byte, size)
			assertRead(buf, addr4)
			if n, _, err := conn.ReadFrom(buf); n != 0 || err == nil || stderrors.Is(err, io.ErrShortBuffer) {
				t.Fatalf("ReadFrom tampered datagram: n=%d err=%v, want authentication error", n, err)
			}
			assertRead(buf, addr6)
			n, addr, err := conn.ReadFrom(buf)
			var dropped *netproxy.ErrDatagramDropped
			if n != 0 || addr != addr6 || !stderrors.As(err, &dropped) || !stderrors.Is(err, io.ErrShortBuffer) {
				t.Fatalf("ReadFrom oversized datagram: n=%d addr=%v err=%v, want typed short-buffer drop from %v", n, addr, err, addr6)
			}
			if n, _, err := conn.ReadFrom(buf); n != 0 || !stderrors.Is(err, protocol.ErrReplayAttack) {
				t.Fatalf("ReadFrom replayed datagram: n=%d err=%v, want replay error", n, err)
			}
			assertRead(make([]byte, 65536), addr4)
		})
	}
}

// TestUdpConn_ReadFromEmptyPayloadIsADatagram pins the empty-body contract: a
// server datagram whose framing header and address consumed the entire
// payload decodes as a zero-length datagram with its address, not as an
// error. io.EOF from the empty read used to retire the whole UDP endpoint.
func TestUdpConn_ReadFromEmptyPayloadIsADatagram(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}

	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x23
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	localSessionID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	remoteSessionID := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	wantAddr := netip.MustParseAddrPort("203.0.113.9:853")

	packet := buildServerPacket(t, core, remoteSessionID, localSessionID, 1, wantAddr.String(), nil)
	conn, err := NewUdpConn(&udpReadBufferConn{packet: packet}, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.sessionID = localSessionID

	buf := make([]byte, 128)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom of an empty-payload datagram: %v", err)
	}
	if n != 0 {
		t.Fatalf("payload length = %d, want 0", n)
	}
	if addr != wantAddr {
		t.Fatalf("unexpected addr: got %v want %v", addr, wantAddr)
	}
}
