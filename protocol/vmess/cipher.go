package vmess

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KDFSaltConstAuthIDEncryptionKey             = "AES Auth ID Encryption"
	KDFSaltConstAEADRespHeaderLenKey            = "AEAD Resp Header Len Key"
	KDFSaltConstAEADRespHeaderLenIV             = "AEAD Resp Header Len IV"
	KDFSaltConstAEADRespHeaderPayloadKey        = "AEAD Resp Header Key"
	KDFSaltConstAEADRespHeaderPayloadIV         = "AEAD Resp Header IV"
	KDFSaltConstVMessAEADKDF                    = "VMess AEAD KDF"
	KDFSaltConstVMessHeaderPayloadAEADKey       = "VMess Header AEAD Key"
	KDFSaltConstVMessHeaderPayloadAEADIV        = "VMess Header AEAD Nonce"
	KDFSaltConstVMessHeaderPayloadLengthAEADKey = "VMess Header AEAD Key_Length"
	KDFSaltConstVMessHeaderPayloadLengthAEADIV  = "VMess Header AEAD Nonce_Length"
)

type BytesGenerator func() []byte

// fnv32aPool mirrors shadowsocks' fnv32aPool: the checksummer is per-chunk in
// ss but per-connection-header here, and pooling keeps the dial hot path
// allocation-free either way.
var fnv32aPool = sync.Pool{New: func() any { return fnv.New32a() }}

// ChunkSizeEncoder is a utility class to encode size value into bytes.
type ChunkSizeEncoder interface {
	SizeBytes() int32
	Encode(uint16, []byte) []byte
}

// ChunkSizeDecoder is a utility class to decode size value from bytes.
type ChunkSizeDecoder interface {
	SizeBytes() int32
	Decode([]byte) (uint16, error)
}

type Cipher string

const (
	CipherC20P1305  Cipher = "chacha20-poly1305"
	CipherAES128GCM Cipher = "aes-128-gcm"
)

const (
	OptionChunkStream        = 1
	OptionChunkLengthMasking = 4
	OptionGlobalPadding      = 8
)

func ContainOption(options byte, option byte) bool {
	return options&option == option
}

func ParseCipherFromSecurity(security byte) (Cipher, error) {
	switch security {
	case 4:
		return CipherC20P1305, nil
	case 3:
		return CipherAES128GCM, nil
	default:
		return "", fmt.Errorf("unexpected security: %v", security)
	}
}

func (c Cipher) ToSecurity() byte {
	switch c {
	case CipherC20P1305:
		return 4
	case CipherAES128GCM:
		return 3
	default:
		//log.Warn("unexpected cipher: %v", c)
		return CipherAES128GCM.ToSecurity()
	}
}

var (
	NewCipherMapper = map[Cipher]func(key []byte) (cipher.AEAD, error){
		CipherC20P1305:  NewC20P1305,
		CipherAES128GCM: NewAesGcm,
	}
)

type hMacCreator struct {
	parent *hMacCreator
	value  []byte
}

func (h *hMacCreator) Create() hash.Hash {
	if h.parent == nil {
		return hmac.New(sha256.New, h.value)
	}
	return hmac.New(h.parent.Create, h.value)
}

// kdfReference is the original nested-hmac KDF construction. It stays as the
// semantic reference for the allocation-free KDF below (differential tests
// pin the two together) and remains the fallback for chains deeper than
// kdfMaxChainLen, which no production call site reaches.
func kdfReference(key []byte, path ...[]byte) []byte {
	hmacCreator := &hMacCreator{value: []byte(KDFSaltConstVMessAEADKDF)}
	for _, v := range path {
		hmacCreator = &hMacCreator{value: []byte(v), parent: hmacCreator}
	}
	hmacf := hmacCreator.Create()
	hmacf.Write(key)
	return hmacf.Sum(nil)
}

// kdfMaxChainLen bounds the stack-node fast path. Production call sites use
// at most three path elements (chain depth 4): the request/response headers
// and the auth-ID fallback decryptor.
const kdfMaxChainLen = 8

// kdfMaxKeyLen bounds the stack-scratch fast path. The vmess key material is
// 16 bytes everywhere; longer keys fall back to the reference construction.
const kdfMaxKeyLen = 256

// kdfScratchSize budgets the concat buffer for the worst chain: the message
// grows by one pad (64B) per level, so a chain of L levels over a K-byte key
// consumes 64*L*(L+1)/2 + K*L bytes.
const kdfScratchSize = kdfMaxChainLen*(kdfMaxChainLen+1)/2*sha256.BlockSize + kdfMaxChainLen*kdfMaxKeyLen

// kdfChainNode is one level of the nested-HMAC tree: an HMAC keyed with padKey
// whose underlying hash is the child level's HMAC (sha256 at the bottom). The
// pads follow RFC 2104 with sha256's 64-byte block size.
type kdfChainNode struct {
	iPad, oPad [sha256.BlockSize]byte
	child      *kdfChainNode // nil => sha256 leaf
}

func kdfChainNodeWithKey(n *kdfChainNode, key []byte, child *kdfChainNode, buf []byte) {
	n.child = child
	k := key
	if len(k) > sha256.BlockSize {
		// RFC 2104 hashes over-sized keys with the underlying hash; the
		// reference (crypto/hmac) does exactly that through the parent
		// chain, so route the pre-hash through the child level instead of
		// a bare sha256 or the trees diverge.
		var d [sha256.Size]byte
		if child == nil {
			d = sha256.Sum256(k)
		} else {
			d = child.sum(k, buf)
		}
		k = d[:]
	}
	for i := range n.iPad {
		var b byte
		if i < len(k) {
			b = k[i]
		}
		n.iPad[i] = b ^ 0x36
		n.oPad[i] = b ^ 0x5c
	}
}

// sum evaluates HMAC_(this node's key, child hash)(msg) and returns the
// digest by value (no heap). buf holds the scratch for this level's
// pad||msg concat; the child level gets buf[len(s):] so its own concat
// never overlaps a message it still has to read (the message grows by one
// pad per level down the tree). Digests stay in value semantics end to
// end: routing one through a hash.Hash interface (h.Sum(out[:0])) makes
// the compiler heap-allocate the output, which is exactly the churn this
// evaluator exists to remove.
func (n *kdfChainNode) sum(msg, buf []byte) [sha256.Size]byte {
	s := buf[:0]
	s = append(s, n.iPad[:]...)
	s = append(s, msg...)
	var inner [sha256.Size]byte
	if n.child == nil {
		inner = sha256.Sum256(s)
	} else {
		inner = n.child.sum(s, buf[len(s):])
	}
	s = buf[:0]
	s = append(s, n.oPad[:]...)
	s = append(s, inner[:]...)
	if n.child == nil {
		return sha256.Sum256(s)
	}
	return n.child.sum(s, buf[len(s):])
}

// KDF derives keys exactly like kdfReference: level 0 is
// HMAC(sha256, KDFSaltConstVMessAEADKDF), each path element adds one HMAC
// level keyed with that element, and the vmess key is written into the final
// HMAC. The reference builds every tree node with hmac.New, which evaluates
// 2^(len(path)+1)-1 constructors and turns each handshake into ~250 heap
// objects; this evaluator walks the identical tree with nodes on the
// caller's stack and sha256 states from a pool, so a derivation allocates
// only its result slice.
func KDF(key []byte, path ...[]byte) []byte {
	if len(path) == 0 || len(path) >= kdfMaxChainLen || len(key) > kdfMaxKeyLen {
		return kdfReference(key, path...)
	}
	var nodes [kdfMaxChainLen]kdfChainNode
	var buf [kdfScratchSize]byte
	kdfChainNodeWithKey(&nodes[0], []byte(KDFSaltConstVMessAEADKDF), nil, buf[:])
	for i, v := range path {
		kdfChainNodeWithKey(&nodes[i+1], v, &nodes[i], buf[:])
	}
	out := nodes[len(path)].sum(key, buf[:])
	return out[:]
}

// authIDEncBlockCache memoizes the AES block cipher derived from
// KDF(cmdKey, KDFSaltConstAuthIDEncryptionKey). The derivation depends only
// on the credential, but PutEAuthID used to redo the whole nested-hmac chain
// (plus an aes key schedule) on every connection. Bounded by the number of
// configured vmess accounts; aes.Block.Encrypt is stateless and safe to
// share across connections.
var authIDEncBlockCache sync.Map // map[string]cipher.Block

func authIDEncBlock(cmdKey []byte) (cipher.Block, error) {
	if blk, ok := authIDEncBlockCache.Load(string(cmdKey)); ok {
		return blk.(cipher.Block), nil
	}
	blk, err := aes.NewCipher(KDF(cmdKey, []byte(KDFSaltConstAuthIDEncryptionKey))[:16])
	if err != nil {
		return nil, err
	}
	authIDEncBlockCache.Store(string(cmdKey), blk)
	return blk, nil
}

func PutEAuthID(dst []byte, cmdKey []byte) []byte {
	binary.BigEndian.PutUint64(dst[:8], uint64(time.Now().Unix()))
	_, _ = fastrand.Read(dst[8:12])
	binary.BigEndian.PutUint32(dst[12:], crc32.ChecksumIEEE(dst[:12]))
	blk, err := authIDEncBlock(cmdKey)
	if err != nil {
		// Unreachable for 16-byte keys; keep the failure loud rather than
		// silently emitting an unencrypted auth ID.
		panic("vmess: derive auth ID encryption block: " + err.Error())
	}
	blk.Encrypt(dst[:16], dst[:16])
	return dst[:16]
}

func ReqInstructionDataFromPool(metadata Metadata) []byte {
	P := fastrand.Intn(1 << 4)
	// 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + metadata.AddrLen() + P + 4
	buf := pool.Get(metadata.AddrLen() + P + 45)
	buf[0] = 1                      // version
	_, _ = fastrand.Read(buf[1:34]) // random IV(16), Key(16), V(1)
	// https://github.com/v2fly/v2ray-core/blob/a66bb28aee661caa191b5746ba4915eb99e12c59/proxy/vmess/outbound/outbound.go#L112
	//buf[34] = OptionChunkStream | OptionChunkLengthMasking | OptionGlobalPadding
	buf[34] = OptionChunkStream | OptionChunkLengthMasking | OptionGlobalPadding
	// https://github.com/v2fly/v2ray-core/blob/054e6679830885c94cc37d27ab2aa96b5b37e019/common/protocol/headers.pb.go#L37
	buf[35] = byte(P)<<4 | Cipher(metadata.Cipher).ToSecurity()
	buf[36] = 0                                           // Reserved
	buf[37] = NetworkToByte(metadata.Network)             // TCP/UDP
	binary.BigEndian.PutUint16(buf[38:40], metadata.Port) // Port
	buf[40] = MetadataTypeToByte(metadata.Type)           // Address Type
	metadata.PutAddr(buf[41:])                            // Address
	// The P-byte padding between the address and the FNV1a checksum is part of
	// the wire layout and must be given a definite value. pool.Get does not
	// zero, and this region was previously left untouched, so up to 15 bytes of
	// uninitialized pool residue went out on every connection (a per-connection
	// nondeterministic byte pattern the server can see). RespHeaderFromPool
	// already fills its padding; this is the request-side counterpart.
	padding := buf[41+metadata.AddrLen() : 41+metadata.AddrLen()+P]
	_, _ = fastrand.Read(padding)
	n := len(buf) - 4
	h := fnv32aPool.Get().(hash.Hash32)
	h.Reset()
	h.Write(buf[:n])
	binary.BigEndian.PutUint32(buf[n:], h.Sum32()) // FNV1a
	fnv32aPool.Put(h)
	return buf
}

func EncryptReqHeaderFromPool(instruction []byte, cmdKey []byte) ([]byte, error) {
	buf := pool.Get(58 + len(instruction)) // EAuthID(16) + length(2) + tag(16) + nonce(8) + len(instruction) + tag(16)
	eAuthID := PutEAuthID(buf, cmdKey)
	connectionNonce := buf[34:42] // 16+2+16
	_, _ = fastrand.Read(connectionNonce)

	gcm, err := NewAesGcm(KDF(cmdKey, []byte(KDFSaltConstVMessHeaderPayloadLengthAEADKey), eAuthID, connectionNonce)[:16])
	if err != nil {
		pool.Put(buf)
		return nil, err
	}
	binary.BigEndian.PutUint16(buf[16:18], uint16(len(instruction)))
	gcm.Seal(buf[16:16], KDF(cmdKey, []byte(KDFSaltConstVMessHeaderPayloadLengthAEADIV), eAuthID, connectionNonce)[:12], buf[16:18], eAuthID)

	gcm, err = NewAesGcm(KDF(cmdKey, []byte(KDFSaltConstVMessHeaderPayloadAEADKey), eAuthID, connectionNonce)[:16])
	if err != nil {
		pool.Put(buf)
		return nil, err
	}
	copy(buf[42:], instruction) // 16+2+16+8
	gcm.Seal(buf[42:42], KDF(cmdKey, []byte(KDFSaltConstVMessHeaderPayloadAEADIV), eAuthID, connectionNonce)[:12], instruction, eAuthID)

	return buf, nil
}

func RespHeaderFromPool(V byte) []byte {
	buf := pool.GetZero(4) // V(1)+Option(1)+Cmd(1)+InstructionLen(1)
	buf[0] = V
	// no instruction data
	return buf
}

func NewAesGcm(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// GenerateChacha20Poly1305Key generates a 32-byte key from a given 16-byte array.
func GenerateChacha20Poly1305KeyFromPool(b []byte) []byte {
	key := pool.Get(32)
	t := md5.Sum(b)
	copy(key, t[:])
	t = md5.Sum(key[:16])
	copy(key[16:], t[:])
	return key
}

func NewC20P1305(key []byte) (cipher.AEAD, error) {
	if len(key) == 16 {
		key = GenerateChacha20Poly1305KeyFromPool(key)
		defer pool.Put(key)
	}
	return chacha20poly1305.New(key)
}
