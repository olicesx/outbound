package vmess

import (
	"bytes"
	"math/rand"
	"testing"
)

// TestKDFMatchesReference pins the allocation-free KDF evaluator to the
// original nested-hmac construction byte for byte. Both are deterministic,
// so random vectors over every reachable chain depth plus the long-key
// branches give full-path coverage.
func TestKDFMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	keySizes := []int{16, 32, 48, 64, 65, 100}
	elemSizes := []int{0, 1, 8, 16, 31, 64, 65, 200}
	for depth := 1; depth < kdfMaxChainLen; depth++ {
		for i := 0; i < 200; i++ {
			key := make([]byte, keySizes[rng.Intn(len(keySizes))])
			rng.Read(key)
			path := make([][]byte, depth)
			for j := range path {
				path[j] = make([]byte, elemSizes[rng.Intn(len(elemSizes))])
				rng.Read(path[j])
			}
			want := kdfReference(key, path...)
			got := KDF(key, path...)
			if !bytes.Equal(want, got) {
				t.Fatalf("KDF mismatch at depth=%d keyLen=%d: want %x got %x", depth, len(key), want, got)
			}
		}
	}
	// The exact production shapes, with the real salt constants.
	prodKey := make([]byte, 16)
	rng.Read(prodKey)
	shapes := [][][]byte{
		{[]byte(KDFSaltConstAuthIDEncryptionKey)},
		{[]byte(KDFSaltConstAEADRespHeaderLenKey)},
		{[]byte(KDFSaltConstAEADRespHeaderPayloadIV)},
		{[]byte(KDFSaltConstVMessHeaderPayloadLengthAEADKey), prodKey[:16], prodKey[:8]},
		{[]byte(KDFSaltConstVMessHeaderPayloadLengthAEADIV), prodKey[:16], prodKey[:8]},
		{[]byte(KDFSaltConstVMessHeaderPayloadAEADKey), prodKey[:16], prodKey[:8]},
		{[]byte(KDFSaltConstVMessHeaderPayloadAEADIV), prodKey[:16], prodKey[:8]},
	}
	for i, path := range shapes {
		want := kdfReference(prodKey, path...)
		got := KDF(prodKey, path...)
		if !bytes.Equal(want, got) {
			t.Fatalf("production shape %d mismatch: want %x got %x", i, want, got)
		}
	}
	// Path len 0 and >= kdfMaxChainLen must route through the reference.
	if !bytes.Equal(KDF(prodKey), kdfReference(prodKey)) {
		t.Fatal("empty path mismatch")
	}
	deep := make([][]byte, kdfMaxChainLen)
	for j := range deep {
		deep[j] = []byte{byte(j)}
	}
	if !bytes.Equal(KDF(prodKey, deep...), kdfReference(prodKey, deep...)) {
		t.Fatal("deep path mismatch")
	}
}

func BenchmarkKDF(b *testing.B) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	eAuthID := make([]byte, 16)
	nonce := make([]byte, 8)
	path := [][]byte{[]byte(KDFSaltConstVMessHeaderPayloadAEADKey), eAuthID, nonce}
	b.Run("reference", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = kdfReference(key, path...)
		}
	})
	b.Run("pooled", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = KDF(key, path...)
		}
	})
}
