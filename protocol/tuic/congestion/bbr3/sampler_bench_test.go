package bbr3

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// The sampler runs on the data plane: onPacketSent once per sent packet and one
// onPacketAcked per acked packet. Both must be allocation-free; a map entry per
// packet (the previous implementation) cost one allocation per packet plus a
// slice copy per eviction.
//
// Both benchmarks drive a sliding packet-number window so the ring rebases and
// evicts, which is the path the old eviction slice copy sat on.

func BenchmarkOnPacketSent(b *testing.B) {
	const window = 4096
	s := newSampler(window)
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.onPacketSent(now, congestion.PacketNumber(i), 1200, 1200, false)
	}
}

func BenchmarkAckEvent(b *testing.B) {
	const window = 4096
	s := newSampler(window)
	now := time.Now()
	// Prime the ring with a full window of in-flight packets.
	for i := 0; i < window; i++ {
		s.onPacketSent(now, congestion.PacketNumber(i), 1200, 1200, false)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pn := congestion.PacketNumber(i)
		s.onPacketSent(now, pn, 1200, 1200, false)
		s.onPacketAcked(now.Add(time.Millisecond), pn)
	}
}

// TestSamplerSendAndAckAreAllocationFree asserts the property the benchmarks
// measure, so a regression fails the suite and not just a benchmark comparison.
func TestSamplerSendAndAckAreAllocationFree(t *testing.T) {
	const window = 1024
	s := newSampler(window)
	now := time.Now()

	allocs := testing.AllocsPerRun(1000, func() {
		pn := congestion.PacketNumber(1)
		s.onPacketSent(now, pn, 1200, 1200, false)
		if _, ok := s.onPacketAcked(now.Add(time.Millisecond), pn); !ok {
			t.Fatal("ack produced no sample")
		}
	})
	if allocs != 0 {
		t.Fatalf("send+ack cycle allocated %v times, want 0", allocs)
	}

	// Eviction through a rebasing window must not allocate either.
	allocs = testing.AllocsPerRun(1000, func() {
		for i := 0; i < 2; i++ {
			s.onPacketSent(now, congestion.PacketNumber(window*3+i), 1200, 1200, false)
		}
	})
	if allocs != 0 {
		t.Fatalf("eviction path allocated %v times, want 0", allocs)
	}
}
