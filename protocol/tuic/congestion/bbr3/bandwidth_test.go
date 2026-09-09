package bbr3

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

func TestBandwidthFromDelta(t *testing.T) {
	if got := bandwidthFromDelta(1200, 100*time.Millisecond); got != 12000 {
		t.Fatalf("rate = %d, want 12000", got)
	}
	if got := bandwidthFromDelta(0, time.Second); got != 0 {
		t.Fatalf("zero bytes must give zero rate, got %d", got)
	}
	if got := bandwidthFromDelta(1200, 0); got != 0 {
		t.Fatalf("zero delta must give zero rate, got %d", got)
	}
}

func TestBdpFrom(t *testing.T) {
	if got := bdpFrom(1_000_000, 100*time.Millisecond); got != 100_000 {
		t.Fatalf("bdp = %d, want 100000", got)
	}
	if got := bdpFrom(0, time.Second); got != 0 {
		t.Fatalf("zero bandwidth must give zero bdp, got %d", got)
	}
	if got := bdpFrom(1_000_000, 0); got != 0 {
		t.Fatalf("zero rtt must give zero bdp, got %d", got)
	}
}

func TestRoundFilterKeepsMaxInsideWindow(t *testing.T) {
	f := newRoundFilter(2)
	f.Update(100, 1)
	f.Update(300, 1)
	f.Update(200, 2)
	if got := f.Max(2); got != 300 {
		t.Fatalf("max = %d, want 300", got)
	}
	// Round 4 still holds the round-2 sample (window 2); round 5 evicts it.
	if got := f.Max(4); got != 200 {
		t.Fatalf("max at round 4 = %d, want 200", got)
	}
	if got := f.Max(5); got != 0 {
		t.Fatalf("max after window expiry = %d, want 0", got)
	}
}

func TestRoundFilterIgnoresZeroSamples(t *testing.T) {
	f := newRoundFilter(2)
	f.Update(0, 1)
	f.Update(500, 1)
	if got := f.Max(1); got != 500 {
		t.Fatalf("max = %d, want 500", got)
	}
	if len(f.samples) != 1 {
		t.Fatalf("zero sample was stored: %d samples", len(f.samples))
	}
}

func TestRoundFilterReset(t *testing.T) {
	f := newRoundFilter(2)
	f.Update(100, 1)
	f.Reset()
	if got := f.Max(1); got != 0 {
		t.Fatalf("max after reset = %d, want 0", got)
	}
}

func TestSamplerProducesRateAndAccumulatesDelivery(t *testing.T) {
	s := newSampler(64)
	t0 := time.Now()
	s.onPacketSent(t0, 1, 1200, 1200, false)
	s.onPacketSent(t0.Add(10*time.Millisecond), 2, 1200, 2400, false)

	rate, ok := s.onPacketAcked(t0.Add(100*time.Millisecond), 1)
	if !ok {
		t.Fatal("no sample for a recorded packet")
	}
	if rate != 12000 {
		t.Fatalf("rate = %d, want 12000", rate)
	}
	if got := s.deliveredVolume(); got != 1200 {
		t.Fatalf("delivered = %d, want 1200", got)
	}
	if _, ok := s.onPacketAcked(t0.Add(200*time.Millisecond), 1); ok {
		t.Fatal("acking the same packet twice must not produce a second sample")
	}
}

func TestSamplerUnknownPacketHasNoSample(t *testing.T) {
	s := newSampler(64)
	if _, ok := s.onPacketAcked(time.Now(), 42); ok {
		t.Fatal("unknown packet produced a sample")
	}
}

func TestSamplerLostPacketDropsState(t *testing.T) {
	s := newSampler(64)
	t0 := time.Now()
	s.onPacketSent(t0, 7, 1200, 1200, false)
	s.onPacketLost(7)
	if _, ok := s.onPacketAcked(t0.Add(time.Second), 7); ok {
		t.Fatal("lost packet still produced a sample")
	}
}

func TestSamplerBoundsRetainedState(t *testing.T) {
	const window = 16
	s := newSampler(window)
	t0 := time.Now()
	for i := 0; i < window*8; i++ {
		s.onPacketSent(t0, congestion.PacketNumber(i), 1200, 1200, false)
	}
	if len(s.states) > window+window/4 {
		t.Fatalf("retained %d packet states, want at most %d", len(s.states), window+window/4)
	}
}
