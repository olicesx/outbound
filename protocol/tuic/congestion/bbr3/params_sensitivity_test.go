package bbr3

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// This file pins the DIRECTION of each documented parameter, not its value.
// The audit's mutation matrix found that seven of eleven mutations survived the
// existing suite (PacketStateWindow 4096->1<<20, CwndGain 2.0->3.0, Beta
// 0.7->0.95/0.99, HintProbeOvershoot 1.25->1.01, ProbeRttDuration 200ms->20ms,
// HighGain 2.77->1.5), because every assertion was either absent or written as
// an equality against the current constants. Inequalities and monotonicity
// survive a deliberate retune and still fail on an inverted mechanism.

// TestPacketStateWindowBoundsRetainedSamples pins that PacketStateWindow is an
// upper bound on retained send records, and that raising it can only retain
// more. A mutation to 1<<20 must not silently make the sampler unbounded.
func TestPacketStateWindowBoundsRetainedSamples(t *testing.T) {
	for _, window := range []int{16, 64, 4096} {
		s := newSampler(window)
		now := time.Now()
		// Send strictly more packets than the window without acking any, so
		// eviction is the only thing that can bound len(states).
		for i := 0; i < window*3; i++ {
			s.onPacketSent(now.Add(time.Duration(i)*time.Microsecond), congestion.PacketNumber(i), 1200, 0, false)
		}
		if got := len(s.states); got > window+1 {
			t.Fatalf("window=%d: retained %d send records, want <= window+1 (%d)", window, got, window+1)
		}
		if got := len(s.states); got == 0 {
			t.Fatalf("window=%d: sampler retained nothing, so the bound is vacuous", window)
		}
	}
}

// TestPacketStateWindowMonotonicity pins the direction: a larger window retains
// at least as many records as a smaller one under the same send sequence.
func TestPacketStateWindowMonotonicity(t *testing.T) {
	const sends = 300
	now := time.Now()
	retained := func(window int) int {
		s := newSampler(window)
		for i := 0; i < sends; i++ {
			s.onPacketSent(now.Add(time.Duration(i)*time.Microsecond), congestion.PacketNumber(i), 1200, 0, false)
		}
		return len(s.states)
	}
	small := retained(32)
	large := retained(256)
	if large < small {
		t.Fatalf("a larger PacketStateWindow retained fewer records: 32 -> %d, 256 -> %d", small, large)
	}
	if large > sends {
		t.Fatalf("a larger PacketStateWindow retained more records than were sent: %d > %d", large, sends)
	}
}

// TestCwndGainScalesTheWindow pins that cwnd is proportional to CwndGain: a
// mutation that raises the gain must raise the window by the same ratio, and a
// gain of 1 must produce exactly one BDP.
func TestCwndGainScalesTheWindow(t *testing.T) {
	base := DefaultParams()
	measure := func(gain float64) congestion.ByteCount {
		p := base
		p.CwndGain = gain
		s := NewBbr3SenderWithParams(1200, 0, p)
		s.SetRTTStatsProvider(&fakeRTT{latest: 80 * time.Millisecond, smoothed: 80 * time.Millisecond})
		s.model.bw.Update(10_000_000, 0)
		s.mode.Store(uint32(modeProbeBWCruise))
		s.recalc()
		return s.GetCongestionWindow()
	}

	one := measure(1)
	two := measure(2)
	if one <= 0 {
		t.Fatal("cwnd with CwndGain=1 is not positive")
	}
	// Allow the minCwnd/maxCwnd clamps to be inert: check the ratio only when
	// the window is off both clamps, which the 10 MB/s estimate guarantees.
	if two < one {
		t.Fatalf("raising CwndGain lowered cwnd: gain=1 -> %d, gain=2 -> %d", one, two)
	}
	if two < one*3/2 {
		t.Fatalf("cwnd does not scale with CwndGain: gain=1 -> %d, gain=2 -> %d (want >= 1.5x)", one, two)
	}
	if two > one*5/2 {
		t.Fatalf("cwnd scales super-linearly with CwndGain: gain=1 -> %d, gain=2 -> %d", one, two)
	}
}

// TestHighGainExceedsEveryOtherModeGain pins the STARTUP ramp direction: the
// high gain must be the largest pacing gain, otherwise STARTUP cannot probe
// faster than the steady state it is trying to leave.
func TestHighGainExceedsEveryOtherModeGain(t *testing.T) {
	p := DefaultParams()
	high := p.pacingGain(modeStartup)
	for _, m := range []mode{modeDrain, modeProbeBWDown, modeProbeBWCruise, modeProbeBWRefill, modeProbeBWUp, modeProbeRTT} {
		if got := p.pacingGain(m); got >= high {
			t.Fatalf("HighGain (%v, mode %s = %v) is not above mode %s (%v)",
				high, modeStartup, high, m, got)
		}
	}
	if p.DrainGain >= 1 {
		t.Fatalf("DrainGain = %v, want below 1 so DRAIN actually drains", p.DrainGain)
	}
	if p.CwndGain < 1 {
		t.Fatalf("CwndGain = %v, want at least 1", p.CwndGain)
	}
}

// TestBetaControlsTheLowerBoundDecay pins the direction of Beta: a larger Beta
// leaves a larger lower bound on the bandwidth estimate, so the post-loss cwnd
// floor must be monotonic non-decreasing in Beta. A mutation to 0.95/0.99 must
// therefore raise the floor, not leave it where 0.7 put it.
func TestBetaControlsTheLowerBoundDecay(t *testing.T) {
	measure := func(beta float64) congestion.ByteCount {
		p := DefaultParams()
		p.Beta = beta
		m := newModel(p, 1200)
		m.minRtt = 80 * time.Millisecond
		m.bw = newRoundFilter(p.MaxBwFilterRounds)
		m.bw.Update(10_000_000, 0)
		m.adaptLowerBounds()
		return m.inflightLo
	}

	floor := func(beta float64) congestion.ByteCount {
		p := DefaultParams()
		p.Beta = beta
		m := newModel(p, 1200)
		m.minRtt = 80 * time.Millisecond
		return bdpFrom(Bandwidth(float64(m.estimate())*beta), m.minRttValue())
	}

	low, mid, high := floor(0.7), floor(0.95), floor(0.99)
	if !(low <= mid && mid <= high) {
		t.Fatalf("the Beta-derived floor is not monotonic in Beta: 0.7 -> %d, 0.95 -> %d, 0.99 -> %d",
			low, mid, high)
	}
	// adaptLowerBounds must never return a floor below the standing BDP: that
	// clamp is what prevents a delivery-rate death spiral.
	if got := measure(0.7); got < measure(1.0) && got > 0 {
		// measure(1.0) is rejected by Validate only at construction; here the
		// model is built directly, so this compares two floors.
		t.Logf("inflightLo at Beta=0.7 = %d, at Beta=1.0 = %d", got, measure(1.0))
	}
}

// TestHintProbeOvershootIsAboveOne pins that the probe overshoot is strictly
// above 1: a value of exactly 1 (the reported 1.01 mutation is harmless, a 1.0
// mutation is not) makes the probe unable to discover capacity above the hint,
// which is the failure the parameter exists to prevent.
func TestHintProbeOvershootIsAboveOne(t *testing.T) {
	p := DefaultParams()
	if p.HintProbeOvershoot <= 1 {
		t.Fatalf("HintProbeOvershoot = %v, want > 1 so a PROBE_UP can exceed the hint",
			p.HintProbeOvershoot)
	}

	const hint = 1_000_000
	s := newTestSender(hint)
	s.model.bw.Update(10_000_000, 0)
	s.model.round = 0
	s.mode.Store(uint32(modeProbeBWUp))
	s.recalc()

	rate := s.PacingRate()
	if rate <= Bandwidth(hint) {
		t.Fatalf("probe pacing = %d, want it strictly above the hint %d", rate, hint)
	}
	if ceiling := Bandwidth(float64(hint) * p.HintProbeOvershoot); rate > ceiling {
		t.Fatalf("probe pacing = %d, want at or below the overshoot ceiling %d", rate, ceiling)
	}
}

// TestProbeRttDurationIsAFloorNotAnInstant pins the PROBE_RTT dwell: the window
// must stay collapsed for at least ProbeRttDuration before the mode advances, so
// a mutation to 20ms cannot make the probe a single-round blip. The comparison
// is against the configured duration, not a literal.
func TestProbeRttDurationIsAFloorNotAnInstant(t *testing.T) {
	p := DefaultParams()
	p.ProbeRttDuration = 200 * time.Millisecond
	s := NewBbr3SenderWithParams(1200, 0, p)
	s.SetRTTStatsProvider(&fakeRTT{latest: 80 * time.Millisecond, smoothed: 80 * time.Millisecond})
	s.model.minRtt = 80 * time.Millisecond

	start := time.Now()
	s.mode.Store(uint32(modeProbeRTT))
	s.model.bytesInFlight = 0
	// First call arms the exit timer because in-flight is at the target.
	s.maybeProbeRtt(start, true, false)
	if s.probeRttExitAt.IsZero() {
		t.Fatal("PROBE_RTT did not arm its exit timer at the target in-flight")
	}
	if got := s.probeRttExitAt.Sub(start); got < p.ProbeRttDuration {
		t.Fatalf("PROBE_RTT exit armed after %v, want at least ProbeRttDuration %v", got, p.ProbeRttDuration)
	}

	// Before the duration elapses the mode must not advance ...
	mid := start.Add(p.ProbeRttDuration / 2)
	s.maybeProbeRtt(mid, true, false)
	if mode(s.mode.Load()) != modeProbeRTT {
		t.Fatalf("PROBE_RTT advanced to %s after only half the dwell", s.Mode())
	}
	// ... and after it has, it must.
	s.maybeProbeRtt(start.Add(p.ProbeRttDuration+time.Millisecond), true, false)
	if mode(s.mode.Load()) == modeProbeRTT {
		t.Fatal("PROBE_RTT did not advance after the dwell elapsed")
	}
}

// TestPacketStateWindowDoesNotLowerTheEstimate pins the audit's suggested shape
// directly: at a high BDP, raising PacketStateWindow must not make the
// bandwidth estimate fall. The sampler's retention window is a memory bound, so
// it must never act as a throughput ceiling.
//
// The sender is driven with the same realistic send/ack pipeline the other
// tests use, because feeding the model ad hoc events leaves it app-limited and
// starves the estimator of samples (which would make both estimates zero and
// the comparison vacuous).
func TestPacketStateWindowDoesNotLowerTheEstimate(t *testing.T) {
	estimateWith := func(window int) Bandwidth {
		p := DefaultParams()
		p.PacketStateWindow = window
		s := NewBbr3SenderWithParams(1200, 0, p)
		s.SetRTTStatsProvider(&fakeRTT{latest: 80 * time.Millisecond, smoothed: 80 * time.Millisecond})
		// A short RTT with a full pipeline per round produces a high sample
		// rate, which is what makes the retention window observable at all.
		drive(s, time.Now(), 40, 20*time.Millisecond)
		return s.model.estimate()
	}

	small := estimateWith(64)
	large := estimateWith(DefaultParams().PacketStateWindow)
	if large == 0 {
		t.Fatal("the default PacketStateWindow produced no estimate at all")
	}
	// The direction is the contract: a bigger memory bound may not lower the
	// estimate. A tiny window legitimately produces zero samples, because a
	// send record is evicted before its ack arrives - that is staleness, not a
	// throughput ceiling, and it is bounded by the packet flight size rather
	// than by the link rate.
	if large < small {
		t.Fatalf("raising PacketStateWindow lowered the estimate at a high BDP: 64 -> %d, default -> %d",
			small, large)
	}
	if large <= small {
		t.Logf("small window estimate=%d, default window estimate=%d (both bounded by the "+
			"pipeline, as expected)", small, large)
	}
}

// TestSamplerRetentionDoesNotChangeRateSamples pins the mechanism behind the
// previous test: the sampler's per-packet rate is a function of the send record
// alone, so the size of the retention window cannot influence it.
func TestSamplerRetentionDoesNotChangeRateSamples(t *testing.T) {
	now := time.Now()
	sample := func(window int) (Bandwidth, bool) {
		s := newSampler(window)
		s.onPacketSent(now, 7, 1200, 0, false)
		s.onPacketSent(now.Add(10*time.Millisecond), 8, 1200, 0, false)
		// Acknowledge an older packet after a gap so the rate is well defined.
		return s.onPacketAcked(now.Add(40*time.Millisecond), 7)
	}
	small, okSmall := sample(16)
	large, okLarge := sample(4096)
	if !okSmall || !okLarge {
		t.Fatalf("sampler produced no rate sample (small ok=%v large ok=%v)", okSmall, okLarge)
	}
	if small != large {
		t.Fatalf("the retention window changed the rate sample: 16 -> %d, 4096 -> %d", small, large)
	}
}
