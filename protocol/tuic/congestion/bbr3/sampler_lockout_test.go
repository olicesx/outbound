package bbr3

// sampler_lockout_test.go pins the registration invariant the sampler broke.
// A slot is indexed by pn % len(states), so it holds either that packet number's
// own record or a stale record that has left the sampler's window - and an
// occupied slot may only be read as "this packet number is already tracked" when
// it really is that packet number. When a ring wrap-around was read as a resend
// instead (the reproduction measured registeredPn=4120 across 10528 sends), the
// sampler stopped taking samples, the bandwidth estimate fell to zero, and the
// sender parked at its floors: cwnd=5120 B, pacing=65536 B/s.
//
// The cases are ported from the throwaway reproduction kept under /tmp during
// the diagnosis, with the assertions inverted: the reproduction pinned the bug,
// these pin its absence. sampler_loopback_test.go exercises the same span on a
// real quic-go sending stack, which is the gap the original suite left open.

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// tracked reports whether the sampler retains the send record of pn. Every
// delivery-rate sample depends on it: a send whose record is missing can never
// be turned into a rate.
func tracked(s *sampler, pn congestion.PacketNumber) bool {
	slot, ok := s.slot(pn)
	return ok && s.occupied[slot] && s.states[slot].packetNumber == pn
}

// TestSamplerRegistrationNeverLocksOut drives the sampler the way the data
// plane does - monotonically increasing packet numbers registered on send - and
// asserts that no packet-number span, however wide, can stop registration. The
// reproduction's first unregistered send was pn=4098, after which every later
// send was discarded while the ring sat mostly empty.
func TestSamplerRegistrationNeverLocksOut(t *testing.T) {
	const psw = 4096 // the production PacketStateWindow
	s := newSampler(psw)
	now := time.Now()

	// Phase 1: fill the ring exactly, with nothing acked.
	for pn := congestion.PacketNumber(1); pn <= psw; pn++ {
		s.onPacketSent(now.Add(time.Duration(pn)*time.Microsecond), pn, 1280, 0, false)
		if !tracked(s, pn) {
			t.Fatalf("send of pn=%d was not registered while the ring was still filling (live=%d)",
				pn, s.liveSamples())
		}
	}

	// Phase 2: keep sending across four ring wraps with no acks at all, the
	// worst case for the ring - every record it holds has left the window by the
	// time its slot comes round again.
	for pn := congestion.PacketNumber(psw + 1); pn <= congestion.PacketNumber(psw*4); pn++ {
		s.onPacketSent(now.Add(time.Duration(pn)*time.Microsecond), pn, 1280, 0, false)
		if !tracked(s, pn) {
			t.Fatalf("send record of pn=%d was discarded (base=%d ringSize=%d live=%d): the ring locked registration",
				pn, s.base, len(s.states), s.liveSamples())
		}
		if live, capacity := s.liveSamples(), len(s.states); live > capacity {
			t.Fatalf("retained %d send records, above the fixed capacity %d", live, capacity)
		}
	}

	// Phase 3: the realistic pattern - sends with acks half a window behind, so
	// the in-flight span stays inside the window while the ring still wraps many
	// times. Every send registers and every acked packet resolves its own record.
	for pn := congestion.PacketNumber(psw*4 + 1); pn <= congestion.PacketNumber(psw*8); pn++ {
		s.onPacketSent(now.Add(time.Duration(pn)*time.Microsecond), pn, 1280, 0, false)
		if !tracked(s, pn) {
			t.Fatalf("send record of pn=%d was discarded with the in-flight span inside the window", pn)
		}
		if old := pn - psw/2; old > psw {
			if _, ok := s.onPacketAcked(now.Add(time.Duration(pn)*time.Microsecond), old); !ok {
				t.Fatalf("ack of in-window pn=%d returned no sample", old)
			}
		}
	}
}

// TestSamplerAckResolvesOwnPacketRecord pins the ack side of the invariant: with
// the send head past the ring span, an ack must resolve the record of its own
// packet number or report no sample. The reproduction measured 201 of 201 acks
// over pn 4000..4200 returning samples built from other packets' records, which
// attributes a delivery rate to the wrong send time. The size differs per packet
// number so a misattributed record is visible in the delivered volume.
func TestSamplerAckResolvesOwnPacketRecord(t *testing.T) {
	const psw = 4096
	s := newSampler(psw)
	now := time.Now()
	sizeOf := func(pn congestion.PacketNumber) congestion.ByteCount { return congestion.ByteCount(1000 + pn) }
	for pn := congestion.PacketNumber(1); pn <= 4200; pn++ {
		s.onPacketSent(now, pn, sizeOf(pn), 0, false)
	}

	// pn 4000..4200 are all inside the window the send head leaves behind.
	for pn := congestion.PacketNumber(4200); pn >= 4000; pn-- {
		before := s.deliveredVolume()
		if _, ok := s.onPacketAcked(now.Add(100*time.Millisecond), pn); !ok {
			t.Fatalf("ack of in-window pn=%d produced no sample", pn)
		}
		if got := s.deliveredVolume() - before; got != sizeOf(pn) {
			t.Fatalf("ack of pn=%d credited %d bytes, want %d: the sample came from another packet's record",
				pn, got, sizeOf(pn))
		}
	}
}

// TestSamplerAnchorBehindTheSendHeadIsSafe pins the late-installation case: the
// hysteria2 client installs the controller on a live connection, so the first
// packet number the sampler sees can be far behind the next send. That jump is
// wider than the ring, and it must re-anchor instead of locking registration out.
func TestSamplerAnchorBehindTheSendHeadIsSafe(t *testing.T) {
	s := newSampler(64)
	t0 := time.Now()
	// First call is an ack for a packet sent before the controller was installed.
	if _, ok := s.onPacketAcked(t0, 10); ok {
		t.Fatal("an ack with no send record produced a sample")
	}
	for pn := congestion.PacketNumber(5000); pn <= 5200; pn++ {
		s.onPacketSent(t0, pn, 1200, 0, false)
		if !tracked(s, pn) {
			t.Fatalf("send record of pn=%d was discarded after a %d-packet jump (base=%d)",
				pn, pn-10, s.base)
		}
	}
	if live, capacity := s.liveSamples(), len(s.states); live > capacity {
		t.Fatalf("retained %d send records, above the fixed capacity %d", live, capacity)
	}
}

// TestSamplerWindowAboveHeadroomIsClean is the sizing corollary from the
// reproduction: with a window comfortably larger than the in-flight packet span
// the same send sequence registers without exception. It is kept as the control
// that separates "this path's span does not fit the window" from "the window's
// bookkeeping is broken".
func TestSamplerWindowAboveHeadroomIsClean(t *testing.T) {
	s := newSampler(16384)
	now := time.Now()
	for pn := congestion.PacketNumber(1); pn <= 12000; pn++ {
		s.onPacketSent(now, pn, 1280, 0, false)
		if !tracked(s, pn) {
			t.Fatalf("registration failed at pn=%d with window=16384", pn)
		}
	}
	t.Logf("window=16384 registered 12000 packets cleanly, live=%d", s.liveSamples())
}

// TestSamplerOutOfWindowPacketHasNoRecord pins the cost side of the span bound:
// once a packet number leaves the window its record is gone, so its ack yields
// no sample rather than one attributed to whatever now occupies the slot. This
// is what keeps the ring at PacketStateWindow+1 slots whatever the span.
func TestSamplerOutOfWindowPacketHasNoRecord(t *testing.T) {
	const psw = 64
	s := newSampler(psw)
	t0 := time.Now()
	s.onPacketSent(t0, 1, 1200, 0, false)
	for pn := congestion.PacketNumber(2); pn <= congestion.PacketNumber(psw*3); pn++ {
		s.onPacketSent(t0, pn, 1200, 0, false)
	}
	if _, ok := s.onPacketAcked(t0.Add(time.Second), 1); ok {
		t.Fatal("an ack for pn=1 produced a sample after its record left the window")
	}
	if live, capacity := s.liveSamples(), len(s.states); live > capacity {
		t.Fatalf("retained %d send records, above the fixed capacity %d", live, capacity)
	}
}

// TestSamplerResendKeepsTheFirstSendRecord pins the guard the registration fix
// must not weaken: a resend of a packet number the sampler is already tracking
// keeps the original record, because the delivery-rate sample is anchored on the
// first send. The resend carries a different size and a later timestamp, so an
// overwrite would show up in both the sample and the delivered volume.
func TestSamplerResendKeepsTheFirstSendRecord(t *testing.T) {
	s := newSampler(64)
	t0 := time.Now()
	s.onPacketSent(t0, 7, 1200, 0, false)
	s.onPacketSent(t0.Add(50*time.Millisecond), 7, 900, 0, true)

	rate, ok := s.onPacketAcked(t0.Add(100*time.Millisecond), 7)
	if !ok {
		t.Fatal("resend lost the send record entirely")
	}
	if want := bandwidthFromDelta(1200, 100*time.Millisecond); rate != want {
		t.Fatalf("rate = %d, want %d: the resend overwrote the record of the first send (1200 B at t0)",
			rate, want)
	}
	if got := s.deliveredVolume(); got != 1200 {
		t.Fatalf("delivered = %d, want 1200: the resend's size was credited instead of the first send's", got)
	}
}

// TestSamplerResendInsideARebasedWindowKeepsTheFirstSendRecord is the same
// contract after the window has slid, which is where the slot index used to move
// out from under the record.
func TestSamplerResendInsideARebasedWindowKeepsTheFirstSendRecord(t *testing.T) {
	const psw = 4096
	s := newSampler(psw)
	t0 := time.Now()
	for pn := congestion.PacketNumber(1); pn <= 5000; pn++ {
		s.onPacketSent(t0, pn, 1200, 0, false)
	}
	// pn 4210 is inside the window the head at 5000 leaves behind.
	const pn = congestion.PacketNumber(4210)
	if !tracked(s, pn) {
		t.Fatalf("pn=%d is not tracked after the window slid", pn)
	}

	s.onPacketSent(t0.Add(50*time.Millisecond), pn, 900, 0, true)
	slot, ok := s.slot(pn)
	if !ok || !s.occupied[slot] || s.states[slot].packetNumber != pn {
		t.Fatal("the resend dropped the tracked record")
	}
	if s.states[slot].size != 1200 || !s.states[slot].sentTime.Equal(t0) {
		t.Fatalf("the resend overwrote the record: size=%d sentTime=%v, want the first send's 1200 B at %v",
			s.states[slot].size, s.states[slot].sentTime, t0)
	}
	if _, ok := s.onPacketAcked(t0.Add(100*time.Millisecond), pn); !ok {
		t.Fatal("ack after a resend produced no sample")
	}
	if got := s.deliveredVolume(); got != 1200 {
		t.Fatalf("delivered = %d, want 1200: the resend's size was credited", got)
	}
}
