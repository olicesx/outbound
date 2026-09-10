package bbr3

import (
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// packetState is the per-packet send record a delivery-rate sample needs.
//
// packetNumber identifies the record: a slot is only ever read as the record of
// the packet number it is indexed by, never of whatever packet last wrote it.
type packetState struct {
	packetNumber    congestion.PacketNumber
	sentTime        time.Time
	size            congestion.ByteCount
	deliveredAtSend congestion.ByteCount
	appLimited      bool
}

// sampler is a simplified local estimator: delivered volume since send divided
// by packet age. It is not the reference BBR sampler and is not guaranteed immune
// to ACK compression. Hint validation uses a separate wall-clock delivery window.
//
// Storage is a fixed-size ring indexed by packet number, not a map: the data
// plane calls onPacketSent once per sent packet, and a map entry per packet cost
// one allocation per packet (plus a slice copy per eviction). The ring is sized
// from PacketStateWindow and never grows, so the whole estimator is
// allocation-free after construction.
//
// The ring index of a packet number is pn % len(states), which does not move when
// the window slides, so a slot holds either that packet number's own record or a
// stale record whose packet number has left the window - and the two are told
// apart by comparing the recorded packet number, never by the occupied flag
// alone. Sliding the window releases the records that left it, which frees their
// slots for immediate reuse: no packet-number span, however wide, can stop the
// sampler from registering sends. PacketStateWindow is therefore a bound on the
// packet-number SPAN whose samples can still be resolved, not a cap on
// registration, throughput or memory of the last N packets.
type sampler struct {
	states    []packetState
	occupied  []bool
	hasBase   bool
	base      congestion.PacketNumber
	delivered congestion.ByteCount
	window    int
	lastAcked congestion.PacketNumber
}

func newSampler(window int) *sampler {
	if window <= 0 {
		window = 1024
	}
	return &sampler{
		states:    make([]packetState, window+1),
		occupied:  make([]bool, window+1),
		window:    window,
		lastAcked: -1,
	}
}

// slot maps a packet number to its ring index and reports whether the packet
// number is still inside the tracked window. The index is pn modulo the ring
// size, not an offset from base: the mapping must not move when base advances,
// otherwise a rebase leaves slots indexed by one packet number holding the record
// of another, and a packet number that wraps onto such a slot is read as a resend
// of a packet it has nothing to do with.
//
// Rebasing advances base so that pn lands at the last slot and releases exactly
// the records that fell out of the window, which is what the window is for: a
// record whose ack can no longer arrive usefully must not be retained. Releasing
// them is also what keeps registration possible - a slot freed here is reusable
// by the next packet number that maps to it.
func (s *sampler) slot(pn congestion.PacketNumber) (int, bool) {
	size := congestion.PacketNumber(len(s.states))
	if !s.hasBase {
		s.hasBase = true
		s.base = pn
		return int(pn % size), true
	}
	if pn < s.base {
		return 0, false
	}
	// Advance the base only when pn is outside [base, base+size). The packets in
	// [base, pn-size] left the window and their slots are cleared; a jump wider
	// than the ring clears all of them, because every record in the ring is then
	// out of window. base moves by the full drop so that pn always lands at the
	// last slot, which keeps every retained record inside the new window.
	if drop := pn - s.base - size + 1; drop > 0 {
		cleared := drop
		if cleared > size {
			cleared = size
		}
		for i := congestion.PacketNumber(0); i < cleared; i++ {
			s.occupied[int((s.base+i)%size)] = false
		}
		s.base += drop
	}
	return int(pn % size), true
}

func (s *sampler) onPacketSent(now time.Time, pn congestion.PacketNumber, size congestion.ByteCount, _ congestion.ByteCount, appLimited bool) {
	slot, ok := s.slot(pn)
	if !ok {
		return
	}
	if s.occupied[slot] && s.states[slot].packetNumber == pn {
		// A resend of a packet number already tracked keeps the original
		// record: the delivery-rate sample is anchored on the first send.
		//
		// The packet number is compared, not just the occupied flag: a slot may
		// still hold the record of a packet number that has left the window, and
		// treating that as "already tracked" would refuse to register every
		// packet number that maps to the slot from then on. Because the slot
		// index is pn % len(states) and rebasing releases out-of-window records
		// before the slot is reused, an occupied slot either holds pn's own
		// record (this branch) or a reclaimable stale one (stored below).
		return
	}
	s.states[slot] = packetState{
		packetNumber:    pn,
		sentTime:        now,
		size:            size,
		deliveredAtSend: s.delivered,
		appLimited:      appLimited,
	}
	s.occupied[slot] = true
}

// onPacketAcked records the delivery and returns the rate sample for pn. The
// record is only used when it belongs to pn: an ack whose send record was
// displaced by the window reports no sample instead of a rate attributed to a
// different packet.
func (s *sampler) onPacketAcked(now time.Time, pn congestion.PacketNumber) (Bandwidth, bool) {
	slot, ok := s.slot(pn)
	if !ok || !s.occupied[slot] || s.states[slot].packetNumber != pn {
		return 0, false
	}
	st := s.states[slot]
	s.occupied[slot] = false
	s.delivered += st.size
	if pn > s.lastAcked {
		s.lastAcked = pn
	}

	delta := now.Sub(st.sentTime)
	if delta <= 0 {
		return 0, false
	}
	bytes := s.delivered - st.deliveredAtSend
	if bytes <= 0 {
		return 0, false
	}
	return bandwidthFromDelta(bytes, delta), true
}

func (s *sampler) onPacketLost(pn congestion.PacketNumber) {
	// Only pn's own record may be released: clearing the slot of another packet
	// number would discard a sample that is still going to arrive.
	if slot, ok := s.slot(pn); ok && s.occupied[slot] && s.states[slot].packetNumber == pn {
		s.occupied[slot] = false
	}
}

// deliveredVolume exposes uniquely acknowledged bytes retained by the sampler.
func (s *sampler) deliveredVolume() congestion.ByteCount { return s.delivered }

// liveSamples reports how many send records are currently retained. Exposed for
// the invariant test that pins the bound on retained state.
func (s *sampler) liveSamples() int {
	n := 0
	for _, occupied := range s.occupied {
		if occupied {
			n++
		}
	}
	return n
}
