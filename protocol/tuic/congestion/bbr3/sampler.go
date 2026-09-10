package bbr3

import (
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// packetState is the per-packet send record a delivery-rate sample needs.
type packetState struct {
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

// slot maps a packet number to its ring index, rebasing the ring when the packet
// number has moved past the tracked range. Rebasing drops the records that fell
// out of range, which is exactly what the window is for: a record whose ack can
// no longer arrive usefully must not be retained.
func (s *sampler) slot(pn congestion.PacketNumber) (int, bool) {
	size := congestion.PacketNumber(len(s.states))
	if !s.hasBase {
		s.hasBase = true
		s.base = pn
		return 0, true
	}
	if pn < s.base {
		return 0, false
	}
	offset := pn - s.base
	if offset < size {
		return int(offset), true
	}
	// Advance the base so pn lands at the last slot, clearing everything the
	// rebase skipped over.
	advance := offset - size + 1
	for i := congestion.PacketNumber(0); i < advance && i < size; i++ {
		s.occupied[int((s.base+i)%size)] = false
	}
	s.base += advance
	if pn < s.base {
		return 0, false
	}
	return int(pn - s.base), true
}

func (s *sampler) onPacketSent(now time.Time, pn congestion.PacketNumber, size congestion.ByteCount, _ congestion.ByteCount, appLimited bool) {
	slot, ok := s.slot(pn)
	if !ok {
		return
	}
	if s.occupied[slot] {
		// A resend of a packet number already tracked keeps the original
		// record: the delivery-rate sample is anchored on the first send.
		return
	}
	s.states[slot] = packetState{
		sentTime:        now,
		size:            size,
		deliveredAtSend: s.delivered,
		appLimited:      appLimited,
	}
	s.occupied[slot] = true
}

// onPacketAcked records the delivery and returns the rate sample for pn.
func (s *sampler) onPacketAcked(now time.Time, pn congestion.PacketNumber) (Bandwidth, bool) {
	slot, ok := s.slot(pn)
	if !ok || !s.occupied[slot] {
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
	if slot, ok := s.slot(pn); ok {
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
