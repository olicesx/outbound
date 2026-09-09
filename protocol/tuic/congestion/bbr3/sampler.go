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
type sampler struct {
	states    map[congestion.PacketNumber]*packetState
	order     []congestion.PacketNumber
	delivered congestion.ByteCount
	window    int
	lastAcked congestion.PacketNumber
}

func newSampler(window int) *sampler {
	if window <= 0 {
		window = 1024
	}
	return &sampler{
		states:    make(map[congestion.PacketNumber]*packetState, window),
		order:     make([]congestion.PacketNumber, 0, window),
		window:    window,
		lastAcked: -1,
	}
}

func (s *sampler) onPacketSent(now time.Time, pn congestion.PacketNumber, size congestion.ByteCount, _ congestion.ByteCount, appLimited bool) {
	if _, exists := s.states[pn]; exists {
		return
	}
	s.states[pn] = &packetState{
		sentTime:        now,
		size:            size,
		deliveredAtSend: s.delivered,
		appLimited:      appLimited,
	}
	s.order = append(s.order, pn)
	s.evict()
}

// onPacketAcked records the delivery and returns the rate sample for pn.
func (s *sampler) onPacketAcked(now time.Time, pn congestion.PacketNumber) (Bandwidth, bool) {
	st, ok := s.states[pn]
	if !ok {
		return 0, false
	}
	delete(s.states, pn)
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
	delete(s.states, pn)
}

// deliveredVolume exposes uniquely acknowledged bytes retained by the sampler.
func (s *sampler) deliveredVolume() congestion.ByteCount { return s.delivered }

// evict drops send records that can no longer be acked usefully, bounding the
// map to roughly the packet-state window. It trims a quarter-window at a time
// so the cost is amortised O(1) per sent packet instead of a full copy of the
// order slice on every send.
func (s *sampler) evict() {
	if len(s.order) <= s.window {
		return
	}
	batch := s.window / 4
	if batch < 1 {
		batch = 1
	}
	cut := len(s.order) - s.window + batch
	if cut > len(s.order) {
		cut = len(s.order)
	}
	for _, pn := range s.order[:cut] {
		delete(s.states, pn)
	}
	kept := make([]congestion.PacketNumber, len(s.order)-cut)
	copy(kept, s.order[cut:])
	s.order = kept
}
