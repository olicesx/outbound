package bbr3

import (
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// estimator.go holds the delivery-rate, minimum-RTT and round accounting half of
// the network model.
func (m *model) estimate() Bandwidth { return m.bw.Max(m.round) }

// bdp is the bandwidth-delay product of the standing estimate.
func (m *model) bdp() congestion.ByteCount {
	return bdpFrom(m.estimate(), m.minRttValue())
}

// pacingInFlight is the volume a given pacing rate would keep on the path.
func (m *model) pacingInFlight(rate Bandwidth) congestion.ByteCount {
	return bdpFrom(rate, m.minRttValue())
}

// minRttValue substitutes a default before the first sample so BDP math never
// divides by zero.
func (m *model) minRttValue() time.Duration {
	if m.minRtt <= 0 {
		return m.params.DefaultMinRtt
	}
	return m.minRtt
}

// updateRound advances the round counter when a packet sent after the current
// round boundary is acknowledged. Returns true on a round start.
func (m *model) updateRound(ackedPn congestion.PacketNumber) bool {
	if ackedPn < 0 {
		return false
	}
	if m.roundEnd < 0 || ackedPn > m.roundEnd {
		m.round++
		m.roundEnd = m.lastSent
		return true
	}
	return false
}

// onPacketSent records the send-side state a later delivery-rate sample needs.
func (m *model) onPacketSent(sentTime time.Time, packetNumber congestion.PacketNumber, bytes, bytesInFlight congestion.ByteCount) {
	m.lastSent = packetNumber
	m.roundBytesSent += bytes
	m.sampler.onPacketSent(sentTime, packetNumber, bytes, bytesInFlight, m.appLimited)
}

// accountEvent folds one ack/loss event into the round counters and returns
// whether this event started a new round. The completed round is snapshotted
// after the event's bytes are counted, then the counters restart; resetting
// before accounting would discard sends that already belong to the new round.
func (m *model) updateBandwidth(sample Bandwidth) {
	if m.appLimited || sample == 0 {
		return
	}
	m.bw.Update(sample, m.round)
}

// updateMinRtt refreshes the minimum RTT sample and reports whether the filter
// had expired, which is the trigger for PROBE_RTT.
func (m *model) updateMinRtt(now time.Time, sample time.Duration) (expired bool) {
	if sample <= 0 {
		return false
	}
	expired = m.minRtt != 0 && now.After(m.minRttStamp.Add(m.params.MinRttFilterLen))
	if expired || m.minRtt == 0 || sample < m.minRtt {
		m.minRtt = sample
		m.minRttStamp = now
	}
	return expired
}

// checkFullBwReached implements the STARTUP exit test: bandwidth must grow by
// FullBwThreshold over FullBwRounds consecutive rounds.
func (m *model) checkFullBwReached() {
	est := m.estimate()
	if est == 0 {
		return
	}
	if m.fullBwBaseline == 0 {
		m.fullBwBaseline = est
		return
	}
	if float64(est) >= m.params.FullBwThreshold*float64(m.fullBwBaseline) {
		m.fullBwBaseline = est
		m.fullBwRounds = 0
		return
	}
	m.fullBwRounds++
	if m.fullBwRounds >= m.params.FullBwRounds {
		m.fullBwReached = true
	}
}

// updateLossBaseline tracks the path's recent random-loss rate. Independent loss
// is not a congestion signal: on a path that always drops a few percent,
// treating the baseline itself as overshoot pins the sender far below the rate
// the path actually carries. Only loss clearly above the baseline counts.
