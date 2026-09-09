package bbr3

import (
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// model is the network model: everything the sender estimates about the path.
// It owns no policy about modes; the sender reads it and decides.
type model struct {
	params          Params
	sampler         *sampler
	maxDatagramSize congestion.ByteCount
	initialCwnd     congestion.ByteCount
	minCwnd         congestion.ByteCount

	// Round accounting.
	round    uint64
	roundEnd congestion.PacketNumber
	lastSent congestion.PacketNumber

	bytesInFlight congestion.ByteCount
	appLimited    bool

	// Delivery-rate estimate and its loss-driven lower bound.
	bw   *roundFilter
	bwLo Bandwidth

	// inflight_hi / inflight_lo: the upper and lower bounds the sender keeps on
	// bytes in flight, per the BBRv2 bound pair.
	inflightHi congestion.ByteCount
	inflightLo congestion.ByteCount

	minRtt      time.Duration
	minRttStamp time.Time

	fullBwReached  bool
	fullBwBaseline Bandwidth
	fullBwRounds   int

	// Per-round loss accounting, plus the completed round's snapshot so a
	// round-boundary decision still sees the finished round.
	roundBytesSent         congestion.ByteCount
	roundBytesLost         congestion.ByteCount
	roundBytesAcked        congestion.ByteCount
	roundLostPackets       int
	lastRoundSent          congestion.ByteCount
	lastRoundLost          congestion.ByteCount
	lastRoundAcked         congestion.ByteCount
	lastRoundLostPkts      int
	lastRoundLossThreshold float64

	lossBaseline    float64
	lossBaselineSet bool

	// Rounds spent in the current PROBE_UP, bounded by ProbeUpRounds.
	probeUpRounds int
}

func newModel(params Params, maxDatagramSize congestion.ByteCount) *model {
	if maxDatagramSize <= 0 {
		maxDatagramSize = congestion.InitialPacketSizeIPv4
	}
	return &model{
		params:          params,
		maxDatagramSize: maxDatagramSize,
		initialCwnd:     congestion.ByteCount(params.InitialCwndPackets) * maxDatagramSize,
		minCwnd:         congestion.ByteCount(params.MinCwndPackets) * maxDatagramSize,
		roundEnd:        -1,
		lastSent:        -1,
		bw:              newRoundFilter(params.MaxBwFilterRounds),
		sampler:         newSampler(params.PacketStateWindow),
	}
}
func (m *model) setMaxDatagramSize(s congestion.ByteCount) {
	if s <= 0 {
		return
	}
	m.maxDatagramSize = s
	m.minCwnd = congestion.ByteCount(m.params.MinCwndPackets) * s
}

// estimate is the windowed-max delivery-rate estimate.
func (m *model) accountEvent(ackedBytes, lostBytes congestion.ByteCount, lostPackets int, maxPn congestion.PacketNumber) (roundStart bool) {
	roundStart = m.updateRound(maxPn)
	m.roundBytesLost += lostBytes
	m.roundBytesAcked += ackedBytes
	m.roundLostPackets += lostPackets
	if !roundStart {
		return false
	}
	m.lastRoundLossThreshold = m.lossThresholdNow()
	m.lastRoundSent = m.roundBytesSent
	m.lastRoundLost = m.roundBytesLost
	m.lastRoundAcked = m.roundBytesAcked
	m.lastRoundLostPkts = m.roundLostPackets
	m.roundBytesSent = 0
	m.roundBytesLost = 0
	m.roundBytesAcked = 0
	m.roundLostPackets = 0
	return true
}

// updateBandwidth folds a delivery-rate sample into the estimate. App-limited
// samples must not raise it.
