package bbr3

import (
	"time"

	"github.com/daeuniverse/outbound/protocol/tuic/congestion/common"
	"github.com/olicesx/quic-go/congestion"
)

// Bbr3Sender is an EXPERIMENTAL congestion controller, not verified BBRv3.
type Bbr3Sender struct {
	params   Params
	model    *model
	rttStats congestion.RTTStatsProvider
	pacer    *common.Pacer

	maxCwnd congestion.ByteCount

	mode mode

	pacingRate Bandwidth
	cwnd       congestion.ByteCount

	// PROBE_RTT bookkeeping.
	probeRttExitAt time.Time
	probeRttRound  bool

	// AccessBudget hint in bytes per second. Zero means unset (pure probing).
	hint Bandwidth
	gate hintGate

	// createdAt anchors hint timeline telemetry (ms offsets), not control.
	createdAt time.Time
}

var _ congestion.CongestionControl = &Bbr3Sender{}

// NewBbr3Sender builds a sender with DefaultParams. hintBps is the access-link
// upper bound in bytes per second; zero disables the cap.
func NewBbr3Sender(maxDatagramSize congestion.ByteCount, hintBps uint64) *Bbr3Sender {
	return NewBbr3SenderWithParams(maxDatagramSize, hintBps, DefaultParams())
}

// NewBbr3SenderWithParams builds a sender with explicit parameters.
func NewBbr3SenderWithParams(maxDatagramSize congestion.ByteCount, hintBps uint64, params Params) *Bbr3Sender {
	if err := params.Validate(); err != nil {
		panic(err)
	}
	if hintBps > 1<<40 {
		panic("bbr3: hint exceeds supported bytes/s")
	}
	m := newModel(params, maxDatagramSize)
	s := &Bbr3Sender{
		params:    params,
		model:     m,
		maxCwnd:   congestion.ByteCount(congestion.MaxCongestionWindowPackets) * m.maxDatagramSize,
		mode:      modeStartup,
		hint:      Bandwidth(hintBps),
		cwnd:      m.initialCwnd,
		createdAt: time.Now(),
	}
	s.pacer = common.NewPacer(func() congestion.ByteCount { return congestion.ByteCount(s.pacingRate) })
	s.pacer.SetMaxDatagramSize(m.maxDatagramSize)
	s.recalc()
	return s
}

// Mode reports the current state-machine state.
func (b *Bbr3Sender) Mode() string { return b.mode.String() }

// PacingRate reports the current pacing rate in bytes per second.
func (b *Bbr3Sender) PacingRate() Bandwidth { return b.pacingRate }

// SetRTTStatsProvider implements congestion.CongestionControl.
func (b *Bbr3Sender) SetRTTStatsProvider(p congestion.RTTStatsProvider) {
	b.rttStats = p
}

// SetMaxDatagramSize implements congestion.CongestionControl.
func (b *Bbr3Sender) SetMaxDatagramSize(s congestion.ByteCount) {
	if s <= 0 {
		return
	}
	b.model.setMaxDatagramSize(s)
	if b.cwnd < b.model.minCwnd {
		b.cwnd = b.model.minCwnd
	}
	b.pacer.SetMaxDatagramSize(s)
}

// TimeUntilSend implements congestion.CongestionControl.
func (b *Bbr3Sender) TimeUntilSend(bytesInFlight congestion.ByteCount) time.Time {
	return b.pacer.TimeUntilSend()
}

// HasPacingBudget implements congestion.CongestionControl.
func (b *Bbr3Sender) HasPacingBudget(now time.Time) bool {
	b.expireHint(now)
	return b.pacer.Budget(now) >= b.model.maxDatagramSize
}

// CanSend implements congestion.CongestionControl.
func (b *Bbr3Sender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight < b.cwnd
}

// OnPacketSent implements congestion.CongestionControl.
func (b *Bbr3Sender) OnPacketSent(sentTime time.Time, bytesInFlight congestion.ByteCount, packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool) {
	if !isRetransmittable {
		return
	}
	b.expireHint(sentTime)
	b.model.bytesInFlight = bytesInFlight + bytes
	b.model.onPacketSent(sentTime, packetNumber, bytes, b.model.bytesInFlight)
	b.pacer.SentPacket(sentTime, bytes)
}

// MaybeExitSlowStart implements congestion.CongestionControl. STARTUP exit is
// driven by the bandwidth model, not by this hint.
func (b *Bbr3Sender) MaybeExitSlowStart() {}

// OnRetransmissionTimeout withdraws hint authorization on a retransmitting PTO.
func (b *Bbr3Sender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if packetsRetransmitted {
		b.revokeHint(time.Now(), reasonPto)
		b.recalc()
	}
}

// InSlowStart implements congestion.CongestionControl.
func (b *Bbr3Sender) InSlowStart() bool { return b.mode == modeStartup }

// InRecovery reports false; this experiment has no explicit recovery state.
func (b *Bbr3Sender) InRecovery() bool { return false }

// GetCongestionWindow implements congestion.CongestionControl.
func (b *Bbr3Sender) GetCongestionWindow() congestion.ByteCount { return b.cwnd }

// OnPacketAcked implements congestion.CongestionControl. It is deliberately a
// no-op: quic-go reports the acknowledgement both per packet through this
// method and as a vector through OnCongestionEventEx, so acting here would
// count every ack twice. The other senders in this tree do the same.
func (b *Bbr3Sender) OnPacketAcked(number congestion.PacketNumber, ackedBytes congestion.ByteCount, priorInFlight congestion.ByteCount, eventTime time.Time) {
}

// OnCongestionEvent withdraws hint authorization for loss or ECN signals.
func (b *Bbr3Sender) OnCongestionEvent(number congestion.PacketNumber, lostBytes congestion.ByteCount, priorInFlight congestion.ByteCount) {
	// This callback also carries ECN and timer-only loss without a vector event.
	// Revoke the hint here; vector loss accounting remains in onAckEvent.
	reason := reasonEcnOrTimer
	if lostBytes > 0 {
		reason = reasonLoss
	}
	b.revokeHint(time.Now(), reason)
	b.recalc()
}

// OnCongestionEventEx implements congestion.CongestionControl.
func (b *Bbr3Sender) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime time.Time, ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo) {
	if len(ackedPackets) == 0 && len(lostPackets) == 0 {
		return
	}
	b.onAckEvent(eventTime, ackedPackets, lostPackets, priorInFlight)
}

// onAckEvent is the single control point: it folds the ack/loss vector into the
// network model, advances the state machine, and recomputes pacing and cwnd.
func (b *Bbr3Sender) onAckEvent(now time.Time, acked []congestion.AckedPacketInfo, lost []congestion.LostPacketInfo, priorInFlight congestion.ByteCount) {
	if b.rttStats == nil {
		return
	}
	m := b.model
	b.expireHint(now)

	var ackedBytes, lostBytes congestion.ByteCount
	var maxPn congestion.PacketNumber = -1
	for _, p := range acked {
		ackedBytes += p.BytesAcked
		if p.PacketNumber > maxPn {
			maxPn = p.PacketNumber
		}
	}
	for _, p := range lost {
		lostBytes += p.BytesLost
		if p.PacketNumber > maxPn {
			maxPn = p.PacketNumber
		}
	}

	// App-limited is judged against what pacing would sustain, not against the
	// congestion window: pacing deliberately holds about one BDP in flight
	// while cwnd allows two, so a cwnd-relative test would mark every event
	// app-limited and starve the bandwidth model of samples forever.
	limit := b.cwnd
	if p := m.pacingInFlight(b.pacingRate); p < limit {
		limit = p
	}
	m.appLimited = priorInFlight < limit*3/4

	m.bytesInFlight = priorInFlight - ackedBytes - lostBytes
	if m.bytesInFlight < 0 {
		m.bytesInFlight = 0
	}

	roundStart := m.accountEvent(ackedBytes, lostBytes, len(lost), maxPn)

	// Delivery-rate samples. The maximum over the event is the bandwidth
	// estimate candidate; app-limited samples must not raise it.
	beforeDelivered := m.sampler.deliveredVolume()
	var sample Bandwidth
	for _, p := range acked {
		if rate, ok := m.sampler.onPacketAcked(now, p.PacketNumber); ok && rate > sample {
			sample = rate
		}
	}
	for _, p := range lost {
		m.sampler.onPacketLost(p.PacketNumber)
	}
	m.updateBandwidth(sample)

	// Compare against the prior minimum before any filter refresh can hide a queue.
	b.observeHint(now, m.sampler.deliveredVolume()-beforeDelivered, lostBytes)
	minRttExpired := m.updateMinRtt(now, b.rttSample())

	if lostBytes > 0 {
		m.adaptLowerBounds()
	}

	switch b.mode {
	case modeStartup:
		// The full-bandwidth test is a per-round measurement; running it on
		// every ack event would exit STARTUP within a single round.
		if roundStart {
			m.checkFullBwReached()
		}
		if lostBytes > 0 && m.lossRateExceeded() {
			// Sustained loss during the ramp means the path is saturated: stop
			// probing and drain the queue. The upper bound is left unset so
			// PROBE_UP owns it in this local policy.
			b.mode = modeDrain
		} else if m.fullBwReached {
			b.mode = modeDrain
		}
	case modeDrain:
		if m.bytesInFlight <= m.bdp() {
			b.mode = modeProbeBWDown
		}
	case modeProbeBWUp:
		if m.probeUpRound(roundStart, lostBytes, b.cwnd) {
			b.mode = modeProbeBWDown
		}
	case modeProbeBWDown, modeProbeBWCruise, modeProbeBWRefill:
		if roundStart {
			b.mode = b.mode.advance()
			if b.mode == modeProbeBWUp {
				m.resetProbeUp()
			}
		}
	}

	if roundStart {
		m.updateLossBaseline()
	}
	b.maybeProbeRtt(now, roundStart, minRttExpired)
	b.recalc()
}

// rttSample reads the most recent RTT the QUIC stack measured.
func (b *Bbr3Sender) rttSample() time.Duration {
	sample := b.rttStats.LatestRTT()
	if sample <= 0 {
		sample = b.rttStats.SmoothedRTT()
	}
	return sample
}

// maybeProbeRtt enters PROBE_RTT when the minimum RTT has expired and leaves it
// after ProbeRttDuration plus one round with inflight at the target.
func (b *Bbr3Sender) maybeProbeRtt(now time.Time, roundStart, minRttExpired bool) {
	if b.mode == modeProbeRTT {
		if b.probeRttExitAt.IsZero() {
			if b.model.bytesInFlight <= b.model.probeRttTarget() {
				b.probeRttExitAt = now.Add(b.params.ProbeRttDuration)
				b.probeRttRound = false
			}
			return
		}
		if roundStart {
			b.probeRttRound = true
		}
		if b.probeRttRound && !now.Before(b.probeRttExitAt) {
			b.probeRttExitAt = time.Time{}
			b.mode = modeProbeBWDown
		}
		return
	}
	if minRttExpired {
		b.mode = modeProbeRTT
		b.probeRttExitAt = time.Time{}
		b.probeRttRound = false
	}
}

// recalc derives pacing rate and congestion window from the model, the current
// mode, and the access hint.
func (b *Bbr3Sender) recalc() {
	m := b.model
	est := b.hintEstimate(m.estimate())

	// The access hint bounds the steady-state estimate: the sender does not
	// believe the path is faster than the link that feeds it.
	if b.hint > 0 && est > b.hint {
		est = b.hint
	}
	rate := Bandwidth(float64(est) * b.params.pacingGain(b.mode))
	if rate < b.params.MinPacingRate {
		rate = b.params.MinPacingRate
	}
	// A bounded probe may exceed the hint for one round. Without this the
	// estimator could never observe a path faster than the hint, so a hint equal
	// to path capacity would pin throughput below capacity.
	if b.hint > 0 {
		ceiling := b.hint
		if !b.params.StrictHintCap && b.mode == modeProbeBWUp {
			ceiling = Bandwidth(float64(b.hint) * b.params.HintProbeOvershoot)
		}
		if rate > ceiling {
			rate = ceiling
		}
	}
	// The hint probe's bound applies to the actual rate after mode gain, not
	// merely to the input estimate. STARTUP/PROBE_UP must not amplify it.
	if b.params.EnableValidatedHint && b.gate.state == hintProbing {
		ceiling := Bandwidth(float64(b.gate.recent) * 1.1)
		if ceiling > b.hint {
			ceiling = b.hint
		}
		if rate > ceiling {
			rate = ceiling
		}
	}
	b.pacingRate = rate

	var cwnd congestion.ByteCount
	if b.mode == modeProbeRTT {
		cwnd = m.probeRttTarget()
	} else {
		cwnd = congestion.ByteCount(b.params.CwndGain * float64(bdpFrom(est, m.minRttValue())))
		if m.inflightLo > 0 && cwnd < m.inflightLo {
			cwnd = m.inflightLo
		}
		if m.inflightHi > 0 && cwnd > m.inflightHi {
			cwnd = m.inflightHi
		}
	}
	if b.mode == modeStartup && cwnd < m.initialCwnd {
		cwnd = m.initialCwnd
	}
	if cwnd < m.minCwnd {
		cwnd = m.minCwnd
	}
	if cwnd > b.maxCwnd {
		cwnd = b.maxCwnd
	}

	// AccessBudget cap: the access link is an upper bound on both how fast we
	// may pace and how much we may keep in flight. It is deliberately not
	// applied to inflight_hi, which is a path observation.
	if b.hint > 0 {
		capFactor := 1.0
		if b.mode == modeProbeBWUp && !b.params.StrictHintCap {
			capFactor = b.params.HintProbeOvershoot
		}
		capCwnd := congestion.ByteCount(float64(b.hint) * m.minRttValue().Seconds() * b.params.CwndGain * capFactor)
		if capCwnd < m.minCwnd {
			capCwnd = m.minCwnd
		}
		if cwnd > capCwnd {
			cwnd = capCwnd
		}
	}

	b.cwnd = cwnd
}
