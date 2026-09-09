package bbr3

import (
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// fakeRTT is a minimal congestion.RTTStatsProvider.
type fakeRTT struct {
	latest   time.Duration
	smoothed time.Duration
}

func (f *fakeRTT) MinRTT() time.Duration                       { return f.latest }
func (f *fakeRTT) LatestRTT() time.Duration                    { return f.latest }
func (f *fakeRTT) SmoothedRTT() time.Duration                  { return f.smoothed }
func (f *fakeRTT) MeanDeviation() time.Duration                { return 0 }
func (f *fakeRTT) MaxAckDelay() time.Duration                  { return 0 }
func (f *fakeRTT) PTO(bool) time.Duration                      { return 0 }
func (f *fakeRTT) UpdateRTT(sendDelta, ackDelay time.Duration) {}
func (f *fakeRTT) SetMaxAckDelay(time.Duration)                {}
func (f *fakeRTT) SetInitialRTT(time.Duration)                 {}

func newTestSender(hint uint64) *Bbr3Sender {
	s := NewBbr3Sender(1200, hint)
	s.SetRTTStatsProvider(&fakeRTT{latest: 80 * time.Millisecond, smoothed: 80 * time.Millisecond})
	return s
}

// drive keeps a pipeline running: each round fills the current congestion window
// with fresh packets and acknowledges the previous round's batch, so bytes stay
// in flight and the sampler is never app-limited.
func drive(s *Bbr3Sender, now time.Time, rounds int, rtt time.Duration) time.Time {
	var nextPn congestion.PacketNumber
	var pending []congestion.PacketNumber
	for r := 0; r < rounds; r++ {
		n := int(s.GetCongestionWindow()/1200) + 2
		for i := 0; i < n; i++ {
			nextPn++
			s.OnPacketSent(now, s.model.bytesInFlight, nextPn, 1200, true)
			now = now.Add(time.Millisecond)
		}
		if len(pending) > 0 {
			acked := make([]congestion.AckedPacketInfo, 0, len(pending))
			for _, pn := range pending {
				acked = append(acked, congestion.AckedPacketInfo{PacketNumber: pn, BytesAcked: 1200})
			}
			s.OnCongestionEventEx(s.model.bytesInFlight, now, acked, nil)
		}
		pending = pending[:0]
		for i := 0; i < n; i++ {
			pending = append(pending, nextPn-congestion.PacketNumber(i))
		}
		now = now.Add(rtt)
	}
	return now
}

// losePackets feeds a round that sent sentBytes and lost lostBytes across
// MinLossPackets separate loss events, the shape a real overshoot has.
func losePackets(s *Bbr3Sender, now time.Time, sentBytes, lostBytes congestion.ByteCount) {
	s.model.roundBytesSent = sentBytes
	s.model.roundBytesAcked = sentBytes - lostBytes
	per := lostBytes / congestion.ByteCount(s.params.MinLossPackets)
	lost := make([]congestion.LostPacketInfo, 0, s.params.MinLossPackets)
	for i := 0; i < s.params.MinLossPackets; i++ {
		lost = append(lost, congestion.LostPacketInfo{
			PacketNumber: s.model.lastSent - congestion.PacketNumber(i),
			BytesLost:    per,
		})
	}
	s.OnCongestionEventEx(s.model.bytesInFlight, now, nil, lost)
}
