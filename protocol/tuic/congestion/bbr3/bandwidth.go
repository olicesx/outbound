package bbr3

import (
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// Bandwidth in bytes per second.
type Bandwidth uint64

// bandwidthFromDelta converts a delivered volume over an interval to a rate.
func bandwidthFromDelta(bytes congestion.ByteCount, delta time.Duration) Bandwidth {
	if bytes <= 0 || delta <= 0 {
		return 0
	}
	return Bandwidth(float64(bytes) / delta.Seconds())
}

// bdpFrom is the bandwidth-delay product in bytes.
func bdpFrom(bw Bandwidth, rtt time.Duration) congestion.ByteCount {
	if bw == 0 || rtt <= 0 {
		return 0
	}
	return congestion.ByteCount(float64(bw) * rtt.Seconds())
}

type bwSample struct {
	value Bandwidth
	round uint64
}

// roundFilter is the windowed maximum of delivery-rate samples: BBR takes the
// largest rate observed over the last window round trips so that a single slow
// round does not lower the estimate.
type roundFilter struct {
	window  uint64
	samples []bwSample
}

func newRoundFilter(window uint64) *roundFilter {
	if window == 0 {
		window = 1
	}
	return &roundFilter{window: window}
}

func (f *roundFilter) Update(v Bandwidth, round uint64) {
	if v == 0 {
		return
	}
	f.samples = append(f.samples, bwSample{value: v, round: round})
	f.trim(round)
}

func (f *roundFilter) trim(round uint64) {
	keep := 0
	for keep < len(f.samples) && round-f.samples[keep].round > f.window {
		keep++
	}
	if keep > 0 {
		f.samples = append(f.samples[:0], f.samples[keep:]...)
	}
}

// Max returns the largest sample still inside the window.
func (f *roundFilter) Max(round uint64) Bandwidth {
	f.trim(round)
	var max Bandwidth
	for _, s := range f.samples {
		if s.value > max {
			max = s.value
		}
	}
	return max
}

func (f *roundFilter) Reset() { f.samples = f.samples[:0] }
