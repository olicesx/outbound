package common

import (
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"
	"github.com/olicesx/quic-go"
)

const (
	InitialStreamReceiveWindow     = 8 * 1024 * 1024  // 8 MB (fast start)
	MaxStreamReceiveWindow         = 32 * 1024 * 1024 // 32MB - netem sweep peak (same quic-go engine as hysteria2)
	InitialConnectionReceiveWindow = 12 * 1024 * 1024 // 12 MB (reduced from 20MB, enough for 1-2 concurrent streams)
	MaxConnectionReceiveWindow     = 64 * 1024 * 1024 // 64MB - stream x2, measured peak combo
)

// CWNDFromFeature extracts the brutal target bandwidth (bytes per second)
// from protocol.Header.Feature2. Missing or non-numeric values are treated
// as unset (0) so a mis-typed header falls back to BBR instead of panicking.
func CWNDFromFeature(v interface{}) uint64 {
	switch n := v.(type) {
	case int:
		if n > 0 {
			return uint64(n)
		}
	case int64:
		if n > 0 {
			return uint64(n)
		}
	case uint:
		return uint64(n)
	case uint64:
		return n
	}
	return 0
}

// SetCongestionController wires the configured congestion controller into
// the QUIC connection. "brutal" uses cwnd as the target bandwidth in bytes
// per second (community convention shared with sing-box and the tuic brutal
// forks); when it is zero the connection falls back to BBR. "bbr3" uses the
// same field as the access-link upper bound in bytes per second, which caps
// pacing and inflight but is never a target; zero leaves it purely probing.
func SetCongestionController(quicConn quic.Connection, cc string, cwnd uint64) {
	switch cc {
	case "brutal":
		if cwnd == 0 {
			congestion.UseBBR(quicConn)
			return
		}
		congestion.UseBrutal(quicConn, cwnd)
	case "bbr3":
		congestion.UseBbr3(quicConn, cwnd)
	default:
		congestion.UseBBR(quicConn)
	}
}
