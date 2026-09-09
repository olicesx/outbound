package common

import (
	"fmt"

	"github.com/daeuniverse/outbound/protocol/tuic/congestion"
	"github.com/olicesx/quic-go"
	"github.com/sirupsen/logrus"
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

// supportedCongestionControllers is the allowlist accepted by the client-local
// cc_override parameter. It lists only the controllers this client can install;
// an unrecognized value is a configuration error, never a silent BBR fallback.
var supportedCongestionControllers = map[string]struct{}{
	"bbr":      {},
	"cubic":    {},
	"new_reno": {},
	"brutal":   {},
	"bbr3":     {},
}

// SelectCongestionController resolves the congestion controller to install.
// serverCC is the value echoed by the server during the handshake; override is
// the optional client-local cc_override value, already normalized (lowercased
// and trimmed) by the link parser. An empty override returns serverCC unchanged,
// preserving the pre-override behavior exactly. A non-empty override must be in
// the allowlist, otherwise an error is returned so a typo fails fast instead of
// being silently downgraded to BBR.
func SelectCongestionController(serverCC, override string) (string, error) {
	if override == "" {
		return serverCC, nil
	}
	if _, ok := supportedCongestionControllers[override]; !ok {
		return "", fmt.Errorf("unsupported cc_override %q: must be one of bbr, cubic, new_reno, brutal, bbr3", override)
	}
	return override, nil
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
		// Testers need an observable signal that the experimental controller
		// was actually installed instead of silently falling back to BBR.
		logrus.WithFields(logrus.Fields{
			"cc":       "bbr3",
			"hint_bps": cwnd,
		}).Debug("installing experimental bbr3 congestion controller")
		congestion.UseBbr3(quicConn, cwnd)
	default:
		congestion.UseBBR(quicConn)
	}
}
