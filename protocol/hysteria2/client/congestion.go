package client

import "fmt"

// Congestion controller names used by the hysteria2 client. They match the
// shared cc_override allowlist in protocol/tuic/common, restricted to the
// controllers this client can actually install.
const (
	ccBBR    = "bbr"
	ccBrutal = "brutal"
	ccBbr3   = "bbr3"
)

// ValidateCongestionOverride reports whether override can be installed by this
// client before any connection is attempted. An empty value is always valid and
// means "no client override" (server-driven selection). cubic and new_reno are
// in the shared link allowlist but have no hysteria2 implementation, so they are
// rejected here instead of being silently downgraded to BBR.
func ValidateCongestionOverride(override string) error {
	switch override {
	case "", ccBBR, ccBrutal, ccBbr3:
		return nil
	case "cubic", "new_reno":
		return fmt.Errorf("cc_override %q is not supported by hysteria2", override)
	default:
		return fmt.Errorf("unsupported cc_override %q: hysteria2 supports bbr, brutal, bbr3", override)
	}
}

// resolveCongestion decides which congestion controller the client installs
// after a successful handshake. It is a pure function so the whole decision
// table is unit-testable without a QUIC connection.
//
// override is the normalized (lowercased, trimmed) cc_override value. An empty
// override reproduces the historical server-driven behavior exactly:
//
//   - rxAuto: the server asks for bandwidth detection, so BBR is used;
//   - otherwise actualTx = min(serverRx, clientTx); a positive target selects
//     Brutal, and zero (no bandwidth known) selects BBR.
//
// A non-empty override takes precedence over the server:
//
//   - bbr3 installs the experimental sender with clientTx (the configured
//     access-link bandwidth in bytes per second) as its ceiling hint; zero
//     leaves it purely probing and is never treated as a target;
//   - bbr forces BBR and reports no target;
//   - brutal runs the same min(serverRx, clientTx) computation and keeps the
//     historical BBR fallback when no bandwidth is known;
//   - cubic, new_reno, and anything else return an error, because a silent
//     downgrade would hide a typo.
//
// The returned tx is the target handed to the installer (brutal target or bbr3
// hint) and is reported through HandshakeInfo.Tx; it is zero when no target
// applies.
func resolveCongestion(override string, rxAuto bool, serverRx, clientTx uint64) (string, uint64, error) {
	if err := ValidateCongestionOverride(override); err != nil {
		return "", 0, err
	}
	switch override {
	case "":
		if rxAuto {
			return ccBBR, 0, nil
		}
		name, tx := brutalTarget(serverRx, clientTx)
		return name, tx, nil
	case ccBbr3:
		return ccBbr3, clientTx, nil
	case ccBrutal:
		name, tx := brutalTarget(serverRx, clientTx)
		return name, tx, nil
	default: // ccBBR
		return ccBBR, 0, nil
	}
}

// brutalTarget is the historical min(serverRx, clientTx) computation: a
// positive target selects Brutal, otherwise BBR.
func brutalTarget(serverRx, clientTx uint64) (string, uint64) {
	tx := serverRx
	if tx == 0 || tx > clientTx {
		tx = clientTx
	}
	if tx > 0 {
		return ccBrutal, tx
	}
	return ccBBR, 0
}
