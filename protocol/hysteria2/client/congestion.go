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

// defaultCongestionController mirrors
// protocol/tuic/common.DefaultCongestionController: the controller installed
// when a link carries no explicit cc_override. This package keeps its own
// allowlist copy, so the default is mirrored here as well.
const defaultCongestionController = ccBbr3

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
// override installs defaultCongestionController (bbr3) — the experimental
// default — ignoring the historical server-driven table entirely:
//
//   - rxAuto: previously BBR, now bbr3 (serverRx is irrelevant to the sender);
//   - otherwise the min(serverRx, clientTx) Brutal target is computed and
//     handed to bbr3 as its access-link ceiling hint, so the bandwidth fields
//     still bound pacing and inflight.
//
// A non-empty override keeps the historical semantics:
//
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
	if override == "" {
		_, tx := brutalTarget(serverRx, clientTx)
		return defaultCongestionController, tx, nil
	}
	switch override {
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
