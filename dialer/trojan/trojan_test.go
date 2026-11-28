package trojan

import (
	"errors"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
)

func TestTrojanRejectsIncompleteShadowsocksEncryption(t *testing.T) {
	opt := &dialer.ExtraOption{TlsImplementation: "tls"}
	for _, value := range []string{"ss%3Baes-128-gcm", "ss%3B%3Bsecret"} {
		_, _, err := NewTrojan(opt, nil, "trojan-go://password@127.0.0.1:443?encryption="+value)
		if !errors.Is(err, dialer.InvalidParameterErr) {
			t.Errorf("encryption=%q: got %v, want invalid parameter", value, err)
		}
	}
}
