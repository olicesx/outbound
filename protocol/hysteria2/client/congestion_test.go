package client

import "testing"

// TestResolveCongestion pins the whole decision table, including the
// default-on behavior: an empty override now selects bbr3 (the experimental
// default), with the historical min(serverRx, clientTx) value kept as its
// access-link ceiling hint.
func TestResolveCongestion(t *testing.T) {
	const (
		mbps5  = uint64(5_000_000)
		mbps10 = uint64(10_000_000)
		mbps20 = uint64(20_000_000)
	)
	cases := []struct {
		name     string
		override string
		rxAuto   bool
		serverRx uint64
		clientTx uint64
		wantName string
		wantTx   uint64
		wantErr  bool
	}{
		{
			name:     "empty override with RxAuto uses bbr3 with min-target hint",
			rxAuto:   true,
			serverRx: mbps5,
			clientTx: mbps10,
			wantName: ccBbr3,
			wantTx:   mbps5,
		},
		{
			name:     "empty override without RxAuto uses bbr3 with server limit hint",
			serverRx: mbps5,
			clientTx: mbps10,
			wantName: ccBbr3,
			wantTx:   mbps5,
		},
		{
			name:     "empty override without RxAuto hints at clientTx cap",
			serverRx: mbps20,
			clientTx: mbps10,
			wantName: ccBbr3,
			wantTx:   mbps10,
		},
		{
			name:     "empty override without server limit hints at clientTx",
			serverRx: 0,
			clientTx: mbps10,
			wantName: ccBbr3,
			wantTx:   mbps10,
		},
		{
			name:     "empty override without any bandwidth uses bbr3 purely probing",
			wantName: ccBbr3,
			wantTx:   0,
		},
		{
			name:     "empty override ignores server limit when clientTx is unset",
			serverRx: mbps5,
			clientTx: 0,
			wantName: ccBbr3,
			wantTx:   0,
		},
		{
			name:     "bbr3 hint is clientTx",
			override: ccBbr3,
			serverRx: mbps5,
			clientTx: mbps10,
			wantName: ccBbr3,
			wantTx:   mbps10,
		},
		{
			name:     "bbr3 overrides RxAuto",
			override: ccBbr3,
			rxAuto:   true,
			clientTx: mbps10,
			wantName: ccBbr3,
			wantTx:   mbps10,
		},
		{
			name:     "bbr3 without bandwidth probes with zero hint",
			override: ccBbr3,
			serverRx: mbps5,
			wantName: ccBbr3,
			wantTx:   0,
		},
		{
			name:     "bbr forces BBR and reports no target",
			override: ccBBR,
			serverRx: mbps5,
			clientTx: mbps10,
			wantName: ccBBR,
			wantTx:   0,
		},
		{
			name:     "brutal uses server limit",
			override: ccBrutal,
			serverRx: mbps5,
			clientTx: mbps10,
			wantName: ccBrutal,
			wantTx:   mbps5,
		},
		{
			name:     "brutal overrides RxAuto and falls back to clientTx",
			override: ccBrutal,
			rxAuto:   true,
			clientTx: mbps10,
			wantName: ccBrutal,
			wantTx:   mbps10,
		},
		{
			name:     "brutal without bandwidth falls back to BBR",
			override: ccBrutal,
			wantName: ccBBR,
			wantTx:   0,
		},
		{
			name:     "cubic is rejected",
			override: "cubic",
			serverRx: mbps5,
			clientTx: mbps10,
			wantErr:  true,
		},
		{
			name:     "new_reno is rejected",
			override: "new_reno",
			serverRx: mbps5,
			clientTx: mbps10,
			wantErr:  true,
		},
		{
			name:     "unknown override is rejected",
			override: "bbr4",
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, tx, err := resolveCongestion(tc.override, tc.rxAuto, tc.serverRx, tc.clientTx)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveCongestion(%q, %v, %d, %d) = (%q, %d), want error",
						tc.override, tc.rxAuto, tc.serverRx, tc.clientTx, name, tx)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveCongestion(%q, %v, %d, %d): %v",
					tc.override, tc.rxAuto, tc.serverRx, tc.clientTx, err)
			}
			if name != tc.wantName || tx != tc.wantTx {
				t.Fatalf("resolveCongestion(%q, %v, %d, %d) = (%q, %d), want (%q, %d)",
					tc.override, tc.rxAuto, tc.serverRx, tc.clientTx, name, tx, tc.wantName, tc.wantTx)
			}
		})
	}
}

func TestValidateCongestionOverride(t *testing.T) {
	cases := []struct {
		override string
		wantErr  bool
	}{
		{override: "", wantErr: false},
		{override: ccBBR, wantErr: false},
		{override: ccBrutal, wantErr: false},
		{override: ccBbr3, wantErr: false},
		{override: "cubic", wantErr: true},
		{override: "new_reno", wantErr: true},
		{override: "bbr4", wantErr: true},
		{override: "BBR3", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.override, func(t *testing.T) {
			if err := ValidateCongestionOverride(tc.override); (err != nil) != tc.wantErr {
				t.Fatalf("ValidateCongestionOverride(%q) error = %v, wantErr %v",
					tc.override, err, tc.wantErr)
			}
		})
	}
}
