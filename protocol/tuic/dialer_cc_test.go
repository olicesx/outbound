package tuic

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestSelectCongestionController(t *testing.T) {
	cases := []struct {
		name     string
		serverCC string
		override string
		want     string
		wantErr  bool
	}{
		{
			name:     "empty override keeps server value",
			serverCC: "bbr",
			override: "",
			want:     "bbr",
		},
		{
			name:     "empty override keeps empty server value",
			serverCC: "",
			override: "",
			want:     "",
		},
		{
			name:     "override wins over server value",
			serverCC: "cubic",
			override: "bbr3",
			want:     "bbr3",
		},
		{
			name:     "override bbr",
			serverCC: "cubic",
			override: "bbr",
			want:     "bbr",
		},
		{
			name:     "override cubic",
			serverCC: "bbr",
			override: "cubic",
			want:     "cubic",
		},
		{
			name:     "override new_reno",
			serverCC: "bbr",
			override: "new_reno",
			want:     "new_reno",
		},
		{
			name:     "override brutal",
			serverCC: "bbr",
			override: "brutal",
			want:     "brutal",
		},
		{
			name:     "unknown override rejected",
			serverCC: "bbr",
			override: "bbr4",
			wantErr:  true,
		},
		{
			// The link parser lowercases the value before it reaches here, so
			// the selector itself is strict: anything else is a caller bug.
			name:     "un-normalized override rejected",
			serverCC: "bbr",
			override: "BBR3",
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectCongestionController(tc.serverCC, tc.override)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("selectCongestionController(%q, %q) = %q, want error",
						tc.serverCC, tc.override, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("selectCongestionController(%q, %q): %v", tc.serverCC, tc.override, err)
			}
			if got != tc.want {
				t.Fatalf("selectCongestionController(%q, %q) = %q, want %q",
					tc.serverCC, tc.override, got, tc.want)
			}
		})
	}
}

func TestNewDialerWiresCongestionOverride(t *testing.T) {
	cases := []struct {
		name     string
		serverCC string
		override string
		want     string
	}{
		{
			name:     "no override keeps server value",
			serverCC: "cubic",
			override: "",
			want:     "cubic",
		},
		{
			name:     "override replaces server value",
			serverCC: "cubic",
			override: "bbr3",
			want:     "bbr3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewDialer(direct.SymmetricDirect, protocol.Header{
				ProxyAddress: "127.0.0.1:443",
				Feature1:     tc.serverCC,
				Feature2:     0,
				TlsConfig: &tls.Config{
					NextProtos: []string{"h3"},
					MinVersion: tls.VersionTLS13,
					ServerName: "example.com",
				},
				CongestionOverride: tc.override,
				User:               "00000000-0000-0000-0000-000000000000",
				Password:           "pass",
				IsClient:           true,
			})
			if err != nil {
				t.Fatalf("NewDialer: %v", err)
			}
			td, ok := d.(*Dialer)
			if !ok {
				t.Fatalf("got %T, want *Dialer", d)
			}
			defer func() { _ = td.Close() }()

			cli := td.clientRing.newClient(func(int64) {})
			if cli.CongestionController != tc.want {
				t.Fatalf("CongestionController = %q, want %q", cli.CongestionController, tc.want)
			}
		})
	}
}

func TestNewDialerRejectsUnknownCongestionOverride(t *testing.T) {
	d, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress:       "127.0.0.1:443",
		Feature1:           "bbr",
		CongestionOverride: "bbr4",
		User:               "00000000-0000-0000-0000-000000000000",
		Password:           "pass",
		IsClient:           true,
	})
	if err == nil {
		if td, ok := d.(*Dialer); ok {
			_ = td.Close()
		}
		t.Fatal("NewDialer with unknown cc_override: want error, got nil")
	}
	if !strings.Contains(err.Error(), "cc_override") {
		t.Fatalf("error %q does not mention cc_override", err)
	}
}

func TestNewDialerNonStringFeature1DoesNotPanic(t *testing.T) {
	d, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: "127.0.0.1:443",
		Feature1:     42,
		User:         "00000000-0000-0000-0000-000000000000",
		Password:     "pass",
		IsClient:     true,
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	td, ok := d.(*Dialer)
	if !ok {
		t.Fatalf("got %T, want *Dialer", d)
	}
	defer func() { _ = td.Close() }()

	cli := td.clientRing.newClient(func(int64) {})
	if cli.CongestionController != "" {
		t.Fatalf("CongestionController = %q, want empty for non-string Feature1", cli.CongestionController)
	}
}
