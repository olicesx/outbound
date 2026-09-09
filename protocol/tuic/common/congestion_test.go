package common

import "testing"

func TestCWNDFromFeature(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want uint64
	}{
		{name: "int", in: 80000000, want: 80000000},
		{name: "int64", in: int64(123), want: 123},
		{name: "uint64", in: uint64(9), want: 9},
		{name: "zero int", in: 0, want: 0},
		{name: "negative", in: -5, want: 0},
		{name: "nil", in: nil, want: 0},
		{name: "string", in: "brutal", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CWNDFromFeature(tc.in); got != tc.want {
				t.Fatalf("CWNDFromFeature(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

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
			got, err := SelectCongestionController(tc.serverCC, tc.override)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("SelectCongestionController(%q, %q) = %q, want error",
						tc.serverCC, tc.override, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SelectCongestionController(%q, %q): %v", tc.serverCC, tc.override, err)
			}
			if got != tc.want {
				t.Fatalf("SelectCongestionController(%q, %q) = %q, want %q",
					tc.serverCC, tc.override, got, tc.want)
			}
		})
	}
}
