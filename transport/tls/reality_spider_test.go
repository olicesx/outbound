package tls

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// realityTestLink builds a REALITY link with a valid pbk/sid/fp so construction
// reaches the spiderX parsing this test targets. Without a valid fp the
// fingerprint check fails first and the spiderX code is never reached.
//
// The spiderX value is query-escaped the way a real link carries it (the
// parser calls url.QueryUnescape on the raw value before parsing it, so the
// escaped and unescaped forms must survive the round trip).
func realityTestLink(t *testing.T, spx string) string {
	t.Helper()
	key := mustGenerateX25519Key(t)
	pbk := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	return "reality://example.com:443?sni=example.com&pbk=" + pbk +
		"&sid=0123456789abcdef&fp=chrome&spx=" + url.QueryEscape(spx)
}

// TestNewRealityMalformedSpiderXDoesNotPanic is the P2-13 defect-A regression:
// url.Parse returns a nil *URL for an unparseable spiderX, and the pre-fix
// code dereferenced it on the very next line. The host of this function is
// configuration load / hot reload, where the link can be subscription- or
// typo-controlled, so it must return an error rather than panic the process.
func TestNewRealityMalformedSpiderXDoesNotPanic(t *testing.T) {
	for _, spx := range []string{
		"/%00",   // NUL: url.Parse rejects the control character
		"/\x7f",  // raw DEL
		"//[::1", // unterminated IPv6 host
	} {
		link := realityTestLink(t, spx)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("spx=%q: NewReality panicked: %v", spx, r)
				}
			}()
			x, err := NewReality(link, nil)
			if err == nil {
				t.Fatalf("spx=%q: NewReality returned %#v, want an error", spx, x)
			}
			if !strings.Contains(err.Error(), "spiderX") {
				t.Fatalf("spx=%q: error = %v, want it to name spiderX", spx, err)
			}
		}()
	}
}

// TestNewRealityValidSpiderXStillParses pins that the new error check does not
// reject the values REALITY actually uses, including the query parameters that
// drive the spider's padding/concurrency/timing schedule.
func TestNewRealityValidSpiderXStillParses(t *testing.T) {
	for _, tc := range []struct {
		spx string
		// spiderY holds the parsed start/end pairs; indices without a param in
		// the input stay zero.
		wantY []int64
	}{
		{"/", nil},
		{"/?p=100-200&c=2-3&t=4-5&i=6-7&r=8-9", []int64{100, 200, 2, 3, 4, 5, 6, 7, 8, 9}},
		{"/?p=100", []int64{100, 100, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"/path", nil},
	} {
		x, err := NewReality(realityTestLink(t, tc.spx), nil)
		if err != nil {
			t.Fatalf("spx=%q: NewReality error = %v", tc.spx, err)
		}
		if x.spiderX == "" || x.spiderX[0] != '/' {
			t.Fatalf("spx=%q: spiderX = %q, want a rooted path", tc.spx, x.spiderX)
		}
		if tc.wantY != nil {
			for i, want := range tc.wantY {
				if x.spiderY[i] != want {
					t.Fatalf("spx=%q: spiderY[%d] = %d, want %d", tc.spx, i, x.spiderY[i], want)
				}
			}
			// Note: this fork strips the schedule params from u.RawQuery, but
			// x.spiderX is taken from tmpU.String(), so the parameters remain
			// in the spider's request path. That is pre-existing behaviour and
			// is recorded here rather than silently asserted away.
			if !strings.HasPrefix(x.spiderX, "/") {
				t.Fatalf("spx=%q: spiderX = %q, want a rooted path", tc.spx, x.spiderX)
			}
			if _, err := url.Parse(x.spiderX); err != nil {
				t.Fatalf("spx=%q: spiderX = %q is not a parseable URL: %v", tc.spx, x.spiderX, err)
			}
		}
	}
}

// TestNewRealityRejectsNonRootedSpiderX pins the pre-existing guard that runs
// after the parse, so the new error check did not replace it.
func TestNewRealityRejectsNonRootedSpiderX(t *testing.T) {
	if _, err := NewReality(realityTestLink(t, "relative/path"), nil); err == nil {
		t.Fatal("NewReality accepted a non-rooted spiderX")
	}
}
