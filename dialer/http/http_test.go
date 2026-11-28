package http

import (
	"testing"

	"github.com/daeuniverse/outbound/dialer"
)

func TestHTTPSLinkKeepsAllowInsecureWithoutSNI(t *testing.T) {
	p, err := ParseHTTPURL("https://proxy.example?allowInsecure=true")
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := ParseHTTPURL(p.ExportToURL())
	if err != nil {
		t.Fatal(err)
	}
	if !roundTrip.AllowInsecure || roundTrip.SNI != "" {
		t.Fatalf("TLS options after export: %+v", roundTrip)
	}
}

func TestHTTPSLinkUsesTLSImplementationFromOptions(t *testing.T) {
	opt := &dialer.ExtraOption{TlsImplementation: "utls", UtlsImitate: "unknown-fingerprint"}
	if _, _, err := NewHTTP(opt, nil, "https://proxy.example"); err == nil {
		t.Fatal("HTTPS accepted an invalid uTLS fingerprint")
	}
	if _, _, err := NewHTTP(opt, nil, "http://proxy.example"); err != nil {
		t.Fatalf("plain HTTP used TLS defaults: %v", err)
	}
}
