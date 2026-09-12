package protocol

import (
	"net"
	"net/netip"
	"sync"
	"testing"
)

func cacheEntries(cache *sync.Map) (n int) {
	cache.Range(func(any, any) bool {
		n++
		return true
	})
	return n
}

// TestDomainIpMappingBoundsTheCache is the regression guard for the unbounded
// per-connection domain->IP cache. Its key is the hostname carried in a
// received packet's metadata, so it is chosen by the peer: measured on the
// production path, one distinct hostname per datagram retains ~165 bytes, i.e.
// ~33 MB for 200k names on a single UDP association, held until the association
// closes. The cache must stop growing at its bound without changing any result.
//
// The hostnames are IP literals, which net.ResolveUDPAddr parses without a DNS
// query, so this test needs no network.
func TestDomainIpMappingBoundsTheCache(t *testing.T) {
	var cache sync.Map
	const lookups = maxDomainIpCacheEntries * 4
	for i := 0; i < lookups; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		m := Metadata{Type: MetadataTypeDomain, Hostname: ip.String(), Port: 53}
		got, err := m.DomainIpMapping(&cache)
		if err != nil {
			t.Fatalf("lookup %d (%s): %v", i, m.Hostname, err)
		}
		// Compare against the resolver itself rather than a hand-built address:
		// the point is that the bound never changes the answer, and
		// ResolveUDPAddr's own representation (a 4-in-6 mapped address for an
		// IPv4 literal) is part of that answer.
		resolved, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), "53"))
		if err != nil {
			t.Fatalf("lookup %d: ResolveUDPAddr: %v", i, err)
		}
		if want := resolved.AddrPort(); got != want {
			t.Fatalf("lookup %d (%s): addr = %v, want %v", i, m.Hostname, got, want)
		}
	}
	if n := cacheEntries(&cache); n > maxDomainIpCacheEntries {
		t.Fatalf("cache holds %d entries after %d distinct hostnames, want <= %d",
			n, lookups, maxDomainIpCacheEntries)
	}
	if n := cacheEntries(&cache); n == 0 {
		t.Fatal("cache stored nothing; the bound must not disable caching")
	}
}

// TestDomainIpMappingCachesBelowTheBound pins the other half of the contract:
// under the bound the cache still saves the resolution, so the fix is a bound
// and not a silent disable.
func TestDomainIpMappingCachesBelowTheBound(t *testing.T) {
	var cache sync.Map
	m := Metadata{Type: MetadataTypeDomain, Hostname: "10.1.2.3", Port: 53}
	if _, err := m.DomainIpMapping(&cache); err != nil {
		t.Fatalf("DomainIpMapping: %v", err)
	}
	if _, ok := cache.Load("10.1.2.3"); !ok {
		t.Fatal("a lookup below the bound was not cached")
	}
	if got := cacheEntries(&cache); got != 1 {
		t.Fatalf("cache holds %d entries after one hostname, want 1", got)
	}
}

// TestDomainIpMappingBoundsOnlyTheDomainBranch pins that resolving an
// IP-typed metadata neither consults nor grows the domain cache, so the bound
// cannot affect the branch that has no key domain at all.
func TestDomainIpMappingBoundsOnlyTheDomainBranch(t *testing.T) {
	var cache sync.Map
	ip := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	m := Metadata{Type: MetadataTypeIPv4, IP: ip, Hostname: ip.String(), Port: 443}
	got, err := m.DomainIpMapping(&cache)
	if err != nil {
		t.Fatalf("DomainIpMapping: %v", err)
	}
	if want := netip.AddrPortFrom(ip, 443); got != want {
		t.Fatalf("addr = %v, want %v", got, want)
	}
	if n := cacheEntries(&cache); n != 0 {
		t.Fatalf("IP-typed metadata touched the domain cache (%d entries)", n)
	}
}
