package protocol

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
)

type Metadata struct {
	Type     MetadataType
	Hostname string
	Port     uint16
	// IP carries the parsed address for MetadataTypeIPv4/IPv6 so hot paths
	// avoid the Hostname string round-trip. Invalid for other types.
	IP netip.Addr
	// Cmd is valid only if Type is MetadataTypeMsg.
	Cmd      MetadataCmd
	Cipher   string
	IsClient bool
}

// maxDomainIpCacheEntries bounds a domain->IP cache handed to DomainIpMapping.
//
// The key is the hostname carried in a received packet's metadata, so it is
// chosen by the peer, and nothing in the protocol requires a response to use an
// IP-typed address. Measured on the production path, one distinct hostname per
// datagram retains ~165 bytes each, i.e. ~33 MB for 200k names on a single UDP
// association, held until that association closes. The cache exists to save a
// repeated resolution, so refusing new entries past this bound changes no
// result: a miss resolves, exactly as the first occurrence did. Normal traffic
// needs one or two entries per association (dae keys UDP endpoints by
// source and destination), so the bound is far above what correct peers use.
const maxDomainIpCacheEntries = 64

// domainIpCacheHasRoom reports whether the cache may take another entry. It
// counts at most maxDomainIpCacheEntries entries, so it stays O(bound), and it
// runs only on a cache miss -- where a DNS resolution is about to dwarf it.
func domainIpCacheHasRoom(cache *sync.Map) bool {
	n := 0
	cache.Range(func(any, any) bool {
		n++
		return n < maxDomainIpCacheEntries
	})
	return n < maxDomainIpCacheEntries
}

// DomainIpMapping resolves the metadata's destination, caching the domain->IP
// result in the caller's per-connection map. cache must be owned by one
// connection; see maxDomainIpCacheEntries for why its growth is bounded.
func (m *Metadata) DomainIpMapping(cache *sync.Map) (addrPort netip.AddrPort, err error) {
	if m.Type == MetadataTypeDomain {
		if _addr, ok := cache.Load(m.Hostname); ok {
			addrPort = netip.AddrPortFrom(_addr.(netip.Addr), m.Port)
		} else {
			uAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(m.Hostname, strconv.Itoa(int(m.Port))))
			if err != nil {
				return netip.AddrPort{}, err
			}
			addrPort = uAddr.AddrPort()
			if domainIpCacheHasRoom(cache) {
				if _addr, ok = cache.LoadOrStore(m.Hostname, addrPort.Addr()); ok {
					addrPort = netip.AddrPortFrom(_addr.(netip.Addr), m.Port)
				}
			}
		}
	} else {
		if addrPort, err = m.AddrPort(); err != nil {
			return netip.AddrPort{}, fmt.Errorf("ReadFrom AddrPort: %w", err)
		}
	}
	return addrPort, nil
}

type MetadataCmd uint8

const (
	MetadataCmdPing MetadataCmd = iota
	MetadataCmdSyncPassages
	MetadataCmdResponse
)

type MetadataType int

const (
	MetadataTypeIPv4 MetadataType = iota
	MetadataTypeIPv6
	MetadataTypeDomain
	MetadataTypeMsg
	MetadataTypeInvalid
)

func ParseMetadata(tgt string) (mdata Metadata, err error) {
	host, strPort, err := net.SplitHostPort(tgt)
	if err != nil {
		return mdata, fmt.Errorf("SplitHostPort: %w", err)
	}
	port, err := strconv.ParseUint(strPort, 10, 16)
	if err != nil {
		return mdata, fmt.Errorf("failed to parse port: %w", err)
	}
	tgtIP, err := netip.ParseAddr(host)
	var typ MetadataType
	if err != nil {
		typ = MetadataTypeDomain
	} else if tgtIP.Is4() {
		typ = MetadataTypeIPv4
	} else {
		typ = MetadataTypeIPv6
	}
	return Metadata{
		Type:     typ,
		Hostname: host,
		Port:     uint16(port),
		IP:       tgtIP,
	}, nil
}

func (m *Metadata) AddrPort() (netip.AddrPort, error) {
	switch m.Type {
	case MetadataTypeIPv4, MetadataTypeIPv6:
		if m.IP.IsValid() {
			return netip.AddrPortFrom(m.IP, m.Port), nil
		}
		ip, err := netip.ParseAddr(m.Hostname)
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(ip, m.Port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("bad metadata type: %v; should be ip", m.Type)
	}
}
