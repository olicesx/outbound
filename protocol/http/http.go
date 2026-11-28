package http

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	tls2 "github.com/daeuniverse/outbound/transport/tls"
)

// HttpProxy is an HTTP/HTTPS proxy.
type HttpProxy struct {
	https     bool
	transport bool
	Addr      string
	Host      string
	Path      string
	HaveAuth  bool
	Username  string
	Password  string
	dialer    netproxy.Dialer
}

func NewHTTPProxy(u *url.URL, forward netproxy.Dialer) (netproxy.Dialer, error) {
	return NewHTTPProxyWithTLSOptions(u, forward, nil)
}

// NewHTTPProxyWithTLSOptions applies the caller's TLS defaults to HTTPS proxies.
// URL options override implementation and fingerprint, and can opt out of verification.
func NewHTTPProxyWithTLSOptions(u *url.URL, forward netproxy.Dialer, defaults *dialer.ExtraOption) (netproxy.Dialer, error) {
	s := new(HttpProxy)
	query := u.Query()
	s.Addr = u.Host
	s.Path = u.Path
	if !strings.HasPrefix(s.Path, "/") {
		s.Path = "/" + s.Path
	}
	s.Host = query.Get("host")
	s.dialer = forward
	if u.User != nil {
		s.HaveAuth = true
		s.Username = u.User.Username()
		s.Password, _ = u.User.Password()
	}
	s.transport, _ = strconv.ParseBool(query.Get("transport"))
	if u.Scheme == "https" {
		s.https = true
		serverName := query.Get("sni")
		if serverName == "" {
			serverName = u.Hostname()
		}

		options := dialer.ExtraOption{TlsImplementation: "tls"}
		if defaults != nil {
			options = *defaults
		}
		if impl := query.Get("tlsImplementation"); impl != "" {
			options.TlsImplementation = impl
		}
		if imitate := query.Get("utlsImitate"); imitate != "" {
			options.UtlsImitate = imitate
		}
		alpnValue := "h2,http/1.1"
		if query.Get("alpn") != "" {
			alpnValue = query.Get("alpn")
		}
		tlsURL := url.URL{
			Host: s.Addr,
			RawQuery: url.Values{
				"sni":  []string{serverName},
				"alpn": []string{alpnValue},
			}.Encode(),
		}
		options.AllowInsecure = options.AllowInsecure || dialer.AllowInsecureFromQuery(query)
		var err error
		s.dialer, _, err = tls2.NewTls(&options, s.dialer, tlsURL.String())
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *HttpProxy) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return NewConn(ctx, s.dialer, s, addr, network), nil
	case "udp":
		return nil, netproxy.UnsupportedTunnelTypeError
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
