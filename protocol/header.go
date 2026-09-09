package protocol

import "crypto/tls"

type Header struct {
	ProxyAddress string
	SNI          string
	Feature1     interface{}
	Feature2     interface{}
	// CongestionOverride is a client-local congestion controller override. It
	// is never sent to the server: Feature1 keeps carrying the value that the
	// handshake echoes back. Empty means "use the server-echoed controller".
	CongestionOverride string
	TlsConfig          *tls.Config
	Cipher             string
	User               string
	Password           string
	IsClient           bool
	Flags              Flags
}

type Flags uint64

const (
	Flags_VMess_UsePacketAddr = 1 << iota
)

const (
	Flags_Tuic_UdpRelayModeQuic = 1 << iota
)
