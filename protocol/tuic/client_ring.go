package tuic

import (
	"context"
	"sync/atomic"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/infra/clientring"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
)

// udpAssociationsPerConn is how many UDP associations one QUIC connection
// carries before the ring places further ones on another connection.
//
// The count itself costs nothing: measured on loopback, one connection
// forwarded at the same rate with 256 and with 60,000 associations. What it
// spreads is the load on a connection's single QUIC run loop and datagram
// demux goroutine: two connections carrying the same 16,384 associations
// sustained 37% more round trips per second than one. The value is a policy
// choice rather than a measured knee. 2048 keeps an ordinary network on one
// connection and its single handshake, keeps association-ID allocation to
// one probe in practice (3% of the ID space in use), and gives a heavily
// loaded client one more connection per 2048 associations.
const udpAssociationsPerConn = 2048

// clientRing wraps the shared failover ring (protocol/infra/clientring)
// with the tuic dial bodies.
type clientRing struct {
	ring      *clientring.Ring[*clientImpl]
	newClient func(capabilityCallback func(n int64)) *clientImpl
	reserved  int64
	// associationCap is udpAssociationsPerConn; a field, atomically read on
	// the dial path, so tests can lower it.
	associationCap atomic.Int64
}

func newClientRing(newClient func(capabilityCallback func(n int64)) *clientImpl, reserved, associationCap int64) *clientRing {
	r := &clientRing{
		ring: clientring.New(
			newClient,
			func(cli *clientImpl, onClose func()) { cli.setOnClose(onClose) },
			func(cli *clientImpl) error { return cli.Close() },
			reserved,
		),
		newClient: newClient,
		reserved:  reserved,
	}
	r.associationCap.Store(associationCap)
	return r
}

func (r *clientRing) DialContextWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (conn netproxy.Conn, err error) {
	err = r.ring.TryNextContext(ctx, func(node *clientring.Node[*clientImpl]) error {
		if capability := node.Capability(); capability != -1 && capability <= r.reserved {
			return common.ErrHoldOn
		}
		conn, err = node.Client.DialContextWithDialer(ctx, metadata, dialer, dialFn)
		return err
	})
	return conn, err
}

func (r *clientRing) ListenPacketWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (conn netproxy.PacketConn, err error) {
	// An association rides QUIC datagrams and never opens a bidirectional
	// stream, so UDP is placed by association count rather than by the
	// stream headroom that gates TCP. Hold is per request here: the ring
	// moves on to a connection with room (or opens one) and still keeps
	// routing TCP through this one.
	err = r.ring.TryNextContext(ctx, func(node *clientring.Node[*clientImpl]) error {
		if node.Client.udpAssociationCount() >= r.associationCap.Load() {
			return common.ErrHoldOn
		}
		conn, err = node.Client.ListenPacketWithDialer(ctx, metadata, dialer, dialFn)
		return err
	})
	return conn, err
}

func (r *clientRing) Close() error {
	return r.ring.Close()
}
