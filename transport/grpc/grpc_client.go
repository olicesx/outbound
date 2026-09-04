package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/cert"
	proto "github.com/daeuniverse/outbound/pkg/gun_proto"
	"github.com/daeuniverse/outbound/pool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// https://github.com/v2fly/v2ray-core/blob/v5.0.6/transport/internet/grpc/dial.go
type clientConnMeta struct {
	cc *grpc.ClientConn
}

var (
	globalCCMap    map[string]*clientConnMeta
	globalCCAccess sync.Mutex
)

func grpcClientCacheKey(scope, serverName, address string, allowInsecure bool, somark uint32, mptcp bool) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%t\x00%d\x00%t", scope, serverName, address, allowInsecure, somark, mptcp)
}

func scopedCachePrefix(scope string) string {
	return scope + "\x00"
}

func CleanGlobalClientConnectionCache() {
	globalCCAccess.Lock()
	cached := make([]*grpc.ClientConn, 0, len(globalCCMap))
	for _, meta := range globalCCMap {
		if meta != nil && meta.cc != nil {
			cached = append(cached, meta.cc)
		}
	}
	globalCCMap = make(map[string]*clientConnMeta)
	globalCCAccess.Unlock()

	for _, cc := range cached {
		_ = cc.Close()
	}
}

func CleanScopedClientConnectionCache(scope string) {
	if scope == "" {
		return
	}
	prefix := scopedCachePrefix(scope)
	globalCCAccess.Lock()
	var cached []*grpc.ClientConn
	for key, meta := range globalCCMap {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if meta != nil && meta.cc != nil {
			cached = append(cached, meta.cc)
		}
		delete(globalCCMap, key)
	}
	globalCCAccess.Unlock()

	for _, cc := range cached {
		_ = cc.Close()
	}
}

type ccCanceller func()

type ClientConn struct {
	tun       proto.GunService_TunClient
	closer    context.CancelFunc
	muReading sync.Mutex // muReading protects reading
	muWriting sync.Mutex // muWriting protects writing
	muSend    sync.Mutex // muSend serializes stream sends
	buf       []byte
	offset    int

	// recvCh is fed by a single lazily-started receive pump so an abandoned
	// deadline-expired Read cannot lose a received hunk (a per-Read Recv
	// goroutine whose buffered(1) result channel nobody drains anymore).
	recvCh   chan RecvResp
	pumpOnce sync.Once
	recvErr  error

	deadlineMu    sync.Mutex
	readDeadline  *time.Timer
	writeDeadline *time.Timer

	ctxRead     context.Context
	cancelRead  func()
	ctxWrite    context.Context
	cancelWrite func()
	ctx         context.Context
	cancel      func()
}

// readCtx snapshots the current read-deadline context under deadlineMu: the
// Set*Deadline methods replace ctxRead/ctxWrite concurrently, and selecting
// on the field without the lock is a data race.
func (c *ClientConn) readCtx() context.Context {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.ctxRead
}

func (c *ClientConn) writeCtx() context.Context {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.ctxWrite
}

// ensureRecvPump starts the single receive pump goroutine. It exits when the
// stream context is done or Recv reports a terminal error.
func (c *ClientConn) ensureRecvPump() {
	c.pumpOnce.Do(func() {
		c.recvCh = make(chan RecvResp, 1)
		go func() {
			for {
				recv, e := c.tun.Recv()
				select {
				case c.recvCh <- RecvResp{hunk: recv, err: e}:
				case <-c.ctx.Done():
					return
				}
				if e != nil {
					return
				}
			}
		}()
	})
}

func NewClientConn(tun proto.GunService_TunClient, closer context.CancelFunc) *ClientConn {
	ctx, cancel := context.WithCancel(context.Background())
	ctxRead, cancelRead := context.WithCancel(context.Background())
	ctxWrite, cancelWrite := context.WithCancel(context.Background())
	return &ClientConn{
		tun:         tun,
		closer:      closer,
		ctx:         ctx,
		cancel:      cancel,
		ctxRead:     ctxRead,
		cancelRead:  cancelRead,
		ctxWrite:    ctxWrite,
		cancelWrite: cancelWrite,
	}
}

type RecvResp struct {
	hunk *proto.Hunk
	err  error
}

func (c *ClientConn) Read(p []byte) (n int, err error) {
	c.ensureRecvPump()
	ctxRead := c.readCtx()
	select {
	case <-ctxRead.Done():
		// Deadline expiry is NOT terminal: the pending Recv keeps running in
		// the pump and its result stays queued in recvCh for the next Read
		// after the caller clears or extends the deadline.
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	default:
	}

	c.muReading.Lock()
	defer c.muReading.Unlock()
	if c.recvErr != nil {
		return 0, c.recvErr
	}
	// Refresh after acquiring the read lock so deadline changes made while
	// this operation waited for another reader apply to the pending I/O.
	ctxRead = c.readCtx()
	if c.buf != nil {
		n = copy(p, c.buf[c.offset:])
		c.offset += n
		if c.offset == len(c.buf) {
			pool.Put(c.buf)
			c.buf = nil
		}
		return n, nil
	}
	select {
	case <-ctxRead.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	case recvResp := <-c.recvCh:
		err = recvResp.err
		if err != nil {
			if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
				err = io.EOF
			}
			c.recvErr = err
			return 0, err
		}
		n = copy(p, recvResp.hunk.Data)
		if rest := len(recvResp.hunk.Data) - n; rest > 0 {
			// A zero-length remainder must not be stored: an empty
			// non-nil buf made the next Read return (0, nil), one
			// spurious iteration per fully-consumed hunk.
			c.buf = pool.Get(rest)
			copy(c.buf, recvResp.hunk.Data[n:])
			c.offset = 0
		}
		return n, nil
	}
}

func (c *ClientConn) Write(p []byte) (n int, err error) {
	ctxWrite := c.writeCtx()
	select {
	case <-ctxWrite.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	default:
	}

	c.muWriting.Lock()
	defer c.muWriting.Unlock()
	// Refresh after acquiring the write lock so deadline changes made while
	// this operation waited for another writer apply to the pending I/O.
	ctxWrite = c.writeCtx()
	// set 1 to avoid channel leak
	sendDone := make(chan error, 1)
	// pass channel to the function to avoid closure leak
	go func(sendDone chan error) {
		c.muSend.Lock()
		defer c.muSend.Unlock()
		e := c.tun.Send(&proto.Hunk{Data: p})
		sendDone <- e
	}(sendDone)
	select {
	case <-ctxWrite.Done():
		// A wedged gRPC Send cannot be aborted or bypassed, and a second
		// Send must not overtake it (that would reorder stream data), so
		// cancelling the stream is the only way to unblock writers. Write
		// deadlines are therefore terminal for this conn, unlike read
		// deadlines above.
		c.closer() // Cancel stream context so the Send goroutine can exit
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	case err = <-sendDone:
		if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
			err = io.EOF
		}
		return len(p), err
	}
}

// armDeadline replaces the timer in slot with one that cancels the matching
// context half at t. Callers must hold deadlineMu.
func (c *ClientConn) armDeadline(slot **time.Timer, t time.Time, done <-chan struct{}, cancel context.CancelFunc) {
	if *slot != nil {
		(*slot).Stop()
	}
	*slot = time.AfterFunc(time.Until(t), func() {
		c.deadlineMu.Lock()
		defer c.deadlineMu.Unlock()
		select {
		case <-done:
		default:
			cancel()
		}
	})
}

func (c *ClientConn) Close() error {
	c.deadlineMu.Lock()
	if c.readDeadline != nil {
		c.readDeadline.Stop()
	}
	if c.writeDeadline != nil {
		c.writeDeadline.Stop()
	}
	c.deadlineMu.Unlock()
	select {
	case <-c.ctx.Done():
	default:
		c.cancel()
	}
	c.closer()
	return nil
}
func (c *ClientConn) CloseWrite() error {
	return c.tun.CloseSend()
}

func (c *ClientConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.ctxRead.Done():
			c.ctxRead, c.cancelRead = context.WithCancel(context.Background())

		default:
		}
		select {
		case <-c.ctxWrite.Done():
			c.ctxWrite, c.cancelWrite = context.WithCancel(context.Background())
		default:
		}
		// reset the deadline timers
		c.armDeadline(&c.readDeadline, t, c.ctxRead.Done(), c.cancelRead)
		c.armDeadline(&c.writeDeadline, t, c.ctxWrite.Done(), c.cancelWrite)
	} else {
		select {
		case <-c.ctxRead.Done():
		default:
			c.cancelRead()
		}
		select {
		case <-c.ctxWrite.Done():
		default:
			c.cancelWrite()
		}
	}
	return nil
}

func (c *ClientConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.ctxRead.Done():
			c.ctxRead, c.cancelRead = context.WithCancel(context.Background())
		default:
		}
		// reset the deadline timer
		if c.readDeadline != nil {
			c.readDeadline.Stop()
		}
		c.readDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxRead.Done():
			default:
				c.cancelRead()
			}
		})
	} else {
		select {
		case <-c.ctxRead.Done():
		default:
			c.cancelRead()
		}
	}
	return nil
}

func (c *ClientConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.ctxWrite.Done():
			c.ctxWrite, c.cancelWrite = context.WithCancel(context.Background())
		default:
		}
		if c.writeDeadline != nil {
			c.writeDeadline.Stop()
		}
		c.writeDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxWrite.Done():
			default:
				c.cancelWrite()
			}
		})
	} else {
		select {
		case <-c.ctxWrite.Done():
		default:
			c.cancelWrite()
		}
	}
	return nil
}

type Dialer struct {
	NextDialer    netproxy.Dialer
	ServiceName   string
	ServerName    string
	AllowInsecure bool
}

func (d *Dialer) UnwrapDialer() netproxy.Dialer {
	return d.NextDialer
}

func (d *Dialer) DialContext(ctx context.Context, network string, address string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	meta, cancel, err := getGrpcClientConn(ctx, d.NextDialer, d.ServerName, address, d.AllowInsecure, magicNetwork.Mark, magicNetwork.Mptcp)
	if err != nil {
		cancel()
		return nil, err
	}
	client := proto.NewGunServiceClient(meta.cc)

	clientX := client.(proto.GunServiceClientX)
	serviceName := d.ServiceName
	if serviceName == "" {
		serviceName = "GunService"
	}
	// Stream lifetime is independent of the dial ctx (dae cancels dial ctx
	// after Dial returns). Honor the caller ctx only while Tun is opening.
	ctxStream, streamCloser := context.WithCancel(context.Background())
	stopWatch := context.AfterFunc(ctx, streamCloser)
	tun, err := clientX.TunCustomName(ctxStream, serviceName)
	if err != nil {
		_ = stopWatch()
		streamCloser()
		return nil, err
	}
	if !stopWatch() {
		streamCloser()
		_ = tun.CloseSend()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, context.Canceled
	}
	return NewClientConn(tun, streamCloser), nil
}

// systemCertPoolCached resolves the system pool once: GetSystemCertPool is
// not free and previously ran on every dial, even on cache-hit paths.
var (
	systemCertPoolMu  sync.Mutex
	systemCertPool    *x509.CertPool
	systemCertPoolErr error
)

// Success is memoized; a failure (e.g. CA bundle briefly missing at cold
// start) must stay retryable or every gRPC dial fails until restart.
func systemCertPoolCached() (*x509.CertPool, error) {
	systemCertPoolMu.Lock()
	defer systemCertPoolMu.Unlock()
	if systemCertPool != nil {
		return systemCertPool, nil
	}
	systemCertPool, systemCertPoolErr = cert.GetSystemCertPool()
	return systemCertPool, systemCertPoolErr
}

func getGrpcClientConn(ctx context.Context, tcpDialer netproxy.Dialer, serverName string, address string, allowInsecure bool, somark uint32, mptcp bool) (*clientConnMeta, ccCanceller, error) {
	scope := netproxy.TransportCacheNamespace(tcpDialer)
	cacheKey := grpcClientCacheKey(scope, serverName, address, allowInsecure, somark, mptcp)
	// allowInsecure?
	roots, err := systemCertPoolCached()
	if err != nil {
		return nil, func() {}, fmt.Errorf("failed to get system certificate pool")
	}
	certOption := grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: serverName, RootCAs: roots, InsecureSkipVerify: allowInsecure}))

	// Hold the cache lock across lookup, dial and store: grpc.DialContext is
	// lazy (it does not wait for the connection), and doing the dial outside
	// the lock let two concurrent dials for the same key both miss, both
	// connect, and orphan the loser's connection.
	globalCCAccess.Lock()
	defer globalCCAccess.Unlock()
	if globalCCMap == nil {
		globalCCMap = make(map[string]*clientConnMeta)
	}

	var meta *clientConnMeta
	canceller := func() {
		globalCCAccess.Lock()
		if current, ok := globalCCMap[cacheKey]; ok && current == meta {
			delete(globalCCMap, cacheKey)
		}
		globalCCAccess.Unlock()
		if meta != nil && meta.cc != nil {
			_ = meta.cc.Close()
		}
	}

	// TODO Should support chain proxy to the same destination
	if meta, found := globalCCMap[cacheKey]; found && meta.cc.GetState() != connectivity.Shutdown {
		return meta, canceller, nil
	}
	meta = &clientConnMeta{
		cc: nil,
	}
	meta.cc, err = grpc.DialContext(ctx, address,
		certOption,
		grpc.WithContextDialer(func(ctxGrpc context.Context, s string) (net.Conn, error) {
			tcpNetwork := netproxy.MagicNetwork{
				Network: "tcp",
				Mark:    somark,
				Mptcp:   mptcp,
			}.Encode()
			c, err := tcpDialer.DialContext(ctxGrpc, tcpNetwork, s)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{
				Conn:  c,
				LAddr: nil,
				RAddr: nil,
			}, nil
		}), grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}), grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, canceller, err
	}
	globalCCMap[cacheKey] = meta
	return meta, canceller, err
}
