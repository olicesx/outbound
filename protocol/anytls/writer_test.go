package anytls

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- harnesses ----

// gateConn lets a test gate the writer: writes flow until hold() and
// resume after release(). A closed gate channel means "open".
type gateConn struct {
	mu       sync.Mutex
	writes   [][]byte
	gate     chan struct{}
	held     bool
	closed   atomic.Bool
	entered  atomic.Int32
	writeErr error
	wdNano   atomic.Int64
}

func newGateConn() *gateConn {
	gate := make(chan struct{})
	close(gate)
	return &gateConn{gate: gate}
}

func (c *gateConn) hold() {
	c.mu.Lock()
	c.gate = make(chan struct{})
	c.held = true
	c.mu.Unlock()
}

func (c *gateConn) release() {
	c.mu.Lock()
	gate := c.gate
	c.gate = nil
	held := c.held
	c.held = false
	c.mu.Unlock()
	if gate != nil && held {
		close(gate)
	}
}

func (c *gateConn) Write(p []byte) (int, error) {
	c.entered.Add(1)
	c.mu.Lock()
	gate := c.gate
	err := c.writeErr
	var cp []byte
	if err == nil {
		cp = append([]byte(nil), p...)
	}
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	// A nil gate is fully open; an open (unclosed) gate blocks until
	// release or the write deadline, whichever comes first.
	if gate != nil {
		timeout := 30 * time.Second
		if wd := c.wdNano.Load(); wd != 0 {
			timeout = time.Until(time.Unix(0, wd))
			if timeout < 0 {
				return 0, os.ErrDeadlineExceeded
			}
		}
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-gate:
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		}
	}
	c.mu.Lock()
	c.writes = append(c.writes, cp)
	c.mu.Unlock()
	return len(p), nil
}

func (c *gateConn) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.writes))
	copy(out, c.writes)
	return out
}

func (c *gateConn) Read([]byte) (int, error)        { time.Sleep(time.Hour); return 0, nil }
func (c *gateConn) Close() error                    { c.closed.Store(true); return nil }
func (c *gateConn) LocalAddr() net.Addr             { return testAddr("local") }
func (c *gateConn) RemoteAddr() net.Addr            { return testAddr("remote") }
func (c *gateConn) SetDeadline(t time.Time) error   { return c.SetWriteDeadline(t) }
func (c *gateConn) SetReadDeadline(time.Time) error { return nil }
func (c *gateConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.wdNano.Store(0)
	} else {
		c.wdNano.Store(t.UnixNano())
	}
	return nil
}

// decodedWire concatenates every recorded write and decodes the frames.
func decodedWire(t *testing.T, writes [][]byte) []decodedTestFrame {
	t.Helper()
	var wire []byte
	for _, w := range writes {
		wire = append(wire, w...)
	}
	return decodeTestFrames(t, wire)
}

// ---- opportunistic batching ----

// One write per small frame from a single stream must not cost one socket
// write per frame once the writer is briefly outrun: the gather coalesces
// the already-queued frames into one burst (honk drain_available).
func TestWriterGathersQueuedFramesIntoOneBurst(t *testing.T) {
	conn := newGateConn()
	s := newSession(conn, 1)
	s.sendPadding = false
	defer func() { _ = s.Close() }()
	stream := newStream(s, 1)

	// Gate the writer on a known first frame so the queue state at gather
	// time is deterministic.
	conn.hold()
	if _, err := stream.Write([]byte("first")); err != nil {
		t.Fatalf("gated Write: %v", err)
	}
	waitFor(t, func() bool { return conn.entered.Load() > 0 }, "writer entered the gated write")
	const n = 31
	for i := 0; i < n; i++ {
		if _, err := stream.Write([]byte("payload")); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if got := s.wq.depth(); got != n {
		t.Fatalf("queued frames = %d, want %d (Write must return at enqueue)", got, n)
	}
	conn.release()
	s.wq.waitDrain()

	writes := conn.snapshot()
	if len(writes) != 2 {
		t.Fatalf("socket writes = %d, want 2 (one gated frame plus one gathered burst)", len(writes))
	}
	frames := decodedWire(t, writes)
	if len(frames) != n+1 {
		t.Fatalf("frames on wire = %d, want %d", len(frames), n+1)
	}
}

// waitFor polls cond until true or fails the test.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", msg)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// The gather respects the frame cap: 200 queued frames flush as bursts of
// at most writerBatchMaxFrames.
func TestWriterBatchFrameCap(t *testing.T) {
	conn := newGateConn()
	s := newSession(conn, 1)
	s.sendPadding = false
	defer func() { _ = s.Close() }()
	stream := newStream(s, 1)

	conn.hold()
	const n = 200
	for i := 0; i < n; i++ {
		if _, err := stream.Write([]byte("x")); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	conn.release()
	s.wq.waitDrain()

	writes := conn.snapshot()
	// The gated first frame leaves alone; the remaining n-1 frames ride
	// bursts of at most writerBatchMaxFrames-1 gathered extras.
	for i, w := range writes {
		if i == 0 {
			continue
		}
		if got := len(decodeTestFrames(t, w)); got > writerBatchMaxFrames {
			t.Fatalf("burst %d carried %d frames, cap %d", i, got, writerBatchMaxFrames)
		}
	}
	if total := len(decodedWire(t, writes)); total != n {
		t.Fatalf("frames on wire = %d, want %d", total, n)
	}
}

// ---- concurrency and ordering ----

// Concurrent writers on several streams must each preserve their own frame
// order on the wire (FIFO queue, per-stream sequence intact).
func TestWriterConcurrentStreamsPreserveOrder(t *testing.T) {
	conn := newGateConn()
	s := newSession(conn, 1)
	s.sendPadding = false
	defer func() { _ = s.Close() }()

	const streams = 6
	const perStream = 400
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 1; i <= streams; i++ {
		wg.Add(1)
		go func(sid uint32) {
			defer wg.Done()
			<-start
			for j := 0; j < perStream; j++ {
				payload := make([]byte, 8)
				binary.BigEndian.PutUint32(payload, sid)
				binary.BigEndian.PutUint32(payload[4:], uint32(j))
				if _, err := writeDataFrames(s, sid, payload, time.Time{}); err != nil {
					t.Errorf("stream %d write %d: %v", sid, j, err)
					return
				}
			}
		}(uint32(i))
	}
	close(start)
	wg.Wait()
	s.wq.waitDrain()

	frames := decodedWire(t, conn.snapshot())
	seq := map[uint32]uint32{}
	for _, f := range frames {
		if len(f.data) != 8 {
			t.Fatalf("unexpected frame payload size %d", len(f.data))
		}
		sid := binary.BigEndian.Uint32(f.data)
		idx := binary.BigEndian.Uint32(f.data[4:])
		if got := seq[sid]; got != idx {
			t.Fatalf("stream %d: frame %d arrived after %d (out of order)", sid, idx, got)
		}
		seq[sid] = idx + 1
	}
	for i := 1; i <= streams; i++ {
		if seq[uint32(i)] != perStream {
			t.Fatalf("stream %d delivered %d frames, want %d", i, seq[uint32(i)], perStream)
		}
	}
}

// ---- backpressure ----

// With the writer blocked, the queue fills; a further Write blocks instead
// of growing memory, and completes once the writer drains.
func TestWriterQueueBackpressuresStreams(t *testing.T) {
	conn := newGateConn()
	s := newSession(conn, 1)
	s.sendPadding = false
	defer func() { _ = s.Close() }()
	stream := newStream(s, 1)

	// Park the writer inside one gated batch first so the fill depth is
	// deterministic. The parked frame is already popped and does not count
	// toward the queued byte cap.
	conn.hold()
	if _, err := stream.Write(make([]byte, maxFramePayloadSize)); err != nil {
		t.Fatalf("parking Write: %v", err)
	}
	waitFor(t, func() bool { return conn.entered.Load() > 0 }, "writer entered the gated write")

	// Fill the byte cap exactly: maxFramePayloadSize frames fill
	// writerDataBytesCap, so one more byte must block.
	filler := make([]byte, maxFramePayloadSize)
	frames := writerDataBytesCap / maxFramePayloadSize
	for i := 0; i < frames; i++ {
		if _, err := stream.Write(filler); err != nil {
			t.Fatalf("fill write %d: %v", i, err)
		}
	}
	if got := s.wq.depth(); got != frames {
		t.Fatalf("queued frames = %d, want %d before the cap", got, frames)
	}

	blocked := make(chan error, 1)
	go func() {
		_, err := stream.Write([]byte("one more"))
		blocked <- err
	}()
	select {
	case err := <-blocked:
		t.Fatalf("Write past the byte cap returned immediately: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	conn.release()
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("backpressured Write: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backpressured Write never completed after the writer resumed")
	}
	s.wq.waitDrain()
	if got := len(decodedWire(t, conn.snapshot())); got != frames+2 {
		t.Fatalf("frames on wire = %d, want %d", got, frames+2)
	}
}

// ---- write failure kills the session ----

// A physical write failure must kill the whole session: pending confirms
// get the error, later writes fail, and the underlying conn is closed.
func TestWriterFailureKillsSession(t *testing.T) {
	conn := newGateConn()
	s := newSession(conn, 1)
	s.sendPadding = false
	stream := newStream(s, 1)

	failure := errors.New("physical write failure")
	conn.mu.Lock()
	conn.writeErr = failure
	conn.mu.Unlock()
	conn.release() // un-gate so the first write proceeds into the error

	if _, err := writeFrame(s, newFrame(cmdFIN, stream.id)); !errors.Is(err, failure) {
		t.Fatalf("confirmed control write error = %v, want %v", err, failure)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !s.Closed() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.Closed() {
		t.Fatal("physical write failure did not kill the session")
	}
	if !conn.closed.Load() {
		t.Fatal("physical write failure left the underlying conn open")
	}
	// Later writes fail with the failure the writer recorded, not a bare
	// ErrClosed, so callers can distinguish a broken transport.
	if _, err := stream.Write([]byte("after")); !errors.Is(err, failure) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after writer failure = %v, want the recorded failure or %v", err, net.ErrClosed)
	}
}

// A deadline-armed stream write aborting its own batch must NOT kill the
// session, and later unarmed writes must still flush (the abort scope is
// the armed caller's data only).
func TestWriterDeadlineAbortKeepsSessionAlive(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	s := newSession(local, 1)
	defer func() { _ = s.Close() }()
	stream := newStream(s, 1)

	deadline := time.Now().Add(150 * time.Millisecond)
	if err := stream.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := stream.Write([]byte("armed and blocked")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("armed blocked Write = %v, want %v", err, os.ErrDeadlineExceeded)
	}
	if s.Closed() {
		t.Fatal("stream deadline abort must not kill the session")
	}

	if err := stream.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	// Drain the pipe so the unarmed write can complete.
	go func() {
		_, _ = io.Copy(io.Discard, remote)
	}()
	if _, err := stream.Write([]byte("alive")); err != nil {
		t.Fatalf("unarmed Write after abort: %v", err)
	}
	s.wq.waitDrain()
}

// The control-only I/O timeout must become terminal: a control write that
// cannot reach the wire within the window kills the session.
func TestWriterControlTimeoutKillsSession(t *testing.T) {
	oldTimeout := writerIOTimeout
	writerIOTimeout = 50 * time.Millisecond
	t.Cleanup(func() { writerIOTimeout = oldTimeout })

	conn := newGateConn()
	s := newSession(conn, 1)
	defer func() { _ = s.Close() }()

	conn.hold() // every physical write blocks past the control timeout
	start := time.Now()
	if _, err := writeFrame(s, newFrame(cmdHeartRequest, 0)); err == nil {
		t.Fatal("gated control write succeeded, want timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("control timeout took %v, expected the shortened window", elapsed)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !s.Closed() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !s.Closed() {
		t.Fatal("control-only I/O timeout did not kill the session")
	}
}

// ---- shutdown and half-close ordering ----

// Session Close must release blocked producers and waiters without a
// deadlock, failing them with net.ErrClosed.
func TestWriterCloseUnblocksEverything(t *testing.T) {
	conn := newGateConn()
	s := newSession(conn, 1)
	s.sendPadding = false
	stream := newStream(s, 1)

	// Park the writer inside one gated batch first (its frame leaves the
	// queued accounting) so the fill reaches the byte cap deterministically.
	conn.hold()
	if _, err := stream.Write(make([]byte, maxFramePayloadSize)); err != nil {
		t.Fatalf("parking Write: %v", err)
	}
	waitFor(t, func() bool { return conn.entered.Load() > 0 }, "writer entered the gated write")
	filler := make([]byte, maxFramePayloadSize)
	for i := 0; i < writerDataBytesCap/maxFramePayloadSize; i++ {
		if _, err := stream.Write(filler); err != nil {
			t.Fatalf("fill write %d: %v", i, err)
		}
	}
	blocked := make(chan error, 1)
	go func() {
		_, err := stream.Write([]byte("blocked"))
		blocked <- err
	}()
	select {
	case err := <-blocked:
		t.Fatalf("Write past the byte cap returned immediately: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	closed := make(chan struct{})
	go func() {
		_ = s.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close deadlocked with a full queue and blocked writer")
	}
	select {
	case err := <-blocked:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked Write after Close = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Write was not released by Close")
	}
}

// The FIN of a half-close must follow every data frame the same stream
// wrote before CloseWrite, byte-for-byte on the wire.
func TestWriterHalfCloseOrdersFINAfterData(t *testing.T) {
	conn := newGateConn()
	s := newSession(conn, 1)
	s.sendPadding = false
	defer func() { _ = s.Close() }()
	stream := newStream(s, 1)

	// Gate the writer on a parked frame so both data writes provably queue
	// before the FIN is queued behind them.
	conn.hold()
	if _, err := stream.Write([]byte("park")); err != nil {
		t.Fatalf("parking Write: %v", err)
	}
	waitFor(t, func() bool { return conn.entered.Load() > 0 }, "writer entered the gated write")
	if _, err := stream.Write([]byte("first")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := stream.Write([]byte("second")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	waitFor(t, func() bool { return s.wq.depth() >= 2 }, "both data frames queued")

	finDone := make(chan error, 1)
	go func() { finDone <- stream.CloseWrite() }()
	// The FIN queues behind the data frames while the writer is gated.
	waitFor(t, func() bool { return s.wq.depth() >= 3 }, "FIN queued behind the data frames")
	conn.release()
	select {
	case err := <-finDone:
		if err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CloseWrite never completed")
	}
	s.wq.waitDrain()

	frames := decodedWire(t, conn.snapshot())
	if len(frames) != 4 {
		t.Fatalf("frames = %d, want 4 (parked PSH, two PSH, FIN)", len(frames))
	}
	want := []struct {
		cmd  byte
		data string
	}{{cmdPSH, "park"}, {cmdPSH, "first"}, {cmdPSH, "second"}, {cmdFIN, ""}}
	for i, w := range want {
		if frames[i].cmd != w.cmd || string(frames[i].data) != w.data {
			t.Fatalf("frame %d = (cmd %d, %q), want (cmd %d, %q)", i, frames[i].cmd, frames[i].data, w.cmd, w.data)
		}
	}
}

// An armed write must not take unarmed frames down with it: frames queued
// behind an armed frame on another stream still flush after the abort.
func TestWriterArmedBatchIsolation(t *testing.T) {
	conn := newGateConn()
	s := newSession(conn, 1)
	s.sendPadding = false
	defer func() { _ = s.Close() }()
	a := newStream(s, 1)
	b := newStream(s, 2)

	conn.hold()
	if err := a.SetWriteDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	armedDone := make(chan error, 1)
	go func() {
		_, err := a.Write([]byte("armed"))
		armedDone <- err
	}()
	waitFor(t, func() bool { return conn.entered.Load() > 0 }, "armed write reached the conn")
	// Queue an unarmed frame while the armed write is stuck in the gate.
	if _, err := b.Write([]byte("unarmed")); err != nil {
		t.Fatalf("unarmed Write: %v", err)
	}

	select {
	case err := <-armedDone:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("armed Write = %v, want %v", err, os.ErrDeadlineExceeded)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("armed Write was not released by its deadline")
	}
	if s.Closed() {
		t.Fatal("armed abort must not kill the session")
	}

	conn.release()
	s.wq.waitDrain()
	frames := decodedWire(t, conn.snapshot())
	var sawUnarmed bool
	for _, f := range frames {
		if f.sid == 2 && string(f.data) == "unarmed" {
			sawUnarmed = true
		}
	}
	if !sawUnarmed {
		t.Fatalf("unarmed frame never flushed after the armed abort: %+v", frames)
	}
}

// depth returns the number of queued frames (test helper).
func (q *writerQueue) depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items) - q.head
}
