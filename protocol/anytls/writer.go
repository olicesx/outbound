package anytls

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/pool"
)

// The session writer mirrors honk's anytls session_writer
// (crates/honk-outbound/src/proxy/anytls/writer.rs): one goroutine per
// session owns the TLS write path. Streams enqueue whole frames into a
// bounded FIFO and return immediately; the writer opportunistically gathers
// frames that are already queued (never waiting) into one buffer so a batch
// costs one write burst plus one coalescer flush instead of one per frame.
// Order is preserved because every frame rides the same FIFO, so batching
// stays byte-transparent to the peer.
const (
	// writerQueueCap is the total queue depth (data plus the control
	// headroom below). Exhausting it fails control enqueue instead of
	// growing memory without bound.
	writerQueueCap = 1024
	// writerControlReserved keeps slots free for control frames (SYN/FIN/
	// heartbeats) so payload can never starve them: data enqueue stops at
	// writerQueueCap - writerControlReserved queued data frames.
	writerControlReserved = 128
	// writerDataBytesCap bounds in-flight payload bytes queued ahead of the
	// TLS writer. The frame cap alone allowed 896 x 32768 bytes (~28 MiB)
	// of queued payload; honk measured RSS following that growth and
	// settled on 8 MiB as covering writer latency without throttling
	// throughput.
	writerDataBytesCap = 8 << 20
	// writerBatchMaxFrames and writerBatchMaxBytes bound one gathered
	// batch: after the blocking pop of the first frame, at most this many
	// already-queued frames (or serialized bytes) ride the same write burst
	// and flush. Only what is queued now is taken — gathering never waits,
	// so it adds no latency.
	writerBatchMaxFrames = 64
	writerBatchMaxBytes  = 256 << 10
)

// writerIOTimeout bounds a control-only batch's physical write. A stuck
// shared writer must become terminal instead of leaving the session
// selectable by the idle pool. Data batches stay unbounded like honk:
// under uplink congestion the queue caps backpressure the streams instead
// of killing the session and every sibling flow with it. A variable so
// tests can shorten the window.
var writerIOTimeout = 5 * time.Second

// writerFrame is one queued frame plus its enqueue contract.
type writerFrame struct {
	frame frame
	// confirm, when non-nil, receives the outcome of the batch this frame
	// rode in: nil after a successful flush, the write error otherwise. It
	// is also signaled (with an error) when the queue closes or fails
	// before the frame is written, so waiters never block forever.
	confirm chan error
	// deadline is the stream write deadline armed at enqueue time (zero
	// when none). The gather splits runs of mixed armedness so a deadline
	// abort can only ever drop deadline-armed data.
	deadline time.Time
	// data frames count toward the queue data caps; control frames do not.
	isData bool
}

// writerQueue is the bounded FIFO between stream writers and the session
// writer goroutine. Producers block while the data caps are exhausted
// (TCP-style backpressure); the writer blocks until a frame is available or
// the queue closes.
type writerQueue struct {
	mu    sync.Mutex
	items []writerFrame
	head  int // next pop index within items

	dataFrames int
	dataBytes  int

	closed  bool
	dropped error

	// notEmpty wakes the writer after a push; hasSpace wakes producers
	// after a pop or drop. Both are cap-1 signals: waiters re-check state
	// under mu after waking.
	notEmpty chan struct{}
	hasSpace chan struct{}
	// done is closed exactly once when the queue closes, releasing every
	// waiter (writer, producers, drain waiters).
	done chan struct{}
	// busy marks the writer as mid-batch; waitDrain waits for an empty,
	// idle queue. idleWait is closed and replaced on each empty+idle
	// transition (cond-on-channel without an extra goroutine).
	busy     bool
	idleWait chan struct{}
}

func newWriterQueue() *writerQueue {
	return &writerQueue{
		notEmpty: make(chan struct{}, 1),
		hasSpace: make(chan struct{}, 1),
		done:     make(chan struct{}),
		idleWait: make(chan struct{}),
	}
}

// wake sends a cap-1 signal.
func wake(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// groupFitsLocked reports whether pushing controlFrames control frames and
// dataFrames data frames carrying dataBytes payload fits every cap.
func (q *writerQueue) groupFitsLocked(controlFrames, dataFrames, dataBytes int) bool {
	queued := len(q.items) - q.head
	if queued+controlFrames+dataFrames > writerQueueCap {
		return false
	}
	return q.dataFrames+dataFrames <= writerQueueCap-writerControlReserved &&
		q.dataBytes+dataBytes <= writerDataBytesCap
}

// push enqueues one group atomically, blocking while the data caps are
// exhausted. A zero deadline blocks until space or close (backpressure); an
// armed deadline also gives up with os.ErrDeadlineExceeded.
func (q *writerQueue) push(group []writerFrame, deadline time.Time) error {
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		if !deadline.After(time.Now()) {
			return os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		timeout = timer.C
	}
	control, data, bytes := 0, 0, 0
	for _, f := range group {
		if f.isData {
			data++
			bytes += len(f.frame.data)
		} else {
			control++
		}
	}
	for {
		q.mu.Lock()
		if q.closed {
			err := q.dropped
			q.mu.Unlock()
			if err == nil {
				err = net.ErrClosed
			}
			return err
		}
		if q.groupFitsLocked(control, data, bytes) {
			// Compaction keeps the backing array bounded for FIFO use.
			if q.head > 0 && q.head*2 >= len(q.items)-q.head {
				n := copy(q.items, q.items[q.head:])
				q.items = q.items[:n]
				q.head = 0
			}
			q.items = append(q.items, group...)
			q.dataFrames += data
			q.dataBytes += bytes
			q.mu.Unlock()
			wake(q.notEmpty)
			return nil
		}
		q.mu.Unlock()
		select {
		case <-q.hasSpace:
		case <-q.done:
		case <-timeout:
			return os.ErrDeadlineExceeded
		}
	}
}

// pop removes the head frame, updating the data accounting, and wakes
// producers that were blocked on the caps. ok is false once the queue is
// closed and drained.
func (q *writerQueue) pop() (writerFrame, bool) {
	for {
		q.mu.Lock()
		if q.head < len(q.items) {
			f := q.items[q.head]
			q.items[q.head] = writerFrame{}
			q.head++
			if q.head == len(q.items) {
				q.items = q.items[:0]
				q.head = 0
			} else if q.head > 64 && q.head*2 >= len(q.items)-q.head {
				n := copy(q.items, q.items[q.head:])
				q.items = q.items[:n]
				q.head = 0
			}
			if f.isData {
				q.dataFrames--
				q.dataBytes -= len(f.frame.data)
			}
			q.busy = true
			q.mu.Unlock()
			wake(q.hasSpace)
			return f, true
		}
		q.busy = false
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return writerFrame{}, false
		}
		select {
		case <-q.notEmpty:
		case <-q.done:
		}
	}
}

// peek returns the head frame without removing it.
func (q *writerQueue) peek() (writerFrame, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.head < len(q.items) {
		return q.items[q.head], true
	}
	return writerFrame{}, false
}

// gather appends queued frames to batch, bounded by maxFrames and
// maxBytes of serialized payload (the head included, like honk's
// drain_available), without ever waiting. The gather stops at a frame whose
// deadline armedness differs from the batch head: unarmed payload must not
// ride a batch a stream deadline could abort, and an armed frame keeps its
// abort scope to itself.
func (q *writerQueue) gather(batch []writerFrame, maxFrames, maxBytes int) []writerFrame {
	if len(batch) == 0 {
		return batch
	}
	headArmed := !batch[0].deadline.IsZero()
	bytes := headerOverHeadSize + len(batch[0].frame.data)
	for len(batch) < maxFrames {
		f, ok := q.peek()
		if !ok {
			break
		}
		next := bytes + headerOverHeadSize + len(f.frame.data)
		if next > maxBytes {
			break
		}
		if (!f.deadline.IsZero()) != headArmed {
			break
		}
		popped, _ := q.pop()
		batch = append(batch, popped)
		bytes = next
	}
	return batch
}

// endBatch clears the mid-batch marker and wakes waitDrain waiters when the
// queue is empty and idle.
func (q *writerQueue) endBatch() {
	q.mu.Lock()
	q.busy = false
	if q.head >= len(q.items) {
		close(q.idleWait)
		q.idleWait = make(chan struct{})
	}
	q.mu.Unlock()
}

// waitDrain blocks until the queue is empty and the writer is between
// batches (or the queue is closed). Synchronization helper for tests and
// teardown diagnostics; it does not prevent new pushes.
func (q *writerQueue) waitDrain() {
	for {
		q.mu.Lock()
		if q.closed || (q.head >= len(q.items) && !q.busy) {
			q.mu.Unlock()
			return
		}
		wait := q.idleWait
		q.mu.Unlock()
		select {
		case <-wait:
		case <-q.done:
			return
		}
	}
}

// close terminates the queue: producers fail with err, queued frames are
// dropped (their buffers returned through release, their confirms
// signaled), and the writer exits once it finishes its current batch.
func (q *writerQueue) close(err error, release func(writerFrame)) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	if err != nil {
		q.dropped = err
	}
	dropped := q.items[q.head:]
	q.items = nil
	q.head = 0
	q.dataFrames = 0
	q.dataBytes = 0
	q.mu.Unlock()
	close(q.done)
	wake(q.hasSpace)
	for _, f := range dropped {
		signalConfirm(f.confirm, err)
		release(f)
	}
}

func signalConfirm(confirm chan error, err error) {
	if confirm == nil {
		return
	}
	select {
	case confirm <- err:
	default:
	}
}

// releaseFrame returns a flushed frame's payload buffer to the session
// recycle path for the next enqueue.
func (s *session) releaseFrame(f writerFrame) {
	s.recyclePayloadBuf(f.frame.data)
}

// payloadRecycleSlots bounds the session-local direct handoff of frame
// payload buffers between the enqueue side and the writer goroutine.
const payloadRecycleSlots = 4

// takePayloadBuf returns a buffer with at least size bytes of capacity for
// a queued frame's payload copy. The session-recycled path matters because
// sync.Pool ping-pongs between the two goroutines of this pipeline (the
// enqueue side Gets what the writer Puts, on different per-P caches) and
// measured ~80% misses here; the session channel keeps the steady-state
// handoff allocation-free while spilling to the shared pool.
func (s *session) takePayloadBuf(size int) []byte {
	if size <= 0 {
		return nil
	}
	var stash [][]byte
	defer func() {
		for _, buf := range stash {
			select {
			case s.payloadRecycle <- buf:
			default:
				pool.Put(buf)
			}
		}
	}()
	for {
		select {
		case buf := <-s.payloadRecycle:
			if cap(buf) >= size {
				// Safe without clearing: every caller fills the whole
				// [:size] prefix before the buffer becomes observable.
				return buf[:size]
			}
			stash = append(stash, buf)
			continue
		default:
		}
		return pool.Get(size)
	}
}

// recyclePayloadBuf returns a flushed frame's buffer for the next enqueue.
func (s *session) recyclePayloadBuf(buf []byte) {
	if len(buf) == 0 {
		return
	}
	select {
	case s.payloadRecycle <- buf:
	default:
		pool.Put(buf)
	}
}

// runWriter is the session's dedicated writer goroutine (honk
// session_writer). It drains the queue in order and gather-writes whole
// batches per flush. A physical write failure kills the session — frames
// still queued are lost with it. A stream write deadline aborting its own
// batch is not fatal: it releases only that deadline-armed caller's data,
// matching the synchronous write path it replaces.
func (s *session) runWriter() {
	var batch []writerFrame
	for {
		first, ok := s.wq.pop()
		if !ok {
			return
		}
		batch = append(batch[:0], first)

		// While the padding scheme is active a batch carries one frame so
		// bursts keep firing per frame with the packet counter advancing
		// once per burst, exactly like the synchronous path. The session's
		// very first settings frame is the exception: the settings+SYN+PSH
		// opening group pushed atomically beside it rides one burst (honk:
		// initial batches gather two extra frames).
		extra := writerBatchMaxFrames - 1
		if s.paddingAppliesToNextBurst() {
			extra = 0
		}
		if first.frame.cmd == cmdSettings {
			extra = 2
		}
		batch = s.wq.gather(batch, len(batch)+extra, writerBatchMaxBytes)

		err := s.writeBatch(batch)
		for _, f := range batch {
			signalConfirm(f.confirm, err)
			s.releaseFrame(f)
		}
		s.wq.endBatch()
		if err != nil && !isStreamDeadlineAbort(err, batch) {
			// Physical write failure (or the control-only I/O timeout):
			// the shared transport is unusable — kill the session now
			// rather than letting every caller rediscover it.
			s.wq.close(err, s.releaseFrame)
			_ = s.Close()
			return
		}
		if s.closed.Load() {
			return
		}
	}
}

// paddingAppliesToNextBurst reports whether the padding scheme still shapes
// the next burst and disables padding once past its stop packet, mirroring
// the head of writeConnLocked without consuming a packet number: the write
// itself performs the Add.
func (s *session) paddingAppliesToNextBurst() bool {
	if !s.sendPadding {
		return false
	}
	paddingF := s.GetPadding()
	if paddingF == nil || s.pktCounter.Load()+1 >= paddingF.Stop {
		s.sendPadding = false
		return false
	}
	return true
}

// isStreamDeadlineAbort reports whether err is an armed stream write
// deadline aborting the batch's own data — the non-fatal case the
// synchronous path exposed as Write returning os.ErrDeadlineExceeded.
// Unarmed batches carry no stream deadline, so a deadline error there is
// the control-only I/O timeout, which stays fatal like honk.
func isStreamDeadlineAbort(err error, batch []writerFrame) bool {
	return errors.Is(err, os.ErrDeadlineExceeded) && !batch[0].deadline.IsZero()
}

// writeBatch encodes the batch into the session buffer and pushes it
// through one write burst plus one coalescer flush. Armed batches pass
// their earliest stream deadline down; control-only batches are bounded by
// writerIOTimeout; data batches block until written, exactly like the
// synchronous path with no deadline armed.
func (s *session) writeBatch(batch []writerFrame) error {
	totalSize := 0
	for _, f := range batch {
		totalSize += headerOverHeadSize + len(f.frame.data)
	}

	s.connLock.Lock()
	defer s.connLock.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	buffer := s.borrowWriteBuf(totalSize)
	offset := 0
	for _, f := range batch {
		offset += encodeFrame(buffer[offset:], f.frame)
	}
	deadline := time.Time{}
	if !batch[0].deadline.IsZero() {
		// The gather keeps a batch one armedness run, so every frame's
		// deadline is live; the earliest bounds the physical write.
		deadline = batch[0].deadline
		for _, f := range batch[1:] {
			if f.deadline.Before(deadline) {
				deadline = f.deadline
			}
		}
	} else {
		controlOnly := true
		for _, f := range batch {
			if f.isData {
				controlOnly = false
				break
			}
		}
		if controlOnly {
			deadline = time.Now().Add(writerIOTimeout)
		}
	}
	_, err := s.writeConnLockedWithDeadline(buffer, deadline)
	return err
}

// copyFrameData copies payload into a queue-owned buffer: after the enqueue
// returns, the caller owns its slice again.
func (s *session) copyFrameData(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	buf := s.takePayloadBuf(len(data))
	copy(buf, data)
	return buf
}

// makeWriterFrame validates and copies one frame for the queue. Validation
// happens before any copy or enqueue, keeping callers' synchronous errors.
func (s *session) makeWriterFrame(cmd byte, sid uint32, data []byte, isData bool, deadline time.Time, confirm chan error) (writerFrame, error) {
	f := frame{cmd: cmd, sid: sid, data: data}
	if _, err := encodedFrameSize(f); err != nil {
		return writerFrame{}, err
	}
	f.data = s.copyFrameData(data)
	return writerFrame{frame: f, confirm: confirm, deadline: deadline, isData: isData}, nil
}
