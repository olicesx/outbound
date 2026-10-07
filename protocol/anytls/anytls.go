package anytls

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

const ( // cmds
	cmdWaste               = iota // Paddings
	cmdSYN                        // stream open
	cmdPSH                        // data push
	cmdFIN                        // stream close, a.k.a EOF mark
	cmdSettings                   // Settings (Client send to Server)
	cmdAlert                      // Alert
	cmdUpdatePaddingScheme        // update padding scheme
	// Since version 2
	cmdSYNACK         // Server reports to the client that the stream has been opened
	cmdHeartRequest   // Keep alive command
	cmdHeartResponse  // Keep alive command
	cmdServerSettings // Settings (Server send to client)
)

const (
	headerOverHeadSize = 1 + 4 + 2
	// maxFramePayloadSize caps a single frame's data so the encoded frame
	// (headerOverHeadSize + data) stays within pool's largest bucket (65536).
	// At math.MaxUint16 a frame encodes to 65542 bytes, overflowing the pool
	// and forcing a heap allocation per write — a ~67x slowdown near 64KB.
	// The receiver reads by the wire Length field, so the sender's chunking
	// choice does not affect protocol compatibility.
	//
	// Downstream contract: consumers (e.g. dae's TCP relay, buffer 32 KiB)
	// hand whole read buffers to stream.Write. Keep relayCopyBufferSize an
	// integer multiple of this value or a 32 KiB read splits into a full
	// frame plus a one-byte tail frame (measured as a large regression on
	// other implementations). TestRelayBufferAlignment locks this property
	// for the common buffer sizes.
	maxFramePayloadSize = 32768
	maxUDPPayloadSize   = 65535
)

// frame defines a packet from or to be multiplexed into a single connection
type frame struct {
	cmd  byte   // 1
	sid  uint32 // 4
	data []byte // 2 + len(data)
}

func newFrame(cmd byte, sid uint32) frame {
	return frame{cmd: cmd, sid: sid}
}

type rawHeader [headerOverHeadSize]byte

func (h rawHeader) Cmd() byte {
	return h[0]
}

func (h rawHeader) StreamID() uint32 {
	return binary.BigEndian.Uint32(h[1:])
}

func (h rawHeader) Length() uint16 {
	return binary.BigEndian.Uint16(h[5:])
}

// writeFrame enqueues one frame on the session writer queue and waits for
// its flush. Callers are the control paths (dial open, half-close FIN,
// heartbeats) that must observe the write result synchronously, so unlike
// stream data writes they block until the frame left the process. Queue
// ownership of the payload is taken at enqueue; validation errors stay
// synchronous.
func writeFrame(session *session, frame frame) (int, error) {
	confirm := make(chan error, 1)
	wf, err := session.makeWriterFrame(frame.cmd, frame.sid, frame.data, frame.cmd == cmdPSH, time.Time{}, confirm)
	if err != nil {
		return 0, err
	}
	if err := session.wq.push([]writerFrame{wf}, time.Time{}); err != nil {
		session.releaseFrame(wf)
		return 0, err
	}
	if werr := <-confirm; werr != nil {
		return 0, werr
	}
	return len(frame.data), nil
}

// writeFrames pushes a group of frames onto the writer queue atomically —
// nothing can interleave inside the group — and waits for the group's flush
// through a completion on its last frame. Used by newStream so the settings/
// SYN/address-PSH opening and the SYN/address-PSH pair of a reused session
// each leave as one burst.
func writeFrames(session *session, frames ...frame) (int, error) {
	if len(frames) == 0 {
		return 0, nil
	}
	group := make([]writerFrame, 0, len(frames))
	totalData := 0
	for _, fr := range frames {
		wf, err := session.makeWriterFrame(fr.cmd, fr.sid, fr.data, fr.cmd == cmdPSH, time.Time{}, nil)
		if err != nil {
			for _, built := range group {
				session.releaseFrame(built)
			}
			return 0, err
		}
		group = append(group, wf)
		totalData += len(fr.data)
	}
	group[len(group)-1].confirm = make(chan error, 1)
	confirm := group[len(group)-1].confirm
	if err := session.wq.push(group, time.Time{}); err != nil {
		for _, built := range group {
			session.releaseFrame(built)
		}
		return 0, err
	}
	if werr := <-confirm; werr != nil {
		return 0, werr
	}
	return totalData, nil
}

func encodedFrameSize(frame frame) (int, error) {
	dataLen := len(frame.data)
	if dataLen > maxFramePayloadSize {
		return 0, fmt.Errorf("anytls frame payload too large: %d > %d", dataLen, maxFramePayloadSize)
	}
	return headerOverHeadSize + dataLen, nil
}

func encodeFrame(dst []byte, frame frame) int {
	dataLen := len(frame.data)
	dst[0] = frame.cmd
	binary.BigEndian.PutUint32(dst[1:], frame.sid)
	binary.BigEndian.PutUint16(dst[5:], uint16(dataLen))
	copy(dst[headerOverHeadSize:], frame.data)
	return headerOverHeadSize + dataLen
}

// writeGroupChunk bounds one atomic push so a group can always fit the data
// caps once the queue drains (a group larger than the caps could never be
// admitted and would deadlock its producer against an idle writer).
const writeGroupChunk = 128

// writeDataFramesBatch enqueues several datagram payloads as consecutive PSH
// frames for one stream and returns; the session writer flushes them as one
// gathered burst (one TLS record batch, one socket write). It exists for the
// netproxy.PacketBatchWriter path so N datagrams cost one burst instead of
// N. Sizes must be pre-validated. With a deadline armed the call waits for
// the flush through a completion on the final frame.
func writeDataFramesBatch(session *session, sid uint32, datas [][]byte, deadline time.Time) (int, error) {
	chunks := make([][]byte, 0, len(datas))
	totalData := 0
	for _, data := range datas {
		for written := 0; written < len(data); {
			end := written + maxFramePayloadSize
			if end > len(data) {
				end = len(data)
			}
			chunks = append(chunks, data[written:end])
			totalData += end - written
			written = end
		}
	}
	if len(chunks) == 0 {
		return 0, nil
	}
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		return 0, os.ErrDeadlineExceeded
	}
	var confirm chan error
	if !deadline.IsZero() {
		confirm = make(chan error, 1)
	}
	for start := 0; start < len(chunks); start += writeGroupChunk {
		end := min(start+writeGroupChunk, len(chunks))
		group := make([]writerFrame, 0, end-start)
		for i := start; i < end; i++ {
			var fc chan error
			if i == len(chunks)-1 {
				fc = confirm
			}
			wf, err := session.makeWriterFrame(cmdPSH, sid, chunks[i], true, deadline, fc)
			if err != nil {
				for _, built := range group {
					session.releaseFrame(built)
				}
				return 0, err
			}
			group = append(group, wf)
		}
		if err := session.wq.push(group, deadline); err != nil {
			for _, built := range group {
				session.releaseFrame(built)
			}
			return 0, err
		}
	}
	if confirm != nil {
		if werr := <-confirm; werr != nil {
			return 0, werr
		}
	}
	return totalData, nil
}

// writeDataFrames splits data into maxFramePayloadSize frames and enqueues
// them on the session writer queue. Without an armed write deadline the call
// returns once every frame is queued: the bounded queue preserves TCP-style
// backpressure while the caller (the relay read loop) proceeds in parallel
// with the TLS write path. With a deadline armed the call instead waits for
// the flush through a completion on the final frame, preserving the
// synchronous deadline contract (Write returns os.ErrDeadlineExceeded when
// the deadline aborts its own batch).
func writeDataFrames(session *session, sid uint32, data []byte, deadline time.Time) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		return 0, os.ErrDeadlineExceeded
	}
	var confirm chan error
	if !deadline.IsZero() {
		confirm = make(chan error, 1)
	}
	for off := 0; off < len(data); {
		end := off + maxFramePayloadSize
		if end > len(data) {
			end = len(data)
		}
		var fc chan error
		if end >= len(data) {
			fc = confirm
		}
		wf, err := session.makeWriterFrame(cmdPSH, sid, data[off:end], true, deadline, fc)
		if err != nil {
			return 0, err
		}
		if err := session.wq.push([]writerFrame{wf}, deadline); err != nil {
			session.releaseFrame(wf)
			return 0, err
		}
		off = end
	}
	if confirm != nil {
		if werr := <-confirm; werr != nil {
			return 0, werr
		}
	}
	return len(data), nil
}
