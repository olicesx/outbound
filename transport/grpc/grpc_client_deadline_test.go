package grpc

import (
	"os"
	"testing"
	"time"

	proto "github.com/daeuniverse/outbound/pkg/gun_proto"
	"google.golang.org/grpc"
)

// stubTun implements just enough of GunService_TunClient for the deadline
// semantics test; Recv blocks on a channel the test controls.
type stubTun struct {
	grpc.ClientStream
	recvCh chan *proto.Hunk
}

func (s *stubTun) Recv() (*proto.Hunk, error) { return <-s.recvCh, nil }
func (s *stubTun) Send(*proto.Hunk) error     { return nil }
func (s *stubTun) CloseSend() error           { return nil }

// TestReadDeadlineIsNotTerminal pins the net.Conn deadline contract: an
// expired read deadline must surface os.ErrDeadlineExceeded WITHOUT killing
// the stream, and a later Read (after the deadline is extended) must still
// deliver the hunk the pump received meanwhile.
func TestReadDeadlineIsNotTerminal(t *testing.T) {
	tun := &stubTun{recvCh: make(chan *proto.Hunk)}
	c := NewClientConn(tun, func() {})
	defer func() { _ = c.Close() }()

	if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	if _, err := c.Read(make([]byte, 128)); !os.IsTimeout(err) {
		t.Fatalf("Read() error = %v, want os.ErrDeadlineExceeded", err)
	}

	// The conn must remain usable: deliver a hunk and read it after the
	// deadline was cleared.
	tun.recvCh <- &proto.Hunk{Data: []byte("still alive")}
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read() after deadline expiry error = %v, want success", err)
	}
	if string(buf[:n]) != "still alive" {
		t.Fatalf("Read() = %q, want %q", buf[:n], "still alive")
	}
}
