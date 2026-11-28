package tuic

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/infra/clientring"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/olicesx/quic-go"
)

// registerUDPAssociationAt registers packets under a chosen ID the way
// production does, for tests that build wire packets for a known ID.
func registerUDPAssociationAt(c *clientImpl, connId uint16, packets *Packets) {
	c.udpIncomingPacketsMap.Store(connId, packets)
	c.udpAssociations.Add(1)
}

// assertTableMatchesCount checks the invariant the placement gate relies on:
// the association count is the size of the association table.
func assertTableMatchesCount(t *testing.T, c *clientImpl) {
	t.Helper()
	size := 0
	c.udpIncomingPacketsMap.Range(func(_, _ any) bool {
		size++
		return true
	})
	if got := c.udpAssociationCount(); got != int64(size) {
		t.Fatalf("udpAssociationCount() = %d, but the table holds %d associations", got, size)
	}
}

// TestAllocateConnIdVisitsEachIDOnceThenRefuses fills tables of several
// sizes. The allocation sweep must hand out every ID exactly once before it
// refuses, and an ID that was released must be the one handed out next. The
// random-retry loop this replaced never returned from a full table.
func TestAllocateConnIdVisitsEachIDOnceThenRefuses(t *testing.T) {
	for _, spaceSize := range []int{1, 2, 64, 1000} {
		var table sync.Map
		seen := make(map[uint16]bool, spaceSize)
		var first uint16
		for len(seen) < spaceSize {
			id, ok := allocateConnId(&table, NewPackets(), spaceSize)
			if !ok {
				t.Fatalf("space %d: allocateConnId() refused with %d IDs free", spaceSize, spaceSize-len(seen))
			}
			if seen[id] {
				t.Fatalf("space %d: allocateConnId() handed out ID %d twice with %d IDs still free", spaceSize, id, spaceSize-len(seen))
			}
			if len(seen) == 0 {
				first = id
			}
			seen[id] = true
		}
		if id, ok := allocateConnId(&table, NewPackets(), spaceSize); ok {
			t.Fatalf("space %d: allocateConnId() = ID %d on a full table, want a refusal", spaceSize, id)
		}

		table.Delete(first)
		id, ok := allocateConnId(&table, NewPackets(), spaceSize)
		if !ok || id != first {
			t.Fatalf("space %d: allocateConnId() = ID %d, %v with only ID %d free, want that ID", spaceSize, id, ok, first)
		}
	}
}

// TestAllocateConnIdRefusesFullProductionSpace takes the production ID space
// completely and expects a refusal after a single pass: before the sweep was
// bounded, a full connection spun here forever while holding connMutex.
func TestAllocateConnIdRefusesFullProductionSpace(t *testing.T) {
	client := &clientImpl{}
	for i := 0; i < udpAssociationIDSpace; i++ {
		registerUDPAssociationAt(client, uint16(i), NewPackets())
	}
	assertTableMatchesCount(t, client)
	res := make(chan bool, 1)
	go func() {
		_, ok := client.addUDPAssociation(NewPackets())
		res <- ok
	}()
	select {
	case ok := <-res:
		if ok {
			t.Fatal("addUDPAssociation() succeeded on a full table")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("addUDPAssociation() did not return on a full table")
	}
	assertTableMatchesCount(t, client)
}

// TestTakeUDPAssociationRemovesEachEntryOnce walks the three paths that take
// an association off a connection: the consumer's Close, an inbound packet
// error, and forceClose. Each entry must cost exactly one decrement, and a
// path that arrives late must find nothing to take.
func TestTakeUDPAssociationRemovesEachEntryOnce(t *testing.T) {
	client := &clientImpl{}
	count := func(want int64) {
		t.Helper()
		if got := client.udpAssociationCount(); got != want {
			t.Fatalf("udpAssociationCount() = %d, want %d", got, want)
		}
		assertTableMatchesCount(t, client)
	}

	// Consumer Close: only the queue that owns the ID takes it, once.
	owner := NewPackets()
	id, ok := client.addUDPAssociation(owner)
	if !ok {
		t.Fatal("addUDPAssociation() refused an empty table")
	}
	if q := client.takeUDPAssociation(id, NewPackets()); q != nil {
		t.Fatalf("a queue that does not own ID %d took it", id)
	}
	count(1)
	if q := client.takeUDPAssociation(id, owner); q != owner {
		t.Fatalf("takeUDPAssociation(%d, owner) = %p, want the owning queue %p", id, q, owner)
	}
	count(0)
	if q := client.takeUDPAssociation(id, owner); q != nil {
		t.Fatalf("a second Close of association %d took a queue; once the ID is reused that loses the new association", id)
	}
	count(0)

	// Inbound packet error: the queue is taken by ID alone.
	owner = NewPackets()
	if id, ok = client.addUDPAssociation(owner); !ok {
		t.Fatal("addUDPAssociation() refused a table with room")
	}
	if q := client.takeUDPAssociationByID(id); q != owner {
		t.Fatalf("takeUDPAssociationByID(%d) = %p, want the registered queue %p", id, q, owner)
	}
	count(0)
	if q := client.takeUDPAssociationByID(id); q != nil {
		t.Fatalf("a second take of association %d by a packet error returned a queue", id)
	}
	count(0)

	// forceClose: every entry leaves the table, and the closes it preempts
	// must not drive the count below zero.
	owners := make([]*Packets, 3)
	ids := make([]uint16, len(owners))
	for i := range owners {
		owners[i] = NewPackets()
		if ids[i], ok = client.addUDPAssociation(owners[i]); !ok {
			t.Fatal("addUDPAssociation() refused a table with room")
		}
	}
	count(int64(len(owners)))
	client.forceClose(nil, common.ErrClientClosed)
	count(0)
	for i := range owners {
		if q := client.takeUDPAssociation(ids[i], owners[i]); q != nil {
			t.Fatalf("Close of association %d after forceClose took a queue", ids[i])
		}
		if q := client.takeUDPAssociationByID(ids[i]); q != nil {
			t.Fatalf("a packet error for association %d after forceClose took a queue", ids[i])
		}
		if _, loaded := client.udpIncomingPacketsMap.Load(ids[i]); loaded {
			t.Fatalf("ID %d is still registered after forceClose", ids[i])
		}
	}
	count(0)
}

// TestUDPAssociationCountTracksTableUnderContention runs the insert and all
// three removal paths against each other from several goroutines, with a
// forceClose landing halfway. Whatever the interleaving, each association is
// taken exactly once and, once quiet, the count equals the table.
func TestUDPAssociationCountTracksTableUnderContention(t *testing.T) {
	client := &clientImpl{}
	const workers, perWorker = 8, 2000
	var wg sync.WaitGroup
	var progress atomic.Int64
	start := make(chan struct{})
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := range perWorker {
				q := NewPackets()
				id, ok := client.addUDPAssociation(q)
				if !ok {
					t.Errorf("worker %d: addUDPAssociation() refused with room in the table", w)
					return
				}
				var taken int
				switch (w + i) % 3 {
				case 0: // the consumer's Close
					if client.takeUDPAssociation(id, q) != nil {
						taken++
					}
				case 1: // an inbound packet error
					if client.takeUDPAssociationByID(id) != nil {
						taken++
					}
				default: // both arrive, in either order
					if client.takeUDPAssociationByID(id) != nil {
						taken++
					}
					if client.takeUDPAssociation(id, q) != nil {
						taken++
					}
				}
				// Zero is legitimate here only when forceClose won the race.
				if taken != 1 && !client.closed.Load() {
					t.Errorf("worker %d: association %d was taken %d times while the client was open", w, id, taken)
					return
				}
				if got := client.udpAssociationCount(); got < 0 {
					t.Errorf("worker %d: udpAssociationCount() = %d, want a non-negative count", w, got)
					return
				}
				progress.Add(1)
			}
		}(w)
	}

	close(start)
	for progress.Load() < workers*perWorker/2 {
		time.Sleep(time.Millisecond)
	}
	client.forceClose(nil, common.ErrClientClosed)
	wg.Wait()

	assertTableMatchesCount(t, client)
	if got := client.udpAssociationCount(); got != 0 {
		t.Fatalf("udpAssociationCount() = %d after every association was added and taken, want 0", got)
	}
}

// dialRecorder is a dial function that fails without touching the network
// and counts the connections the ring offered it to.
type dialRecorder struct {
	err   error
	calls atomic.Int32
}

func (r *dialRecorder) dial(context.Context, netproxy.Dialer) (*quic.Transport, net.Addr, error) {
	r.calls.Add(1)
	return nil, nil, r.err
}

// fakeClientRing builds a ring whose clients never connect. The first
// client starts with associations UDP associations, and capability is the
// bidirectional-stream headroom every client reports (-1: no report).
func fakeClientRing(associations, capability, associationCap int64) *clientRing {
	return newClientRing(func(capabilityCallback func(n int64)) *clientImpl {
		c := newClientImpl(&ClientOption{}, true, 0)
		c.udpAssociations.Store(associations)
		associations = 0
		if capability >= 0 {
			capabilityCallback(capability)
		}
		return c
	}, 10, associationCap)
}

// TestClientRingPlacesUDPByAssociationCount drives the ring's UDP gate with
// clients that never connect, so the test sees which connection the ring
// tries without a handshake.
func TestClientRingPlacesUDPByAssociationCount(t *testing.T) {
	tests := []struct {
		name         string
		associations int64 // already carried by the current connection
		capability   int64 // bidirectional streams the peer leaves free
		wantDials    int32 // connections the ring tried
		wantRing     int
	}{
		{name: "room on the current connection", associations: 3, capability: 100, wantDials: 1, wantRing: 1},
		{name: "current connection full", associations: 4, capability: 100, wantDials: 1, wantRing: 2},
		{name: "no stream headroom left", associations: 0, capability: 0, wantDials: 1, wantRing: 1},
		{name: "stream headroom unknown", associations: 0, capability: -1, wantDials: 1, wantRing: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := fakeClientRing(tt.associations, tt.capability, 4)
			t.Cleanup(func() { _ = r.Close() })
			dial := &dialRecorder{err: errors.New("reached the dial")}

			// The first attempt creates the current connection; the ring
			// returns a failure on a freshly created one without walking.
			_, _ = r.ListenPacketWithDialer(context.Background(), &protocol.Metadata{}, nil, dial.dial)
			dial.calls.Store(0)

			_, err := r.ListenPacketWithDialer(context.Background(), &protocol.Metadata{}, nil, dial.dial)
			if !errors.Is(err, dial.err) {
				t.Fatalf("ListenPacketWithDialer() error = %v, want the dial error %v", err, dial.err)
			}
			if got := dial.calls.Load(); got != tt.wantDials {
				t.Fatalf("dial was offered to %d connections, want %d", got, tt.wantDials)
			}
			if got := r.ring.Len(); got != tt.wantRing {
				t.Fatalf("ring holds %d connections, want %d", got, tt.wantRing)
			}
		})
	}
}

// TestClientRingUDPFullConnectionStillDialsTCP: a connection that is full
// for UDP keeps taking TCP, which has its own gate.
func TestClientRingUDPFullConnectionStillDialsTCP(t *testing.T) {
	r := fakeClientRing(1, 100, 1)
	t.Cleanup(func() { _ = r.Close() })
	dial := &dialRecorder{err: errors.New("reached the dial")}

	if _, err := r.DialContextWithDialer(context.Background(), &protocol.Metadata{}, nil, dial.dial); !errors.Is(err, dial.err) {
		t.Fatalf("DialContextWithDialer() error = %v, want the dial error %v", err, dial.err)
	}
	if got := dial.calls.Load(); got != 1 {
		t.Fatalf("dial was offered to %d connections, want 1", got)
	}
	if got := r.ring.Len(); got != 1 {
		t.Fatalf("ring holds %d connections, want 1", got)
	}
}

func TestUDPAssociationsExhaustedIsAFailoverError(t *testing.T) {
	if !clientring.IsFailoverError(common.ErrUDPAssociationsExhausted) {
		t.Fatal("IsFailoverError(ErrUDPAssociationsExhausted) = false: the ring would return the error instead of moving to a connection with free IDs")
	}
}
