package tuic

// Test-only accessors for the black-box e2e tests in package tuic_test,
// which drive real dialers built from tuic:// links.

// RingLenForTest reports how many QUIC clients the dialer's ring holds.
func (d *Dialer) RingLenForTest() int {
	return d.clientRing.ring.Len()
}

// RingCapabilityForTest reports the bidirectional-stream headroom the
// ring's current connection last reported, -1 while none has arrived.
func (d *Dialer) RingCapabilityForTest() int64 {
	return d.clientRing.ring.CurrentCapability()
}

// SetUDPAssociationsCapForTest sets how many UDP associations a connection
// carries before the ring moves to another one.
func (d *Dialer) SetUDPAssociationsCapForTest(n int64) {
	d.clientRing.associationCap.Store(n)
}
