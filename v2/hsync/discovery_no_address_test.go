/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package hsync

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
)

// discoveryCounter is the d25 transport with a note of the peers it was asked
// to discover.
type discoveryCounter struct {
	*d25Transport
	mu    sync.Mutex
	asked map[string]int
}

func (c *discoveryCounter) DiscoverPeer(ctx context.Context, identity string) (*transport.Peer, error) {
	c.mu.Lock()
	c.asked[identity]++
	c.mu.Unlock()
	return c.reg.GetOrCreate(identity), nil
}

func (c *discoveryCounter) count(identity string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.asked[identity]
}

// The discovery retry goes by the address as well as the state: a mechanism
// that is past NEEDED and has no address is discovered again, since nothing
// can be sent to it and nothing else looks the peer up (tdns-mp #84). One
// that has its address is left alone.
func TestTheDiscoveryRetryTakesAMechanismWithNoAddress(t *testing.T) {
	c := &discoveryCounter{d25Transport: newD25Transport(), asked: map[string]int{}}
	e := NewEngine(Deps{LocalID: "local.example.", Transport: c}, DefaultConfig())

	for _, id := range []string{"no-address.example.", "resolved.example."} {
		peer := NewPeer(PeerID(id))
		peer.DnsMethod = true
		e.registry.S.Set(peer.ID, peer)
		c.seed(id, TransportDNS, transport.PeerStateIntroducing)
	}
	c.reg.GetOrCreate("resolved.example.").SetMechanismAddress(TransportDNS,
		&transport.Address{Host: "192.0.2.1", Port: 53, Transport: "udp"})

	e.retryPendingDiscoveries()

	deadline := time.Now().Add(2 * time.Second)
	for c.count("no-address.example.") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := c.count("no-address.example."); got != 1 {
		t.Errorf("%d discoveries of a peer whose introduced mechanism has no address, want 1", got)
	}
	time.Sleep(50 * time.Millisecond)
	if got := c.count("resolved.example."); got != 0 {
		t.Errorf("%d discoveries of a peer whose introduced mechanism has its address, want none", got)
	}
}

// A peer the engine has removed is not discovered by a pass that saw it
// before the removal: its removal dropped its transport peer, and a
// discovery would make that peer again, so the comms that ended would not
// stay ended (W1). A peer the engine holds is discovered as before.
func TestARemovedPeerIsNotDiscoveredByAPassThatSawItBefore(t *testing.T) {
	c := &discoveryCounter{d25Transport: newD25Transport(), asked: map[string]int{}}
	e := NewEngine(Deps{LocalID: "local.example.", Transport: c}, DefaultConfig())

	gone := NewPeer("gone.example.")
	gone.DnsMethod = true
	e.registry.S.Set(gone.ID, gone)
	held := NewPeer("held.example.")
	held.DnsMethod = true
	e.registry.S.Set(held.ID, held)

	e.RemovePeer(gone.ID) // the pass took its list before this
	e.attemptDiscovery(gone, false, true)
	e.attemptDiscovery(held, false, true)

	if got := c.count("gone.example."); got != 0 {
		t.Errorf("%d discoveries of a peer removed since the pass began, want none", got)
	}
	if _, ok := c.reg.Get("gone.example."); ok {
		t.Error("the removed peer's transport peer was made again")
	}
	if got := c.count("held.example."); got != 1 {
		t.Errorf("%d discoveries of a peer the engine holds, want 1", got)
	}

	// a new peer under the removed one's identity is discovered: the old
	// object is not, the new one is
	again := NewPeer("gone.example.")
	again.DnsMethod = true
	e.registry.S.Set(again.ID, again)
	e.attemptDiscovery(gone, false, true)
	if got := c.count("gone.example."); got != 0 {
		t.Errorf("the removed object was discovered once a new peer took its identity: %d", got)
	}
	e.attemptDiscovery(again, false, true)
	if got := c.count("gone.example."); got != 1 {
		t.Errorf("%d discoveries of the new peer under the identity, want 1", got)
	}
}
