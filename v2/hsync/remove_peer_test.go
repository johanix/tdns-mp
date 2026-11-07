/*
 * Phase 3c: RemovePeer fires OnPeerRemoved so prunes are events —
 * the application drops its view promptly instead of waiting for a scan.
 */
package hsync

import (
	"testing"
	"time"
)

func TestRemovePeerFiresHook(t *testing.T) {
	var removed []PeerID
	e := NewEngine(Deps{
		LocalID:   "self.agent.example.",
		Transport: &mockTransport{},
		PeerHooks: PeerHooks{
			OnPeerRemoved: func(p *Peer) { removed = append(removed, p.ID) },
		},
	}, DefaultConfig())

	peer := NewPeer("gone.agent.example.")
	e.registry.S.Set(peer.ID, peer)

	e.RemovePeer(peer.ID)

	if _, exists := e.registry.S.Get(peer.ID); exists {
		t.Fatal("peer must be removed from the registry")
	}
	if len(removed) != 1 || removed[0] != peer.ID {
		t.Fatalf("OnPeerRemoved fired %v, want exactly [%s]", removed, peer.ID)
	}

	// Removing an unknown peer is a no-op and must not fire the hook.
	e.RemovePeer("never-existed.example.")
	if len(removed) != 1 {
		t.Fatal("RemovePeer on unknown id must not fire the hook")
	}
}

const hold = time.Hour

// pruneEngine is an engine with the zone customer.test., where this agent and
// fox hold a role, and the peers it is given, each with no zone.
func pruneEngine(t *testing.T, removed *[]*Peer, unshared *[]bool, ids ...PeerID) (*Engine, mapZoneLookup) {
	t.Helper()
	zl := mapZoneLookup{"customer.test.": standingZone(t, "customer.test.", []string{"self", "fox"}, nil)}
	cfg := DefaultConfig()
	cfg.PeerHold = hold
	e := NewEngine(Deps{
		LocalID:   "self.agent.example.",
		Transport: &mockTransport{},
		Zones:     zl,
		PeerHooks: PeerHooks{
			OnPeerRemoved: func(p *Peer) {
				if removed != nil {
					*removed = append(*removed, p)
				}
			},
			OnPeerUnshared: func(p *Peer, u bool) {
				if unshared != nil {
					*unshared = append(*unshared, u)
				}
			},
		},
	}, cfg)
	for _, id := range ids {
		e.registry.S.Set(id, NewPeer(id))
	}
	return e, zl
}

// A zone the agent no longer holds is taken off its peers; the zones it holds
// stay, one that is not multi-provider included (ApplyHsyncDiff registers
// peers for it), and so does one that arrives while the pass runs.
func TestAZoneTheAgentNoLongerHoldsIsTakenOffItsPeers(t *testing.T) {
	e, zl := pruneEngine(t, nil, nil)
	zl["single.test."] = &mockZone{zone: "single.test."}
	e.reconcileAllZones()
	fox, _ := e.registry.S.Get("fox.agent.example.")
	fox.Mu.Lock()
	fox.Zones["gone.test."] = true
	fox.Zones["single.test."] = true
	fox.Zones["late.test."] = true
	fox.Mu.Unlock()

	held := map[ZoneName]bool{"customer.test.": true, "single.test.": true}
	zl["late.test."] = &mockZone{zone: "late.test."} // arrives after the pass read the zones
	e.dropZonesNotHeld(held)
	got := peerZones(t, e, "fox.agent.example.")
	if len(got) != 3 || !got["customer.test."] || !got["single.test."] || !got["late.test."] {
		t.Fatalf("fox's zones after the pass: %v, want customer.test., single.test. and late.test.", got)
	}

	delete(zl, "late.test.")
	e.reconcileAllZones()
	if got := peerZones(t, e, "fox.agent.example."); got["late.test."] || got["gone.test."] {
		t.Fatalf("fox's zones after the zones left: %v", got)
	}
}

// A peer that no zone names is kept for the hold time, and beaten meanwhile.
func TestAPeerWithNoZoneIsKeptForTheHoldTime(t *testing.T) {
	var unshared []bool
	s := newScriptedBeats()
	e, _ := pruneEngine(t, nil, &unshared)
	e.deps.Transport = s
	peer := operationalDNSPeer(e, s)

	t0 := time.Now()
	e.pruneUnsharedPeers(t0)
	e.pruneUnsharedPeers(t0.Add(hold - time.Second))
	if _, ok := e.registry.S.Get(peer.ID); !ok {
		t.Fatal("the peer was removed within the hold time")
	}
	if len(unshared) != 1 || !unshared[0] {
		t.Fatalf("OnPeerUnshared fired %v, want once, unshared", unshared)
	}
	e.sendHeartbeats()
	s.waitBeats(t, 1, time.Second)
}

// After the hold time the peer is removed, and no beat, hello or discovery
// goes to it.
func TestAPeerWithNoZoneIsRemovedAfterTheHoldTime(t *testing.T) {
	var removed []*Peer
	tb := &discoveryCounter{d25Transport: newD25Transport(), asked: map[string]int{}}
	e, _ := pruneEngine(t, &removed, nil)
	e.deps.Transport = tb
	peer := knownDNSPeer(e, tb.d25Transport)

	t0 := time.Now()
	e.pruneUnsharedPeers(t0)
	e.pruneUnsharedPeers(t0.Add(hold))
	if _, ok := e.registry.S.Get(peer.ID); ok {
		t.Fatal("the peer is still there after the hold time")
	}
	if len(removed) != 1 || removed[0] != peer {
		t.Fatalf("OnPeerRemoved fired for %v, want the peer once", removed)
	}
	e.retryPendingDiscoveries()
	e.startHelloRetrier(peer)
	beats := newScriptedBeats()
	e.deps.Transport = beats
	e.sendHeartbeats()
	e.BeatPeer(peer.ID)
	time.Sleep(20 * time.Millisecond)
	if n := len(beats.beats()); n != 0 {
		t.Errorf("%d beat(s) to the removed peer, want none", n)
	}
	if n := tb.count(string(peer.ID)); n != 0 {
		t.Errorf("%d discoveries of the removed peer, want none", n)
	}
	if e.registry.hasHelloCancel(peer.ID) {
		t.Error("a hello retrier is registered for the removed peer")
	}
}

// A peer named again within the hold time is kept, and a second loss of its
// zones starts the hold time anew.
func TestAPeerNamedAgainWithinTheHoldTimeIsKept(t *testing.T) {
	var unshared []bool
	e, _ := pruneEngine(t, nil, &unshared, "hare.agent.example.")
	const id = PeerID("hare.agent.example.")
	t0 := time.Now()
	e.pruneUnsharedPeers(t0)
	e.registry.AddZoneToPeer(id, "customer.test.")
	e.pruneUnsharedPeers(t0.Add(hold / 2))
	peer, _ := e.registry.S.Get(id)
	if !peer.Unshared.IsZero() {
		t.Fatal("the hold time was not cleared when a zone named the peer again")
	}
	e.registry.RemovePeerFromZone("customer.test.", id)
	e.pruneUnsharedPeers(t0.Add(hold))
	e.pruneUnsharedPeers(t0.Add(hold + hold/2))
	if _, ok := e.registry.S.Get(id); !ok {
		t.Fatal("the peer was removed before a full hold time since it lost its zones again")
	}
	e.pruneUnsharedPeers(t0.Add(2 * hold))
	if _, ok := e.registry.S.Get(id); ok {
		t.Fatal("the peer is still there a full hold time after it lost its zones again")
	}
	if want := []bool{true, false, true}; len(unshared) != 3 || unshared[0] != want[0] || unshared[1] != want[1] || unshared[2] != want[2] {
		t.Fatalf("OnPeerUnshared fired %v, want %v", unshared, want)
	}
}

// A zone added after the prune read the peer, before its removal, keeps the
// peer: the removal tests the zones again under the shard's lock.
func TestAZoneAddedWhileThePruneRunsKeepsThePeer(t *testing.T) {
	e, _ := pruneEngine(t, nil, nil, "hare.agent.example.")
	const id = PeerID("hare.agent.example.")
	t0 := time.Now()
	e.pruneUnsharedPeers(t0)
	e.beforePruneRemoval = func(PeerID) { e.registry.AddZoneToPeer(id, "customer.test.") }
	e.pruneUnsharedPeers(t0.Add(hold))
	if _, ok := e.registry.S.Get(id); !ok {
		t.Fatal("a peer given a zone while the prune ran was removed")
	}
}

// A refresh on its way when the peer is removed does not store the removed
// object again. One that names the identity makes a new peer, which is looked
// up afresh.
func TestARefreshOnItsWayDoesNotPutARemovedPeerBack(t *testing.T) {
	tb := &discoveryCounter{d25Transport: newD25Transport(), asked: map[string]int{}}
	e, _ := pruneEngine(t, nil, nil, "fox.agent.example.")
	e.deps.Transport = tb
	const id = PeerID("fox.agent.example.")
	old, _ := e.registry.S.Get(id)
	t0 := time.Now()
	e.pruneUnsharedPeers(t0)
	e.pruneUnsharedPeers(t0.Add(hold))

	if e.registry.AddZoneToPeer(id, "customer.test.") {
		t.Fatal("a zone was added to the removed peer")
	}
	e.registry.RemovePeerFromZone("customer.test.", id)
	if _, ok := e.registry.S.Get(id); ok {
		t.Fatal("a zone change stored the removed peer again")
	}
	e.ReconcileZone("customer.test.")
	peer, ok := e.registry.S.Get(id)
	if !ok || peer == old {
		t.Fatal("a zone that names the identity again must make a new peer")
	}
}

// A peer named again after its removal is a new peer, and is looked up afresh.
func TestAPeerNamedAgainAfterItsRemovalIsDiscoveredAfresh(t *testing.T) {
	tb := &discoveryCounter{d25Transport: newD25Transport(), asked: map[string]int{}}
	e, zl := pruneEngine(t, nil, nil)
	e.deps.Transport = tb
	const id = PeerID("fox.agent.example.")
	e.reconcileAllZones()
	waitDiscoveries(t, tb, id, 1)

	zl["customer.test."].rrs = zl["customer.test."].rrs[:1] // fox's record leaves
	t0 := time.Now()
	e.ReconcileZone("customer.test.")
	e.pruneUnsharedPeers(t0)
	e.pruneUnsharedPeers(t0.Add(hold))
	if _, ok := e.registry.S.Get(id); ok {
		t.Fatal("fox was not removed")
	}

	zl["customer.test."].rrs = append(zl["customer.test."].rrs, mustHSYNC3RR(t, "fox", string(id)))
	e.ReconcileZone("customer.test.")
	if _, ok := e.registry.S.Get(id); !ok {
		t.Fatal("fox named again is not a peer again")
	}
	waitDiscoveries(t, tb, id, 2)
}

func waitDiscoveries(t *testing.T, tb *discoveryCounter, id PeerID, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for tb.count(string(id)) < want && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := tb.count(string(id)); got != want {
		t.Fatalf("%d discoveries of %s, want %d", got, id, want)
	}
}

// An infrastructure peer is never removed.
func TestAnInfrastructurePeerIsNeverRemoved(t *testing.T) {
	var removed []*Peer
	e, _ := pruneEngine(t, &removed, nil)
	infra := NewPeer("combiner.example.")
	infra.IsInfraPeer = true
	e.registry.S.Set(infra.ID, infra)
	t0 := time.Now()
	e.pruneUnsharedPeers(t0)
	e.pruneUnsharedPeers(t0.Add(2 * hold))
	if _, ok := e.registry.S.Get(infra.ID); !ok || len(removed) != 0 {
		t.Fatal("an infrastructure peer was removed")
	}
}

// A zone added to a peer while the peer is removed never stores the removed
// object again. The add holds the peer's lock while the removal runs: the old
// add had read the peer and stored it again after its change, over the
// removal. Now the add runs under the shard's lock, which the removal waits
// for.
func TestAZoneAddedWhileThePeerIsRemovedDoesNotPutItBack(t *testing.T) {
	e := NewEngine(Deps{LocalID: "local.example.", Transport: &mockTransport{}}, DefaultConfig())
	const id = PeerID("racing.example.")
	old := NewPeer(id)
	e.registry.S.Set(id, old)

	old.Mu.Lock()
	added := make(chan struct{})
	go func() {
		defer close(added)
		e.registry.AddZoneToPeer(id, "z.example.")
	}()
	time.Sleep(20 * time.Millisecond) // the add waits for the peer's lock
	removed := make(chan struct{})
	go func() {
		defer close(removed)
		e.RemovePeer(id)
	}()
	time.Sleep(20 * time.Millisecond)
	old.Mu.Unlock()
	<-added
	<-removed
	if stored, ok := e.registry.S.Get(id); ok && stored == old {
		t.Fatal("a zone added during the removal stored the removed peer again")
	}
}
