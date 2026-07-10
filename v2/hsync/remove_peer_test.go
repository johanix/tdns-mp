/*
 * Phase 3c: RemovePeer fires OnPeerRemoved so prunes are events —
 * the application drops its view promptly instead of waiting for a scan.
 */
package hsync

import "testing"

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
