/*
 * E1.b regression tests: one hsync.Peer allocation per peer, the *Agent in
 * ar.S is a VIEW sharing that pointer, and materialization never replaces an
 * existing view (the pre-E1.b bridge re-Set a fresh wrapper on every
 * store/hello/beat, silently wiping MP-only fields like meta/ErrorMsg).
 */
package tdnsmp

import (
	"sync"
	"testing"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns/v2/core"
)

func newE1bRegistry() *AgentRegistry {
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent]()}
	ar.Registry = hsync.NewRegistry("local.e1b.test.", nil)
	return ar
}

// enginePeer stores a new peer in the engine's registry, as the engine does
// before anything materializes its view.
func enginePeer(ar *AgentRegistry, id AgentId) *hsync.Peer {
	peer := hsync.NewPeer(id)
	ar.Registry.S.Set(peer.ID, peer)
	return peer
}

func TestMaterializeAgentView(t *testing.T) {
	const id = AgentId("agent.e1b.test.")

	t.Run("creates a view sharing the peer pointer", func(t *testing.T) {
		ar := newE1bRegistry()
		peer := enginePeer(ar, id)
		view := ar.materializeAgentView(peer)
		if view == nil || view.Peer != peer {
			t.Fatal("view must share the exact hsync.Peer pointer")
		}
		stored, ok := ar.S.Get(id)
		if !ok || stored != view {
			t.Fatal("view must be stored in ar.S")
		}
	})

	t.Run("idempotent: never replaces, MP-only fields survive", func(t *testing.T) {
		ar := newE1bRegistry()
		peer := enginePeer(ar, id)
		first := ar.materializeAgentView(peer)
		first.ErrorMsg = "marker"
		first.InitialZone = "zone.marker.test."

		second := ar.materializeAgentView(peer)
		if second != first {
			t.Fatal("re-materialization must return the SAME view, not a fresh wrapper")
		}
		if second.ErrorMsg != "marker" || second.InitialZone != "zone.marker.test." {
			t.Fatal("MP-only fields must survive re-materialization")
		}
	})

	t.Run("concurrent materialization converges on one view", func(t *testing.T) {
		ar := newE1bRegistry()
		peer := enginePeer(ar, id)
		views := make([]*Agent, 16)
		var wg sync.WaitGroup
		for i := range views {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				views[i] = ar.materializeAgentView(peer)
			}(i)
		}
		wg.Wait()
		for i, v := range views {
			if v != views[0] {
				t.Fatalf("goroutine %d got a different view (Upsert atomicity broken)", i)
			}
		}
	})

	// A beat, a hello or a discovery on its way when the engine removed the
	// peer does not bring its view back (#132).
	t.Run("no view for a peer the engine does not hold", func(t *testing.T) {
		ar := newE1bRegistry()
		peer := hsync.NewPeer(id)
		if view := ar.materializeAgentView(peer); view != nil {
			t.Fatal("a view was made for a peer the engine does not hold")
		}
		if _, ok := ar.S.Get(id); ok {
			t.Fatal("a view was stored for a peer the engine does not hold")
		}
	})

	t.Run("no view for a removed object, a fresh one for its successor", func(t *testing.T) {
		ar := newE1bRegistry()
		old := enginePeer(ar, id)
		oldView := ar.materializeAgentView(old)
		ar.Registry.S.Remove(old.ID)
		successor := enginePeer(ar, id)
		if view := ar.materializeAgentView(old); view != nil {
			t.Fatal("a view was made through the removed object")
		}
		view := ar.materializeAgentView(successor)
		if view == nil || view == oldView || view.Peer != successor {
			t.Fatal("the successor must get a view of its own, not the removed object's")
		}
	})
}

// removePeerView drops the view and the transport peer of a removed peer. A
// successor stored under the same identity after the removal keeps its own.
func TestRemovePeerViewKeepsASuccessorsView(t *testing.T) {
	const id = AgentId("agent.successor.e1b.test.")
	ar := newE1bRegistry()

	gone := enginePeer(ar, id)
	ar.materializeAgentView(gone)
	ar.Registry.S.Remove(gone.ID)
	ar.removePeerView(gone)
	if _, ok := ar.S.Get(id); ok {
		t.Fatal("the removed peer's view is still there")
	}

	old := enginePeer(ar, id)
	ar.materializeAgentView(old)
	ar.Registry.S.Remove(old.ID)
	successor := enginePeer(ar, id)
	view := ar.materializeAgentView(successor)
	ar.removePeerView(old)
	if stored, ok := ar.S.Get(id); !ok || stored != view {
		t.Fatal("the hook for the removed object dropped its successor's view")
	}
}

func TestAgentViewForIdentity(t *testing.T) {
	const id = AgentId("agent.oob.e1b.test.")

	t.Run("wraps the engine's existing peer", func(t *testing.T) {
		ar := newE1bRegistry()
		enginePeer := hsync.NewPeer(id)
		ar.Registry.S.Set(id, enginePeer)

		agent := ar.agentViewForIdentity(id, false, true)
		if agent == nil || agent.Peer != enginePeer {
			t.Fatal("view must wrap the ENGINE's peer, not a fresh allocation")
		}
	})

	t.Run("creates the peer IN the engine registry when absent", func(t *testing.T) {
		ar := newE1bRegistry()
		agent := ar.agentViewForIdentity(id, false, true)
		if agent == nil {
			t.Fatal("nil view")
		}
		enginePeer, ok := ar.Registry.S.Get(id)
		if !ok {
			t.Fatal("out-of-band discovery must create the peer in the engine registry (D2.5 Hello depends on it)")
		}
		if agent.Peer != enginePeer {
			t.Fatal("view and engine registry must share ONE allocation")
		}
		if enginePeer.ApiMethod || !enginePeer.DnsMethod {
			t.Fatal("capability seeding must mirror MarkNeeded (api=false, dns=true)")
		}
	})

	t.Run("existing view returned unchanged", func(t *testing.T) {
		ar := newE1bRegistry()
		first := ar.agentViewForIdentity(id, false, true)
		first.ErrorMsg = "keep-me"
		second := ar.agentViewForIdentity(id, false, true)
		if second != first || second.ErrorMsg != "keep-me" {
			t.Fatal("existing view must be returned, not rebuilt")
		}
	})

	t.Run("agent-only fallback without an engine registry", func(t *testing.T) {
		ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent]()} // no ar.Registry
		agent := ar.agentViewForIdentity(id, false, true)
		if agent == nil || agent.Peer == nil {
			t.Fatal("fallback must still produce a view over one allocation")
		}
		if stored, ok := ar.S.Get(id); !ok || stored != agent {
			t.Fatal("fallback view must be stored in ar.S")
		}
	})
}

func TestAgentViewForPeer(t *testing.T) {
	const id = AgentId("agent.bridge.e1b.test.")
	peer := hsync.NewPeer(id)

	t.Run("nil registry yields a transient unstored view", func(t *testing.T) {
		view := agentViewForPeer(nil, peer)
		if view == nil || view.Peer != peer {
			t.Fatal("transient view must share the peer pointer")
		}
	})

	t.Run("with registry delegates to materialization", func(t *testing.T) {
		ar := newE1bRegistry()
		ar.Registry.S.Set(peer.ID, peer)
		view := agentViewForPeer(ar, peer)
		stored, ok := ar.S.Get(id)
		if !ok || stored != view || view.Peer != peer {
			t.Fatal("view must be the stored, pointer-sharing one")
		}
	})
}
