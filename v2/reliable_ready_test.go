/*
 * Regression tests for recipientTransportReady — the ReliableMessageQueue's
 * IsRecipientReady predicate.
 *
 * The predicate must read the canonical transport.Peer mechanism state, NOT
 * the retired agent.{Api,Dns}Details.State sidecar: its writers were deleted
 * at END.0/D2.5, so gating on the dead store deferred every queued zone
 * update to an agent recipient until the queue's 24h expiry.
 */
package tdnsmp

import (
	"testing"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
)

const readyTestID = "agent.ready-test.example."

// newReadyTestRegistry builds an AgentRegistry holding one agent in the shape
// discovery creates it (Phase 2: no AgentDetails — readiness must come from
// transport.Peer alone, which is exactly what these tests assert).
func newReadyTestRegistry() *AgentRegistry {
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent]()}
	ar.S.Set(AgentId(readyTestID), NewAgent(AgentId(readyTestID)))
	return ar
}

func TestRecipientTransportReady(t *testing.T) {
	t.Run("nil registry keeps always-ready (combiner/signer roles)", func(t *testing.T) {
		if !recipientTransportReady(nil, transport.NewPeerRegistry(), readyTestID) {
			t.Fatal("nil AgentRegistry must report ready (pre-existing role behavior)")
		}
	})

	t.Run("unknown agent not ready", func(t *testing.T) {
		ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent]()}
		if recipientTransportReady(ar, transport.NewPeerRegistry(), readyTestID) {
			t.Fatal("recipient absent from AgentRegistry must not be ready")
		}
	})

	t.Run("known agent without transport.Peer not ready", func(t *testing.T) {
		if recipientTransportReady(newReadyTestRegistry(), transport.NewPeerRegistry(), readyTestID) {
			t.Fatal("recipient without a transport.Peer must not be ready")
		}
	})

	t.Run("pre-handshake mechanism states not ready", func(t *testing.T) {
		for _, st := range []transport.PeerState{
			transport.PeerStateNeeded,
			transport.PeerStateKnown,
			transport.PeerStateError,
		} {
			peers := transport.NewPeerRegistry()
			peers.GetOrCreate(readyTestID).SetMechanismState("DNS", st, "test")
			if recipientTransportReady(newReadyTestRegistry(), peers, readyTestID) {
				t.Fatalf("DNS mechanism state %v must not be ready", st)
			}
		}
	})

	// The regression: a handshaked transport.Peer must make the recipient
	// ready even though the agent's AgentDetails.State is stuck at zero —
	// the old AgentDetails-gated predicate returned false here forever.
	t.Run("handshaked mechanism ready despite dead AgentDetails", func(t *testing.T) {
		for _, st := range []transport.PeerState{
			transport.PeerStateIntroducing,
			transport.PeerStateOperational,
			transport.PeerStateDegraded,
			transport.PeerStateInterrupted,
		} {
			peers := transport.NewPeerRegistry()
			peers.GetOrCreate(readyTestID).SetMechanismState("DNS", st, "test")
			if !recipientTransportReady(newReadyTestRegistry(), peers, readyTestID) {
				t.Fatalf("DNS mechanism state %v must be ready (AgentDetails.State is dead and must not gate)", st)
			}
		}
	})

	t.Run("API-only mechanism ready via the OR", func(t *testing.T) {
		peers := transport.NewPeerRegistry()
		peers.GetOrCreate(readyTestID).SetMechanismState("API", transport.PeerStateOperational, "test")
		if !recipientTransportReady(newReadyTestRegistry(), peers, readyTestID) {
			t.Fatal("API-operational recipient must be ready")
		}
	})
}
