package tdnsmp

import (
	"testing"

	"github.com/johanix/tdns-transport/v2/transport"
)

// tdns-mp #57 item 1: an agent counts as having applied a DNSKEY
// distribution only on the final applied status; a relaying agent's
// immediate "pending" (and partial, failed, ignored) leave the propagation
// waiting. A rejection is final and surfaces once everyone answered.
func TestProcessDnskeyConfirmationCountsOnlyApplied(t *testing.T) {
	tm := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	tm.TrackDnskeyPropagation("z.example.", "d1", []uint16{4711}, []AgentId{"a1", "a2"})
	waiting := func(dist, step string) {
		t.Helper()
		if _, ok := tm.pendingDnskeyPropagations[dist]; !ok {
			t.Fatalf("%s: the propagation was resolved", step)
		}
	}
	if !tm.ProcessDnskeyConfirmation("d1", "a1", transport.ConfirmPending.String(), nil) {
		t.Fatal("not recognised as a DNSKEY propagation")
	}
	waiting("d1", "a1 pending")
	tm.ProcessDnskeyConfirmation("d1", "a2", transport.ConfirmPending.String(), nil)
	waiting("d1", "both pending (P9)")
	tm.ProcessDnskeyConfirmation("d1", "a1", transport.ConfirmPartial.String(), nil)
	waiting("d1", "a1 partial")
	tm.ProcessDnskeyConfirmation("d1", "a1", transport.ConfirmSuccess.String(), nil)
	waiting("d1", "a1 applied, a2 pending")
	if p := tm.pendingDnskeyPropagations["d1"]; !p.ExpectedAgents["a1"] || p.ExpectedAgents["a2"] {
		t.Errorf("confirmed: a1 %v a2 %v, want a1 only", p.ExpectedAgents["a1"], p.ExpectedAgents["a2"])
	}
	tm.ProcessDnskeyConfirmation("d1", "a2", transport.ConfirmSuccess.String(), nil)
	if _, ok := tm.pendingDnskeyPropagations["d1"]; ok {
		t.Error("everyone applied, the propagation is still pending")
	}
	if tm.ProcessDnskeyConfirmation("d1", "a2", transport.ConfirmSuccess.String(), nil) {
		t.Error("a confirmation after the propagation resolved was taken as one")
	}

	// a rejection is final: it resolves the propagation as rejected
	tm.TrackDnskeyPropagation("z.example.", "d2", []uint16{4712}, []AgentId{"a1", "a2"})
	tm.ProcessDnskeyConfirmation("d2", "a1", transport.ConfirmRejected.String(), []RejectedItemInfo{{Record: "DNSKEY", Reason: "policy forbids"}})
	waiting("d2", "a1 rejected, a2 not heard")
	if p := tm.pendingDnskeyPropagations["d2"]; !p.Rejected || p.RejectionMsg != "policy forbids" {
		t.Errorf("rejection not recorded: %+v", p)
	}
	tm.ProcessDnskeyConfirmation("d2", "a2", transport.ConfirmSuccess.String(), nil)
	if _, ok := tm.pendingDnskeyPropagations["d2"]; ok {
		t.Error("everyone answered (one rejected), the propagation is still pending")
	}
}
