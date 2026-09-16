package tdnsmp

import (
	"testing"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// tdns-mp #57 and the S3 review's B3: what a remote agent's confirmation
// says about the keys being propagated. Applied when every key of ours is
// among the applied records (a plain success, or a partial that applied
// ours and rejected someone else's); rejected when a key of ours is among
// the rejected items or the whole answer is a rejection (the combiner's
// "error" for an all-rejected update arrives as failed with rejected
// items); pending, and a partial that says nothing about our keys, leave
// the propagation waiting.
func TestProcessDnskeyConfirmationReadsWhatTheAnswerSaysAboutOurKeys(t *testing.T) {
	ours := testDnskeyRR(t, "z.example.", 257)
	theirs := testDnskeyRR(t, "z.example.", 257)
	tm := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	track := func(dist string) {
		tm.TrackDnskeyPropagation("z.example.", dist, []uint16{ours.KeyTag()}, nil, []AgentId{"a1", "a2"})
	}
	waiting := func(dist, step string) {
		t.Helper()
		if _, ok := tm.pendingDnskeyPropagations[dist]; !ok {
			t.Fatalf("%s: the propagation was resolved", step)
		}
	}
	resolved := func(dist, step string) {
		t.Helper()
		if _, ok := tm.pendingDnskeyPropagations[dist]; ok {
			t.Fatalf("%s: the propagation is still pending", step)
		}
	}
	rej := func(rr *dns.DNSKEY, why string) []RejectedItemInfo {
		return []RejectedItemInfo{{Record: rr.String(), Reason: why}}
	}

	track("d1")
	if !tm.ProcessDnskeyConfirmation("d1", "a1", transport.ConfirmPending.String(), nil, nil) {
		t.Fatal("not recognised as a DNSKEY propagation")
	}
	waiting("d1", "a1 pending")
	tm.ProcessDnskeyConfirmation("d1", "a2", transport.ConfirmPending.String(), nil, nil)
	waiting("d1", "both pending (P9)")
	// a partial that applied someone else's key and says nothing of ours
	tm.ProcessDnskeyConfirmation("d1", "a1", transport.ConfirmPartial.String(), []string{theirs.String()}, rej(theirs, "not that one"))
	waiting("d1", "a1 partial about another key")
	if p := tm.pendingDnskeyPropagations["d1"]; p.ExpectedAgents["a1"] || p.Rejected {
		t.Errorf("a partial about another key counted: confirmed=%v rejected=%v", p.ExpectedAgents["a1"], p.Rejected)
	}
	// a partial that applied ours and rejected theirs: applied
	tm.ProcessDnskeyConfirmation("d1", "a1", transport.ConfirmPartial.String(), []string{ours.String()}, rej(theirs, "not that one"))
	waiting("d1", "a1 applied ours, a2 pending")
	if p := tm.pendingDnskeyPropagations["d1"]; !p.ExpectedAgents["a1"] || p.Rejected {
		t.Errorf("a partial that applied ours: confirmed=%v rejected=%v, want confirmed, not rejected", p.ExpectedAgents["a1"], p.Rejected)
	}
	tm.ProcessDnskeyConfirmation("d1", "a2", transport.ConfirmSuccess.String(), []string{ours.String()}, nil)
	resolved("d1", "everyone applied")
	if tm.ProcessDnskeyConfirmation("d1", "a2", transport.ConfirmSuccess.String(), nil, nil) {
		t.Error("a confirmation after the propagation resolved was taken as one")
	}

	// the combiner's all-rejected answer: failed with our key rejected
	track("d2")
	tm.ProcessDnskeyConfirmation("d2", "a1", transport.ConfirmFailed.String(), nil, rej(ours, "policy forbids"))
	waiting("d2", "a1 rejected, a2 not heard")
	if p := tm.pendingDnskeyPropagations["d2"]; !p.Rejected || p.RejectionMsg != "policy forbids" || !p.ExpectedAgents["a1"] {
		t.Errorf("rejection not recorded as a final answer: %+v", p)
	}
	tm.ProcessDnskeyConfirmation("d2", "a2", transport.ConfirmSuccess.String(), []string{ours.String()}, nil)
	resolved("d2", "everyone answered, one rejected")

	// a partial that rejected ours while applying theirs: rejected
	track("d3")
	tm.ProcessDnskeyConfirmation("d3", "a1", transport.ConfirmPartial.String(), []string{theirs.String()}, rej(ours, "bad flags"))
	if p := tm.pendingDnskeyPropagations["d3"]; !p.Rejected || p.RejectionMsg != "bad flags" {
		t.Errorf("a partial that rejected ours: %+v, want rejected", p)
	}

	// a failure that names no rejected item (a transport error) is not an answer
	track("d4")
	tm.ProcessDnskeyConfirmation("d4", "a1", transport.ConfirmFailed.String(), nil, nil)
	if p := tm.pendingDnskeyPropagations["d4"]; p.Rejected || p.ExpectedAgents["a1"] {
		t.Errorf("a failure naming nothing counted: %+v", p)
	}

	// a removal: the record shows up among the removed ones, and the
	// tracker knows the key was removed (its answer goes out as "removed")
	tm.TrackDnskeyPropagation("z.example.", "d5", []uint16{ours.KeyTag()}, []uint16{ours.KeyTag()}, []AgentId{"a1", "a2"})
	if p := tm.pendingDnskeyPropagations["d5"]; !p.Removed[ours.KeyTag()] {
		t.Errorf("the removed key is not marked removed in the tracker: %+v", p)
	}
	tm.ProcessDnskeyConfirmation("d5", "a1", transport.ConfirmSuccess.String(), []string{ours.String()}, nil)
	tm.ProcessDnskeyConfirmation("d5", "a2", transport.ConfirmSuccess.String(), []string{ours.String()}, nil)
	resolved("d5", "a removal applied everywhere")
}

func testDnskeyRR(t *testing.T, zone string, flags uint16) *dns.DNSKEY {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: flags, Protocol: 3, Algorithm: dns.ED25519}
	if _, err := k.Generate(256); err != nil {
		t.Fatal(err)
	}
	return k
}

// The tracker keeps each key's result per agent: a distribution of two
// keys where one is applied and the other rejected ends with one key
// propagated and one rejected, not both rejected; an agent that answered
// for one key only has not answered.
func TestProcessDnskeyConfirmationKeepsResultsPerKey(t *testing.T) {
	a := testDnskeyRR(t, "z.example.", 257)
	b := testDnskeyRR(t, "z.example.", 256)
	tm := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	tm.TrackDnskeyPropagation("z.example.", "d1", []uint16{a.KeyTag(), b.KeyTag()}, nil, []AgentId{"a1"})
	// a partial that applied a and says nothing of b: a1 has not answered
	tm.ProcessDnskeyConfirmation("d1", "a1", transport.ConfirmPartial.String(), []string{a.String()}, nil)
	p := tm.pendingDnskeyPropagations["d1"]
	if p == nil || p.ExpectedAgents["a1"] {
		t.Fatalf("an answer for one key of two counted as the agent's answer: %+v", p)
	}
	if p.Results["a1"][a.KeyTag()] != "applied" || p.Results["a1"][b.KeyTag()] != "" {
		t.Errorf("results after the partial: %v", p.Results["a1"])
	}
	// then a partial that rejected b: a1 has answered, a applied, b rejected
	tm.ProcessDnskeyConfirmation("d1", "a1", transport.ConfirmPartial.String(), nil, []RejectedItemInfo{{Record: b.String(), Reason: "no ZSKs here"}})
	if _, ok := tm.pendingDnskeyPropagations["d1"]; ok {
		t.Fatal("every key answered by every agent, the propagation is still pending")
	}
	// the results that went to the signer are per key: a propagated, b
	// rejected (the send itself needs a transport; the split is what the
	// tracker decided)
	if p.Results["a1"][a.KeyTag()] != "applied" || p.Results["a1"][b.KeyTag()] != "rejected" {
		t.Errorf("final results: %v, want a applied, b rejected", p.Results["a1"])
	}
	// a whole rejection rejects every key it did not apply
	tm.TrackDnskeyPropagation("z.example.", "d2", []uint16{a.KeyTag(), b.KeyTag()}, nil, []AgentId{"a1"})
	tm.ProcessDnskeyConfirmation("d2", "a1", transport.ConfirmFailed.String(), nil, []RejectedItemInfo{{Record: a.String(), Reason: "policy"}})
	if p := tm.pendingDnskeyPropagations["d2"]; p != nil {
		t.Errorf("a whole rejection left the propagation pending: %+v", p.Results)
	}
}
