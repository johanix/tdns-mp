package tdnsmp

import (
	"strings"
	"testing"

	"github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
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

// A provider that does not sign the zone answers "ignored" to a DNSKEY
// distribution: it applies no key of ours and serves the zone as the
// signer gives it. That is a final answer, and the key is propagated once
// every peer answered; the lab's single-signer cells depend on it.
func TestProcessDnskeyConfirmationTakesIgnoredAsAnswered(t *testing.T) {
	ours := testDnskeyRR(t, "z.example.", 256)
	tm := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	tm.TrackDnskeyPropagation("z.example.", "d1", []uint16{ours.KeyTag()}, nil, []AgentId{"a1", "a2"})
	tm.ProcessDnskeyConfirmation("d1", "a1", transport.ConfirmPending.String(), nil, nil)
	tm.ProcessDnskeyConfirmation("d1", "a1", transport.ConfirmIgnored.String(), nil, nil)
	p := tm.pendingDnskeyPropagations["d1"]
	if p == nil || !p.ExpectedAgents["a1"] || p.Rejected || p.Results["a1"][ours.KeyTag()] != "ignored" {
		t.Fatalf("an ignored answer did not count as the agent's answer: %+v", p)
	}
	tm.ProcessDnskeyConfirmation("d1", "a2", transport.ConfirmIgnored.String(), nil, nil)
	if _, ok := tm.pendingDnskeyPropagations["d1"]; ok {
		t.Error("both peers answered ignored, the propagation is still pending")
	}
	if p.Rejected {
		t.Error("ignored answers made the propagation rejected")
	}
}

// Found on the lab (2026-09-16, finding 5): the first distribution after
// the agent's local set was reset carries the zone's whole served set, and
// the peers list in done only the key that was new to them. The tracker
// waited for the other keys' results for good, and the signer's resend was
// a no-op (nothing changed). A success covers every key of the
// distribution: a key the peer did not list was already there.
func TestProcessDnskeyConfirmationSuccessCoversKeysAlreadyThere(t *testing.T) {
	ksk, zsk, standby, retired := testDnskeyRR(t, "z.example.", 257), testDnskeyRR(t, "z.example.", 256), testDnskeyRR(t, "z.example.", 256), testDnskeyRR(t, "z.example.", 256)
	tags := []uint16{ksk.KeyTag(), zsk.KeyTag(), standby.KeyTag(), retired.KeyTag()}
	tm := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	tm.TrackDnskeyPropagation("z.example.", "d1", tags, nil, []AgentId{"a1", "a2"})
	tm.ProcessDnskeyConfirmation("d1", "a1", transport.ConfirmSuccess.String(), []string{standby.String()}, nil)
	p := tm.pendingDnskeyPropagations["d1"]
	if p == nil || !p.ExpectedAgents["a1"] {
		t.Fatalf("a success listing the one new key did not count as the agent's answer for every key: %+v", p)
	}
	for _, kt := range tags {
		if p.Results["a1"][kt] != "applied" {
			t.Errorf("key %d after the success: %q, want applied", kt, p.Results["a1"][kt])
		}
	}
	// a partial answer still says which keys it covers
	tm.ProcessDnskeyConfirmation("d1", "a2", transport.ConfirmPartial.String(), []string{standby.String()}, nil)
	if p.ExpectedAgents["a2"] {
		t.Error("a partial answer listing one key was taken as the answer for every key")
	}
	tm.ProcessDnskeyConfirmation("d1", "a2", transport.ConfirmSuccess.String(), nil, nil)
	if _, ok := tm.pendingDnskeyPropagations["d1"]; ok {
		t.Error("both peers answered success, the propagation is still pending")
	}
	if p.Rejected {
		t.Error("successes made the propagation rejected")
	}
}

// The review of the lab fixes (C1): an ignored answer is no obstacle only
// from a provider that does not sign the zone. A signing provider that
// ignores our key does not have it (its combiner does not take us for a
// signer: the two sides disagree), and design §5.4 wants the key at every
// signing provider before it is published: that key is rejected, with the
// reason. When who signs is not known here, an ignored answer counts as it
// comes (the single-signer cell of the control run).
func TestDnskeyPropagationOutcomeKnowsWhoSigns(t *testing.T) {
	ours := testDnskeyRR(t, "z.example.", 256)
	kt := ours.KeyTag()
	run := func(signing map[AgentId]bool, a1, a2 string) *PendingDnskeyPropagation {
		tm := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
		tm.TrackDnskeyPropagation("z.example.", "d1", []uint16{kt}, nil, []AgentId{"a1", "a2"})
		p := tm.pendingDnskeyPropagations["d1"]
		p.Signing = signing
		tm.ProcessDnskeyConfirmation("d1", "a1", a1, nil, nil)
		tm.ProcessDnskeyConfirmation("d1", "a2", a2, nil, nil)
		if _, ok := tm.pendingDnskeyPropagations["d1"]; ok {
			t.Fatalf("answers %s and %s: the propagation is still pending", a1, a2)
		}
		return p
	}
	success, ignored := transport.ConfirmSuccess.String(), transport.ConfirmIgnored.String()

	// one signing provider applied, one that does not sign ignored: propagated
	propagated, _, rejected, _ := run(map[AgentId]bool{"a1": true}, success, ignored).outcome()
	if len(propagated) != 1 || propagated[0] != kt || len(rejected) != 0 {
		t.Errorf("signer applied, non-signer ignored: propagated %v rejected %v, want the key propagated", propagated, rejected)
	}
	// the signing provider ignored the key: not propagated, and it says why
	propagated, _, rejected, msg := run(map[AgentId]bool{"a1": true}, ignored, ignored).outcome()
	if len(propagated) != 0 || len(rejected) != 1 || !strings.Contains(msg, "a1") || !strings.Contains(msg, "signers") {
		t.Errorf("a signing provider ignored the key: propagated %v rejected %v msg %q, want it rejected naming a1", propagated, rejected, msg)
	}
	// nobody else signs (the single-signer cell): every ignored answer counts
	propagated, _, rejected, _ = run(map[AgentId]bool{}, ignored, ignored).outcome()
	if len(propagated) != 1 || len(rejected) != 0 {
		t.Errorf("no other signer, both ignored: propagated %v rejected %v, want the key propagated", propagated, rejected)
	}
	// who signs is not known here: as it comes
	propagated, _, rejected, _ = run(nil, ignored, ignored).outcome()
	if len(propagated) != 1 || len(rejected) != 0 {
		t.Errorf("signers unknown, both ignored: propagated %v rejected %v, want the key propagated", propagated, rejected)
	}
}

// signingAgents reads who signs from the zone: an agent whose HSYNC3 label
// is among the HSYNCPARAM signers; nil for a zone that is not here.
func TestSigningAgentsComeFromTheZone(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	mpzd := signerTestZone(t, "peers.track.example.", kdb)
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: mpzd.ZoneName, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600}
	}
	hp := &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMSigners{Signers: []string{"us", "p2"}}}}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNCPARAM), Data: hp}}})
	var h3s []dns.RR
	for label, id := range map[string]string{"us": "agent.us.example.", "p2": "agent.p2.example.", "p3": "agent.p3.example."} {
		h3s = append(h3s, &dns.PrivateRR{Hdr: hdr(core.TypeHSYNC3), Data: &core.HSYNC3{State: 1, Label: label, Identity: id, Upstream: "."}})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: h3s})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.InstallInitialSnapshot()

	got := signingAgents(ZoneName(mpzd.ZoneName), []AgentId{"agent.p2.example.", "agent.p3.example.", "agent.nobody.example."})
	if got == nil || !got["agent.p2.example."] || got["agent.p3.example."] || got["agent.nobody.example."] || len(got) != 1 {
		t.Errorf("signing agents %v, want p2's agent alone", got)
	}
	if got := signingAgents("absent.track.example.", []AgentId{"agent.p2.example."}); got != nil {
		t.Errorf("a zone that is not here: %v, want nil (unknown)", got)
	}
}
