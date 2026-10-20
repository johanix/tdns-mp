/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A record that this agent's combiner rejected stays in the agent's repo,
 * marked rejected. It is not held: the same set sent again goes to the
 * combiner, and no confirmation names it as applied before the combiner
 * has taken it.
 */
package tdnsmp

import (
	"slices"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The owner's edit makes the sender a signer, and the sender distributes its
// DNSKEY. This agent's combiner has not loaded that edit yet, and rejects
// the key: in its copy of the zone the sender is no signer. The sender
// sends the same set again. Taken as held because the repo has it, the
// resend was confirmed as applied without reaching the combiner: the
// sender's propagation of the key ended, and it signed with a key this
// provider never published. Now the resend goes to the combiner, the
// sender's propagation waits, and it ends when the combiner takes the key.
// An older distribution of the set, stale, is confirmed PARTIAL without the
// key, which a plain success would have covered.
func TestADnskeyItsCombinerRejectedIsSentToItAgain(t *testing.T) {
	r := receivingRig(t, "rejected.dnskey.example.")
	z := r.mpzd.ZoneName
	signer, us := AgentId(r.peer.Identity), AgentId(r.us.Identity)
	key := testDnskey(t, z, 256)
	rec, kt := key.String(), key.KeyTag()
	op := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{rec}}

	// the sender's side: its propagation of the key, sent again as d2
	snd := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	d0, d1, d2 := nextDistributionID(), nextDistributionID(), nextDistributionID()
	snd.TrackDnskeyPropagation(ZoneName(z), d0, []uint16{kt}, nil, []AgentId{us})
	snd.TrackDnskeyPropagation(ZoneName(z), d2, []uint16{kt}, nil, []AgentId{us})
	waiting := func(d string) bool {
		snd.dnskeyPropMu.Lock()
		defer snd.dnskeyPropMu.Unlock()
		_, ok := snd.pendingDnskeyPropagations[d]
		return ok
	}

	sent := time.Now().Add(-time.Minute)
	r.receivesAt(t, string(signer), d1, sent.Add(10*time.Second), nil, op)
	first := r.heldBy(t, signer, dns.TypeDNSKEY, rec)
	r.rejects(rigCombiner, first.DistributionID, rec, "DNSKEY rejected: sender is not a signer")
	if c := r.answered(t, d1); slices.Contains(c.AppliedRecords, rec) {
		t.Fatalf("the sender got %+v for the distribution the combiner rejected", *c)
	}

	// an older distribution of the same set, overtaken by d1: stale, it is
	// confirmed with what this agent holds, and the rejected key is not held
	r.receivesAt(t, string(signer), d0, sent, nil, op)
	c0 := r.answered(t, d0)
	if c0.Status != "PARTIAL" || slices.Contains(c0.AppliedRecords, rec) {
		t.Fatalf("the stale distribution of the rejected key got %+v, want PARTIAL without the key", *c0)
	}
	snd.ProcessDnskeyConfirmation(d0, c0.Source, c0.Status, c0.AppliedRecords, nil)
	if !waiting(d0) {
		t.Fatal("the stale distribution's confirmation ended the sender's propagation of a key the combiner rejected")
	}

	// the same set again, newer
	r.receivesAt(t, string(signer), d2, sent.Add(20*time.Second), nil, op)
	var again TrackedRRInfo
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if info := r.heldBy(t, signer, dns.TypeDNSKEY, rec); info.DistributionID != first.DistributionID {
			again = info
			break
		}
	}
	if again.DistributionID == "" || again.State != RRStatePending.String() {
		t.Fatalf("the resend did not go to the combiner: the key is tracked as %+v\n%s", r.heldBy(t, signer, dns.TypeDNSKEY, rec), r.log)
	}
	for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); {
		c, ok := recvWithin(r.peer.MsgQs.Confirmation, time.Until(end))
		if !ok {
			break
		}
		if c.DistributionID != d2 {
			continue
		}
		if slices.Contains(c.AppliedRecords, rec) {
			t.Fatalf("before the combiner took the key, the sender got %+v", *c)
		}
		snd.ProcessDnskeyConfirmation(d2, c.Source, c.Status, c.AppliedRecords, nil)
	}
	if !waiting(d2) {
		t.Fatal("the sender's propagation of the key ended before this agent's combiner took it")
	}

	// the combiner, which has loaded the edit by now, takes the key
	r.confirms(rigCombiner, again.DistributionID, rec)
	c := r.answered(t, d2)
	if !slices.Contains(c.AppliedRecords, rec) {
		t.Fatalf("after the combiner took the key, the sender got %+v", *c)
	}
	snd.ProcessDnskeyConfirmation(d2, c.Source, c.Status, c.AppliedRecords, nil)
	if waiting(d2) {
		t.Error("the sender's propagation of the key still waits after this agent confirmed it")
	}
}

// In each form an update takes, the add, the replace, and the class-tagged
// RRsets, the same record again is a change while this agent's combiner
// has it rejected, and no change once the combiner has taken it.
func TestARecordItsCombinerRejectedIsAChangeInEveryForm(t *testing.T) {
	const zone, agent = ZoneName("rejected.forms.example."), AgentId("agent.peer.example.")
	rr, err := dns.NewRR(string(zone) + " 3600 IN TXT \"held\"")
	if err != nil {
		t.Fatal(err)
	}
	rec := rr.String()
	forms := map[string]func() *ZoneUpdate{
		"add": func() *ZoneUpdate {
			return &ZoneUpdate{Operations: []core.RROperation{{Operation: "add", RRtype: "TXT", Records: []string{rec}}}}
		},
		"replace": func() *ZoneUpdate {
			return &ZoneUpdate{Operations: []core.RROperation{{Operation: "replace", RRtype: "TXT", Records: []string{rec}}}}
		},
		"rrsets": func() *ZoneUpdate {
			return &ZoneUpdate{RRsets: map[uint16]core.RRset{dns.TypeTXT: {RRs: []dns.RR{dns.Copy(rr)}}}}
		},
	}
	for name, form := range forms {
		zdr, err := NewZoneDataRepo()
		if err != nil {
			t.Fatal(err)
		}
		process := func() bool {
			changed, _, err := zdr.ProcessUpdate(&SynchedDataUpdate{Zone: zone, AgentId: agent, UpdateType: "remote", Update: form()})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			return changed
		}
		if !process() {
			t.Fatalf("%s: the first send changed nothing", name)
		}
		tracked := zdr.getOrCreateTracking(zone, agent, dns.TypeTXT)
		tracked.Tracked = []TrackedRR{{RR: dns.Copy(rr), State: RRStateRejected}}
		if !process() {
			t.Errorf("%s: the record the combiner rejected, sent again, is no change", name)
		}
		tracked.Tracked = []TrackedRR{{RR: dns.Copy(rr), State: RRStateAccepted}}
		if process() {
			t.Errorf("%s: the record the combiner took, sent again, is a change", name)
		}
	}
}
