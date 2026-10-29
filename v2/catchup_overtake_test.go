/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * An answer to a request for the zone's state, or any later message,
 * can reach an agent before a distribution of the same set that was sent
 * earlier. The distribution's replace is then stale, and goes no further
 * than the repo; its confirmation still names what the repo holds of it,
 * which the sender tracks the distribution by.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// receivesAt is receives with the sender's time and, for an answer to a
// request for the zone's state, its marker.
func (r *notifyRig) receivesAt(t *testing.T, originator, distID string, at time.Time, cu *CatchUp, ops ...core.RROperation) {
	t.Helper()
	body, err := json.Marshal(DnsSyncPayload{
		MessageType:    "sync",
		OriginatorID:   originator,
		YourIdentity:   r.us.Identity,
		Zone:           r.mpzd.ZoneName,
		Operations:     ops,
		Time:           at.Format(time.RFC3339Nano),
		Timestamp:      at.Unix(),
		DistributionID: distID,
		CatchUp:        cu,
	})
	if err != nil {
		t.Fatalf("the SYNC: %v", err)
	}
	r.us.Bridge.routeIncomingMessage(&transport.IncomingMessage{
		TypeToken:       "sync",
		DistributionID:  distID,
		SenderID:        originator,
		TransportSender: originator,
		Zone:            r.mpzd.ZoneName,
		Payload:         body,
		ReceivedAt:      time.Now(),
		SourceAddr:      "127.0.0.1:0",
	})
	amp, ok := recvMsgWithin(t, r.us.MsgQs.Msg, 10*time.Second)
	if !ok {
		t.Fatal("the transport did not queue the SYNC")
	}
	r.us.Registry.MsgHandler(amp, r.us.MsgQs.SynchedDataUpdate, r.us.MsgQs.SynchedDataCmd)
}

// heldBy waits for the agent's repo to hold the record under the sender's
// name, and returns it as tracked.
func (r *notifyRig) heldBy(t *testing.T, sender AgentId, rrtype uint16, record string) TrackedRRInfo {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		for _, info := range r.repo(t)[sender][rrtype] {
			if info.RR == record {
				return info
			}
		}
	}
	t.Fatalf("the agent's repo does not hold %s\n%s", record, r.log)
	return TrackedRRInfo{}
}

// queuedForCombiner is how many messages wait in the queue for the agent's
// combiner.
func (r *notifyRig) queuedForCombiner() int {
	n := 0
	for _, m := range r.us.Bridge.ReliableQueue.GetPendingMessages() {
		if m.RecipientID == rigCombiner {
			n++
		}
	}
	return n
}

// The leader has sent its CSYNC (distribution D) and waits for every
// provider's confirmation. This agent restarts, asks the leader for the
// zone's state, and the leader's answer, which carries the same CSYNC,
// arrives before D. D's replace is then older than the one applied, and
// goes no further; but the agent's final confirmation of D names the
// CSYNC, which its repo holds, and the leader's tracking of D records this
// agent. Confirmed with no record, D was closed at the leader with this
// agent still awaited, and the NOTIFY(CSYNC) waited for good.
func TestALeadersCsyncOvertakenByItsAnswerIsStillConfirmed(t *testing.T) {
	r := receivingRig(t, "overtaken.csync.example.")
	z := r.mpzd.ZoneName
	leader := AgentId(r.peer.Identity)
	r.leader(leader)
	op, rec := csyncOp(z, 1000)
	empty := func(rrtype string) core.RROperation {
		return core.RROperation{Operation: "replace", RRtype: rrtype, Records: []string{}}
	}

	// the leader's tracking of D, as the leader keeps it
	d := nextDistributionID()
	lead, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	lead.MarkRRsPending(ZoneName(z), leader, &ZoneUpdate{Zone: ZoneName(z), AgentId: leader, Operations: []core.RROperation{op}},
		d, []string{r.us.Identity, rigCombiner})

	sent := time.Now().Add(-time.Minute)
	yes := true
	r.receivesAt(t, string(leader), nextDistributionID(), sent.Add(30*time.Second),
		&CatchUp{Request: "r1", Complete: &yes}, empty("NS"), empty("CDS"), op)
	r.heldBy(t, leader, dns.TypeCSYNC, rec)
	forwards := r.queuedForCombiner()

	r.receivesAt(t, string(leader), d, sent, nil, op)
	c := r.answered(t, d)
	if c.Status != "SUCCESS" || !slices.Equal(c.AppliedRecords, []string{rec}) {
		t.Fatalf("the leader got the final confirmation %+v of its CSYNC, want SUCCESS naming %s", *c, rec)
	}
	if n := r.queuedForCombiner(); n != forwards {
		t.Errorf("the overtaken CSYNC went to the combiner again: %d messages for it, were %d", n, forwards)
	}

	lead.ProcessConfirmation(c, nil)
	tr := lead.trackedRR(ZoneName(z), leader, dns.TypeCSYNC, rec)
	if tr == nil {
		t.Fatal("the leader does not track its CSYNC")
	}
	if got := tr.Confirmations[r.us.Identity].Status; got != "accepted" {
		t.Errorf("the leader's tracking of its CSYNC has %q for this agent, want accepted", got)
	}
}

// A distribution whose replace of one set is stale and of another is not:
// the fresh one goes to the combiner, the stale one does not, and when the
// combiner has confirmed, the sender's final confirmation names both. When
// the combiner refuses the fresh one, the stale one's records, which this
// agent holds, are still named as applied.
func TestAStaleReplaceBesideAFreshOneIsConfirmedWithIt(t *testing.T) {
	r := receivingRig(t, "beside.overtaken.csync.example.")
	z := r.mpzd.ZoneName
	leader := AgentId(r.peer.Identity)
	r.leader(leader)
	op, rec := csyncOp(z, 1000)
	ns := fmt.Sprintf("%s\t3600\tIN\tNS\tns9.provider.example.", z)

	sent := time.Now().Add(-time.Minute)
	r.receivesAt(t, string(leader), nextDistributionID(), sent.Add(30*time.Second), nil, op)
	r.heldBy(t, leader, dns.TypeCSYNC, rec)

	d := nextDistributionID()
	r.receivesAt(t, string(leader), d, sent, nil, op, core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{ns}})
	held := r.heldBy(t, leader, dns.TypeNS, ns)
	r.confirms(rigCombiner, held.DistributionID, ns)
	c := r.answered(t, d)
	got := slices.Clone(c.AppliedRecords)
	slices.Sort(got)
	want := []string{ns, rec}
	slices.Sort(want)
	if c.Status != "SUCCESS" || !slices.Equal(got, want) {
		t.Errorf("the sender got the final confirmation %+v, want SUCCESS naming the NS and the CSYNC", *c)
	}

	// again, a later CSYNC first; and the combiner refuses the NS
	r.receivesAt(t, string(leader), nextDistributionID(), sent.Add(90*time.Second), nil, op)
	ns8 := fmt.Sprintf("%s\t3600\tIN\tNS\tns8.provider.example.", z)
	d2 := nextDistributionID()
	r.receivesAt(t, string(leader), d2, sent.Add(60*time.Second), nil, op, core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{ns8}})
	held = r.heldBy(t, leader, dns.TypeNS, ns8)
	r.rejects(rigCombiner, held.DistributionID, ns8, "not taken here")
	c = r.answered(t, d2)
	if c.Status == "SUCCESS" || !slices.Equal(c.AppliedRecords, []string{rec}) || len(c.RejectedItems) != 1 || c.RejectedItems[0].Record != ns8 {
		t.Errorf("the sender got the final confirmation %+v, want the NS refused and the CSYNC applied", *c)
	}
}

// A stale replace of a set, and an add to the same set in the same update:
// the repo applies the add, and the add goes on to the combiner. Only the
// replace goes no further, and it removes nothing.
func TestAnAddBesideAStaleReplaceOfTheSameSetGoesOn(t *testing.T) {
	r := receivingRig(t, "add.overtaken.example.")
	z := r.mpzd.ZoneName
	peer := AgentId(r.peer.Identity)
	ns1 := fmt.Sprintf("%s\t3600\tIN\tNS\tns1.provider.example.", z)
	ns2 := fmt.Sprintf("%s\t3600\tIN\tNS\tns2.provider.example.", z)

	sent := time.Now().Add(-time.Minute)
	r.receivesAt(t, string(peer), nextDistributionID(), sent.Add(30*time.Second), nil,
		core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{ns1}})
	r.heldBy(t, peer, dns.TypeNS, ns1)

	r.receivesAt(t, string(peer), nextDistributionID(), sent, nil,
		core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{}},
		core.RROperation{Operation: "add", RRtype: "NS", Records: []string{ns2}})
	held := r.heldBy(t, peer, dns.TypeNS, ns2)
	if got := r.queuedFor(held.DistributionID); !slices.Equal(got, []string{rigCombiner}) {
		t.Errorf("the add beside a stale replace is queued for %v, want our combiner\n%s", got, r.log)
	}
	r.heldBy(t, peer, dns.TypeNS, ns1)
}

// The leader's DNSKEY distribution D is overtaken at this agent by the
// leader's answer to its request, which carries the same key. D is stale
// here, and its key is in the repo only through the answer's forward,
// which this agent's combiner has not confirmed. D's confirmation closes
// the leader's queue entry, but it is PARTIAL and does not name the key,
// so the leader's propagation tracking does not take the key as applied.
// When the combiner confirms the answer, this agent's final confirmation of
// the answer is its word that the key is here, and the propagation ends.
func TestADnskeyDistributionOvertakenByAnAnswerWaitsForTheCombiner(t *testing.T) {
	r := receivingRig(t, "dnskey.overtaken.example.")
	z := r.mpzd.ZoneName
	leader, us := AgentId(r.peer.Identity), AgentId(r.us.Identity)
	r.leader(leader)
	key := testDnskey(t, z, 257)
	rec, kt := key.String(), key.KeyTag()
	op := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{rec}}

	// the leader's side: D's propagation tracking, and the answer it sent
	lead := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	d, an := nextDistributionID(), nextDistributionID()
	lead.TrackDnskeyPropagation(t.Context(), ZoneName(z), d, []uint16{kt}, nil, []AgentId{us})
	lead.noteCatchUpAnswer(an, ZoneName(z), us, map[uint16]bool{kt: true})
	result := func() (string, bool) {
		lead.dnskeyPropMu.Lock()
		defer lead.dnskeyPropMu.Unlock()
		prop, waiting := lead.pendingDnskeyPropagations[d]
		if !waiting {
			return "", false
		}
		return prop.Results[us][kt], true
	}

	sent := time.Now().Add(-time.Minute)
	yes := true
	r.receivesAt(t, string(leader), an, sent.Add(30*time.Second), &CatchUp{Request: "r1", Complete: &yes}, op)
	held := r.heldBy(t, leader, dns.TypeDNSKEY, rec)
	r.receivesAt(t, string(leader), d, sent, nil, op)
	c := r.answered(t, d)
	if c.Status != "PARTIAL" || slices.Contains(c.AppliedRecords, rec) {
		t.Fatalf("the leader got the final confirmation %+v of its DNSKEY, want PARTIAL without the key", *c)
	}
	lead.ProcessDnskeyConfirmation(d, c.Source, c.Status, c.AppliedRecords, nil)
	if got, waiting := result(); !waiting || got != "" {
		t.Fatalf("before this agent's combiner confirmed, the leader's tracking has %q for the key (waiting %v)", got, waiting)
	}

	// the combiner confirms the answer's forward; this agent then confirms
	// the answer
	r.confirms(rigCombiner, held.DistributionID, rec)
	ca := r.answered(t, an)
	lead.ProcessDnskeyConfirmation(an, ca.Source, ca.Status, ca.AppliedRecords, nil)
	if got, waiting := result(); waiting {
		t.Errorf("after this agent confirmed the answer, the propagation still waits (%q for the key)", got)
	}
}
