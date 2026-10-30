/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A stale replace of a set that this agent's combiner ignores (#288). The
 * combiner holds none of the sender's records of the set, by its policy,
 * and its word on the set that overtook the replace named them as ignored.
 * The stale replace's confirmation names them as ignored too, so the
 * sender's add of them settles.
 */
package tdnsmp

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// combinerIgnores is the combiner's final confirmation of distID: it applies
// none of the records.
func (r *notifyRig) combinerIgnores(distID string) {
	r.us.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(distID, rigCombiner, transport.ConfirmIgnored, r.mpzd.ZoneName,
		nil, nil, nil, nil, false, ""))
}

// sendersTracking is the sender's tracking of distribution distID of ops,
// sent to this agent, as the sender keeps it.
func (r *notifyRig) sendersTracking(t *testing.T, distID string, ops ...core.RROperation) *ZoneDataRepo {
	t.Helper()
	snd, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	z, sender := ZoneName(r.mpzd.ZoneName), AgentId(r.peer.Identity)
	snd.MarkRRsPending(z, sender, &ZoneUpdate{Zone: z, AgentId: sender, Operations: ops}, distID, []string{r.us.Identity})
	return snd
}

// settledAt checks the sender's tracking of record after this agent's
// confirmation: this agent's word on it is want, and the record no longer
// waits.
func (r *notifyRig) settledAt(t *testing.T, snd *ZoneDataRepo, rrtype uint16, record, want string) {
	t.Helper()
	tr := snd.trackedRR(ZoneName(r.mpzd.ZoneName), AgentId(r.peer.Identity), rrtype, record)
	if tr == nil {
		t.Fatalf("the sender does not track %s", record)
	}
	if got := tr.Confirmations[r.us.Identity].Status; got != want {
		t.Errorf("the sender's tracking of %s has %q for this agent, want %q", record, got, want)
	}
	if tr.State == RRStatePending {
		t.Errorf("the sender's %s is still PENDING", record)
	}
}

// The sender adds an NS record (distribution D) while this agent is away.
// When the agent is back, the sender's answer to its request for the zone's
// state, a newer replace of the same set, arrives first, and this agent's
// combiner, which takes none of the sender's records, answers IGNORED. Then
// D arrives, stale. Its confirmation is IGNORED and names the NS as ignored,
// as the answer's did, and the sender's add settles. Confirmed PARTIAL with
// no record, D left the add PENDING at the sender for good.
func TestAnAddOvertakenByASetTheCombinerIgnoresSettles(t *testing.T) {
	r := receivingRig(t, "ignored.overtaken.example.")
	sender := AgentId(r.peer.Identity)
	ns := fmt.Sprintf("%s\t3600\tIN\tNS\tns9.provider.example.", r.mpzd.ZoneName)
	op := core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{ns}}

	d := nextDistributionID()
	snd := r.sendersTracking(t, d, op)

	sent := time.Now().Add(-time.Minute)
	yes := true
	answer := nextDistributionID()
	before := r.combinerDists()
	r.receivesAt(t, string(sender), answer, sent.Add(30*time.Second), &CatchUp{Request: "r1", Complete: &yes}, op)
	fwd := r.newCombinerDist(before, 10*time.Second)
	if fwd == "" {
		t.Fatalf("the answer did not go to the combiner\n%s", r.log)
	}
	r.combinerIgnores(fwd)
	if c := r.answered(t, answer); c.Status != "IGNORED" {
		t.Fatalf("the sender got the final confirmation %+v of its answer, want IGNORED", *c)
	}

	before = r.combinerDists()
	r.receivesAt(t, string(sender), d, sent, nil, op)
	c := r.answered(t, d)
	if c.Status != "IGNORED" || !slices.Equal(c.IgnoredRecords, []string{ns}) || len(c.AppliedRecords) > 0 {
		t.Fatalf("the sender got the final confirmation %+v of its add, want IGNORED naming the NS as ignored", *c)
	}
	if fwd := r.newCombinerDist(before, 200*time.Millisecond); fwd != "" {
		t.Errorf("the stale replace went to the combiner (%s)", fwd)
	}
	snd.ProcessConfirmation(c, nil)
	r.settledAt(t, snd, dns.TypeNS, ns, "ignored")
}

// The same beside a fresh set: D carries a CSYNC, which goes to the
// combiner, and the stale NS, which does not. When the combiner has
// confirmed the CSYNC, D's confirmation names it as applied and the NS as
// ignored; it is PARTIAL, as the combiner does not hold the NS.
func TestAStaleSetTheCombinerIgnoresIsNamedBesideAFreshOne(t *testing.T) {
	r := receivingRig(t, "ignored.beside.overtaken.example.")
	leader := AgentId(r.peer.Identity)
	r.leader(leader)
	csync, rec := csyncOp(r.mpzd.ZoneName, 1000)
	ns := fmt.Sprintf("%s\t3600\tIN\tNS\tns9.provider.example.", r.mpzd.ZoneName)
	nsOp := core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{ns}}

	d := nextDistributionID()
	snd := r.sendersTracking(t, d, csync, nsOp)

	sent := time.Now().Add(-time.Minute)
	before := r.combinerDists()
	newer := nextDistributionID()
	r.receivesAt(t, string(leader), newer, sent.Add(30*time.Second), nil, nsOp)
	fwd := r.newCombinerDist(before, 10*time.Second)
	if fwd == "" {
		t.Fatalf("the newer NS set did not go to the combiner\n%s", r.log)
	}
	r.combinerIgnores(fwd)
	r.answered(t, newer)

	r.receivesAt(t, string(leader), d, sent, nil, csync, nsOp)
	held := r.heldBy(t, leader, dns.TypeCSYNC, rec)
	r.confirms(rigCombiner, held.DistributionID, rec)
	c := r.answered(t, d)
	if c.Status != "PARTIAL" || !slices.Equal(c.AppliedRecords, []string{rec}) || !slices.Equal(c.IgnoredRecords, []string{ns}) {
		t.Fatalf("the sender got the final confirmation %+v, want PARTIAL naming the CSYNC as applied and the NS as ignored", *c)
	}
	snd.ProcessConfirmation(c, nil)
	r.settledAt(t, snd, dns.TypeCSYNC, rec, "accepted")
	r.settledAt(t, snd, dns.TypeNS, ns, "ignored")
}

// A combiner that applies one set of a distribution and ignores another
// answers PARTIAL. The set it ignored is noted as ignored all the same, from
// the records it names as ignored: a stale replace of that set alone is
// IGNORED, naming them, and the sender's add settles.
func TestASetIgnoredBesideOneAppliedIsNotedAsIgnored(t *testing.T) {
	r := receivingRig(t, "partly.ignored.overtaken.example.")
	leader := AgentId(r.peer.Identity)
	r.leader(leader)
	csync, rec := csyncOp(r.mpzd.ZoneName, 1000)
	ns := fmt.Sprintf("%s\t3600\tIN\tNS\tns9.provider.example.", r.mpzd.ZoneName)
	nsOp := core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{ns}}

	d := nextDistributionID()
	snd := r.sendersTracking(t, d, nsOp)

	sent := time.Now().Add(-time.Minute)
	before := r.combinerDists()
	newer := nextDistributionID()
	r.receivesAt(t, string(leader), newer, sent.Add(30*time.Second), nil, csync, nsOp)
	fwd := r.newCombinerDist(before, 10*time.Second)
	if fwd == "" {
		t.Fatalf("the newer sets did not go to the combiner\n%s", r.log)
	}
	r.us.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(fwd, rigCombiner, transport.ConfirmPartial, r.mpzd.ZoneName,
		[]string{rec}, nil, nil, []string{ns}, false, ""))
	r.answered(t, newer)

	r.receivesAt(t, string(leader), d, sent, nil, nsOp)
	c := r.answered(t, d)
	if c.Status != "IGNORED" || !slices.Equal(c.IgnoredRecords, []string{ns}) || len(c.AppliedRecords) > 0 {
		t.Fatalf("the sender got the final confirmation %+v of its add, want IGNORED naming the NS as ignored", *c)
	}
	snd.ProcessConfirmation(c, nil)
	r.settledAt(t, snd, dns.TypeNS, ns, "ignored")
}

// A stale DNSKEY replace waits for the combiner's word on the set that
// overtook it, which carries a CSYNC too. The combiner answers PARTIAL: it
// applies the CSYNC and ignores the keys. The stale replace names the keys
// it holds as ignored, though the combiner's word left them out of what it
// applied.
func TestAStaleKeySetWaitingOnAPartialThatIgnoredItIsNamedAsIgnored(t *testing.T) {
	r := receivingRig(t, "partial.waited.overtaken.example.")
	z := r.mpzd.ZoneName
	signer := AgentId(r.peer.Identity)
	r.leader(signer)
	k1, k2 := testDnskey(t, z, 256), testDnskey(t, z, 256)
	keys := []string{k1.String(), k2.String()}
	slices.Sort(keys)
	keyOp := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: keys}
	csync, rec := csyncOp(z, 1000)

	sent := time.Now().Add(-time.Minute)
	before := r.combinerDists()
	r.receivesAt(t, string(signer), nextDistributionID(), sent.Add(20*time.Second), nil, keyOp, csync)
	fwd := r.newCombinerDist(before, 10*time.Second)
	if fwd == "" {
		t.Fatalf("the newer sets did not go to the combiner\n%s", r.log)
	}
	waits := r.logCount(staleWaitLine)
	d := nextDistributionID()
	r.receivesAt(t, string(signer), d, sent.Add(10*time.Second), nil, keyOp)
	r.waitLog(t, staleWaitLine, waits+1)

	r.us.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(fwd, rigCombiner, transport.ConfirmPartial, z,
		[]string{rec}, nil, nil, keys, false, ""))
	c := r.answered(t, d)
	got := slices.Clone(c.IgnoredRecords)
	slices.Sort(got)
	if c.Status != "PARTIAL" || !slices.Equal(got, keys) || len(c.AppliedRecords) > 0 {
		t.Fatalf("the sender got the final confirmation %+v of the stale key set, want PARTIAL naming both keys as ignored", *c)
	}
}

// The sender's DNSKEY propagation takes a key that a peer's PARTIAL names as
// ignored as that peer's answer on the key, as it takes an overall IGNORED:
// the peer applied another set of the distribution and ignored the keys.
// Without it, the key had no answer from the peer, and the propagation
// waited for the signer's resend.
func TestAKeyAPartialNamesAsIgnoredIsAnswered(t *testing.T) {
	r := receivingRig(t, "partial.ignored.keys.example.")
	z := r.mpzd.ZoneName
	peer := AgentId(r.peer.Identity)
	key := testDnskey(t, z, 256)
	_, rec := csyncOp(z, 1000)
	tm := r.us.Bridge
	tm.dnskeyPropMu.Lock()
	if tm.pendingDnskeyPropagations == nil {
		tm.pendingDnskeyPropagations = map[string]*PendingDnskeyPropagation{}
	}
	tm.dnskeyPropMu.Unlock()
	d := nextDistributionID()
	tm.TrackDnskeyPropagation(ZoneName(z), d, []uint16{key.KeyTag()}, nil, []AgentId{peer})

	tm.ChunkHandler.OnConfirmationReceived(confirmIn(d, string(peer), transport.ConfirmPartial, z,
		[]string{rec}, nil, nil, []string{key.String()}, false, ""))
	tm.dnskeyPropMu.Lock()
	_, waiting := tm.pendingDnskeyPropagations[d]
	tm.dnskeyPropMu.Unlock()
	if waiting {
		t.Errorf("the propagation still waits for the peer whose PARTIAL named the key as ignored\n%s", r.log)
	}
}

// The same for a key credited from the asker's confirmation of an answer: a
// PARTIAL that names the answer's key as ignored ends the propagation made
// before the answer that waits for the asker.
func TestAnAnswersPartialThatNamesTheKeyAsIgnoredIsAnswered(t *testing.T) {
	const zone = "answer.partial.ignored.keys.example."
	asker := AgentId("bob.agent.example.")
	key := testDnskey(t, zone, 256)
	_, rec := csyncOp(zone, 1000)
	snd := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	d, an := nextDistributionID(), nextDistributionID()
	snd.TrackDnskeyPropagation(ZoneName(zone), d, []uint16{key.KeyTag()}, nil, []AgentId{asker})
	snd.noteCatchUpAnswer(an, ZoneName(zone), asker, map[uint16]bool{key.KeyTag(): true})

	snd.processDnskeyConfirmation(an, string(asker), transport.ConfirmPartial.String(), []string{rec}, []string{key.String()}, nil, false, nil)
	snd.dnskeyPropMu.Lock()
	_, waiting := snd.pendingDnskeyPropagations[d]
	snd.dnskeyPropMu.Unlock()
	if waiting {
		t.Errorf("the propagation still waits for the asker whose PARTIAL of the answer named the key as ignored")
	}
}

// A combiner that fails the newer set is not one that ignores it: the stale
// replace still names none of the set and is PARTIAL.
func TestAStaleSetTheCombinerFailedIsStillNotNamed(t *testing.T) {
	r := receivingRig(t, "failed.overtaken.example.")
	sender := AgentId(r.peer.Identity)
	ns := fmt.Sprintf("%s\t3600\tIN\tNS\tns9.provider.example.", r.mpzd.ZoneName)
	op := core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{ns}}

	sent := time.Now().Add(-time.Minute)
	before := r.combinerDists()
	newer := nextDistributionID()
	r.receivesAt(t, string(sender), newer, sent.Add(30*time.Second), nil, op)
	fwd := r.newCombinerDist(before, 10*time.Second)
	if fwd == "" {
		t.Fatalf("the newer set did not go to the combiner\n%s", r.log)
	}
	r.us.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(fwd, rigCombiner, transport.ConfirmFailed, r.mpzd.ZoneName,
		nil, nil, nil, nil, false, "zone not found on this combiner"))
	r.answered(t, newer)

	d := nextDistributionID()
	r.receivesAt(t, string(sender), d, sent, nil, op)
	c := r.answered(t, d)
	if c.Status != "PARTIAL" || len(c.AppliedRecords) > 0 || len(c.IgnoredRecords) > 0 {
		t.Errorf("the sender got the final confirmation %+v, want PARTIAL naming no record", *c)
	}
}
