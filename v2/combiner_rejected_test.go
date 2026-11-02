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
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
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
	snd.TrackDnskeyPropagation(t.Context(), ZoneName(z), d0, []uint16{kt}, nil, []AgentId{us})
	snd.TrackDnskeyPropagation(t.Context(), ZoneName(z), d2, []uint16{kt}, nil, []AgentId{us})
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

// A distribution whose hand-over to this agent's combiner fails (its queue
// full while the combiner is away) leaves the key in the repo and not with
// the combiner. The same set sent again was a no-op, confirmed as applied
// from the repo alone, and the sender took the key as published here. Now
// the key is not held: the resend goes to the combiner, and the sender's
// propagation ends only when the combiner has taken it.
func TestADnskeyNotHandedToTheCombinerIsSentToItAgain(t *testing.T) {
	r := receivingRig(t, "unhanded.dnskey.example.")
	z := r.mpzd.ZoneName
	signer, us := AgentId(r.peer.Identity), AgentId(r.us.Identity)
	key := testDnskey(t, z, 256)
	rec, kt := key.String(), key.KeyTag()
	op := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{rec}}

	var failing atomic.Bool
	failing.Store(true)
	saved := enqueueForCombiner
	enqueueForCombiner = func(tm *MPTransportBridge, zone ZoneName, update *ZoneUpdate, distID string) (string, error) {
		if failing.Load() {
			return "", errors.New("queue full")
		}
		return saved(tm, zone, update, distID)
	}
	t.Cleanup(func() { enqueueForCombiner = saved })

	snd := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	d1, d2 := nextDistributionID(), nextDistributionID()
	snd.TrackDnskeyPropagation(t.Context(), ZoneName(z), d2, []uint16{kt}, nil, []AgentId{us})
	waiting := func() bool {
		snd.dnskeyPropMu.Lock()
		defer snd.dnskeyPropMu.Unlock()
		_, ok := snd.pendingDnskeyPropagations[d2]
		return ok
	}

	sent := time.Now().Add(-time.Minute)
	r.receivesAt(t, string(signer), d1, sent, nil, op)
	var first TrackedRRInfo
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if first = r.heldBy(t, signer, dns.TypeDNSKEY, rec); first.State == RRStateRejected.String() {
			break
		}
	}
	if first.State != RRStateRejected.String() {
		t.Fatalf("a key the combiner was never handed is tracked as %+v, want rejected\n%s", first, r.log)
	}

	// the combiner's queue has room again; the same set, newer
	failing.Store(false)
	r.receivesAt(t, string(signer), d2, sent.Add(10*time.Second), nil, op)
	var again TrackedRRInfo
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if again = r.heldBy(t, signer, dns.TypeDNSKEY, rec); again.State == RRStatePending.String() {
			break
		}
	}
	if again.State != RRStatePending.String() || again.DistributionID == "" {
		t.Fatalf("the resend did not go to the combiner: the key is tracked as %+v\n%s", again, r.log)
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
	if !waiting() {
		t.Fatal("the sender's propagation of the key ended before this agent's combiner had it")
	}

	r.confirms(rigCombiner, again.DistributionID, rec)
	c := r.answered(t, d2)
	if !slices.Contains(c.AppliedRecords, rec) {
		t.Fatalf("after the combiner took the key, the sender got %+v", *c)
	}
	snd.ProcessDnskeyConfirmation(d2, c.Source, c.Status, c.AppliedRecords, nil)
	if waiting() {
		t.Error("the sender's propagation of the key still waits after this agent confirmed it")
	}
}

// A record the combiner holds, or that an earlier forward still carries to
// it, stays as tracked when a later hand-over fails; the others, a record
// removed before and sent again among them, are marked not held.
func TestAFailedHandOverLeavesHeldRecordsAlone(t *testing.T) {
	const zone, agent = ZoneName("handover.forms.example."), AgentId("agent.peer.example.")
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	rr := func(s string) dns.RR {
		r, err := dns.NewRR(string(zone) + " 3600 IN TXT \"" + s + "\"")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	held, pending, removed, fresh := rr("held"), rr("pending"), rr("removed"), rr("fresh")
	zdr.getOrCreateTracking(zone, agent, dns.TypeTXT).Tracked = []TrackedRR{
		{RR: held, State: RRStateAccepted},
		{RR: pending, State: RRStatePending},
		{RR: removed, State: RRStateRemoved},
	}
	zdr.markNotHandedOver(zone, agent, &ZoneUpdate{Operations: []core.RROperation{{Operation: "replace", RRtype: "TXT",
		Records: []string{held.String(), pending.String(), removed.String(), fresh.String()}}}}, "not handed to the combiner")
	for _, c := range []struct {
		rr   dns.RR
		want bool
	}{{held, false}, {pending, false}, {removed, true}, {fresh, true}} {
		if got := zdr.rejectedByCombiner(zone, agent, dns.TypeTXT, c.rr.String()); got != c.want {
			t.Errorf("%s: not held %v, want %v", c.rr.String(), got, c.want)
		}
	}
	// the class-tagged form: the RRsets' IN records
	legacy := rr("legacy")
	zdr.markNotHandedOver(zone, agent, &ZoneUpdate{RRsets: map[uint16]core.RRset{dns.TypeTXT: {RRs: []dns.RR{legacy}}}}, "not handed to the combiner")
	if !zdr.rejectedByCombiner(zone, agent, dns.TypeTXT, legacy.String()) {
		t.Errorf("%s, in the RRsets form, is held after a failed hand-over", legacy.String())
	}
}

// combinerDists are the distribution IDs queued for this agent's combiner.
func (r *notifyRig) combinerDists() map[string]bool {
	out := map[string]bool{}
	for _, m := range r.us.Bridge.ReliableQueue.GetPendingMessages() {
		if m.RecipientID == rigCombiner {
			out[m.DistributionID] = true
		}
	}
	return out
}

// newCombinerDist waits for a distribution to this agent's combiner that is
// not among before, and returns it ("" when none comes).
func (r *notifyRig) newCombinerDist(before map[string]bool, within time.Duration) string {
	for end := time.Now().Add(within); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		for d := range r.combinerDists() {
			if !before[d] {
				return d
			}
		}
	}
	return ""
}

// combinerTakes is the combiner's final confirmation of distID, the records
// applied.
func (r *notifyRig) combinerTakes(distID string, records ...string) {
	r.us.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(distID, rigCombiner, transport.ConfirmSuccess, r.mpzd.ZoneName,
		records, nil, nil, nil, false, ""))
}

// A DNSKEY removal is a key left out of a replace. The combiner holds both
// keys; the replace that drops one is applied here, and its hand-over to the
// combiner fails. Every key still in the set is accepted, so no record is
// left to mark. The queue's resend of the same distribution found the repo
// matching and was confirmed SUCCESS, which covers every key: the signer was
// told the old key was gone while the combiner still served it. Now the set's
// note says its last hand-over failed: the resend goes to the combiner, the
// sender gets no success until the combiner has taken it, and an older copy
// of the set, arriving meanwhile, is confirmed PARTIAL with none of the set.
// The same for an empty replace, the last key removed.
func TestARemovalNotHandedToTheCombinerIsNotConfirmed(t *testing.T) {
	for _, c := range []struct {
		name string
		keep int // keys left in the replace that removes
	}{{"a key left out", 1}, {"the last key, an empty replace", 0}} {
		t.Run(c.name, func(t *testing.T) {
			zone := map[int]string{1: "omitted.dnskey.example.", 0: "emptied.dnskey.example."}[c.keep]
			r := receivingRig(t, zone)
			z := r.mpzd.ZoneName
			signer, us := AgentId(r.peer.Identity), AgentId(r.us.Identity)
			k1, k2 := testDnskey(t, z, 256), testDnskey(t, z, 256)
			all := []string{k1.String(), k2.String()}
			if c.keep == 0 {
				all = []string{k2.String()}
			}
			kept := all[:c.keep]
			gone := k2.String()

			var failing atomic.Bool
			saved := enqueueForCombiner
			enqueueForCombiner = func(tm *MPTransportBridge, zone ZoneName, update *ZoneUpdate, distID string) (string, error) {
				if failing.Load() {
					return "", errors.New("queue full")
				}
				return saved(tm, zone, update, distID)
			}
			t.Cleanup(func() { enqueueForCombiner = saved })

			sent := time.Now().Add(-time.Minute)
			// the set as the combiner holds it
			d0 := nextDistributionID()
			before := r.combinerDists()
			r.receivesAt(t, string(signer), d0, sent, nil, core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: all})
			c0 := r.newCombinerDist(before, 10*time.Second)
			if c0 == "" {
				t.Fatalf("the first set did not go to the combiner\n%s", r.log)
			}
			r.combinerTakes(c0, all...)
			r.answered(t, d0)

			// the replace that removes k2; its hand-over fails
			snd := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
			d1 := nextDistributionID()
			snd.TrackDnskeyPropagation(t.Context(), ZoneName(z), d1, []uint16{k2.KeyTag()}, []uint16{k2.KeyTag()}, []AgentId{us})
			waiting := func() bool {
				snd.dnskeyPropMu.Lock()
				defer snd.dnskeyPropMu.Unlock()
				_, ok := snd.pendingDnskeyPropagations[d1]
				return ok
			}
			removal := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: kept}
			failing.Store(true)
			r.receivesAt(t, string(signer), d1, sent.Add(10*time.Second), nil, removal)
			for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
				if !slices.ContainsFunc(r.repo(t)[signer][dns.TypeDNSKEY], func(i TrackedRRInfo) bool { return i.RR == gone }) {
					break
				}
			}

			// an older copy of the set, stale: none of the set is named
			dStale := nextDistributionID()
			r.receivesAt(t, string(signer), dStale, sent.Add(5*time.Second), nil,
				core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: all})

			// the queue sends d1 again; the combiner's queue has room now
			failing.Store(false)
			before = r.combinerDists()
			r.receivesAt(t, string(signer), d1, sent.Add(10*time.Second), nil, removal)
			c1 := r.newCombinerDist(before, 10*time.Second)
			if c1 == "" {
				t.Fatalf("the resend of the removal did not go to the combiner\n%s", r.log)
			}
			for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); {
				cf, ok := recvWithin(r.peer.MsgQs.Confirmation, time.Until(end))
				if !ok {
					break
				}
				if cf.Status == "SUCCESS" || cf.Status == "ok" {
					if cf.DistributionID == d1 {
						t.Fatalf("before the combiner took the removal, the sender got %+v", *cf)
					}
					if cf.DistributionID == dStale || slices.ContainsFunc(cf.AppliedRecords, func(s string) bool { return slices.Contains(all, s) }) {
						t.Fatalf("a stale copy of a set the combiner may not have got %+v", *cf)
					}
				}
				if cf.DistributionID == d1 {
					snd.ProcessDnskeyConfirmation(d1, cf.Source, cf.Status, cf.AppliedRecords, nil)
				}
			}
			if !waiting() {
				t.Fatal("the sender's propagation of the removal ended before the combiner had it")
			}

			r.combinerTakes(c1, kept...)
			cf := r.answered(t, d1)
			snd.ProcessDnskeyConfirmation(d1, cf.Source, cf.Status, cf.AppliedRecords, nil)
			if waiting() {
				t.Errorf("after the combiner took the removal, the sender's propagation still waits (%+v)", *cf)
			}
		})
	}
}

// A resend that arrives while this agent's combiner has not yet confirmed
// the set's last hand-over goes to the combiner again: that forward may be
// of an older set, or given up. The sender gets no success before the
// combiner's word.
func TestAResendWhileTheCombinerHasNotConfirmedGoesToItAgain(t *testing.T) {
	r := receivingRig(t, "inflight.dnskey.example.")
	z := r.mpzd.ZoneName
	signer := AgentId(r.peer.Identity)
	k := testDnskey(t, z, 256)
	op := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{k.String()}}
	sent := time.Now().Add(-time.Minute)
	d1 := nextDistributionID()

	before := r.combinerDists()
	r.receivesAt(t, string(signer), d1, sent, nil, op)
	c1 := r.newCombinerDist(before, 10*time.Second)
	if c1 == "" {
		t.Fatalf("the set did not go to the combiner\n%s", r.log)
	}
	// the sender's wait ends before the combiner's word; it sends d1 again
	before = r.combinerDists()
	r.receivesAt(t, string(signer), d1, sent, nil, op)
	c2 := r.newCombinerDist(before, 10*time.Second)
	if c2 == "" {
		t.Fatalf("the resend, while the combiner had not confirmed, did not go to it again\n%s", r.log)
	}
	for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); {
		cf, ok := recvWithin(r.peer.MsgQs.Confirmation, time.Until(end))
		if !ok {
			break
		}
		if cf.DistributionID == d1 && (cf.Status == "SUCCESS" || cf.Status == "ok") {
			t.Fatalf("before the combiner's word, the sender got %+v", *cf)
		}
	}
	r.combinerTakes(c2, k.String())
	if cf := r.answered(t, d1); !slices.Contains(cf.AppliedRecords, k.String()) {
		t.Errorf("after the combiner took the set, the sender got %+v", *cf)
	}
}

// An update whose fresh part goes to the combiner, and whose stale replace
// is of a set whose last hand-over failed: the final confirmation names none
// of that set and is PARTIAL, though the combiner confirms the fresh part.
// The set's keys were accepted before, so no record of it is marked: only
// the set's note says the combiner may not have it.
func TestAStaleSetWhoseHandOverFailedIsNotNamedBesideAFreshOne(t *testing.T) {
	// The combiner names what it applied, or names nothing (a no-op), or
	// ignores the update naming nothing: then the records are made from the
	// repo, which holds the failed set too.
	for _, answer := range []string{"names the CSYNC", "names nothing", "ignores it"} {
		t.Run("the combiner "+answer, func(t *testing.T) {
			staleSetBesideAFreshOne(t, answer)
		})
	}
}

func staleSetBesideAFreshOne(t *testing.T, answer string) {
	zone := map[string]string{"names the CSYNC": "mixed.handover.example.", "names nothing": "mixed.noop.handover.example.",
		"ignores it": "mixed.ignored.handover.example."}[answer]
	r := receivingRig(t, zone)
	z := r.mpzd.ZoneName
	signer := AgentId(r.peer.Identity)
	r.leader(signer)
	k1, k2 := testDnskey(t, z, 256), testDnskey(t, z, 256)
	both := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{k1.String(), k2.String()}}
	one := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{k1.String()}}
	csync, crec := csyncOp(z, 1000)

	var failing atomic.Bool
	saved := enqueueForCombiner
	enqueueForCombiner = func(tm *MPTransportBridge, zone ZoneName, update *ZoneUpdate, distID string) (string, error) {
		if failing.Load() {
			return "", errors.New("queue full")
		}
		return saved(tm, zone, update, distID)
	}
	t.Cleanup(func() { enqueueForCombiner = saved })

	sent := time.Now().Add(-time.Minute)
	// the combiner holds both keys
	d0 := nextDistributionID()
	before := r.combinerDists()
	r.receivesAt(t, string(signer), d0, sent, nil, both)
	c0 := r.newCombinerDist(before, 10*time.Second)
	if c0 == "" {
		t.Fatalf("the key set did not go to the combiner\n%s", r.log)
	}
	r.combinerTakes(c0, k1.String(), k2.String())
	r.answered(t, d0)

	// a newer set drops k2; its hand-over fails, and k1 stays accepted
	failing.Store(true)
	r.receivesAt(t, string(signer), nextDistributionID(), sent.Add(10*time.Second), nil, one)
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if !slices.ContainsFunc(r.repo(t)[signer][dns.TypeDNSKEY], func(i TrackedRRInfo) bool { return i.RR == k2.String() }) {
			break
		}
	}
	failing.Store(false)

	// an older update: the key set stale, the CSYNC fresh
	d := nextDistributionID()
	before = r.combinerDists()
	r.receivesAt(t, string(signer), d, sent.Add(5*time.Second), nil, both, csync)
	c := r.newCombinerDist(before, 10*time.Second)
	if c == "" {
		t.Fatalf("the CSYNC did not go to the combiner\n%s", r.log)
	}
	switch answer {
	case "names the CSYNC":
		r.combinerTakes(c, crec)
	case "names nothing":
		r.combinerTakes(c)
	case "ignores it":
		r.us.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(c, rigCombiner, transport.ConfirmIgnored, r.mpzd.ZoneName,
			nil, nil, nil, nil, false, ""))
	}
	cf := r.answered(t, d)
	if answer == "ignores it" {
		if slices.Contains(cf.IgnoredRecords, k1.String()) || slices.Contains(cf.AppliedRecords, k1.String()) {
			t.Errorf("the ignored update got %+v, naming the key set", *cf)
		}
		return
	}
	if cf.Status != "PARTIAL" || slices.Contains(cf.AppliedRecords, k1.String()) || !slices.Contains(cf.AppliedRecords, crec) {
		t.Errorf("the update got %+v, want PARTIAL with the CSYNC and without the key set", *cf)
	}
}

// A record the combiner rejected stays in the repo. A later update of
// another type, which the combiner confirms naming nothing, is confirmed with
// records made from the repo: the rejected record is not among them.
func TestARecordTheCombinerRejectedIsNotNamedFromTheRepo(t *testing.T) {
	r := receivingRig(t, "rejected.noop.example.")
	z := r.mpzd.ZoneName
	signer := AgentId(r.peer.Identity)
	r.leader(signer)
	k := testDnskey(t, z, 256)
	sent := time.Now().Add(-time.Minute)

	d1 := nextDistributionID()
	r.receivesAt(t, string(signer), d1, sent, nil, core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{k.String()}})
	first := r.heldBy(t, signer, dns.TypeDNSKEY, k.String())
	r.rejects(rigCombiner, first.DistributionID, k.String(), "DNSKEY rejected: sender is not a signer")
	r.answered(t, d1)

	csync, crec := csyncOp(z, 1000)
	d2 := nextDistributionID()
	before := r.combinerDists()
	r.receivesAt(t, string(signer), d2, sent.Add(10*time.Second), nil, csync)
	c := r.newCombinerDist(before, 10*time.Second)
	if c == "" {
		t.Fatalf("the CSYNC did not go to the combiner\n%s", r.log)
	}
	r.combinerTakes(c)
	cf := r.answered(t, d2)
	if slices.Contains(cf.AppliedRecords, k.String()) || !slices.Contains(cf.AppliedRecords, crec) {
		t.Errorf("the CSYNC's confirmation, made from the repo, is %+v: want the CSYNC and not the rejected key", *cf)
	}
}

// staleWaitLine is the engine's line for a stale DNSKEY replace that waits.
const staleWaitLine = "a stale DNSKEY replace waits for this agent's combiner to confirm the set that overtook it"

// logCount is how many times the rig's log holds line.
func (r *notifyRig) logCount(line string) int {
	return strings.Count(r.log.String(), line)
}

// waitLog waits until the rig's log holds line n times.
func (r *notifyRig) waitLog(t *testing.T, line string, n int) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if r.logCount(line) >= n {
			return
		}
	}
	t.Fatalf("the log never held %q %d times\n%s", line, n, r.log)
}

// A sender's DNSKEY distribution is overtaken by its next one, and this
// agent's combiner, which is away, has confirmed neither. The queue sends the
// first again, or it arrives only now: either way it is stale here, and its
// set is the newer one's, which the combiner has not confirmed. No success,
// and no key named, goes to the sender before the combiner's word: a sender
// takes either as its keys published here (rig Z1). When the first was
// handed over itself, the combiner's word on it is relayed as before, and
// nothing more follows. When it was overtaken before it arrived, its final
// word follows the combiner's on the set that overtook it. For a withdrawal
// (a key left out) and for an introduction (a key added).
func TestAStaleKeySetOvertakenInFlightWaitsForTheCombiner(t *testing.T) {
	for _, kind := range []string{"a withdrawal", "an introduction"} {
		for _, order := range []string{"handed over, then overtaken", "overtaken before it arrives", "overtaken twice before it arrives"} {
			t.Run(kind+", "+order, func(t *testing.T) {
				staleKeySetOvertakenInFlight(t, kind, order)
			})
		}
	}
}

func staleKeySetOvertakenInFlight(t *testing.T, kind, order string) {
	zone := map[string]string{"a withdrawal": "withdrawn", "an introduction": "introduced"}[kind] + "." +
		map[string]string{"handed over, then overtaken": "inflight", "overtaken before it arrives": "late",
			"overtaken twice before it arrives": "twice"}[order] + ".overtaken.example."
	r := receivingRig(t, zone)
	z := r.mpzd.ZoneName
	signer, us := AgentId(r.peer.Identity), AgentId(r.us.Identity)
	k1, k2, k3 := testDnskey(t, z, 256), testDnskey(t, z, 256), testDnskey(t, z, 256)
	var held, first []string
	var keyTags, removedTags []uint16
	if kind == "a withdrawal" {
		held = []string{k1.String(), k2.String()}
		first = []string{k1.String()} // k2 withdrawn
		keyTags, removedTags = []uint16{k2.KeyTag()}, []uint16{k2.KeyTag()}
	} else {
		held = []string{k1.String()}
		first = []string{k1.String(), k2.String()} // k2 introduced
		keyTags = []uint16{k2.KeyTag()}
	}
	next := append(slices.Clone(first), k3.String())
	replace := func(records []string) core.RROperation {
		return core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: records}
	}
	// noFinal: no final word on d1 comes within d
	noFinal := func(d1, when string, d time.Duration) {
		t.Helper()
		for end := time.Now().Add(d); time.Now().Before(end); {
			cf, ok := recvWithin(r.peer.MsgQs.Confirmation, time.Until(end))
			if !ok {
				return
			}
			if cf.DistributionID == d1 && cf.Status != "PENDING" {
				t.Fatalf("%s, the sender got %+v", when, *cf)
			}
		}
	}
	final := func(d1, when string) *ConfirmationDetail {
		t.Helper()
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); {
			cf, ok := recvWithin(r.peer.MsgQs.Confirmation, time.Until(end))
			if !ok {
				break
			}
			if cf.DistributionID == d1 && cf.Status != "PENDING" {
				return cf
			}
		}
		t.Fatalf("%s, no final word on the first distribution\n%s", when, r.log)
		return nil
	}

	sent := time.Now().Add(-time.Minute)
	d0 := nextDistributionID()
	before := r.combinerDists()
	r.receivesAt(t, string(signer), d0, sent, nil, replace(held))
	c0 := r.newCombinerDist(before, 10*time.Second)
	if c0 == "" {
		t.Fatalf("the first set did not go to the combiner\n%s", r.log)
	}
	r.combinerTakes(c0, held...)
	r.answered(t, d0)

	// the sender's propagation of the first distribution
	snd := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	d1 := nextDistributionID()
	snd.TrackDnskeyPropagation(t.Context(), ZoneName(z), d1, keyTags, removedTags, []AgentId{us})
	waiting := func() bool {
		snd.dnskeyPropMu.Lock()
		defer snd.dnskeyPropMu.Unlock()
		_, ok := snd.pendingDnskeyPropagations[d1]
		return ok
	}

	c1 := ""
	if order == "handed over, then overtaken" {
		before = r.combinerDists()
		r.receivesAt(t, string(signer), d1, sent.Add(10*time.Second), nil, replace(first))
		if c1 = r.newCombinerDist(before, 10*time.Second); c1 == "" {
			t.Fatalf("the first distribution did not go to the combiner\n%s", r.log)
		}
	}
	before = r.combinerDists()
	r.receivesAt(t, string(signer), nextDistributionID(), sent.Add(20*time.Second), nil, replace(next))
	c2 := r.newCombinerDist(before, 10*time.Second)
	if c2 == "" {
		t.Fatalf("the newer set did not go to the combiner\n%s", r.log)
	}

	// the first distribution, sent again or only now: stale here
	waits := r.logCount(staleWaitLine)
	r.receivesAt(t, string(signer), d1, sent.Add(10*time.Second), nil, replace(first))
	r.waitLog(t, staleWaitLine, waits+1)
	noFinal(d1, "while the combiner had confirmed no set", 300*time.Millisecond)

	if order == "overtaken twice before it arrives" {
		// the set changes again before the combiner's word on the newer one:
		// that word says nothing of the set the repo holds now
		k4 := testDnskey(t, z, 256)
		last := append(slices.Clone(next), k4.String())
		before = r.combinerDists()
		r.receivesAt(t, string(signer), nextDistributionID(), sent.Add(30*time.Second), nil, replace(last))
		c3 := r.newCombinerDist(before, 10*time.Second)
		if c3 == "" {
			t.Fatalf("the newest set did not go to the combiner\n%s", r.log)
		}
		r.combinerTakes(c2, next...)
		noFinal(d1, "after the combiner's word on a set overtaken in turn", 300*time.Millisecond)
		r.combinerTakes(c3, last...)
		cf := final(d1, "after the combiner took the newest set")
		snd.ProcessDnskeyConfirmation(d1, cf.Source, cf.Status, cf.AppliedRecords, nil)
		if waiting() {
			t.Errorf("after the combiner took the newest set the sender's propagation still waits (%+v)", *cf)
		}
		return
	}
	if c1 != "" {
		// the combiner's word on the first hand-over is its word on that
		// set, and is relayed; its word on the newer set adds nothing
		r.combinerTakes(c1, first...)
		cf := final(d1, "after the combiner took the first set")
		snd.ProcessDnskeyConfirmation(d1, cf.Source, cf.Status, cf.AppliedRecords, nil)
		if waiting() {
			t.Errorf("after the combiner took the first set the sender's propagation still waits (%+v)", *cf)
		}
		r.combinerTakes(c2, next...)
		noFinal(d1, "after the relay, on the combiner's word on the newer set", 300*time.Millisecond)
		return
	}
	r.combinerTakes(c2, next...)
	cf := final(d1, "after the combiner took the newer set")
	if cf.Status != "ok" && cf.Status != "SUCCESS" {
		t.Errorf("after the combiner took the newer set the sender got %+v, want ok", *cf)
	}
	snd.ProcessDnskeyConfirmation(d1, cf.Source, cf.Status, cf.AppliedRecords, nil)
	if waiting() {
		t.Errorf("after the combiner took the newer set the sender's propagation still waits (%+v)", *cf)
	}
}

// An update whose fresh part goes to the combiner, and whose stale replace is
// of a key set that overtook it and that the combiner has not confirmed yet:
// the final confirmation names none of that set and is PARTIAL, though the
// combiner confirms the fresh part.
func TestAStaleKeySetInFlightIsNotNamedBesideAFreshOne(t *testing.T) {
	r := receivingRig(t, "mixed.inflight.handover.example.")
	z := r.mpzd.ZoneName
	signer := AgentId(r.peer.Identity)
	r.leader(signer)
	k1, k2 := testDnskey(t, z, 256), testDnskey(t, z, 256)
	both := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{k1.String(), k2.String()}}
	one := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{k1.String()}}
	csync, crec := csyncOp(z, 1000)

	sent := time.Now().Add(-time.Minute)
	d0 := nextDistributionID()
	before := r.combinerDists()
	r.receivesAt(t, string(signer), d0, sent, nil, both)
	c0 := r.newCombinerDist(before, 10*time.Second)
	if c0 == "" {
		t.Fatalf("the key set did not go to the combiner\n%s", r.log)
	}
	r.combinerTakes(c0, k1.String(), k2.String())
	r.answered(t, d0)

	// a newer set drops k2; the combiner has not confirmed it
	before = r.combinerDists()
	r.receivesAt(t, string(signer), nextDistributionID(), sent.Add(10*time.Second), nil, one)
	if r.newCombinerDist(before, 10*time.Second) == "" {
		t.Fatalf("the newer set did not go to the combiner\n%s", r.log)
	}

	// an older update: the key set stale, the CSYNC fresh
	d := nextDistributionID()
	before = r.combinerDists()
	r.receivesAt(t, string(signer), d, sent.Add(5*time.Second), nil, both, csync)
	c := r.newCombinerDist(before, 10*time.Second)
	if c == "" {
		t.Fatalf("the CSYNC did not go to the combiner\n%s", r.log)
	}
	r.combinerTakes(c, crec)
	cf := r.answered(t, d)
	if cf.Status != "PARTIAL" || slices.Contains(cf.AppliedRecords, k1.String()) || !slices.Contains(cf.AppliedRecords, crec) {
		t.Errorf("the update got %+v, want PARTIAL with the CSYNC and without the key set", *cf)
	}
}

// Only a success from the combiner says it holds the set that overtook a
// stale DNSKEY replace. A combiner that fails the set, naming no record,
// does not hold it: the stale replace names no key and is PARTIAL, and the
// set is handed over again when it comes again. An IGNORED is passed on.
func TestAStaleKeySetIsNotCreditedOnTheCombinersFailure(t *testing.T) {
	for _, word := range []transport.ConfirmStatus{transport.ConfirmFailed, transport.ConfirmIgnored, transport.ConfirmPartial} {
		t.Run(word.String(), func(t *testing.T) {
			r := receivingRig(t, strings.ToLower(word.String())+".word.overtaken.example.")
			z := r.mpzd.ZoneName
			signer, us := AgentId(r.peer.Identity), AgentId(r.us.Identity)
			k1, k2, k3 := testDnskey(t, z, 256), testDnskey(t, z, 256), testDnskey(t, z, 256)
			replace := func(records ...string) core.RROperation {
				return core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: records}
			}
			sent := time.Now().Add(-time.Minute)
			d0 := nextDistributionID()
			before := r.combinerDists()
			r.receivesAt(t, string(signer), d0, sent, nil, replace(k1.String(), k2.String()))
			c0 := r.newCombinerDist(before, 10*time.Second)
			r.combinerTakes(c0, k1.String(), k2.String())
			r.answered(t, d0)

			snd := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
			d1 := nextDistributionID()
			snd.TrackDnskeyPropagation(t.Context(), ZoneName(z), d1, []uint16{k2.KeyTag()}, []uint16{k2.KeyTag()}, []AgentId{us})

			// the set that overtakes the withdrawal, then the withdrawal
			d2 := nextDistributionID()
			newer := replace(k1.String(), k3.String())
			before = r.combinerDists()
			r.receivesAt(t, string(signer), d2, sent.Add(20*time.Second), nil, newer)
			c2 := r.newCombinerDist(before, 10*time.Second)
			if c2 == "" {
				t.Fatalf("the newer set did not go to the combiner\n%s", r.log)
			}
			waits := r.logCount(staleWaitLine)
			r.receivesAt(t, string(signer), d1, sent.Add(10*time.Second), nil, replace(k1.String()))
			r.waitLog(t, staleWaitLine, waits+1)

			var said []string // a PARTIAL names part of the set
			if word == transport.ConfirmPartial {
				said = []string{k1.String()}
			}
			r.us.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(c2, rigCombiner, word, r.mpzd.ZoneName,
				said, nil, nil, nil, false, "zone not found on this combiner"))
			var cf *ConfirmationDetail
			for end := time.Now().Add(10 * time.Second); time.Now().Before(end) && cf == nil; {
				got, ok := recvWithin(r.peer.MsgQs.Confirmation, time.Until(end))
				if !ok {
					break
				}
				if got.DistributionID == d1 && got.Status != "PENDING" {
					cf = got
				}
			}
			if cf == nil {
				t.Fatalf("no final word on the withdrawal after the combiner's %s\n%s", word, r.log)
			}
			if cf.Status == "SUCCESS" || cf.Status == "ok" || len(cf.RemovedRecords) > 0 ||
				slices.ContainsFunc(cf.AppliedRecords, func(rec string) bool { return !slices.Contains(said, rec) }) {
				t.Fatalf("after the combiner's %s the sender got %+v, naming keys it did not", word, *cf)
			}
			if word == transport.ConfirmIgnored && cf.Status != "IGNORED" {
				t.Errorf("after the combiner's IGNORED the sender got %+v, want IGNORED", *cf)
			}
			if word != transport.ConfirmIgnored {
				snd.ProcessDnskeyConfirmation(d1, cf.Source, cf.Status, cf.AppliedRecords, nil)
				snd.dnskeyPropMu.Lock()
				_, waiting := snd.pendingDnskeyPropagations[d1]
				snd.dnskeyPropMu.Unlock()
				if !waiting {
					t.Errorf("the withdrawal was credited though the combiner did not confirm the set (%+v)", *cf)
				}
			}
			if word == transport.ConfirmFailed {
				// the set the combiner failed goes to it again when it comes again
				before = r.combinerDists()
				r.receivesAt(t, string(signer), d2, sent.Add(20*time.Second), nil, newer)
				if r.newCombinerDist(before, 10*time.Second) == "" {
					t.Errorf("the set the combiner failed was not handed over again\n%s", r.log)
				}
			}
		})
	}
}

// A stale withdrawal arrives while an answer's forward of the set, which
// drops the key, waits for the combiner. Its keys were accepted before, so
// the forward marks none of them pending. The withdrawal names no key and is
// PARTIAL; the sender credits the removal from the asker's confirmation of
// the answer, once the combiner has the set.
func TestAStaleWithdrawalBehindAnAnswersForwardIsNotCredited(t *testing.T) {
	r := receivingRig(t, "answer.withdrawal.overtaken.example.")
	z := r.mpzd.ZoneName
	leader, us := AgentId(r.peer.Identity), AgentId(r.us.Identity)
	r.leader(leader)
	k1, k2 := testDnskey(t, z, 257), testDnskey(t, z, 256)
	both := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{k1.String(), k2.String()}}
	one := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{k1.String()}}

	sent := time.Now().Add(-time.Minute)
	d0 := nextDistributionID()
	before := r.combinerDists()
	r.receivesAt(t, string(leader), d0, sent, nil, both)
	c0 := r.newCombinerDist(before, 10*time.Second)
	r.combinerTakes(c0, k1.String(), k2.String())
	r.answered(t, d0)

	lead := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	d, an := nextDistributionID(), nextDistributionID()
	lead.TrackDnskeyPropagation(t.Context(), ZoneName(z), d, []uint16{k2.KeyTag()}, []uint16{k2.KeyTag()}, []AgentId{us})
	lead.noteCatchUpAnswer(an, ZoneName(z), us, map[uint16]bool{k1.KeyTag(): true})
	waiting := func() bool {
		lead.dnskeyPropMu.Lock()
		defer lead.dnskeyPropMu.Unlock()
		_, ok := lead.pendingDnskeyPropagations[d]
		return ok
	}

	yes := true
	before = r.combinerDists()
	r.receivesAt(t, string(leader), an, sent.Add(30*time.Second), &CatchUp{Request: "r1", Complete: &yes}, one)
	ca := r.newCombinerDist(before, 10*time.Second)
	if ca == "" {
		t.Fatalf("the answer was not forwarded\n%s", r.log)
	}
	r.receivesAt(t, string(leader), d, sent.Add(10*time.Second), nil, one)
	c := r.answered(t, d)
	if c.Status != "PARTIAL" || len(c.AppliedRecords) > 0 || len(c.RemovedRecords) > 0 {
		t.Fatalf("the stale withdrawal got %+v, want PARTIAL naming no key", *c)
	}
	lead.ProcessDnskeyConfirmation(d, c.Source, c.Status, c.AppliedRecords, nil)
	if !waiting() {
		t.Fatal("the withdrawal was credited before the combiner had the answer's set")
	}

	r.combinerTakes(ca, k1.String())
	cf := r.answered(t, an)
	lead.ProcessDnskeyConfirmation(an, cf.Source, cf.Status, cf.AppliedRecords, nil)
	if waiting() {
		t.Errorf("after the asker confirmed the answer, the withdrawal still waits (%+v)", *cf)
	}
}

// Only a success from the combiner says it holds a set. After a PARTIAL or an
// IGNORED, the key lifecycle's resend of the same set, a new distribution that
// matches the repo, goes to the combiner again: confirmed "ok" from the repo,
// it would cover every key, though the combiner applied part of the set or
// none of it (the reviewer's first case).
func TestAResendAfterTheCombinersPartialWordGoesToItAgain(t *testing.T) {
	for _, word := range []transport.ConfirmStatus{transport.ConfirmPartial, transport.ConfirmIgnored} {
		t.Run(word.String(), func(t *testing.T) {
			r := receivingRig(t, strings.ToLower(word.String())+".resend.combiner.example.")
			z := r.mpzd.ZoneName
			signer := AgentId(r.peer.Identity)
			k1, k2 := testDnskey(t, z, 256), testDnskey(t, z, 256)
			set := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{k1.String(), k2.String()}}
			sent := time.Now().Add(-time.Minute)

			d1 := nextDistributionID()
			before := r.combinerDists()
			r.receivesAt(t, string(signer), d1, sent, nil, set)
			c1 := r.newCombinerDist(before, 10*time.Second)
			if c1 == "" {
				t.Fatalf("the set did not go to the combiner\n%s", r.log)
			}
			var said []string
			if word == transport.ConfirmPartial {
				said = []string{k1.String()}
			}
			r.us.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(c1, rigCombiner, word, r.mpzd.ZoneName,
				said, nil, nil, nil, false, ""))
			if cf := r.answered(t, d1); cf.Status == "SUCCESS" || cf.Status == "ok" {
				t.Fatalf("the combiner's %s was relayed as %+v", word, *cf)
			}

			// the key lifecycle sends the same set again, a new distribution
			d2 := nextDistributionID()
			before = r.combinerDists()
			r.receivesAt(t, string(signer), d2, sent.Add(time.Minute), nil, set)
			if r.newCombinerDist(before, 10*time.Second) == "" {
				t.Fatalf("after the combiner's %s the resend was not handed over again\n%s", word, r.log)
			}
			for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); {
				cf, ok := recvWithin(r.peer.MsgQs.Confirmation, time.Until(end))
				if !ok {
					break
				}
				if cf.DistributionID == d2 && (cf.Status == "SUCCESS" || cf.Status == "ok") {
					t.Fatalf("after the combiner's %s the resend was confirmed %+v from the repo", word, *cf)
				}
			}
		})
	}
}

// A stale distribution added a key that the newer set, now held, dropped.
// Its confirmation names only the keys that are held and is PARTIAL: a
// success would tell the sender the dropped key is published here. Released
// after the combiner's word on the newer set, and arriving after it alike
// (the reviewer's second case).
func TestAStaleSetWhoseKeyTheNewerSetDroppedIsNotASuccess(t *testing.T) {
	for _, order := range []string{"released", "after the word"} {
		t.Run(order, func(t *testing.T) {
			r := receivingRig(t, map[string]string{"released": "released", "after the word": "late"}[order]+".dropped.overtaken.example.")
			z := r.mpzd.ZoneName
			signer, us := AgentId(r.peer.Identity), AgentId(r.us.Identity)
			k1, k2, k3 := testDnskey(t, z, 256), testDnskey(t, z, 256), testDnskey(t, z, 256)
			replace := func(records ...string) core.RROperation {
				return core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: records}
			}
			sent := time.Now().Add(-time.Minute)
			d0 := nextDistributionID()
			before := r.combinerDists()
			r.receivesAt(t, string(signer), d0, sent, nil, replace(k1.String()))
			c0 := r.newCombinerDist(before, 10*time.Second)
			r.combinerTakes(c0, k1.String())
			r.answered(t, d0)

			snd := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
			d1 := nextDistributionID()
			snd.TrackDnskeyPropagation(t.Context(), ZoneName(z), d1, []uint16{k2.KeyTag()}, nil, []AgentId{us})

			// the newer set, which drops k2 (and adds k3)
			before = r.combinerDists()
			r.receivesAt(t, string(signer), nextDistributionID(), sent.Add(20*time.Second), nil, replace(k1.String(), k3.String()))
			c2 := r.newCombinerDist(before, 10*time.Second)
			if c2 == "" {
				t.Fatalf("the newer set did not go to the combiner\n%s", r.log)
			}
			if order == "after the word" {
				r.combinerTakes(c2, k1.String(), k3.String())
			}
			// the stale distribution, which added k2
			waits := r.logCount(staleWaitLine)
			r.receivesAt(t, string(signer), d1, sent.Add(10*time.Second), nil, replace(k1.String(), k2.String()))
			if order == "released" {
				r.waitLog(t, staleWaitLine, waits+1)
				r.combinerTakes(c2, k1.String(), k3.String())
			}
			var cf *ConfirmationDetail
			for end := time.Now().Add(10 * time.Second); time.Now().Before(end) && cf == nil; {
				got, ok := recvWithin(r.peer.MsgQs.Confirmation, time.Until(end))
				if !ok {
					break
				}
				if got.DistributionID == d1 && got.Status != "PENDING" {
					cf = got
				}
			}
			if cf == nil {
				t.Fatalf("no final word on the stale distribution\n%s", r.log)
			}
			if cf.Status == "SUCCESS" || cf.Status == "ok" || slices.Contains(cf.AppliedRecords, k2.String()) {
				t.Fatalf("the stale distribution got %+v: a word that k2 is published here", *cf)
			}
			snd.ProcessDnskeyConfirmation(d1, cf.Source, cf.Status, cf.AppliedRecords, nil)
			snd.dnskeyPropMu.Lock()
			_, waiting := snd.pendingDnskeyPropagations[d1]
			snd.dnskeyPropMu.Unlock()
			if !waiting {
				t.Errorf("k2's propagation ended though the combiner holds a set without it (%+v)", *cf)
			}
		})
	}
}

// The combiner answers a hand-over late, after the set that overtook it: a
// newer set dropped the key the handed-over one added while the combiner was
// away. Its success, which names nothing (a no-op to it), is relayed as
// PARTIAL with the keys the repo holds, so the sender does not take the
// dropped key as published here. The same with the sender's resend of the
// older set waiting as a stale replace meanwhile, which is how an end-to-end
// run met it (heldSuccess on the relay).
func TestALateCombinerSuccessOnASetWhoseKeyWasDroppedIsNotASuccess(t *testing.T) {
	for _, resend := range []bool{false, true} {
		name := map[bool]string{false: "no resend", true: "a resend waits"}[resend]
		t.Run(name, func(t *testing.T) {
			r := receivingRig(t, map[bool]string{false: "plain", true: "resend"}[resend]+".late.dropped.example.")
			z := r.mpzd.ZoneName
			signer, us := AgentId(r.peer.Identity), AgentId(r.us.Identity)
			k1, k2, k3 := testDnskey(t, z, 256), testDnskey(t, z, 256), testDnskey(t, z, 256)
			replace := func(records ...string) core.RROperation {
				return core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: records}
			}
			sent := time.Now().Add(-time.Minute)
			d0 := nextDistributionID()
			before := r.combinerDists()
			r.receivesAt(t, string(signer), d0, sent, nil, replace(k1.String()))
			c0 := r.newCombinerDist(before, 10*time.Second)
			r.combinerTakes(c0, k1.String())
			r.answered(t, d0)

			snd := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
			// the set that adds k2, handed over; the combiner is away
			d1 := nextDistributionID()
			snd.TrackDnskeyPropagation(t.Context(), ZoneName(z), d1, []uint16{k2.KeyTag()}, nil, []AgentId{us})
			before = r.combinerDists()
			r.receivesAt(t, string(signer), d1, sent.Add(10*time.Second), nil, replace(k1.String(), k2.String()))
			c1 := r.newCombinerDist(before, 10*time.Second)
			// the newer set, which drops k2 and adds k3, handed over too
			before = r.combinerDists()
			r.receivesAt(t, string(signer), nextDistributionID(), sent.Add(20*time.Second), nil, replace(k1.String(), k3.String()))
			c2 := r.newCombinerDist(before, 10*time.Second)
			if c1 == "" || c2 == "" {
				t.Fatalf("the sets did not go to the combiner (%q, %q)\n%s", c1, c2, r.log)
			}
			if resend {
				waits := r.logCount(staleWaitLine)
				r.receivesAt(t, string(signer), d1, sent.Add(10*time.Second), nil, replace(k1.String(), k2.String()))
				r.waitLog(t, staleWaitLine, waits+1)
			}
			// the combiner is back: the newer set, then the older hand-over,
			// which changes nothing for it
			r.combinerTakes(c2, k1.String(), k3.String())
			r.combinerTakes(c1)

			var words []*ConfirmationDetail
			for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
				got, ok := recvWithin(r.peer.MsgQs.Confirmation, time.Until(end))
				if !ok {
					break
				}
				if got.DistributionID == d1 && got.Status != "PENDING" {
					words = append(words, got)
					snd.ProcessDnskeyConfirmation(d1, got.Source, got.Status, got.AppliedRecords, nil)
				}
			}
			if len(words) == 0 {
				t.Fatalf("no final word on the older set\n%s", r.log)
			}
			for _, cf := range words {
				if cf.Status == "SUCCESS" || cf.Status == "ok" || slices.Contains(cf.AppliedRecords, k2.String()) {
					t.Errorf("the older set got %+v: a word that k2 is published here", *cf)
				}
			}
			snd.dnskeyPropMu.Lock()
			_, waiting := snd.pendingDnskeyPropagations[d1]
			snd.dnskeyPropMu.Unlock()
			if !waiting {
				t.Error("k2's propagation ended though the combiner holds a set without it")
			}
		})
	}
}
