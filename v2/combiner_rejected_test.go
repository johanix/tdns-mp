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
	snd.TrackDnskeyPropagation(ZoneName(z), d2, []uint16{kt}, nil, []AgentId{us})
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
	r.us.Bridge.ChunkHandler.OnConfirmationReceived(distID, rigCombiner, transport.ConfirmSuccess, r.mpzd.ZoneName,
		records, nil, nil, nil, false, "")
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
			snd.TrackDnskeyPropagation(ZoneName(z), d1, []uint16{k2.KeyTag()}, []uint16{k2.KeyTag()}, []AgentId{us})
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
		r.us.Bridge.ChunkHandler.OnConfirmationReceived(c, rigCombiner, transport.ConfirmIgnored, r.mpzd.ZoneName,
			nil, nil, nil, nil, false, "")
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
