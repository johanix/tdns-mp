/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The runner for a change of parentsync (plan S20), on the reconciliation's
// rig: agent a leads a zone that a and b serve, thawed from 41 to 42, which
// differ in parentsync. The parent is played by rollTestParent.

type parentSyncRig struct {
	*reconcileRig
	mpzd   *MPZoneData
	parent *rollTestParent
	key    sig0Row
}

const (
	psStep1 = "parent sync to the owner: step 1 (the CDS and CSYNC withdrawn)"
	psStep2 = "parent sync to the owner: step 2 (their TTL)"
	psStep3 = "parent sync to the owner: step 3 (the agents' key deleted at the parent)"
	psStep4 = "parent sync to the owner: step 4 (every agent stops syncing)"
)

// newParentSyncRig: the zone's parentsync goes from from to to. The leader
// holds the zone's key, which the zone publishes and the parent trusts.
func newParentSyncRig(t *testing.T, zone, from, to string) *parentSyncRig {
	t.Helper()
	r := &parentSyncRig{reconcileRig: newReconcileRig(t, zone, roleA)}
	at := func(serial uint32, suffix, parentsync string) *Instructions {
		return jAt(t, serial, fmt.Sprintf(`servers="a,b" nsmgmt="agent" parentsync="%s" suffix="%s"`, parentsync, suffix), freezeRecords...)
	}
	r.n, r.v = at(41, "n", from), at(42, "v", to)
	knownAs(t, r.store, zone, r.n)
	r.mpzd, _ = Zones.Get(zone)
	r.mpzd.KeyDB = r.hdb.KeyDB
	r.mpzd.SetRuntimeOption(tdns.OptParentSync, from == "agent")
	r.key = testSig0Key(t, r.mpzd.KeyDB, zone)
	trustKey(r.mpzd.KeyDB, zone, r.key.keyid)
	r.parent = newRollTestParent(r.key.keyid)
	r.conf.InternalMp.rollParent = r.parent
	t.Cleanup(r.conf.InternalMp.parentSyncs.wait)
	r.serve(dns.TypeKEY, r.key.key)
	return r
}

// serve puts these records at the apex of the agent's copy of the zone.
func (r *parentSyncRig) serve(rrtype uint16, rrs ...dns.RR) {
	zd := r.mpzd.ZoneData
	apex, ok := zd.Data.Get(zd.ZoneName)
	if !ok {
		r.t.Fatal("the zone has no apex")
	}
	apex.RRtypes.Set(rrtype, core.RRset{RRs: rrs})
	zd.Data.Set(zd.ZoneName, apex)
	zd.InstallInitialSnapshot()
}

// next has every member hold the step this agent holds, and takes a turn.
func (r *parentSyncRig) next() {
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
}

// toStep goes on until the step held says what.
func (r *parentSyncRig) toStep(what string) {
	r.t.Helper()
	for range 12 {
		r.conf.InternalMp.parentSyncs.wait()
		if st, _ := r.step(); st.What == what {
			return
		}
		r.next()
	}
	st, _ := r.step()
	r.t.Fatalf("the zone did not come to %q: it holds %q (%s)", what, st.What, r.conf.reconcileLine(r.zone, time.Now()))
}

// passTTL has step 2's wait pass, as time passing would.
func (r *parentSyncRig) passTTL() {
	r.t.Helper()
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.StepAt = z.StepAt.Add(-24 * time.Hour)
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
}

// sets are what this agent hands its combiner now.
func (r *parentSyncRig) sets() Roles {
	r.t.Helper()
	w := r.wanted()
	if w == nil {
		r.t.Fatal("nothing handed to the combiner")
	}
	return w.Sets
}

// policy is the edit policy of a signer combiner that holds these sets.
func policyOf(r Roles) *editPolicy {
	return &editPolicy{ZoneSigned: true, WeAreSigner: true, ParentSync: r.ParentSync, NSmgmt: r.NSmgmt, CDSWithdrawn: r.CDSWithdrawn}
}

// The option follows the step's sets. A refresh of the owner's edit changes
// nothing, also after the thaw; the agents sync the zone until step 4.
func TestTheAgentsStopSyncingAtTheirStepAndNotAtTheRefresh(t *testing.T) {
	r := newParentSyncRig(t, "stops.parentsync.example.", "agent", "owner")
	r.agree()
	r.conf.onSetsChanged(r.mpzd, false) // the refresh that brought the edit
	if !r.mpzd.Options[tdns.OptParentSync] {
		t.Fatal("the refresh of the owner's edit turned the delegation sync off")
	}
	r.thawNow()
	r.conf.onSetsChanged(r.mpzd, false)
	if !r.mpzd.Options[tdns.OptParentSync] {
		t.Fatal("the thaw turned the delegation sync off")
	}
	for _, what := range []string{psStep1, psStep2, psStep3} {
		r.toStep(what)
		if !r.mpzd.Options[tdns.OptParentSync] {
			t.Fatalf("at %q the delegation sync is off", what)
		}
		if what == psStep2 {
			r.passTTL()
		}
	}
	r.toStep(psStep4)
	if r.mpzd.Options[tdns.OptParentSync] {
		t.Fatal("step 4 did not turn the delegation sync off")
	}
	if tdnsSaysAgents := rolesForZone(ZoneName(r.zone)).ParentSync == core.HsyncParentSyncAgent; tdnsSaysAgents {
		t.Error("the hook that tdns asks (P3) still says the agents sync the zone")
	}
}

// A member follows the leader's step: its option goes off at step 4, from the
// leader's stamp, and it asks the parent nothing.
func TestAMemberStopsSyncingAtTheLeadersStep(t *testing.T) {
	r := newParentSyncRig(t, "member.parentsync.example.", "agent", "owner")
	r.lead(roleB, time.Now().Add(time.Hour))
	r.agree()
	if err := r.store.Activate(r.zone, Thaw{From: sd(r.n), To: sd(r.v)}); err != nil {
		t.Fatal(err)
	}
	sets := rolesFor(r.n, r.n, 0)
	sets.CDSWithdrawn = true
	r.hear(roleB, r.leaderStep(3, sets, []string{parentSyncCDSKey, parentSyncTTLKey, parentSyncKeyKey}), true)
	r.turn(time.Now())
	if !r.mpzd.Options[tdns.OptParentSync] {
		t.Fatal("step 3 turned the delegation sync off")
	}
	sets.ParentSync = core.HsyncParentSyncOwner
	r.hear(roleB, r.leaderStep(4, sets, []string{parentSyncCDSKey, parentSyncTTLKey, parentSyncKeyKey, parentSyncStopKey}), true)
	r.turn(time.Now())
	if r.mpzd.Options[tdns.OptParentSync] {
		t.Error("the leader's step 4 did not turn the delegation sync off here")
	}
	if u := r.parent.updates(); len(u) != 0 {
		t.Errorf("a member sent the parent %+v", u)
	}
}

// Step 1: the combiners stop applying CDS and CSYNC, and the signers stop
// serving a CDS through their DS engine, while the KEY and the agents' sync
// stay; step 2 then waits their TTL, as they were served.
func TestParentsyncToOwnerWithdrawsCDSAndCSYNCFirst(t *testing.T) {
	r := newParentSyncRig(t, "cds.parentsync.example.", "agent", "owner")
	cds, err := dns.NewRR(r.zone + " 300 IN CDS 12345 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	r.serve(dns.TypeCDS, cds)
	r.agree()
	r.thawNow()
	before := r.sets()
	if before.CDSWithdrawn || !policyOf(before).canApply(dns.TypeCDS) || !policyOf(before).canApply(dns.TypeCSYNC) {
		t.Fatalf("at the thaw the CDS is withdrawn already: %+v", before)
	}
	r.toStep(psStep1)
	sets := r.sets()
	p := policyOf(sets)
	if !sets.CDSWithdrawn || sets.CDSTTL != 300 {
		t.Errorf("step 1 hands the combiner CDSWithdrawn=%v, TTL %d", sets.CDSWithdrawn, sets.CDSTTL)
	}
	if p.canApply(dns.TypeCDS) || p.canApply(dns.TypeCSYNC) {
		t.Error("a combiner handed step 1 still applies CDS or CSYNC")
	}
	if p.canSubmit(dns.TypeCDS) || p.canSubmit(dns.TypeCSYNC) {
		t.Error("an agent at step 1 still submits CDS or CSYNC")
	}
	if !p.canApply(dns.TypeKEY) {
		t.Error("a combiner handed step 1 no longer applies the agents' KEY")
	}
	if sets.ParentSync != core.HsyncParentSyncAgent {
		t.Errorf("step 1 hands parentsync %d: the sets change at step 4", sets.ParentSync)
	}

	// the other carrier: the signer's DS engine, by the owner's DS set
	w := r.wantedBy(r.signer)
	if w == nil || !w.Sets.CDSWithdrawn {
		t.Fatalf("step 1 is not handed to the signer: %+v", w)
	}
	owner := &MPKeyLifecycleOwner{}
	store := withActing(t, r.hdb)
	if _, _, err := store.take(w, roleA); err != nil {
		t.Fatalf("the signer's store takes the hand-over: %v", err)
	}
	in, err := owner.DSIntent(r.mpzd.ZoneData, dns.SHA256)
	if err != nil || !in.Known || len(in.Set) != 0 {
		t.Errorf("a signer handed step 1 gives the DS engine %+v, %v: want no CDS", in, err)
	}
	if !servesNoCDS(rolesFor(r.v, r.v, 0)) {
		t.Error("at rest under parentsync=owner a signer would serve a CDS again")
	}
	if servesNoCDS(before) {
		t.Error("a signer under parentsync=agent would serve no CDS")
	}

	// step 2: the TTL, from when the step was taken
	r.next()
	if st, _ := r.step(); st.What != psStep2 {
		t.Fatalf("after step 1 the step is %q", st.What)
	}
	r.next()
	if st, _ := r.step(); st.What != psStep2 {
		t.Fatalf("the TTL did not hold step 2: %q", st.What)
	}
	if line := r.conf.reconcileLine(r.zone, time.Now()); !strings.Contains(line, "the TTL of the CDS and CSYNC, until") {
		t.Errorf("the status during the TTL: %q", line)
	}
	if u := r.parent.updates(); len(u) != 0 {
		t.Errorf("the parent heard %+v before the TTL passed", u)
	}
	r.passTTL()
	r.next()
	if st, _ := r.step(); st.What != psStep3 {
		t.Errorf("the TTL passed, and the step is %q", st.What)
	}
}

// Step 1 is a DS step: it waits for an emergency rollover.
func TestTheCDSStepWaitsForAnEmergencyRollover(t *testing.T) {
	logs := captureLog(t)
	r := newParentSyncRig(t, "rollover.parentsync.example.", "agent", "owner")
	r.agree()
	r.thawNow()
	r.partsTake()
	st := r.own()
	st.StepHeld, st.Rollover = true, true
	r.hear(roleB, st, true)
	r.turn(time.Now())
	if st, _ := r.step(); st.What == psStep1 {
		t.Fatal("step 1 did not wait for the emergency rollover")
	}
	if s := r.sets(); s.CDSWithdrawn {
		t.Error("the CDS was withdrawn during the emergency rollover")
	}
	if !strings.Contains(logs.String(), `msg="a DS or DNSKEY step waits for an emergency rollover"`) {
		t.Errorf("no log line: %s", logs)
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "the next step waits for an emergency rollover at "+roleB) {
		t.Errorf("the status: %q", line)
	}
	r.next()
	if st, _ := r.step(); st.What != psStep1 {
		t.Errorf("the rollover ended, and the step is %q", st.What)
	}
}

// Step 3: an update the key itself signs deletes it, once. A failure, and a
// parent that takes NOTIFY only, tell the owner, and the step goes on. A key
// the parent does not trust any more is not asked of it.
func TestParentsyncToOwnerDeletesTheAgentsKeyAtTheParent(t *testing.T) {
	t.Run("by an update the key signs", func(t *testing.T) {
		logs := captureLog(t)
		r := newParentSyncRig(t, "delete.parentsync.example.", "agent", "owner")
		r.agree()
		r.thawNow()
		r.toStep(psStep2)
		r.passTTL()
		r.toStep(psStep3)
		if u := r.parent.updates(); len(u) != 0 {
			t.Fatalf("the parent got %+v before every member held step 3", u)
		}
		r.toStep(psStep4)
		u := r.parent.updates()
		if len(u) != 1 || u[0].what != "delete" || u[0].keyid != r.key.keyid || u[0].signer != r.key.keyid || u[0].rcode != dns.RcodeSuccess {
			t.Fatalf("the updates: %+v, want one delete of %d signed by itself", u, r.key.keyid)
		}
		if trusts := r.parent.trusts(); len(trusts) != 0 {
			t.Errorf("the parent still trusts %v", trusts)
		}
		k := sig0RowByID(r.mpzd.KeyDB, ZoneName(r.zone), tdns.Sig0StateActive, r.key.keyid)
		if k == nil || k.parentState == edns0.KeyStateTrusted {
			t.Errorf("after the delete the key's row says %+v", k)
		}
		if line := r.conf.InternalMp.parentSyncs.ownerTold(r.zone); line != "" {
			t.Errorf("the owner was told: %q", line)
		}
		if !strings.Contains(logs.String(), `msg="the agents' SIG(0) key is deleted at the parent"`) {
			t.Errorf("no log line: %s", logs)
		}
		if held, _ := r.conf.offerHeld(context.Background(), ZoneName(r.zone)); !held {
			t.Error("the key is offered again after its delete")
		}
		r.conf.agentsKeyWait(r.zone)
		r.conf.InternalMp.parentSyncs.wait()
		if len(r.parent.updates()) != 1 {
			t.Errorf("the delete was sent again: %+v", r.parent.updates())
		}
	})

	t.Run("a failure tells the owner", func(t *testing.T) {
		r := newParentSyncRig(t, "refused.parentsync.example.", "agent", "owner")
		r.parent.refuse["delete"] = dns.RcodeRefused
		r.agree()
		r.thawNow()
		r.toStep(psStep2)
		r.passTTL()
		r.toStep(psStep4) // it goes on
		line := r.conf.InternalMp.parentSyncs.ownerTold(r.zone)
		if !strings.Contains(line, "the zone's owner has to delete it") || !strings.Contains(line, fmt.Sprint(r.key.keyid)) {
			t.Errorf("the owner is told: %q", line)
		}
		if got := r.conf.zoneKeyLine(context.Background(), ZoneName(r.zone)); got != line {
			t.Errorf("the status says %q, want %q", got, line)
		}
	})

	t.Run("a parent that takes NOTIFY only", func(t *testing.T) {
		r := newKeyRoundRig(t, "notify.parentsync.example.", "NOTIFY")
		k := testSig0Key(t, r.mpzd.KeyDB, string(r.zone))
		r.publish(t, k)
		p := newRollTestParent(k.keyid)
		r.conf.InternalMp.rollParent = p
		r.conf.deleteAgentsKey(r.ctx, r.zone)
		if u := p.updates(); len(u) != 0 {
			t.Errorf("the parent got %+v", u)
		}
		if line := r.conf.InternalMp.parentSyncs.ownerTold(string(r.zone)); !strings.Contains(line, "the zone's owner has to delete it") {
			t.Errorf("the owner is told: %q", line)
		}
	})

	t.Run("a key the parent no longer trusts", func(t *testing.T) {
		r := newRollRig(t, "gone.parentsync.example.")
		delete(r.parent.trusted, r.old.keyid)
		r.conf.deleteAgentsKey(r.ctx, r.zone)
		if u := r.parent.updates(); len(u) != 0 {
			t.Errorf("the parent got %+v", u)
		}
		if line := r.conf.InternalMp.parentSyncs.ownerTold(string(r.zone)); line != "" {
			t.Errorf("the owner is told: %q", line)
		}
	})

	t.Run("a roll under way ends, and both its keys go", func(t *testing.T) {
		r := newRollRig(t, "roll.parentsync.example.")
		newKeyid := r.start(t)
		r.pass(t, syncOther)
		ro := r.roll(t)
		if ro == nil || ro.phase != rollPublished {
			t.Fatalf("the roll: %+v", ro)
		}
		r.conf.deleteAgentsKey(r.ctx, r.zone)
		if ro := r.roll(t); ro != nil {
			t.Errorf("the roll goes on: %+v", ro)
		}
		if trusts := r.parent.trusts(); len(trusts) != 0 {
			t.Errorf("the parent still trusts %v (old %d, new %d)", trusts, r.old.keyid, newKeyid)
		}
	})
}

// The KEY stays until the key is deleted at the parent: a combiner applies it
// through steps 1 to 3, and stops at step 4.
func TestTheKEYStaysUntilTheKeyIsDeletedAtTheParent(t *testing.T) {
	r := newParentSyncRig(t, "key.parentsync.example.", "agent", "owner")
	r.agree()
	r.thawNow()
	for _, what := range []string{psStep1, psStep2, psStep3} {
		r.toStep(what)
		if what == psStep2 {
			r.passTTL()
		}
		if !policyOf(r.sets()).canApply(dns.TypeKEY) {
			t.Fatalf("at %q a combiner no longer applies the agents' KEY", what)
		}
		if !policyOf(r.sets()).canSubmit(dns.TypeKEY) {
			t.Fatalf("at %q an agent no longer submits its KEY", what)
		}
	}
	if trusts := r.parent.trusts(); len(trusts) != 1 {
		t.Fatalf("the parent trusts %v before the step is held", trusts)
	}
	r.toStep(psStep4)
	if trusts := r.parent.trusts(); len(trusts) != 0 {
		t.Fatalf("step 4 came with the key at the parent: %v", trusts)
	}
	if policyOf(r.sets()).canApply(dns.TypeKEY) {
		t.Error("at step 4 a combiner still applies the agents' KEY")
	}
}

// "Done" waits until the leader has nothing in flight.
func TestParentsyncToOwnerIsDoneOnlyWhenNothingIsInFlight(t *testing.T) {
	r := newParentSyncRig(t, "inflight.parentsync.example.", "agent", "owner")
	r.agree()
	r.thawNow()
	_, done := r.conf.delegationSyncRun(context.Background(), r.zone) // cancelled at step 4, not returned yet
	defer done()
	r.toStep(psStep2)
	r.passTTL()
	r.toStep(psStep4)
	r.next()
	if st, _ := r.step(); st.What != psStep4 {
		t.Fatalf("a sync in flight, and the step is %q", st.What)
	}
	if line := r.conf.reconcileLine(r.zone, time.Now()); !strings.Contains(line, "a sync in flight") {
		t.Errorf("the status: %q", line)
	}
	done()
	r.next()
	r.next()
	if r.conf.reconcileLine(r.zone, time.Now()) != "" {
		t.Errorf("nothing in flight, and the zone reconciles: %q", r.conf.reconcileLine(r.zone, time.Now()))
	}
	if !policyOf(rolesForZone(ZoneName(r.zone))).canApply(dns.TypeA) || policyOf(rolesForZone(ZoneName(r.zone))).canApply(dns.TypeCDS) {
		t.Error("at rest the edit policy is not the owner's")
	}
}

// Step 4 ends the agent's work towards the parent: the zone's parent context,
// the chain and its held NOTIFY, and the owed sync, which "done" does not ask
// for again.
func TestParentsyncToOwnerDropsTheOwedSyncAndTheParentContext(t *testing.T) {
	r := newParentSyncRig(t, "owed.parentsync.example.", "agent", "owner")
	zone := ZoneName(r.zone)
	tr := newCatchUpTracker(AgentId(roleA), []string{r.zone}, time.Hour)
	r.conf.InternalMp.CatchUp = tr
	r.agree()
	r.thawNow()
	r.toStep(psStep2)
	r.passTTL()
	r.toStep(psStep3)

	// what the zone has at the parent as step 4 comes
	run, done := r.conf.delegationSyncRun(context.Background(), r.zone)
	defer done()
	c := &r.conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	if c.zones == nil {
		c.zones = map[string]*delegationSyncChain{}
	}
	c.zones[r.zone] = &delegationSyncChain{hold: &delegationNotifyHold{}}
	c.mu.Unlock()
	if held, _ := r.conf.syncHeld(r.zone, syncOther); !held {
		t.Fatal("a sync passes the freeze")
	}

	r.toStep(psStep4)
	if run.Err() == nil {
		t.Error("the zone's parent context was not cancelled at step 4")
	}
	c.mu.Lock()
	chained := c.zones[r.zone] != nil
	c.mu.Unlock()
	if chained {
		t.Error("the chain and its held NOTIFY were not ended at step 4")
	}
	if tr.releaseFreezeOwed(zone) {
		t.Error("the owed sync was not dropped at step 4")
	}
	if r.conf.requestDelegationSync(context.Background(), r.zone, "the transition is done") {
		t.Error("the agent still asks a sync of a zone whose owner syncs it")
	}
	r.next() // every member holds it: only the run, cancelled and not returned, holds it now
	if line := r.conf.reconcileLine(r.zone, time.Now()); !strings.Contains(line, "a sync in flight") {
		t.Errorf("the status at step 4: %q", line)
	}
}

// The take-up is the transition's first step: every agent turns the option on
// at it, not at the thaw; the leader, and only the leader, takes the zone up
// as at an arrival, once every member holds the step, and once.
func TestParentsyncToAgentTakesTheZoneUpAtTheFirstStep(t *testing.T) {
	const takeUp = "parent sync to the agents: the zone taken up"
	setUp := func(t *testing.T, zone string) (*parentSyncRig, chan ZoneName) {
		r := newParentSyncRig(t, zone, "owner", "agent")
		joined := make(chan ZoneName, 4)
		r.lem.SetOnZoneJoined(func(z ZoneName) error {
			joined <- z
			return nil
		})
		return r, joined
	}

	t.Run("the leader", func(t *testing.T) {
		logs := captureLog(t)
		r, joined := setUp(t, "leader.takeup.example.")
		r.agree()
		r.conf.onSetsChanged(r.mpzd, false)
		r.thawNow()
		r.conf.onSetsChanged(r.mpzd, false)
		if r.mpzd.Options[tdns.OptParentSync] {
			t.Fatal("the delegation sync came on before the step")
		}
		r.next()
		st, _ := r.step()
		if st.What != takeUp || st.Number != 1 {
			t.Fatalf("the first step is %d %q", st.Number, st.What)
		}
		if !r.mpzd.Options[tdns.OptParentSync] {
			t.Error("the first step did not turn the delegation sync on")
		}
		if !strings.Contains(logs.String(), `msg="parent sync taken up by the agents"`) {
			t.Errorf("no log line: %s", logs)
		}
		if len(joined) != 0 {
			t.Fatal("the zone was taken up before every member held the step")
		}
		r.next()
		r.conf.InternalMp.parentSyncs.wait()
		if z, ok := recvWithin(joined, 5*time.Second); !ok || z != ZoneName(r.zone) {
			t.Fatalf("the zone was not taken up: %v", z)
		}
		r.next()
		r.conf.InternalMp.parentSyncs.wait()
		if len(joined) != 0 {
			t.Error("the zone was taken up twice")
		}
		if !r.conf.parentSyncTakenUp(r.zone) {
			t.Error("the step's own work is not told from the freeze")
		}
		if held, why := r.conf.syncHeld(r.zone, r.conf.syncCauseFor(r.zone, tdns.DelegationSyncStatus{})); held {
			t.Errorf("the take-up's sync is held: %s", why)
		}
		if why := r.conf.frozenForNotify(r.zone); len(why) != 0 {
			t.Errorf("the take-up's NOTIFY is held: %v", why)
		}
	})

	t.Run("a member", func(t *testing.T) {
		r, joined := setUp(t, "member.takeup.example.")
		r.lead(roleB, time.Now().Add(time.Hour))
		r.agree()
		if err := r.store.Activate(r.zone, Thaw{From: sd(r.n), To: sd(r.v)}); err != nil {
			t.Fatal(err)
		}
		sets := rolesFor(r.n, r.n, 0)
		sets.ParentSync = core.HsyncParentSyncAgent
		r.hear(roleB, r.leaderStep(1, sets, []string{parentSyncTakeUpKey}), true)
		r.turn(time.Now())
		if !r.mpzd.Options[tdns.OptParentSync] {
			t.Error("the leader's step did not turn the delegation sync on here")
		}
		r.conf.InternalMp.parentSyncs.wait()
		if len(joined) != 0 {
			t.Error("a member took the zone up")
		}
	})

	t.Run("before anything else, and after a hand-over last", func(t *testing.T) {
		defer withRunners(append(slices.Clone(stepRunners),
			stepRunner{name: "add", kind: stepAddition, steps: func(planView) []plannedStep { return []plannedStep{{key: "add", what: "add"}} }},
			stepRunner{name: "remove", kind: stepRemoval, steps: func(planView) []plannedStep { return []plannedStep{{key: "remove", what: "remove"}} }})...)()
		agent := Roles{ParentSync: core.HsyncParentSyncAgent}
		owner := Roles{ParentSync: core.HsyncParentSyncOwner}
		keys := func(p planView) []string {
			var out []string
			for _, st := range planSteps(p) {
				out = append(out, st.key)
			}
			return out
		}
		up := keys(planView{to: &Instructions{ParentSync: core.HsyncParentSyncAgent}, held: owner})
		if want := []string{parentSyncTakeUpKey, "add", "remove", lastStepKey}; !slices.Equal(up, want) {
			t.Errorf("a take-up with an addition and a removal: %v, want %v", up, want)
		}
		over := keys(planView{to: &Instructions{ParentSync: core.HsyncParentSyncOwner}, held: agent})
		if want := []string{"add", "remove", parentSyncCDSKey, parentSyncTTLKey, parentSyncKeyKey, parentSyncStopKey, lastStepKey}; !slices.Equal(over, want) {
			t.Errorf("a hand-over with an addition and a removal: %v, want %v", over, want)
		}
		// a new leader plans the same from what is in place: the sets say owner
		// by then, the steps taken say it was a hand-over
		again := keys(planView{to: &Instructions{ParentSync: core.HsyncParentSyncOwner}, held: owner,
			taken: []string{"add", "remove", parentSyncCDSKey, parentSyncTTLKey, parentSyncKeyKey, parentSyncStopKey}})
		if !slices.Equal(again, over) {
			t.Errorf("a new leader's plan: %v, want %v", again, over)
		}
		if none := keys(planView{to: &Instructions{ParentSync: core.HsyncParentSyncOwner}, held: owner}); !slices.Equal(none, []string{"add", "remove", lastStepKey}) {
			t.Errorf("no change of parentsync: %v", none)
		}
	})
}

// takeUpRig is the roll's rig, whose keyPoll stands in for tdns's, at the
// take-up's step of a transition: the zone publishes no KEY yet.
func takeUpRig(t *testing.T, zone string) *rollRig {
	t.Helper()
	r := newRollRig(t, zone)
	r.publish(t)
	tdns.UpdateParentState(r.mpzd.KeyDB, string(r.zone), r.old.keyid, edns0.KeyStateUnknown)
	delete(r.parent.trusted, r.old.keyid)
	freezeServed(t, r.conf, r.mpzd)
	if err := r.conf.InternalMp.Instructions.update(r.mpzd.ZoneName, func(z *zoneSerials) error {
		z.Taken = []string{parentSyncTakeUpKey}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.conf.InternalMp.parentSyncs.wait)
	return r
}

// Every nameserver serves the KEY before it is offered: the poll, which
// bootstraps the key at the parent, runs only after every recipient of the
// take-up's KEY has confirmed it, whoever asks for it, and once for the step.
func TestTheTakeUpsKEYIsOfferedOnlyAfterEveryMemberConfirmedIt(t *testing.T) {
	r := takeUpRig(t, "offered.takeup.example.")
	zone := string(r.zone)
	r.lem.SetOnZoneJoined(func(z ZoneName) error {
		return r.conf.leaderKeySetup(r.ctx, z, false)
	})
	if w := r.conf.takeUpWait(zone); w != "the zone's KEY to be published" {
		t.Fatalf("the step waits for %q", w)
	}
	waitUntil(t, "the KEY is not booked", func() bool {
		_, ok := r.conf.InternalMp.MPTransport.rollKEYs.state(r.zone)
		return ok
	})
	r.conf.InternalMp.parentSyncs.wait()
	w := r.conf.takeUpWait(zone)
	if !strings.HasPrefix(w, "the zone's KEY confirmed by ") {
		t.Fatalf("published, and the step waits for %q", w)
	}
	// as the key rounds offer it
	r.conf.launchKeyPoll(r.ctx, nil, r.zone, zone, r.old.keyid, r.old.key.Algorithm)
	r.conf.InternalMp.keyPolls.goroutines.Wait()
	if len(r.polls) != 0 {
		t.Fatalf("the key was offered before the KEY was confirmed: %d polls", len(r.polls))
	}
	r.confirmAll(t)
	if w := r.conf.takeUpWait(zone); w != "" {
		t.Fatalf("every recipient has confirmed, and the step waits for %q", w)
	}
	if keyid := r.polled(t, "after the KEY's confirmations"); keyid != r.old.keyid {
		t.Errorf("the poll is of key %d, want %d", keyid, r.old.keyid)
	}
	if w := r.conf.takeUpWait(zone); w != "" {
		t.Errorf("the step waits again for %q", w)
	}
	r.conf.InternalMp.keyPolls.goroutines.Wait()
	if len(r.polls) != 0 {
		t.Error("the key was offered twice")
	}
}

// A recipient that refuses the KEY has it sent again; one that keeps it and
// does not apply it by its role (IGNORED) has taken it.
func TestATakeUpsRefusedKEYIsPublishedAgain(t *testing.T) {
	r := takeUpRig(t, "refused.takeup.example.")
	zone := string(r.zone)
	r.lem.SetOnZoneJoined(func(z ZoneName) error {
		return r.conf.leaderKeySetup(r.ctx, z, false)
	})
	r.conf.takeUpWait(zone)
	waitUntil(t, "the KEY is not booked", func() bool {
		_, ok := r.conf.InternalMp.MPTransport.rollKEYs.state(r.zone)
		return ok
	})
	r.conf.InternalMp.parentSyncs.wait()
	tm := r.conf.InternalMp.MPTransport
	st, _ := tm.rollKEYs.state(r.zone)
	tm.rollKEYs.heard(st.distID, st.expected[0], "ERROR", "no", false)
	if w := r.conf.takeUpWait(zone); w != "the zone's KEY to be published" {
		t.Fatalf("a refused KEY: the step waits for %q", w)
	}
	waitUntil(t, "the KEY is not booked again", func() bool {
		again, ok := tm.rollKEYs.state(r.zone)
		return ok && again.distID != st.distID
	})
	r.conf.InternalMp.parentSyncs.wait()
	again, _ := tm.rollKEYs.state(r.zone)
	for _, rcpt := range again.expected {
		tm.rollKEYs.heard(again.distID, rcpt, "IGNORED", "", false)
	}
	if w := r.conf.takeUpWait(zone); w != "" {
		t.Errorf("IGNORED by every recipient, and the step waits for %q", w)
	}
}

// The parent's trust stays owed under keyPending, not under the transition:
// with the KEY confirmed the step is done while the parent has not taken the
// key, and a sync waits for the key. A zone that uses no key has no KEY to
// wait for, and no key to offer.
func TestATakeUpTheParentDoesNotTrustYetIsDoneAndTheSyncOwed(t *testing.T) {
	t.Run("a key the parent has not taken", func(t *testing.T) {
		r := takeUpRig(t, "owed.takeup.example.")
		zone := string(r.zone)
		r.conf.InternalMp.keyPoll = func(_ context.Context, _ ZoneName, _ string, keyid uint16, _ uint8) { r.polls <- keyid }
		r.lem.SetOnZoneJoined(func(z ZoneName) error {
			return r.conf.leaderKeySetup(r.ctx, z, false)
		})
		r.conf.takeUpWait(zone)
		waitUntil(t, "the KEY is not booked", func() bool {
			_, ok := r.conf.InternalMp.MPTransport.rollKEYs.state(r.zone)
			return ok
		})
		r.conf.InternalMp.parentSyncs.wait()
		r.confirmAll(t)
		if w := r.conf.takeUpWait(zone); w != "" {
			t.Fatalf("the KEY is confirmed, the parent has not taken it, and the step waits for %q", w)
		}
		r.polled(t, "after the KEY's confirmations")
		r.conf.InternalMp.keyPolls.goroutines.Wait()
		if !r.conf.keyPending(r.ctx, r.zone) {
			t.Error("the parent's trust is not owed under keyPending")
		}
		ds := tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: zone, ZoneData: r.mpzd.ZoneData}
		if held, why := r.conf.holdForZoneKey(r.ctx, ds); !held || why == "" {
			t.Errorf("a sync goes out on a key the parent has not taken: held=%v %q", held, why)
		}
	})

	t.Run("a zone that uses no key", func(t *testing.T) {
		r := newKeyRoundRig(t, "nokey.takeup.example.", "NOTIFY")
		freezeServed(t, r.conf, r.mpzd)
		t.Cleanup(r.conf.InternalMp.parentSyncs.wait)
		zone := string(r.zone)
		joined := make(chan ZoneName, 1)
		r.lem.SetOnZoneJoined(func(z ZoneName) error { joined <- z; return nil })
		if w := r.conf.takeUpWait(zone); w == "" {
			t.Fatal("the step did not look at the parent first")
		}
		r.conf.InternalMp.parentSyncs.wait()
		if w := r.conf.takeUpWait(zone); w != "" {
			t.Errorf("a parent that takes NOTIFY only, and the step waits for %q", w)
		}
		if _, ok := recvWithin(joined, 5*time.Second); !ok {
			t.Error("the zone was not taken up: its sync is not asked for")
		}
	})
}

// The judge lets a change of parentsync through, both ways, on every agent.
func TestAChangeOfParentsyncIsAgreed(t *testing.T) {
	at := func(serial uint32, parentsync string) *Instructions {
		return jAt(t, serial, fmt.Sprintf(`servers="a,b" parentsync="%s"`, parentsync), freezeRecords...)
	}
	if rs := judgeTransition(at(1, "agent"), at(2, "owner")); len(rs) != 0 {
		t.Errorf("agent to owner: %+v", rs)
	}
	if rs := judgeTransition(at(1, "owner"), at(2, "agent")); len(rs) != 0 {
		t.Errorf("owner to agent: %+v", rs)
	}
}
