/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The removal (plan S17b), on S12's reconcile rig: the leader a, with b, and
// n leaving. The leader's actions stand in; the parent is what the rig says.

type leaverRig struct {
	*reconcileRig
	parent      parentSeen
	parentErr   error
	withdrawals []string // in the order asked, as "<provider> <type>"
	confirmed   bool     // every withdrawal is confirmed as soon as it is asked
	syncs       []string
	rolls       int
	dsThere     func(parentSeen) bool
	bNS         []string // what b tells in its beats
}

func removalAt(t *testing.T, serial uint32, nsmgmt, servers, signers string) *Instructions {
	t.Helper()
	param := fmt.Sprintf(`servers="%s" nsmgmt="%s" parentsync="agent"`, servers, nsmgmt)
	if signers != "" {
		param += fmt.Sprintf(` signers="%s"`, signers)
	}
	return jAt(t, serial, param, freezeRecords...)
}

// standIns has the removal's actions and the parent stand in for r until the
// test ends.
func (r *leaverRig) standIns(t *testing.T) {
	t.Helper()
	pl, pg, aw, ss, or, dl := parentLook, parentLookGo, askWithdrawal, stepSyncAsk, oweRemovalRoll, dsLeft
	t.Cleanup(func() {
		parentLook, parentLookGo, askWithdrawal, stepSyncAsk, oweRemovalRoll, dsLeft = pl, pg, aw, ss, or, dl
	})
	parentLook = func(*Config, string) (parentSeen, error) { return r.parent, r.parentErr }
	parentLookGo = func(look func()) { look() }
	askWithdrawal = func(conf *Config, zone string, w Withdraw) {
		k := strings.TrimSuffix(w.Provider, ".") + " " + w.RRtype
		if !slices.Contains(r.withdrawals, k) {
			r.withdrawals = append(r.withdrawals, k)
		}
		if r.confirmed {
			r.confirmWithdrawal(w.Provider, w.RRtype)
		}
	}
	stepSyncAsk = func(_ *Config, _, why string) { r.syncs = append(r.syncs, why) }
	oweRemovalRoll = func(*Config, ZoneName) { r.rolls++ }
	dsLeft = func(_ *Config, _ string, seen parentSeen) bool { return r.dsThere == nil || r.dsThere(seen) }
}

func (r *leaverRig) confirmWithdrawal(provider, rrtype string) {
	rb := &r.conf.InternalMp.reconciles
	rb.mu.Lock()
	defer rb.mu.Unlock()
	zr := rb.zone(canonicalName(r.zone))
	if zr.withdrawn == nil {
		zr.withdrawn = map[string]bool{}
	}
	zr.withdrawn[withdrawnKey(provider, rrtype)] = true
}

// newLeaverRigAt is the rig thawed from n to v, at step 0, with the parent
// serving parent.
func newLeaverRigAt(t *testing.T, zone string, n, v *Instructions, parent parentSeen) *leaverRig {
	t.Helper()
	r := &leaverRig{reconcileRig: newReconcileRig(t, zone, roleA), parent: parent, confirmed: true, bNS: []string{"ns1.b.example."}}
	r.standIns(t)
	r.conf.MpConfig().Local.Nameservers = []string{"ns1.a.example."}
	r.n, r.v = n, v
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.Active.Reading, z.Active.SerialDigest = r.n, sd(r.n)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r.holdUnjudged(r.v, time.Now())
	if err := r.conf.activate(r.zone, Thaw{From: sd(r.n), To: sd(r.v)}, roleA); err != nil {
		t.Fatal(err)
	}
	return r
}

// newLeaverRig: a, b and n serve under 41, a and n sign; 42 takes n out of
// both, its record kept. The parent names ns1.n.example. among others.
func newLeaverRig(t *testing.T, zone, nsmgmt string) *leaverRig {
	t.Helper()
	return newLeaverRigAt(t, zone, removalAt(t, 41, nsmgmt, "a,b,n", "a,n"), removalAt(t, 42, nsmgmt, "a,b", "a"),
		parentSeen{ns: []string{"ns1.a.example.", "ns1.b.example.", "ns1.n.example."}, nsTTL: 600, ds: []uint16{1, 2}, dsTTL: 900})
}

// served has the parent serve seen, looked at from now on.
func (r *leaverRig) served(seen parentSeen) {
	r.parent = seen
	rb := &r.conf.InternalMp.reconciles
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.zone(canonicalName(r.zone)).lookedAt = time.Time{}
}

// tellsNS has the member id tell its NS names in its beats.
func (r *leaverRig) statusNoDS() tdns.DelegationSyncStatus { return tdns.DelegationSyncStatus{} }

func (r *leaverRig) tellsNS(id string, names ...string) {
	r.seq++
	r.stamps.note(&GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
		id: {Identity: id, Timestamp: time.Now(), Epoch: 1, Seq: r.seq, Crypto: true, Nameservers: names, Instr: map[string]InstrStamp{}}}}, id, "DNS")
}

// aged moves every wait's start back by d.
func (r *leaverRig) aged(d time.Duration) {
	rb := &r.conf.InternalMp.reconciles
	rb.mu.Lock()
	defer rb.mu.Unlock()
	zr := rb.zone(canonicalName(r.zone))
	for k, at := range zr.since {
		zr.since[k] = at.Add(-d)
	}
}

// bHolds has b tell the step this agent holds, held by both its parts.
func (r *leaverRig) bHolds() {
	st := r.own()
	st.StepHeld = true
	r.seq++
	r.stamps.note(&GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
		roleB: {Identity: roleB, Timestamp: time.Now(), Epoch: 1, Seq: r.seq, Crypto: true, Nameservers: r.bNS, Instr: map[string]InstrStamp{r.zone: st}}}}, roleB, "DNS")
}

// next is a turn after every part holds the step: this agent's and b's.
func (r *leaverRig) next() {
	r.t.Helper()
	r.partsTake()
	r.bHolds()
	r.turn(time.Now())
}

// taken are the keys of the steps taken, the removal's by their last word.
func (r *leaverRig) taken() []string {
	st, _ := r.step()
	var out []string
	for _, k := range st.Taken {
		if _, part, ok := removalKeyParts(k); ok {
			k = part
		}
		out = append(out, k)
	}
	return out
}

// sets are the sets of the step held.
func (r *leaverRig) sets() Roles {
	r.t.Helper()
	sets, ok := r.store.stepSets(r.zone)
	if !ok {
		r.t.Fatal("no step's sets")
	}
	return sets
}

// toNSGone: the parent no longer names n's names and the NS TTL has passed.
func (r *leaverRig) toNSGone() {
	r.t.Helper()
	r.served(parentSeen{ns: []string{"ns1.a.example.", "ns1.b.example."}, nsTTL: 600, ds: r.parent.ds, dsTTL: 900})
	r.next()
	r.aged(2 * time.Hour)
	r.next()
}

// toDSGone: the parent no longer serves n's DS and the TTLs have passed.
func (r *leaverRig) toDSGone() {
	r.t.Helper()
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	r.served(parentSeen{ns: r.parent.ns, nsTTL: 600, ds: []uint16{1}, dsTTL: 900})
	r.next()
	r.aged(3 * time.Hour)
	r.next()
}

// run drives a removal under nsmgmt=agent to the transition's end.
func (r *leaverRig) run() {
	r.t.Helper()
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	r.next() // names
	r.next() // ns
	r.toNSGone()
	r.next() // ds
	r.toDSGone()
	r.next() // done
	r.next() // last
	r.next() // transition done
}

func TestARemovalWithdrawsNSThenDSThenDNSKEY(t *testing.T) {
	r := newLeaverRig(t, "order.remove.example.", "agent")
	r.next()
	if got := r.taken(); !slices.Equal(got, []string{"names"}) {
		t.Fatalf("the first step: %v", got)
	}
	r.run()
	want := []string{"n.role.example NS", "n.role.example CDS", "n.role.example DNSKEY"}
	if !slices.Equal(r.withdrawals, want) {
		t.Errorf("the withdrawals:\n got %v\nwant %v", r.withdrawals, want)
	}
	if st := status(t, r.store, r.zone); st.Phase != PhaseSteady || len(st.Removals) != 0 {
		t.Errorf("after the removal: phase %s, removals %v", st.Phase, st.Removals)
	}
}

func TestTheLeadersFirstStepNamesTheLeavingNSNames(t *testing.T) {
	r := newLeaverRig(t, "names.remove.example.", "agent")
	r.tellsNS(roleN, "told.n.example.")
	r.next()
	rm, ok := r.store.removal(r.zone, "n", "")
	if !ok || !slices.Equal(rm.NSNames, []string{"ns1.n.example.", "told.n.example."}) || !core.EqualNames(rm.Identity, roleN) {
		t.Fatalf("the removal: %+v %v", rm, ok)
	}
	if st := r.own(); len(st.Removals) != 1 || !slices.Equal(st.Removals[0].NSNames, rm.NSNames) {
		t.Errorf("the stamp's removals: %+v", st.Removals)
	}
}

// A name the leader's data holds of n, which n does not tell and the parent
// does not name, is not n's by that. A name at the parent that a remaining
// provider tells or contributes is not n's.
func TestTheLeavingNSNamesComeFromItsStampAndTheParentNotTheLeadersData(t *testing.T) {
	r := newLeaverRig(t, "fromdata.remove.example.", "agent")
	zdr, _ := NewZoneDataRepo()
	ar, _ := NewAgentRepo()
	zdr.Repo.Set(ZoneName(r.zone), ar)
	nsOf := func(id AgentId, names ...string) {
		od := tdns.NewOwnerData(r.zone)
		rrset := core.RRset{}
		for _, n := range names {
			rr, err := dns.NewRR(r.zone + " 3600 IN NS " + n)
			if err != nil {
				t.Fatal(err)
			}
			rrset.RRs = append(rrset.RRs, rr)
		}
		od.RRtypes.Set(dns.TypeNS, rrset)
		ar.Set(id, od)
	}
	nsOf(roleN, "indata.n.example.")
	nsOf(roleB, "ns1.b.example.")
	r.conf.InternalMp.ZoneDataRepo = zdr
	r.bNS = nil // b's is its contribution
	r.next()
	rm, _ := r.store.removal(r.zone, "n", "")
	if !slices.Equal(rm.NSNames, []string{"ns1.n.example."}) {
		t.Errorf("the names: %v", rm.NSNames)
	}
}

func TestEveryAgentKeepsTheLeavingNSNamesFromTheLeadersFirstStep(t *testing.T) {
	leader := newLeaverRig(t, "kept.remove.example.", "agent")
	leader.next()
	told := leader.own()
	m := newMemberRig(t, "kept2.remove.example.")
	st := m.leaderStep(told.Step.Number, leader.sets(), told.Step.Taken, told.Removals...)
	m.hear(roleB, st, true)
	m.turn(time.Now())
	rm, ok := m.store.removal(m.zone, "n", "")
	if !ok || !slices.Contains(rm.NSNames, "ns1.n.example.") {
		t.Errorf("the member keeps %+v, %v", rm, ok)
	}
}

// A new leader watches for the names kept with the removal: what it took from
// the step, whatever the stamps and the parent say of them now.
func TestANewLeaderTakesTheKeptNSNames(t *testing.T) {
	r := newLeaverRig(t, "newnames.remove.example.", "agent")
	r.next()
	r.stamps.kept = map[string]*memberStamp{}
	r.conf.InternalMp.reconciles.forget(canonicalName(r.zone))
	r.next()
	if !slices.Equal(r.taken(), []string{"names", "ns"}) {
		t.Fatalf("the steps: %v", r.taken())
	}
	r.next()
	if !strings.Contains(r.conf.thawLine(r.zone), "waiting until the parent no longer names ns1.n.example.") {
		t.Errorf("the status: %q", r.conf.thawLine(r.zone))
	}
}

func TestALeaderWithoutTheStateTakesTheRemovalFromTheMembersStamps(t *testing.T) {
	r := newLeaverRig(t, "nostate.remove.example.", "agent")
	r.next()
	r.next()
	told := r.own()
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.Sets, z.Step, z.Taken, z.Removals, z.Pending = nil, 0, nil, nil, true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r.hear(roleB, told, true)
	r.turn(time.Now())
	if rm, ok := r.store.removal(r.zone, "n", ""); !ok || !slices.Contains(rm.NSNames, "ns1.n.example.") {
		t.Fatalf("the removal: %+v %v", rm, ok)
	}
	if !slices.Equal(r.taken(), []string{"names", "ns"}) {
		t.Errorf("the steps: %v", r.taken())
	}
}

func TestUnderNsmgmtOwnerTheLeaderWithdrawsNoNSAndWatchesTheParent(t *testing.T) {
	r := newLeaverRig(t, "owner.remove.example.", "owner")
	r.next()
	r.next()
	if !slices.Equal(r.taken(), []string{"names", "ns"}) {
		t.Fatalf("the steps: %v", r.taken())
	}
	r.next()
	if slices.Contains(r.withdrawals, "n.role.example NS") {
		t.Errorf("under nsmgmt=owner an NS was withdrawn: %v", r.withdrawals)
	}
	if len(r.syncs) == 0 {
		t.Error("no sync asked")
	}
	if !strings.Contains(r.conf.thawLine(r.zone), "waiting until the parent no longer names ns1.n.example.") {
		t.Errorf("the status: %q", r.conf.thawLine(r.zone))
	}
	r.toNSGone()
	if !slices.Equal(r.taken(), []string{"names", "ns", "confirmers"}) {
		t.Errorf("after the parent dropped them: %v", r.taken())
	}
}

// The step's wait counts from when the parent no longer names the names, and
// starts over if it names them again.
func TestTheNSTTLCountsFromWhenTheParentNoLongerNamesTheNames(t *testing.T) {
	r := newLeaverRig(t, "nsttl.remove.example.", "agent")
	r.next()
	r.next()
	r.next()
	r.aged(24 * time.Hour) // nothing counts yet
	r.next()
	if len(r.taken()) != 2 {
		t.Fatalf("went on while the parent names them: %v", r.taken())
	}
	gone := parentSeen{ns: []string{"ns1.a.example.", "ns1.b.example."}, nsTTL: 600}
	r.served(gone)
	r.next()
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "step 2 (its NS), waiting for the NS TTL until ") {
		t.Errorf("the status: %q", line)
	}
	r.aged(5 * time.Minute)
	r.next()
	if len(r.taken()) != 2 {
		t.Fatalf("went on before the TTL passed: %v", r.taken())
	}
	r.served(parentSeen{ns: []string{"ns1.n.example."}, nsTTL: 600}) // named again
	r.next()
	r.served(gone)
	r.next()
	r.aged(5 * time.Minute)
	r.next()
	if len(r.taken()) != 2 {
		t.Fatalf("the wait did not start over: %v", r.taken())
	}
	r.aged(6 * time.Minute)
	r.next()
	if !slices.Equal(r.taken(), []string{"names", "ns", "confirmers"}) {
		t.Errorf("after the TTL: %v", r.taken())
	}
}

// The S13 exit test: a key confirmer leaves once the NS TTL has passed since
// the parent dropped its names, not before; and until then the set names it.
func TestAKeyConfirmerLeavesOnceTheNSTTLHasPassedSinceTheParentDroppedItsNames(t *testing.T) {
	r := newLeaverRig(t, "confirmer.remove.example.", "agent")
	r.next()
	r.next()
	sets := r.sets()
	if slices.Contains(providerLabels(sets.Servers), "n") {
		t.Errorf("the NS step's servers still name n: %v", providerLabels(sets.Servers))
	}
	if !slices.Contains(providerLabels(sets.KeyConfirmers), "n") {
		t.Fatalf("n left the confirmers at the NS step: %v", providerLabels(sets.KeyConfirmers))
	}
	r.toNSGone()
	if slices.Contains(providerLabels(r.sets().KeyConfirmers), "n") {
		t.Errorf("n still confirms after the NS TTL: %v", providerLabels(r.sets().KeyConfirmers))
	}
	if !slices.Contains(providerLabels(r.sets().DSSigners), "n") {
		t.Errorf("n left the DS signers with the confirmers: %v", providerLabels(r.sets().DSSigners))
	}
}

// TestTheLeavingSignerLeavesTheConfirmersWhenItsNSTTLPassed, with
// TestTheConfirmersLeaveIsPartOfTheNSStepAndPassesTheFreeze: its step is taken
// and handed to the parts while the zone is frozen.
func TestTheConfirmersLeaveIsPartOfTheNSStepAndPassesTheFreeze(t *testing.T) {
	r := newLeaverRig(t, "freeze.remove.example.", "agent")
	r.next()
	r.next()
	r.toNSGone()
	if len(r.conf.zoneFrozen(r.zone)) == 0 {
		t.Fatal("the zone is not frozen during its reconciliation")
	}
	if !slices.Equal(r.taken(), []string{"names", "ns", "confirmers"}) {
		t.Fatalf("the steps: %v", r.taken())
	}
	want := r.wanted()
	if want == nil || want.Step != 3 || slices.Contains(providerLabels(want.Sets.KeyConfirmers), "n") {
		t.Errorf("handed to the combiner: %+v", want)
	}
}

func TestTheDSIsNotWithdrawnBeforeTheParentDroppedTheNSAndTheNSTTLPassed(t *testing.T) {
	r := newLeaverRig(t, "dsafter.remove.example.", "agent")
	r.next()
	r.next()
	r.next()
	r.aged(24 * time.Hour)
	r.next()
	if slices.Contains(r.withdrawals, "n.role.example CDS") || !slices.Contains(providerLabels(r.sets().DSSigners), "n") {
		t.Fatalf("its DS went before the parent dropped its NS: %v", r.withdrawals)
	}
	r.toNSGone()
	r.next()
	if !slices.Contains(r.withdrawals, "n.role.example CDS") {
		t.Errorf("its DS did not go after the NS TTL: %v, steps %v", r.withdrawals, r.taken())
	}
}

func TestTheCDSGoesAtTheDSStep(t *testing.T) {
	r := newLeaverRig(t, "cds.remove.example.", "agent")
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	r.next()
	r.next()
	r.toNSGone()
	if slices.Contains(r.withdrawals, "n.role.example CDS") {
		t.Fatalf("the CDS went before the DS step: %v", r.withdrawals)
	}
	r.next()
	if !slices.Equal(r.taken(), []string{"names", "ns", "confirmers", "ds"}) || !slices.Contains(r.withdrawals, "n.role.example CDS") {
		t.Fatalf("the DS step: %v, withdrawn %v", r.taken(), r.withdrawals)
	}
	if slices.Contains(providerLabels(r.sets().DSSigners), "n") || !slices.Contains(providerLabels(r.sets().KeySigners), "n") {
		t.Errorf("the DS step's sets: %+v", r.sets())
	}
	r.next()
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "step 3 (its DS), waiting until the parent no longer serves its DS") {
		t.Errorf("the status: %q", line)
	}
}

func TestTheDNSKEYsAreNotWithdrawnBeforeTheDSTTLPassed(t *testing.T) {
	r := newLeaverRig(t, "dnskeyafter.remove.example.", "agent")
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	r.next()
	r.next()
	r.toNSGone()
	r.next()
	r.next()
	if slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Fatalf("its DNSKEY went while the parent serves its DS: %v", r.withdrawals)
	}
	r.served(parentSeen{ns: r.parent.ns, nsTTL: 600, ds: []uint16{1}, dsTTL: 900})
	r.next()
	r.aged(10 * time.Minute) // under the DS TTL
	r.next()
	if slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Fatalf("its DNSKEY went within the DS TTL: %v", r.withdrawals)
	}
	r.aged(3 * time.Hour)
	r.next()
	if !slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Errorf("its DNSKEY did not go after the TTLs: %v, steps %v", r.withdrawals, r.taken())
	}
}

// toDSStep brings a removal to step 3 with the parent still serving n's DS.
func (r *leaverRig) toDSStep() {
	r.t.Helper()
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	r.next()
	r.next()
	r.toNSGone()
	r.next()
	r.next()
}

// A held key has the TTL it was generated with, 3600; what resolvers keep is
// what the zone's servers serve (the demo's rig run: an hour against 5 min).
func TestTheDSStepWaitsForTheDNSKEYTTLServedNotTheOneHeld(t *testing.T) {
	r := newSweepRig(t, "servedttl.remove.example.")
	r.holds(roleN, dns.TypeDNSKEY)
	r.toDSStep()
	r.served(parentSeen{ns: r.parent.ns, nsTTL: 600, ds: []uint16{1}, dsTTL: 120, dnskeyTTL: 300})
	r.next()
	r.aged(4 * time.Minute) // over the DS TTL, under the DNSKEY TTL
	r.next()
	if slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Fatalf("its DNSKEY went within the served TTL: %v", r.withdrawals)
	}
	r.aged(2 * time.Minute)
	r.next()
	if !slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Errorf("its DNSKEY did not go after the served TTL: %v, steps %v", r.withdrawals, r.taken())
	}
}

func TestWithNoServerTellingTheTTLTheDSStepGoesByTheOneHeld(t *testing.T) {
	logs := captureLog(t)
	r := newSweepRig(t, "heldttl.remove.example.")
	r.holds(roleN, dns.TypeDNSKEY)
	r.toDSStep()
	r.served(parentSeen{ns: r.parent.ns, nsTTL: 600, ds: []uint16{1}, dsTTL: 120})
	r.next()
	r.aged(30 * time.Minute)
	r.next()
	if slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Fatalf("its DNSKEY went within the held TTL: %v", r.withdrawals)
	}
	if !strings.Contains(logs.String(), "no server told the zone's DNSKEY TTL") {
		t.Errorf("no log line: %s", logs)
	}
	r.aged(31 * time.Minute)
	r.next()
	if !slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Errorf("its DNSKEY did not go after the held TTL: %v, steps %v", r.withdrawals, r.taken())
	}
}

// A server the parent has dropped may have served the larger TTL.
func TestTheLargestDNSKEYTTLSeenStands(t *testing.T) {
	r := newLeaverRig(t, "largestttl.remove.example.", "agent")
	for _, ttl := range []uint32{600, 300, 0} {
		r.served(parentSeen{ns: r.parent.ns, nsTTL: 600, dnskeyTTL: ttl})
		if seen, ok := r.conf.parentNow(r.zone); !ok || seen.dnskeyTTL != 600 {
			t.Errorf("after a look that saw %d: %d, known %v", ttl, seen.dnskeyTTL, ok)
		}
	}
}

// dnskeyServer serves the zone's DNSKEY RRset over TCP only, with the TTL; with
// none it answers empty. The address it listens on is what it returns.
func dnskeyServer(t *testing.T, zone string, ttl uint32) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		if ttl != 0 {
			rr, err := dns.NewRR(fmt.Sprintf("%s %d IN DNSKEY 257 3 15 11qYAYKxCrfVS/7TyWQHOg7nGkjJ3KgP9h8fZqXsIY8=", zone, ttl))
			if err != nil {
				t.Error(err)
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := w.WriteMsg(m); err != nil {
			t.Error(err)
		}
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return ln.Addr().String()
}

func TestTheServedDNSKEYTTLIsTheLargestAnyServerGives(t *testing.T) {
	const zone = "served.remove.example."
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := closed.Addr().String()
	closed.Close()
	if got := servedDnskeyTTL(zone, []string{gone, dnskeyServer(t, zone, 120), dnskeyServer(t, zone, 300), dnskeyServer(t, zone, 0)}); got != 300 {
		t.Errorf("the servers' largest: %d, want 300", got)
	}
	if got := servedDnskeyTTL(zone, []string{gone, dnskeyServer(t, zone, 0)}); got != 0 {
		t.Errorf("no server tells: %d, want 0", got)
	}
}

// syncDue makes the step's next ask of the sync due at once.
func (r *leaverRig) syncDue() {
	rb := &r.conf.InternalMp.reconciles
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.zone(canonicalName(r.zone)).syncAt = time.Time{}
}

// nextAsks is the syncs a turn asks, with one due.
func (r *leaverRig) nextAsks() int {
	r.t.Helper()
	r.syncDue()
	before := len(r.syncs)
	r.next()
	return len(r.syncs) - before
}

// The sync is asked again while the parent still serves what leaves, and not
// through the TTL wait after it has dropped it: then there is nothing to sync.
func TestAStepStopsAskingTheSyncOnceTheParentHasDroppedItsRecords(t *testing.T) {
	r := newLeaverRig(t, "syncstops.remove.example.", "agent")
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	r.next()
	r.next()
	r.next()
	if n := r.nextAsks(); n != 1 {
		t.Errorf("with the parent naming n: %d syncs asked, want 1", n)
	}
	r.served(parentSeen{ns: []string{"ns1.a.example.", "ns1.b.example."}, nsTTL: 600, ds: r.parent.ds, dsTTL: 900})
	if n := r.nextAsks(); n != 0 {
		t.Errorf("through the NS TTL: %d syncs asked, want 0", n)
	}
	r.aged(2 * time.Hour)
	r.next()
	r.next()
	r.next()
	if n := r.nextAsks(); n != 1 {
		t.Errorf("with the parent serving n's DS: %d syncs asked, want 1; steps %v", n, r.taken())
	}
	r.served(parentSeen{ns: r.parent.ns, nsTTL: 600, ds: []uint16{1}, dsTTL: 900})
	if n := r.nextAsks(); n != 0 {
		t.Errorf("through the DS TTL: %d syncs asked, want 0", n)
	}
}

// A leader that has not read the parent yet still asks: the look may fail where
// the sync works. Step 1 waits for the look, so this is a new leader's, at a
// step taken before it led.
func TestTheSyncIsAskedWhileWhatTheParentServesIsNotKnown(t *testing.T) {
	r := newLeaverRig(t, "syncunknown.remove.example.", "agent")
	r.next()
	r.next()
	rb := &r.conf.InternalMp.reconciles
	rb.mu.Lock()
	rb.zone(canonicalName(r.zone)).parent = parentSeen{}
	rb.zone(canonicalName(r.zone)).lookedAt = time.Time{}
	rb.mu.Unlock()
	r.parentErr = errors.New("no answer")
	r.next()
	if len(r.syncs) == 0 {
		t.Error("no sync asked")
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "until the parent's NS RRset is known") {
		t.Errorf("the status: %q", line)
	}
}

func TestTheRollStartsFirstAndDoesNotHoldTheRemoval(t *testing.T) {
	r := newLeaverRig(t, "roll.remove.example.", "agent")
	r.next()
	if r.rolls != 1 || !slices.Equal(r.taken(), []string{"names"}) {
		t.Fatalf("at the first step: %d rolls, steps %v", r.rolls, r.taken())
	}
	r.next() // the roll is owed, and nothing waits for it
	if !slices.Equal(r.taken(), []string{"names", "ns"}) || r.rolls != 1 {
		t.Errorf("the next step: %d rolls, steps %v", r.rolls, r.taken())
	}
	// a new leader took the first step from a member: it owes the roll itself
	r.conf.InternalMp.reconciles.forget(canonicalName(r.zone))
	r.next()
	if r.rolls != 2 {
		t.Errorf("a new leader's turn: %d rolls owed, want 2", r.rolls)
	}
	r.next()
	if r.rolls != 2 {
		t.Errorf("its next turn: %d rolls owed, want 2", r.rolls)
	}
}

func TestARemovalFromServersOnlyHasNoDSOrDNSKEYStep(t *testing.T) {
	r := newLeaverRigAt(t, "serveronly.remove.example.", removalAt(t, 41, "agent", "a,b,n", "a,b"), removalAt(t, 42, "agent", "a,b", "a,b"),
		parentSeen{ns: []string{"ns1.n.example."}, nsTTL: 60})
	r.next()
	r.next()
	r.toNSGone()
	r.next()
	if got := r.taken(); !slices.Equal(got, []string{"names", "ns", "done", lastStepKey}) {
		t.Errorf("the steps: %v", got)
	}
	if !slices.Equal(r.withdrawals, []string{"n.role.example NS"}) {
		t.Errorf("the withdrawals: %v", r.withdrawals)
	}
}

// One that leaves servers= and stays in signers= keeps its signer sets and is
// waited for as the voting member it is, with no time-out.
func TestALeaverThatStaysASignerKeepsItsSignerSetsAndVotes(t *testing.T) {
	logs := captureLog(t)
	r := newLeaverRigAt(t, "stayssigner.remove.example.", removalAt(t, 41, "agent", "a,b,n", "a,n"), removalAt(t, 42, "agent", "a,b", "a,n"),
		parentSeen{ns: []string{"ns1.n.example."}, nsTTL: 60})
	r.partsTake()
	r.bHolds()
	r.turn(time.Now())
	if len(r.taken()) != 0 {
		t.Fatalf("went on without n, a voting member: %v", r.taken())
	}
	r.holdsToo(roleN)
	r.next()
	if !slices.Equal(r.taken(), []string{"names"}) {
		t.Fatalf("the steps: %v", r.taken())
	}
	r.turn(time.Now().Add(48 * time.Hour))
	if strings.Contains(logs.String(), `msg="a leaving member that has not confirmed a step is excused"`) {
		t.Error("a voting member was excused")
	}
	if !slices.Contains(providerLabels(r.sets().KeyConfirmers), "n") || !slices.Contains(providerLabels(r.sets().Signing), "n") {
		t.Errorf("its signer sets: %+v", r.sets())
	}
}

func TestARemovalOfASignerThatDoesNotServeHasNoNSStep(t *testing.T) {
	r := newLeaverRigAt(t, "signeronly.remove.example.", removalAt(t, 41, "agent", "a,b", "a,n"), removalAt(t, 42, "agent", "a,b", "a"), parentSeen{ns: []string{"ns1.a.example."}, nsTTL: 60, ds: []uint16{1, 2}, dsTTL: 60})
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	r.next()
	r.next()
	r.toDSGone()
	if got := r.taken(); !slices.Equal(got, []string{"names", "ds", "dnskey"}) {
		t.Errorf("the steps: %v", got)
	}
	if slices.Contains(r.withdrawals, "n.role.example NS") {
		t.Errorf("the withdrawals: %v", r.withdrawals)
	}
}

// The S13 exit test: every leaving signer that serves nothing leaves
// KeyConfirmers at the reconciliation's first step, excused or not, and stays
// in the other signer sets until its own steps.
func TestEveryLeavingSignerThatServesNothingLeavesTheConfirmersAtTheFirstStep(t *testing.T) {
	for _, excused := range []bool{false, true} {
		t.Run(fmt.Sprintf("excused %v", excused), func(t *testing.T) {
			r := newLeaverRigAt(t, fmt.Sprintf("firststep%v.remove.example.", excused), removalAt(t, 41, "agent", "a,b", "a,n"), removalAt(t, 42, "agent", "a,b", "a"), parentSeen{ns: []string{"ns1.a.example."}, nsTTL: 60})
			if excused {
				if err := r.store.excuse(r.zone, roleN); err != nil {
					t.Fatal(err)
				}
			}
			r.next()
			sets := r.sets()
			if !slices.Equal(r.taken(), []string{"names"}) || slices.Contains(providerLabels(sets.KeyConfirmers), "n") {
				t.Fatalf("the first step: %v, confirmers %v", r.taken(), providerLabels(sets.KeyConfirmers))
			}
			if !slices.Contains(providerLabels(sets.DSSigners), "n") || !slices.Contains(providerLabels(sets.KeySigners), "n") || !slices.Contains(providerLabels(sets.Signing), "n") {
				t.Errorf("it left another set too: %+v", sets)
			}
		})
	}
}

// A signer that serves nothing holds no addition's keys: it leaves the
// confirmers ahead of any addition's DNSKEY step, excused or not.
func TestASignerThatServesNothingHoldsNoAdditionsKeys(t *testing.T) {
	for _, excused := range []bool{false, true} {
		t.Run(fmt.Sprintf("excused %v", excused), func(t *testing.T) {
			defer withRunners(stepRunner{name: "addition", kind: stepAddition, steps: func(planView) []plannedStep {
				return []plannedStep{{key: "d dnskey", what: "d's DNSKEY", keys: true}}
			}}, stepRunner{name: "removal", kind: stepRemoval, steps: removalSteps})()
			r := newLeaverRigAt(t, fmt.Sprintf("noadd%v.remove.example.", excused), removalAt(t, 41, "agent", "a,b", "a,n"), removalAt(t, 42, "agent", "a,b", "a"), parentSeen{ns: []string{"ns1.a.example."}, nsTTL: 60})
			if excused {
				if err := r.store.excuse(r.zone, roleN); err != nil {
					t.Fatal(err)
				}
			}
			r.next()
			if !slices.Equal(r.taken(), []string{"names"}) || slices.Contains(providerLabels(r.sets().KeyConfirmers), "n") {
				t.Fatalf("the first step: %v", r.taken())
			}
			r.next()
			if got := r.taken(); !slices.Equal(got, []string{"names", "d dnskey"}) {
				t.Errorf("the second: %v", got)
			}
		})
	}
}

func TestTheLeavingProviderSignsUntilItsDNSKEYsAreWithdrawn(t *testing.T) {
	r := newLeaverRig(t, "signs.remove.example.", "agent")
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	r.next()
	r.next()
	r.toNSGone()
	r.next()
	for _, set := range [][]Provider{r.sets().Signing, r.sets().KeySigners} {
		if !slices.Contains(providerLabels(set), "n") {
			t.Fatalf("n left a signing set before its DNSKEY step: %+v", r.sets())
		}
	}
	r.toDSGone()
	if !slices.Contains(r.taken(), "dnskey") {
		t.Fatalf("the steps: %v", r.taken())
	}
	if slices.Contains(providerLabels(r.sets().Signing), "n") || slices.Contains(providerLabels(r.sets().KeySigners), "n") {
		t.Errorf("n signs on after its DNSKEY step: %+v", r.sets())
	}
}

// n is never heard, and the removal runs to its end.
func TestTheRemovalNeedsNothingFromTheLeavingProvider(t *testing.T) {
	r := newLeaverRig(t, "needsnothing.remove.example.", "agent")
	r.run()
	if st := status(t, r.store, r.zone); st.Phase != PhaseSteady {
		t.Errorf("after the removal: %s, steps %v", st.Line(), r.taken())
	}
}

func TestAnEmergencyRolloverHoldsOnlyTheDSAndDNSKEYSteps(t *testing.T) {
	r := newLeaverRig(t, "emergency.remove.example.", "agent")
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	rolling := func() {
		r.partsTake()
		st := r.own()
		st.StepHeld, st.Rollover = true, true
		r.hear(roleB, st, true)
		r.turn(time.Now())
	}
	rolling()
	rolling()
	r.served(parentSeen{ns: []string{"ns1.a.example."}, nsTTL: 60, ds: []uint16{1, 2}, dsTTL: 60})
	rolling()
	r.aged(time.Hour)
	rolling()
	if !slices.Equal(r.taken(), []string{"names", "ns", "confirmers"}) {
		t.Fatalf("the NS steps waited for the rollover: %v", r.taken())
	}
	rolling()
	if len(r.taken()) != 3 {
		t.Errorf("the DS step did not wait for the rollover: %v", r.taken())
	}
	r.next() // over
	if !slices.Contains(r.taken(), "ds") {
		t.Fatalf("the DS step: %v", r.taken())
	}
	r.served(parentSeen{ns: []string{"ns1.a.example."}, nsTTL: 60, ds: []uint16{1}, dsTTL: 60})
	r.next()
	r.aged(3 * time.Hour)
	rolling()
	if slices.Contains(r.taken(), "dnskey") {
		t.Errorf("the DNSKEY step did not wait for the rollover: %v", r.taken())
	}
}

// Another signer's new DNSKEY waits for the leaving signer with no time-out
// while it is still delegated to: until it leaves the confirmers. Then it goes
// on, at once.
func TestAnotherSignersNewDNSKEYWaitsForTheLeavingSignerUntilItsNSTTLPassed(t *testing.T) {
	r := newLeaverRig(t, "dnskeywait.remove.example.", "agent")
	r.next()
	r.next()
	tm := r.conf.InternalMp.MPTransport
	tm.noRoleTimeout = 10 * time.Millisecond
	waiting := func() bool {
		tm.dnskeyPropMu.Lock()
		defer tm.dnskeyPropMu.Unlock()
		_, ok := tm.pendingDnskeyPropagations["d1"]
		return ok
	}
	tm.TrackDnskeyPropagation(t.Context(), ZoneName(r.zone), "d1", []uint16{4711}, nil, []AgentId{roleB, roleN})
	tm.ProcessDnskeyConfirmation("d1", roleB, transport.ConfirmSuccess.String(), nil, nil)
	time.Sleep(50 * time.Millisecond) // time-outs pass while n confirms keys
	if !waiting() {
		t.Fatal("the distribution went on without n while it is still delegated to")
	}
	r.toNSGone()
	if waiting() {
		t.Error("the distribution still waits for n, out of the confirmers")
	}
}

func TestAnExcusedLeaversNSStepComesFirstAndItsPausedRolloversResume(t *testing.T) {
	defer withRunners(stepRunner{name: "addition", kind: stepAddition, steps: func(planView) []plannedStep {
		return []plannedStep{{key: "d dnskey", what: "d's DNSKEY", keys: true}}
	}}, stepRunner{name: "removal", kind: stepRemoval, steps: removalSteps})()
	r := newLeaverRig(t, "excused.remove.example.", "agent")
	if err := r.store.excuse(r.zone, roleN); err != nil {
		t.Fatal(err)
	}
	r.next()
	r.next()
	if !slices.Equal(r.taken(), []string{"names", "ns"}) {
		t.Fatalf("its NS step does not come first: %v", r.taken())
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "removing "+roleN+" (excused): its NS first") {
		t.Errorf("the status: %q", line)
	}
	r.toNSGone()
	if slices.Contains(providerLabels(r.sets().KeyConfirmers), "n") {
		t.Errorf("n confirms on: %+v", r.sets())
	}
	// a rollover paused only on n, excused, holds no step
	st := r.own()
	st.StepHeld, st.Rollover, st.WaitsOn = true, true, []string{"n"}
	r.partsTake()
	r.hear(roleB, st, true)
	r.turn(time.Now())
	if !slices.Contains(r.taken(), "d dnskey") {
		t.Errorf("the addition's DNSKEY step waited for a rollover paused only on n: %v", r.taken())
	}
}

func TestALeaverExcusedDuringTheReconciliationIsPlannedAsExcused(t *testing.T) {
	logs := captureLog(t)
	r := newLeaverRig(t, "excusedlater.remove.example.", "agent")
	r.partsTake()
	r.holdsToo(roleB)
	st := r.own()
	st.StepHeld = false
	r.hear(roleN, st, true)
	r.turn(time.Now())
	if len(r.taken()) != 0 {
		t.Fatalf("went on without a heard leaver within its time: %v", r.taken())
	}
	if !strings.Contains(r.conf.thawLine(r.zone), roleN+" (leaving)") {
		t.Errorf("the status: %q", r.conf.thawLine(r.zone))
	}
	r.hear(roleN, st, true)
	r.turn(time.Now().Add(2 * time.Hour))
	if !strings.Contains(logs.String(), `msg="a leaving member that has not confirmed a step is excused"`) {
		t.Fatalf("not excused: %s", logs)
	}
	r.next()
	r.next()
	if s, _ := r.step(); !strings.HasSuffix(s.What, "(excused): its NS first") {
		t.Errorf("its NS step: %q", s.What)
	}
}

// S12's item 5, S17b's reading: a heard leaver that has not confirmed holds a
// step past no-role-timeout, until it is excused at leaving-timeout: so a
// short transition does not end with it never excused.
func TestAStepWaitsForAHeardLeaverUntilItIsExcused(t *testing.T) {
	r := newLeaverRig(t, "uptoleaving.remove.example.", "agent")
	r.partsTake()
	r.holdsToo(roleB)
	st := r.own()
	st.StepHeld = false
	r.hear(roleN, st, true)
	now := time.Now()
	r.turn(now)
	r.turn(now.Add(30 * time.Minute)) // past no-role-timeout, within leaving-timeout
	if len(r.taken()) != 0 {
		t.Errorf("went on without the leaver past the no-role-timeout: %v", r.taken())
	}
}

// A new leader, or one restarted, plans the same steps from the sets it took
// and the steps taken: not again from the top, and with the wait of the step
// held. The test of S12's own planner has the shorter name.
func TestANewLeaderPlansTheRemovalAgainFromWhatIsInPlace(t *testing.T) {
	r := newLeaverRig(t, "plans.remove.example.", "agent")
	r.next()
	r.next()
	r.toNSGone()
	told := r.own()
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.From = nil // its from-serial is not held
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r.next()
	if got := r.taken(); !slices.Equal(got, []string{"names", "ns", "confirmers", "ds"}) {
		t.Errorf("planned without its from-serial: %v (told %v)", got, told.Step.Taken)
	}
}

// The NS step's wait logs its terms once, and again when one changes or the
// clock starts over, so that a wait can be read from the log.
func TestTheNSWaitLogsItsTerms(t *testing.T) {
	alog := &lockedBuffer{}
	logTo(t, lg, slog.NewTextHandler(alog, nil))
	r := newLeaverRig(t, "nsterms.remove.example.", "agent")
	r.next()
	r.next()
	lines := func() []string {
		var got []string
		for _, line := range strings.Split(alog.String(), "\n") {
			if strings.Contains(line, "counts its wait") {
				got = append(got, line)
			}
		}
		return got
	}
	if got := lines(); len(got) != 0 {
		t.Fatalf("no wait counts while the parent names the names: %v", got)
	}
	gone := parentSeen{ns: []string{"ns1.a.example.", "ns1.b.example."}, nsTTL: 600, nsServer: "192.0.2.1:53"}
	r.served(gone)
	r.next()
	r.next()
	got := lines()
	if len(got) != 1 {
		t.Fatalf("the same terms were logged %d times: %v", len(got), got)
	}
	for _, term := range []string{"zone=nsterms.remove.example.", "parent_ns_ttl=600", "parent_server=192.0.2.1:53", "zone_ns_ttl=", "delay=0s", "since=", "until="} {
		if !strings.Contains(got[0], term) {
			t.Errorf("no %s in %q", term, got[0])
		}
	}
	gone.nsTTL = 300
	r.served(gone)
	r.next()
	if got := lines(); len(got) != 2 || !strings.Contains(got[1], "parent_ns_ttl=300") {
		t.Errorf("a term changed: %v", got)
	}
	r.served(parentSeen{ns: []string{"ns1.n.example."}, nsTTL: 300, nsServer: "192.0.2.1:53"}) // named again
	r.next()
	r.served(gone)
	r.next()
	if got := lines(); len(got) != 3 {
		t.Errorf("the clock started over: %v", got)
	}
}

func TestAWaitWhoseStartIsUnknownStartsNow(t *testing.T) {
	r := newLeaverRig(t, "startnow.remove.example.", "agent")
	r.next()
	r.next()
	r.served(parentSeen{ns: []string{"ns1.a.example."}, nsTTL: 600})
	r.next()
	r.aged(time.Hour)
	// a restart: the book is gone; the wait starts now, whatever it had counted
	r.conf.InternalMp.reconciles.forget(canonicalName(r.zone))
	r.next()
	if !slices.Equal(r.taken(), []string{"names", "ns"}) {
		t.Fatalf("went on by a wait from before the restart: %v", r.taken())
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "waiting for the NS TTL until ") {
		t.Errorf("the status: %q", line)
	}
}

// A suffix edit, or an edit of the record, during the removal is held, told
// as newest, and changes no set; after "done" it is agreed on.
func TestASuffixEditDuringTheNSStepWaitsForDoneAndIsThenAgreed(t *testing.T) {
	r := newLeaverRig(t, "suffixedit.remove.example.", "agent")
	r.next()
	r.next()
	before := r.sets()
	param := `servers="a,b" signers="a" nsmgmt="agent" suffix="later"`
	w := jAt(t, 43, param, freezeRecords...)
	r.store.Note(r.zone, w, nil)
	r.next()
	if !slices.Equal(providerLabels(before.Servers), providerLabels(r.sets().Servers)) || !slices.Equal(r.taken(), []string{"names", "ns"}) {
		t.Errorf("the edit changed the removal: %v", r.taken())
	}
	if _, ok := r.conf.thawView(r.zone, time.Now()); ok {
		t.Error("the edit is agreed during the reconciliation")
	}
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	r.toNSGone()
	r.next()
	r.toDSGone()
	r.next()
	r.next()
	r.next()
	v, ok := r.conf.thawView(r.zone, time.Now())
	if !ok || v.to != sd(w) {
		t.Errorf("the edit is not agreed after done: %+v %v, active %d", v, ok, r.active())
	}
}

func TestARecordEditDuringTheRemovalWaitsForDone(t *testing.T) {
	r := newLeaverRig(t, "recordedit.remove.example.", "agent")
	r.next()
	r.next()
	w := jAt(t, 43, `servers="a,b" signers="a" nsmgmt="agent"`, freezeRecords[0], freezeRecords[1])
	r.store.Note(r.zone, w, nil)
	r.next()
	if line := r.conf.thawLine(r.zone); !strings.HasSuffix(line, "; 43 held, waits until done") {
		t.Errorf("the status: %q", line)
	}
	if _, ok := r.store.removal(r.zone, "n", ""); !ok {
		t.Error("the edit ended the removal")
	}
	if !slices.Contains(zoneMembersOf(r), canonicalName(roleN)) {
		t.Errorf("n is no member while its removal runs: %v", zoneMembersOf(r))
	}
}

func zoneMembersOf(r *leaverRig) []string {
	members, _, _ := zoneParticipants(r.zone, r.store.activeReading(r.zone))
	return members
}

// The agent of the leaving provider follows the leader, and is told at the end.
func TestTheLeavingProviderIsToldSafeToRemove(t *testing.T) {
	r := newLeaverRig(t, "safe.remove.example.", "agent")
	r.run()
	if r.conf.safeToRemove(r.zone) {
		t.Error("a is told safe to remove")
	}
	if strings.Contains(r.conf.thawLine(r.zone), "safe to remove") {
		t.Errorf("a's status: %q", r.conf.thawLine(r.zone))
	}
	mp := r.conf.MpConfig()
	id := mp.Identity
	mp.Identity = roleN
	defer func() { mp.Identity = id }()
	if !r.conf.safeToRemove(r.zone) {
		t.Fatal("n is not told safe to remove")
	}
	if line := r.conf.thawLine(r.zone); !strings.HasSuffix(line, "; safe to remove") {
		t.Errorf("n's status: %q", line)
	}
}

// A step's own sync passes the freeze, as it asks; one of no step's is owed.
func TestAStepsOwnSyncPassesTheFreezeAndMakesItsCSYNC(t *testing.T) {
	r := newLeaverRig(t, "ownsync.remove.example.", "agent")
	r.next()
	if held, _ := r.conf.syncHeld(r.zone, r.conf.syncCauseFor(r.zone, r.statusNoDS())); !held {
		t.Fatal("a sync before the NS step asks one passes the freeze")
	}
	r.next()
	r.next()
	if len(r.syncs) != 1 {
		t.Fatalf("the syncs asked: %v", r.syncs)
	}
	if held, why := r.conf.syncHeld(r.zone, r.conf.syncCauseFor(r.zone, r.statusNoDS())); held {
		t.Errorf("the NS step's own sync is held: %s", why)
	}
	if !r.conf.InternalMp.reconciles.asksSync(canonicalName(r.zone)) {
		t.Error("the CSYNC of the NS step's own sync would not be made")
	}
	csync := []tdns.NotifyRequest{{RRtype: dns.TypeCSYNC}}
	if got := leavingDuringFreeze(r.conf.frozenForNotify(r.zone), csync); len(got) != 1 {
		t.Error("the NOTIFY(CSYNC) of the NS step's own sync is held")
	}
	r.toNSGone()
	if r.conf.InternalMp.reconciles.asksSync(canonicalName(r.zone)) {
		t.Error("the next step still counts as asking the sync")
	}
	if got := leavingDuringFreeze(r.conf.frozenForNotify(r.zone), csync); len(got) != 0 {
		t.Error("a NOTIFY(CSYNC) of no step's left during the freeze")
	}
}

// A label with no ON record names nobody: there is no removal.
func TestARemovalOfALabelWithNoRecordHasNoSteps(t *testing.T) {
	r := newLeaverRigAt(t, "ghost.remove.example.", removalAt(t, 41, "agent", "a,b,ghost", "a"), removalAt(t, 42, "agent", "a,b", "a"), parentSeen{ns: []string{"ns1.a.example."}, nsTTL: 60})
	r.next()
	if got := r.taken(); !slices.Equal(got, []string{lastStepKey}) {
		t.Errorf("the steps: %v", got)
	}
}

// A parent that gives no answer holds the first step of one that leaves
// servers=, as it cannot tell what the parent names, and the status says so.
func TestAParentNotKnownHoldsTheFirstStep(t *testing.T) {
	r := newLeaverRig(t, "noparent.remove.example.", "agent")
	r.parentErr = fmt.Errorf("no answer")
	r.next()
	if len(r.taken()) != 0 {
		t.Fatalf("took a step with the parent not known: %v", r.taken())
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "until the parent's NS RRset is known") {
		t.Errorf("the status: %q", line)
	}
}

// The step's wait asks the data engine: the withdrawal goes once, and the book
// says done only when no record of it is held any more.
func TestARemovalsWithdrawalIsAskedOfTheEngineUntilItIsDone(t *testing.T) {
	r := newReceiveRig(t, "engine.remove.example.")
	r.leads(roleA)
	r.heldForN(r.n, time.Now(), "ns1.n.example.")
	w := &Withdraw{Provider: roleN, RRtype: "NS"}
	done := func() bool {
		rb := &r.conf.InternalMp.reconciles
		rb.mu.Lock()
		defer rb.mu.Unlock()
		return rb.zone(canonicalName(r.zone)).withdrawn[withdrawnKey(roleN, "NS")]
	}
	sent := r.sent()[freezeCombiner]
	r.conf.planWithdraw(r.zdr, ZoneName(r.zone), w)
	r.conf.planWithdraw(r.zdr, ZoneName(r.zone), w)
	if r.sent()[freezeCombiner] != sent+1 {
		t.Errorf("queued %v: want one withdrawal handed to the combiner", r.sent())
	}
	if done() {
		t.Fatal("done with its records still pending removal")
	}
	od, _ := r.zdr.Repo.Get(ZoneName(r.zone))
	nod, _ := od.Get(roleN)
	nod.RRtypes.Delete(dns.TypeNS)
	r.conf.planWithdraw(r.zdr, ZoneName(r.zone), w)
	if !done() {
		t.Error("not done with no record held")
	}
}

// The default stand-in for the turn's ask: a full queue is no failure, the
// next turn asks again.
func TestAFullEngineQueueDoesNotHoldTheTurn(t *testing.T) {
	q := make(chan *SynchedDataCmd, 1)
	q <- &SynchedDataCmd{}
	conf := &Config{}
	conf.InternalMp.MsgQs = &MsgQs{SynchedDataCmd: q}
	finished := make(chan struct{})
	go func() {
		askWithdrawal(conf, "full.remove.example.", Withdraw{Provider: roleN, RRtype: "NS"})
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the turn waits for a full queue")
	}
}

// activeSeven is the zone's active serial 7 in the judge's tests below: alpha
// and beta serve, alpha signs.
func activeSeven(t *testing.T, s *InstructionStore) {
	t.Helper()
	noteKnown(t, s, storeZone, readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="7" servers="alpha,beta" signers="alpha"`))
}

// A removal has its steps: it is agreed on, the zone frozen and the active
// serial where it was.
func TestARemovalIsAgreedOn(t *testing.T) {
	s := newStore(t)
	activeSeven(t, s)
	s.Note(storeZone, readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha"`), nil)
	st := status(t, s, storeZone)
	if st.Active == nil || st.Active.Serial != 7 {
		t.Fatalf("a removal took effect at once: %s", st.Line())
	}
	if st.Agreeing == nil || st.Agreeing.Serial != 8 || len(st.Refused) != 0 || len(s.frozen(storeZone)) == 0 {
		t.Errorf("a removal not agreed on: %s", st.Line())
	}
}

// A serial is judged whole: a removal in one edit with a kind not built has no
// steps, and the zone stays at its active serial, frozen for nothing. The owner
// publishes the removal alone. pubkey's step lands last, with S21.
func TestARemovalWithAKindNotBuiltIsRefusedWhole(t *testing.T) {
	s := newStore(t)
	activeSeven(t, s)
	s.Note(storeZone, readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha" pubkey`), nil)
	st := status(t, s, storeZone)
	if st.Active == nil || st.Active.Serial != 7 || st.Agreeing != nil || len(s.frozen(storeZone)) != 0 {
		t.Fatalf("a removal with a kind not built: %s", st.Line())
	}
	if len(st.Refused) == 0 || st.Refused[0].Code != RefusedNotBuilt {
		t.Errorf("the refusal: %v", st.Refused)
	}
}

// Removing a record that still has a role is a rule of the design, not a step
// missing (S17b leaves it so): refused.
func TestRemovingARecordThatStillHasARoleStaysRefused(t *testing.T) {
	s := newStore(t)
	activeSeven(t, s)
	s.Note(storeZone, readOf(t, instrBase[0], `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha"`), nil)
	st := status(t, s, storeZone)
	if st.Active == nil || st.Active.Serial != 7 || st.Agreeing != nil {
		t.Fatalf("a record with a role removed: %s", st.Line())
	}
	if len(st.Refused) == 0 || st.Refused[0].Code != RefusedRecordWithRoleRemoved {
		t.Errorf("the refusal: %v", st.Refused)
	}
}

// The owner's order: the roles first, the record later. With the roles gone,
// removing the record has nothing to carry out, and is agreed on.
func TestARecordRemovedAfterItsRolesIsAgreed(t *testing.T) {
	noRole := readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha"`)
	gone := readOf(t, instrBase[0], `3600 IN HSYNCPARAM serial="9" servers="alpha" signers="alpha"`)
	if refs := judgeTransition(noRole, gone); len(refs) != 0 {
		t.Errorf("the record of a provider with no role: %v", refs)
	}
}
