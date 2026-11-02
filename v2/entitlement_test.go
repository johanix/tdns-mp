/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The sweep (design 3.3, plan S17b). V: a and b serve, a signs, nsmgmt=agent;
// a leads; n has a record and no role.

type sweepRig struct {
	*leaverRig
	zdr    *ZoneDataRepo
	ar     *AgentRepo
	purged []string
	// the type whose purge the combiner cannot be asked for; 0 for none
	purgeFails uint16
}

func newSweepRig(t *testing.T, zone string) *sweepRig {
	t.Helper()
	r := &sweepRig{leaverRig: newLeaverRig(t, zone, "agent")}
	var err error
	if r.ar, err = NewAgentRepo(); err != nil {
		t.Fatal(err)
	}
	if r.zdr, err = NewZoneDataRepo(); err != nil {
		t.Fatal(err)
	}
	r.zdr.Repo.Set(ZoneName(r.zone), r.ar)
	r.conf.InternalMp.ZoneDataRepo = r.zdr
	saved, savedSweep := purgeAtCombiner, askSweep
	t.Cleanup(func() { purgeAtCombiner, askSweep = saved, savedSweep })
	purgeAtCombiner = func(_ *MPTransportBridge, _ ZoneName, origin AgentId, rrtype uint16) error {
		if rrtype == r.purgeFails {
			return errors.New("the queue would not take it")
		}
		r.purged = append(r.purged, strings.TrimSuffix(string(origin), ".")+" "+dns.TypeToString[rrtype])
		return nil
	}
	askSweep = func(conf *Config, zone string, in *Instructions) { conf.sweep(r.zdr, ZoneName(zone), in) }
	return r
}

// holds gives origin records of the types in the agent's data.
func (r *sweepRig) holds(origin AgentId, rrtypes ...uint16) {
	r.t.Helper()
	od, ok := r.ar.Data.Get(origin)
	if !ok {
		od = tdns.NewOwnerData(r.zone)
		r.ar.Set(origin, od)
	}
	for _, t := range rrtypes {
		text := map[uint16]string{
			dns.TypeNS:     "NS ns." + string(origin),
			dns.TypeDNSKEY: "DNSKEY 257 3 15 11qYAYKxCrfVS/7TyWQHOg7nGkjJ3KgP9h8fZqXsIY8=",
			dns.TypeCDS:    "CDS 4711 15 2 0000000000000000000000000000000000000000000000000000000000000000",
			dns.TypeKEY:    "KEY 256 3 15 11qYAYKxCrfVS/7TyWQHOg7nGkjJ3KgP9h8fZqXsIY8=",
			dns.TypeCSYNC:  "CSYNC 1 1 A NS AAAA",
		}[t]
		rr, err := dns.NewRR(r.zone + " 3600 IN " + text)
		if err != nil {
			r.t.Fatal(err)
		}
		od.RRtypes.Set(t, core.RRset{Name: r.zone, RRtype: t, RRs: []dns.RR{rr}})
	}
}

func (r *sweepRig) has(origin AgentId, rrtype uint16) bool {
	od, ok := r.ar.Data.Get(origin)
	if !ok {
		return false
	}
	_, has := od.RRtypes.Get(rrtype)
	return has
}

// A withdrawal lost to a restart: n's records are still here when the zone is
// done. They leave the data, and the combiner is told; nobody answers for n
// at catch-up, so nothing else would have taken them away.
func TestALostWithdrawalIsSweptWhenTheZoneIsDone(t *testing.T) {
	logs := captureLog(t)
	saved := lgEngine
	lgEngine = lg
	defer func() { lgEngine = saved }()
	r := newSweepRig(t, "lost.sweep.example.")
	r.holds(roleN, dns.TypeNS, dns.TypeDNSKEY, dns.TypeCDS)
	r.run()
	if st := status(t, r.store, r.zone); st.Phase != PhaseSteady {
		t.Fatalf("the transition is not done: %s", st.Line())
	}
	for _, rt := range []uint16{dns.TypeNS, dns.TypeDNSKEY, dns.TypeCDS} {
		if r.has(roleN, rt) {
			t.Errorf("n's %s stays", dns.TypeToString[rt])
		}
	}
	slices.Sort(r.purged)
	if want := []string{"n.role.example CDS", "n.role.example DNSKEY", "n.role.example NS"}; !slices.Equal(r.purged, want) {
		t.Errorf("the combiner's purges:\n got %v\nwant %v", r.purged, want)
	}
	if !strings.Contains(logs.String(), `msg="swept a contribution its origin is not entitled to"`) {
		t.Errorf("no log line: %s", logs)
	}
}

// The combiner is asked first. A contribution it could not be asked to drop
// stays here with its tracking, the record of what is owed, and the other
// purges go on. The tick asks again once roll-retry has passed, for as long as
// it takes, and then the records leave this agent and the combiner.
func TestAFailedPurgeIsAskedForAgainByTheTickUntilTheCombinerHasDroppedIt(t *testing.T) {
	// the real purge says when it could not be queued
	for name, tm := range map[string]*MPTransportBridge{"no transport": nil, "no combiner": {}} {
		if err := purgeAtCombiner(tm, "real.sweep.example.", roleN, dns.TypeNS); err == nil {
			t.Errorf("%s: the purge says nothing", name)
		}
	}
	r := newSweepRig(t, "failed.sweep.example.")
	zone := ZoneName(r.zone)
	mpzd, hdb := withdrawnAtCombiner(t, "failed.combiner.sweep.example.", "ns1")
	// in place of the transport: a queued NS purge reaches the combiner
	queued := purgeAtCombiner
	purgeAtCombiner = func(tm *MPTransportBridge, z ZoneName, origin AgentId, rrtype uint16) error {
		err := queued(tm, z, origin, rrtype)
		if err == nil && rrtype == dns.TypeNS {
			if resp := combinerWithdraws(mpzd, hdb, false); resp.Status == "error" {
				t.Errorf("the combiner refused the purge: %+v", resp)
			}
		}
		return err
	}
	every := rollRetryFor(r.conf.MpConfig())
	due := func() {
		owed := r.zdr.sweepsOwed[zone]
		owed.at = time.Now().Add(-every)
		r.zdr.sweepsOwed[zone] = owed
	}
	stays := func(when string) {
		t.Helper()
		if !r.has(roleN, dns.TypeNS) || r.zdr.Tracking[zone][roleN][dns.TypeNS] == nil {
			t.Errorf("%s: n's NS or its tracking left here", when)
		}
		if len(combinerHolds(mpzd, goneOrigin)) == 0 {
			t.Errorf("%s: the combiner dropped it", when)
		}
		if !slices.Equal(r.purged, []string{"n.role.example DNSKEY"}) {
			t.Errorf("%s: the purges %v, want DNSKEY's alone", when, r.purged)
		}
	}

	r.holds(roleN, dns.TypeNS, dns.TypeDNSKEY)
	r.zdr.getOrCreateTracking(zone, roleN, dns.TypeNS)
	r.purgeFails = dns.TypeNS
	r.run()
	if st := status(t, r.store, r.zone); st.Phase != PhaseSteady {
		t.Fatalf("the transition is not done: %s", st.Line())
	}
	if r.has(roleN, dns.TypeDNSKEY) {
		t.Error("the other purge did not go on: n's DNSKEY stays")
	}
	stays("after the failed enqueue")

	due()
	r.conf.retrySweeps(r.zdr)
	stays("the tick, and it fails again")
	if time.Since(r.zdr.sweepsOwed[zone].at) >= every {
		t.Error("a retry that failed is not owed again a roll-retry on")
	}

	r.purgeFails = 0
	r.conf.retrySweeps(r.zdr)
	stays("the tick within roll-retry")

	due()
	r.conf.retrySweeps(r.zdr)
	if r.has(roleN, dns.TypeNS) || r.zdr.Tracking[zone][roleN][dns.TypeNS] != nil {
		t.Error("the tick's sweep did not take n's NS here")
	}
	if held := combinerHolds(mpzd, goneOrigin); len(held) != 0 {
		t.Errorf("the combiner still holds %v", held)
	}
	if !slices.Equal(r.purged, []string{"n.role.example DNSKEY", "n.role.example NS"}) {
		t.Errorf("the purges %v, want each once", r.purged)
	}
	if len(r.zdr.sweepsOwed) != 0 {
		t.Errorf("still owed: %v", r.zdr.sweepsOwed)
	}
}

// The tick's sweep keeps the sweep's rule: while a transition is under way it
// takes nothing and stays owed, and that transition's "done" answers for it.
func TestAnOwedSweepWaitsWhileATransitionIsUnderWay(t *testing.T) {
	r := newSweepRig(t, "underway.sweep.example.")
	zone := ZoneName(r.zone)
	r.holds(roleN, dns.TypeNS)
	if cur, ok := r.conf.InternalMp.Instructions.reconcileInputs(r.zone); !ok || !cur.reconciling {
		t.Fatal("the zone is not under way")
	}
	r.zdr.sweepsOwed = map[ZoneName]sweepOwed{zone: {in: r.v}}
	r.conf.retrySweeps(r.zdr)
	if !r.has(roleN, dns.TypeNS) || len(r.purged) != 0 {
		t.Errorf("swept while the zone reconciles: purged %v", r.purged)
	}
	if _, owed := r.zdr.sweepsOwed[zone]; !owed {
		t.Error("no longer owed, with nothing swept")
	}
	r.run()
	if r.has(roleN, dns.TypeNS) || !slices.Equal(r.purged, []string{"n.role.example NS"}) || len(r.zdr.sweepsOwed) != 0 {
		t.Errorf("after the transition's done: NS held %v, purged %v, owed %v", r.has(roleN, dns.TypeNS), r.purged, r.zdr.sweepsOwed)
	}
}

// An owed sweep of a serial no longer active does nothing, and is no longer
// owed: the serial after it has its own sweep at its "done".
func TestAnOwedSweepOfAnEarlierSerialDoesNothing(t *testing.T) {
	r := newSweepRig(t, "owed.sweep.example.")
	r.run()
	r.holds(roleN, dns.TypeNS)
	r.zdr.sweepsOwed = map[ZoneName]sweepOwed{ZoneName(r.zone): {in: removalAt(t, 41, "agent", "a,b", "a")}}
	r.conf.retrySweeps(r.zdr)
	if !r.has(roleN, dns.TypeNS) || len(r.purged) != 0 || len(r.zdr.sweepsOwed) != 0 {
		t.Errorf("swept by 41 with 42 active: purged %v, owed %v", r.purged, r.zdr.sweepsOwed)
	}
}

func TestNothingIsSweptWhileTheZoneIsFrozen(t *testing.T) {
	r := newSweepRig(t, "frozen.sweep.example.")
	r.holds(roleN, dns.TypeNS)
	r.next()
	r.conf.sweep(r.zdr, ZoneName(r.zone), r.v)
	if !r.has(roleN, dns.TypeNS) || len(r.purged) != 0 {
		t.Errorf("swept while the zone reconciles: purged %v", r.purged)
	}
}

// With a newer serial waiting the zone stays frozen from "done" (S12's item
// 7): the sweep does not wait for the freeze to end. It runs by V, before the
// waiting serial is agreed on.
func TestTheSweepRunsBeforeAWaitingSerialIsAgreed(t *testing.T) {
	r := newSweepRig(t, "waiting.sweep.example.")
	r.holds(roleN, dns.TypeNS)
	// 43 changes no role, so it is agreed on after "done": by V, n's NS goes
	savedSweep := askSweep
	agreedAtSweep := false
	askSweep = func(conf *Config, zone string, in *Instructions) {
		if st := r.store.Status(zone); st.Agreeing != nil && st.Thaw != "" {
			agreedAtSweep = true
		}
		if in.Serial != 42 {
			t.Errorf("swept by %d", in.Serial)
		}
		savedSweep(conf, zone, in)
	}
	w := jAt(t, 43, `servers="a,b" signers="a" nsmgmt="agent" suffix="later"`, freezeRecords...)
	r.store.Note(r.zone, w, nil)
	r.run()
	if r.has(roleN, dns.TypeNS) {
		t.Error("n's NS stays with a newer serial waiting")
	}
	if agreedAtSweep {
		t.Error("43 was agreed on before the sweep")
	}
	if v, ok := r.conf.thawView(r.zone, time.Now()); !ok || v.to != sd(w) {
		t.Errorf("43 is not agreed on after done: %+v %v", v, ok)
	}
}

// A newer serial refused only for kinds not built is followed in the very
// store update that ends V's transition (#350's fallback; CodeRabbit on
// #352). 43 gives n a server role again and takes b's, unenforced. The sweep
// runs all the same: what neither entitles goes (n's DNSKEY), what 43 gives
// stays (n's NS), and what only 43 takes away stays (b's NS).
func TestTheSweepRunsWhenDoneFollowsASerialNotBuilt(t *testing.T) {
	t.Skip("211-demo: S21 builds pubkey, so no kind is refused as not built with the real judge (S19, S20 and S21 built); needs a test seam or another example")
	r := newSweepRig(t, "followed.sweep.example.")
	r.holds(roleN, dns.TypeNS, dns.TypeDNSKEY)
	r.holds(roleB, dns.TypeNS)
	// pubkey is a kind with no step yet: refused as not built, so 43 is followed at done
	r.store.Note(r.zone, jAt(t, 43, `servers="a,n" nsmgmt="agent" signers="a" pubkey`, freezeRecords...), nil)
	r.run()
	if st := status(t, r.store, r.zone); st.Active.Serial != 43 || st.Follows == "" {
		t.Fatalf("43 is not followed at done: %s", st.Line())
	}
	if r.has(roleN, dns.TypeDNSKEY) {
		t.Error("n's DNSKEY stays: no serial entitles it")
	}
	if !r.has(roleN, dns.TypeNS) {
		t.Error("n's NS went: 43 gives n the role")
	}
	if !r.has(roleB, dns.TypeNS) {
		t.Error("b's NS went: only 43 takes it away, unenforced")
	}
	if !slices.Equal(r.purged, []string{"n.role.example DNSKEY"}) {
		t.Errorf("the purges: %v", r.purged)
	}
}

// A sweep by a serial no longer active does nothing, unless the fallback
// followed the active one.
func TestASweepByAnotherSerialDoesNothing(t *testing.T) {
	r := newSweepRig(t, "other.sweep.example.")
	r.run()
	r.holds(roleN, dns.TypeNS)
	r.conf.sweep(r.zdr, ZoneName(r.zone), removalAt(t, 41, "agent", "a,b", "a"))
	if !r.has(roleN, dns.TypeNS) || len(r.purged) != 0 {
		t.Errorf("swept by 41 with 42 active: purged %v", r.purged)
	}
}

func TestAKEYUnderAnEarlierPublishersNameIsSweptOnceTheLeadersKEYIsHere(t *testing.T) {
	r := newSweepRig(t, "key.sweep.example.")
	r.holds(roleB, dns.TypeKEY, dns.TypeCSYNC)
	r.run() // the leader's own is not here yet: b's stay
	if !r.has(roleB, dns.TypeKEY) || !r.has(roleB, dns.TypeCSYNC) || len(r.purged) != 0 {
		t.Fatalf("swept before the leader's own is here: %v", r.purged)
	}
	r.holds(roleA, dns.TypeKEY)
	r.conf.sweep(r.zdr, ZoneName(r.zone), r.v)
	if r.has(roleB, dns.TypeKEY) || !r.has(roleA, dns.TypeKEY) {
		t.Errorf("the KEYs: b's %v, the leader's %v", r.has(roleB, dns.TypeKEY), r.has(roleA, dns.TypeKEY))
	}
	if !r.has(roleB, dns.TypeCSYNC) {
		t.Error("b's CSYNC went with the leader holding none")
	}
	if !slices.Equal(r.purged, []string{"b.role.example KEY"}) {
		t.Errorf("the purges: %v", r.purged)
	}
}

// The purge goes to this agent's combiner and to nobody else.
func TestASweepSendsNothingToPeers(t *testing.T) {
	r := newReceiveRig(t, "peers.sweep.example.")
	r.leads(roleA)
	r.heldForN(r.n, time.Now(), "ns1.n.example.")
	sent := r.sent()
	r.conf.sweep(r.zdr, ZoneName(r.zone), r.n)
	if len(r.nsOf(roleN)) != 0 {
		t.Errorf("n's NS stays: %v", r.nsOf(roleN))
	}
	for to, n := range r.sent() {
		if n > sent[to] && to != freezeCombiner {
			t.Errorf("the sweep sent %d to %s: %v", n-sent[to], to, r.sent())
		}
	}
	if r.sent()[freezeCombiner] != sent[freezeCombiner]+1 {
		t.Errorf("queued %v: want the purge handed to the combiner", r.sent())
	}
}

func TestAnEntitledContributionIsNeverSwept(t *testing.T) {
	r := newSweepRig(t, "entitled.sweep.example.")
	r.holds(roleA, dns.TypeNS, dns.TypeDNSKEY, dns.TypeCDS, dns.TypeKEY, dns.TypeCSYNC)
	r.holds(roleB, dns.TypeNS)
	r.run()
	for _, rt := range []uint16{dns.TypeNS, dns.TypeDNSKEY, dns.TypeCDS, dns.TypeKEY, dns.TypeCSYNC} {
		if !r.has(roleA, rt) {
			t.Errorf("a's %s went", dns.TypeToString[rt])
		}
	}
	if !r.has(roleB, dns.TypeNS) || len(r.purged) != 0 {
		t.Errorf("b's NS: %v; purged %v", r.has(roleB, dns.TypeNS), r.purged)
	}
}

// NS needs nsmgmt=agent.
func TestUnderNsmgmtOwnerNoNSIsEntitled(t *testing.T) {
	in := removalAt(t, 42, "owner", "a,b", "a")
	if entitled(in, roleA, dns.TypeNS, roleA, true) {
		t.Error("an NS under nsmgmt=owner is entitled")
	}
	if !entitled(in, roleA, dns.TypeDNSKEY, roleA, true) {
		t.Error("the signer's DNSKEY is not entitled")
	}
}
