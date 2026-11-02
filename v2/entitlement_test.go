/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
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
	purgeAtCombiner = func(_ *MPTransportBridge, _ ZoneName, origin AgentId, rrtype uint16) {
		r.purged = append(r.purged, strings.TrimSuffix(string(origin), ".")+" "+dns.TypeToString[rrtype])
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
	r := newSweepRig(t, "followed.sweep.example.")
	r.holds(roleN, dns.TypeNS, dns.TypeDNSKEY)
	r.holds(roleB, dns.TypeNS)
	r.store.Note(r.zone, removalAt(t, 43, "agent", "a,n", "a"), nil)
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
