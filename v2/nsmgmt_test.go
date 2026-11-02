/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Plan S19: a change of nsmgmt has a step of its own (design 5.4), and under
// nsmgmt=owner every agent reports an owner's NS RRset that names a provider
// whose role is not done (design 3.7).

// nsToTheAgents has the zone's HSYNCPARAM say nsmgmt=agent, for a test of an
// agent that holds NS records: under the default nsmgmt=owner it holds none.
func nsToTheAgents(t *testing.T, zd *tdns.ZoneData) {
	t.Helper()
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex not found for %s: %v", zd.ZoneName, err)
	}
	rrset := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNCPARAM)
	if len(rrset.RRs) != 1 {
		t.Fatalf("%s has %d HSYNCPARAM records", zd.ZoneName, len(rrset.RRs))
	}
	hp, ok := rrset.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM)
	if !ok {
		t.Fatalf("%s: not an HSYNCPARAM", zd.ZoneName)
	}
	hp.Value = append(hp.Value, &core.HSYNCPARAMNSmgmt{Value: core.HsyncNSmgmtAGENT})
	zd.Data.Set(zd.ZoneName, *apex)
	zd.InstallInitialSnapshot()
}

// stepHandover is the hand-over of V's records at a step whose sets hand
// nsmgmt, as the leader's step makes it.
func stepHandover(t *testing.T, zone string, step int, nsmgmt uint8, records ...string) *ActingHandover {
	t.Helper()
	h := handoverFor(t, zone, records...)
	h.Step, h.Phase = step, PhaseReconciling
	h.Sets.NSmgmt = nsmgmt
	return h
}

// nsRRs are an origin's NS records for the zone's apex.
func nsRRs(t *testing.T, zone string, targets ...string) []dns.RR {
	t.Helper()
	var out []dns.RR
	for _, target := range targets {
		out = append(out, mustRR(t, zone+" 3600 IN NS "+target))
	}
	return out
}

// storedNS is what the combiner stores of the origin's NS.
func storedNS(mpzd *MPZoneData, origin string) []dns.RR {
	mpzd.Lock()
	defer mpzd.Unlock()
	return mpzd.MP.AgentContributions[origin][mpzd.ZoneName][dns.TypeNS].RRs
}

func nsTargets(rrs []string) []string {
	var out []string
	for _, s := range rrs {
		out = append(out, s[strings.LastIndexAny(s, " \t")+1:])
	}
	slices.Sort(out)
	return out
}

// To the owner: at the step that hands the role, a combiner stops applying
// the NS of every origin, its own agent's and the others', and serves the
// owner's; what it stored of them is gone, and a contribution that arrives
// late is stored and not applied.
func TestNsmgmtToOwnerStopsApplyingAgentNSAtEveryCombiner(t *testing.T) {
	const zone = "toowner.nsmgmt.example."
	records := func(serial, nsmgmt string) []string {
		return actRecords(`serial="` + serial + `" servers="alpha,beta" nsmgmt="` + nsmgmt + `"`)
	}
	conf, mpzd := actingCombiner(t, zone, records("5", "agent")...)
	withActing(t, nil)
	if resp := handTo(conf, handoverFor(t, zone, records("5", "agent")...), actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	for origin, target := range map[string]string{actUs: "ns.alpha.example.", actOther: "ns.beta.example."} {
		if _, _, _, err := mpzd.ReplaceCombinerDataByRRtype(origin, zone, dns.TypeNS, nsRRs(t, zone, target)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := mpzd.CombineWithLocalChanges(); err != nil {
		t.Fatal(err)
	}
	if got := nsTargets(servedTypes(t, mpzd, dns.TypeNS)); !slices.Contains(got, "ns.alpha.example.") || !slices.Contains(got, "ns.beta.example.") {
		t.Fatalf("under nsmgmt=agent the zone serves %v, without the contributions", got)
	}

	// V's step 0: the sets held, so the role stays and so does what is stored
	v := records("6", "owner")
	if resp := handTo(conf, stepHandover(t, zone, 0, core.HsyncNSmgmtAGENT, v...), actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if got := nsTargets(servedTypes(t, mpzd, dns.TypeNS)); !slices.Contains(got, "ns.beta.example.") {
		t.Fatalf("at step 0 the zone serves %v: the role changed before its step", got)
	}

	if resp := handTo(conf, stepHandover(t, zone, 1, core.HsyncNSmgmtOWNER, v...), actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if got := nsTargets(servedTypes(t, mpzd, dns.TypeNS)); !slices.Equal(got, []string{"ns1." + zone}) {
		t.Errorf("at the step the zone serves %v, want the owner's alone", got)
	}
	for _, origin := range []string{actUs, actOther} {
		if got := storedNS(mpzd, origin); len(got) != 0 {
			t.Errorf("%s's NS is still stored: %v", origin, got)
		}
	}
	if p := mpzd.getEditPolicy(); p.canApply(dns.TypeNS) {
		t.Error("the edit policy still lets the combiner apply NS")
	}

	if _, _, _, err := mpzd.ReplaceCombinerDataByRRtype(actOther, zone, dns.TypeNS, nsRRs(t, zone, "ns.late.example.")); err != nil {
		t.Fatal(err)
	}
	if _, err := mpzd.CombineWithLocalChanges(); err != nil {
		t.Fatal(err)
	}
	if got := nsTargets(servedTypes(t, mpzd, dns.TypeNS)); !slices.Equal(got, []string{"ns1." + zone}) {
		t.Errorf("a late contribution reached the zone: %v", got)
	}
}

// To the agents: what is stored is dropped at the step, persisted, and comes
// back neither by itself nor at a restart. An operator's contribution is
// applied, and only it.
func TestNsmgmtToAgentsRevivesNoStoredNS(t *testing.T) {
	const zone = "toagents.nsmgmt.example."
	hdb := NewHsyncDB(newMPTestKeyDB(t))
	if err := hdb.InitCombinerEditTables(); err != nil {
		t.Fatalf("the combiner's tables: %v", err)
	}
	records := func(serial, nsmgmt string) []string {
		return actRecords(`serial="` + serial + `" servers="alpha,beta" nsmgmt="` + nsmgmt + `"`)
	}
	conf, mpzd := actingCombiner(t, zone, records("5", "owner")...)
	mpzd.restoreContributions(hdb, nil, true)
	withActing(t, hdb)
	if resp := handTo(conf, handoverFor(t, zone, records("5", "owner")...), actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	// stored under nsmgmt=owner, and not applied: a late contribution
	if _, _, _, err := mpzd.ReplaceCombinerDataByRRtype(actOther, zone, dns.TypeNS, nsRRs(t, zone, "ns.stale.example.")); err != nil {
		t.Fatal(err)
	}
	// one that stays: the step touches no other type
	if _, _, _, err := mpzd.ReplaceCombinerDataByRRtype(actOther, zone, dns.TypeCSYNC, []dns.RR{mustRR(t, zone+" 3600 IN CSYNC 7 1 NS")}); err != nil {
		t.Fatal(err)
	}

	v := records("6", "agent")
	if resp := handTo(conf, stepHandover(t, zone, 0, core.HsyncNSmgmtOWNER, v...), actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if len(storedNS(mpzd, actOther)) != 1 {
		t.Fatal("at step 0, whose sets hold the role, the stored NS went")
	}
	if resp := handTo(conf, stepHandover(t, zone, 1, core.HsyncNSmgmtAGENT, v...), actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if got := nsTargets(servedTypes(t, mpzd, dns.TypeNS)); !slices.Equal(got, []string{"ns1." + zone}) {
		t.Errorf("at the step the zone serves %v: a stored NS came back by itself", got)
	}
	if got := storedNS(mpzd, actOther); len(got) != 0 {
		t.Errorf("the stored NS is still there: %v", got)
	}

	// the drop is on disk: a restart restores no NS, and the other type
	stored, err := LoadAllContributions(hdb)
	if err != nil {
		t.Fatal(err)
	}
	if rrset, ok := stored[zone][actOther][zone][dns.TypeNS]; ok {
		t.Errorf("the store still holds %v", rrset.RRs)
	}
	if _, ok := stored[zone][actOther][zone][dns.TypeCSYNC]; !ok {
		t.Error("the step dropped the CSYNC too")
	}

	if _, _, _, err := mpzd.ReplaceCombinerDataByRRtype(actUs, zone, dns.TypeNS, nsRRs(t, zone, "ns.alpha.example.")); err != nil {
		t.Fatal(err)
	}
	if _, err := mpzd.CombineWithLocalChanges(); err != nil {
		t.Fatal(err)
	}
	if got := nsTargets(servedTypes(t, mpzd, dns.TypeNS)); !slices.Contains(got, "ns.alpha.example.") || slices.Contains(got, "ns.stale.example.") {
		t.Errorf("after an operator's contribution the zone serves %v", got)
	}
}

// A hand-over whose drop cannot be kept is refused, the NS stays stored, as
// the store still holds it, and the same hand-over drops it once it can.
func TestAHandOverWhoseDropCannotBeKeptIsRefusedAndTriedAgain(t *testing.T) {
	const zone = "faildrop.nsmgmt.example."
	records := func(serial, nsmgmt string) []string {
		return actRecords(`serial="` + serial + `" servers="alpha,beta" nsmgmt="` + nsmgmt + `"`)
	}
	conf, mpzd := actingCombiner(t, zone, records("5", "agent")...)
	store := withActing(t, nil)
	if resp := handTo(conf, handoverFor(t, zone, records("5", "agent")...), actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if _, _, _, err := mpzd.ReplaceCombinerDataByRRtype(actOther, zone, dns.TypeNS, nsRRs(t, zone, "ns.beta.example.")); err != nil {
		t.Fatal(err)
	}
	mpzd.MP.PersistContributions = func(string, string, map[string]map[uint16]core.RRset) error { return errors.New("the disk is full") }
	h := stepHandover(t, zone, 1, core.HsyncNSmgmtOWNER, records("6", "owner")...)
	if resp := handTo(conf, h, actUs); resp.Status != "error" || !strings.Contains(resp.Message, "the disk is full") {
		t.Fatalf("the answer: %s %q", resp.Status, resp.Message)
	}
	if got := storedNS(mpzd, actOther); len(got) != 1 {
		t.Errorf("the store holds it, and memory %v", got)
	}
	if held, ok := store.get(zone); !ok || held.handover.Serial != 5 {
		t.Errorf("the refused hand-over was kept: %+v", held.handover)
	}
	mpzd.MP.PersistContributions = nil
	if resp := handTo(conf, h, actUs); resp.Status != "ok" {
		t.Fatalf("refused again: %s", resp.Message)
	}
	if got := storedNS(mpzd, actOther); len(got) != 0 {
		t.Errorf("after the hand-over again the NS is still stored: %v", got)
	}
}

// A first hand-over changes no handed role: a combiner holding nothing, whose
// agent hands another nsmgmt than its copy says, keeps what it stores.
func TestAFirstHandOverDropsNoStoredNS(t *testing.T) {
	const zone = "firsthand.nsmgmt.example."
	conf, mpzd := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" nsmgmt="owner"`)...)
	withActing(t, nil)
	if _, _, _, err := mpzd.ReplaceCombinerDataByRRtype(actOther, zone, dns.TypeNS, nsRRs(t, zone, "ns.beta.example.")); err != nil {
		t.Fatal(err)
	}
	if resp := handTo(conf, handoverFor(t, zone, actRecords(`serial="6" servers="alpha,beta" nsmgmt="agent"`)...), actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if got := storedNS(mpzd, actOther); len(got) != 1 {
		t.Errorf("the first hand-over dropped what is stored: %v", got)
	}
}

// nsmgmtRig is the reconciliation's rig on a zone whose nsmgmt changes from
// from to to, thawed by the judge's own word, with the data engine running.
type nsmgmtRig struct {
	*reconcileRig
}

func newNsmgmtRig(t *testing.T, zone, from, to string) *nsmgmtRig {
	t.Helper()
	r := &nsmgmtRig{reconcileRig: newReconcileRig(t, zone, roleA)}
	if err := r.store.Forget(zone); err != nil {
		t.Fatal(err)
	}
	r.n = jAt(t, 41, `servers="a,b" nsmgmt="`+from+`" suffix="n"`, freezeRecords...)
	r.v = jAt(t, 42, `servers="a,b" nsmgmt="`+to+`" suffix="v"`, freezeRecords...)
	knownAs(t, r.store, zone, r.n)
	return r
}

// runEngine runs the data engine, which owns the agent's data, for the test.
func (r *nsmgmtRig) runEngine() {
	r.t.Helper()
	ctx, cancel := context.WithCancel(r.t.Context())
	done := make(chan struct{})
	go func() { defer close(done); r.conf.SynchedDataEngine(ctx, r.conf.InternalMp.MsgQs) }()
	r.t.Cleanup(func() {
		cancel()
		<-done
		r.conf.InternalMp.ownReads.Wait()
	})
	r.repo()
}

// reads has the engine apply what the combiner answers an own read with.
func (r *nsmgmtRig) reads(recs map[string]map[string][]string) {
	r.t.Helper()
	r.conf.InternalMp.MsgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "own-read", Zone: ZoneName(r.zone), ownRead: &ownReadAnswer{
		zone: ZoneName(r.zone), asked: true, sentAt: time.Now(), resp: &EditsResponseMsg{Message: editsLoaded, AgentRecords: recs}}}
}

// repo is what the engine's data holds, on the engine's own loop.
func (r *nsmgmtRig) repo() map[AgentId]map[uint16][]TrackedRRInfo {
	r.t.Helper()
	resp := make(chan *SynchedDataCmdResponse, 1)
	r.conf.InternalMp.MsgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "dump-zonedatarepo", Zone: ZoneName(r.zone), Response: resp}
	got, ok := recvWithin(resp, 5*time.Second)
	if !ok {
		r.t.Fatal("the engine did not answer")
	}
	return got.ZDR[ZoneName(r.zone)]
}

// firstStep has the leader thaw the zone and take its first step.
func (r *nsmgmtRig) firstStep() {
	r.t.Helper()
	r.agree()
	if st := status(r.t, r.store, r.zone); len(st.Refused) != 0 {
		r.t.Fatalf("the judge refuses the change: %v", st.Refused)
	}
	r.thawNow()
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
}

func (r *nsmgmtRig) nsRecord(target string) string { return r.zone + " 3600 IN NS " + target }

// To the owner: at the step every agent drops the NS from its data, its own
// and the others', which a resync would hand its combiner again. Its other
// data stays.
func TestNsmgmtToOwnerDropsEachAgentsOwnNS(t *testing.T) {
	r := newNsmgmtRig(t, "dropown.nsmgmt.example.", "agent", "owner")
	r.runEngine()
	cds := &dns.CDS{DS: *testDnskey(t, r.zone, 257).ToDS(dns.SHA256)}
	cds.Hdr = dns.RR_Header{Name: r.zone, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 120}
	r.reads(map[string]map[string][]string{
		roleA: {r.zone: {r.nsRecord("ns.a.example."), cds.String()}},
		roleB: {r.zone: {r.nsRecord("ns.b.example.")}},
	})
	got := r.repo()
	if len(got[roleA][dns.TypeNS]) != 1 || len(got[roleB][dns.TypeNS]) != 1 {
		t.Fatalf("under nsmgmt=agent the data holds %+v", got)
	}

	r.agree()
	r.thawNow()
	if got := r.repo(); len(got[roleA][dns.TypeNS]) != 1 {
		t.Fatalf("at the thaw, before the step, this agent's NS went: %+v", got)
	}
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	got = r.repo()
	if len(got[roleA][dns.TypeNS]) != 0 || len(got[roleB][dns.TypeNS]) != 0 {
		t.Errorf("at the step the data holds %+v", got)
	}
	if len(got[roleA][dns.TypeCDS]) != 1 {
		t.Errorf("the step took this agent's CDS too: %+v", got)
	}
	if owed := r.conf.InternalMp.ZoneDataRepo.Tracking[ZoneName(r.zone)][roleA][dns.TypeNS]; owed != nil {
		t.Errorf("the tracking of its NS stays: %+v", owed)
	}
}

// To the agents: a peer's NS that arrived late under nsmgmt=owner does not
// outlast the change, where a resync would hand it to the combiner again.
func TestNsmgmtToAgentsLeavesNoNSInTheAgentsData(t *testing.T) {
	r := newNsmgmtRig(t, "toagentsdata.nsmgmt.example.", "owner", "agent")
	r.runEngine()
	mpzd, _ := Zones.Get(r.zone)
	r.conf.followNSmgmt(mpzd) // the look of the zone's load: no change

	r.agree()
	r.thawNow()
	r.conf.InternalMp.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: ZoneName(r.zone), AgentId: roleB, UpdateType: "remote",
		Update: &ZoneUpdate{Zone: ZoneName(r.zone), AgentId: roleB, Operations: []core.RROperation{{Operation: "replace", RRtype: "NS", Records: []string{r.nsRecord("ns.late.example.")}}}}}
	for deadline := time.Now().Add(5 * time.Second); len(r.repo()[roleB][dns.TypeNS]) == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the late NS did not reach the data")
		}
	}
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	if rolesForZone(ZoneName(r.zone)).NSmgmt != core.HsyncNSmgmtAGENT {
		t.Fatal("the step did not hand the role")
	}
	if got := r.repo(); len(got[roleB][dns.TypeNS]) != 0 {
		t.Errorf("after the step the data still holds the late NS: %+v", got)
	}
}

// An own read under nsmgmt=owner takes no NS: what the combiner stores of a
// late contribution is no agent's data. A zone whose instructions are not
// known reads as no such zone.
func TestAnOwnReadUnderNsmgmtOwnerTakesNoNS(t *testing.T) {
	r := newOwnRig(t, "ownread.nsmgmt.example.")
	ns := string(r.zone) + " 3600 IN NS ns.a.role.example."
	s := newStore(t)
	withStore(t, s)
	activeAs(t, s, string(r.zone), jAt(t, 7, `servers="a,b" nsmgmt="owner"`, freezeRecords...))
	r.apply(editsLoaded, time.Now(), r.records(roleA, ns))
	if got := r.holds(roleA, dns.TypeNS); len(got) != 0 {
		t.Errorf("an own read under nsmgmt=owner brought %v", got)
	}
	activeAs(t, s, string(r.zone), jAt(t, 8, `servers="a,b" nsmgmt="agent"`, freezeRecords...))
	r.apply(editsLoaded, time.Now(), r.records(roleA, ns))
	if got := r.holds(roleA, dns.TypeNS); len(got) != 1 {
		t.Errorf("an own read under nsmgmt=agent brought %v", got)
	}
	if nsLeftToOwner("nosuch.nsmgmt.example.") {
		t.Error("a zone whose instructions are not known reads as left to the owner")
	}
}

// The engine's round drops what the agent's data holds under nsmgmt=owner, a
// late message or a request a full queue did not take, and nothing under
// nsmgmt=agent.
func TestTheEnginesRoundDropsNSUnderNsmgmtOwner(t *testing.T) {
	r := newReconcileRig(t, "round.nsmgmt.example.", roleA)
	s := r.store
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	zone := ZoneName(r.zone)
	zdr.AddConfirmedRR(zone, roleB, mustRR(t, r.zone+" 3600 IN NS ns.b.example."))
	activeAs(t, s, r.zone, jAt(t, 43, `servers="a,b" nsmgmt="agent"`, freezeRecords...))
	r.conf.nsmgmtRound(zdr, time.Now())
	if !zdr.holdsNS(zone) {
		t.Fatal("the round dropped NS under nsmgmt=agent")
	}
	activeAs(t, s, r.zone, jAt(t, 44, `servers="a,b" nsmgmt="owner"`, freezeRecords...))
	r.conf.nsmgmtRound(zdr, time.Now())
	if zdr.holdsNS(zone) {
		t.Error("the round left NS under nsmgmt=owner")
	}
}

// The round runs on the engine's own ticker: a peer's NS that arrives under
// nsmgmt=owner goes with no change of the sets to ask for it.
func TestTheEnginesTickerRunsTheRound(t *testing.T) {
	saved := ownReadInterval
	ownReadInterval = 20 * time.Millisecond
	t.Cleanup(func() { ownReadInterval = saved })
	r := newNsmgmtRig(t, "ticker.nsmgmt.example.", "owner", "owner")
	buf := &lockedBuffer{}
	logTo(t, lgEngine, slog.NewJSONHandler(buf, nil))
	r.runEngine()
	r.conf.InternalMp.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: ZoneName(r.zone), AgentId: roleB, UpdateType: "remote",
		Update: &ZoneUpdate{Zone: ZoneName(r.zone), AgentId: roleB, Operations: []core.RROperation{{Operation: "replace", RRtype: "NS", Records: []string{r.nsRecord("ns.late.example.")}}}}}
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(buf.String(), "the zone's NS is dropped"); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no round dropped the late NS")
		}
	}
	if got := r.repo(); len(got[roleB][dns.TypeNS]) != 0 {
		t.Errorf("the data still holds %+v", got)
	}
}

// A catch-up answer under nsmgmt=owner carries an empty NS set, whatever the
// data still holds; the answer to the same request under nsmgmt=agent names
// the records.
func TestACatchUpAnswerUnderNsmgmtOwnerNamesNoNS(t *testing.T) {
	r := newAnswerRig(t, "answer.nsmgmt.example.", []string{"p2"})
	r.holds(t, r.ns("ns.us.example."))
	if op := ops(r.answer(t))["NS"]; len(op.Records) != 1 {
		t.Fatalf("under nsmgmt=agent the answer's NS: %+v", op)
	}
	s := newStore(t)
	withStore(t, s)
	in := r.mpzd.instructions()
	owner := *in
	owner.NSmgmt, owner.Serial = core.HsyncNSmgmtOWNER, in.Serial+1
	activeAs(t, s, string(r.zone), &owner)
	got := ops(r.answer(t))
	op, ok := got["NS"]
	if !ok || op.Operation != "replace" {
		t.Fatalf("the answer names no NS replace: %+v", got)
	}
	if len(op.Records) != 0 {
		t.Errorf("under nsmgmt=owner the answer's NS: %v", op.Records)
	}
}

// The change takes effect at the runner's step, the first, and not at the
// thaw: until then the parts and the agents' readers keep the role they hold.
// Both ways.
func TestTheNsmgmtChangeTakesEffectAtTheFirstStepNotAtTheThaw(t *testing.T) {
	for _, c := range []struct {
		name, from, to string
		before, after  uint8
		what           string
	}{
		{"to the owner", "agent", "owner", core.HsyncNSmgmtAGENT, core.HsyncNSmgmtOWNER, "NS management to the owner"},
		{"to the agents", "owner", "agent", core.HsyncNSmgmtOWNER, core.HsyncNSmgmtAGENT, "NS management to the agents"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newNsmgmtRig(t, "first"+c.from+".nsmgmt.example.", c.from, c.to)
			mpzd, _ := Zones.Get(r.zone)
			r.agree()
			if st := status(t, r.store, r.zone); len(st.Refused) != 0 {
				t.Fatalf("the judge refuses the change: %v", st.Refused)
			}
			r.thawNow()
			if h := r.wanted(); h == nil || h.Serial != 42 || h.Step != 0 || h.Sets.NSmgmt != c.before {
				t.Fatalf("the hand-over at the thaw: %+v", h)
			}
			if p := mpzd.getEditPolicy(); p.NSmgmt != c.before {
				t.Errorf("the edit policy followed the thaw: %d", p.NSmgmt)
			}
			if got := rolesForZone(ZoneName(r.zone)).NSmgmt; got != c.before {
				t.Errorf("the readers followed the thaw: %d", got)
			}
			r.partsTake()
			r.holdsToo(roleB)
			r.turn(time.Now())
			st, _ := r.step()
			if st.Number != 1 || st.Of != 2 || st.What != c.what || !slices.Equal(st.Taken, []string{nsmgmtStepKey}) {
				t.Fatalf("the first step: %+v", st)
			}
			if h := r.wanted(); h.Step != 1 || h.Sets.NSmgmt != c.after {
				t.Errorf("the hand-over at the first step: %+v", h)
			}
			if p := mpzd.getEditPolicy(); p.NSmgmt != c.after {
				t.Errorf("the edit policy at the first step: %d", p.NSmgmt)
			}

			// done once the parts hold the serial: the last step, and "done"
			r.partsTake()
			r.holdsToo(roleB)
			r.turn(time.Now())
			if st, _ := r.step(); st.Number != 2 || st.Of != 2 || !slices.Equal(st.Taken, []string{nsmgmtStepKey, lastStepKey}) {
				t.Fatalf("the last step: %+v", st)
			}
			r.partsTake()
			r.holdsToo(roleB)
			r.turn(time.Now())
			if r.own().Reconciling {
				t.Error("not done after the last step is held")
			}
		})
	}
}

// A new leader plans again from what is in place: with the role handed, the
// step is not taken again, nor is one planned where the role was never to
// change.
func TestTheNsmgmtStepIsPlannedFromWhatIsInPlace(t *testing.T) {
	owner := jAt(t, 42, `servers="a,b" nsmgmt="owner"`, freezeRecords...)
	held := func(nsmgmt uint8) Roles {
		r := rolesFor(owner, owner, 0)
		r.NSmgmt = nsmgmt
		return r
	}
	keys := func(p planView) []string {
		var out []string
		for _, st := range planSteps(p) {
			if !slices.Contains(p.taken, st.key) {
				out = append(out, st.key)
			}
		}
		return out
	}
	if got := keys(planView{to: owner, held: held(core.HsyncNSmgmtAGENT)}); !slices.Equal(got, []string{nsmgmtStepKey, lastStepKey}) {
		t.Errorf("the role to change: %v", got)
	}
	if got := keys(planView{to: owner, held: held(core.HsyncNSmgmtOWNER), taken: []string{nsmgmtStepKey}}); !slices.Equal(got, []string{lastStepKey}) {
		t.Errorf("the step taken: %v", got)
	}
	if got := keys(planView{to: owner, held: held(core.HsyncNSmgmtOWNER)}); !slices.Equal(got, []string{lastStepKey}) {
		t.Errorf("no change: %v", got)
	}
}

// The join: the leader's step, as its tracker hands it, is what has the
// combiner drop what it stores and stop applying NS.
func TestTheLeadersStepHandsTheCombinerTheRole(t *testing.T) {
	r := newNsmgmtRig(t, "join.nsmgmt.example.", "agent", "owner")
	r.agree()
	r.thawNow()
	h0 := *r.wanted()
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	h1 := *r.wanted()
	raw, err := json.Marshal(h1)
	if err != nil {
		t.Fatal(err)
	}
	var onTheWire ActingHandover
	if err := json.Unmarshal(raw, &onTheWire); err != nil {
		t.Fatal(err)
	}

	mpzd, _ := Zones.Get(r.zone)
	withActing(t, nil)
	take := func(h *ActingHandover) {
		t.Helper()
		resp := r.conf.combinerTakeHandover(&AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{OriginatorID: roleA, DeliveredBy: roleA,
			Zone: ZoneName(r.zone), DistributionID: nextDistributionID(), Acting: h}}, map[string]bool{roleA: true})
		if resp.Status != "ok" {
			t.Fatalf("refused: %s", resp.Message)
		}
	}
	take(&h0)
	if _, _, _, err := mpzd.ReplaceCombinerDataByRRtype(roleB, r.zone, dns.TypeNS, nsRRs(t, r.zone, "ns.b.example.")); err != nil {
		t.Fatal(err)
	}
	if p := mpzd.getEditPolicy(); p.NSmgmt != core.HsyncNSmgmtAGENT {
		t.Fatalf("handed step 0, nsmgmt %d", p.NSmgmt)
	}
	take(&onTheWire)
	if p := mpzd.getEditPolicy(); p.NSmgmt != core.HsyncNSmgmtOWNER {
		t.Errorf("handed the step, nsmgmt %d", p.NSmgmt)
	}
	if got := storedNS(mpzd, roleB); len(got) != 0 {
		t.Errorf("handed the step, the combiner stores %v", got)
	}
}

// reportRig is the reconciliation's rig on a zone whose apex NS the owner has set, under
// the instructions given, with the members' nameservers told as a beat tells
// them.
type reportRig struct {
	*reconcileRig
	mpzd *MPZoneData
}

func newReportRig(t *testing.T, zone string, active *Instructions, ns ...string) *reportRig {
	t.Helper()
	r := &reportRig{reconcileRig: newReconcileRig(t, zone, roleA)}
	r.mpzd, _ = Zones.Get(zone)
	if err := r.store.Forget(zone); err != nil {
		t.Fatal(err)
	}
	r.n = active
	knownAs(t, r.store, zone, active)
	apex, err := r.mpzd.GetOwner(zone)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	var rrs []dns.RR
	for _, name := range ns {
		rrs = append(rrs, mustRR(t, zone+" 3600 IN NS "+name))
	}
	apex.RRtypes.Set(dns.TypeNS, core.RRset{Name: zone, RRtype: dns.TypeNS, RRs: rrs})
	r.mpzd.Data.Set(zone, *apex)
	return r
}

// tellsNameservers has id tell its nameserver names in its stamp row.
func (r *reportRig) tellsNameservers(id string, names ...string) {
	r.seq++
	r.stamps.note(&GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
		id: {Identity: id, Timestamp: time.Now(), Epoch: 1, Seq: r.seq, Crypto: true, Nameservers: names}}}, id, "DNS")
}

func wantReport(t *testing.T, what string, got []string, ids ...string) {
	t.Helper()
	var want []string
	for _, id := range ids {
		want = append(want, "the owner's NS RRset names the servers of "+id+", whose role is not done")
	}
	if !slices.Equal(got, want) {
		t.Errorf("%s: the report %q, want %q", what, got, want)
	}
}

// Under nsmgmt=owner an agent reports the provider whose servers the owner's
// NS RRset names while its role is not done: one with a record and no role,
// one on its way in at the step that does not name it yet; not one that
// serves, and not under nsmgmt=agent. Logged once an hour, with the status's
// line.
func TestTheOwnersNSRRsetNamingAProviderNotDoneIsReported(t *testing.T) {
	const zone = "report.nsmgmt.example."
	r := newReportRig(t, zone, jAt(t, 41, `servers="a,b" nsmgmt="owner" suffix="n"`, freezeRecords...), "ns1.a.example.", "ns1.b.example.", "NS1.N.example.")
	r.tellsNameservers(roleB, "ns1.b.example.")
	wantReport(t, "n tells no names yet", r.conf.ownersNSReport(r.mpzd))
	r.tellsNameservers(roleN, "ns1.n.example.")
	wantReport(t, "n has a record and no role", r.conf.ownersNSReport(r.mpzd), roleN)

	buf := captureLog(t)
	count := func() int { return strings.Count(buf.String(), "whose role is not done") }
	now := time.Now()
	r.conf.logOwnersNS(r.mpzd, now)
	r.conf.logOwnersNS(r.mpzd, now.Add(time.Minute))
	if n := count(); n != 1 {
		t.Errorf("logged %d times within the hour", n)
	}
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "zone="+zone) {
		t.Errorf("the log line: %s", buf.String())
	}
	r.conf.logOwnersNS(r.mpzd, now.Add(ownersNSLogEvery))
	if n := count(); n != 2 {
		t.Errorf("logged %d times after the hour, want 2", n)
	}

	if err := r.store.Forget(zone); err != nil {
		t.Fatal(err)
	}
	knownAs(t, r.store, zone, jAt(t, 42, `servers="a,b" nsmgmt="agent" suffix="n"`, freezeRecords...))
	wantReport(t, "under nsmgmt=agent", r.conf.ownersNSReport(r.mpzd))

	if err := r.store.Forget(zone); err != nil {
		t.Fatal(err)
	}
	knownAs(t, r.store, zone, jAt(t, 43, `servers="a,b,n" nsmgmt="owner" suffix="n"`, freezeRecords...))
	wantReport(t, "n serves", r.conf.ownersNSReport(r.mpzd))
}

// A provider on its way, either way, is not done until the step's sets and
// the active serial both name it a server. A removal's kept names are read
// though its provider tells none any more.
func TestTheReportReadsTheStepsSetsAndTheRemovals(t *testing.T) {
	const zone = "reportstep.nsmgmt.example."
	r := newReportRig(t, zone, jAt(t, 41, `servers="a,b" nsmgmt="owner" suffix="n"`, freezeRecords...), "ns1.b.example.", "ns1.n.example.")
	v := jAt(t, 42, `servers="a,n" nsmgmt="owner" suffix="v"`, freezeRecords...)
	r.v = v
	r.holdUnjudged(v, time.Now())
	r.hear(roleN, tells(r.n, v), true)
	r.thawNow()
	r.tellsNameservers(roleB, "ns1.b.example.")
	r.tellsNameservers(roleN, "ns1.n.example.")
	// at step 0 n is on its way in and b on its way out, b's name still there
	wantReport(t, "at step 0", r.conf.ownersNSReport(r.mpzd), roleB, roleN)

	sets := rolesFor(v, v, 0)
	raw, digest, err := stepDigest(sets)
	if err != nil {
		t.Fatal(err)
	}
	removal := Removal{Label: "b", Identity: roleB, NSNames: []string{"ns1.gone.example."}}
	if err := r.store.setStep(zone, sd(v), InstrStep{Number: 1, Of: 2, Sets: raw, Digest: digest, Taken: []string{"x"}}, []Removal{removal}); err != nil {
		t.Fatal(err)
	}
	wantReport(t, "n in the step's sets", r.conf.ownersNSReport(r.mpzd), roleB)

	r.tellsNameservers(roleB)
	apex, _ := r.mpzd.GetOwner(zone)
	apex.RRtypes.Set(dns.TypeNS, core.RRset{Name: zone, RRtype: dns.TypeNS, RRs: []dns.RR{mustRR(t, zone+" 3600 IN NS ns1.gone.example.")}})
	r.mpzd.Data.Set(zone, *apex)
	wantReport(t, "the removal's kept names", r.conf.ownersNSReport(r.mpzd), roleB)
}

// A provider that tells no nameserver names is not checked, whatever the
// owner's NS RRset names; once it tells them it is. This agent's own names
// are its configuration's.
func TestAProviderWithoutConfiguredNameserversIsNotChecked(t *testing.T) {
	const zone = "nonames.nsmgmt.example."
	r := newReportRig(t, zone, jAt(t, 41, `servers="b" signers="b" nsmgmt="owner"`, freezeRecords...), "ns1.a.example.", "ns1.n.example.")
	r.tellsNameservers(roleN)
	wantReport(t, "neither tells any name", r.conf.ownersNSReport(r.mpzd))
	r.tellsNameservers(roleN, "ns1.n.example.")
	wantReport(t, "n tells its name", r.conf.ownersNSReport(r.mpzd), roleN)
	r.stamps.nameservers = []string{"ns1.a.example."}
	wantReport(t, "this agent's own name too", r.conf.ownersNSReport(r.mpzd), roleA, roleN)
}

// An auditor has no role transition: its names are not looked at.
func TestTheAuditorIsNotReported(t *testing.T) {
	const zone = "auditor.nsmgmt.example."
	r := newReportRig(t, zone, jAt(t, 41, `servers="a,b" auditors="n" nsmgmt="owner"`, freezeRecords...), "ns1.n.example.")
	r.tellsNameservers(roleN, "ns1.n.example.")
	wantReport(t, "the auditor", r.conf.ownersNSReport(r.mpzd))
}
