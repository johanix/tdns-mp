/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"slices"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Plan S13: every reader takes the step's sets per purpose, and a leaving
// provider stays in each set until its step for that set (design 5.2).
// The steps that take a provider out come with the removal's runner
// (S17b); here a test runner, or the store, gives a step its sets.

// providersOf are the providers with the labels, each with the identity
// agent.<label>.example.
func providersOf(labels ...string) []Provider {
	out := []Provider{}
	for _, l := range labels {
		out = append(out, Provider{Label: l, Identity: "agent." + l + ".example."})
	}
	return out
}

// signerSetsOf are sets with the labels in every signer set: KeySigners,
// DSSigners, KeyConfirmers and Signing.
func signerSetsOf(labels ...string) Roles { return withSigners(Roles{}, labels...) }

// withSigners are base with the labels in every signer set, its servers and
// settings as they are.
func withSigners(base Roles, labels ...string) Roles {
	base.KeySigners, base.DSSigners, base.KeyConfirmers, base.Signing = providersOf(labels...), providersOf(labels...), providersOf(labels...), providersOf(labels...)
	return base
}

// stepAs makes sets the zone's step n in the store, as the leader's stamp
// gives them (plan S12).
func stepAs(t *testing.T, s *InstructionStore, zone string, n int, sets Roles) {
	t.Helper()
	raw, _, err := stepDigest(sets)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.update(zone, func(z *zoneSerials) error {
		z.Step, z.Sets = n, raw
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// withActiveStore installs a store of serials whose active instructions for
// mpzd's zone are its copy's, and returns it.
func withActiveStore(t *testing.T, mpzd *MPZoneData) *InstructionStore {
	t.Helper()
	in := mpzd.instructions()
	s := newStore(t)
	withStore(t, s)
	activeAs(t, s, mpzd.ZoneName, in)
	return s
}

// outOfSignersZone is a zone whose records list us, p2 and p3 ON, and whose
// signers= names signers.
func outOfSignersZone(t *testing.T, name string, kdb *tdns.KeyDB, signers ...string) *MPZoneData {
	t.Helper()
	mpzd := signerTestZone(t, name, kdb)
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: mpzd.ZoneName, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600}
	}
	hp := numbered(&core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMSigners{Signers: signers}}})
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNCPARAM), Data: hp}}})
	var h3s []dns.RR
	for _, label := range []string{"us", "p2", "p3"} {
		h3s = append(h3s, &dns.PrivateRR{Hdr: hdr(core.TypeHSYNC3), Data: &core.HSYNC3{State: 1, Label: label, Identity: "agent." + label + ".example.", Upstream: "."}})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: h3s})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.Lock()
	mpzd.Ready, mpzd.Status = true, tdns.ZoneStatusReady // the served zone, which the origin rule reads
	mpzd.Unlock()
	mpzd.InstallInitialSnapshot()
	mpzd.EnsureMP()
	return mpzd
}

// Each step's sets reach both parts as the step makes them: a step that
// keeps x, whom the active serial names in no list, in KeySigners,
// DSSigners and Signing hands it to the combiner and to the signer in
// those sets alone; the last step hands the active serial's lists.
func TestEachStepsSetsAreHandedToBothParts(t *testing.T) {
	x := Provider{Label: "x", Identity: "agent.x.example."}
	defer withRunners(stepRunner{name: "removal", kind: stepRemoval, steps: func(planView) []plannedStep {
		return []plannedStep{{key: "x keeps signing", what: "x keeps signing", provider: x.Identity, sets: func(held Roles) Roles {
			held.KeySigners = append(slices.Clone(held.KeySigners), x)
			held.DSSigners = append(slices.Clone(held.DSSigners), x)
			held.Signing = append(slices.Clone(held.Signing), x)
			return held
		}}}
	}})()
	r := newReconcileRig(t, "handed.steps.example.", roleA)
	r.agree()
	r.thawNow()
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	if st, ok := r.step(); !ok || st.Number != 1 {
		t.Fatalf("the step taken: %+v (%v), want step 1", st, ok)
	}
	for _, tr := range []*handoverTracker{r.combiner, r.signer} {
		h := r.wantedBy(tr)
		if h == nil || h.Step != 1 || !has(h.Sets.KeySigners, "x") || !has(h.Sets.DSSigners, "x") || !has(h.Sets.Signing, "x") ||
			has(h.Sets.Servers, "x") || has(h.Sets.KeyConfirmers, "x") {
			t.Errorf("the %s is handed %+v, want step 1's sets: x in the key, DS and signing sets alone", tr.part(), h)
		}
	}
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	if st, ok := r.step(); !ok || st.Number != 2 {
		t.Fatalf("the step taken: %+v (%v), want the last, 2", st, ok)
	}
	for _, tr := range []*handoverTracker{r.combiner, r.signer} {
		if h := r.wantedBy(tr); h == nil || has(h.Sets.KeySigners, "x") || has(h.Sets.DSSigners, "x") || has(h.Sets.Signing, "x") {
			t.Errorf("at the last step the %s is handed %+v, want the active lists", tr.part(), h)
		}
	}
}

// At rest every set is the active serial's list: no signing set beside the
// sets (#275's), and what the agent hands is the sets as they read.
func TestAtRestTheSetsAreTheActiveLists(t *testing.T) {
	const zone = "rest.steps.example."
	asMPDaemon(t, AppTypeMPAgent)
	agentMp := &MultiProviderConf{Role: "agent", Identity: actUs}
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(agentMp)
	mpzd := instrTestZone(t, zone, actRecords(`serial="6" servers="alpha,beta" signers="alpha"`)...)
	mpzd.EnsureMP()
	mpzd.populateMPdata(agentMp, mpzd.roles())
	want := rolesFor(mpzd.instructions(), mpzd.instructions(), 0)
	if r := mpzd.roles(); !slices.Equal(r.Servers, want.Servers) || !slices.Equal(r.Signing, providersOf("alpha")) {
		t.Fatalf("the sets at rest %+v, want the active lists %+v", r, want)
	}
	h := conf.wantedHandover(zone)
	if h == nil {
		t.Fatal("nothing handed")
	}
	for name, set := range map[string][]Provider{"key signers": h.Sets.KeySigners, "DS signers": h.Sets.DSSigners, "key confirmers": h.Sets.KeyConfirmers, "signing": h.Sets.Signing} {
		if !slices.Equal(labelsOf(set), []string{"alpha"}) {
			t.Errorf("the %s handed at rest are %v, want signers= alone", name, labelsOf(set))
		}
	}
	if d := mpzd.MP.MPdata; d == nil || !slices.Equal(labelsOf(d.Sets.Signing), []string{"alpha"}) || d.Leaving {
		t.Errorf("the multi-provider data at rest %+v, want alpha's signing set and nobody leaving", d)
	}
}

// A provider out of signers= that the step's sets keep in Signing signs on
// and applies what it is sent, and its agent submits no keys; its combiner
// takes its own agent's operations, notwithstanding the origin rule. At its
// DNSKEY step, which takes it out of KeySigners and Signing, it is no
// signer, and its own agent is an origin with no role like any other.
func TestALeavingSignerSignsAndAppliesUntilItsDNSKEYStep(t *testing.T) {
	asMPDaemon(t, AppTypeMPCombiner)
	combiner := &MultiProviderConf{Role: "combiner", Identity: "combiner.us.example.", Agents: []*PeerConf{{Identity: "agent.us.example."}}}
	mpzd := outOfSignersZone(t, "applies.steps.example.", newMPTestKeyDB(t), "p2")
	z := mpzd.ZoneName
	ops := []core.RROperation{{Operation: "add", RRtype: "CSYNC", Records: []string{"x 300 IN CSYNC 1 3 A NS AAAA"}}}

	mpzd.populateMPdata(combiner, signerSetsOf("p2", "us"))
	d := mpzd.MP.MPdata
	if !d.WeAreSigner || !d.Leaving || d.OtherSigners != 1 || !d.ZoneSigned || !d.Options[tdns.OptMultiSigner] {
		t.Fatalf("before its DNSKEY step: signer=%v leaving=%v others=%d signed=%v multi-signer=%v, want a leaving signer with one other",
			d.WeAreSigner, d.Leaving, d.OtherSigners, d.ZoneSigned, d.Options[tdns.OptMultiSigner])
	}
	if mpzd.MPOptions[OptMPDisallowEdits] {
		t.Error("the leaving provider's combiner disallows edits: it would serve a stale copy")
	}
	p := mpzd.getEditPolicy()
	if !p.canApply(dns.TypeDNSKEY) || !mpzd.combinerShouldApplyEdits() {
		t.Error("the leaving provider's combiner does not apply what it is sent")
	}
	if p.canSubmit(dns.TypeDNSKEY) || p.canSubmit(dns.TypeCDS) || p.canSubmit(dns.TypeCSYNC) {
		t.Error("the leaving provider's agent may submit keys: it must start nothing")
	}
	if r := originVoteRefusal(z, "agent.us.example.", true, ops, nil); r != nil {
		t.Errorf("the leaving provider's combiner refused its own agent: %s", r.Message)
	}
	if r := originVoteRefusal(z, "agent.us.example.", false, ops, nil); r == nil {
		t.Error("the leaving provider's agent was taken as an origin from outside: only its own combiner takes it")
	}
	if r := originVoteRefusal(z, "agent.p3.example.", false, ops, nil); r == nil {
		t.Error("an origin with no role that is not this combiner's agent was taken")
	}

	mpzd.populateMPdata(combiner, signerSetsOf("p2"))
	if d := mpzd.MP.MPdata; d.WeAreSigner || d.Leaving {
		t.Errorf("at its DNSKEY step: signer=%v leaving=%v, want neither", d.WeAreSigner, d.Leaving)
	}
	if r := originVoteRefusal(z, "agent.us.example.", true, ops, nil); r == nil {
		t.Error("after its DNSKEY step the combiner took its own agent's operations with no role")
	}
}

// #200 item 4: the leaving signer's DS stays in the leader's computed DS set
// while the step's DSSigners keep it, and leaves at its DS step.
func TestALeavingSignersDSStaysInTheComputedSetUntilTheDSStep(t *testing.T) {
	yes := true
	r := newComputedDSRig(t, "computed.steps.example.", []string{"p2"})
	z := r.mpzd.ZoneName
	k2, k3 := testDnskey(t, z, 257), testDnskey(t, z, 257)
	r.distribution(t, "agent.p2.example.", word{k2, KeyStateActive, &yes})
	r.distribution(t, "agent.p3.example.", word{k3, KeyStateActive, &yes})
	known, tags := r.dsSet(t)
	if !known || !tags[k2.KeyTag()] || tags[k3.KeyTag()] {
		t.Fatalf("at rest, by signers=: known=%v tags=%v, want p2's DS alone", known, tags)
	}
	s := withActiveStore(t, r.mpzd)
	rest := r.mpzd.roles()
	stepAs(t, s, z, 1, withSigners(rest, "p2", "p3"))
	known, tags = r.dsSet(t)
	if !known || !tags[k2.KeyTag()] || !tags[k3.KeyTag()] {
		t.Fatalf("p3 out of signers=, the step keeping it in DSSigners: known=%v tags=%v, want p2's and p3's DS", known, tags)
	}
	stepAs(t, s, z, 2, withSigners(rest, "p2"))
	known, tags = r.dsSet(t)
	if !known || tags[k3.KeyTag()] {
		t.Fatalf("at p3's DS step: known=%v tags=%v, want p3's DS out", known, tags)
	}
}

// The agent's hold on its own signer's inventory asks a provider the step
// keeps in DSSigners, out of signers= or not: an inventory that dropped its
// DS is held back while its key states keep it. One in no DS signer set is
// not asked.
func TestTheInventoryHoldAsksAProviderInTheStepsDSSigners(t *testing.T) {
	yes := true
	r := newComputedDSRig(t, "withheld.steps.example.", []string{"us", "p2"})
	z := r.mpzd.ZoneName
	k3 := testDnskey(t, z, 257)
	r.distribution(t, "agent.p3.example.", word{k3, KeyStateActive, &yes})
	inv := []tdns.KeyInventoryItem{invItem(t, z, 257, KeyStateActive, &yes)}
	if why := r.conf.foreignDSWithheld(z, inv); why != "" {
		t.Fatalf("p3 is in no DS signer set, and the hold names it: %s", why)
	}
	s := withActiveStore(t, r.mpzd)
	rest := r.mpzd.roles()
	stepAs(t, s, z, 1, withSigners(rest, "us", "p2", "p3"))
	if why := r.conf.foreignDSWithheld(z, inv); why == "" {
		t.Fatal("an inventory without the DS of p3, which the step keeps in DSSigners, was not held back")
	}
}

// A step that changes DSSigners changes the DS set with no key and no
// inventory changing: it asks the leader's delegation sync, once. A step
// that leaves them as they are asks for nothing, and so does an agent that
// does not lead.
func TestAStepThatChangesTheDSSetAsksTheLeadersSync(t *testing.T) {
	r := newComputedDSRig(t, "sync.steps.example.", []string{"us", "p2"})
	z := r.mpzd.ZoneName
	r.mpzd.Options[tdns.OptMultiProvider] = true
	r.leader("agent.us.example.")
	s := withActiveStore(t, r.mpzd)
	rest := r.mpzd.roles()
	rest.ParentSync = core.HsyncParentSyncAgent // the agents sync the parent
	stepAs(t, s, z, 1, withSigners(rest, "us", "p2"))
	r.mpzd.populateMPdata(r.conf.MpConfig(), r.mpzd.roles())
	r.conf.onSetsChanged(r.mpzd, true)
	if n := r.requests(t); n != 0 {
		t.Fatalf("no change of the DS signers, and %d syncs were asked for", n)
	}
	stepAs(t, s, z, 2, withSigners(rest, "us", "p2", "p3"))
	r.conf.onSetsChanged(r.mpzd, true)
	if n := r.requests(t); n != 1 {
		t.Fatalf("the step changed the DS signers at the leader: %d syncs asked for, want 1", n)
	}
	r.conf.onSetsChanged(r.mpzd, true)
	if n := r.requests(t); n != 0 {
		t.Fatalf("the same step asked again: %d more syncs", n)
	}
	r.leader("agent.p2.example.")
	stepAs(t, s, z, 3, withSigners(rest, "us", "p2"))
	r.conf.onSetsChanged(r.mpzd, true)
	if n := r.requests(t); n != 0 {
		t.Fatalf("an agent that does not lead asked for %d syncs", n)
	}
}

// A key a provider's agent answers "ignored" counts against the key only
// when the step's KeyConfirmers name that provider: one in KeySigners alone
// (a leaver past its NS step) does not hold the key up.
func TestAnIgnoredKeyCountsOnlyFromAKeyConfirmer(t *testing.T) {
	r := newComputedDSRig(t, "confirmers.steps.example.", []string{"us", "p2", "p3"})
	s := withActiveStore(t, r.mpzd)
	rest := r.mpzd.roles()
	sets := withSigners(rest, "us", "p2", "p3")
	sets.KeyConfirmers = providersOf("us", "p2")
	stepAs(t, s, r.mpzd.ZoneName, 1, sets)
	sa := signingAgents(ZoneName(r.mpzd.ZoneName), []AgentId{"agent.p2.example.", "agent.p3.example."})
	if !sa["agent.p2.example."] || sa["agent.p3.example."] {
		t.Errorf("the agents whose ignored answer counts: %v, want p2's alone", sa)
	}
}

// #200 item 3 (#138): the signer left alone in signers= keeps the leaving
// signer's DNSKEYs as foreign rows, and stays in multi-signer mode, while
// the sets its agent hands it keep the leaver in KeySigners; at the
// leaver's DNSKEY step its rows go.
func TestTheLastSignerLeftKeepsTheLeavingSignersKeysUntilTheDNSKEYStep(t *testing.T) {
	const zone = "lastone.steps.example."
	records := sigRecords(`serial="5" servers="us,p2" signers="us"`)
	r := newSignerRig(t, zone, records...)
	kt := r.foreignKey(t, 256)
	keep := handoverFor(t, zone, records...)
	keep.Sets.KeySigners = append(keep.Sets.KeySigners, Provider{Label: "p2", Identity: "agent.p2.example."})
	r.hand(keep, sigUs)
	others, signs := otherSignerLabels(r.mpzd, r.conf.MpConfig())
	if !signs || !slices.Equal(others, []string{"p2"}) {
		t.Fatalf("before p2's DNSKEY step the signer keeps the foreign rows of %v (a signer: %v), want p2's", others, signs)
	}
	if !r.mpzd.MPOptions[tdns.OptMultiSigner] || !slices.Contains(r.foreignRows(t), kt) {
		t.Fatalf("before p2's DNSKEY step: multi-signer %v, foreign rows %v, want p2's row kept", r.mpzd.MPOptions[tdns.OptMultiSigner], r.foreignRows(t))
	}
	drop := handoverFor(t, zone, records...)
	drop.Made = keep.Made.Add(time.Second)
	r.hand(drop, sigUs)
	if others, _ := otherSignerLabels(r.mpzd, r.conf.MpConfig()); len(others) != 0 {
		t.Errorf("at p2's DNSKEY step the signer keeps the foreign rows of %v", others)
	}
	if r.mpzd.MPOptions[tdns.OptMultiSigner] || slices.Contains(r.foreignRows(t), kt) {
		t.Errorf("at p2's DNSKEY step: multi-signer %v, foreign rows %v, want p2's row gone", r.mpzd.MPOptions[tdns.OptMultiSigner], r.foreignRows(t))
	}
}

// The status names the sets per purpose as this agent acts by them: at
// rest the active serial's lists, during a transition the step's.
func TestTheStatusShowsTheStepsSetsPerPurpose(t *testing.T) {
	r := newComputedDSRig(t, "status.steps.example.", []string{"p2"})
	if got, want := r.mpzd.setsLine(), "servers none; key signers p2; DS signers p2; key confirmers p2; signing p2"; got != want {
		t.Errorf("at rest the status says %q, want %q", got, want)
	}
	s := withActiveStore(t, r.mpzd)
	rest := r.mpzd.roles()
	sets := withSigners(rest, "p2", "p3")
	sets.KeyConfirmers = providersOf("p2")
	stepAs(t, s, r.mpzd.ZoneName, 1, sets)
	if got, want := r.mpzd.setsLine(), "servers none; key signers p2,p3; DS signers p2,p3; key confirmers p2; signing p2,p3"; got != want {
		t.Errorf("at a step the status says %q, want %q", got, want)
	}
}

// A change of the sets computes the zone's data on a wrapper and swaps it in
// under the zone's lock, as a refresh and a hand-over do: a reader under the
// lock never races it (external review of #339). It tells only under -race.
func TestAChangeOfTheSetsSwapsTheDataUnderTheZonesLock(t *testing.T) {
	r := newComputedDSRig(t, "locked.steps.example.", []string{"us", "p2"})
	r.mpzd.Options[tdns.OptMultiProvider] = true
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			r.mpzd.Lock()
			if d := r.mpzd.MP.MPdata; d != nil {
				_ = d.WeAreSigner
			}
			_ = r.mpzd.MPOptions[OptMPDisallowEdits]
			r.mpzd.Unlock()
		}
	}()
	for range 50 {
		r.conf.onSetsChanged(r.mpzd, true)
	}
	close(stop)
	<-done
}

// The signer's inventory is the owner's before what the signer holds is
// learned from it: a step that learning finds held reads the DS set of
// this inventory, not the one before (external review of #339).
func TestTheInventoryIsTheOwnersBeforeTheSignersHoldIsLearned(t *testing.T) {
	yes := true
	r := newComputedDSRig(t, "inventoryfirst.steps.example.", []string{"us", "p2"})
	z := r.mpzd.ZoneName
	h := &ActingHandover{Zone: z, Serial: 1, Digest: "x", Records: []string{"r"}, Made: time.Now()}
	tr := newHandoverTracker(AgentId("agent.us.example."), func(ZoneName, *ZoneUpdate, string) (string, error) { return "", nil })
	tr.toSigner = true
	tr.zones[handoverKey(z)] = &zoneHandover{want: h}
	var told, inventoried bool
	tr.onHeld = func(zone string) { told, inventoried = true, r.owner.inventoryOf(zone) != nil }
	r.conf.InternalMp.SignerHandover = tr
	r.conf.noteKeyInventory(r.ctx, r.mpzd, &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: z,
		Inventory: []KeyInventoryItem{invItem(t, z, 257, KeyStateActive, &yes)}, Owned: true, Acting: h})
	if !told {
		t.Fatal("the signer's hold of the hand-over was not learned")
	}
	if !inventoried {
		t.Error("the signer's hold was learned before its inventory was the owner's")
	}
}

// The first data a change of the sets computes over the config parse's stub
// is no change of the DS signers: the stub names none, and asks no sync
// (external review of #339, N2).
func TestTheFirstDataOverTheParsesStubAsksNoSync(t *testing.T) {
	r := newComputedDSRig(t, "stub.steps.example.", []string{"us", "p2"})
	r.mpzd.Options[tdns.OptMultiProvider] = true
	r.leader("agent.us.example.")
	s := withActiveStore(t, r.mpzd)
	rest := r.mpzd.roles()
	rest.ParentSync = core.HsyncParentSyncAgent // the agents sync the parent
	stepAs(t, s, r.mpzd.ZoneName, 1, withSigners(rest, "us", "p2"))
	r.mpzd.MP.MPdata = &MPdata{Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}} // as the parse leaves it
	r.conf.onSetsChanged(r.mpzd, true)
	if n := r.requests(t); n != 0 {
		t.Errorf("the first data over the parse's stub asked for %d syncs", n)
	}
}
