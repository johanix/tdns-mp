/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"io"
	"log"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// tdns-mp #147, the interim rule (#267 item 5): a signer the owner takes out
// of signers= signs on while the zone's HSYNC3 RRset still lists it, and the
// other providers go on treating it as a signer: its DNSKEYs stay in their
// RRsets and its DS in the DS set (#200 items 3 and 4).

// hsyncApex is the apex of a zone carrying the given HSYNC3 and HSYNCPARAM
// records, in zone file form, read as an incoming copy is.
func hsyncApex(t *testing.T, zone string, records ...string) *tdns.OwnerData {
	t.Helper()
	text := zone + " 3600 IN SOA ns1." + zone + " hostmaster." + zone + " 1 7200 1800 604800 7200\n" +
		zone + " 3600 IN NS ns1." + zone + "\n"
	for _, rr := range records {
		if p, ok := strings.CutPrefix(rr, "HSYNCPARAM "); ok {
			rr = "HSYNCPARAM " + numberedText(p)
		}
		text += zone + " 300 IN " + rr + "\n"
	}
	zd := &tdns.ZoneData{ZoneName: zone, ZoneStore: tdns.MapZone, ZoneType: tdns.Primary, Logger: log.New(io.Discard, "", 0)}
	if _, _, err := zd.ReadZoneData(text, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	apex, err := zd.OwnerForAnalysis(zone)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	return apex
}

func sameSigningSet(got signingSet, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, label := range want {
		if _, in := got[label]; !in {
			return false
		}
	}
	return true
}

// The signing set: signers=, and every provider that signed by the copy
// before and whose HSYNC3 record stays, under the same label and identity.
// Only a provider that has been in signers= is ever in it.
func TestTheSigningSetKeepsALeaverUntilItsRecordGoes(t *testing.T) {
	const z = "set.leaving.example."
	alpha := `HSYNC3 ON alpha agent.alpha.example. .`
	beta := `HSYNC3 ON beta agent.beta.example. .`
	steps := []struct {
		name    string
		records []string
		want    []string
	}{
		{"both sign", []string{alpha, beta, `HSYNCPARAM servers="alpha,beta" signers="alpha,beta"`}, []string{"alpha", "beta"}},
		{"beta out of signers=, its record stays", []string{alpha, beta, `HSYNCPARAM servers="alpha" signers="alpha"`}, []string{"alpha", "beta"}},
		{"an unrelated edit while beta leaves", []string{alpha, beta, `HSYNCPARAM servers="alpha" signers="alpha" auditors=""`}, []string{"alpha", "beta"}},
		{"beta's record removed", []string{alpha, `HSYNCPARAM servers="alpha" signers="alpha"`}, []string{"alpha"}},
		{"beta back as a server: it does not sign", []string{alpha, beta, `HSYNCPARAM servers="alpha,beta" signers="alpha"`}, []string{"alpha"}},
	}
	var set signingSet
	for _, s := range steps {
		set = nextSigningSet(hsyncApex(t, z, s.records...), set)
		if !sameSigningSet(set, s.want...) {
			t.Fatalf("%s: the signing set is %v, want %v", s.name, set, s.want)
		}
	}

	// One that never signed never enters: a newcomer whose record comes
	// first, or a server.
	prev := nextSigningSet(hsyncApex(t, z, alpha, `HSYNCPARAM servers="alpha" signers="alpha"`), nil)
	next := nextSigningSet(hsyncApex(t, z, alpha, beta, `HSYNCPARAM servers="alpha,beta" signers="alpha"`), prev)
	if !sameSigningSet(next, "alpha") {
		t.Errorf("a newcomer that has never been in signers= is in the signing set: %v", next)
	}

	// The record must stay as it was: turned OFF, or another identity under
	// the label, ends the leave.
	both := nextSigningSet(hsyncApex(t, z, alpha, beta, `HSYNCPARAM signers="alpha,beta"`), nil)
	for name, rec := range map[string]string{
		"beta's record turned OFF":       `HSYNC3 OFF beta agent.beta.example. .`,
		"another identity under beta":    `HSYNC3 ON beta agent.gamma.example. .`,
		"beta's identity, another label": `HSYNC3 ON delta agent.beta.example. .`,
	} {
		if got := nextSigningSet(hsyncApex(t, z, alpha, rec, `HSYNCPARAM signers="alpha"`), both); !sameSigningSet(got, "alpha") {
			t.Errorf("%s: the signing set is %v, want alpha alone", name, got)
		}
	}

	// A copy with no HSYNCPARAM has no reading (#308): the zone keeps its
	// last, whose signers= is alpha alone.
	t.Cleanup(func() { lastGood.Delete(z); noReading.Delete(z) })
	if got := nextSigningSet(hsyncApex(t, z, alpha, beta), both); !sameSigningSet(got, "alpha") {
		t.Errorf("a copy with no HSYNCPARAM: %v, want the last reading's alpha", got)
	}
}

// The set is kept in the keystore and read at the zone's first copy after a
// restart: a provider that left signers= before the restart is still
// leaving after it.
func TestALeavingSignerIsRememberedAcrossARestart(t *testing.T) {
	const z = "restart.leaving.example."
	kdb := newMPTestKeyDB(t)
	alpha := `HSYNC3 ON alpha agent.alpha.example. .`
	beta := `HSYNC3 ON beta agent.beta.example. .`

	before := &MPZoneData{ZoneData: &tdns.ZoneData{ZoneName: z}, MP: &MPState{}}
	set, changed := before.advanceSigningSet(hsyncApex(t, z, alpha, beta, `HSYNCPARAM signers="alpha,beta"`), kdb)
	if changed {
		t.Error("the zone's first copy here is reported as a change of its signing set: an agent would sync before its election")
	}
	before.MP.MPdata = &MPdata{Signing: set}
	set, changed = before.advanceSigningSet(hsyncApex(t, z, alpha, beta, `HSYNCPARAM signers="alpha"`), kdb)
	if !sameSigningSet(set, "alpha", "beta") || changed {
		t.Fatalf("after the edit: %v (changed %v), want alpha and beta (leaving), the set unchanged", set, changed)
	}

	// The restart: nothing in memory, the main_init stub.
	after := &MPZoneData{ZoneData: &tdns.ZoneData{ZoneName: z}, MP: &MPState{MPdata: &MPdata{}}}
	set, _ = after.advanceSigningSet(hsyncApex(t, z, alpha, beta, `HSYNCPARAM signers="alpha"`), kdb)
	if !sameSigningSet(set, "alpha", "beta") {
		t.Fatalf("after a restart: %v, want alpha and beta (still leaving)", set)
	}
	if kept, err := loadSigningSet(kdb, z); err != nil || !sameSigningSet(kept, "alpha", "beta") || kept["beta"] != "agent.beta.example." {
		t.Fatalf("the keystore keeps %v (err %v), want alpha and beta with beta's identity", kept, err)
	}

	// Without the keystore a restart starts from signers=: what main did.
	cold := &MPZoneData{ZoneData: &tdns.ZoneData{ZoneName: z}, MP: &MPState{}}
	if set, _ := cold.advanceSigningSet(hsyncApex(t, z, alpha, beta, `HSYNCPARAM signers="alpha"`), nil); !sameSigningSet(set, "alpha") {
		t.Errorf("with no keystore: %v, want alpha alone", set)
	}

	// The record removed: the keystore forgets beta, so a later record of
	// beta's does not bring the leave back.
	after.MP.MPdata = &MPdata{Signing: set}
	if _, changed := after.advanceSigningSet(hsyncApex(t, z, alpha, `HSYNCPARAM signers="alpha"`), kdb); !changed {
		t.Error("the leaver's record removed by a live refresh, and the signing set is not reported changed: the leader would not sync its DS away")
	}
	fresh := &MPZoneData{ZoneData: &tdns.ZoneData{ZoneName: z}, MP: &MPState{}}
	if set, _ := fresh.advanceSigningSet(hsyncApex(t, z, alpha, beta, `HSYNCPARAM servers="alpha,beta" signers="alpha"`), kdb); !sameSigningSet(set, "alpha") {
		t.Errorf("beta re-added as a server after its removal, across a restart: %v, want alpha alone", set)
	}
}

// leaveTestZone is a zone whose owner took "us" out of signers= while its
// HSYNC3 record stays: the zone's records list us, p2 and p3, signers=
// names signers, and the signing set is the one the copy before, when the
// providers in before signed, leaves. Its MPdata is populateMPdata's for
// the role mp gives.
func leaveTestZone(t *testing.T, name string, kdb *tdns.KeyDB, mp *MultiProviderConf, signers, before []string) *MPZoneData {
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
	leaveSigners(t, mpzd, mp, before...)
	return mpzd
}

// leaveSigners gives mpzd the MPdata of a refresh whose copy before had the
// providers in before as its signers.
func leaveSigners(t *testing.T, mpzd *MPZoneData, mp *MultiProviderConf, before ...string) {
	t.Helper()
	prev := signingSet{}
	for _, label := range before {
		prev[label] = "agent." + label + ".example."
	}
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	mpzd.EnsureMP()
	mpzd.populateMPdata(mp, nextSigningSet(apex, prev))
	if mpzd.MP.MPdata == nil {
		t.Fatal("populateMPdata found no multi-provider data")
	}
}

// The provider that left signers= is still a signer to every role: its
// signer signs on, its combiner applies, its agent submits no keys; a
// provider that never signed is none.
func TestALeavingProviderSignsOnButSubmitsNoKeys(t *testing.T) {
	asMPDaemon(t, AppTypeMPCombiner)
	combiner := &MultiProviderConf{Role: "combiner", Identity: "combiner.us.example.", Agents: []*PeerConf{{Identity: "agent.us.example."}}}
	kdb := newMPTestKeyDB(t)

	leaving := leaveTestZone(t, "on.leaving.example.", kdb, combiner, []string{"p2"}, []string{"us", "p2"})
	d := leaving.MP.MPdata
	if !d.WeAreSigner || !d.Leaving || d.OtherSigners != 1 || !d.ZoneSigned || !d.Options[tdns.OptMultiSigner] {
		t.Fatalf("a provider out of signers= with its record kept: signer=%v leaving=%v others=%d signed=%v multi-signer=%v, want a leaving signer with one other",
			d.WeAreSigner, d.Leaving, d.OtherSigners, d.ZoneSigned, d.Options[tdns.OptMultiSigner])
	}
	if leaving.MPOptions[OptMPDisallowEdits] {
		t.Error("the leaving provider's combiner disallows edits: it would serve a stale copy")
	}
	p := leaving.getEditPolicy()
	if !p.canApply(dns.TypeDNSKEY) || !leaving.combinerShouldApplyEdits() {
		t.Error("the leaving provider's combiner does not apply what it is sent")
	}
	if p.canSubmit(dns.TypeDNSKEY) || p.canSubmit(dns.TypeCDS) || p.canSubmit(dns.TypeCSYNC) {
		t.Error("the leaving provider's agent may submit keys: it must start nothing")
	}

	never := leaveTestZone(t, "never.leaving.example.", kdb, combiner, []string{"p2"}, []string{"p2"})
	if d := never.MP.MPdata; d.WeAreSigner || d.Leaving {
		t.Errorf("a provider that never signed: signer=%v leaving=%v, want neither", d.WeAreSigner, d.Leaving)
	}
	listed := leaveTestZone(t, "listed.leaving.example.", kdb, combiner, []string{"us", "p2"}, []string{"us", "p2"})
	if d := listed.MP.MPdata; !d.WeAreSigner || d.Leaving {
		t.Errorf("a provider in signers=: signer=%v leaving=%v, want a signer that is not leaving", d.WeAreSigner, d.Leaving)
	}
	if p := listed.getEditPolicy(); !p.canSubmit(dns.TypeDNSKEY) {
		t.Error("a provider in signers= may not submit its DNSKEYs")
	}
}

// (b): the leaving provider's combiner takes its own agent's operations,
// notwithstanding the origin rule; any other origin that does not vote is
// refused as before, and so is its own agent once it is not leaving.
func TestTheLeaversCombinerTakesItsOwnAgentsOperations(t *testing.T) {
	asMPDaemon(t, AppTypeMPCombiner)
	combiner := &MultiProviderConf{Role: "combiner", Identity: "combiner.us.example.", Agents: []*PeerConf{{Identity: "agent.us.example."}}}
	kdb := newMPTestKeyDB(t)
	ops := []core.RROperation{{Operation: "add", RRtype: "CSYNC", Records: []string{"x 300 IN CSYNC 1 3 A NS AAAA"}}}

	leaving := leaveTestZone(t, "origin.leaving.example.", kdb, combiner, []string{"p2"}, []string{"us", "p2"})
	z := leaving.ZoneName
	if r := originVoteRefusal(z, "agent.us.example.", true, ops, nil); r != nil {
		t.Errorf("the leaving provider's combiner refused its own agent: %s", r.Message)
	}
	if r := originVoteRefusal(z, "agent.us.example.", false, ops, nil); r == nil {
		t.Error("the leaving provider's agent was taken as an origin from outside: only its own combiner takes it")
	}
	if r := originVoteRefusal(z, "agent.p3.example.", false, ops, nil); r == nil {
		t.Error("an origin with no role that is not this combiner's agent was taken")
	}
	if r := originVoteRefusal(z, "agent.p2.example.", false, ops, nil); r != nil {
		t.Errorf("a voting origin was refused: %s", r.Message)
	}

	never := leaveTestZone(t, "origin.never.example.", kdb, combiner, []string{"p2"}, []string{"p2"})
	if r := originVoteRefusal(never.ZoneName, "agent.us.example.", true, ops, nil); r == nil {
		t.Error("the combiner of a provider that never signed took its own agent's operations with no role")
	}
}

// #200 item 4: the leaving signer's DS stays in the leader's computed DS set
// while its record stays, and leaves it with the record.
func TestALeavingSignersDSStaysInTheComputedSet(t *testing.T) {
	yes := true
	r := newComputedDSRig(t, "computed.leaving.example.", []string{"p2"})
	z := r.mpzd.ZoneName
	k2, k3 := testDnskey(t, z, 257), testDnskey(t, z, 257)
	r.distribution(t, "agent.p2.example.", word{k2, KeyStateActive, &yes})
	r.distribution(t, "agent.p3.example.", word{k3, KeyStateActive, &yes})

	// signers= alone, as main reads it: p3's DS is out of the set at once
	known, tags := r.dsSet(t)
	if !known || !tags[k2.KeyTag()] || tags[k3.KeyTag()] {
		t.Fatalf("by signers= alone: known=%v tags=%v, want p2's DS alone", known, tags)
	}

	agent := &MultiProviderConf{Role: "agent", Identity: "agent.us.example."}
	leaveSigners(t, r.mpzd, agent, "p2", "p3")
	known, tags = r.dsSet(t)
	if !known || !tags[k2.KeyTag()] || !tags[k3.KeyTag()] {
		t.Fatalf("p3 out of signers=, its record kept: known=%v tags=%v, want p2's and p3's DS", known, tags)
	}

	// The record removed: the signing set is signers= again.
	r.mpzd.MP.MPdata.Signing = signingSet{"p2": "agent.p2.example."}
	known, tags = r.dsSet(t)
	if !known || tags[k3.KeyTag()] {
		t.Fatalf("p3's record removed: known=%v tags=%v, want p3's DS out", known, tags)
	}
}

// When the owner removes a leaving signer's record, the DS set loses its DS
// with no key and no inventory changing: the refresh that changed the
// signing set asks the leader's delegation sync, once (seen in the lab: the
// parent held the departed signer's DS for good). An agent that does not
// lead asks for nothing.
func TestASigningSetChangeAsksTheLeadersSync(t *testing.T) {
	r := newComputedDSRig(t, "sync.leaving.example.", []string{"p2"})
	r.mpzd.EnsureMP()
	r.leader("agent.us.example.")
	r.conf.afterSigningSetChange(r.mpzd)
	if n := r.requests(t); n != 0 {
		t.Fatalf("no change of the signing set, and %d syncs were asked for", n)
	}
	r.mpzd.MP.SigningChanged = true
	r.conf.afterSigningSetChange(r.mpzd)
	if n := r.requests(t); n != 1 {
		t.Fatalf("the signing set changed at the leader: %d syncs asked for, want 1", n)
	}
	r.conf.afterSigningSetChange(r.mpzd)
	if n := r.requests(t); n != 0 {
		t.Fatalf("the change was asked for again: %d more syncs", n)
	}
	r.leader("agent.p2.example.")
	r.mpzd.MP.SigningChanged = true
	r.conf.afterSigningSetChange(r.mpzd)
	if n := r.requests(t); n != 0 {
		t.Fatalf("an agent that does not lead asked for %d syncs", n)
	}
}

// The agent's hold on its own signer's inventory asks the leaving provider
// too: an inventory that dropped the leaver's DS is held back while the
// leaver's key states keep it.
func TestTheInventoryHoldAsksTheLeavingSigner(t *testing.T) {
	yes := true
	r := newComputedDSRig(t, "withheld.leaving.example.", []string{"us", "p2"})
	z := r.mpzd.ZoneName
	k3 := testDnskey(t, z, 257)
	r.distribution(t, "agent.p3.example.", word{k3, KeyStateActive, &yes})
	inv := []tdns.KeyInventoryItem{invItem(t, z, 257, KeyStateActive, &yes)}
	if why := r.conf.foreignDSWithheld(z, inv); why != "" {
		t.Fatalf("p3 never signed here, and the hold names it: %s", why)
	}
	leaveSigners(t, r.mpzd, &MultiProviderConf{Role: "agent", Identity: "agent.us.example."}, "us", "p2", "p3")
	if why := r.conf.foreignDSWithheld(z, inv); why == "" {
		t.Fatal("an inventory without the leaving signer's DS was not held back")
	}
}

// A signer that stays counts the leaving one among the other signers: its
// key machine waits for the leaver's answers as before, and keeps ds on the
// leaver's KSK, which is what puts the leaver's DS in the set it hands its
// agent (foreignDSFor).
func TestTheRemainingSignerCountsTheLeaverAmongTheOtherSigners(t *testing.T) {
	asMPDaemon(t, AppTypeMPSigner)
	signer := &MultiProviderConf{Role: "signer", Identity: "signer.us.example.", Agents: []*PeerConf{{Identity: "agent.us.example."}}}
	mpzd := leaveTestZone(t, "remaining.leaving.example.", newMPTestKeyDB(t), signer, []string{"us", "p2"}, []string{"us", "p2", "p3"})
	others, ok := otherSignerLabels(mpzd, signer)
	if !ok || len(others) != 2 || others[0] != "p2" || others[1] != "p3" {
		t.Fatalf("the other signers %v (a signer: %v), want p2 and p3 (leaving)", others, ok)
	}
	signers := map[string]bool{}
	for _, p := range others {
		signers[p] = true
	}
	yes := true
	if ds, decided := foreignDSFor(foreignSaid{Provider: "p3", State: KeyStateActive, DS: &yes}, true, signers); !ds || !decided {
		t.Errorf("the leaving signer's active KSK: ds=%v decided=%v, want its DS kept", ds, decided)
	}
}

// While a provider leaves the signing set, no key machine of the zone starts
// anything, the leaver's or a remaining signer's: the leaver takes no
// distribution, so a remaining signer's new key would be missing from the
// DNSKEY RRset the leaver serves. The zone stays owned, so tdns's machine
// does not take it either. A zone nobody leaves mints its first keys at the
// first tick, and so does a paused one once the leaver's record goes.
func TestEveryKeyMachineOfTheZonePausesWhileAProviderLeaves(t *testing.T) {
	signer := &MultiProviderConf{Role: "signer", Identity: "signer.us.example.", Agents: []*PeerConf{{Identity: "agent.us.example."}}}
	for _, tc := range []struct {
		name            string
		signers, before []string
		others          []string
		paused          string
	}{
		{"leaving", []string{"p2"}, []string{"us", "p2"}, []string{"p2"}, "key rollovers paused: agent.us.example. is leaving the signing set"},
		{"remaining", []string{"us", "p2"}, []string{"us", "p2", "p3"}, []string{"p2", "p3"}, "key rollovers paused: agent.p3.example. is leaving the signing set"},
		{"nobody-leaves", []string{"us", "p2"}, []string{"us", "p2"}, []string{"p2"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asMPDaemon(t, AppTypeMPSigner)
			kdb := newMPTestKeyDB(t)
			mpzd := leaveTestZone(t, tc.name+".machine.leaving.example.", kdb, signer, tc.signers, tc.before)
			conf := &Config{Config: &tdns.Config{}}
			conf.SetMpConfig(signer)
			conf.Config.Internal.KeyDB = kdb
			owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
			e := NewKeyLifecycleEngine(conf, owner)
			e.wire.push = func(*Config, string, []uint16) {}
			owner.Take(mpzd.ZoneName)
			ownKeys := func() int {
				t.Helper()
				var n int
				if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=? AND state!=?`, mpzd.ZoneName, DnskeyStateForeign).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}

			others, ok := otherSignerLabels(mpzd, signer)
			if !ok || strings.Join(others, " ") != strings.Join(tc.others, " ") {
				t.Fatalf("the other signers %v (a signer: %v), want %v", others, ok, tc.others)
			}
			paused := map[string]keyPause{}
			e.tickOwned(paused)
			if !owner.Owns(mpzd.ZoneData) {
				t.Fatal("the zone was released to tdns's key machine")
			}
			st, err := e.Status(mpzd.ZoneName)
			if err != nil {
				t.Fatal(err)
			}
			if st.Paused != tc.paused {
				t.Errorf("the status says %q, want %q", st.Paused, tc.paused)
			}
			if tc.paused == "" {
				if ownKeys() == 0 || len(paused) != 0 {
					t.Fatalf("nobody leaves, and the machine minted no key (paused %v): the test does not tell", paused)
				}
				return
			}
			if n := ownKeys(); n != 0 || paused[mpzd.ZoneName].line != tc.paused {
				t.Fatalf("while a provider leaves the machine minted %d keys, paused as %q; want none, paused as %q", n, paused[mpzd.ZoneName].line, tc.paused)
			}

			// The leaver's record goes: the remaining signers resume.
			if tc.name == "remaining" {
				leaveSigners(t, mpzd, signer, "us", "p2")
				e.tickOwned(paused)
				if ownKeys() == 0 || len(paused) != 0 {
					t.Errorf("the leave over, the machine minted no key (paused %v)", paused)
				}
			}
		})
	}
}

// The review's S1: while the rollovers pause, a confirmation must not carry
// a rollover under way on, and the other providers' word must not change a
// ds bit. Both are kept: a key in mpdist stays there through the pause,
// with the agents' "propagated" in hand, and the word is not recorded.
// Once the leaver's record goes, the first tick applies them: the key is
// published (T3), and the word is recorded.
func TestAConfirmationDuringThePauseIsKeptAndAppliedAfterTheLeave(t *testing.T) {
	asMPDaemon(t, AppTypeMPSigner)
	signer := &MultiProviderConf{Role: "signer", Identity: "signer.us.example.", Agents: []*PeerConf{{Identity: "agent.us.example."}}}
	kdb := newMPTestKeyDB(t)
	mpzd := leaveTestZone(t, "kept.leaving.example.", kdb, signer, []string{"us", "p2"}, []string{"us", "p2"})
	z := mpzd.ZoneName
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(signer)
	conf.Config.Internal.KeyDB = kdb
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
	e := NewKeyLifecycleEngine(conf, owner)
	e.wire.push = func(*Config, string, []uint16) {}
	owner.Take(z)

	// before the leave: the first keys are minted and sent to p2
	paused := map[string]keyPause{}
	e.tickOwned(paused)
	var keyid int
	if err := kdb.DB.QueryRow(`SELECT keyid FROM DnssecKeyStore WHERE zonename=? AND state=? LIMIT 1`, z, KeyStateMpdist).Scan(&keyid); err != nil {
		t.Fatalf("no key in %s after the first tick: %v", KeyStateMpdist, err)
	}
	kt := uint16(keyid)

	// p3, a signer before, leaves: the rollovers pause
	leaveSigners(t, mpzd, signer, "us", "p2", "p3")
	yes := true
	word := []core.ForeignKeyState{{Provider: "p2", KeyState: core.KeyState{KeyTag: 4711, State: KeyStateActive, DS: &yes}}}
	if !e.Signal(z, kt, "propagated", "", time.Time{}) || !e.ForeignWord(z, word, []string{"p2"}) {
		t.Fatal("a signal or a word for an owned zone was not claimed")
	}
	e.tickOwned(paused)
	if st := mpKeyState(t, kdb, z, kt); st != KeyStateMpdist {
		t.Fatalf("a confirmation during the pause moved key %d to %s: the rollover went on", kt, st)
	}
	if w, err := readForeignWord(kdb, z); err != nil || len(w) != 0 {
		t.Fatalf("the other providers' word was recorded during the pause: %v (err %v)", w, err)
	}

	// the leaver's record goes: what was kept is applied
	leaveSigners(t, mpzd, signer, "us", "p2")
	e.tickOwned(paused)
	if st := mpKeyState(t, kdb, z, kt); st != KeyStatePublished {
		t.Errorf("after the leave the kept confirmation left key %d in %s, want %s", kt, st, KeyStatePublished)
	}
	if w, err := readForeignWord(kdb, z); err != nil || w[4711].Provider != "p2" {
		t.Errorf("after the leave the kept word was not recorded: %v (err %v)", w, err)
	}
}

// The leaving signer, end to end through its refresh path: the owner takes
// it out of signers= and keeps its record; it signs on with its own keys, its
// serial moves on, and so it does after a restart.
func TestALeavingSignerKeepsSigningAcrossTheEditAndARestart(t *testing.T) {
	asMPDaemon(t, AppTypeMPSigner)
	kdb := newMPTestKeyDB(t)
	const zone = "harness.leaving.example."
	mpGenKey(t, kdb, zone, tdns.DnskeyStateActive, "KSK")
	mpGenKey(t, kdb, zone, tdns.DnskeyStateActive, "ZSK")
	policy := &tdns.DnssecPolicy{
		Mode:         tdns.DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity:  tdns.PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
	}
	ownKeys := func() []*dns.DNSKEY {
		t.Helper()
		inv, err := tdns.GetKeyInventory(kdb, zone)
		if err != nil {
			t.Fatalf("GetKeyInventory: %v", err)
		}
		var keys []*dns.DNSKEY
		for _, it := range inv {
			if it.State == DnskeyStateForeign {
				continue
			}
			rr, err := dns.NewRR(it.KeyRR)
			if err != nil {
				t.Fatalf("key %d: %v", it.KeyTag, err)
			}
			keys = append(keys, rr.(*dns.DNSKEY))
		}
		return keys
	}

	up := startMPUpstream(t, zone, "alpha,beta", false, 7)
	z := startMPServedZone(t, kdb, up, signerConfBeta(), policy)
	if !z.signsInline() {
		t.Fatal("inline-signing is off for a zone whose HSYNCPARAM names this provider as a signer")
	}
	first, _ := z.servedSOA(t)

	// The owner's edit: beta out of signers=, its record kept.
	up.signers = "alpha"
	up.publish(t, 8)
	z.notified(t)
	if !z.signsInline() {
		t.Fatal("the leaving signer stopped signing at the owner's edit (#147)")
	}
	soa, _ := z.servedSOA(t)
	if soa.Serial != first.Serial+1 {
		t.Fatalf("after the edit the leaving signer serves serial %d, want %d: its own count goes on", soa.Serial, first.Serial+1)
	}
	if err := z.soaValidates(t, ownKeys()); err != nil {
		t.Fatalf("after the edit: %v", err)
	}

	// A restart: the leave is read back from the keystore.
	z.halt()
	again := startMPServedZone(t, kdb, up, signerConfBeta(), policy)
	if !again.signsInline() {
		t.Fatal("after a restart the leaving signer does not sign")
	}
	if err := again.soaValidates(t, ownKeys()); err != nil {
		t.Fatalf("after a restart: %v", err)
	}
	up.publish(t, 9)
	again.notified(t)
	if !again.signsInline() {
		t.Fatal("after a restart and a refresh the leaving signer does not sign")
	}
}

// #200 item 3 (#138): the signer left alone in signers= keeps the leaving
// signer's DNSKEYs while its record stays, and drops them with the record.
func TestTheLastSignerLeftKeepsTheLeaversDNSKEYs(t *testing.T) {
	asMPDaemon(t, AppTypeMPSigner)
	kdb := newMPTestKeyDB(t)
	const zone = "lastone.leaving.example."
	mpGenKey(t, kdb, zone, tdns.DnskeyStateActive, "KSK")
	mpGenKey(t, kdb, zone, tdns.DnskeyStateActive, "ZSK")
	policy := &tdns.DnssecPolicy{
		Mode:         tdns.DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity:  tdns.PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
	}
	// alpha's ZSK, as alpha's agent contributed it through our combiner
	alphaZSK := testDnskey(t, zone, 256)
	foreign := func(t *testing.T) bool {
		t.Helper()
		var n int
		if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=? AND keyid=? AND state=?`, zone, alphaZSK.KeyTag(), DnskeyStateForeign).Scan(&n); err != nil {
			t.Fatalf("foreign rows: %v", err)
		}
		return n > 0
	}

	up := startMPUpstream(t, zone, "alpha,beta", false, 7)
	up.extra = []string{alphaZSK.String()}
	up.publish(t, 7)
	z := startMPServedZone(t, kdb, up, signerConfBeta(), policy)
	if !foreign(t) {
		t.Fatal("with two signers the other signer's DNSKEY is no foreign row: the test does not tell")
	}

	// alpha out of signers=, its record kept: beta alone in signers=
	up.signers = "beta"
	up.publish(t, 8)
	z.notified(t)
	if !foreign(t) {
		t.Fatal("the last signer in signers= dropped the leaving signer's DNSKEY (#138, #200 item 3)")
	}

	// alpha's record removed: its DNSKEY goes
	up.without = "alpha"
	up.publish(t, 9)
	z.notified(t)
	if foreign(t) {
		t.Fatal("the leaving signer's DNSKEY stayed after the owner removed its record")
	}
}
