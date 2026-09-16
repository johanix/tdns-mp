package tdnsmp

import (
	"errors"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// zoneSignedBy makes this provider one of the zone's signers, label "us"
// with the given agent identity, beside the others: an HSYNCPARAM signers
// list and an HSYNC3 record for us at the apex.
func zoneSignedBy(t *testing.T, mpzd *MPZoneData, identity string, others ...string) {
	t.Helper()
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: mpzd.ZoneName, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600}
	}
	hp := &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMSigners{Signers: append([]string{"us"}, others...)}}}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNCPARAM), Data: hp}}})
	h3 := &core.HSYNC3{State: 1, Label: "us", Identity: dns.Fqdn(identity), Upstream: "."}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNC3), Data: h3}}})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.InstallInitialSnapshot()
}

// The S3 review's B1 (T16): a KSK rollover on request with no standby
// configured, the default, mints the key it will promote.
func TestDriverRollsAKSKWithNoStandbyConfigured(t *testing.T) {
	r := newDriverRig(t, "nostandby.owned.example.", driverPolicy, "p2")
	bootstrap := func() uint16 {
		r.tick("mint")
		for _, k := range append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...) {
			if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
				t.Fatal(err)
			}
		}
		r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
		r.tick("propagated")
		return r.keysIn(KeyStateActive, "KSK")[0]
	}
	a := bootstrap()
	r.wire.parentDS[a] = true
	r.tick("steady")
	if n := len(r.keysIn(KeyStateMpdist, "KSK")); n != 0 {
		t.Fatalf("with no standby configured %d KSKs are in the pipeline, want 0", n)
	}
	r.l.RequestRollover("KSK")
	r.tick("roll requested")
	pend := r.keysIn(KeyStateMpdist, "KSK")
	if len(pend) != 1 {
		t.Fatalf("after the request %d KSKs in mpdist, want the one minted for the roll", len(pend))
	}
	b := pend[0]
	if _, _, err := r.l.Confirm(b, "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("the new key propagated")
	if st := r.state(b); st != KeyStateActive {
		t.Errorf("the key minted for the roll is %s, want active", st)
	}
	if st := r.state(a); st != KeyStateRetired {
		t.Errorf("the old KSK is %s, want retired", st)
	}
	if n := len(r.keysIn(KeyStateMpdist, "KSK")); n != 0 {
		t.Errorf("after the roll %d KSKs in the pipeline, want 0: the request is spent", n)
	}
}

// B4: a retired KSK whose DS the parent goes on serving is reported once
// the wait passes three margins; S3 withdraws nothing at the parent (S5).
func TestDriverReportsARetiredKSKWaitingOnTheParent(t *testing.T) {
	pol := driverPolicy
	pol.StandbyKSK = 1
	r := newDriverRig(t, "waits.owned.example.", pol, "p2")
	r.tick("mint")
	for _, k := range append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...) {
		if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
			t.Fatal(err)
		}
	}
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	a := r.keysIn(KeyStateActive, "KSK")[0]
	r.wire.parentDS[a] = true
	b := r.keysIn(KeyStateMpdist, "KSK")[0]
	if _, _, err := r.l.Confirm(b, "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("standby propagated")
	r.wire.parentDS[b] = true
	r.l.RequestRollover("KSK")
	r.tick("roll")
	if st := r.state(a); st != KeyStateRetired {
		t.Fatalf("old KSK %s, want retired", st)
	}
	// the row's retired_at is stamped by the store on the real clock; the
	// rig's clock is hours ahead of it by now, so align the stamp with it
	if _, err := r.kdb.DB.Exec(`UPDATE DnssecKeyStore SET retired_at=? WHERE zonename=? AND keyid=?`, r.clock.Now().UTC().Format(time.RFC3339), r.l.Zone, a); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(pol.Margin + time.Second)
	r.tick("margin, the parent still serves the DS")
	if st := r.state(a); st != KeyStateRetired {
		t.Fatalf("old KSK left retired while the parent serves its DS: %s", st)
	}
	if len(r.wire.reports) != 0 {
		t.Errorf("reported before three margins: %v", r.wire.reports)
	}
	r.clock.Advance(2*pol.Margin + time.Second)
	r.tick("three margins")
	r.tick("and again")
	if len(r.wire.reports) != 1 || !containsStr(r.wire.reports[0], "waits for the parent") {
		t.Errorf("reports %v, want one saying the key waits for the parent", r.wire.reports)
	}
	r.wire.parentDS[a] = false
	r.tick("the parent dropped it")
	if st := r.state(a); st == KeyStateRetired {
		t.Errorf("the old KSK is still retired after the parent dropped its DS")
	}
}

// S9: the RRSIGs are stripped before the row moves to mpremove; a strip
// that fails leaves the row where it was, with its distribution as it was,
// and the next attempt tries again.
func TestDriverKeepsTheRowWhenTheStripFails(t *testing.T) {
	r := newDriverRig(t, "strip.owned.example.", driverPolicy, "p2")
	r.tick("mint")
	ksk := r.keysIn(KeyStateMpdist, "KSK")[0]
	r.wire.mu.Lock()
	r.wire.stripErr = errors.New("the signer is busy")
	r.wire.mu.Unlock()
	if _, to, err := r.l.Apply(ksk, CmdWithdraw); err == nil || to != KeyStateMpdist {
		t.Fatalf("withdraw with the strip failing: to=%s err=%v, want the row kept in mpdist with an error", to, err)
	}
	if st := r.state(ksk); st != KeyStateMpdist {
		t.Errorf("after the failed strip the row is %s, want mpdist", st)
	}
	found := false
	for _, d := range r.l.InFlight() {
		if d.KeyId == ksk {
			found = true
			if d.Removal {
				t.Errorf("after the failed strip the key's distribution in flight is a removal: %+v", d)
			}
		}
	}
	if !found {
		t.Errorf("after the failed strip the key has no distribution in flight; want its own kept")
	}
	r.wire.mu.Lock()
	r.wire.stripErr = nil
	r.wire.mu.Unlock()
	if _, to, err := r.l.Apply(ksk, CmdWithdraw); err != nil || to != KeyStateMpremove {
		t.Fatalf("withdraw once the strip works: to=%s err=%v", to, err)
	}
	r.check("withdrawn")
}

// B2 and S12: the aggregated confirmation counts for the signers the
// record in flight expects, not for whoever signs now; one that answers a
// distribution sent before the record's is stale.
func TestDriverConfirmAllAtFollowsTheRecord(t *testing.T) {
	r := newDriverRig(t, "record.owned.example.", driverPolicy, "p2", "p3")
	r.tick("mint")
	ksk := r.keysIn(KeyStateMpdist, "KSK")[0]
	sent := r.l.InFlight()[0].SentAt
	if _, _, err := r.l.ConfirmAllAt(ksk, "applied", "", sent.Add(-time.Hour)); !errors.Is(err, ErrStaleConfirmation) {
		t.Errorf("a confirmation of an older distribution: err=%v, want ErrStaleConfirmation", err)
	}
	if st := r.state(ksk); st != KeyStateMpdist {
		t.Fatalf("the stale confirmation moved the key to %s", st)
	}
	// p3 leaves, but the record still expects it until the driver hears of
	// the change: the confirmation is by the record, so p3 counts too
	r.wire.mu.Lock()
	r.wire.signers = []string{"p2"}
	r.wire.mu.Unlock()
	if _, to, err := r.l.ConfirmAllAt(ksk, "applied", "", sent); err != nil || to != KeyStatePublished {
		t.Errorf("the confirmation by the record: to=%s err=%v, want published", to, err)
	}
	// alone: the confirmation of a key with nobody expected publishes it
	r.wire.mu.Lock()
	r.wire.signers = nil
	r.wire.mu.Unlock()
	zsk := r.keysIn(KeyStateMpdist, "ZSK")[0]
	if err := r.l.SignersChanged(); err != nil {
		t.Fatal(err)
	}
	if st := r.state(zsk); st != KeyStatePublished {
		t.Errorf("alone after the signers left, the ZSK is %s, want published", st)
	}
	if _, _, err := r.l.ConfirmAllAt(ksk, "rejected", "late", time.Time{}); err == nil {
		t.Error("a rejection of a key with no distribution in flight was taken")
	}
}

// S6: the owner runs multi-provider zones only; a zone named in the
// configuration that is not one keeps tdns's machine.
func TestOwnerNeedsAMultiProviderZone(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
	mp := &tdns.ZoneData{ZoneName: "mp.example.", Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}}
	plain := &tdns.ZoneData{ZoneName: "plain.example.", Options: map[tdns.ZoneOption]bool{}}
	owner.Take(mp.ZoneName)
	owner.Take(plain.ZoneName)
	if !owner.Owns(mp) {
		t.Error("the multi-provider zone taken is not owned")
	}
	if owner.Owns(plain) {
		t.Error("a zone that is not multi-provider is owned (it would get two machines)")
	}
}

// S10: the hook that pushes the inventory on a state change is for the
// zones tdns still runs; an owned zone's machine pushes on its own.
func TestHookPushesOnlyForZonesTdnsRuns(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	conf := withSignerHooks(t, kdb)
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
	conf.InternalMp.KeyLifecycleOwner = owner
	oldApp := tdns.Globals.App.Type
	tdns.Globals.App.Type = AppTypeMPSigner
	t.Cleanup(func() { tdns.Globals.App.Type = oldApp })
	pushes := make(chan string, 8)
	saved := inventoryPush
	inventoryPush = func(conf *Config, zone string) { pushes <- zone }
	t.Cleanup(func() { inventoryPush = saved })
	owned := signerTestZone(t, "owned.hook.example.", kdb)
	hooked := signerTestZone(t, "hooked.hook.example.", kdb)
	owner.Take(owned.ZoneName)
	for _, z := range []*MPZoneData{owned, hooked} {
		k := mpGenKey(t, kdb, z.ZoneName, tdns.DnskeyStateActive, "KSK")
		if err := tdns.UpdateKeyRow(kdb, z.ZoneName, k, tdns.DnskeyStateStandby, mustCols(KeyStateStandby, true)); err != nil {
			t.Fatal(err)
		}
	}
	// the generate and the state write each fire the hook: every push is
	// for the zone tdns runs, none for the owned one
	n := 0
	deadline := time.After(2 * time.Second)
	for done := false; !done; {
		select {
		case z := <-pushes:
			n++
			if z != hooked.ZoneName {
				t.Errorf("the hook pushed for %s, want only the zone tdns runs (%s); the owned zone's machine pushes on its own", z, hooked.ZoneName)
			}
		case <-deadline:
			done = true
		case <-time.After(300 * time.Millisecond):
			done = n > 0
		}
	}
	if n == 0 {
		t.Fatal("the hook did not push for the zone tdns runs")
	}
}

// The re-review's N8: a resend keeps the record's first send time, so the
// answer a slow signer gives to the first send still counts after E12; a
// confirmation older than the first send by more than the tolerance is
// stale; one a little earlier (the agent's clock, its tracking after the
// push) counts; the resend timer runs from the last send; and all of it
// survives a restart.
func TestDriverResendKeepsTheFirstSendTime(t *testing.T) {
	pol := driverPolicy
	pol.ResendAfter = 30 * time.Minute
	r := newDriverRig(t, "resend.owned.example.", pol, "p2")
	r.tick("mint")
	ksk := r.keysIn(KeyStateMpdist, "KSK")[0]
	var first DistributionStatus
	for _, d := range r.l.InFlight() {
		if d.KeyId == ksk {
			first = d
		}
	}
	sends := len(r.wire.distributions())
	r.clock.Advance(pol.ResendAfter + time.Second)
	r.tick("resend due")
	if len(r.wire.distributions()) != sends+2 {
		t.Fatalf("after the resend timer %d distributions, want %d (both keys sent again)", len(r.wire.distributions()), sends+2)
	}
	for _, d := range r.l.InFlight() {
		if d.KeyId == ksk && !d.SentAt.Equal(first.SentAt) {
			t.Errorf("the resend moved the first send time %s to %s", first.SentAt, d.SentAt)
		}
	}
	r.tick("right after the resend")
	if len(r.wire.distributions()) != sends+2 {
		t.Errorf("a tick right after the resend sent again: %d distributions, want %d (the timer runs from the last send)", len(r.wire.distributions()), sends+2)
	}
	// the agent's answer to the first send: its tracking began just after
	// the push, on its own clock, a little behind ours
	if _, to, err := r.l.ConfirmAllAt(ksk, "applied", "", first.SentAt.Add(-30*time.Second)); err != nil || to != KeyStatePublished {
		t.Errorf("the answer to the first send after a resend: to=%s err=%v, want published", to, err)
	}
	// a removal's record refuses the answer to a distribution from before
	// it: the key is given up on while published (T7')
	if _, to, err := r.l.Apply(ksk, CmdWithdraw); err != nil || to != KeyStateMpremove {
		t.Fatalf("withdraw: to=%s err=%v", to, err)
	}
	if _, _, err := r.l.ConfirmAllAt(ksk, "applied", "", first.SentAt); !errors.Is(err, ErrStaleConfirmation) {
		t.Errorf("the old distribution's answer against the removal's record: err=%v, want ErrStaleConfirmation", err)
	}
	if st := r.state(ksk); st != KeyStateMpremove {
		t.Errorf("the stale answer moved the key to %s", st)
	}
	// a restart keeps both times
	before := r.l.InFlight()
	l2 := NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, pol, r.wire)
	if err := l2.Reload(); err != nil {
		t.Fatal(err)
	}
	after := l2.InFlight()
	// persisted to the second
	if len(after) != len(before) || !after[0].SentAt.Equal(before[0].SentAt.Truncate(time.Second)) || after[0].KeyId != before[0].KeyId {
		t.Errorf("after a restart the records are %+v, want %+v", after, before)
	}
	if _, _, err := l2.ConfirmAllAt(ksk, "applied", "", first.SentAt); !errors.Is(err, ErrStaleConfirmation) {
		t.Errorf("after a restart the old answer is taken: err=%v", err)
	}
}

// N9: a zone taken by configuration that this provider does not sign is
// released, so tdns's own machine runs its keys rather than nobody.
func TestEngineReleasesAZoneThisProviderDoesNotSign(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "signer", Agents: []*PeerConf{{Identity: "agent.us.example."}}})
	conf.Config.Internal.KeyDB = kdb
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
	e := NewKeyLifecycleEngine(conf, owner)
	mpzd := signerTestZone(t, "notours.owned.example.", kdb)
	apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	hp := &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMSigners{Signers: []string{"p1", "p2"}}}}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: dns.RR_Header{Name: mpzd.ZoneName, Rrtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, Ttl: 3600}, Data: hp}}})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.InstallInitialSnapshot()
	owner.Take(mpzd.ZoneName)
	if !owner.Owns(mpzd.ZoneData) {
		t.Fatal("not owned after Take")
	}
	if e.driver(mpzd.ZoneName) != nil {
		t.Error("a driver for a zone this provider does not sign")
	}
	if owner.Owns(mpzd.ZoneData) {
		t.Error("still owned after the engine found this provider is not a signer; tdns's machine would not run it either")
	}
}

// N10: a key whose step fails does not stop the zone's tick: the strip a
// retired key needs keeps failing, and the standby the policy wants is
// still minted; the tick reports the failure.
func TestDriverTickGoesOnPastAFailingKey(t *testing.T) {
	pol := driverPolicy
	pol.StandbyKSK = 1
	r := newDriverRig(t, "goeson.owned.example.", pol, "p2")
	r.tick("mint")
	for _, k := range append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...) {
		if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
			t.Fatal(err)
		}
	}
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	a := r.keysIn(KeyStateActive, "KSK")[0]
	r.wire.parentDS[a] = true
	b := r.keysIn(KeyStateMpdist, "KSK")[0]
	if _, _, err := r.l.Confirm(b, "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("standby propagated")
	r.wire.parentDS[b] = true
	r.l.RequestRollover("KSK")
	r.tick("roll")
	if st := r.state(a); st != KeyStateRetired {
		t.Fatalf("old KSK %s, want retired", st)
	}
	r.wire.parentDS[a] = false
	// the strip keeps failing at the margin; the roll left the pipeline
	// empty, so the tick has a standby to mint beside the failing key
	r.wire.mu.Lock()
	r.wire.stripErr = errors.New("the signer is busy")
	r.wire.mu.Unlock()
	r.clock.Advance(pol.Margin + time.Second)
	if err := r.l.Tick(); err == nil {
		t.Error("a tick with a failing strip reported no error")
	}
	if st := r.state(a); st != KeyStateRetired {
		t.Errorf("the old KSK is %s after the failed strip, want still retired", st)
	}
	if n := len(r.keysIn(KeyStateMpdist, "KSK")); n != 1 {
		t.Errorf("the standby was not minted beside the failing key: %d in mpdist, want 1", n)
	}
	r.wire.mu.Lock()
	r.wire.stripErr = nil
	r.wire.mu.Unlock()
	r.tick("the strip works again")
	if st := r.state(a); st == KeyStateRetired {
		t.Error("the old KSK is still retired once the strip works")
	}
}

// N6: the table's mint row knows a rollover pending with nothing in the
// pipeline, as Tick does (T16 with a standby count of 0).
func TestMintRowMintsForARolloverPending(t *testing.T) {
	steady := ZoneView{StandbyCount: 0, InPipeline: 0}
	if _, row := Next(KeyView{}, EvMint, steady); row != nil {
		t.Errorf("a steady zone with no standby wanted mints (row %s)", row.ID)
	}
	pending := steady
	pending.RolloverPending = true
	if next, row := Next(KeyView{}, EvMint, pending); row == nil || row.ID != "T1" || next != KeyStateCreated {
		t.Errorf("a rollover pending with nothing in the pipeline: row %v next %q, want T1 to created", row, next)
	}
	pending.InPipeline = 1
	if _, row := Next(KeyView{}, EvMint, pending); row != nil {
		t.Errorf("a rollover pending with a key already in the pipeline mints again (row %s)", row.ID)
	}
}
