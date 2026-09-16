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
