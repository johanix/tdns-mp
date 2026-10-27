package tdnsmp

import (
	"context"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// #191: a zone named in key-lifecycle-zones is the machine's from the
// signer's start, not from the take. The take waits for the zone's first
// load to bind its policy; in that window tdns's key worker minted a
// standby by tdns's policy, and its signing path checked the stored keys
// against tdns's policy, which mid-way through an algorithm rollover
// refused to sign (SERVFAIL until the take).

// ownsConfigRig is a signer's owner, registered with tdns, whose config
// names the zones in named.
func ownsConfigRig(t *testing.T, named ...string) (*tdns.KeyDB, *Config, *MPKeyLifecycleOwner) {
	t.Helper()
	kdb := newMPTestKeyDB(t)
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.SetMpConfig(&MultiProviderConf{Role: "signer", Agents: []*PeerConf{{Identity: "agent.us.example."}}, KeyLifecycleZones: named})
	owner := RegisterMPKeyLifecycleOwner(conf)
	t.Cleanup(func() { tdns.RegisterKeyLifecycleOwner(nil) })
	owner.SetConfiguredZones(conf.keyLifecycleZones)
	return kdb, conf, owner
}

// keyCount is the number of key rows the zone has, any state.
func keyCount(t *testing.T, kdb *tdns.KeyDB, zone string) int {
	t.Helper()
	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=?`, zone).Scan(&n); err != nil {
		t.Fatalf("count keys of %s: %v", zone, err)
	}
	return n
}

func genKey(t *testing.T, kdb *tdns.KeyDB, zone, state, role string, alg uint8) uint16 {
	t.Helper()
	pkc, _, err := kdb.GenerateKeypair(zone, "test", state, dns.TypeDNSKEY, alg, role, nil)
	if err != nil {
		t.Fatalf("generate %s %s of %s: %v", state, role, zone, err)
	}
	return pkc.KeyId
}

// The owner's answer: a named multi-provider zone with keys to sign with is
// owned before it is taken; one not named, one that is not multi-provider,
// and one with no active key of a role are not. A released zone is tdns's
// until it is taken again.
func TestNamedZoneIsOwnedBeforeTheTake(t *testing.T) {
	kdb, _, owner := ownsConfigRig(t, "named.owns.example.", "plain.owns.example.", "fresh.owns.example.")
	named := signerTestZone(t, "named.owns.example.", kdb)
	other := signerTestZone(t, "other.owns.example.", kdb)
	plain := signerTestZone(t, "plain.owns.example.", kdb)
	plain.ZoneData.Options[tdns.OptMultiProvider] = false
	fresh := signerTestZone(t, "fresh.owns.example.", kdb)
	for _, z := range []*MPZoneData{named, other, plain} {
		genKey(t, kdb, z.ZoneName, tdns.DnskeyStateActive, "KSK", dns.ED25519)
		genKey(t, kdb, z.ZoneName, tdns.DnskeyStateActive, "ZSK", dns.ED25519)
	}

	if !owner.Owns(named.ZoneData) || !owner.runsKeys(named.ZoneData) {
		t.Errorf("named zone, not taken: Owns=%v runsKeys=%v, want both true", owner.Owns(named.ZoneData), owner.runsKeys(named.ZoneData))
	}
	if z := owner.Zones(); len(z) != 0 {
		t.Errorf("owning a named zone took it: %v", z)
	}
	if owner.Owns(other.ZoneData) {
		t.Error("a zone the config does not name is owned")
	}
	if owner.Owns(plain.ZoneData) {
		t.Error("a named zone that is not multi-provider is owned")
	}

	// a named zone never signed: its first keys are tdns's, and it is owned
	// once they exist
	if owner.Owns(fresh.ZoneData) {
		t.Error("a named zone with no keys is owned; tdns's first bind could not sign it")
	}
	genKey(t, kdb, fresh.ZoneName, tdns.DnskeyStateActive, "ZSK", dns.ED25519)
	if owner.Owns(fresh.ZoneData) {
		t.Error("a named zone with no active KSK is owned")
	}
	genKey(t, kdb, fresh.ZoneName, tdns.DnskeyStateActive, "KSK", dns.ED25519)
	if !owner.Owns(fresh.ZoneData) {
		t.Error("a named zone with an active KSK and ZSK is not owned")
	}

	owner.Release(named.ZoneName)
	if owner.Owns(named.ZoneData) {
		t.Error("a released named zone is still owned")
	}
	owner.Take(named.ZoneName)
	if !owner.Owns(named.ZoneData) {
		t.Error("a named zone taken again is not owned")
	}
}

// The window, tdns's KeyStateWorker: a named zone that is not taken yet
// gets no standby key. The zone the config does not name gets one, which
// shows the worker ran its standby maintenance.
func TestNoStandbyMintedOnANamedZoneBeforeTheTake(t *testing.T) {
	kdb, conf, owner := ownsConfigRig(t, "window.owns.example.")
	named := signerTestZone(t, "window.owns.example.", kdb)
	other := signerTestZone(t, "tdns.owns.example.", kdb)
	for _, z := range []*MPZoneData{named, other} {
		genKey(t, kdb, z.ZoneName, tdns.DnskeyStateActive, "KSK", dns.ED25519)
		genKey(t, kdb, z.ZoneName, tdns.DnskeyStateActive, "ZSK", dns.ED25519)
	}
	if z := owner.Zones(); len(z) != 0 {
		t.Fatalf("zones taken: %v, want none (the window before the take)", z)
	}

	conf.Config.Dnssec.Kasp.CheckInterval = "20ms"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tdns.KeyStateWorker(ctx, conf.Config) }()
	deadline := time.Now().Add(5 * time.Second)
	for keyCount(t, kdb, other.ZoneName) < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // a few more ticks over the named zone
	cancel()
	<-done

	if n := keyCount(t, kdb, other.ZoneName); n != 3 {
		t.Fatalf("the zone tdns runs has %d keys, want its standby ZSK minted (3); the worker did not run", n)
	}
	if n := keyCount(t, kdb, named.ZoneName); n != 2 {
		t.Errorf("the named zone not taken yet has %d keys, want its 2: tdns's worker minted beside the machine", n)
	}
}

// The window, tdns's signing path: mid-way through an algorithm rollover
// the stored keys sign with the owner's algorithm (ECDSAP256SHA256), and
// tdns's bound policy still names the old one (ED25519, no rollover
// method). A named zone not taken yet signs with its stored keys and is
// not checked against tdns's policy; a zone tdns runs is refused.
func TestNamedZoneSignsWithItsStoredKeysBeforeTheTake(t *testing.T) {
	kdb, _, owner := ownsConfigRig(t, "roll.owns.example.")
	named := signerTestZone(t, "roll.owns.example.", kdb)
	other := signerTestZone(t, "tdnsroll.owns.example.", kdb)
	for _, z := range []*MPZoneData{named, other} {
		z.ZoneData.DnssecPolicy.Rollover.Method = tdns.RolloverMethodNone
		genKey(t, kdb, z.ZoneName, tdns.DnskeyStateActive, "KSK", dns.ECDSAP256SHA256)
		genKey(t, kdb, z.ZoneName, tdns.DnskeyStateActive, "ZSK", dns.ECDSAP256SHA256)
	}
	if z := owner.Zones(); len(z) != 0 {
		t.Fatalf("zones taken: %v, want none (the window before the take)", z)
	}

	if _, err := other.ZoneData.EnsureActiveDnssecKeys(kdb, false); err == nil || !strings.Contains(err.Error(), "requires an auto-rollover policy") {
		t.Fatalf("the zone tdns runs: %v, want tdns's policy check to refuse the KSK algorithm", err)
	}

	dak, err := named.ZoneData.EnsureActiveDnssecKeys(kdb, false)
	if err != nil {
		t.Fatalf("the named zone not taken yet: %v, want its stored keys", err)
	}
	if len(dak.KSKs) != 1 || len(dak.ZSKs) != 1 || dak.KSKs[0].DnskeyRR.Algorithm != dns.ECDSAP256SHA256 {
		t.Errorf("the named zone's signing keys: %d KSK %d ZSK, want the stored ECDSAP256SHA256 pair", len(dak.KSKs), len(dak.ZSKs))
	}
	if _, err := named.ZoneData.SignZone(context.Background(), kdb, true); err != nil {
		t.Errorf("signing the named zone not taken yet: %v", err)
	}
	if n := keyCount(t, kdb, named.ZoneName); n != 2 {
		t.Errorf("the named zone has %d keys after signing, want its 2", n)
	}

	// a role with no active key is "not yet": nothing minted beside the
	// owner's keys (a lone active KSK signs as a CSK, so the role missing
	// is the KSK)
	half := signerTestZone(t, "half.owns.example.", kdb)
	owner.Take(half.ZoneName)
	genKey(t, kdb, half.ZoneName, tdns.DnskeyStateActive, "ZSK", dns.ED25519)
	if _, err := half.ZoneData.EnsureActiveDnssecKeys(kdb, false); err == nil || !strings.Contains(err.Error(), tdns.ErrKeyGenerationDeferred.Error()) {
		t.Errorf("an owned zone with no active KSK: %v, want the deferral", err)
	}
	if n := keyCount(t, kdb, half.ZoneName); n != 1 {
		t.Errorf("an owned zone with no active KSK has %d keys, want its 1", n)
	}
}

// A key-lifecycle-zones entry names its zone whatever its case, as the
// rollout gate reads it: "A.MIXED.EXAMPLE." passes the gate for
// a.mixed.example., so the zone is owned before the take and taken, and its
// driver runs.
func TestMixedCaseNamedZoneIsOwnedAndTaken(t *testing.T) {
	kdb, conf, owner := ownsConfigRig(t, "A.MIXED.EXAMPLE.")
	e := NewKeyLifecycleEngine(conf, owner)
	mpzd := signerTestZone(t, "a.mixed.example.", kdb)
	zoneSignedBy(t, mpzd, "agent.us.example.", "p2")
	genKey(t, kdb, mpzd.ZoneName, tdns.DnskeyStateActive, "KSK", dns.ED25519)
	genKey(t, kdb, mpzd.ZoneName, tdns.DnskeyStateActive, "ZSK", dns.ED25519)
	if missing := unlistedMultiProviderZones([]string{mpzd.ZoneName}, conf.keyLifecycleZones()); len(missing) != 0 {
		t.Fatalf("the rollout gate does not take the entry for the zone: missing %v", missing)
	}

	if !owner.Owns(mpzd.ZoneData) {
		t.Error("the zone named in another case is not owned before the take")
	}
	e.TakeConfiguredZones()
	if z := owner.Zones(); len(z) != 1 || z[0] != mpzd.ZoneName {
		t.Fatalf("zones taken: %v, want %s", z, mpzd.ZoneName)
	}
	if !owner.taken(mpzd.ZoneName) || !owner.Owns(mpzd.ZoneData) {
		t.Errorf("after the take: taken=%v Owns=%v, want both", owner.taken(mpzd.ZoneName), owner.Owns(mpzd.ZoneData))
	}
	if e.driver(mpzd.ZoneName) == nil {
		t.Error("no driver for the zone named in another case")
	}
}

// The engine runs a named zone's driver from the take, not from the
// ownership: before the take a signal for it has no taker here, as before.
func TestNamedZoneHasNoDriverBeforeTheTake(t *testing.T) {
	kdb, conf, owner := ownsConfigRig(t, "driver.owns.example.")
	e := NewKeyLifecycleEngine(conf, owner)
	mpzd := signerTestZone(t, "driver.owns.example.", kdb)
	zoneSignedBy(t, mpzd, "agent.us.example.", "p2")
	genKey(t, kdb, mpzd.ZoneName, tdns.DnskeyStateActive, "KSK", dns.ED25519)
	genKey(t, kdb, mpzd.ZoneName, tdns.DnskeyStateActive, "ZSK", dns.ED25519)
	if !owner.Owns(mpzd.ZoneData) {
		t.Fatal("the named zone is not owned before the take")
	}
	if e.driver(mpzd.ZoneName) != nil {
		t.Error("a driver runs for a named zone not taken yet")
	}
	if e.Signal(mpzd.ZoneName, 1, "propagated", "", time.Time{}) {
		t.Error("a signal for a named zone not taken yet was claimed by a driver")
	}
	e.TakeConfiguredZones()
	if e.driver(mpzd.ZoneName) == nil {
		t.Error("no driver after the take")
	}
}
