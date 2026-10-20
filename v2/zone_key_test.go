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

// testSig0Key makes an active SIG(0) key for zone in kdb and returns its row.
func testSig0Key(t *testing.T, kdb *tdns.KeyDB, zone string) sig0Row {
	t.Helper()
	before, err := activeSig0Rows(kdb, ZoneName(zone))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kdb.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: zone,
		Keyname: zone, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("a SIG(0) key for %s: %v", zone, err)
	}
	after, err := activeSig0Rows(kdb, ZoneName(zone))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range after {
		if !slices.ContainsFunc(before, func(b sig0Row) bool { return b.keyid == r.keyid }) {
			return r
		}
	}
	t.Fatalf("no new key for %s", zone)
	return sig0Row{}
}

// keyZone is handoverZone with these KEY records at its apex.
func keyZone(t *testing.T, zone string, keys ...sig0Row) *tdns.ZoneData {
	t.Helper()
	zd := seedZoneWithHSYNC3(t, zone, "alice.agent.example.", "bob.agent.example.", "carol.agent.example.", "dave.agent.example.")
	rr, err := dns.NewRR(zone + ` 3600 IN HSYNCPARAM servers="alice" signers="bob" auditors="carol"`)
	if err != nil {
		t.Fatalf("HSYNCPARAM: %v", err)
	}
	apex, _ := zd.Data.Get(zone)
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{rr}})
	if len(keys) > 0 {
		var rrs []dns.RR
		for _, k := range keys {
			rrs = append(rrs, k.key)
		}
		apex.RRtypes.Set(dns.TypeKEY, core.RRset{RRs: rrs})
	}
	zd.Data.Set(zone, apex)
	zd.InstallInitialSnapshot()
	return zd
}

func keyIDs(rows []sig0Row) []uint16 {
	var out []uint16
	for _, r := range rows {
		out = append(out, r.keyid)
	}
	slices.Sort(out)
	return out
}

// The holder hands over the key the zone publishes, not the first active row
// of its keystore. A holder whose keys the zone does not publish holds no key
// of the zone's.
func TestTheHolderHandsOverThePublishedKey(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	answers := make(chan keyAnswer, 4)
	saved := answerConfigRequest
	answerConfigRequest = func(_ *MPTransportBridge, _ *AgentRegistry, requester, _, subtype, nonce string, data map[string]string) {
		answers <- keyAnswer{requester, subtype, nonce, data}
	}
	t.Cleanup(func() { answerConfigRequest = saved })
	ask := func(zone string) map[string]string {
		t.Helper()
		env.Bob.Registry.MsgHandler(&AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{MessageType: AgentMsgRfi,
			OriginatorID: "alice.agent.example.", Zone: ZoneName(zone), RfiType: "CONFIG", RfiSubtype: "sig0key", Nonce: "n-" + zone}}, nil, nil)
		select {
		case a := <-answers:
			return a.data
		case <-time.After(5 * time.Second):
			t.Fatalf("no answer for %s", zone)
			return nil
		}
	}

	for _, which := range []int{0, 1} {
		zone := []string{"first.published.example.", "second.published.example."}[which]
		kdb := newMPTestKeyDB(t)
		k := []sig0Row{testSig0Key(t, kdb, zone), testSig0Key(t, kdb, zone)}
		keyZone(t, zone, k[which]).KeyDB = kdb
		if got := ask(zone); got["keyrr"] != k[which].keyrr {
			t.Errorf("%s publishes key %d; the holder handed over %q", zone, k[which].keyid, got["keyrr"])
		}
	}

	// a holder whose apex carries several KEYs does not say "no key": its
	// keystore may hold one of them
	const several = "several.holder.example."
	skdb := newMPTestKeyDB(t)
	keyZone(t, several, testSig0Key(t, skdb, several), testSig0Key(t, newMPTestKeyDB(t), several)).KeyDB = skdb
	if got := ask(several); got["status"] != sig0StatusSeveral || got["privatekey"] != "" {
		t.Errorf("a holder whose apex carries two KEYs answered %v, want %q", got, sig0StatusSeveral)
	}

	const zone = "unpublished.example."
	kdb, other := newMPTestKeyDB(t), newMPTestKeyDB(t)
	testSig0Key(t, kdb, zone)
	keyZone(t, zone, testSig0Key(t, other, zone)).KeyDB = kdb
	if got := ask(zone); got["status"] != "no sig0 key for zone" || got["privatekey"] != "" {
		t.Errorf("a holder whose key the zone does not publish answered %v, want no key", got)
	}
}

// A key handed over is added, and every other active key of the zone is
// retired: the agent keeps one active key, the zone's. A key the zone does not
// publish is not imported, and retires nothing.
func TestOneActiveKeyPerZone(t *testing.T) {
	const zone = "onekey.example."
	hdb := NewHsyncDB(newMPTestKeyDB(t))
	old := testSig0Key(t, hdb.KeyDB, zone)
	holder := newMPTestKeyDB(t)
	zoneKey, stray := testSig0Key(t, holder, zone), testSig0Key(t, holder, zone)
	keyZone(t, zone, zoneKey)
	data := func(r sig0Row) map[string]string {
		return map[string]string{"algorithm": r.algorithm, "privatekey": r.privatekey, "keyrr": r.keyrr}
	}

	if err := importSig0KeyFromPeer(hdb, zone, data(stray)); err == nil {
		t.Fatal("a key the zone does not publish was imported")
	}
	if got, _ := activeSig0Rows(hdb.KeyDB, zone); !slices.Equal(keyIDs(got), []uint16{old.keyid}) {
		t.Fatalf("after a refused import the active keys are %v, want only %d", keyIDs(got), old.keyid)
	}

	if err := importSig0KeyFromPeer(hdb, zone, data(zoneKey)); err != nil {
		t.Fatalf("the zone's key was not imported: %v", err)
	}
	if got, _ := activeSig0Rows(hdb.KeyDB, zone); !slices.Equal(keyIDs(got), []uint16{zoneKey.keyid}) {
		t.Errorf("after the import the active keys are %v, want only the zone's key %d", keyIDs(got), zoneKey.keyid)
	}
	if sak, err := hdb.GetSig0Keys(zone, tdns.Sig0StateActive); err != nil || len(sak.Keys) != 1 || sak.Keys[0].KeyId != zoneKey.keyid {
		t.Errorf("tdns signs with %+v (%v), want the zone's key %d", sak, err, zoneKey.keyid)
	}
}

// A zone that publishes no KEY: the zone's key is the active key tdns signs
// with, and the others are retired.
func TestWithNoPublishedKeyTheKeyTdnsSignsWithIsKept(t *testing.T) {
	const zone = "nokey.published.example."
	kdb := newMPTestKeyDB(t)
	testSig0Key(t, kdb, zone)
	testSig0Key(t, kdb, zone)
	keyZone(t, zone)
	sak, err := kdb.GetSig0Keys(zone, tdns.Sig0StateActive)
	if err != nil || len(sak.Keys) == 0 {
		t.Fatalf("tdns's key: %v", err)
	}
	signs := sak.Keys[0].KeyId
	zk, err := readZoneKey(kdb, zone)
	if err != nil || zk.held == nil || zk.held.keyid != signs {
		t.Fatalf("the zone's key: %+v, %v; want %d, the key tdns signs with", zk, err, signs)
	}
	if only, err := retireOtherActiveKeys(kdb, zone, zk); err != nil || !only {
		t.Fatalf("retire: only %v, %v", only, err)
	}
	if got, _ := activeSig0Rows(kdb, zone); !slices.Equal(keyIDs(got), []uint16{signs}) {
		t.Errorf("the active keys are %v, want only %d", keyIDs(got), signs)
	}
}

// While the apex carries several KEYs no local key is the zone's key: the
// agent holds none, hands none over, imports none and retires none.
func TestSeveralPublishedKEYsAreNoZoneKey(t *testing.T) {
	const zone = "several.keys.example."
	hdb := NewHsyncDB(newMPTestKeyDB(t))
	mine := testSig0Key(t, hdb.KeyDB, zone)
	other := testSig0Key(t, newMPTestKeyDB(t), zone)
	keyZone(t, zone, mine, other)

	zk, err := readZoneKey(hdb.KeyDB, zone)
	if err != nil || zk.held != nil {
		t.Fatalf("with two KEYs at the apex the zone's key is %+v (%v), want none", zk, err)
	}
	if only, err := retireOtherActiveKeys(hdb.KeyDB, zone, zk); only || err != nil {
		t.Errorf("retire with no zone's key: only %v, %v", only, err)
	}
	if err := importSig0KeyFromPeer(hdb, zone, map[string]string{"algorithm": other.algorithm, "privatekey": other.privatekey, "keyrr": other.keyrr}); err == nil {
		t.Error("a key was imported while the apex carries two KEYs")
	}
	if got, _ := activeSig0Rows(hdb.KeyDB, zone); !slices.Equal(keyIDs(got), []uint16{mine.keyid}) {
		t.Errorf("the active keys are %v, want %d as it was", keyIDs(got), mine.keyid)
	}
}
