package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// B-MP M-2S: the signer's keys live in tdns's DnssecKeyStore and tdns signs
// with them; what is MP's is the protocol between the states, run through
// tdns's key lifecycle hooks. Mode 2 (single signer): no key is minted
// beside staged ones, a confirmed key is promoted and signs. Mode 4 (several
// signers): the other signers' keys are foreign rows, served and never
// signing. And the one-shot, fail-closed migration of the old key table.

func newMPTestKeyDB(t *testing.T) *tdns.KeyDB {
	t.Helper()
	f := filepath.Join(t.TempDir(), "keys.db")
	if err := os.WriteFile(f, nil, 0664); err != nil {
		t.Fatalf("create db file: %v", err)
	}
	kdb, err := tdns.NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	return kdb
}

// signerTestZone is a Ready multi-provider zone that signs its own content,
// with a bound policy and no keys, registered with tdns and wrapped.
func signerTestZone(t *testing.T, name string, kdb *tdns.KeyDB) *MPZoneData {
	t.Helper()
	zone := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 1800 604800 7200\n"+
		"%s 3600 IN NS ns1.%s\nns1.%s 3600 IN A 192.0.2.1\nwww.%s 3600 IN A 192.0.2.2\n", name, name, name, name, name, name, name)
	zd := &tdns.ZoneData{
		ZoneName:  name,
		ZoneStore: tdns.MapZone,
		ZoneType:  tdns.Primary,
		Logger:    log.New(io.Discard, "", 0),
		Options:   map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true, tdns.OptInlineSigning: true},
		KeyDB:     kdb,
		DnssecPolicy: &tdns.DnssecPolicy{
			Mode:         tdns.DnssecPolicyModeKSKZSK,
			KSKAlgorithm: dns.ED25519,
			ZSKAlgorithm: dns.ED25519,
			SigValidity:  tdns.PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
		},
	}
	if _, _, err := zd.ReadZoneData(zone, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	tdns.Zones.Set(name, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(name)
		Zones.Invalidate(name)
	})
	mpzd, ok := Zones.Get(name)
	if !ok {
		t.Fatal("wrapper not found")
	}
	return mpzd
}

func withSignerHooks(t *testing.T, kdb *tdns.KeyDB) *Config {
	t.Helper()
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	RegisterMPKeyLifecycleHooks(conf)
	t.Cleanup(func() { tdns.RegisterKeyLifecycleHooks(tdns.KeyLifecycleHooks{}) })
	return conf
}

func mpGenKey(t *testing.T, kdb *tdns.KeyDB, zone, state, role string) uint16 {
	t.Helper()
	pkc, _, err := kdb.GenerateKeypair(zone, "test", state, dns.TypeDNSKEY, dns.ED25519, role, nil)
	if err != nil {
		t.Fatalf("generate %s %s: %v", state, role, err)
	}
	return pkc.KeyId
}

func mpKeyState(t *testing.T, kdb *tdns.KeyDB, zone string, keyid uint16) string {
	t.Helper()
	var state string
	if err := kdb.DB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zone, keyid).Scan(&state); err != nil {
		t.Fatalf("state of key %d: %v", keyid, err)
	}
	return state
}

func mpCountByCreator(t *testing.T, kdb *tdns.KeyDB, zone, creator string) int {
	t.Helper()
	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=? AND creator=?`, zone, creator).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func servedDnskeyTagsOf(t *testing.T, zd *tdns.ZoneData) map[uint16]bool {
	t.Helper()
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("GetOwner(apex): owner=%v err=%v", apex, err)
	}
	tags := map[uint16]bool{}
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
		tags[rr.(*dns.DNSKEY).KeyTag()] = true
	}
	return tags
}

func rrsigTagsOf(t *testing.T, zd *tdns.ZoneData, owner string, rrtype uint16) []uint16 {
	t.Helper()
	od, err := zd.GetOwner(owner)
	if err != nil || od == nil {
		t.Fatalf("GetOwner(%s): owner=%v err=%v", owner, od, err)
	}
	var tags []uint16
	for _, s := range od.RRtypes.GetOnlyRRSet(rrtype).RRSIGs {
		tags = append(tags, s.(*dns.RRSIG).KeyTag)
	}
	return tags
}

// Mode 2. Keys staged as mpdist are not signed with and nothing is minted
// beside them; once the peers confirm propagation (the KEYSTATE handler's
// transitions, here called directly) and the TTL has passed, tdns promotes
// them and signs.
func TestSignerStagedKeysGateTheSignUntilConfirmed(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	hdb := NewHsyncDB(kdb)
	if err := hdb.InitHsyncTables(); err != nil {
		t.Fatalf("InitHsyncTables: %v", err)
	}
	withSignerHooks(t, kdb)
	mpzd := signerTestZone(t, "mode2.example.", kdb)
	ksk := mpGenKey(t, kdb, mpzd.ZoneName, DnskeyStateMpdist, "KSK")
	zsk := mpGenKey(t, kdb, mpzd.ZoneName, DnskeyStateMpdist, "ZSK")

	// The first-load publish: unsigned, not Ready, no mint, no fault.
	mpzd.ZoneData.InstallInitialSnapshot()
	t.Cleanup(mpzd.ZoneData.StopPublisher)
	if mpzd.Ready {
		t.Fatal("a signing zone with only staged keys became Ready")
	}
	if _, err := mpzd.ZoneData.SignZone(context.Background(), kdb, false); !errors.Is(err, tdns.ErrKeyGenerationDeferred) {
		t.Fatalf("SignZone with only staged keys: err=%v, want ErrKeyGenerationDeferred", err)
	}
	if n := mpCountByCreator(t, kdb, mpzd.ZoneName, "ensure-active-keys"); n != 0 {
		t.Fatalf("%d keys minted by the generation fallback beside the staged ones", n)
	}
	if mpzd.HasError(tdns.DnssecError) {
		t.Fatalf("DnssecError for a zone that is merely waiting: %s", mpzd.ErrorMsg)
	}

	// The peers confirm propagation: mpdist -> published, and the gate
	// opens once the DNSKEY TTL has passed since the confirmation.
	for _, id := range []uint16{ksk, zsk} {
		if err := SetPropagationConfirmed(hdb, mpzd.ZoneName, id); err != nil {
			t.Fatalf("SetPropagationConfirmed(%d): %v", id, err)
		}
		if err := TransitionMpdistToPublished(hdb, mpzd.ZoneName, id); err != nil {
			t.Fatalf("TransitionMpdistToPublished(%d): %v", id, err)
		}
		if got := mpKeyState(t, kdb, mpzd.ZoneName, id); got != tdns.DnskeyStatePublished {
			t.Fatalf("key %d is %s after confirmation, want published", id, got)
		}
	}
	if _, err := mpzd.ZoneData.SignZone(context.Background(), kdb, false); !errors.Is(err, tdns.ErrKeyGenerationDeferred) {
		t.Fatalf("SignZone before the TTL passed: err=%v, want ErrKeyGenerationDeferred", err)
	}
	longAgo := time.Now().Add(-2 * tdns.DefaultDnskeyTTL).UTC().Format(time.RFC3339)
	if _, err := kdb.DB.Exec(`UPDATE MPKeyPropagation SET confirmed_at=? WHERE zonename=?`, longAgo, mpzd.ZoneName); err != nil {
		t.Fatalf("age the confirmations: %v", err)
	}
	if _, err := mpzd.ZoneData.SignZone(context.Background(), kdb, false); err != nil {
		t.Fatalf("SignZone after the gate opened: %v", err)
	}
	if !mpzd.Ready {
		t.Fatal("the zone is not Ready after signing with the promoted keys")
	}
	for _, id := range []uint16{ksk, zsk} {
		if got := mpKeyState(t, kdb, mpzd.ZoneName, id); got != tdns.DnskeyStateActive {
			t.Fatalf("key %d is %s after promotion, want active", id, got)
		}
	}
	served := servedDnskeyTagsOf(t, mpzd.ZoneData)
	if len(served) != 2 || !served[ksk] || !served[zsk] {
		t.Fatalf("served DNSKEY RRset %v, want exactly the two promoted keys", served)
	}
	for _, tag := range rrsigTagsOf(t, mpzd.ZoneData, "www."+mpzd.ZoneName, dns.TypeA) {
		if tag != zsk {
			t.Fatalf("www A signed by %d, want the promoted ZSK %d", tag, zsk)
		}
	}
	if n := mpCountByCreator(t, kdb, mpzd.ZoneName, "ensure-active-keys"); n != 0 {
		t.Fatalf("%d keys minted although the staged ones were promotable", n)
	}

	// A retired key parks in mpremove, out of the served RRset, and the
	// peers' confirmation of the withdrawal removes it.
	newZsk := mpGenKey(t, kdb, mpzd.ZoneName, tdns.DnskeyStateStandby, "ZSK")
	if _, _, err := kdb.RolloverKey(mpzd.ZoneName, "ZSK", nil); err != nil {
		t.Fatalf("RolloverKey: %v", err)
	}
	if got := mpKeyState(t, kdb, mpzd.ZoneName, zsk); got != tdns.DnskeyStateRetired {
		t.Fatalf("rolled-out ZSK is %s, want retired", got)
	}
	if err := TransitionMpremoveToRemoved(hdb, mpzd.ZoneName, zsk); err != nil {
		t.Fatalf("TransitionMpremoveToRemoved on a retired key: %v", err)
	}
	if got := mpKeyState(t, kdb, mpzd.ZoneName, zsk); got != tdns.DnskeyStateRetired {
		t.Fatalf("a retired key was moved by the mpremove transition: %s", got)
	}
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET state=? WHERE zonename=? AND keyid=?`, DnskeyStateMpremove, mpzd.ZoneName, zsk); err != nil {
		t.Fatalf("park the key: %v", err)
	}
	if err := TransitionMpremoveToRemoved(hdb, mpzd.ZoneName, zsk); err != nil {
		t.Fatalf("TransitionMpremoveToRemoved: %v", err)
	}
	if got := mpKeyState(t, kdb, mpzd.ZoneName, zsk); got != tdns.DnskeyStateRemoved {
		t.Fatalf("key is %s after the withdrawal was confirmed, want removed", got)
	}
	_ = newZsk
}

// Mode 4. The other signers' DNSKEYs arrive in the incoming zone; they are
// kept as foreign rows, served in the DNSKEY RRset, never signing; a key
// that leaves the incoming zone leaves the store; mode 2 keeps none.
func TestSignerForeignKeysAreServedAndNeverSign(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	if err := NewHsyncDB(kdb).InitHsyncTables(); err != nil {
		t.Fatalf("InitHsyncTables: %v", err)
	}
	withSignerHooks(t, kdb)
	mpzd := signerTestZone(t, "mode4.example.", kdb)
	ksk := mpGenKey(t, kdb, mpzd.ZoneName, tdns.DnskeyStateActive, "KSK")
	zsk := mpGenKey(t, kdb, mpzd.ZoneName, tdns.DnskeyStateActive, "ZSK")
	mpzd.ZoneData.InstallInitialSnapshot()
	t.Cleanup(mpzd.ZoneData.StopPublisher)

	// The incoming zone, as another signer published it: our keys plus two of
	// theirs.
	foreign := []*dns.DNSKEY{}
	for i := 0; i < 2; i++ {
		pkc, err := tdns.GenerateKeyMaterial(mpzd.ZoneName, dns.TypeDNSKEY, dns.ED25519, "ZSK")
		if err != nil {
			t.Fatalf("GenerateKeyMaterial: %v", err)
		}
		foreign = append(foreign, &pkc.DnskeyRR)
	}
	incoming := &tdns.ZoneData{ZoneName: mpzd.ZoneName, ZoneStore: tdns.MapZone, Logger: log.New(io.Discard, "", 0), Data: core.NewNameMap[tdns.OwnerData]()}
	setIncomingDnskeys := func(keys ...*dns.DNSKEY) {
		apex := tdns.OwnerData{Name: mpzd.ZoneName, RRtypes: tdns.NewRRTypeStore()}
		rs := core.RRset{Name: mpzd.ZoneName, RRtype: dns.TypeDNSKEY}
		for _, k := range keys {
			rs.RRs = append(rs.RRs, k)
		}
		apex.RRtypes.Set(dns.TypeDNSKEY, rs)
		incoming.Data.Set(mpzd.ZoneName, apex)
	}
	setIncomingDnskeys(foreign[0], foreign[1])

	changed, err := mpzd.syncForeignDNSKEYs(incoming, true)
	if err != nil || !changed {
		t.Fatalf("syncForeignDNSKEYs: changed=%v err=%v", changed, err)
	}
	for _, k := range foreign {
		if got := mpKeyState(t, kdb, mpzd.ZoneName, k.KeyTag()); got != DnskeyStateForeign {
			t.Fatalf("foreign key %d is in state %q", k.KeyTag(), got)
		}
	}
	if len(mpzd.GetRemoteDNSKEYs()) != 2 {
		t.Fatalf("RemoteDNSKEYs = %d, want 2", len(mpzd.GetRemoteDNSKEYs()))
	}
	if changed, err := mpzd.syncForeignDNSKEYs(incoming, true); err != nil || changed {
		t.Fatalf("a second sync of the same set: changed=%v err=%v", changed, err)
	}

	if _, err := mpzd.ZoneData.SignZone(context.Background(), kdb, false); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	served := servedDnskeyTagsOf(t, mpzd.ZoneData)
	for _, k := range foreign {
		if !served[k.KeyTag()] {
			t.Errorf("foreign key %d is not in the served DNSKEY RRset %v", k.KeyTag(), served)
		}
	}
	if !served[ksk] || !served[zsk] || len(served) != 4 {
		t.Errorf("served DNSKEY RRset %v, want ours and the two foreign ones", served)
	}
	for _, rrtype := range []uint16{dns.TypeSOA, dns.TypeDNSKEY} {
		for _, tag := range rrsigTagsOf(t, mpzd.ZoneData, mpzd.ZoneName, rrtype) {
			if tag != ksk && tag != zsk {
				t.Errorf("%s signed by key %d, which is not ours", dns.TypeToString[rrtype], tag)
			}
		}
	}

	// One foreign key gone from the incoming zone: its row goes.
	setIncomingDnskeys(foreign[0])
	if changed, err := mpzd.syncForeignDNSKEYs(incoming, true); err != nil || !changed {
		t.Fatalf("sync after a foreign key left: changed=%v err=%v", changed, err)
	}
	if n := mpCountByCreator(t, kdb, mpzd.ZoneName, "foreign"); n != 1 {
		t.Fatalf("%d foreign rows after one key left, want 1", n)
	}
	// Mode 2: none.
	if changed, err := mpzd.syncForeignDNSKEYs(incoming, false); err != nil || !changed {
		t.Fatalf("sync in single-signer mode: changed=%v err=%v", changed, err)
	}
	if n := mpCountByCreator(t, kdb, mpzd.ZoneName, "foreign"); n != 0 {
		t.Fatalf("%d foreign rows in single-signer mode, want 0", n)
	}
}

// The one-shot migration: rows in every state, a confirmed key, a foreign
// key, a key at an old codepoint. After InitHsyncTables the rows are in
// DnssecKeyStore with the same states, the propagation flags in the side
// table, the codepoint and key id rewritten, the old table renamed; a
// second start changes nothing but drops the parked copy.
func TestMPKeystoreMigration(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	// The old table, as the last release created it.
	if _, err := kdb.DB.Exec(`CREATE TABLE 'MPDnssecKeyStore' (
		id INTEGER PRIMARY KEY, zonename TEXT, state TEXT, keyid INTEGER, flags INTEGER, algorithm TEXT, creator TEXT,
		privatekey TEXT, keyrr TEXT, comment TEXT, propagation_confirmed INTEGER DEFAULT 0, propagation_confirmed_at TEXT DEFAULT '',
		published_at TEXT DEFAULT '', retired_at TEXT DEFAULT '', UNIQUE (zonename, keyid))`); err != nil {
		t.Fatalf("create old table: %v", err)
	}
	const zone = "migrate.example."
	type row struct {
		state, role string
		confirmed   bool
		alg         uint8
	}
	rows := []row{
		{tdns.DnskeyStateActive, "KSK", true, dns.ED25519},
		{tdns.DnskeyStateActive, "ZSK", true, dns.ED25519},
		{DnskeyStateMpdist, "ZSK", false, dns.ED25519},
		{tdns.DnskeyStatePublished, "ZSK", true, dns.ED25519},
		{tdns.DnskeyStateStandby, "ZSK", false, dns.ED25519},
		{tdns.DnskeyStateRetired, "ZSK", false, dns.ED25519},
		{DnskeyStateMpremove, "ZSK", false, dns.ED25519},
		{DnskeyStateForeign, "ZSK", false, dns.ED25519},
	}
	oldIDs := map[string]uint16{}
	var renumberedOld uint16
	for i, r := range rows {
		pkc, err := tdns.GenerateKeyMaterial(zone, dns.TypeDNSKEY, r.alg, r.role)
		if err != nil {
			t.Fatalf("GenerateKeyMaterial: %v", err)
		}
		dnskey := pkc.DnskeyRR
		privatekey := pkc.PrivateKey
		if r.state == DnskeyStateForeign {
			privatekey = ""
		}
		if i == 2 {
			// A key minted under the signer's old MLDSA44 number, 18. The
			// key material is ED25519; what the migration rewrites is the
			// number in the record, and the tag with it.
			dnskey.Algorithm = 18
			renumberedOld = dnskey.KeyTag()
		}
		confirmed := 0
		if r.confirmed {
			confirmed = 1
		}
		if _, err := kdb.DB.Exec(`INSERT INTO MPDnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, propagation_confirmed, propagation_confirmed_at, published_at)
			VALUES (?, ?, ?, ?, ?, 'old', ?, ?, ?, ?, ?)`,
			zone, r.state, dnskey.KeyTag(), dnskey.Flags, "ED25519", privatekey, dnskey.String(), confirmed, "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"); err != nil {
			t.Fatalf("insert old row %d: %v", i, err)
		}
		oldIDs[r.state+"/"+fmt.Sprint(i)] = dnskey.KeyTag()
	}

	hdb := NewHsyncDB(kdb)
	if err := hdb.InitHsyncTables(); err != nil {
		t.Fatalf("InitHsyncTables (migration): %v", err)
	}
	if dbTableExists(kdb.DB, "MPDnssecKeyStore") {
		t.Fatal("the old table is still there after the migration")
	}
	if !dbTableExists(kdb.DB, migratedMPKeystoreTable) {
		t.Fatal("the old table was not parked under its migrated name")
	}
	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=?`, zone).Scan(&n); err != nil || n != len(rows) {
		t.Fatalf("%d rows in DnssecKeyStore after the migration (err=%v), want %d", n, err, len(rows))
	}
	states := map[string]int{}
	rs, err := kdb.DB.Query(`SELECT state, keyid, keyrr, privatekey FROM DnssecKeyStore WHERE zonename=?`, zone)
	if err != nil {
		t.Fatal(err)
	}
	var renumberedSeen bool
	for rs.Next() {
		var state, keyrr, priv string
		var keyid int
		if err := rs.Scan(&state, &keyid, &keyrr, &priv); err != nil {
			t.Fatal(err)
		}
		states[state]++
		rr, err := dns.NewRR(keyrr)
		if err != nil {
			t.Fatalf("migrated keyrr does not parse: %v", err)
		}
		dnskey := rr.(*dns.DNSKEY)
		if int(dnskey.KeyTag()) != keyid {
			t.Errorf("key id %d does not match the record's tag %d", keyid, dnskey.KeyTag())
		}
		if dnskey.Algorithm == 18 {
			t.Errorf("a key is still at the old codepoint 18")
		}
		if dnskey.Algorithm == 199 {
			renumberedSeen = true
			if uint16(keyid) == renumberedOld {
				t.Errorf("the renumbered key kept its old tag %d", keyid)
			}
		}
		if state == DnskeyStateForeign && priv != "" {
			t.Error("a foreign row has a private half")
		}
	}
	rs.Close()
	if !renumberedSeen {
		t.Error("the key at the old codepoint was not rewritten to the registry's 199")
	}
	for _, want := range []string{tdns.DnskeyStateActive, DnskeyStateMpdist, tdns.DnskeyStatePublished, tdns.DnskeyStateStandby, tdns.DnskeyStateRetired, DnskeyStateMpremove, DnskeyStateForeign} {
		if states[want] == 0 {
			t.Errorf("no row in state %s after the migration; states: %v", want, states)
		}
	}
	if states[tdns.DnskeyStateActive] != 2 {
		t.Errorf("%d active rows, want exactly the 2 that were active", states[tdns.DnskeyStateActive])
	}
	var confirmed int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM MPKeyPropagation WHERE zonename=? AND confirmed=1`, zone).Scan(&confirmed); err != nil || confirmed != 3 {
		t.Fatalf("%d confirmed propagation records (err=%v), want 3", confirmed, err)
	}

	// The second start: nothing to migrate, the parked copy dropped, the
	// rows untouched.
	if err := hdb.InitHsyncTables(); err != nil {
		t.Fatalf("InitHsyncTables (second start): %v", err)
	}
	if dbTableExists(kdb.DB, migratedMPKeystoreTable) {
		t.Fatal("the parked copy survived the second start")
	}
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=?`, zone).Scan(&n); err != nil || n != len(rows) {
		t.Fatalf("%d rows after the second start, want %d", n, len(rows))
	}

	// Fail closed: a row whose record does not parse refuses the start and
	// leaves both tables as they were.
	if _, err := kdb.DB.Exec(`CREATE TABLE 'MPDnssecKeyStore' (zonename TEXT, state TEXT, keyid INTEGER, flags INTEGER, algorithm TEXT, creator TEXT, privatekey TEXT, keyrr TEXT, comment TEXT, propagation_confirmed INTEGER, propagation_confirmed_at TEXT, published_at TEXT, retired_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := kdb.DB.Exec(`INSERT INTO MPDnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr) VALUES ('bad.example.', 'active', 1, 257, 'ED25519', 'old', '', 'not a record')`); err != nil {
		t.Fatal(err)
	}
	if err := hdb.InitHsyncTables(); err == nil {
		t.Fatal("a migration with an unparsable record did not refuse")
	}
	if !dbTableExists(kdb.DB, "MPDnssecKeyStore") {
		t.Fatal("the refused migration renamed the old table")
	}
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename='bad.example.'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the refused migration left %d rows behind", n)
	}
}

// A confirmation whose timestamp does not parse must not open the gate: the
// zero time would read as a TTL long elapsed. And a revoked KSK (flags 385)
// is a KSK for the "no key of that role exists" test.
func TestSignerGateAndRoleCountEdges(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	hdb := NewHsyncDB(kdb)
	if err := hdb.InitHsyncTables(); err != nil {
		t.Fatalf("InitHsyncTables: %v", err)
	}
	const zone = "edges.example."
	ksk := mpGenKey(t, kdb, zone, tdns.DnskeyStatePublished, "KSK")
	if _, err := kdb.DB.Exec(`INSERT INTO MPKeyPropagation (zonename, keyid, confirmed, confirmed_at) VALUES (?, ?, 1, 'not a time')`, zone, ksk); err != nil {
		t.Fatal(err)
	}
	if canPromoteMultiProviderMP(hdb, zone, ksk) {
		t.Fatal("a confirmation with an unparsable time opened the promotion gate")
	}
	if _, err := kdb.DB.Exec(`UPDATE DnssecKeyStore SET flags=385 WHERE zonename=? AND keyid=?`, zone, ksk); err != nil {
		t.Fatal(err)
	}
	if n, err := countOwnKeysOfRole(kdb, zone, "KSK"); err != nil || n != 1 {
		t.Fatalf("a revoked KSK (flags 385) counts %d as a KSK (err=%v), want 1", n, err)
	}
	if n, _ := countOwnKeysOfRole(kdb, zone, "ZSK"); n != 0 {
		t.Fatalf("a KSK counted as a ZSK: %d", n)
	}
}
