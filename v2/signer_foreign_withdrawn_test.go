/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// tdns-mp #207, the signer's half: a copy of the zone that lacked another
// signer's DNSKEYs was taken as their removal, and the DNSKEY RRset re-signed
// without them.

// What lets the signer drop another provider's key that an incoming zone
// lacks: the key states that provider's agent sent our agent, as our agent
// relays them, or the zone owner's signers= list. Never the copy alone.
func TestForeignKeyWithdrawnReadsTheRelayedKeyStates(t *testing.T) {
	yes := true
	relayed := map[uint16]foreignSaid{
		1: {Provider: "alpha", State: KeyStateActive, DS: &yes},
		2: {Provider: "alpha", State: foreignStateOmitted},
		3: {Provider: "gamma", State: KeyStateActive},
	}
	for _, c := range []struct {
		name    string
		keytag  uint16
		others  []string
		want    bool
		because string
	}{
		{"listed", 1, []string{"alpha"}, false, "a key the relayed key states still list"},
		{"no longer listed", 2, []string{"alpha"}, true, "a key the relayed key states no longer list"},
		{"provider out of signers=", 3, []string{"alpha"}, true, "a key whose provider the zone owner no longer names as a signer"},
		{"unnamed, one signer not relayed", 4, []string{"alpha", "beta"}, false, "a key no relayed key states name while one signer's are not relayed yet"},
		{"unnamed, every signer relayed", 4, []string{"alpha", "gamma"}, true, "a key no relayed key states name once every signer's are relayed"},
		{"no other signer", 1, nil, true, "a key in a zone whose owner names no other signer"},
	} {
		got, why := foreignKeyWithdrawn(relayed, c.keytag, c.others)
		if got != c.want {
			t.Errorf("%s: withdrawn=%v (%s), want %v for %s", c.name, got, why, c.want, c.because)
		}
	}
}

// The signer: a copy of the zone without the other signer's DNSKEYs, as a
// combiner that has just started sent, does not drop them. Key states from
// the other signer's agent that no longer list a key, relayed by our agent,
// do, whether they arrive after the copy or before it.
func TestSignerKeepsAForeignDNSKEYThatOneCopyLacks(t *testing.T) {
	yes := true
	mpzd := providersTestZone(t, "keep.foreign.example.", []string{"us", "alpha"}, []string{"us", "alpha"})
	t.Cleanup(mpzd.StopPublisher)
	kdb, zone := mpzd.KeyDB, mpzd.ZoneName
	if err := NewHsyncDB(kdb).InitHsyncTables(); err != nil {
		t.Fatalf("InitHsyncTables: %v", err)
	}
	mp := &MultiProviderConf{Role: "signer", Identity: "signer.us.example.", Agents: []*PeerConf{{Identity: "agent.us.example."}}}
	others, signer := otherSignerLabels(mpzd, mp)
	if !signer || len(others) != 1 || others[0] != "alpha" {
		t.Fatalf("the other signers: %v (we sign: %v), want alpha", others, signer)
	}
	l := NewZoneKeyLifecycle(zone, kdb, &fakeClock{t: time.Now()}, driverPolicy, newFakeWire(others...))

	ksk, zsk := testDnskey(t, zone, 257), testDnskey(t, zone, 256)
	copyWith := func(keys ...*dns.DNSKEY) *tdns.ZoneData {
		zd := &tdns.ZoneData{ZoneName: zone, ZoneStore: tdns.MapZone, Data: core.NewNameMap[tdns.OwnerData]()}
		apex := tdns.OwnerData{Name: zone, RRtypes: tdns.NewRRTypeStore()}
		rs := core.RRset{Name: zone, RRtype: dns.TypeDNSKEY}
		for _, k := range keys {
			rs.RRs = append(rs.RRs, k)
		}
		apex.RRtypes.Set(dns.TypeDNSKEY, rs)
		zd.Data.Set(zone, apex)
		return zd
	}
	sync := func(step string, in *tdns.ZoneData, wantChanged bool, wantRows int) {
		t.Helper()
		changed, err := mpzd.syncForeignDNSKEYs(in, true, others)
		if err != nil || changed != wantChanged {
			t.Fatalf("%s: changed=%v err=%v, want changed=%v", step, changed, err, wantChanged)
		}
		if n := mpCountByCreator(t, kdb, zone, "foreign"); n != wantRows {
			t.Fatalf("%s: %d foreign rows, want %d", step, n, wantRows)
		}
	}
	// relay is our agent's KEYSTATE "foreign": the key states alpha's agent
	// sent our agent, as the signer's key lifecycle records them
	relay := func(keys ...core.ForeignKeyState) {
		t.Helper()
		if err := l.SetForeignWord(keys, []string{"alpha"}); err != nil {
			t.Fatalf("SetForeignWord: %v", err)
		}
	}

	sync("alpha's keys arrive", copyWith(ksk, zsk), true, 2)
	relay(said("alpha", ksk.KeyTag(), KeyStateActive, &yes), said("alpha", zsk.KeyTag(), KeyStateActive, nil))

	sync("a copy without alpha's keys", copyWith(), false, 2)
	if absent := mpzd.absentForeignKeys(); len(absent) != 2 {
		t.Fatalf("kept while absent: %v, want both of alpha's keys", absent)
	}
	sync("the copy with them again", copyWith(ksk, zsk), false, 2)
	if absent := mpzd.absentForeignKeys(); len(absent) != 0 {
		t.Fatalf("kept while absent: %v, want none once the copy has them", absent)
	}

	// alpha retires its ZSK: the copy without it comes first, the relayed
	// key states without it second
	sync("a copy without alpha's ZSK, before the relayed key states", copyWith(ksk), false, 2)
	relay(said("alpha", ksk.KeyTag(), KeyStateActive, &yes))
	if !mpzd.dropWithdrawnForeignDNSKEYs(mp) {
		t.Fatal("relayed key states without alpha's ZSK dropped nothing")
	}
	if n := mpCountByCreator(t, kdb, zone, "foreign"); n != 1 {
		t.Fatalf("%d foreign rows after alpha's ZSK left its key states, want its KSK alone", n)
	}
	if got := mpKeyState(t, kdb, zone, ksk.KeyTag()); got != DnskeyStateForeign {
		t.Fatalf("alpha's KSK is in state %q, want foreign", got)
	}

	// alpha withdraws its KSK: the relayed key states first, the copy second
	relay()
	sync("a copy without alpha's KSK, after the relayed key states", copyWith(), true, 0)
}
