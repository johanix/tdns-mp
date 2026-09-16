package tdnsmp

import (
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// T5.1 (the inventory half): the key inventory carries pub, sign and ds
// per key across the wire form and back; an entry from a sender that
// predates the columns decodes with ds unknown and the columns the state
// implies (T5.2).
func TestInventoryCarriesTheColumns(t *testing.T) {
	yes, no := true, false
	items := []KeyInventoryItem{
		{KeyTag: 1, Algorithm: 15, Flags: 257, State: tdns.DnskeyStateStandby, KeyRR: "z. 3600 IN DNSKEY 257 3 15 dGVzdA==", Pub: true, DS: &yes},
		{KeyTag: 2, Algorithm: 15, Flags: 256, State: tdns.DnskeyStateActive, KeyRR: "z. 3600 IN DNSKEY 256 3 15 dGVzdA==", Pub: true, Sign: true, DS: &no},
		{KeyTag: 3, Algorithm: 15, Flags: 257, State: DnskeyStateForeign, KeyRR: "z. 3600 IN DNSKEY 257 3 15 dGVzdA==", Pub: true},
	}
	back := inventoryItemsOf(inventoryEntriesOf(items))
	if len(back) != 3 {
		t.Fatalf("%d items back, want 3", len(back))
	}
	if !back[0].Pub || back[0].Sign || back[0].DS == nil || !*back[0].DS {
		t.Errorf("the standby KSK's columns lost: %+v", back[0])
	}
	if !back[1].Pub || !back[1].Sign || back[1].DS == nil || *back[1].DS {
		t.Errorf("the active ZSK's columns lost: %+v", back[1])
	}
	if back[2].DS != nil || !back[2].Pub {
		t.Errorf("the foreign row with ds unknown: %+v", back[2])
	}
	old := []KeyInventoryEntry{{KeyTag: 4, Algorithm: 15, Flags: 257, State: tdns.DnskeyStateActive}, {KeyTag: 5, Flags: 256, State: DnskeyStateMpdist}, {KeyTag: 6, Flags: 256, State: tdns.DnskeyStateCreated}}
	got := inventoryItemsOf(old)
	if got[0].DS != nil || !got[0].Pub || !got[0].Sign {
		t.Errorf("an old sender's active key: %+v, want pub sign, ds unknown", got[0])
	}
	if got[1].DS != nil || !got[1].Pub || got[1].Sign {
		t.Errorf("an old sender's mpdist key: %+v, want pub only, ds unknown", got[1])
	}
	if got[2].Pub || got[2].Sign {
		t.Errorf("an old sender's created key: %+v, want neither", got[2])
	}
}

// T5.4 (the agent's half): the agent's DS-intent provider answers from
// the signer's latest inventory, own and foreign rows alike; a SEP row
// with ds unknown makes the set unknown; a zone whose inventory says it is
// not owned is not owned here either.
func TestAgentOwnerAnswersFromTheInventory(t *testing.T) {
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return nil })
	zd := &tdns.ZoneData{ZoneName: "inv.example.", Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}}
	if owner.Owns(zd) {
		t.Fatal("owned before any inventory")
	}
	k1 := testDnskey(t, "inv.example.", 257)
	k2 := testDnskey(t, "inv.example.", 257)
	k3 := testDnskey(t, "inv.example.", 256)
	yes, no := true, false
	snap := &KeyInventorySnapshot{Zone: "inv.example.", Owned: true, Received: time.Now(), Inventory: []KeyInventoryItem{
		{KeyTag: k1.KeyTag(), Algorithm: 15, Flags: 257, State: tdns.DnskeyStateActive, KeyRR: k1.String(), Pub: true, Sign: true, DS: &yes},
		{KeyTag: k2.KeyTag(), Algorithm: 15, Flags: 257, State: DnskeyStateForeign, KeyRR: k2.String(), Pub: true, DS: &no},
		{KeyTag: k3.KeyTag(), Algorithm: 15, Flags: 256, State: tdns.DnskeyStateActive, KeyRR: k3.String(), Pub: true, Sign: true, DS: &no},
	}}
	owner.SetInventory("inv.example.", snap)
	if !owner.Owns(zd) {
		t.Error("the inventory says owned; Owns is false")
	}
	in, err := owner.DSIntent(zd, dns.SHA256)
	if err != nil || !in.Known || len(in.Set) != 1 || in.Set[0].(*dns.DS).KeyTag != k1.KeyTag() {
		t.Errorf("DS intent from the inventory: known=%v set=%v err=%v, want the active KSK only", in.Known, in.Set, err)
	}
	snap.Inventory[1].DS = nil // the foreign KSK's provider has not said
	in, err = owner.DSIntent(zd, dns.SHA256)
	if err != nil || in.Known {
		t.Errorf("with a foreign SEP row's ds unknown: known=%v err=%v, want unknown", in.Known, err)
	}
	owner.SetInventory("inv.example.", &KeyInventorySnapshot{Zone: "inv.example.", Owned: false})
	if owner.Owns(zd) {
		t.Error("the inventory says not owned; Owns is true")
	}
	owner.SetInventory("inv.example.", nil)
	if owner.Owns(zd) {
		t.Error("with the inventory forgotten the zone is still owned")
	}
}

func core_RRset(rrs ...dns.RR) core.RRset { return core.RRset{RRs: rrs} }

func testDnskey(t *testing.T, zone string, flags uint16) *dns.DNSKEY {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: flags, Protocol: 3, Algorithm: dns.ED25519}
	if _, err := k.Generate(256); err != nil {
		t.Fatal(err)
	}
	return k
}

// The combiner synthesizes no CDS any more (arrow 1 is the signer's): a
// KSK change publishes nothing into the combiner's data.
func TestCombinerNoLongerSynthesizesCDS(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	mpzd := signerTestZone(t, "nocds.combiner.example.", kdb)
	mpzd.ZoneData.Options = map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	ksk := testDnskey(t, mpzd.ZoneName, 257)
	apex.RRtypes.Set(dns.TypeDNSKEY, core_RRset(ksk))
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.ZoneData.InstallInitialSnapshot()
	t.Cleanup(mpzd.ZoneData.StopPublisher)
	if !mpzd.Ready {
		t.Fatal("the zone is not served")
	}
	mpzd.combinerNotifyDelegationChange(nil, "agent.example.", mpzd.ZoneName, false, true)
	served, _ := mpzd.GetOwner(mpzd.ZoneName)
	if served != nil {
		if rs, ok := served.RRtypes.Get(dns.TypeCDS); ok && len(rs.RRs) > 0 {
			t.Errorf("the combiner published CDS %v on a KSK change", rs.RRs)
		}
	}
	if _, _, changed, err := mpzd.ReplaceCombinerDataByRRtype("local", mpzd.ZoneName, dns.TypeCDS, nil); err == nil && changed {
		t.Error("combiner data held CDS after the KSK change")
	}
}
