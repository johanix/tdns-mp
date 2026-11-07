package tdnsmp

import (
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// putMPZone puts a multi-provider zone into tdns.Zones under name, a new
// *tdns.ZoneData, as a reload that brings the zone in (or back) does.
func putMPZone(t *testing.T, name string) *tdns.ZoneData {
	t.Helper()
	return putZone(t, name, true)
}

// putZone is putMPZone for a zone with or without multi-provider.
func putZone(t *testing.T, name string, mp bool) *tdns.ZoneData {
	t.Helper()
	zd := &tdns.ZoneData{ZoneName: name, ZoneType: tdns.Secondary,
		Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: mp}}
	tdns.Zones.Set(name, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(name)
		Zones.Invalidate(name)
	})
	return zd
}

// A zone a reload drops and a later one brings back is a new
// *tdns.ZoneData: it gets tdns-mp's refresh callbacks and SyncQ again.
// A reload that keeps a zone gives it no second set, and one that drops
// it forgets it (#313).
func TestAZoneAReloadPutsBackGetsItsRefreshCallbacksAgain(t *testing.T) {
	const name = "back.setup.example."
	conf := &Config{Config: &tdns.Config{}}
	conf.InternalMp.SyncQ = make(chan SyncRequest, 1)
	conf.InternalMp.MPZoneNames = []string{name}

	first := putMPZone(t, name)
	conf.RegisterMPRefreshCallbacks()
	pre, post := len(first.OnZonePreRefresh), len(first.OnZonePostRefresh)
	if pre == 0 || post == 0 {
		t.Fatalf("the zone got %d PreRefresh and %d PostRefresh callbacks, want some of each", pre, post)
	}
	conf.RegisterMPRefreshCallbacks() // a reload that keeps the zone
	if len(first.OnZonePreRefresh) != pre || len(first.OnZonePostRefresh) != post {
		t.Errorf("a reload that keeps the zone gave it %d and %d callbacks, want %d and %d",
			len(first.OnZonePreRefresh), len(first.OnZonePostRefresh), pre, post)
	}

	tdns.Zones.Remove(name) // a reload drops the zone
	conf.RegisterMPRefreshCallbacks()
	if _, ok := conf.InternalMp.refreshRegistered[name]; ok {
		t.Error("a zone the reload dropped is still remembered as set up")
	}

	back := putMPZone(t, name) // a later reload brings it back
	conf.RegisterMPRefreshCallbacks()
	if len(back.OnZonePreRefresh) != pre || len(back.OnZonePostRefresh) != post {
		t.Errorf("the zone put back got %d PreRefresh and %d PostRefresh callbacks, want %d and %d",
			len(back.OnZonePreRefresh), len(back.OnZonePostRefresh), pre, post)
	}
	if w, ok := Zones.Get(name); !ok || w.SyncQ != conf.InternalMp.SyncQ {
		t.Error("the zone put back has no SyncQ")
	}
}

// On the combiner, a zone a reload puts back gets its contributions'
// persistence and its OnFirstLoad callbacks again, as at a start (#313).
func TestAZoneAReloadPutsBackGetsTheCombinersSetupAgain(t *testing.T) {
	asMPDaemon(t, AppTypeMPCombiner)
	kdb := newMPTestKeyDB(t)
	if err := NewHsyncDB(kdb).InitHsyncTables(); err != nil {
		t.Fatalf("InitHsyncTables: %v", err)
	}
	const name = "back.combiner-setup.example."
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.InternalMp.MPZoneNames = []string{name}

	first := putMPZone(t, name)
	conf.RegisterCombinerOnFirstLoad()
	n := len(first.OnFirstLoad)
	if n == 0 {
		t.Fatal("the zone got no OnFirstLoad callbacks")
	}
	conf.RegisterCombinerOnFirstLoad() // a reload that keeps the zone
	if len(first.OnFirstLoad) != n {
		t.Errorf("a reload that keeps the zone gave it %d OnFirstLoad callbacks, want %d", len(first.OnFirstLoad), n)
	}

	tdns.Zones.Remove(name) // a reload drops the zone
	conf.RegisterCombinerOnFirstLoad()
	if _, ok := conf.InternalMp.onFirstLoadRegistered[name]; ok {
		t.Error("a zone the reload dropped is still remembered as set up")
	}
	back := putMPZone(t, name) // a later reload brings it back
	conf.RegisterCombinerOnFirstLoad()
	if len(back.OnFirstLoad) != n {
		t.Errorf("the zone put back got %d OnFirstLoad callbacks, want %d", len(back.OnFirstLoad), n)
	}
	if w, ok := Zones.Get(name); !ok || w.MP == nil || w.MP.PersistContributions == nil {
		t.Error("the zone put back does not persist its contributions")
	}
}

// MPZoneNames keeps every name a reload has listed. A zone a reload drops
// and a later one brings back without multi-provider gets none of the
// combiner's setup.
func TestAZoneBackWithoutMultiProviderGetsNoCombinerSetup(t *testing.T) {
	asMPDaemon(t, AppTypeMPCombiner)
	kdb := newMPTestKeyDB(t)
	if err := NewHsyncDB(kdb).InitHsyncTables(); err != nil {
		t.Fatalf("InitHsyncTables: %v", err)
	}
	const name = "back.not-mp.example."
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.InternalMp.MPZoneNames = []string{name}

	putMPZone(t, name)
	conf.RegisterCombinerOnFirstLoad()
	tdns.Zones.Remove(name) // a reload drops the zone
	conf.RegisterCombinerOnFirstLoad()

	back := putZone(t, name, false) // a later reload brings it back, not multi-provider
	conf.RegisterCombinerOnFirstLoad()
	if len(back.OnFirstLoad) != 0 {
		t.Errorf("a zone back without multi-provider got %d OnFirstLoad callbacks, want none", len(back.OnFirstLoad))
	}
	if w, ok := Zones.Get(name); ok && w.MP != nil && w.MP.PersistContributions != nil {
		t.Error("a zone back without multi-provider persists contributions")
	}
}

// unreadStoreZone is a combiner zone whose stored contributions could not
// be read when it was set up: the store holds sender's NS ns8, the zone
// holds none of it. storedNS is sender's stored NS targets.
func unreadStoreZone(t *testing.T, zone, sender string) (*MPZoneData, *HsyncDB, func() string) {
	t.Helper()
	asMPDaemon(t, AppTypeMPCombiner)
	kdb := newMPTestKeyDB(t)
	hdb := NewHsyncDB(kdb)
	if err := hdb.InitHsyncTables(); err != nil {
		t.Fatalf("InitHsyncTables: %v", err)
	}
	mpzd := combinerTestZone(t, zone)
	stored := nsContribution(zone, "ns8."+zone)[zone][0]
	if err := SaveContributions(hdb, zone, sender, map[string]map[uint16]core.RRset{zone: {dns.TypeNS: stored}}); err != nil {
		t.Fatalf("SaveContributions: %v", err)
	}
	storedNS := func() string {
		t.Helper()
		all, err := LoadAllContributions(hdb)
		if err != nil {
			t.Fatalf("LoadAllContributions: %v", err)
		}
		rrset := all[zone][sender][zone][dns.TypeNS]
		var targets []string
		for _, rr := range rrset.RRs {
			targets = append(targets, rr.(*dns.NS).Ns)
		}
		slices.Sort(targets)
		return strings.Join(targets, " ")
	}
	mpzd.restoreContributions(hdb, nil, false) // the snapshot could not be read
	return mpzd, hdb, storedNS
}

// nsUpdate is sender's update of the zone's NS, as it reaches the combiner.
func nsUpdate(sender, zone, op, target string) *CombinerSyncRequest {
	return &CombinerSyncRequest{SenderID: sender, DeliveredBy: sender, Zone: zone,
		Operations:     []core.RROperation{{Operation: op, RRtype: "NS", Records: []string{zone + " 3600 IN NS " + target}}},
		DistributionID: nextDistributionID(), Timestamp: time.Now()}
}

// heldNS is sender's NS targets in the zone's memory.
func heldNS(mpzd *MPZoneData, sender, zone string) string {
	mpzd.Lock()
	defer mpzd.Unlock()
	var targets []string
	if mpzd.MP != nil {
		for _, rr := range mpzd.MP.AgentContributions[sender][zone][dns.TypeNS].RRs {
			targets = append(targets, rr.(*dns.NS).Ns)
		}
	}
	slices.Sort(targets)
	return strings.Join(targets, " ")
}

// While a zone's store has not been read, an update changes nothing and is
// answered PENDING, not refused: the sender's reliable queue keeps it and
// sends it again. Sent again once the store can be read, it is saved beside
// the stored rows. A refusal would close it in the queue, and the
// contribution would stay missing until another send.
func TestAnUpdateBeforeTheStoreIsReadIsLeftWithItsSender(t *testing.T) {
	const zone = "kept-update.example."
	const sender = "agent-a"
	mpzd, hdb, storedNS := unreadStoreZone(t, zone, sender)
	req := nsUpdate(sender, zone, "add", "ns2."+zone)

	mpzd.Ready = false // not loaded yet: the store is not read again
	if resp := CombinerProcessUpdate(req, nil, nil, hdb, nil); resp.Status != "pending" {
		t.Fatalf("an update before the store was read: %q (%s), want pending", resp.Status, resp.Message)
	}
	if got := heldNS(mpzd, sender, zone); got != "" {
		t.Errorf("an update before the store was read changed the zone: it holds %q", got)
	}
	if got, want := storedNS(), "ns8."+zone; got != want {
		t.Errorf("an update before the store was read changed the store: %q, want %q", got, want)
	}

	mpzd.Ready = true // loaded: the update sent again reads the store first
	if resp := CombinerProcessUpdate(req, nil, nil, hdb, nil); resp.Status == "pending" || resp.Status == "error" {
		t.Fatalf("the update sent again once the store can be read: %q (%s)", resp.Status, resp.Message)
	}
	if got, want := storedNS(), "ns2."+zone+" ns8."+zone; got != want {
		t.Errorf("the update sent again was not saved beside the stored rows: %q, want %q", got, want)
	}
}

// Before the zone's store is read, a REPLACE changes nothing, in memory or
// in the store, and neither it nor the same REPLACE sent again is
// confirmed: each is answered PENDING. Changed in memory and refused only
// by the save, the copy sent again found nothing to change and was
// confirmed without being saved.
func TestAReplaceBeforeTheStoreIsReadChangesNothing(t *testing.T) {
	const zone = "unread-replace.example."
	const sender = "agent-a"
	mpzd, hdb, storedNS := unreadStoreZone(t, zone, sender)

	mpzd.Ready = false // not loaded yet: the store is not read again
	for i := 1; i <= 2; i++ {
		if resp := CombinerProcessUpdate(nsUpdate(sender, zone, "replace", "ns2."+zone), nil, nil, hdb, nil); resp.Status != "pending" {
			t.Errorf("REPLACE %d before the store was read: %q (%s), want pending", i, resp.Status, resp.Message)
		}
		if got := heldNS(mpzd, sender, zone); got != "" {
			t.Errorf("REPLACE %d before the store was read changed the zone: it holds %q", i, got)
		}
	}
	if got, want := storedNS(), "ns8."+zone; got != want {
		t.Errorf("a REPLACE before the store was read changed the store: %q, want %q", got, want)
	}

	mpzd.Ready = true
	if resp := CombinerProcessUpdate(nsUpdate(sender, zone, "replace", "ns2."+zone), nil, nil, hdb, nil); resp.Status == "pending" || resp.Status == "error" {
		t.Fatalf("a REPLACE once the store can be read: %q (%s)", resp.Status, resp.Message)
	}
	if got, want := storedNS(), "ns2."+zone; got != want {
		t.Errorf("a REPLACE once the store can be read: stored %q, want %q", got, want)
	}
}

// On the signer, a zone a reload puts back is put on the resigner's
// watchlist again. The watchlist holds one zone per name: without that,
// the resigner renews the dropped zone's signatures and lets the new
// one's expire. A zone whose first load is done before its setup runs is
// put on it at once.
func TestAZoneAReloadPutsBackIsKeptSignedAgain(t *testing.T) {
	asMPDaemon(t, AppTypeMPSigner)
	const name = "back.resign.example."
	q := make(chan tdns.ResignRequest, 4)
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.ResignQ = q
	conf.InternalMp.MPZoneNames = []string{name}
	registered := func() *tdns.ZoneData {
		select {
		case req := <-q:
			if req.Reason != tdns.ResignPeriodic {
				t.Errorf("registered for %v, want a periodic re-sign", req.Reason)
			}
			return req.Zd
		default:
			return nil
		}
	}
	// a zone's first load, after MPPreRefresh has switched inline-signing on
	firstLoad := func(zd *tdns.ZoneData) {
		zd.Options[tdns.OptInlineSigning] = true
		for _, cb := range zd.OnFirstLoad {
			cb(zd)
		}
	}

	first := putMPZone(t, name)
	first.FirstZoneLoad = true
	conf.RegisterMPRefreshCallbacks()
	firstLoad(first)
	if registered() != first {
		t.Fatal("the zone is not on the resigner's watchlist after its first load")
	}

	tdns.Zones.Remove(name) // a reload drops the zone
	conf.RegisterMPRefreshCallbacks()
	back := putMPZone(t, name) // a later reload brings it back
	back.FirstZoneLoad = true
	conf.RegisterMPRefreshCallbacks()
	firstLoad(back)
	if registered() != back {
		t.Error("the zone put back is not on the resigner's watchlist after its first load")
	}

	tdns.Zones.Remove(name)
	conf.RegisterMPRefreshCallbacks()
	loaded := putMPZone(t, name) // back, and loaded before its setup runs
	loaded.Options[tdns.OptInlineSigning] = true
	conf.RegisterMPRefreshCallbacks()
	if registered() != loaded {
		t.Error("a zone put back and loaded before its setup ran is not on the resigner's watchlist")
	}
}

// While a zone's store has not been read (the snapshot could not be read
// when the zone was set up), a change of its contributions is not saved:
// saving the sender's map would replace its stored rows with part of
// them. The re-apply reads the store, and changes are saved from then on.
func TestAnUpdateBeforeTheStoreIsReadLeavesItAlone(t *testing.T) {
	const zone = "unread-store.example."
	const sender = "agent-a"
	mpzd, hdb, storedNS := unreadStoreZone(t, zone, sender)

	if _, err := mpzd.AddCombinerData(sender, nsContribution(zone, "ns2."+zone)); err == nil {
		t.Error("an update before the store was read was accepted")
	}
	if got, want := storedNS(), "ns8."+zone; got != want {
		t.Errorf("the update replaced the stored rows: %q, want %q", got, want)
	}

	if _, err := CombinerReapplyContributions(zone, hdb); err != nil {
		t.Fatalf("CombinerReapplyContributions: %v", err)
	}
	if _, err := mpzd.AddCombinerData(sender, nsContribution(zone, "ns2."+zone)); err != nil {
		t.Fatalf("an update after the re-apply: %v", err)
	}
	if got := storedNS(); !strings.Contains(got, "ns2."+zone) || !strings.Contains(got, "ns8."+zone) {
		t.Errorf("after the re-apply the update was not saved beside the stored rows: %q", got)
	}
}
