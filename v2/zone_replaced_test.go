package tdnsmp

import (
	"sync"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// tdns-mp #396: a config reload removes a zone and a later one adds it back.
// tdns builds a new ZoneData for it, and everything tdns-mp keeps of the zone
// follows the new one: the wrapper, the per-zone hooks, the key machine's
// take and driver.

// noZoneHooks runs the test with no role's zone hooks installed, and puts
// back what was there after it.
func noZoneHooks(t *testing.T) {
	prev := Zones.SetOnNew(nil)
	t.Cleanup(func() { Zones.SetOnNew(prev) })
}

// removeAndReAdd stands in for the two reloads: the zone leaves tdns's zones,
// and comes back as a new ZoneData under the same name.
func removeAndReAdd(t *testing.T, old *MPZoneData, kdb *tdns.KeyDB) *tdns.ZoneData {
	t.Helper()
	name := old.ZoneName
	tdns.Zones.Remove(name)
	if _, ok := Zones.Get(name); ok {
		t.Fatal("Get finds a zone that tdns no longer holds")
	}
	zd := signerTestZone(t, name, kdb).ZoneData
	if zd == old.ZoneData {
		t.Fatal("the re-added zone has the old ZoneData")
	}
	return zd
}

// Get, GetFor, Items and IterCb hand out the wrapper of the ZoneData tdns
// holds, with fresh MP state, and never the removed one's.
func TestMPZonesFollowTheLiveZoneData(t *testing.T) {
	noZoneHooks(t)
	kdb := newMPTestKeyDB(t)
	old := signerTestZone(t, "readded.mpzones.example.", kdb)
	old.EnsureMP()
	old.MP.MPdata = &MPdata{}
	old.MPOptions[tdns.OptAllowEdits] = true
	if again, _ := Zones.Get(old.ZoneName); again != old {
		t.Fatal("a second Get of an unchanged zone built a new wrapper")
	}

	live := removeAndReAdd(t, old, kdb)

	mpzd, ok := Zones.Get(old.ZoneName)
	if !ok || mpzd.ZoneData != live {
		t.Fatalf("Get after the re-add: ok=%v, wraps the live ZoneData=%v", ok, ok && mpzd.ZoneData == live)
	}
	if mpzd.MP.MPdata != nil || mpzd.MPOptions[tdns.OptAllowEdits] {
		t.Error("the new wrapper carries the removed zone's MP state")
	}
	if _, ok := Zones.GetFor(old.ZoneData); ok {
		t.Error("GetFor hands out a wrapper for the removed ZoneData")
	}
	if w, ok := Zones.GetFor(live); !ok || w != mpzd {
		t.Error("GetFor of the live ZoneData is not the cached wrapper")
	}
	if w := Zones.Items()[old.ZoneName]; w == nil || w.ZoneData != live {
		t.Error("Items hands out the removed ZoneData")
	}
	Zones.IterCb(func(key string, w *MPZoneData) {
		if key == old.ZoneName && w.ZoneData != live {
			t.Error("IterCb hands out the removed ZoneData")
		}
	})
}

// A zone looked up by its name in another case has the same wrapper: one
// ZoneData, one MP state, as tdns files it under one name.
func TestMPZonesOneWrapperPerZoneData(t *testing.T) {
	noZoneHooks(t)
	kdb := newMPTestKeyDB(t)
	mpzd := signerTestZone(t, "case.mpzones.example.", kdb)
	other, ok := Zones.Get("Case.MPZones.Example.")
	if !ok || other != mpzd {
		t.Errorf("the zone by another spelling: ok=%v, same wrapper=%v", ok, other == mpzd)
	}
}

// The per-zone hooks run once on the re-created zone, whoever looks it up
// first and however often, and once more on nothing: the reload hook that
// runs after it, and lookups from many goroutines at once, add none. A
// callback left on the removed zone does not reach the new wrapper.
func TestZoneHooksRunOnceOnARecreatedZone(t *testing.T) {
	oldType := tdns.Globals.App.Type
	tdns.Globals.App.Type = AppTypeMPSigner
	t.Cleanup(func() { tdns.Globals.App.Type = oldType })
	noZoneHooks(t)
	kdb := newMPTestKeyDB(t)
	old := signerTestZone(t, "readded.hooks.example.", kdb)
	old.FirstZoneLoad = true
	conf := &Config{Config: &tdns.Config{}}
	conf.InternalMp.mpZones.setForTest(old.ZoneName)
	conf.ForEachMPZone(conf.firstLoadSetup) // MainInit
	conf.RegisterMPRefreshCallbacks()       // the role's start
	conf.installZoneHooks(conf.registerRefreshCallbacks, conf.firstLoadSetup)
	hooks := func(zd *tdns.ZoneData) [3]int {
		return [3]int{len(zd.OnZonePreRefresh), len(zd.OnZonePostRefresh), len(zd.OnFirstLoad)}
	}
	if got := hooks(old.ZoneData); got != [3]int{1, 1, 1} {
		t.Fatalf("hooks on the zone at the start: %v, want one of each", got)
	}
	conf.RegisterMPRefreshCallbacks()
	if got := hooks(old.ZoneData); got != [3]int{1, 1, 1} {
		t.Fatalf("a reload added hooks to an unchanged zone: %v", got)
	}

	tdns.Zones.Remove(old.ZoneName)
	conf.RegisterMPRefreshCallbacks() // the reload that removes it
	live := signerTestZone(t, old.ZoneName, kdb).ZoneData

	// the lookup that saw the new ZoneData (signerTestZone's) ran the hooks
	// on it
	if got := hooks(live); got[0] != 1 || got[1] != 1 {
		t.Fatalf("refresh hooks on the re-created zone after its first lookup: %v, want one each", got)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if mpzd, ok := Zones.Get(old.ZoneName); !ok || mpzd.ZoneData != live {
				t.Error("a concurrent Get missed the live ZoneData")
			}
		}()
	}
	wg.Wait()
	conf.RegisterMPRefreshCallbacks() // the reload that adds it back
	if got := hooks(live); got[0] != 1 || got[1] != 1 {
		t.Errorf("refresh hooks on the re-created zone: %v, want exactly one each", got)
	}
	if got := hooks(old.ZoneData); got != [3]int{1, 1, 1} {
		t.Errorf("hooks on the removed zone changed: %v", got)
	}
	mpzd, _ := Zones.Get(old.ZoneName)
	if mpzd.MP == nil || mpzd.MP.MPdata == nil {
		t.Error("the re-created zone's MPdata was not set up")
	}

	// a refresh still running on the removed zone calls its callbacks with
	// the old ZoneData: they find no wrapper, and leave the new one alone
	before := mpzd.MP.MPdata
	for _, cb := range old.OnZonePostRefresh {
		cb(old.ZoneData)
	}
	if mpzd.MP.MPdata != before {
		t.Error("the removed zone's callback acted on the new wrapper")
	}
}

// The first-load set-up runs once per ZoneData: the re-created zone gets its
// resigner registration, as the zone did at the start, and only one.
func TestFirstLoadSetupOncePerZoneData(t *testing.T) {
	oldType := tdns.Globals.App.Type
	tdns.Globals.App.Type = AppTypeMPSigner
	t.Cleanup(func() { tdns.Globals.App.Type = oldType })
	noZoneHooks(t)
	kdb := newMPTestKeyDB(t)
	old := signerTestZone(t, "readded.firstload.example.", kdb)
	old.FirstZoneLoad = true
	conf := &Config{Config: &tdns.Config{}}
	conf.firstLoadSetup(old)
	conf.firstLoadSetup(old)
	if n := len(old.OnFirstLoad); n != 1 {
		t.Fatalf("first-load callbacks on the zone: %d, want 1", n)
	}
	tdns.Zones.Remove(old.ZoneName)
	live := signerTestZone(t, old.ZoneName, kdb)
	live.FirstZoneLoad = true
	conf.firstLoadSetup(live)
	conf.firstLoadSetup(live)
	if n := len(live.OnFirstLoad); n != 1 {
		t.Errorf("first-load callbacks on the re-created zone: %d, want 1", n)
	}
}

// After the reload that removes the zone, nothing of tdns-mp's points at its
// ZoneData any more: not the wrapper cache, not the hook marks, not the key
// machine's take or driver.
func TestNothingKeepsTheRemovedZoneData(t *testing.T) {
	noZoneHooks(t)
	kdb := newMPTestKeyDB(t)
	old := signerTestZone(t, "removed.keep.example.", kdb)
	zoneSignedBy(t, old, "agent.us.example.", "p2")
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "signer", Agents: []*PeerConf{{Identity: "agent.us.example."}}, KeyLifecycleZones: []string{old.ZoneName}})
	conf.Config.Internal.KeyDB = kdb
	conf.InternalMp.mpZones.setForTest(old.ZoneName)
	conf.firstLoadSetup(old)
	conf.RegisterMPRefreshCallbacks()
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
	e := NewKeyLifecycleEngine(conf, owner)
	e.TakeConfiguredZones()
	if e.driver(old.ZoneName) == nil {
		t.Fatal("no driver for the taken zone")
	}

	tdns.Zones.Remove(old.ZoneName)
	conf.RegisterMPRefreshCallbacks() // the reload's hook
	e.TakeConfiguredZones()           // the engine's next tick

	Zones.mu.RLock()
	for name, w := range Zones.cache {
		if w.ZoneData == old.ZoneData {
			t.Errorf("the wrapper cache keeps the removed ZoneData under %s", name)
		}
	}
	Zones.mu.RUnlock()
	for what, o := range map[string]*zoneOnce{
		"refresh callbacks": &conf.InternalMp.refreshRegistered,
		"first-load set-up": &conf.InternalMp.firstLoadSetUp,
	} {
		o.mu.Lock()
		for _, zd := range o.done {
			if zd == old.ZoneData {
				t.Errorf("the %s marks keep the removed ZoneData", what)
			}
		}
		o.mu.Unlock()
	}
	owner.mu.RLock()
	if _, ok := owner.owned[lifecycleZoneName(old.ZoneName)]; ok {
		t.Error("the owner keeps the take of the removed zone")
	}
	owner.mu.RUnlock()
	e.mu.Lock()
	if e.zones[lifecycleZoneName(old.ZoneName)] != nil || e.madeOn[lifecycleZoneName(old.ZoneName)] != nil {
		t.Error("the engine keeps the removed zone's driver")
	}
	e.mu.Unlock()
}

// The key machine follows the ZoneData: a zone taken on one that tdns
// replaces is not taken any more, its cached driver goes with the take, and
// the next take is made on the new one, with a new driver made from it.
func TestKeyLifecycleTakeAndDriverFollowTheZoneData(t *testing.T) {
	noZoneHooks(t)
	setup := func(t *testing.T, name string) (*KeyLifecycleEngine, *MPKeyLifecycleOwner, *MPZoneData, *tdns.KeyDB) {
		kdb := newMPTestKeyDB(t)
		old := signerTestZone(t, name, kdb)
		zoneSignedBy(t, old, "agent.us.example.", "p2")
		conf := &Config{Config: &tdns.Config{}}
		conf.SetMpConfig(&MultiProviderConf{Role: "signer", Agents: []*PeerConf{{Identity: "agent.us.example."}}, KeyLifecycleZones: []string{name}})
		conf.Config.Internal.KeyDB = kdb
		owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
		e := NewKeyLifecycleEngine(conf, owner)
		e.TakeConfiguredZones()
		if !owner.taken(name) || e.driver(name) == nil {
			t.Fatal("the configured zone was not taken and run")
		}
		return e, owner, old, kdb
	}
	readd := func(t *testing.T, old *MPZoneData, kdb *tdns.KeyDB) *MPZoneData {
		live := removeAndReAdd(t, old, kdb)
		mpzd, _ := Zones.GetFor(live)
		zoneSignedBy(t, mpzd, "agent.us.example.", "p2")
		return mpzd
	}

	t.Run("released, then taken on the new one", func(t *testing.T) {
		e, owner, old, kdb := setup(t, "readded.take.example.")
		first := e.driver(old.ZoneName)
		live := readd(t, old, kdb)
		if owner.taken(old.ZoneName) {
			t.Error("the zone counts as taken on its new ZoneData before any take")
		}
		if owner.Owns(live.ZoneData) {
			t.Error("the old take makes the owner claim the new ZoneData")
		}
		if !owner.Owns(old.ZoneData) {
			t.Error("the removed ZoneData lost its owner: a refresh still running on it would go to tdns's machine")
		}
		if e.driver(old.ZoneName) != nil {
			t.Error("the removed zone's driver is still handed out")
		}
		e.TakeConfiguredZones()
		if !owner.taken(old.ZoneName) || !owner.Owns(live.ZoneData) {
			t.Fatal("the zone was not taken again on its new ZoneData")
		}
		second := e.driver(old.ZoneName)
		if second == nil || second == first {
			t.Errorf("the driver after the re-take: %p, the first %p; want a new one", second, first)
		}
		e.mu.Lock()
		madeOn := e.madeOn[lifecycleZoneName(old.ZoneName)]
		e.mu.Unlock()
		if madeOn != live.ZoneData {
			t.Error("the new driver is not filed under the new ZoneData")
		}
	})

	// taken again before the engine looked at the zone: the cached driver of
	// the old ZoneData is not handed out for the new one
	t.Run("a cached driver is made again", func(t *testing.T) {
		e, owner, old, kdb := setup(t, "readded.driver.example.")
		first := e.driver(old.ZoneName)
		live := readd(t, old, kdb)
		owner.Take(old.ZoneName)
		second := e.driver(old.ZoneName)
		if second == nil || second == first {
			t.Errorf("the driver after a take on the new ZoneData: %p, the first %p; want a new one", second, first)
		}
		if !owner.Owns(live.ZoneData) {
			t.Error("the take on the new ZoneData does not own it")
		}
	})

	// a take finds the zone gone (removed between the engine's look and the
	// take): it takes nothing, and the zone added back later is not taken
	// by it, but by the next take on its own ZoneData
	t.Run("a take of a zone not loaded takes nothing", func(t *testing.T) {
		const name = "unloaded.take.example."
		kdb := newMPTestKeyDB(t)
		owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
		owner.Take(name)
		owner.takeOn(name, nil)
		owner.mu.RLock()
		_, recorded := owner.owned[name]
		owner.mu.RUnlock()
		if recorded {
			t.Fatal("a take of a zone not loaded was recorded")
		}
		later := signerTestZone(t, name, kdb)
		if owner.taken(name) || owner.Owns(later.ZoneData) {
			t.Error("the zone loaded later counts as taken by the take made before")
		}
	})

	t.Run("a zone removed and not added back is released", func(t *testing.T) {
		e, owner, old, _ := setup(t, "removed.take.example.")
		tdns.Zones.Remove(old.ZoneName)
		e.TakeConfiguredZones()
		if z := owner.Zones(); len(z) != 0 {
			t.Errorf("owned after the zone left: %v", z)
		}
		if e.waiting[lifecycleZoneName(old.ZoneName)] != "not loaded yet" {
			t.Errorf("the configured zone waits for %q, want its load", e.waiting[lifecycleZoneName(old.ZoneName)])
		}
	})
}
