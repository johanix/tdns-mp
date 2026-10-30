package tdnsmp

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
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
