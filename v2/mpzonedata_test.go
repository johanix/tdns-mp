package tdnsmp

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// mpZone puts a zone of its own into tdns.Zones, and takes it out again
// when the test ends.
func mpZone(t *testing.T, name string) *tdns.ZoneData {
	t.Helper()
	zd := &tdns.ZoneData{ZoneName: name, ZoneType: tdns.Primary}
	tdns.Zones.Set(name, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(name)
		Zones.Invalidate(name)
	})
	return zd
}

// cachedWrapper is the wrapper Zones keeps for name, if any.
func cachedWrapper(name string) *MPZoneData {
	Zones.mu.RLock()
	defer Zones.mu.RUnlock()
	return Zones.cache[name]
}

// A zone that leaves tdns.Zones, as a config reload takes it out, is not
// returned, and its wrapper is not kept (#303).
func TestAZoneThatLeftTdnsIsNotReturned(t *testing.T) {
	const name = "removed.mpzones.example."
	mpZone(t, name)
	if _, ok := Zones.Get(name); !ok {
		t.Fatal("a zone tdns holds is not returned")
	}

	tdns.Zones.Remove(name)
	if mpzd, ok := Zones.Get(name); ok {
		t.Errorf("a zone that left tdns.Zones is returned, wrapping %p", mpzd.ZoneData)
	}
	if _, ok := Zones.Items()[name]; ok {
		t.Error("Items returns a zone that left tdns.Zones")
	}
	if cachedWrapper(name) != nil {
		t.Error("the wrapper of a zone that left tdns.Zones is still kept")
	}
}

// A zone tdns has replaced, as a reload that drops it and a later one
// that brings it back do, gets a new wrapper. Until then, every Get
// returns the same wrapper, with what was set on it.
func TestAZoneTdnsReplacedGetsANewWrapper(t *testing.T) {
	const name = "replaced.mpzones.example."
	mpZone(t, name)
	before, _ := Zones.Get(name)
	before.SyncQ = make(chan SyncRequest)
	if again, _ := Zones.Get(name); again != before {
		t.Fatal("a second Get of a zone tdns still holds returns a new wrapper")
	}

	tdns.Zones.Remove(name)
	zd := &tdns.ZoneData{ZoneName: name, ZoneType: tdns.Primary}
	tdns.Zones.Set(name, zd)
	after, ok := Zones.Get(name)
	if !ok || after.ZoneData != zd {
		t.Fatalf("Get after the zone came back = %+v, %v, want a wrapper of the new zone", after, ok)
	}
	if after.SyncQ != nil {
		t.Error("the new zone's wrapper carries the old one's SyncQ")
	}
	if Zones.Items()[name] != after {
		t.Error("Items does not return the new zone's wrapper")
	}
}

// A caller that read the zone from tdns.Zones just before tdns replaced
// it, as Items and IterBuffered read their snapshot, gets a wrapper of
// that zone, and the live zone's wrapper stays.
func TestAWrapperOfAReplacedZoneDoesNotTakeTheLiveOnesPlace(t *testing.T) {
	const name = "stale.mpzones.example."
	old := mpZone(t, name)
	tdns.Zones.Set(name, &tdns.ZoneData{ZoneName: name, ZoneType: tdns.Primary})
	live, _ := Zones.Get(name)

	if w := Zones.getOrCreate(name, old); w.ZoneData != old {
		t.Errorf("the wrapper for the replaced zone wraps %p, want %p", w.ZoneData, old)
	}
	if again, _ := Zones.Get(name); again != live {
		t.Error("the live zone's wrapper was replaced by one of the zone tdns replaced")
	}
}

// A Get that found the zone gone drops its wrapper only if tdns has not
// added the zone back in the meantime.
func TestADropAfterTheZoneIsBackKeepsItsWrapper(t *testing.T) {
	const name = "back.mpzones.example."
	mpZone(t, name)
	w, _ := Zones.Get(name)

	Zones.drop(name)
	if again, _ := Zones.Get(name); again != w {
		t.Error("the wrapper of a zone tdns holds was dropped")
	}
}
