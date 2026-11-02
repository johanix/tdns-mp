/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MPZoneData wraps *tdns.ZoneData so that tdns-mp owns the zone lookup
 * type. MPZones is a lazy-caching accessor that delegates to tdns.Zones
 * and returns *MPZoneData instead of *tdns.ZoneData.
 */

package tdnsmp

import (
	"sync"

	tdns "github.com/johanix/tdns/v2"
)

// MPZoneData embeds *tdns.ZoneData. All core ZoneData fields and
// methods are accessible via Go promotion.
//
// MP *MPState shadows the promoted tdns.ZoneData.MP field, so all
// .MP accesses in tdns-mp resolve to the local MPState copy.
//
// MPOptions holds MP-dynamic options (set by HSYNC analysis) that
// are only read by tdns-mp code. Options read by tdns core
// infrastructure (OptInlineSigning, OptMultiProvider, etc.) stay
// on zd.Options.
//
// SyncQ is the MP sync request channel. It lives here (not on
// tdns.ZoneData) because it is only used by tdns-mp code.
type MPZoneData struct {
	*tdns.ZoneData
	MP        *MPState
	MPOptions map[tdns.ZoneOption]bool
	SyncQ     chan SyncRequest
}

// Reads of zone data go through the promoted tdns methods. GetOwner and
// GetRRset read the published snapshot and gate on Ready: the serve path.
// Anything that runs on a zone that may not have published yet -- the
// incoming new_zd the pre-refresh analysis inspects -- reads through
// OwnerForAnalysis and RRsetForAnalysis, which fall back to Data there.
// The shadow that used to make GetOwner read Data on such a zone is gone
// with them.

// MPZoneTuple is the iteration element returned by IterBuffered.
type MPZoneTuple struct {
	Key string
	Val *MPZoneData
}

// MPZones is a lazy-caching accessor over tdns.Zones. It returns
// *MPZoneData, creating and caching the wrapper on first access.
// tdns.Zones remains the authoritative source of zones; MPZones
// never creates or deletes zones, only wraps them.
type MPZones struct {
	mu    sync.RWMutex
	cache map[string]*MPZoneData
}

// Zones is the package-level accessor. tdns-mp code uses Zones.Get()
// instead of tdns.Zones.Get(). The name deliberately shadows tdns.Zones
// so that migration is mechanical (remove "tdns." prefix).
var Zones = &MPZones{
	cache: make(map[string]*MPZoneData),
}

// Get returns the *MPZoneData for the named zone, creating and
// caching the wrapper on first access. Returns false if the zone
// does not exist in tdns.Zones.
//
// tdns.Zones is asked on every call, and the cached wrapper is
// returned only while it wraps the zone tdns holds now. A zone that
// has left tdns.Zones (a config reload, a catalog or API removal) is
// not returned, and its wrapper is dropped. A zone tdns has replaced
// with a new *tdns.ZoneData (a modify, or a removal and a re-add)
// gets a new wrapper.
func (mz *MPZones) Get(name string) (*MPZoneData, bool) {
	zd, ok := tdns.Zones.Get(name)
	if !ok {
		mz.drop(name)
		return nil, false
	}
	return mz.getOrCreate(name, zd), true
}

// drop removes the cached wrapper of a zone tdns.Zones no longer
// holds. It asks again under the lock, so that a wrapper of a zone
// added back in the meantime is kept.
func (mz *MPZones) drop(name string) {
	mz.mu.RLock()
	_, cached := mz.cache[name]
	mz.mu.RUnlock()
	if !cached {
		return
	}

	mz.mu.Lock()
	defer mz.mu.Unlock()
	if mpzd, ok := mz.cache[name]; ok && !isLiveZone(name, mpzd.ZoneData) {
		delete(mz.cache, name)
	}
}

// isLiveZone reports whether zd is the zone tdns.Zones holds under
// name. tdns.Zones runs no callbacks under its own locks, so asking it
// while holding mz.mu cannot deadlock.
func isLiveZone(name string, zd *tdns.ZoneData) bool {
	live, ok := tdns.Zones.Get(name)
	return ok && live == zd
}

// Items returns all zones as a map, wrapping each in *MPZoneData.
// The authoritative source is tdns.Zones.Items().
func (mz *MPZones) Items() map[string]*MPZoneData {
	result := make(map[string]*MPZoneData)
	for name, zd := range tdns.Zones.Items() {
		result[name] = mz.getOrCreate(name, zd)
	}
	return result
}

// Keys returns zone names. Pass-through to tdns.Zones.Keys().
func (mz *MPZones) Keys() []string {
	return tdns.Zones.Keys()
}

// IterBuffered returns a buffered channel of MPZoneTuple, wrapping
// each zone from tdns.Zones.IterBuffered().
func (mz *MPZones) IterBuffered() <-chan MPZoneTuple {
	src := tdns.Zones.IterBuffered()
	ch := make(chan MPZoneTuple, cap(src))
	go func() {
		defer close(ch)
		for item := range src {
			mpzd := mz.getOrCreate(item.Key, item.Val)
			ch <- MPZoneTuple{Key: item.Key, Val: mpzd}
		}
	}()
	return ch
}

// IterCb calls fn for each zone, wrapping the value in *MPZoneData.
func (mz *MPZones) IterCb(fn func(key string, v *MPZoneData)) {
	for item := range tdns.Zones.IterBuffered() {
		mpzd := mz.getOrCreate(item.Key, item.Val)
		fn(item.Key, mpzd)
	}
}

// Set stores a pre-populated *MPZoneData in the cache. Used by
// OnFirstLoad callbacks to ensure the cached object has MP fields
// initialized before any Get() call.
func (mz *MPZones) Set(name string, mpzd *MPZoneData) {
	mz.mu.Lock()
	defer mz.mu.Unlock()
	mz.cache[name] = mpzd
}

// Invalidate removes a cached entry. Get drops the wrapper of a zone
// tdns.Zones no longer holds by itself; Invalidate drops it at once.
func (mz *MPZones) Invalidate(name string) {
	mz.mu.Lock()
	defer mz.mu.Unlock()
	delete(mz.cache, name)
}

// getOrCreate returns the cached *MPZoneData of the given
// *tdns.ZoneData, or creates one. A cached wrapper of another
// *tdns.ZoneData is of a zone tdns has replaced, and is replaced in
// turn. Only the live zone's wrapper is cached: a caller that read zd
// from tdns.Zones just before tdns replaced it gets a wrapper of its
// own, and the live zone's wrapper stays.
func (mz *MPZones) getOrCreate(name string, zd *tdns.ZoneData) *MPZoneData {
	mz.mu.RLock()
	if mpzd, ok := mz.cache[name]; ok && mpzd.ZoneData == zd {
		mz.mu.RUnlock()
		return mpzd
	}
	mz.mu.RUnlock()

	mz.mu.Lock()
	defer mz.mu.Unlock()
	if mpzd, ok := mz.cache[name]; ok && mpzd.ZoneData == zd {
		return mpzd
	}
	mpzd := &MPZoneData{
		ZoneData:  zd,
		MP:        &MPState{},
		MPOptions: make(map[tdns.ZoneOption]bool),
	}
	if isLiveZone(name, zd) {
		mz.cache[name] = mpzd
	}
	return mpzd
}
