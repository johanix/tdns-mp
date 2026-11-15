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
	core "github.com/johanix/tdns/v2/core"
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
//
// A cached wrapper is valid only while it wraps the *tdns.ZoneData
// that tdns.Zones holds under its name (tdns-mp #396). tdns replaces
// a zone's ZoneData when a config reload removes the zone and a later
// one adds it back, and on its dynamic and catalog paths; a lookup
// then builds a new wrapper, with fresh MP state, as a start does,
// and the role's per-zone hooks run for the new ZoneData (OnNew).
type MPZones struct {
	mu sync.RWMutex
	// cache is filed by the name as tdns files its zones
	// (core.CanonicalizeName), so that one ZoneData has one wrapper
	// however its name is spelled.
	cache map[string]*MPZoneData
	// onNew is told of every wrapper built once the role's start has
	// installed it (SetOnNew); nil before that and in most tests.
	onNew func(*MPZoneData)
}

// Zones is the package-level accessor. tdns-mp code uses Zones.Get()
// instead of tdns.Zones.Get(). The name deliberately shadows tdns.Zones
// so that migration is mechanical (remove "tdns." prefix).
var Zones = &MPZones{
	cache: make(map[string]*MPZoneData),
}

// SetOnNew installs what is told of each wrapper built from now on:
// the role's per-zone hooks, which run once per ZoneData whoever looks
// it up first. It returns the one it replaces.
func (mz *MPZones) SetOnNew(f func(*MPZoneData)) func(*MPZoneData) {
	mz.mu.Lock()
	defer mz.mu.Unlock()
	prev := mz.onNew
	mz.onNew = f
	return prev
}

// Get returns the *MPZoneData for the named zone, creating and
// caching the wrapper on first access, and again when tdns has
// replaced the zone's ZoneData since. Returns false if the zone
// does not exist in tdns.Zones.
func (mz *MPZones) Get(name string) (*MPZoneData, bool) {
	zd, ok := tdns.Zones.Get(name)
	if !ok {
		return nil, false
	}
	return mz.getOrCreate(name, zd), true
}

// GetFor returns the wrapper of zd as long as zd is the ZoneData that
// tdns.Zones holds under its name. A callback registered on a zone that
// a reload has removed or replaced since is handed the old ZoneData, and
// gets false: it has nothing left to act on.
func (mz *MPZones) GetFor(zd *tdns.ZoneData) (*MPZoneData, bool) {
	if zd == nil {
		return nil, false
	}
	mpzd, ok := mz.Get(zd.ZoneName)
	if !ok || mpzd.ZoneData != zd {
		return nil, false
	}
	return mpzd, true
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

// Invalidate removes a cached entry. A lookup no longer needs it to
// see a replaced ZoneData; tests use it for a fresh wrapper of the same
// one.
func (mz *MPZones) Invalidate(name string) {
	mz.mu.Lock()
	defer mz.mu.Unlock()
	delete(mz.cache, core.CanonicalizeName(name))
}

// Prune drops the cached wrappers of zones that tdns no longer holds,
// or holds under another ZoneData, so that nothing here keeps a removed
// zone alive. Run after every zone reload (RegisterMPRefreshCallbacks).
func (mz *MPZones) Prune() {
	mz.mu.Lock()
	defer mz.mu.Unlock()
	for name, mpzd := range mz.cache {
		if zd, ok := tdns.Zones.Get(name); !ok || zd != mpzd.ZoneData {
			delete(mz.cache, name)
		}
	}
}

// getOrCreate returns the cached *MPZoneData of zd, or creates one
// when nothing is cached under name or what is wraps another
// ZoneData. zd is what tdns.Zones held a moment ago, or what a
// snapshot of it held (Items, IterBuffered): before anything is
// cached, what tdns holds now is looked at again under the lock, so
// that a ZoneData a reload has replaced since never displaces the
// live zone's wrapper and the MP state it has gathered. A zone tdns
// no longer holds gets a wrapper of zd that is not cached and runs no
// hooks. The hook runs outside the lock, since it reads the zone and
// registers callbacks on it.
func (mz *MPZones) getOrCreate(name string, zd *tdns.ZoneData) *MPZoneData {
	name = core.CanonicalizeName(name)
	mz.mu.RLock()
	if mpzd, ok := mz.cache[name]; ok && mpzd.ZoneData == zd {
		mz.mu.RUnlock()
		return mpzd
	}
	mz.mu.RUnlock()

	mz.mu.Lock()
	live, ok := tdns.Zones.Get(name)
	if !ok {
		mz.mu.Unlock()
		return newMPZoneData(zd)
	}
	if mpzd, ok := mz.cache[name]; ok && mpzd.ZoneData == live {
		mz.mu.Unlock()
		return mpzd
	}
	mpzd := newMPZoneData(live)
	mz.cache[name] = mpzd
	onNew := mz.onNew
	mz.mu.Unlock()
	if onNew != nil {
		onNew(mpzd)
	}
	return mpzd
}

// newMPZoneData is a wrapper of zd with fresh MP state.
func newMPZoneData(zd *tdns.ZoneData) *MPZoneData {
	return &MPZoneData{
		ZoneData:  zd,
		MP:        &MPState{},
		MPOptions: make(map[tdns.ZoneOption]bool),
	}
}
