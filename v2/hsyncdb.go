/*
 * Copyright (c) Johan Stenstam, <johani@johani.org>
 *
 * HsyncDB wraps *tdns.KeyDB so that tdns-mp can define its own
 * methods (HSYNC peer CRUD, sync tracking, schema init, etc.)
 * while retaining access to all core tdns KeyDB methods via
 * Go embedding / promotion.
 */
package tdnsmp

import (
	"strings"
	"sync"

	tdns "github.com/johanix/tdns/v2"
)

type HsyncDB struct {
	*tdns.KeyDB
	mpDnskey *mpDnskeyCache
}

// mpDnskeyCache caches MPDnssecKeyStore key sets, keyed by mpDnssecCacheKey
// (zone+mpdnssec+state). tdns-mp used to park these entries in
// tdns.KeyDB.KeystoreDnskeyCache; tdns cbf13e14 removed that map in favour of
// per-zone signing-key snapshots built from tdns's own DnssecKeyStore, which
// the MP paths never write, so the MP entries live here and the tdns side
// needs no invalidation.
//
// There is one cache per *tdns.KeyDB, shared by every HsyncDB wrapping it,
// just as the old map lived on the KeyDB itself. NewHsyncDB is called in many
// places, some wrappers living for the whole process and some for one call; a
// cache per wrapper let an invalidation through one wrapper leave the others
// serving a retired key set.
type mpDnskeyCache struct {
	mu sync.Mutex
	m  map[string]*tdns.DnssecKeys
}

var mpDnskeyCaches sync.Map // *tdns.KeyDB -> *mpDnskeyCache

func mpDnskeyCacheFor(kdb *tdns.KeyDB) *mpDnskeyCache {
	if c, ok := mpDnskeyCaches.Load(kdb); ok {
		return c.(*mpDnskeyCache)
	}
	c, _ := mpDnskeyCaches.LoadOrStore(kdb, &mpDnskeyCache{m: make(map[string]*tdns.DnssecKeys)})
	return c.(*mpDnskeyCache)
}

func NewHsyncDB(kdb *tdns.KeyDB) *HsyncDB {
	if kdb == nil {
		return nil
	}
	return &HsyncDB{KeyDB: kdb, mpDnskey: mpDnskeyCacheFor(kdb)}
}

func (hdb *HsyncDB) mpDnskeyCache() *mpDnskeyCache {
	if hdb.mpDnskey != nil {
		return hdb.mpDnskey
	}
	return mpDnskeyCacheFor(hdb.KeyDB)
}

func (hdb *HsyncDB) mpDnskeyCacheGet(key string) (*tdns.DnssecKeys, bool) {
	c := hdb.mpDnskeyCache()
	c.mu.Lock()
	defer c.mu.Unlock()
	dk, ok := c.m[key]
	return dk, ok
}

func (hdb *HsyncDB) mpDnskeyCacheSet(key string, dk *tdns.DnssecKeys) {
	c := hdb.mpDnskeyCache()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = dk
}

func (hdb *HsyncDB) mpDnskeyCacheDelete(keys ...string) {
	c := hdb.mpDnskeyCache()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range keys {
		delete(c.m, k)
	}
}

// mpDnskeyCachePurgeZone drops every cached state for zone. The key format
// is produced by mpDnssecCacheKey; its zone prefix ends at the second "+".
func (hdb *HsyncDB) mpDnskeyCachePurgeZone(zone string) {
	c := hdb.mpDnskeyCache()
	c.mu.Lock()
	defer c.mu.Unlock()
	prefix := zone + "+mpdnssec+"
	for k := range c.m {
		if strings.HasPrefix(k, prefix) {
			delete(c.m, k)
		}
	}
}
