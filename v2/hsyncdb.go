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

	// mpDnskeyCache caches MPDnssecKeyStore key sets, keyed by
	// mpDnssecCacheKey (zone+mpdnssec+state). tdns-mp used to park these
	// entries in tdns.KeyDB.KeystoreDnskeyCache; tdns cbf13e14 removed that
	// global map in favour of per-zone signing-key snapshots built from
	// tdns's own DnssecKeyStore, which the MP paths never write, so the MP
	// entries now live here and the tdns side needs no invalidation.
	mpDnskeyMu    sync.Mutex
	mpDnskeyCache map[string]*tdns.DnssecKeys
}

func NewHsyncDB(kdb *tdns.KeyDB) *HsyncDB {
	if kdb == nil {
		return nil
	}
	return &HsyncDB{KeyDB: kdb, mpDnskeyCache: make(map[string]*tdns.DnssecKeys)}
}

func (hdb *HsyncDB) mpDnskeyCacheGet(key string) (*tdns.DnssecKeys, bool) {
	hdb.mpDnskeyMu.Lock()
	defer hdb.mpDnskeyMu.Unlock()
	dk, ok := hdb.mpDnskeyCache[key]
	return dk, ok
}

func (hdb *HsyncDB) mpDnskeyCacheSet(key string, dk *tdns.DnssecKeys) {
	hdb.mpDnskeyMu.Lock()
	defer hdb.mpDnskeyMu.Unlock()
	if hdb.mpDnskeyCache == nil {
		hdb.mpDnskeyCache = make(map[string]*tdns.DnssecKeys)
	}
	hdb.mpDnskeyCache[key] = dk
}

func (hdb *HsyncDB) mpDnskeyCacheDelete(keys ...string) {
	hdb.mpDnskeyMu.Lock()
	defer hdb.mpDnskeyMu.Unlock()
	for _, k := range keys {
		delete(hdb.mpDnskeyCache, k)
	}
}

// mpDnskeyCachePurgeZone drops every cached state for zone. The key format
// is produced by mpDnssecCacheKey; its zone prefix ends at the second "+".
func (hdb *HsyncDB) mpDnskeyCachePurgeZone(zone string) {
	hdb.mpDnskeyMu.Lock()
	defer hdb.mpDnskeyMu.Unlock()
	prefix := zone + "+mpdnssec+"
	for k := range hdb.mpDnskeyCache {
		if strings.HasPrefix(k, prefix) {
			delete(hdb.mpDnskeyCache, k)
		}
	}
}
