/*
 * Copyright (c) Johan Stenstam, <johani@johani.org>
 */
package tdnsmp

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// Every HsyncDB wrapping one KeyDB shares one MP DNSSEC key cache. NewHsyncDB
// is called in many places; with a cache per wrapper, a key-state change
// invalidated through one wrapper left the others serving a retired key set.
func TestMPDnskeyCacheSharedPerKeyDB(t *testing.T) {
	kdb := &tdns.KeyDB{}
	a, b := NewHsyncDB(kdb), NewHsyncDB(kdb)
	key := mpDnssecCacheKey("example.", "active")

	a.mpDnskeyCacheSet(key, &tdns.DnssecKeys{})
	if _, ok := b.mpDnskeyCacheGet(key); !ok {
		t.Fatal("an entry set through one wrapper is not seen through another")
	}
	b.mpDnskeyCacheDelete(key)
	if _, ok := a.mpDnskeyCacheGet(key); ok {
		t.Fatal("an entry deleted through one wrapper is still cached in another")
	}

	a.mpDnskeyCacheSet(key, &tdns.DnssecKeys{})
	b.mpDnskeyCachePurgeZone("example.")
	if _, ok := a.mpDnskeyCacheGet(key); ok {
		t.Fatal("a zone purged through one wrapper is still cached in another")
	}

	other := NewHsyncDB(&tdns.KeyDB{})
	a.mpDnskeyCacheSet(key, &tdns.DnssecKeys{})
	if _, ok := other.mpDnskeyCacheGet(key); ok {
		t.Fatal("a wrapper of a different KeyDB sees this KeyDB's cache")
	}
}
