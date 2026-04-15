/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MPState: tdns-mp-local type that replaces tdns.ZoneMPExtension
 * for all MP state accessed from tdns-mp code. The field
 * mpzd.MP (type *MPState) shadows the promoted mpzd.ZoneData.MP
 * (type *tdns.ZoneMPExtension), so all .MP accesses in tdns-mp
 * resolve to the local copy.
 */

package tdnsmp

import (
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// wiredMultiProvider is set once from MainInit after config parse; EnsureMP
// copies it onto each *MPState so lazy-created MPZoneData wrappers see it.
var wiredMultiProvider *tdns.MultiProviderConf

// MPState holds all multi-provider runtime state for a zone.
// Same fields as tdns.ZoneMPExtension plus RemoteDNSKEYs
// (migrated from tdns.ZoneData).
type MPState struct {
	CombinerData         *core.ConcurrentMap[string, OwnerData]
	UpstreamData         *core.ConcurrentMap[string, OwnerData]
	MultiProvider        *tdns.MultiProviderConf
	MPdata               *tdns.MPdata
	AgentContributions   map[string]map[string]map[uint16]core.RRset
	PersistContributions func(string, string, map[string]map[uint16]core.RRset) error
	LastKeyInventory     *KeyInventorySnapshot
	LocalDNSKEYs         []dns.RR
	RemoteDNSKEYs        []dns.RR
	KeystateOK           bool
	KeystateError        string
	KeystateTime         time.Time
	RefreshAnalysis      *ZoneRefreshAnalysis
}

// EnsureMP initializes the MP extension if nil.
func (mpzd *MPZoneData) EnsureMP() {
	if mpzd.MP == nil {
		mpzd.MP = &MPState{}
	}
	if mpzd.MP.MultiProvider == nil {
		mpzd.MP.MultiProvider = wiredMultiProvider
	}
}

// --- Migrated accessors (shadow promoted tdns versions) ---

func (mpzd *MPZoneData) GetLastKeyInventory() *KeyInventorySnapshot {
	mpzd.Lock()
	defer mpzd.Unlock()
	if mpzd.MP == nil {
		return nil
	}
	return mpzd.MP.LastKeyInventory
}

func (mpzd *MPZoneData) SetLastKeyInventory(inv *KeyInventorySnapshot) {
	mpzd.Lock()
	defer mpzd.Unlock()
	mpzd.EnsureMP()
	mpzd.MP.LastKeyInventory = inv
}

func (mpzd *MPZoneData) GetKeystateOK() bool {
	mpzd.Lock()
	defer mpzd.Unlock()
	if mpzd.MP == nil {
		return false
	}
	return mpzd.MP.KeystateOK
}

func (mpzd *MPZoneData) SetKeystateOK(ok bool) {
	mpzd.Lock()
	defer mpzd.Unlock()
	mpzd.EnsureMP()
	mpzd.MP.KeystateOK = ok
}

func (mpzd *MPZoneData) GetKeystateError() string {
	mpzd.Lock()
	defer mpzd.Unlock()
	if mpzd.MP == nil {
		return ""
	}
	return mpzd.MP.KeystateError
}

func (mpzd *MPZoneData) SetKeystateError(err string) {
	mpzd.Lock()
	defer mpzd.Unlock()
	mpzd.EnsureMP()
	mpzd.MP.KeystateError = err
}

func (mpzd *MPZoneData) GetKeystateTime() time.Time {
	mpzd.Lock()
	defer mpzd.Unlock()
	if mpzd.MP == nil {
		return time.Time{}
	}
	return mpzd.MP.KeystateTime
}

func (mpzd *MPZoneData) SetKeystateTime(t time.Time) {
	mpzd.Lock()
	defer mpzd.Unlock()
	mpzd.EnsureMP()
	mpzd.MP.KeystateTime = t
}

func (mpzd *MPZoneData) GetRemoteDNSKEYs() []dns.RR {
	mpzd.Lock()
	defer mpzd.Unlock()
	if mpzd.MP == nil {
		return nil
	}
	return mpzd.MP.RemoteDNSKEYs
}

func (mpzd *MPZoneData) SetRemoteDNSKEYs(keys []dns.RR) {
	mpzd.Lock()
	defer mpzd.Unlock()
	mpzd.EnsureMP()
	mpzd.MP.RemoteDNSKEYs = keys
}
