/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * tdns-mp Config: wraps a pointer to tdns.Config, adds MP-specific state.
 * MainInit and StartMPSigner are receiver methods on this type.
 */
package tdnsmp

import (
	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"sync/atomic"
)

// Config wraps a pointer to the tdns.Config (typically &tdns.Conf)
// and adds MP-specific configuration and internal state.
//
// Using a pointer ensures that tdns code accessing the global
// tdns.Conf sees the same state as tdns-mp code.
type Config struct {
	*tdns.Config
	InternalMp InternalMpConf
}

// MpConfig returns the tdns-mp-side parse of the multi-provider
// config. This is the runtime source of truth for all MP config
// accessors. Returns nil if no multi-provider: block is present in
// the config (or if ParseConfig has not yet run).
func (conf *Config) MpConfig() *MultiProviderConf {
	return conf.InternalMp.mpConfig.Load()
}

// SetMpConfig installs the tdns-mp-side parse as the runtime MP config
// and mirrors it into the package-level WiredMpConfig(). The config
// parser hook calls it on every ParseConfig, including reloads, while
// the refresh callbacks read MpConfig() concurrently; the atomic pointer
// is what keeps that from being a data race.
func (conf *Config) SetMpConfig(mp *MultiProviderConf) {
	conf.InternalMp.mpConfig.Store(mp)
	wiredMpConfig.Store(mp)
}

// RegisterMPRefreshCallbacks appends tdns-mp PreRefresh/PostRefresh
// closures to all MP zones that don't already have them. Called at
// startup and after every zone reload (SIGHUP / "config reload-zones")
// via the PostParseZonesHook.
func (conf *Config) RegisterMPRefreshCallbacks() {
	tm := conf.InternalMp.MPTransport
	msgQs := conf.InternalMp.MsgQs
	if conf.InternalMp.refreshRegistered == nil {
		conf.InternalMp.refreshRegistered = make(map[string]bool)
	}
	for _, zoneName := range conf.InternalMp.MPZoneNames {
		if conf.InternalMp.refreshRegistered[zoneName] {
			continue
		}
		zd, ok := Zones.Get(zoneName)
		if !ok || !zd.Options[tdns.OptMultiProvider] {
			continue
		}
		// Wire SyncQ on every MP zone so PostRefresh can send without blocking
		if zd.SyncQ == nil {
			zd.SyncQ = conf.InternalMp.SyncQ
		}
		conf.InternalMp.refreshRegistered[zoneName] = true
		// The closure looks up conf.MpConfig() at invocation rather than
		// capturing the current pointer, so PostParseConfigHook can
		// replace the parsed MultiProviderConf on reload (SIGHUP) without
		// leaving these callbacks pointing at a stale copy.
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh,
			func(zd, new_zd *tdns.ZoneData) {
				if mpzd, ok := Zones.Get(zd.ZoneName); ok {
					mpzd.MPPreRefresh(new_zd, tm, msgQs, conf.MpConfig())
				}
			})
		zd.OnZonePostRefresh = append(zd.OnZonePostRefresh,
			func(zd *tdns.ZoneData) {
				if mpzd, ok := Zones.Get(zd.ZoneName); ok {
					mpzd.PostRefresh(tm, msgQs)
				}
			})
	}
}

// ForEachMPZone iterates all zones with OptMultiProvider and calls
// the supplied function for each. Used as the "second-pass loop"
// for attaching OnFirstLoad callbacks, populating MPdata, and
// other MP-specific per-zone setup after ParseZones returns.
//
// Caller must ensure ParseZones has completed (i.e. call after
// conf.Config.MainInit returns). OnFirstLoad callbacks attached
// here will fire later when RefreshEngine processes initial loads.
func (conf *Config) ForEachMPZone(fn func(zd *MPZoneData)) {
	for _, zoneName := range conf.InternalMp.MPZoneNames {
		zd, exists := Zones.Get(zoneName)
		if !exists {
			continue
		}
		if !zd.Options[tdns.OptMultiProvider] {
			continue
		}
		fn(zd)
	}
}

// RegisterCombinerOnFirstLoad attaches OnFirstLoad callbacks
// (PersistContributions, contribution hydration, signal keys) to MP
// zones that don't already have them. Called at startup and on
// reload via PostParseZonesHook for mpcombiner.
func (conf *Config) RegisterCombinerOnFirstLoad() {
	hdb := NewHsyncDB(conf.Config.Internal.KeyDB)
	if hdb == nil {
		return
	}
	if conf.InternalMp.onFirstLoadRegistered == nil {
		conf.InternalMp.onFirstLoadRegistered = make(map[string]bool)
	}

	// Load contributions snapshot once for all new zones
	allContribs, err := LoadAllContributions(hdb)
	if err != nil {
		lgCombiner.Error("RegisterCombinerOnFirstLoad: failed to load contributions", "err", err)
		allContribs = nil
	}

	for _, zoneName := range conf.InternalMp.MPZoneNames {
		if conf.InternalMp.onFirstLoadRegistered[zoneName] {
			continue
		}
		mpzd, exists := Zones.Get(zoneName)
		if !exists {
			continue
		}
		conf.InternalMp.onFirstLoadRegistered[zoneName] = true

		mpzd.OnFirstLoad = append(mpzd.OnFirstLoad, func(zd *tdns.ZoneData) {
			if !zd.Options[tdns.OptMultiProvider] {
				return
			}
			// mpzd is the captured outer loop variable and is the
			// authoritative wrapper for this zone; no need to re-lookup.
			w := mpzd
			w.Lock()
			w.EnsureMP()
			if w.MP.PersistContributions == nil && zd.KeyDB != nil {
				hdb := NewHsyncDB(zd.KeyDB)
				w.MP.PersistContributions = func(zone, senderID string, contribs map[string]map[uint16]core.RRset) error {
					return SaveContributions(hdb, zone, senderID, contribs)
				}
				lgCombiner.Info("PersistContributions callback set", "zone", zd.ZoneName)
			}
			var doRebuild bool
			if w.MP.AgentContributions == nil && allContribs != nil {
				if zoneContribs, ok := allContribs[zd.ZoneName]; ok {
					w.MP.AgentContributions = make(map[string]map[string]map[uint16]core.RRset)
					for senderID, ownerMap := range zoneContribs {
						w.MP.AgentContributions[senderID] = ownerMap
					}
					doRebuild = true
					lgCombiner.Info("hydrated AgentContributions from snapshot",
						"zone", zd.ZoneName, "agents", len(zoneContribs))
				}
			}
			doCombine := w.MPOptions[tdns.OptAllowEdits]
			w.Unlock()
			// RebuildCombinerData and CombineWithLocalChanges acquire
			// their own locks; call them outside our lock window.
			if doRebuild {
				w.RebuildCombinerData()
			}
			if doCombine {
				success, err := w.CombineWithLocalChanges()
				if err != nil {
					lgCombiner.Error("CombineWithLocalChanges failed in OnFirstLoad", "zone", zd.ZoneName, "err", err)
				} else if success {
					lgCombiner.Info("re-applied local changes after hydration", "zone", zd.ZoneName)
				}
			}
		})

		if GetProviderZoneRRtypes(zoneName) != nil {
			mpzd.OnFirstLoad = append(mpzd.OnFirstLoad, func(zd *tdns.ZoneData) {
				if w, ok := Zones.Get(zd.ZoneName); ok {
					w.ApplyPendingSignalKeys(hdb)
				}
			})
		}
	}
}

// InternalMpConf holds multi-provider internal state local to
// tdns-mp. Mirrors tdns.InternalMpConf field-by-field. During
// migration, both exist — code in tdns-mp reads from here,
// code in tdns reads from tdns.Config.Internal.
type InternalMpConf struct {
	HsyncDB               *HsyncDB
	SyncQ                 chan SyncRequest
	MsgQs                 *MsgQs
	SyncStatusQ           chan SyncStatus
	AgentRegistry         *AgentRegistry
	ZoneDataRepo          *ZoneDataRepo
	CombinerState         *CombinerState
	TransportManager      *transport.TransportManager
	MPTransport           *MPTransportBridge
	LeaderElectionManager *LeaderElectionManager
	MPZoneNames           []string
	DistributionCache     *DistributionCache
	AuditStateManager     *AuditStateManager
	AuditWebAuth          *AuditWebAuth
	refreshRegistered     map[string]bool // tracks which zones have tdns-mp refresh callbacks
	onFirstLoadRegistered map[string]bool // tracks which zones have combiner OnFirstLoad callbacks

	// mpConfig is the tdns-mp-side parse of the multi-provider: config
	// block, installed by SetMpConfig from the config parser hook
	// (RegisterMpConfigParser) on every parse. Read through
	// conf.MpConfig(); an atomic pointer because reloads store it while
	// runtime goroutines read it.
	mpConfig atomic.Pointer[MultiProviderConf]
}
