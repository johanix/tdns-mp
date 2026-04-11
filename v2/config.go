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

// RegisterMPRefreshCallbacks appends tdns-mp PreRefresh/PostRefresh
// closures to all MP zones that don't already have them. Called at
// startup and after every zone reload (SIGHUP / "config reload-zones")
// via the PostParseZonesHook.
func (conf *Config) RegisterMPRefreshCallbacks() {
	tm := conf.InternalMp.MPTransport
	msgQs := conf.InternalMp.MsgQs
	mp := conf.Config.MultiProvider
	if conf.InternalMp.refreshRegistered == nil {
		conf.InternalMp.refreshRegistered = make(map[string]bool)
	}
	for _, zoneName := range conf.Config.Internal.MPZoneNames {
		if conf.InternalMp.refreshRegistered[zoneName] {
			continue
		}
		zd, ok := tdns.Zones.Get(zoneName)
		if !ok || !zd.Options[tdns.OptMultiProvider] {
			continue
		}
		conf.InternalMp.refreshRegistered[zoneName] = true
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh,
			func(zd, new_zd *tdns.ZoneData) {
				MPPreRefresh(zd, new_zd, tm, msgQs, mp)
			})
		zd.OnZonePostRefresh = append(zd.OnZonePostRefresh,
			func(zd *tdns.ZoneData) {
				MPPostRefresh(zd, tm, msgQs)
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
func (conf *Config) ForEachMPZone(fn func(zd *tdns.ZoneData)) {
	for _, zoneName := range conf.Config.Internal.MPZoneNames {
		zd, exists := tdns.Zones.Get(zoneName)
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

	for _, zoneName := range conf.Config.Internal.MPZoneNames {
		if conf.InternalMp.onFirstLoadRegistered[zoneName] {
			continue
		}
		zd, exists := tdns.Zones.Get(zoneName)
		if !exists {
			continue
		}
		conf.InternalMp.onFirstLoadRegistered[zoneName] = true

		zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *tdns.ZoneData) {
			if !zd.Options[tdns.OptMultiProvider] {
				return
			}
			zd.EnsureMP()
			if zd.MP.PersistContributions == nil && zd.KeyDB != nil {
				hdb := NewHsyncDB(zd.KeyDB)
				zd.MP.PersistContributions = func(zone, senderID string, contribs map[string]map[uint16]core.RRset) error {
					return SaveContributions(hdb, zone, senderID, contribs)
				}
				lgCombiner.Info("PersistContributions callback set", "zone", zd.ZoneName)
			}
			if zd.MP.AgentContributions == nil && allContribs != nil {
				if zoneContribs, ok := allContribs[zd.ZoneName]; ok {
					zd.MP.AgentContributions = make(map[string]map[string]map[uint16]core.RRset)
					for senderID, ownerMap := range zoneContribs {
						zd.MP.AgentContributions[senderID] = ownerMap
					}
					RebuildCombinerData(zd)
					lgCombiner.Info("hydrated AgentContributions from snapshot",
						"zone", zd.ZoneName, "agents", len(zoneContribs))
				}
			}
			if zd.Options[tdns.OptAllowEdits] {
				success, err := tdns.ZoneDataCombineWithLocalChanges(zd)
				if err != nil {
					lgCombiner.Error("CombineWithLocalChanges failed in OnFirstLoad", "zone", zd.ZoneName, "err", err)
				} else if success {
					lgCombiner.Info("re-applied local changes after hydration", "zone", zd.ZoneName)
				}
			}
		})

		if GetProviderZoneRRtypes(zoneName) != nil {
			zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *tdns.ZoneData) {
				ApplyPendingSignalKeys(zd, hdb)
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
	ChunkPayloadStore     ChunkPayloadStore
	MPZoneNames           []string
	DistributionCache     *DistributionCache
	refreshRegistered     map[string]bool // tracks which zones have tdns-mp refresh callbacks
	onFirstLoadRegistered map[string]bool // tracks which zones have combiner OnFirstLoad callbacks
}
