/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP combiner startup: StartMPCombiner calls tdns.StartCombiner
 * for DNS engines, then starts MP-specific engines on top.
 */
package tdnsmp

import (
	"context"

	"github.com/gorilla/mux"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

// StartMPCombiner starts the MP combiner. It delegates DNS engine
// startup to tdns.StartCombiner (which skips MP engines for
// AppTypeMPCombiner), then starts the MP engines from tdns-mp.
func (conf *Config) StartMPCombiner(ctx context.Context, apirouter *mux.Router) error {
	// Attach OnFirstLoad callbacks to zone stubs created by ParseZones.
	// These use tdns-mp's local combiner functions (not the legacy tdns ones).
	kdb := conf.Config.Internal.KeyDB

	// Pre-load all contributions once (instead of per-zone in each OnFirstLoad).
	var allContribs map[string]map[string]map[string]map[uint16]core.RRset
	if kdb != nil {
		var err error
		allContribs, err = LoadAllContributions(kdb)
		if err != nil {
			lgCombiner.Error("StartMPCombiner: failed to pre-load contributions snapshot", "err", err)
		}
	}

	for _, zoneName := range conf.Config.Internal.AllZones {
		zd, exists := tdns.Zones.Get(zoneName)
		if !exists {
			lgCombiner.Error("zone stub not found, skipping callback attachment", "zone", zoneName)
			continue
		}
		if kdb != nil {
			zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *tdns.ZoneData) {
				if !zd.Options[tdns.OptMultiProvider] {
					return
				}

				zd.EnsureMP()

				// Set PersistContributions callback
				if zd.MP.PersistContributions == nil && zd.KeyDB != nil {
					kdb := zd.KeyDB
					zd.MP.PersistContributions = func(zone, senderID string, contribs map[string]map[uint16]core.RRset) error {
						return SaveContributions(kdb, zone, senderID, contribs)
					}
					lgCombiner.Info("PersistContributions callback set", "zone", zd.ZoneName)
				}
				// Hydrate AgentContributions from pre-loaded snapshot
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
				// Re-apply combined data now that contributions are loaded
				if zd.Options[tdns.OptAllowEdits] {
					success, err := tdns.ZoneDataCombineWithLocalChanges(zd)
					if err != nil {
						lgCombiner.Error("CombineWithLocalChanges failed in OnFirstLoad", "zone", zd.ZoneName, "err", err)
					} else if success {
						lgCombiner.Info("re-applied local changes after hydration", "zone", zd.ZoneName)
					}
				}
			})
		}
		// Provider zones: re-apply stored _signal KEY publish instructions on startup.
		if kdb != nil && GetProviderZoneRRtypes(zoneName) != nil {
			zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *tdns.ZoneData) {
				ApplyPendingSignalKeys(zd, kdb)
			})
		}
	}

	// Register tdns-mp PreRefresh/PostRefresh closures on MP zones
	// and install hook so new zones added via reload also get them.
	conf.RegisterMPRefreshCallbacks()
	conf.Config.Internal.PostParseZonesHook = conf.RegisterMPRefreshCallbacks

	// DNS engines (APIdispatcher, RefreshEngine, Notifier, NotifyHandler, DnsEngine)
	// MP engines are skipped because AppType == AppTypeMPCombiner
	if err := conf.Config.StartCombiner(ctx, apirouter); err != nil {
		return err
	}

	// MP engines from tdns-mp
	tm := conf.InternalMp.MPTransport
	if tm != nil {
		tm.StartIncomingMessageRouter(ctx)
		lgCombiner.Info("combiner incoming message router started")
	}

	// Start combiner message handler
	var protectedNS []string
	var errJournal *tdns.ErrorJournal
	if conf.InternalMp.CombinerState != nil {
		protectedNS = conf.InternalMp.CombinerState.ProtectedNamespaces
		errJournal = conf.InternalMp.CombinerState.ErrorJournal
	}
	tdns.StartEngineNoError(&tdns.Globals.App, "CombinerMsgHandler",
		func() { CombinerMsgHandler(ctx, conf, conf.InternalMp.MsgQs, protectedNS, errJournal) })

	// Start combiner sync API router (for agent→combiner HELLO/BEAT/PING over HTTPS)
	mp := conf.Config.MultiProvider
	if mp != nil && len(mp.SyncApi.Addresses.Listen) > 0 {
		combinerSyncRtr, err := conf.Config.SetupCombinerSyncRouter(ctx)
		if err != nil {
			lgCombiner.Error("failed to set up combiner sync router", "err", err)
		} else {
			tdns.StartEngine(&tdns.Globals.App, "CombinerAPIdispatcherNG", func() error {
				lgCombiner.Info("starting combiner sync API", "addresses", mp.SyncApi.Addresses.Listen)
				return tdns.APIdispatcherNG(conf.Config, combinerSyncRtr,
					mp.SyncApi.Addresses.Listen,
					mp.SyncApi.CertFile,
					mp.SyncApi.KeyFile,
					conf.Config.Internal.APIStopCh)
			})
		}
	}

	return nil
}
