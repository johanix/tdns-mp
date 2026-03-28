/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP agent startup: StartMPAgent replicates tdns.StartAgent but
 * reads MP fields from conf.InternalMp and DNS fields from
 * conf.Config.Internal.
 */
package tdnsmp

import (
	"context"
	"fmt"

	"github.com/gorilla/mux"

	tdns "github.com/johanix/tdns/v2"
)

func (conf *Config) StartMPAgent(ctx context.Context, apirouter *mux.Router) error {
	tdns.StartEngine(&tdns.Globals.App, "APIdispatcher", func() error {
		return tdns.APIdispatcher(conf.Config, apirouter, conf.Config.Internal.APIStopCh)
	})

	// In tdns-agent, IMR is active by default unless explicitly set to false
	imrActive := conf.Config.Imr.Active == nil || *conf.Config.Imr.Active
	if imrActive {
		tdns.StartEngine(&tdns.Globals.App, "ImrEngine", func() error {
			return conf.Config.ImrEngine(ctx, true)
		})
	} else {
		lgAgent.Info("NOT starting imrengine (explicitly set to false)",
			"app", tdns.Globals.App.Name, "mode", tdns.AppTypeToString[tdns.Globals.App.Type])
	}

	kdb := conf.Config.Internal.KeyDB

	// Append tdns-mp PreRefresh/PostRefresh closures to MP zones.
	// ParseZones already registered the tdns versions; we append ours
	// on top (duplicate execution is idempotent — see audit 9.1).
	tm := conf.InternalMp.MPTransport
	msgQs := conf.InternalMp.MsgQs
	for _, zoneName := range conf.Config.Internal.MPZoneNames {
		zd, ok := tdns.Zones.Get(zoneName)
		if !ok || !zd.Options[tdns.OptMultiProvider] {
			continue
		}
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh,
			func(zd, new_zd *tdns.ZoneData) {
				MPPreRefresh(zd, new_zd, tm, msgQs)
			})
		zd.OnZonePostRefresh = append(zd.OnZonePostRefresh,
			func(zd *tdns.ZoneData) {
				MPPostRefresh(zd, tm, msgQs)
			})
	}

	tdns.StartEngineNoError(&tdns.Globals.App, "RefreshEngine", func() {
		tdns.RefreshEngine(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "Notifier", func() error {
		return tdns.Notifier(ctx, conf.Config.Internal.NotifyQ)
	})

	// Register CHUNK NOTIFY handler and start incoming DNS message router (must be before NotifyHandler)
	if conf.InternalMp.TransportManager != nil {
		if err := conf.InternalMp.MPTransport.RegisterChunkNotifyHandler(); err != nil {
			lgAgent.Error("failed to register CHUNK NOTIFY handler", "err", err)
		} else {
			conf.InternalMp.MPTransport.StartIncomingMessageRouter(ctx)
		}
	}

	// Initialize combiner as a virtual peer so HsyncEngine can manage heartbeats
	if err := conf.InternalMp.AgentRegistry.InitializeCombinerAsPeer(conf); err != nil {
		lgAgent.Warn("failed to initialize combiner as peer, continuing without combiner heartbeat monitoring", "err", err)
	}
	// Initialize signer as a virtual peer so it shows in "agent peer list" and can be pinged
	if err := conf.InternalMp.AgentRegistry.InitializeSignerAsPeer(conf); err != nil {
		lgAgent.Warn("failed to initialize signer as peer, continuing without signer peer registration", "err", err)
	}

	// Start the reliable message queue (must be after combiner peer initialization)
	if conf.InternalMp.TransportManager != nil {
		conf.InternalMp.MPTransport.StartReliableQueue(ctx)
	}

	// TODO: Leader election manager setup deferred until parentsync_leader.go
	// and related agent files move to tdns-mp. The leader election block
	// requires unexported symbols from tdns (broadcastElectToZone,
	// configuredPeers, providerGroupMgr, importSig0KeyFromPeer,
	// parseKeygenAlgorithm, parentSyncAfterKeyPublication).
	// Agent operates without leader election until those files are copied.
	lgAgent.Info("leader election not yet available in mpagent (deferred to Step 3c)")

	// Agent-specific engines
	tdns.StartEngineNoError(&tdns.Globals.App, "HsyncEngine", func() {
		conf.HsyncEngine(ctx, conf.InternalMp.MsgQs)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "InfraBeatLoop", func() {
		conf.InternalMp.AgentRegistry.StartInfraBeatLoop(ctx)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "DiscoveryRetrierNG", func() {
		conf.InternalMp.AgentRegistry.DiscoveryRetrierNG(ctx)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "SynchedDataEngine", func() {
		conf.SynchedDataEngine(ctx, conf.InternalMp.MsgQs)
	})

	syncrtr, err := conf.Config.SetupAgentSyncRouter(ctx)
	if err != nil {
		return fmt.Errorf("error setting up agent-to-agent sync router: %v", err)
	}
	tdns.StartEngine(&tdns.Globals.App, "APIdispatcherNG", func() error {
		lgAgent.Info("starting agent-to-agent sync engine",
			"app", tdns.Globals.App.Name, "mode", tdns.AppTypeToString[tdns.Globals.App.Type])
		return tdns.APIdispatcherNG(conf.Config, syncrtr,
			conf.Config.MultiProvider.Api.Addresses.Listen,
			conf.Config.MultiProvider.Api.CertFile,
			conf.Config.MultiProvider.Api.KeyFile,
			conf.Config.Internal.APIStopCh)
	})

	tdns.StartEngineNoError(&tdns.Globals.App, "AuthQueryEngine", func() {
		tdns.AuthQueryEngine(ctx, conf.Config.Internal.AuthQueryQ)
	})
	tdns.StartEngine(&tdns.Globals.App, "ScannerEngine", func() error {
		return tdns.ScannerEngine(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "ZoneUpdaterEngine", func() error {
		return kdb.ZoneUpdaterEngine(ctx)
	})
	tdns.StartEngine(&tdns.Globals.App, "DeferredUpdaterEngine", func() error {
		return kdb.DeferredUpdaterEngine(ctx)
	})
	tdns.StartEngine(&tdns.Globals.App, "UpdateHandler", func() error {
		return tdns.UpdateHandler(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "DelegationSyncher", func() error {
		return kdb.DelegationSyncher(ctx, conf.Config.Internal.DelegationSyncQ, conf.Config.Internal.NotifyQ, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "NotifyHandler", func() error {
		return tdns.NotifyHandler(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "DnsEngine", func() error {
		return tdns.DnsEngine(ctx, conf.Config)
	})

	return nil
}
