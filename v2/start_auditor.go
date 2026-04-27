/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP auditor startup: StartMPAuditor starts DNS infrastructure plus
 * the MP engines needed for a read-only observer role.
 *
 * Phase A scope: passive observer only — receives BEATs, HELLOs,
 * PINGs, SYNC/UPDATE/RFI; participates in gossip; participates in
 * provider group computation. Does NOT run HsyncEngine,
 * SynchedDataEngine, leader election, KeyStateWorker, or any path
 * that produces outbound zone data. Phase B adds persistent event
 * log and in-memory AuditZoneState; Phase D adds the web dashboard.
 */
package tdnsmp

import (
	"context"
	"log"
	"time"

	"github.com/gorilla/mux"

	tdns "github.com/johanix/tdns/v2"
)

// StartMPAuditor starts the MP auditor. Modeled on StartMPAgent but
// omits SDE, HsyncEngine, leader election, parent-sync bootstrapping,
// and other write-side machinery.
func (conf *Config) StartMPAuditor(ctx context.Context, apirouter *mux.Router) error {
	tdns.StartEngine(&tdns.Globals.App, "APIdispatcher", func() error {
		return tdns.APIdispatcher(conf.Config, apirouter, conf.Config.Internal.APIStopCh)
	})

	// IMR for HSYNC3 / DSYNC discovery. Initialize synchronously so
	// it is available before the transport bridge starts processing
	// inbound messages.
	imrActive := conf.Config.Imr.Active == nil || *conf.Config.Imr.Active
	if imrActive {
		if err := conf.Config.InitImrEngine(true); err != nil {
			log.Fatalf("IMR initialization failed: %v", err)
		}
		tdns.StartEngine(&tdns.Globals.App, "ImrEngine", func() error {
			return conf.Config.ImrEngine(ctx, true)
		})
	} else {
		lgAuditor.Info("NOT starting imrengine (explicitly set to false)",
			"app", tdns.Globals.App.Name, "mode", tdns.AppTypeToString[tdns.Globals.App.Type])
	}

	// Register tdns-mp PreRefresh/PostRefresh closures on MP zones.
	conf.RegisterMPRefreshCallbacks()
	conf.Config.Internal.PostParseZonesHook = conf.RegisterMPRefreshCallbacks

	// Register CHUNK NOTIFY handler and start incoming DNS message
	// router (must precede NotifyHandler).
	if conf.InternalMp.TransportManager != nil {
		if err := conf.InternalMp.MPTransport.RegisterChunkNotifyHandler(); err != nil {
			lgAuditor.Error("failed to register CHUNK NOTIFY handler", "err", err)
		} else {
			conf.InternalMp.MPTransport.StartIncomingMessageRouter(ctx)
		}
	}

	tdns.StartEngineNoError(&tdns.Globals.App, "RefreshEngine", func() {
		tdns.RefreshEngine(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "Notifier", func() error {
		return tdns.Notifier(ctx, conf.Config.Internal.NotifyQ)
	})

	// Reliable message queue for outbound BEATs/HELLOs.
	if conf.InternalMp.TransportManager != nil {
		conf.InternalMp.MPTransport.StartReliableQueue(ctx)
	}

	// Provider group recomputation hook. The agent role triggers
	// RecomputeGroups via HsyncEngine's HSYNC-UPDATE flow; the auditor
	// doesn't run HsyncEngine, so we wire a one-shot OnFirstLoad and
	// rely on the AppTypeMPAuditor branch in MPZoneData.PostRefresh
	// for re-runs on HSYNC change. RecomputeGroups is a pure function
	// of zone data and does not require SharedZones / LocateAgent.
	ar := conf.InternalMp.AgentRegistry
	if ar != nil && ar.ProviderGroupManager != nil {
		for _, zoneName := range conf.Config.Internal.AllZones {
			mpzd, exists := Zones.Get(zoneName)
			if !exists {
				continue
			}
			if !mpzd.Options[tdns.OptMultiProvider] {
				continue
			}
			pgm := ar.ProviderGroupManager
			mpzd.OnFirstLoad = append(mpzd.OnFirstLoad, func(zd *tdns.ZoneData) {
				lgAuditor.Debug("OnFirstLoad: recomputing provider groups", "zone", zd.ZoneName)
				pgm.RecomputeGroups()
			})
		}
	}

	// Auditor message handler.
	msgQs := conf.InternalMp.MsgQs
	tdns.StartEngineNoError(&tdns.Globals.App, "AuditorMsgHandler", func() {
		AuditorMsgHandler(ctx, conf, msgQs)
	})

	// Agent-style protocol participation: infra-peer beats and
	// discovery retrier. The auditor's heartbeat ticker mirrors the
	// agent's HsyncEngine ticker without the sync logic.
	if ar != nil {
		tdns.StartEngineNoError(&tdns.Globals.App, "InfraBeatLoop", func() {
			ar.StartInfraBeatLoop(ctx)
		})
		tdns.StartEngineNoError(&tdns.Globals.App, "DiscoveryRetrierNG", func() {
			ar.DiscoveryRetrierNG(ctx)
		})

		heartbeatInterval := configureInterval("agent.remote.beatinterval", 15, 1800)
		tdns.StartEngineNoError(&tdns.Globals.App, "AuditorHeartbeatLoop", func() {
			ticker := time.NewTicker(time.Duration(heartbeatInterval) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					ar.SendHeartbeats()
				}
			}
		})
	}

	// Sync API server: receives HELLOs / BEATs over HTTPS from
	// peers. Auditors must accept these; refusing them would break
	// the protocol's expectation that every HSYNC3 member is
	// reachable.
	mp := conf.Config.MultiProvider
	if mp != nil && len(mp.Api.Addresses.Listen) > 0 {
		syncrtr, err := conf.SetupAgentSyncRouter(ctx)
		if err != nil {
			lgAuditor.Error("failed to set up sync API router", "err", err)
		} else {
			tdns.StartEngine(&tdns.Globals.App, "AuditorAPIdispatcherNG", func() error {
				lgAuditor.Info("starting auditor sync API",
					"addresses", mp.Api.Addresses.Listen)
				return tdns.APIdispatcherNG(conf.Config, syncrtr,
					mp.Api.Addresses.Listen,
					mp.Api.CertFile,
					mp.Api.KeyFile,
					conf.Config.Internal.APIStopCh)
			})
		}
	}

	// Zone-updater engine for any URI/JWK/SVCB publication the
	// auditor itself does (its own identity zone). Reused as-is.
	kdb := conf.Config.Internal.KeyDB
	if kdb != nil {
		tdns.StartEngine(&tdns.Globals.App, "ZoneUpdaterEngine", func() error {
			return kdb.ZoneUpdaterEngine(ctx)
		})
	}

	tdns.StartEngineNoError(&tdns.Globals.App, "AuthQueryEngine", func() {
		tdns.AuthQueryEngine(ctx, conf.Config.Internal.AuthQueryQ)
	})
	tdns.StartEngine(&tdns.Globals.App, "NotifyHandler", func() error {
		return tdns.NotifyHandler(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "DnsEngine", func() error {
		return tdns.DnsEngine(ctx, conf.Config)
	})

	// Setup auditor identity and publish transport records (URI,
	// addresses, TLSA, KEY) so peers can discover us via DNS. Same
	// shape as the agent's SetupAgent. Must run after
	// ZoneUpdaterEngine is started.
	if err := conf.SetupAgent(conf.Config.Internal.AllZones); err != nil {
		lgAuditor.Error("SetupAgent failed", "err", err)
	}

	return nil
}
