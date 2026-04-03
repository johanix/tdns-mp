/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP auditor startup: StartMPAuditor starts DNS infrastructure
 * and MP engines for the read-only observer role.
 */
package tdnsmp

import (
	"context"
	"time"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"

	tdns "github.com/johanix/tdns/v2"
)

// StartMPAuditor starts the MP auditor. It starts DNS engines for
// zone transfer and query handling, then starts MP engines for
// message reception, gossip, and audit event logging.
func (conf *Config) StartMPAuditor(ctx context.Context, apirouter *mux.Router) error {
	tdns.StartEngine(&tdns.Globals.App, "APIdispatcher", func() error {
		return tdns.APIdispatcher(conf.Config, apirouter, conf.Config.Internal.APIStopCh)
	})

	// IMR for DNS discovery
	imrActive := conf.Config.Imr.Active == nil || *conf.Config.Imr.Active
	if imrActive {
		tdns.StartEngine(&tdns.Globals.App, "ImrEngine", func() error {
			return conf.Config.ImrEngine(ctx, true)
		})
	}

	kdb := conf.Config.Internal.KeyDB

	// Register refresh callbacks so HSYNC3/HSYNCPARAM changes are tracked
	conf.RegisterMPRefreshCallbacks()
	conf.Config.Internal.PostParseZonesHook = conf.RegisterMPRefreshCallbacks

	tdns.StartEngineNoError(&tdns.Globals.App, "RefreshEngine", func() {
		tdns.RefreshEngine(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "Notifier", func() error {
		return tdns.Notifier(ctx, conf.Config.Internal.NotifyQ)
	})

	// Register CHUNK NOTIFY handler and start incoming DNS message router
	if conf.InternalMp.TransportManager != nil {
		if err := conf.InternalMp.MPTransport.RegisterChunkNotifyHandler(); err != nil {
			lgAuditor.Error("failed to register CHUNK NOTIFY handler", "err", err)
		} else {
			conf.InternalMp.MPTransport.StartIncomingMessageRouter(ctx)
		}
	}

	// Start the reliable message queue (for outbound BEATs/HELLOs)
	if conf.InternalMp.TransportManager != nil {
		conf.InternalMp.MPTransport.StartReliableQueue(ctx)
	}

	// Create audit state manager
	stateManager := NewAuditStateManager()

	// Initialize audit event log table
	if kdb != nil {
		if err := InitAuditEventLogTable(kdb); err != nil {
			lgAuditor.Error("failed to initialize audit event log", "err", err)
		}
	}

	// Start event log pruner
	retention := viper.GetDuration("audit.event_log.retention")
	if retention == 0 {
		retention = 168 * time.Hour // 1 week default
	}
	pruneInterval := viper.GetDuration("audit.event_log.prune_interval")
	if pruneInterval == 0 {
		pruneInterval = 1 * time.Hour
	}
	if kdb != nil {
		StartAuditEventPruner(ctx, kdb, retention, pruneInterval)
	}

	// Auditor message handler — consumes all messages, logs events, never sends data
	msgQs := conf.InternalMp.MsgQs
	tdns.StartEngineNoError(&tdns.Globals.App, "AuditorMsgHandler", func() {
		AuditorMsgHandler(ctx, conf, msgQs, stateManager)
	})

	// Agent-like engines for protocol participation
	ar := conf.InternalMp.AgentRegistry
	if ar != nil {
		tdns.StartEngineNoError(&tdns.Globals.App, "InfraBeatLoop", func() {
			ar.StartInfraBeatLoop(ctx)
		})
		tdns.StartEngineNoError(&tdns.Globals.App, "DiscoveryRetrierNG", func() {
			ar.DiscoveryRetrierNG(ctx)
		})
	}

	// Agent-to-agent sync API (for receiving HELLOs/BEATs over HTTPS)
	mp := conf.Config.MultiProvider
	if mp != nil && len(mp.Api.Addresses.Listen) > 0 {
		syncrtr, err := conf.Config.SetupAgentSyncRouter(ctx)
		if err != nil {
			lgAuditor.Error("failed to set up agent sync router", "err", err)
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

	// Zone updater — processes queued zone updates (URI, JWK, SVCB publication)
	tdns.StartEngine(&tdns.Globals.App, "ZoneUpdaterEngine", func() error {
		return kdb.ZoneUpdaterEngine(ctx)
	})

	// DNS query engine and notify handler
	tdns.StartEngineNoError(&tdns.Globals.App, "AuthQueryEngine", func() {
		tdns.AuthQueryEngine(ctx, conf.Config.Internal.AuthQueryQ)
	})
	tdns.StartEngine(&tdns.Globals.App, "NotifyHandler", func() error {
		return tdns.NotifyHandler(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "DnsEngine", func() error {
		return tdns.DnsEngine(ctx, conf.Config)
	})

	// Store state manager for API access
	conf.InternalMp.AuditStateManager = stateManager

	// Start the web interface if enabled
	if err := conf.StartAuditorWebServer(ctx); err != nil {
		lgAuditor.Error("failed to start auditor web server", "err", err)
	}

	return nil
}
