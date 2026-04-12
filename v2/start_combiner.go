/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP combiner startup: StartMPCombiner starts DNS infrastructure
 * engines and MP-specific engines for the combiner role.
 */
package tdnsmp

import (
	"context"

	"github.com/gorilla/mux"
	tdns "github.com/johanix/tdns/v2"
)

// StartMPCombiner starts the MP combiner. It starts DNS infrastructure
// engines directly (no delegation to tdns), then starts MP-specific
// engines on top.
func (conf *Config) StartMPCombiner(ctx context.Context, apirouter *mux.Router) error {
	// Attach OnFirstLoad callbacks (contributions, signal keys) and
	// PreRefresh/PostRefresh closures to MP zones. Install hook so
	// zones added via reload also get both sets of callbacks.
	conf.RegisterCombinerOnFirstLoad()
	conf.RegisterMPRefreshCallbacks()
	conf.Config.Internal.PostParseZonesHook = func() {
		conf.RegisterCombinerOnFirstLoad()
		conf.RegisterMPRefreshCallbacks()
	}

	// Register all combiner API routes from tdns-mp
	conf.SetupMPCombinerRoutes(ctx, apirouter)

	// DNS infrastructure engines
	tdns.StartEngine(&tdns.Globals.App, "APIdispatcher", func() error {
		return tdns.APIdispatcher(conf.Config, apirouter, conf.Config.Internal.APIStopCh)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "RefreshEngine", func() {
		tdns.RefreshEngine(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "Notifier", func() error {
		return tdns.Notifier(ctx, conf.Config.Internal.NotifyQ)
	})
	tdns.StartEngine(&tdns.Globals.App, "NotifyHandler", func() error {
		return tdns.NotifyHandler(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "DnsEngine", func() error {
		return tdns.DnsEngine(ctx, conf.Config)
	})

	// MP engines
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
		combinerSyncRtr, err := conf.SetupCombinerSyncRouter(ctx)
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
