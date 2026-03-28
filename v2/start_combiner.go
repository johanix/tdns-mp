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
)

// StartMPCombiner starts the MP combiner. It delegates DNS engine
// startup to tdns.StartCombiner (which skips MP engines for
// AppTypeMPCombiner), then starts the MP engines from tdns-mp.
func (conf *Config) StartMPCombiner(ctx context.Context, apirouter *mux.Router) error {
	// Attach OnFirstLoad callbacks to zone stubs created by ParseZones.
	// These use tdns-mp's local combiner functions (not the legacy tdns ones).
	// Attach OnFirstLoad callbacks (contributions, signal keys) and
	// PreRefresh/PostRefresh closures to MP zones. Install hook so
	// zones added via reload also get both sets of callbacks.
	conf.RegisterCombinerOnFirstLoad()
	conf.RegisterMPRefreshCallbacks()
	conf.Config.Internal.PostParseZonesHook = func() {
		conf.RegisterCombinerOnFirstLoad()
		conf.RegisterMPRefreshCallbacks()
	}

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
