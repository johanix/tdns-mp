/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP signer startup: StartMPSigner calls tdns.StartAuth for
 * DNS engines, then starts MP-specific engines on top.
 */
package tdnsmp

import (
	"context"

	"github.com/gorilla/mux"
	tdns "github.com/johanix/tdns/v2"
)

// StartMPSigner starts the MP signer. It starts only the tdns
// engines the mpsigner actually needs, then starts MP-specific
// engines on top. This mirrors the pattern used by StartMPAgent
// and StartMPCombiner: each MP app manages its own startup
// explicitly rather than delegating to a tdns Start* function
// that may change over time.
func (conf *Config) StartMPSigner(ctx context.Context, apirouter *mux.Router) error {
	// Register tdns-mp PreRefresh/PostRefresh closures on MP zones
	// and install hook so new zones added via reload also get them.
	conf.RegisterMPRefreshCallbacks()
	conf.Config.Internal.PostParseZonesHook = conf.RegisterMPRefreshCallbacks

	// Register all signer API routes from tdns-mp
	conf.SetupMPSignerRoutes(ctx, apirouter)

	kdb := conf.Config.Internal.KeyDB

	// --- tdns engines needed by the mpsigner ---
	tdns.StartEngine(&tdns.Globals.App, "APIdispatcher", func() error {
		return tdns.APIdispatcher(conf.Config, apirouter, conf.Config.Internal.APIStopCh)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "RefreshEngine", func() {
		tdns.RefreshEngine(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "Notifier", func() error {
		return tdns.Notifier(ctx, conf.Config.Internal.NotifyQ)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "AuthQueryEngine", func() {
		tdns.AuthQueryEngine(ctx, conf.Config.Internal.AuthQueryQ)
	})
	tdns.StartEngine(&tdns.Globals.App, "ZoneUpdaterEngine", func() error {
		return kdb.ZoneUpdaterEngine(ctx)
	})
	tdns.StartEngine(&tdns.Globals.App, "UpdateHandler", func() error {
		return tdns.UpdateHandler(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "NotifyHandler", func() error {
		return tdns.NotifyHandler(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "DnsEngine", func() error {
		return tdns.DnsEngine(ctx, conf.Config)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "ResignerEngine", func() {
		tdns.ResignerEngine(ctx, conf.Config.Internal.ResignQ)
	})
	// tdns KeyStateWorker for non-MP zone key lifecycle
	tdns.StartEngine(&tdns.Globals.App, "KeyStateWorker", func() error {
		return tdns.KeyStateWorker(ctx, conf.Config)
	})

	// --- MP engines from tdns-mp ---
	tm := conf.InternalMp.MPTransport
	if tm != nil {
		tm.StartIncomingMessageRouter(ctx)
	}

	tdns.StartEngineNoError(&tdns.Globals.App, "SignerMsgHandler",
		func() { SignerMsgHandler(ctx, conf, conf.InternalMp.MsgQs) })

	// MP KeyStateWorker for MP zone key lifecycle
	tdns.StartEngine(&tdns.Globals.App, "MPKeyStateWorker",
		func() error { return KeyStateWorker(ctx, conf) })

	return nil
}
