/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP signer startup: StartMPSigner starts the tdns engines the signer
 * needs one by one (the DS engine among them; it does not call
 * tdns.StartAuth), then tdns-mp's own engines on top.
 */
package tdnsmp

import (
	"context"
	"time"

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
		return tdns.Notifier(ctx, conf.Config, conf.Config.Internal.NotifyQ)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "AuthQueryEngine", func() {
		tdns.AuthQueryEngine(ctx, conf.Config.Internal.AuthQueryQ)
	})
	tdns.StartEngine(&tdns.Globals.App, "ZoneUpdaterEngine", func() error {
		return kdb.ZoneUpdaterEngine(ctx)
	})
	// tdns's DS engine: the CDS of an owned zone follows its DS set between
	// transfers too (the machine's KeysChanged wakes it; key lifecycle
	// ownership design §4.1, arrow 1; tdns-mp #55)
	tdns.StartEngine(&tdns.Globals.App, "DSEngine", func() error {
		return kdb.DSEngine(ctx)
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
	// tdns KeyStateWorker: every signing zone's key lifecycle, the
	// multi-provider zones' through the lifecycle hooks.
	// tdns-mp's own key state machine for the zones the config names;
	// tdns's worker skips those (an owned zone), and runs the rest. Taken
	// before the worker starts, so its first sweep never sees them unowned.
	if e := conf.InternalMp.KeyLifecycle; e != nil {
		e.TakeConfiguredZones()
	}
	tdns.StartEngine(&tdns.Globals.App, "KeyStateWorker", func() error {
		return tdns.KeyStateWorker(ctx, conf.Config)
	})
	if e := conf.InternalMp.KeyLifecycle; e != nil {
		tdns.StartEngineNoError(&tdns.Globals.App, "KeyLifecycleEngine", func() {
			e.Run(ctx, 30*time.Second)
		})
	}

	// --- MP engines from tdns-mp ---
	tm := conf.InternalMp.MPTransport
	if tm != nil {
		tm.Start(ctx) // D3: router dispatch (chunk handler registered at init)
	}

	tdns.StartEngineNoError(&tdns.Globals.App, "SignerMsgHandler",
		func() { SignerMsgHandler(ctx, conf, conf.InternalMp.MsgQs) })

	// No MP key-state worker: tdns's KeyStateWorker above runs the
	// multi-provider key protocol through the lifecycle hooks
	// (RegisterMPKeyLifecycleHooks).

	return nil
}
