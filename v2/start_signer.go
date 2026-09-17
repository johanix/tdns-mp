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
	ensureDSEngineQueue(kdb)
	tdns.StartEngine(&tdns.Globals.App, "DSEngine", func() error {
		return kdb.DSEngine(ctx)
	})
	// The resolver: the key machine asks it whether the parent still serves
	// a retired KSK's DS (the transition table's E7). Only a signer that
	// owns a zone has that question, so only it starts one. ImrEngine
	// retries its own initialisation; until it has published, and for a
	// signer without one, the machine's answer is "unknown" and a retired
	// KSK waits.
	if want, why := conf.signerResolverWanted(); want {
		tdns.StartEngine(&tdns.Globals.App, "ImrEngine", func() error {
			return conf.Config.ImrEngine(ctx, true)
		})
	} else if why != "" {
		lgSigner.Warn("key lifecycle: no resolver in this signer; a retired KSK of an owned zone will wait for the operator", "why", why)
	}
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

// ensureDSEngineQueue gives the KeyDB the DS engine's request queue when it
// has none. tdns makes that queue in its MainInit, and only if the KeyDB
// exists by then; tdns-mp builds the KeyDB of its roles after that call, so
// here the queue was never made. Without it tdns's KeysChanged returns before
// it marks the zone or wakes the engine, silently: the CDS of an owned zone
// then follows its DS set only when the next transfer from the combiner
// restores the zone's dynamic records, not when a ds column changes.
func ensureDSEngineQueue(kdb *tdns.KeyDB) {
	if kdb != nil && kdb.DSEngineQ == nil {
		kdb.DSEngineQ = make(chan tdns.DSEngineRequest, 100)
	}
}

// signerResolverWanted says whether this signer starts a resolver: it does
// when its config names a zone whose key lifecycle it runs itself
// (key-lifecycle-zones), unless imrengine.active turns the resolver off. why
// is set when an owning signer goes without one.
func (conf *Config) signerResolverWanted() (want bool, why string) {
	mp := conf.MpConfig()
	if mp == nil || len(mp.KeyLifecycleZones) == 0 {
		return false, ""
	}
	if a := conf.Config.Imr.Active; a != nil && !*a {
		return false, "imrengine.active is false"
	}
	return true, ""
}
