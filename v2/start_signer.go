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

// StartMPSigner starts the MP signer. It delegates DNS engine
// startup to tdns.StartAuth (which skips MP engines for
// AppTypeMPSigner), then starts the MP engines from tdns-mp.
func (conf *Config) StartMPSigner(ctx context.Context, apirouter *mux.Router) error {
	// Register tdns-mp PreRefresh/PostRefresh closures on MP zones
	// and install hook so new zones added via reload also get them.
	conf.RegisterMPRefreshCallbacks()
	conf.Config.Internal.PostParseZonesHook = conf.RegisterMPRefreshCallbacks

	// DNS engines (refresh, signing, query, NOTIFY, etc.)
	// MP engines are skipped because AppType == AppTypeMPSigner
	if err := conf.Config.StartAuth(ctx, apirouter); err != nil {
		return err
	}

	// MP engines from tdns-mp
	tm := conf.InternalMp.MPTransport
	if tm != nil {
		tm.StartIncomingMessageRouter(ctx)
	}

	tdns.StartEngineNoError(&tdns.Globals.App, "SignerMsgHandler",
		func() { SignerMsgHandler(ctx, conf, conf.InternalMp.MsgQs) })

	tdns.StartEngine(&tdns.Globals.App, "KeyStateWorker",
		func() error { return KeyStateWorker(ctx, conf) })

	return nil
}
