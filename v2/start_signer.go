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
	// Append tdns-mp PreRefresh/PostRefresh closures to MP zones.
	// ParseZones already registered the tdns versions; we append ours
	// on top (duplicate execution is idempotent — see audit 9.1).
	tm := conf.InternalMp.MPTransport
	msgQs := conf.InternalMp.MsgQs
	mp := conf.Config.MultiProvider
	for _, zoneName := range conf.Config.Internal.MPZoneNames {
		zd, ok := tdns.Zones.Get(zoneName)
		if !ok || !zd.Options[tdns.OptMultiProvider] {
			continue
		}
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh,
			func(zd, new_zd *tdns.ZoneData) {
				MPPreRefresh(zd, new_zd, tm, msgQs, mp)
			})
		zd.OnZonePostRefresh = append(zd.OnZonePostRefresh,
			func(zd *tdns.ZoneData) {
				MPPostRefresh(zd, tm, msgQs)
			})
	}

	// DNS engines (refresh, signing, query, NOTIFY, etc.)
	// MP engines are skipped because AppType == AppTypeMPSigner
	if err := conf.Config.StartAuth(ctx, apirouter); err != nil {
		return err
	}

	// MP engines from tdns-mp
	tm = conf.InternalMp.MPTransport
	if tm != nil {
		tm.StartIncomingMessageRouter(ctx)
	}

	tdns.StartEngineNoError(&tdns.Globals.App, "SignerMsgHandler",
		func() { SignerMsgHandler(ctx, conf, conf.InternalMp.MsgQs) })

	tdns.StartEngine(&tdns.Globals.App, "KeyStateWorker",
		func() error { return KeyStateWorker(ctx, conf) })

	return nil
}
