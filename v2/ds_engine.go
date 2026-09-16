/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"

	tdns "github.com/johanix/tdns/v2"
)

// startDSEngine starts tdns's DS engine, the child side's single owner of a
// zone's CDS RRset, on the process KeyDB.
//
// tdns's MainInit creates KeyDB.DSEngineQ for every process that has a KeyDB,
// and tdns's own StartAuth and StartAgent start the goroutine that serves it.
// The mp processes have their own start functions, so they have to start it
// themselves. A request with nothing serving the queue lands in its buffer,
// and the requester waits out the engine's reply timeout and then fails with
// "the DS engine did not answer".
//
// Two things in an mp process ask it:
//
//   - delegation sync, when a NOTIFY(CDS) carries DS adds or removes. The MP
//     DelegationSyncher reaches that through zd.SyncZoneDelegation, handing it
//     hdb.KeyDB -- the same KeyDB this is given.
//   - the KSK rollover engine run by tdns.KeyStateWorker, for a zone that is
//     not multi-provider.
//
// So the agent (syncher and KeyStateWorker) and the signer (KeyStateWorker)
// start it. The combiner and the auditor run neither, and nothing else asks.
//
// The engine publishes no CDS for a multi-provider zone. The agent still does,
// through PublishCdsRRs, and that is not a request to route through the engine.
//
// Start it after ZoneUpdaterEngine: the engine waits on the zone updater when
// it publishes.
func startDSEngine(ctx context.Context, kdb *tdns.KeyDB) {
	// MainInit creates the queue whenever it creates a KeyDB. Without one there
	// is nothing to serve, and a request against a nil queue already fails at
	// once rather than after the reply timeout.
	if kdb == nil || kdb.DSEngineQ == nil {
		lgEngine.Warn("not starting DSEngine: no KeyDB or no DS engine queue")
		return
	}
	tdns.StartEngine(&tdns.Globals.App, "DSEngine", func() error { return kdb.DSEngine(ctx) })
}
