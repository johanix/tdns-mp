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
)

// StartMPSigner starts the MP signer. It delegates DNS engine
// startup to tdns.StartAuth, then starts MP-specific engines
// (SignerMsgHandler, KeyStateWorker, signer sync router).
func (conf *Config) StartMPSigner(ctx context.Context, apirouter *mux.Router) error {
	// DNS engines (refresh, signing, query, NOTIFY, etc.)
	if err := conf.Config.StartAuth(ctx, apirouter); err != nil {
		return err
	}

	// MP engines will be started here as signer files
	// are copied over:
	// - SignerMsgHandler
	// - KeyStateWorker
	// - SignerSyncRouter

	return nil
}
