/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP startup orchestration: MainInit calls tdns.MainInit for
 * DNS infrastructure, then adds MP components on top.
 */
package tdnsmp

import (
	"context"
)

// MainInit initializes the MP signer. It delegates DNS
// infrastructure setup to tdns.MainInit, then adds MP
// components (TransportManager, crypto, CHUNK handler,
// peer registration).
func (conf *Config) MainInit(ctx context.Context, defaultcfg string) error {
	// DNS infrastructure (zones, KeyDB, handlers, channels)
	if err := conf.Config.MainInit(ctx, defaultcfg); err != nil {
		return err
	}

	// MP additions will be wired here as signer files
	// are copied over:
	// - initSignerCrypto()
	// - createTransportManager()
	// - registerChunkHandler()
	// - registerPeers()

	return nil
}
