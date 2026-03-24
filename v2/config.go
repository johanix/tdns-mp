/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * tdns-mp Config: embeds tdns.Config, adds MP-specific state.
 * MainInit and StartMPSigner are receiver methods on this type.
 */
package tdnsmp

import (
	tdns "github.com/johanix/tdns/v2"
)

// Config embeds the base tdns.Config and adds MP-specific
// configuration and internal state. As MP components are
// extracted from tdns, their config fields migrate here.
//
// The binary creates a tdnsmp.Config and calls its methods:
//
//	var conf tdnsmp.Config
//	conf.MainInit(ctx, defaultcfg)
//	conf.StartMPSigner(ctx)
//	conf.Config.MainLoop(ctx, cancel)
type Config struct {
	tdns.Config // DNS config (embedded)

	// MP-specific fields will be added as signer files
	// are copied over and adapted.
}
