/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Agent discovery — Phase 2.6: the discovery PROCESS (lookups → resolve →
 * register → KNOWN) lives in tdns-transport (transport/discovery.go). MP
 * keeps the GATE — deciding WHICH peers are needed (HSYNC3/zone knowledge
 * transport never has) — and materializes its *Agent view of a completed
 * peer in the OnPeerDiscovered callback (hsync_transport.go).
 */

package tdnsmp

import (
	"context"
	"fmt"
)

// DiscoverAndRegisterAgent performs discovery and registration in one step.
// Thin shim over the transport-owned process; kept so the MP call sites
// (the chunk-notify discovery kick, distrib-time discovery) read naturally.
func (tm *MPTransportBridge) DiscoverAndRegisterAgent(ctx context.Context, identity string) error {
	if tm.TransportManager == nil {
		return fmt.Errorf("no transport manager configured for discovery")
	}
	return tm.TransportManager.DiscoverAndRegisterPeer(ctx, identity)
}
