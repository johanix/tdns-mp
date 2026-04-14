/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import tdns "github.com/johanix/tdns/v2"

// Imr embeds *tdns.Imr to allow adding MP-specific receiver methods
// (agent discovery lookups) while preserving access to all core Imr methods
// via promotion. This follows the same embedding pattern as MPZoneData.
type Imr struct {
	*tdns.Imr
}
