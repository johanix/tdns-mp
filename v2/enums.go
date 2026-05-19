/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * tdns-mp-owned AppType and ZoneOption values. Numeric ranges
 * are allocated in tdns (see tdns/v2/enums.go boundary constants).
 * The unexported sentinel + uint subtraction at the bottom of each
 * block is a compile-time gate: if tdns-mp adds enough constants
 * to cross into the next downstream package's range, the build
 * fails with "constant -1 overflows uint" pointing at the gate.
 *
 * String mappings into tdns.AppTypeToString / tdns.StringToAppType
 * (and the ZoneOption equivalents) are registered in init() so
 * that tdns code that looks up names of MP values continues to
 * work without tdns knowing about MP constants.
 */
package tdnsmp

import (
	tdns "github.com/johanix/tdns/v2"
)

// MP-owned AppType values. Range: tdns.TdnsAppTypeMax+1 .. tdns.TdnsMpAppTypeMax.
const (
	AppTypeMPSigner tdns.AppType = tdns.TdnsAppTypeMax + 1 + iota
	AppTypeMPAgent
	AppTypeMPCombiner
	AppTypeMPAuditor
	appTypeMPSentinel
)

// Compile-time gate: tdns-mp's last AppType value must fit in its
// allocated range. If a new constant is added that crosses
// tdns.TdnsMpAppTypeMax, this expression underflows and the build
// fails.
const _ uint = uint(tdns.TdnsMpAppTypeMax) - uint(appTypeMPSentinel-1)

// MP-owned ZoneOption values. Range: tdns.TdnsZoneOptionMax+1 .. tdns.TdnsMpZoneOptionMax.
const (
	OptMPManualApproval tdns.ZoneOption = tdns.TdnsZoneOptionMax + 1 + iota
	OptMPNotListedErr
	OptMPDisallowEdits
	optMPZoneOptionSentinel
)

// Compile-time gate (same shape as above).
const _ uint = uint(tdns.TdnsMpZoneOptionMax) - uint(optMPZoneOptionSentinel-1)

// Register MP enum names into the tdns string-mapping tables so
// lookup paths in tdns code (banner printing, debug logs) work
// uniformly for tdns and tdns-mp values.
func init() {
	tdns.AppTypeToString[AppTypeMPSigner] = "mpsigner"
	tdns.AppTypeToString[AppTypeMPAgent] = "mpagent"
	tdns.AppTypeToString[AppTypeMPCombiner] = "mpcombiner"
	tdns.AppTypeToString[AppTypeMPAuditor] = "mpauditor"

	tdns.StringToAppType["mpsigner"] = AppTypeMPSigner
	tdns.StringToAppType["mpagent"] = AppTypeMPAgent
	tdns.StringToAppType["mpcombiner"] = AppTypeMPCombiner
	tdns.StringToAppType["mpauditor"] = AppTypeMPAuditor

	tdns.ZoneOptionToString[OptMPManualApproval] = "mp-manual-approval"
	tdns.ZoneOptionToString[OptMPNotListedErr] = "mp-not-listed-error"
	tdns.ZoneOptionToString[OptMPDisallowEdits] = "mp-disallow-edits"

	tdns.StringToZoneOption["mp-manual-approval"] = OptMPManualApproval
	tdns.StringToZoneOption["mp-not-listed-error"] = OptMPNotListedErr
	tdns.StringToZoneOption["mp-disallow-edits"] = OptMPDisallowEdits
}
