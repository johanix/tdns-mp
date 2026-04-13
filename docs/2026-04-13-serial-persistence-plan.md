# Serial Persistence: Automatic Decision from HSYNC Analysis

**Date**: 2026-04-13
**Status**: Plan (not started)
**Priority**: Medium — no immediate catastrophe, but
semantically wrong behavior for agents

## Problem

The `persist-outbound-serial` option is currently a
manual config flag on the DNS engine. This is wrong:

- Operators can misconfigure it (e.g., set it on an
  agent that should never persist serials)
- The correct behavior differs per zone AND per role
- The information needed to decide is already available
  from HSYNC analysis (`populateMPdata`)

Currently, `FetchFromUpstream` and `FetchFromFile` in
`zone_utils.go` unconditionally bump `CurrentSerial++`
on non-first-load refreshes. This causes agents to
serve a different serial than what they received from
upstream.

## Rules

The decision to persist (bump) the outgoing serial
must be derived automatically:

1. **Agent**: Never persist. Agents don't modify zones.
   They consume zone data for HSYNC analysis but serve
   it unchanged.

2. **Combiner**: Persist only for zones with
   `allow-edits` (not `mp-disallow-edits`). If the
   combiner doesn't edit the zone, it passes data
   through and should not bump the serial.

3. **Signer**: Persist only for zones it actually
   signs. Determined by `zd.MP.MPdata.Signer == true`
   after HSYNC analysis. If the signer is just a
   server (not signing), it passes the zone through
   unchanged.

4. **Non-MP zones**: Current behavior (bump for
   primary zones that get modified locally) is correct.
   Secondary non-MP zones should accept upstream serial
   as-is.

## Design Requirements

### (a) Visibility

The persist-or-not-persist decision must be visible as
a dynamically assigned option, similar to `allow-edits`.
This is important because the decision differs per role
and per zone. Candidates:

- `persist-outbound-serial` (dynamic, set by HSYNC
  analysis)
- `accept-upstream-serial` (inverse, set when NOT
  persisting)

The option should appear in zone listings (e.g.,
`zone mplist` output) so operators can see what each
zone is doing.

### (b) MP-specific options on MPZoneData

Consider moving MP-specific dynamic options to a new
options field on `MPZoneData` rather than adding more
MP options to `tdns.ZoneData.Options`:

```go
type MPZoneData struct {
    *tdns.ZoneData
    SyncQ     chan SyncRequest
    MPOptions map[MPOption]bool  // new
}
```

This keeps the tdns `Options` map clean of MP
semantics and makes the separation explicit. Dynamic
options like `allow-edits`, `persist-outbound-serial`,
and future MP-specific flags would live here.

Trade-off: existing code reads `zd.Options[OptXxx]`
everywhere. Moving to `mpzd.MPOptions[OptXxx]` requires
touching all those sites. Could be done incrementally
(new options on MPOptions, migrate old ones later).

### (c) Misconfiguration warnings

If the operator explicitly sets `persist-outbound-serial`
in the config, the system must warn:

- At config validation time: log a warning that the
  option is ignored / overridden by HSYNC analysis
- In `agent config status` or equivalent CLI: show
  "config warning: persist-outbound-serial is set but
  this role does not persist serials"
- The explicit config option should NOT override the
  automatic decision — it's purely informational (or
  removed entirely)

## Implementation Sketch

1. After `populateMPdata` runs (in `OnZonePreRefresh`
   or `OnFirstLoad`), compute the persist decision:
   - Agent: false
   - Combiner: `!zd.Options[OptMPDisallowEdits]`
   - Signer: `zd.MP.MPdata.Signer`

2. Store the decision on MPZoneData (or as a dynamic
   option visible in zone listings).

3. In `FetchFromUpstream` / `FetchFromFile` hard-flip:
   check the decision instead of unconditionally
   bumping. The check must be available at refresh
   time, so the decision must be computed before the
   first non-initial refresh.

4. For the first refresh (FirstZoneLoad), the HSYNC
   analysis hasn't run yet, so use the incoming serial
   (which is correct — no modifications have been made
   yet).

5. Remove or deprecate the `persist-outbound-serial`
   config option. Warn if set.

## Open Questions

- Should `AuthOptPersistOutboundSerial` be removed
  from the config entirely, or kept as an override
  for non-MP use cases (e.g., a standalone auth server
  that modifies zones)?
- Naming: `MPOptions` vs extending `Options` with a
  clear MP prefix?
- Should the decision be recomputed on every refresh
  (in case HSYNC data changes), or set once at first
  load?
