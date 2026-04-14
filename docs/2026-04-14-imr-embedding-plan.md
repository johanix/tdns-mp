# Plan: Embed tdns.Imr in tdnsmp.Imr

**Date**: 2026-04-14
**Status**: DONE
**Linear issue**: TBD

## Goal

Migrate the 6 MP-specific Lookup methods from
`tdns/v2/legacy_agent_discovery_common.go` into tdns-mp as
receivers on a new `*tdnsmp.Imr` type that embeds `*tdns.Imr`.
Also convert the 3 standalone discovery functions into receivers
on `*tdnsmp.Imr`.

## Background

The 6 methods (`LookupAgentAPIEndpoint`, `LookupAgentDNSEndpoint`,
`LookupAgentJWK`, `LookupAgentKEY`, `LookupAgentTLSA`,
`LookupServiceAddresses`) are the last true cross-repo method
dependencies from tdns-mp into tdns/v2 legacy code. They are
MP-specific (agent discovery) and don't belong in tdns core.

The embedding pattern (`type Imr struct { *tdns.Imr }`) is the
same proven approach used for `MPZoneData` embedding
`*tdns.ZoneData`.

## How tdns-mp Gets Hold of *tdns.Imr Today

Two sources, both returning `*tdns.Imr`:

### Source 1: Closure on MPTransportBridge

```
MPTransportBridgeConfig.GetImrEngine func() *tdns.Imr
  → set in main_init.go:544 as:
    func() *tdns.Imr { return conf.Config.Internal.ImrEngine }
  → stored in MPTransportBridge.getImrEngine
```

Callers:
- `DiscoverAndRegisterAgent` (agent_discovery.go:356)
- `retryPendingDiscoveries` (hsyncengine.go:219)
- `MarkAgentAsNeeded` (agent_utils.go:554)
- cache flush in hsync_transport.go:395

### Source 2: Global tdns.Globals.ImrEngine

Callers that pass it into discovery code:
- `apihandler_peer.go:105` — peer-reset command, passed to
  `attemptDiscovery`

Callers that use it for non-discovery (core Imr methods only,
no changes needed):
- `apihandler_agent.go:463` — parentsync-inquire
  (`LookupDSYNCTarget`)
- `apihandler_agent.go:515,562,584,594` — imr-query/flush/
  reset/show (`Cache.*`)
- `start_agent.go:210` — onLeaderElected
  (`LookupDSYNCTarget`)
- `apihandler_peer.go:105` — peer-reset (`Cache.FlushDomain`)

## Call Chain to the 6 Lookup Methods

```
Source 1 (closure):
  tm.getImrEngine()
    → DiscoverAndRegisterAgent → DiscoverAgent
        → DiscoverAgentAPI (calls 3 Lookup methods)
        → DiscoverAgentDNS (calls 3 Lookup methods)

  ar.MPTransport.getImrEngine()
    → MarkAgentAsNeeded → attemptDiscovery
        → DiscoverAgentAPI / DiscoverAgentDNS
    → retryPendingDiscoveries → attemptDiscovery
        → DiscoverAgentAPI / DiscoverAgentDNS

Source 2 (global):
  tdns.Globals.ImrEngine
    → apihandler_peer.go peer-reset → attemptDiscovery
        → DiscoverAgentAPI / DiscoverAgentDNS
```

Key junction: `attemptDiscovery` is the single function through
which all discovery flows except `DiscoverAndRegisterAgent`.

## Implementation Steps

### Step 1: New file `tdns-mp/v2/imr.go`

Define the embedding type:
```go
type Imr struct {
    *tdns.Imr
}
```

### Step 2: New file `tdns-mp/v2/agent_discovery_common.go`

Copy the 6 Lookup methods from
`tdns/v2/legacy_agent_discovery_common.go`. Change receiver
from `(imr *Imr)` (tdns package) to `(imr *Imr)` (tdnsmp
package). Method bodies unchanged — they call `imr.ImrQuery()`
which promotes through embedding.

### Step 3: Convert discovery functions to receivers

In `agent_discovery.go`, convert 3 standalone functions to
receivers on `*Imr`:

```go
// Before:
func DiscoverAgentAPI(ctx, imr *tdns.Imr, identity, result)
func DiscoverAgentDNS(ctx, imr *tdns.Imr, identity, result)
func DiscoverAgent(ctx, imr *tdns.Imr, identity) *Result

// After:
func (imr *Imr) DiscoverAgentAPI(ctx, identity, result)
func (imr *Imr) DiscoverAgentDNS(ctx, identity, result)
func (imr *Imr) DiscoverAgent(ctx, identity) *Result
```

Update internal calls:
- `DiscoverAgent` calls `imr.DiscoverAgentAPI()`
  and `imr.DiscoverAgentDNS()` (receiver, no imr param)
- `DiscoverAndRegisterAgent` calls `imr.DiscoverAgent()`

### Step 4: Change closure return type

In `hsync_transport.go`:
```go
// MPTransportBridge field:
getImrEngine func() *Imr    // was func() *tdns.Imr

// MPTransportBridgeConfig field:
GetImrEngine func() *Imr    // was func() *tdns.Imr
```

In `main_init.go:544`:
```go
// Before:
GetImrEngine: func() *tdns.Imr {
    return conf.Config.Internal.ImrEngine
},

// After:
GetImrEngine: func() *Imr {
    return &Imr{conf.Config.Internal.ImrEngine}
},
```

### Step 5: Update attemptDiscovery and its callers

In `agent_utils.go`:
```go
// Before:
func (ar *AgentRegistry) attemptDiscovery(
    agent *Agent, imr *tdns.Imr, ...)

// After:
func (ar *AgentRegistry) attemptDiscovery(
    agent *Agent, imr *Imr, ...)
```

Call sites change from `DiscoverAgentAPI(ctx, imr, ...)` to
`imr.DiscoverAgentAPI(ctx, ...)`.

Also in `MarkAgentAsNeeded` (agent_utils.go:552):
```go
// Before:
var imr *tdns.Imr
...
imr = ar.MPTransport.getImrEngine()

// After:
var imr *Imr
...
imr = ar.MPTransport.getImrEngine()
```

In `retryPendingDiscoveries` (hsyncengine.go:217):
```go
// Before:
var imr *tdns.Imr
...
imr = ar.MPTransport.getImrEngine()

// After:
var imr *Imr
...
imr = ar.MPTransport.getImrEngine()
```

In `apihandler_peer.go:105` (peer-reset), wrap the global:
```go
// Before:
imr := tdns.Globals.ImrEngine
...
go ar.attemptDiscovery(agent, imr, ...)

// After:
rawImr := tdns.Globals.ImrEngine
...
go ar.attemptDiscovery(agent, &Imr{rawImr}, ...)
```

### Step 5b: Convert ALL remaining `*tdns.Imr` to `*Imr`

Consistency rule: ALL Imr usage in tdns-mp should use
`*tdnsmp.Imr`, not just the discovery call sites. This avoids
the confusion and wrong assumptions that have bitten us before
with mixed type usage.

Sites converted:
- `delegation_sync.go:25` — closure returns `*Imr`
- `parentsync_leader.go:1211` — `GetParentSyncStatus` takes
  `*Imr`
- `parentsync_utils.go:20` — `queryParentKeyStateDetailed`
  takes `*Imr`
- `apihandler_agent.go` — all imr-query/flush/reset/show +
  parentsync-inquire + parentsync-status wrap the global
- `start_agent.go:210` — onLeaderElected wraps the global
- `apihandler_peer.go:105` — peer-reset wraps the global

When crossing back into tdns functions that require
`*tdns.Imr` (e.g. `zd.AnalyseZoneDelegation`,
`zd.SyncZoneDelegation`, `zd.BestSyncScheme`), pass
`imr.Imr` (the embedded field).

### Step 6: Rename legacy file in tdns

Rename `tdns/v2/legacy_agent_discovery_common.go` to
`deadcode_agent_discovery_common.go`.

### Step 7: Build and verify

Run `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make` and
`cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make`.

## Files Modified

| File | Change |
|---|---|
| `tdns-mp/v2/imr.go` | NEW: type definition |
| `tdns-mp/v2/agent_discovery_common.go` | NEW: 6 Lookup methods as receivers |
| `tdns-mp/v2/agent_discovery.go` | Convert 3 funcs → receivers |
| `tdns-mp/v2/hsync_transport.go` | Closure type change |
| `tdns-mp/v2/main_init.go` | Wrap in closure |
| `tdns-mp/v2/agent_utils.go` | Signature + var types |
| `tdns-mp/v2/hsyncengine.go` | var type |
| `tdns-mp/v2/apihandler_peer.go` | Wrap global, consistent `*Imr` |
| `tdns-mp/v2/apihandler_agent.go` | All Imr sites wrapped |
| `tdns-mp/v2/start_agent.go` | onLeaderElected wrapped |
| `tdns-mp/v2/delegation_sync.go` | Closure returns `*Imr` |
| `tdns-mp/v2/parentsync_leader.go` | Signature change |
| `tdns-mp/v2/parentsync_utils.go` | Signature change |
| `tdns/v2/legacy_agent_discovery_common.go` | Rename to deadcode_ |

## Result

Zero `*tdns.Imr` references remain in tdns-mp (except the
embedding definition in `imr.go`). All Imr usage is
consistently `*tdnsmp.Imr`. When calling tdns functions that
require `*tdns.Imr`, the embedded field `imr.Imr` is passed.

## Risk Assessment

Low risk. Same proven embedding pattern as MPZoneData.
Wrapping points: closure in main_init.go + ad-hoc wraps at
`tdns.Globals.ImrEngine` access sites + one
`conf.Config.Internal.ImrEngine` site. All 6 Lookup methods
only use `imr.ImrQuery()` and one exported field, both of
which promote through embedding.
