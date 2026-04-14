# tdns-mp Function Dependencies on tdns

**Date**: 2026-04-11
**Status**: Analysis

## Summary

This document inventories every place where `tdns-mp/v2`
imports and calls symbols from `tdns/v2`, classifying each as
either **core DNS** (no problem — stays in tdns) or **MP leak**
(multi-provider code that should eventually live in tdns-mp).

Focus is on **functions**, not type declarations. Types in
`tdns/v2/mptypes.go` are known MP types but must stay in tdns
until all tdns-internal references are removed (functions
first, types last).

## MP Functions Still in tdns (9 remaining)

These are MP-specific functions/variables defined in tdns
that tdns-mp still depends on. Each needs to eventually
migrate to tdns-mp.

### Distribution (2 functions)

Both are aliased in `tdns-mp/v2/types.go` and called without
the `tdns.` prefix elsewhere.

| Function | Defined in | tdns-mp call sites |
|----------|------------|-------------------|
| `NewDistributionCache` | `legacy_apihandler_agent_distrib.go:76` | `types.go:71` (alias), `main_init.go:159,314,459` |
| `StartDistributionGC` | `legacy_apihandler_agent_distrib.go:610` | `types.go:72` (alias), `main_init.go:160,315,460` |

### Chunk subsystem (2 functions)

| Function | Defined in | tdns-mp call sites |
|----------|------------|-------------------|
| `NewMemChunkPayloadStore` | `legacy_chunk_store.go:50` | `main_init.go:482` |
| `RegisterChunkQueryHandler` | `legacy_chunk_query_handler.go:25` | `main_init.go:484` |

`NewMemChunkPayloadStore` creates the in-memory chunk payload
store used for query-mode CHUNK transport. The interface
(`ChunkPayloadStore`) and implementation
(`MemChunkPayloadStore`) are both in `legacy_chunk_store.go`.
`RegisterChunkQueryHandler` wires the CHUNK query responder
into the DNS engine.

### Wrappers (4 functions)

These wrap unexported tdns methods for tdns-mp's use.
`wrappers.go` exists solely as MP glue — the entire file
can be deleted once tdns-mp has its own implementations.

| Function | Defined in | Wraps | tdns-mp call sites |
|----------|------------|-------|-------------------|
| `ZoneDataCombineWithLocalChanges` | `wrappers.go:17` | `zd.combineWithLocalChanges()` | `config.go:131` |
| `OurHsyncIdentities` | `wrappers.go:36` | `ourHsyncIdentities()` | `combiner_chunk.go:175` |
| `ZoneDataMatchHsyncProvider` | `wrappers.go:41` | `zd.matchHsyncProvider()` | `combiner_chunk.go:176` |
| `ZoneDataSynthesizeCdsRRs` | `wrappers.go:46` | `zd.synthesizeCdsRRs()` | `combiner_chunk.go:319` |

### Signal key naming (1 function)

| Function | Defined in | tdns-mp call sites |
|----------|------------|-------------------|
| `Sig0KeyOwnerName` | `legacy_parentsync_leader.go:1316` | `combiner_chunk.go:528,638`, `combiner_utils.go:729` |

Computes `_sig0key.<zone>._signal.<nameserver>` owner names
for MP signal KEY publication. In a `legacy_` file (part of
the leader election / parent sync subsystem).

### MP variables (not functions, but MP-specific)

| Variable | Defined in | What it is | tdns-mp call sites |
|----------|------------|-----------|-------------------|
| `AgentStateToString` | `mptypes.go:36` | Agent state enum map (NEEDED, KNOWN, OPERATIONAL, etc.) | `cli/hsync_cmds.go` |
| `AllowedLocalRRtypes` | `mptypes.go:726` | Combiner RR type preset — which types a combiner accepts from agents | `cli/agent_zone_cmds.go`, `hsync_utils.go` |
| `ChunkPayloadStore` | `legacy_chunk_store.go:21` | Interface type for CHUNK payload storage | `types.go:53`, `main_init.go:473` |

Note: `HsyncTables` was also MP but has been migrated as
part of the HsyncDB migration and is now in a `deadcode_`
file in tdns.

## Already Migrated (3 functions — HsyncDB migration)

These were in the original list but moved to tdns-mp as
part of the HsyncDB migration (2026-04-11):

| Function | Was in | Now in |
|----------|--------|--------|
| `PeerRecordToInfo` | `db_hsync.go:628` | `tdns-mp/v2/db_hsync.go:634` |
| `SyncOpRecordToInfo` | `db_hsync.go:653` | `tdns-mp/v2/db_hsync.go:659` |
| `ConfirmRecordToInfo` | `db_hsync.go:673` | `tdns-mp/v2/db_hsync.go:679` |

## Core DNS Functions (no problem)

These are legitimate dependencies on core DNS infrastructure
in tdns. They stay as `tdns.` imports.

### Startup and engine registration

- `StartEngine` — generic engine launcher
- `StartEngineNoError` — same, ignores error
- `MainInit` — core DNS initialization
- `StartAgent` — starts standard agent subsystems
  (MP engines already removed from this function)
- `StartAuth` — starts auth subsystems
- `RegisterNotifyHandler` — generic NOTIFY handler
  registration framework (tdns-mp registers CHUNK
  handlers through it, but the framework is core)
- `RegisterZoneOptionHandler` — zone option processing
- `RegisterZoneOptionValidator` — zone option validation
- `ValidateDatabaseFile` — DB file validation

### DNS operations

- `FindZone` — zone lookup
- `SignMsg` — DNSSEC message signing
- `PrepareKeyCache` — DNSSEC key cache setup
- `StripKeyFileComments` — key file parsing
- `RecursiveDNSQueryWithServers` — recursive DNS query
- `DsyncUpdateTargetName` — DSYNC target computation
- `VerifyCertAgainstTlsaRR` — TLSA verification
- `NormalizeAddresses` — address normalization
- `SanitizeForJSON` — JSON sanitization

### Data structure constructors

- `NewClient` — API client
- `NewOwnerData` — DNS owner data
- `NewRRTypeStore` — RR type store
- `NewErrorJournal` — error journal

### Variables (not functions, but referenced)

- `Conf` — global config
- `Globals` — global state
- `Zones` — zone map
- `Logger` — logging
- `AppTypeToString` — enum map

## Import Package Breakdown

| Package | Symbol count | Status |
|---------|-------------|--------|
| `tdns/v2` | ~148 | 9 MP leaks + 3 MP vars, rest core DNS |
| `tdns/v2/core` | ~35 | All fine (RR types, message types) |
| `tdns/v2/edns0` | ~5 | All fine (EDNS0 options) |
| `tdns/v2/cli` | ~15 | All fine (CLI framework utilities) |

---

## apihandler_agent.go: MP sub-command analysis

`tdns/v2/apihandler_agent.go` (1385 lines) contains 28 case
blocks plus 4 standalone API handler functions. At the end
of the migration, this file must NOT reference any MP
functions. Analysis of every case block:

### Core DNS (stays in tdns) — 4 cases

| Case | What it does |
|------|-------------|
| `imr-query` | Queries IMR (recursive resolver) cache |
| `imr-flush` | Flushes IMR cache entries by domain |
| `imr-reset` | Resets entire IMR cache |
| `imr-show` | Shows IMR cache entries |

These use only `Globals.ImrEngine.Cache` — core DNS.

### MP (must be removed from tdns) — 24 cases + 4 handlers

All of these access MP infrastructure (`AgentRegistry`,
`LeaderElectionManager`, `MPTransport`, `MsgQs`,
`zd.MP.CombinerData`, etc.) and **all already have copies
in tdns-mp's `apihandler_agent.go`**.

**APIagent sub-commands** (13):
`config`, `update-local-zonedata`, `add-rr`/`del-rr`,
`hsync-agentstatus`, `discover`, `hsync-locate`,
`refresh-keys`, `resync`, `send-rfi`,
`parentsync-status`, `parentsync-election`,
`parentsync-inquire`, `parentsync-bootstrap`

**APIagentDebug sub-commands** (11):
`send-notify`/`send-rfi`, `dump-agentregistry`,
`dump-zonedatarepo`, `show-key-inventory`, `resync`,
`hsync-chunk-send`, `hsync-chunk-recv`,
`hsync-sync-state`, `show-combiner-data`,
`send-sync-to`, `queue-status`

**Standalone handler functions** (4):
`APIbeat`, `APIhello`, `APIsyncPing`, `APImsg` — all MP
message handlers, all have copies in tdns-mp.

**Helper functions** (2, NOT yet in tdns-mp):
`doPeerPing` (uses `TransportManager`, `PeerRegistry`,
`AgentId`) and `lookupStaticPeer` (uses
`conf.MultiProvider`). These must be copied to tdns-mp
if still needed, or confirmed dead code.

### End state for apihandler_agent.go in tdns

After migration, only the 4 IMR cases remain. The file
shrinks from ~1385 lines to ~200 lines. The 24 MP cases,
4 handler functions, and 2 helpers are all removed.

---

## Migration Plan

### Phase A: Wrappers (low effort)

**Goal**: Eliminate `wrappers.go` in tdns.

All 4 wrapper functions call unexported methods on
`*ZoneData` or unexported package-level functions. Two
migration strategies per wrapper:

1. **Export the underlying method in tdns** — rename e.g.
   `combineWithLocalChanges` → `CombineWithLocalChanges`.
   tdns-mp then calls `zd.CombineWithLocalChanges()`
   directly. The wrapper is deleted.

2. **Move the logic to tdns-mp** — if the underlying method
   is MP-specific and shouldn't be exported from tdns.

Analysis per wrapper:

| Wrapper | Underlying | Strategy |
|---------|-----------|----------|
| `ZoneDataCombineWithLocalChanges` | `zd.combineWithLocalChanges()` | Export in tdns — the method merges local edits with zone data, which is a general zone operation |
| `OurHsyncIdentities` | `ourHsyncIdentities()` | Move to tdns-mp — purely MP (reads HSYNC3 identity from configured zones) |
| `ZoneDataMatchHsyncProvider` | `zd.matchHsyncProvider()` | Move to tdns-mp — purely MP (matches zone HSYNC provider identities) |
| `ZoneDataSynthesizeCdsRRs` | `zd.synthesizeCdsRRs()` | Export in tdns — CDS synthesis is core DNSSEC (used by combiner but the logic is standard) |

**Files touched in tdns**: `wrappers.go` (delete 4 funcs),
zone source files (export 2 methods).

**Files touched in tdns-mp**: `config.go`,
`combiner_chunk.go` (update call sites), plus new local
implementations for the 2 moved functions.

**Verification**: Both repos build.

### Phase B: Sig0KeyOwnerName (low effort)

**Goal**: Move `Sig0KeyOwnerName` from
`legacy_parentsync_leader.go` to tdns-mp.

This is a pure function (takes zone + nameserver strings,
returns an owner name). No dependencies beyond string
formatting. Copy to tdns-mp (e.g. `parentsync_utils.go`),
update 3 call sites, delete from tdns.

**Files touched in tdns**:
`legacy_parentsync_leader.go` (remove function).

**Files touched in tdns-mp**: `parentsync_utils.go` or
`combiner_utils.go` (add function), `combiner_chunk.go`
(update 2 call sites), `combiner_utils.go` (update 1 call
site).

**Verification**: Both repos build.

### Phase C: Chunk subsystem (medium effort)

**Goal**: Move chunk payload store and chunk query handler
from tdns to tdns-mp.

These two files form a unit:
- `legacy_chunk_store.go` — `ChunkPayloadStore` interface,
  `MemChunkPayloadStore` implementation, constructor
- `legacy_chunk_query_handler.go` —
  `RegisterChunkQueryHandler` function

The chunk query handler integrates with the DNS query
responder. Before moving, analyze:
1. What does `RegisterChunkQueryHandler` register with?
   (likely `RegisterNotifyHandler` or a query handler
   map on `ZoneData`)
2. Does the handler reference any unexported tdns symbols?
3. Does any code in tdns itself call these functions?
   (expected: zero, since they're in `legacy_` files)

**Migration approach**:
1. Copy both files to tdns-mp
2. The `ChunkPayloadStore` interface type stays in tdns
   temporarily if `InternalConf` in `config.go` references
   it (it does — `config.go:531`). Add a type alias in
   tdns-mp during transition.
3. Update `main_init.go:482,484` to call local versions
4. Delete `legacy_` files from tdns once zero references
   remain

**Files touched in tdns**: `legacy_chunk_store.go` (delete),
`legacy_chunk_query_handler.go` (delete), possibly
`config.go` (remove `ChunkPayloadStore` from
`InternalConf` if no longer needed).

**Files touched in tdns-mp**: new `chunk_store.go`, new
`chunk_query_handler.go`, `main_init.go`, `types.go`.

**Verification**: Both repos build.

### Phase D: Distribution cache (medium effort)

**Goal**: Move `DistributionCache`, `NewDistributionCache`,
and `StartDistributionGC` from tdns to tdns-mp.

All in `legacy_apihandler_agent_distrib.go`. This file
likely contains more than just these two functions — the
full file needs analysis to determine scope.

**Migration approach**:
1. Read `legacy_apihandler_agent_distrib.go` to inventory
   all its contents
2. Identify which parts are already duplicated in tdns-mp
3. Copy remaining parts to tdns-mp
4. Remove aliases in `types.go:71-72`
5. Update `main_init.go` call sites
6. Check for tdns-internal callers before deleting

**Files touched in tdns**:
`legacy_apihandler_agent_distrib.go` (delete or gut).

**Files touched in tdns-mp**: new distribution file(s),
`types.go` (remove aliases), `main_init.go`.

**Verification**: Both repos build.

### Phase E: Gut MP from apihandler_agent.go (medium effort)

**Goal**: Remove all 24 MP case blocks, 4 MP handler
functions, and 2 MP helpers from
`tdns/v2/apihandler_agent.go`.

**Precondition**: Phases C and D complete (chunk and
distribution code has migrated). All MP sub-commands
already have working copies in tdns-mp.

**What stays**: The 4 IMR cases (`imr-query`,
`imr-flush`, `imr-reset`, `imr-show`) and the API
routing boilerplate.

**What goes**:
- 13 MP cases in `APIagent`
- 11 MP cases in `APIagentDebug`
- `APIbeat`, `APIhello`, `APIsyncPing`, `APImsg`
  (standalone handler functions)
- `doPeerPing`, `lookupStaticPeer` (helper functions)

**Migration of helpers**: Check if `doPeerPing` and
`lookupStaticPeer` are still needed by tdns-mp. If so,
copy them before deleting. If they are dead code in the
new architecture, just delete.

**Files touched in tdns**: `apihandler_agent.go` (gut
from ~1385 to ~200 lines), `apirouters.go` (remove
route registrations for `APIbeat`, `APIhello`,
`APIsyncPing`, `APImsg` — these routes now only exist
in tdns-mp).

**Files touched in tdns-mp**: possibly add `doPeerPing`
and `lookupStaticPeer` if still needed.

**Verification**: Both repos build. tdns's
`apihandler_agent.go` has zero references to
`AgentRegistry`, `LeaderElectionManager`,
`MPTransport`, `MsgQs`, or `zd.MP`.

### Phase F: MP variables (low effort, after functions)

**Goal**: Move `AgentStateToString`, `AllowedLocalRRtypes`,
and `ChunkPayloadStore` interface.

These are variables/types in `mptypes.go` and
`legacy_chunk_store.go`. Per the migration rule (types
last), these move only after all MP functions that reference
them from within tdns have been removed.

`AgentStateToString` and `AllowedLocalRRtypes` can move
when `mptypes.go` cleanup happens (broader effort).
`ChunkPayloadStore` moves with Phase C or after.

### Phase order and dependencies

```
Phase A (wrappers)       — no dependencies, do first
Phase B (Sig0KeyOwner)   — no dependencies, parallel A
Phase C (chunk)          — no dependencies on A/B
Phase D (distribution)   — no dependencies on A/B/C
Phase E (gut apihandler) — after C and D
Phase F (MP vars)        — after all functions migrate
```

Phases A and B are independent and low effort — good
starting points. Phases C and D each require reading and
analyzing a `legacy_` file before proceeding. Phase E
depends on C and D being done (so the gutted sub-commands
don't reference missing functions). Phase F is cleanup
that follows naturally once the functions are gone.

### Post-migration state

After all phases:
- `wrappers.go` deleted from tdns
- `legacy_chunk_store.go` deleted from tdns
- `legacy_chunk_query_handler.go` deleted from tdns
- `legacy_apihandler_agent_distrib.go` deleted from tdns
- `Sig0KeyOwnerName` removed from
  `legacy_parentsync_leader.go`
- `apihandler_agent.go` reduced to ~200 lines (4 IMR
  cases only)
- `APIbeat`, `APIhello`, `APIsyncPing`, `APImsg`
  removed from tdns (live only in tdns-mp)
- tdns-mp has zero MP function dependencies on tdns
- Remaining dependencies are all core DNS (22 functions,
  5 variables) — legitimate and permanent
