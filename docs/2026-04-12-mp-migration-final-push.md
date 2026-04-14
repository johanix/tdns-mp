# MP Migration Final Push: 5-Phase Plan

**Date**: 2026-04-12
**Status**: Plan
**Branch**: `tdns-mp-removal-2` (both repos)
**Precondition**: MPZoneData experiment validated on
`mpzonedata-test-1`

## Goal

Eliminate all MP function dependencies from tdns-mp on
tdns. After this work, tdns-mp's only imports from tdns
are core DNS infrastructure (zones, records, config,
DNSSEC, DNS engine, API framework). The 57 MP type
references (from `mptypes.go`) remain until a later
cleanup pass (types last).

## Current State (9 MP functions + structural)

| # | Function | tdns file | tdns-mp call sites |
|---|----------|-----------|-------------------|
| 1 | `ZoneDataCombineWithLocalChanges` | `wrappers.go` | `config.go:131` |
| 2 | `OurHsyncIdentities` | `wrappers.go` | `combiner_chunk.go:175` |
| 3 | `ZoneDataMatchHsyncProvider` | `wrappers.go` | `combiner_chunk.go:176` |
| 4 | `ZoneDataSynthesizeCdsRRs` | `wrappers.go` | `combiner_chunk.go:319` |
| 5 | `Sig0KeyOwnerName` | `legacy_parentsync_leader.go` | `combiner_chunk.go:528,638` + `combiner_utils.go:729` |
| 6 | `NewMemChunkPayloadStore` | `legacy_chunk_store.go` | `main_init.go:482` |
| 7 | `RegisterChunkQueryHandler` | `legacy_chunk_query_handler.go` | `main_init.go:484` |
| 8 | `NewDistributionCache` | `legacy_apihandler_agent_distrib.go` | `types.go:71` alias, `main_init.go` (3) |
| 9 | `StartDistributionGC` | `legacy_apihandler_agent_distrib.go` | `types.go:72` alias, `main_init.go` (3) |

Plus structural contamination in `apihandler_agent.go`
(24 MP cases, 4 handler functions, MsgQs sends).

---

## Phase 1: Wrappers + Sig0KeyOwnerName (items 1-5)

**Goal**: Eliminate all 5 wrapper functions + 1 legacy
function. Delete `wrappers.go` from tdns.

### 1a: Export two underlying methods in tdns

Two wrappers call methods that are genuinely core DNS
and should be exported:

| Wrapper | Underlying | Action |
|---------|-----------|--------|
| `ZoneDataCombineWithLocalChanges` | `zd.combineWithLocalChanges()` | Rename to `CombineWithLocalChanges` |
| `ZoneDataSynthesizeCdsRRs` | `zd.synthesizeCdsRRs()` | Rename to `SynthesizeCdsRRs` |

Find and update all internal callers of the unexported
names within tdns. Then tdns-mp calls
`zd.CombineWithLocalChanges()` and
`zd.SynthesizeCdsRRs()` directly.

**Files in tdns**: source files defining the methods
(likely `zone_utils.go` or `rrset_utils.go`), plus
any internal callers. Delete the 2 wrappers from
`wrappers.go`.

**Files in tdns-mp**: `config.go:131` changes from
`tdns.ZoneDataCombineWithLocalChanges(zd)` to
`zd.CombineWithLocalChanges()`. `combiner_chunk.go:319`
changes from `tdns.ZoneDataSynthesizeCdsRRs(zd)` to
`zd.SynthesizeCdsRRs()`. (With MPZoneData, these
calls work via promotion.)

### 1b: Move two MP functions to tdns-mp

Two wrappers call functions that are purely MP:

| Wrapper | Underlying | Action |
|---------|-----------|--------|
| `OurHsyncIdentities` | `ourHsyncIdentities()` | Copy implementation to tdns-mp |
| `ZoneDataMatchHsyncProvider` | `zd.matchHsyncProvider()` | Copy implementation to tdns-mp |

Read the unexported functions in tdns, copy the logic
to tdns-mp (as package-level functions or methods on
`*MPZoneData`). Check for unexported dependencies —
if they reference other unexported tdns symbols, those
either need exporting or the logic needs adaptation.

**Files in tdns**: delete the 2 wrappers from
`wrappers.go`.

**Files in tdns-mp**: new implementations in
`hsync_utils.go` or a new file. Update call sites in
`combiner_chunk.go:175-176`.

### 1c: Also handle remaining wrappers

`wrappers.go` contains 2 additional wrappers not in
the original 9-function list:

- `ZoneDataWeAreASigner` — wraps `zd.weAreASigner()`.
  Check if tdns-mp still calls this. If so, same
  treatment: export or move.
- `CombinerStateSetChunkHandler` — wraps a field
  setter on `CombinerState`. Check if still used.

Both must be resolved before `wrappers.go` can be
deleted.

### 1d: Move Sig0KeyOwnerName to tdns-mp

Pure function — computes
`_sig0key.<zone>._signal.<nameserver>` owner names.
No dependencies beyond `dns.Fqdn()` and string
formatting.

Copy to tdns-mp (e.g. `combiner_utils.go` or
`parentsync_utils.go`). Update 3 call sites. Remove
from `legacy_parentsync_leader.go` in tdns. If this
was the only exported function in that file, rename
to `deadcode_parentsync_leader.go`.

### Phase 1 verification

```
cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make
cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make
```

Grep tdns for `wrappers.go` — should not exist.
Grep tdns-mp for `tdns.ZoneData(Combine|Synthesize|
Match|WeAreA)` and `tdns.OurHsync` and
`tdns.Sig0KeyOwnerName` — should find nothing.

---

## Phase 2: Chunk subsystem (items 6-7)

**Goal**: Move chunk payload store and chunk query
handler from tdns to tdns-mp.

### What moves

Two `legacy_` files in tdns:

**`legacy_chunk_store.go`** (185 lines):
- `ChunkPayloadStore` interface
- `MemChunkPayloadStore` struct + all methods
- `NewMemChunkPayloadStore` constructor

**`legacy_chunk_query_handler.go`**:
- `RegisterChunkQueryHandler` function

### Pre-move analysis

Before copying, check:
1. What does `RegisterChunkQueryHandler` register
   with? (It likely calls `RegisterNotifyHandler`
   which is a core tdns registration framework.)
2. Does the chunk query handler reference unexported
   tdns symbols?
3. Does any non-legacy code in tdns call either
   function? (Expected: none.)

### Migration steps

1. Copy both files to tdns-mp (as `chunk_store.go`
   and `chunk_query_handler.go`)
2. Adapt: change `package tdns` to `package tdnsmp`,
   add `tdns` import prefix where needed
3. Update `main_init.go:482,484` to call local
   versions instead of `tdns.NewMemChunkPayloadStore`
   and `tdns.RegisterChunkQueryHandler`
4. Update `types.go:53` — change `ChunkPayloadStore`
   from alias (`= tdns.ChunkPayloadStore`) to local
   type (or just use the local interface directly)
5. Rename legacy files in tdns to `deadcode_`
6. Remove `ChunkPayloadStore` from tdns
   `config.go:531` (`InternalConf` field) — if no
   non-legacy code references it

### Phase 2 verification

Both repos build. Grep tdns-mp for
`tdns.NewMemChunkPayloadStore`,
`tdns.RegisterChunkQueryHandler`,
`tdns.ChunkPayloadStore` — should find nothing.

---

## Phase 3: Distribution cache (items 8-9)

**Goal**: Move distribution cache from tdns to tdns-mp.

### What moves

From `legacy_apihandler_agent_distrib.go` (1030 lines):
- `DistributionCache` struct
- `DistributionInfo` struct
- `DistributionSummary` struct
- `PeerInfo` struct
- `NewDistributionCache` constructor
- `StartDistributionGC` function
- `APIagentDistrib` handler function (if not already
  in tdns-mp)

### Pre-move analysis

1. Read the full file to inventory all contents
2. Check which parts tdns-mp already has locally in
   `apihandler_agent_distrib.go` (781 lines) — likely
   most of the handler logic is already copied
3. Identify which types/functions are missing from
   tdns-mp's copy
4. Check for non-legacy callers in tdns

### Migration steps

1. Copy missing types and functions to tdns-mp
2. Remove aliases in `types.go:71-72`
   (`NewDistributionCache`, `StartDistributionGC`)
3. Update `main_init.go` call sites (6 total across
   3 role init functions)
4. Remove `DistributionCache` from tdns
   `config.go:533` (`InternalConf` field)
5. Remove route registration for `APIagentDistrib`
   from tdns `apirouters.go:116` (if still there)
6. Rename legacy file in tdns to `deadcode_`

### Phase 3 verification

Both repos build. Grep tdns-mp for
`tdns.NewDistributionCache`,
`tdns.StartDistributionGC`,
`tdns.DistributionCache` — should find nothing.

---

## Phase 4: Gut apihandler_agent.go in tdns

**Goal**: Remove all MP code from
`tdns/v2/apihandler_agent.go`, reducing it from ~1385
to ~200 lines. This also eliminates all MsgQs
references in non-legacy tdns code.

### Preconditions

Phases 2+3 complete (chunk and distribution code
migrated). All MP sub-commands already have working
copies in tdns-mp's `apihandler_agent.go`.

### What stays (4 cases)

`imr-query`, `imr-flush`, `imr-reset`, `imr-show` —
all use only `Globals.ImrEngine.Cache`. Pure DNS.

### What goes

**From `APIagent`** (13 MP cases):
`config`, `update-local-zonedata`, `add-rr`/`del-rr`,
`hsync-agentstatus`, `discover`, `hsync-locate`,
`refresh-keys`, `resync`, `send-rfi`,
`parentsync-status`, `parentsync-election`,
`parentsync-inquire`, `parentsync-bootstrap`

**From `APIagentDebug`** (11 MP cases):
`send-notify`/`send-rfi`, `dump-agentregistry`,
`dump-zonedatarepo`, `show-key-inventory`, `resync`,
`hsync-chunk-send`, `hsync-chunk-recv`,
`hsync-sync-state`, `show-combiner-data`,
`send-sync-to`, `queue-status`

**Standalone handler functions** (4):
`APIbeat`, `APIhello`, `APIsyncPing`, `APImsg` —
all have copies in tdns-mp.

**Helper functions** (2):
`doPeerPing`, `lookupStaticPeer` — check if tdns-mp
needs copies before deleting.

**Route registrations** in `apirouters.go`:
Remove routes for `/beat`, `/hello`, `/ping`, `/msg`
(these endpoints now only exist in tdns-mp).

### Migration steps

1. Check `doPeerPing` and `lookupStaticPeer` — if
   tdns-mp needs them, copy first
2. Remove all MP cases from `APIagent` and
   `APIagentDebug`
3. Remove `APIbeat`, `APIhello`, `APIsyncPing`,
   `APImsg` functions
4. Remove `doPeerPing`, `lookupStaticPeer`
5. Remove route registrations in `apirouters.go`
6. Remove `conf.Internal.MsgQs` creation from
   `main_initfuncs.go:206-222`
7. Remove `MsgQs` struct and associated message types
   from `config.go:558-627`
8. Remove `MsgQs` field from `InternalConf`
   (`config.go:523`)

### Post-removal cleanup

After removal, check for newly unused imports in
`apihandler_agent.go`. The file should be ~200 lines
with only the 4 IMR cases + boilerplate.

### Phase 4 verification

Both repos build. Grep tdns for `MsgQs` — should
only appear in `deadcode_`/`legacy_` files. Grep
for `conf.Internal.MsgQs` — should find nothing.
`apihandler_agent.go` has no references to
`AgentRegistry`, `LeaderElectionManager`,
`MPTransport`, `MsgQs`, or `zd.MP`.

---

## Phase 5: Move ZoneMPExtension to tdns-mp

**Goal**: Move `ZoneMPExtension` and `MPdata` from
tdns to tdns-mp. This is the MPZoneData Phase 2 from
the experiment doc.

### Preconditions

Phases 1-4 complete. The remaining `zd.MP` references
in non-legacy tdns code should be near zero:
- `apihandler_agent.go` — gutted in Phase 4
- `structs.go` — accessor methods (move with the type)
- `parseconfig.go` — one comment (delete)

### Migration steps

1. Define `ZoneMPExtension` and `MPdata` locally in
   tdns-mp (copy from `tdns/v2/structs.go`)
2. Add `MP *ZoneMPExtension` field to `MPZoneData`
3. Move `EnsureMP()` to tdns-mp as method on
   `*MPZoneData`
4. Move accessor methods (`SetLastKeyInventory`,
   `GetLastKeyInventory`, `SetKeystateOK`, etc.)
   to tdns-mp
5. Update tdns-mp: change ~30-40 function signatures
   that access `.MP` from `zd *tdns.ZoneData` to
   `mpzd *MPZoneData`
6. Update callers of those functions (~10-15 sites)
7. Remove from tdns: `MP` field on `ZoneData`,
   `ZoneMPExtension` struct, `MPdata` struct,
   `EnsureMP()` method, accessor methods

### Critical detail: initialization

Today `zd.MP` is initialized via `EnsureMP()` (lazy).
After migration, `MPZoneData.MP` is initialized the
same way — `mpzd.EnsureMP()` creates the extension if
nil. The `OnFirstLoad` callbacks that populate MP
fields continue to work unchanged.

The `MPZones.getOrCreate` lazy cache creates bare
`MPZoneData` objects. Code that accesses `mpzd.MP`
must still call `EnsureMP()` first (or check for nil)
just as today.

### Phase 5 verification

Both repos build. Grep tdns for `ZoneMPExtension`,
`MPdata`, `EnsureMP` — should only appear in
`mptypes.go` (type aliases kept temporarily) or
`deadcode_`/`legacy_` files.

Grep tdns-mp for `tdns.ZoneMPExtension` — should
find nothing (type is now local).

---

## Deferred: Items 6-7

### Item 6: delegation_sync.go restructure

`delegation_sync.go` references `LeaderElectionManager`
(lines 86, 127), `MPTransport` (line 200), and
`getAllAgentsForZone` (line 206). These are deep
integrations — the delegation syncher's behavior
changes fundamentally when running in MP mode.

This needs a **pluggable handler** design: tdns
registers a default handler (single-provider
delegation sync), tdns-mp registers an MP-aware one
with leader election and peer notification. Designing
and implementing this is a separate project.

### Item 7: sign.go / keystore.go DNSKEY state machine

`sign.go` has `OptMultiProvider`/`OptMultiSigner`
gates (lines 243, 363, 374-375) and
`DnskeyStateMpdist`/`DnskeyStateMpremove` references
(line 649). `keystore.go` has similar DNSKEY state
transitions (lines 469, 832, 845-871).

These are embedded in the DNSSEC signing and key
lifecycle engine. Extracting them requires a broader
signing engine refactor — either callback-based
(tdns-mp registers MP-aware state transitions) or
a full engine redesign. Not recommended as standalone
work.

Both items 6 and 7 are low-risk to defer: they don't
block the migration of user-visible MP functionality,
and they represent a small number of MP references
(~10 lines total in non-legacy code) in otherwise
core DNS files.

---

## Phase Order and Dependencies

```
Phase 1 (wrappers + Sig0KeyOwnerName) — no deps
Phase 2 (chunk subsystem)             — no deps on 1
Phase 3 (distribution cache)          — no deps on 1/2
Phase 4 (gut apihandler_agent.go)     — after 2+3
Phase 5 (ZoneMPExtension to tdns-mp)  — after 1-4
```

Phases 1-3 are independent and can be done in any
order. Phase 4 depends on 2+3 so the gutted commands
don't reference deleted functions. Phase 5 depends on
all preceding phases clearing MP references from
non-legacy tdns code.

## Post-migration State

After all 5 phases:
- `wrappers.go` deleted from tdns
- 4 more legacy files renamed to `deadcode_`
- `apihandler_agent.go` reduced to ~200 lines (IMR only)
- `MsgQs` struct and all channel types removed from tdns
- `ZoneMPExtension`, `MPdata`, `EnsureMP` removed from
  tdns
- 5 MP fields removed from `InternalConf`
- tdns-mp has zero MP function calls into tdns
- Only remaining MP in tdns: `sign.go` and `keystore.go`
  DNSKEY state gates (~10 lines) + `delegation_sync.go`
  leader election hooks (4 lines) — deferred
- The 57 MP type aliases in tdns-mp's `types.go` (from
  `mptypes.go`) remain — migrated in a future types-last
  cleanup pass
