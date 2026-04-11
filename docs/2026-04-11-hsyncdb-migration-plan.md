# HsyncDB Migration: db_hsync.go + KeyDB Wrapper

**Date**: 2026-04-11
**Status**: Plan

## Motivation

Two files in `tdns/v2` — `db_hsync.go` (951 lines) and
`db_schema_hsync.go` (461 lines) — are 100% multi-provider
code: peer registry CRUD, sync operation tracking,
confirmation records, transport event logging, and operational
metrics. They should live in tdns-mp.

Additionally, 48 functions across 15 files in tdns-mp accept
`*tdns.KeyDB` as a parameter. Since tdns-mp will define its
own methods on the database (the migrated HSYNC methods), it
needs its own wrapper type. Go does not allow defining methods
on imported types, so we introduce `HsyncDB` embedding
`*tdns.KeyDB`.

### Key finding

`db_hsync.go` has **zero callers** from within tdns — none of
its 26 exported symbols are referenced anywhere in `tdns/v2/`.
The only tdns-internal reference to the HSYNC DB code is one
debug command in `apihandler_agent.go:939` calling
`InitHsyncTables()`, which is defined in `db_schema_hsync.go`
(not `db_hsync.go`). This makes the migration low-risk.

## Design: HsyncDB Wrapper Type

```go
// In tdns-mp/v2/hsyncdb.go
type HsyncDB struct {
    *tdns.KeyDB
}

func NewHsyncDB(kdb *tdns.KeyDB) *HsyncDB {
    if kdb == nil { return nil }
    return &HsyncDB{KeyDB: kdb}
}
```

All migrated HSYNC methods become methods on `*HsyncDB`.
All existing tdns-mp functions that take `*tdns.KeyDB` change
to take `*HsyncDB`. Core tdns methods (key management,
signing, zone operations) remain accessible via the embedded
`*tdns.KeyDB` — Go promotion handles the dispatch.

Where tdns-mp needs to call back into a tdns method that
requires `*tdns.KeyDB`, it extracts `hdb.KeyDB`.

The `HsyncDB` instance is stored in `InternalMpConf` and
initialized once during startup, avoiding repeated wrapping.

## What Moves

### From db_hsync.go (entire file):

**Types** (defined locally in tdns-mp):
- `PeerRecord`, `SyncOperationRecord`,
  `SyncConfirmationRecord`, `ConfirmationItem`

**17 methods** (receiver: `*HsyncDB`):
- Peer CRUD: `SavePeer`, `GetPeer`, `ListPeers`,
  `UpdatePeerState`, `UpdatePeerContact`,
  `IncrementPeerFailedContacts`
- Sync ops: `SaveSyncOperation`,
  `UpdateSyncOperationStatus`,
  `MarkSyncOperationConfirmed`, `GetSyncOperation`,
  `ListSyncOperations`
- Confirmations: `SaveSyncConfirmation`,
  `ListSyncConfirmations`
- Events/metrics: `LogTransportEvent`,
  `ListTransportEvents`, `GetAggregatedMetrics`,
  `RecordMetrics`

**5 standalone functions**:
- `PeerRecordFromAgent`, `PeerRecordFromTransportPeer`
- `PeerRecordToInfo`, `SyncOpRecordToInfo`,
  `ConfirmRecordToInfo`

**5 private helpers** (only used within this file):
- `boolToInt`, `nullableUnix`, `unixToTime`,
  `agentStateToString` (imports `tdns.AgentState`),
  `peerStateToString` (imports `transport.PeerState`)

### From db_schema_hsync.go (entire file):

- `HsyncTables` map, `HsyncIndexes` slice
- `InitHsyncTables()` — receiver `*HsyncDB`
- `InitCombinerEditTables()` — receiver `*HsyncDB`
- `migrateHsyncSchema()` — receiver `*HsyncDB`
- `CleanupExpiredHsyncData()` — receiver `*HsyncDB`
- `dbColumnExists()`, `validTableName()` — copied as
  private helpers from `tdns/v2/db.go` (tiny, no need to
  export from tdns)

### Superseded file

`tdns-mp/v2/combiner_db_schema.go` (existing local copy of
`InitCombinerEditTables`) is deleted — subsumed by the
migrated `db_schema_hsync.go`.

## 48 Functions Changing `*tdns.KeyDB` → `*HsyncDB`

| File | # | Functions |
|------|---|-----------|
| db_combiner_edits.go | 13 | NextEditID, SavePendingEdit, ListPendingEdits, GetPendingEdit, ApprovePendingEdit, RejectPendingEdit, ResolvePendingEdit, ListRejectedEdits, ListApprovedEdits, ClearPendingEdits, ClearApprovedEdits, ClearRejectedEdits, ClearContributions |
| signer_keydb.go | 7 | GetDnssecKeysByState, UpdateDnssecKeyState, GenerateAndStageKey, GetKeyInventory, SetPropagationConfirmed, TransitionMpdistToPublished, TransitionMpremoveToRemoved |
| key_state_worker.go | 5 | checkAndTransitionKeys, transitionPublishedToStandby, transitionRetiredToRemoved, maintainStandbyKeys, maintainStandbyKeysForType |
| combiner_chunk.go | 5 | CombinerProcessUpdate, combinerApplyPublishInstruction, combinerResyncSignalKeys, buildPendingSignalKeys, ApplyPendingSignalKeys |
| db_combiner_publish_instructions.go | 4 | SavePublishInstruction, GetPublishInstruction, DeletePublishInstruction, LoadAllPublishInstructions |
| db_combiner_contributions.go | 3 | SaveContributions, LoadAllContributions, DeleteContributions |
| agent_setup.go | 2 | AgentSig0KeyPrep, AgentJWKKeyPrep |
| parentsync_leader.go | 2 | importSig0KeyFromPeer, GetParentSyncStatus |
| combiner_db_schema.go | 1 | InitCombinerEditTables (deleted in Phase 1) |
| apihandler_agent.go | 1 | APIagent |
| apihandler_agent_hsync.go | 1 | APIagentHsync |
| apihandler_combiner.go | 1 | APIcombiner |
| combiner_utils.go | 1 | CombinerReapplyContributions |
| parentsync_utils.go | 1 | queryParentKeyStateDetailed |

## Entry Points

### conf.Config.Internal.KeyDB (17 sites)

After migration, these read `conf.InternalMp.HsyncDB` instead:

- main_init.go (lines 269, 446)
- start_agent.go (39)
- key_state_worker.go (65)
- combiner_msg_handler.go (130)
- signer_msg_handler.go (96, 174)
- apihandler_agent_routes.go (13)
- apihandler_combiner_routes.go (22)
- apihandler_signer_routes.go (24)
- apihandler_combiner.go (112)
- apihandler_agent.go (768, 773)
- agent_setup.go (42, 48, 71)
- config.go (82)

### zd.KeyDB (wrap at call site)

- config.go:112-113 — `NewHsyncDB(zd.KeyDB)`
- agent_setup.go:191,198 — `NewHsyncDB(zd.KeyDB)`
- hsyncengine.go:586,589 — nil check stays on `zd.KeyDB`;
  line 589 calls `zd.KeyDB.GetSig0KeyRaw()` (tdns method,
  no change)

## Implementation Phases

### Phase 1: HsyncDB type + schema migration (tdns-mp only)

- Create `hsyncdb.go` (type definition)
- Create `db_schema_hsync.go` (tables, indexes, init funcs)
- Delete `combiner_db_schema.go`
- Update callers of InitHsyncTables / InitCombinerEditTables
- Add `HsyncDB` field to `InternalMpConf`, init in
  `main_init.go`

### Phase 2: Migrate db_hsync.go (tdns-mp only)

- Create `db_hsync.go` (types, methods on *HsyncDB,
  functions, helpers)
- Update `apihandler_agent_hsync.go` to use *HsyncDB
- Update `apihandler_agent_routes.go` to construct HsyncDB

### Phase 3: Convert 47 signatures (tdns-mp only)

- Change all `kdb *tdns.KeyDB` params to `hdb *HsyncDB`
- Update all entry points to pass `conf.InternalMp.HsyncDB`
  or `NewHsyncDB(zd.KeyDB)`
- Where calling back into tdns, extract `hdb.KeyDB`

### Phase 4: Remove from tdns

- Remove `case "hsync-init-db"` from
  `tdns/v2/apihandler_agent.go`
- Delete `tdns/v2/db_hsync.go`
- Delete `tdns/v2/db_schema_hsync.go`
- Verify tdns builds clean

### Phase 5: Move types (future)

The 5 display types (HsyncPeerInfo, HsyncSyncOpInfo, etc.)
in `mptypes.go` move to tdns-mp when no tdns code references
them. This is part of the broader mptypes.go migration.

## Locking Pattern

`db_hsync.go` in tdns uses the unexported `kdb.mu.Lock()`.
tdns-mp's existing DB files already use the exported
`kdb.Lock()` / `kdb.Unlock()` (defined in
`tdns/v2/structs.go:673-674`). The migrated code follows the
tdns-mp convention: `hdb.Lock()` / `hdb.Unlock()`.

## Verification

After each phase, both repos must build:
```
cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make
cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make
```

After Phase 4:
- grep tdns/v2/ for `db_hsync`, `HsyncTables`,
  `InitHsyncTables` — should find nothing
- grep tdns-mp/v2/ for `*tdns.KeyDB` in function params —
  should only remain where calling back into tdns methods

## Review Notes (2026-04-11)

Plan verified against codebase. Corrections applied:

1. **Function count**: 48 across 15 files (was 47/14).
   `combiner_db_schema.go:InitCombinerEditTables` was
   uncounted (deleted in Phase 1 anyway).
2. **Entry points**: 17 sites (was 13). Missed
   `agent_setup.go` (3 sites: lines 42, 48, 71) and
   `apihandler_agent.go:773`.
3. **Helper source**: `dbColumnExists` and `validTableName`
   are defined in `tdns/v2/db.go`, not `db_schema_hsync.go`
   (they are called from there but defined in `db.go`).
4. **Zero-caller claim**: Confirmed. All 26 exported symbols
   in `db_hsync.go` have zero references in `tdns/v2/`.
   The `apihandler_agent.go:939` reference is to
   `InitHsyncTables` in `db_schema_hsync.go`.
5. **Locking**: Confirmed. Migrated code converts
   `kdb.mu.Lock()` → `hdb.Lock()` (exported wrappers in
   `structs.go:673-674`).
6. **Startup ordering**: Safe. KeyDB is fully initialized
   (including channels) before `initMPAgent` runs.
   `InternalMpConf` is a value type — never nil.
7. **Risk**: Low. Phase 3 (48 signature changes) is the
   largest blast radius but all errors are compile-time.
