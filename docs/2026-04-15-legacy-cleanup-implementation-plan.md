# Legacy Cleanup Implementation Plan

**Date**: 2026-04-15
**Companion to**: `2026-04-15-legacy-dependency-analysis.md`
**Purpose**: Step-by-step executable plan for removing every
remaining cross-repo coupling between tdns-mp/v2 and tdns/v2,
culminating in **(1)** deleting `legacy_*.go` from tdns/v2 once
nothing needs them, and **(2)** shrinking or removing
`mptypes.go` / `mpmethods.go` only **after** their non-legacy
contents have been relocated (those files are not legacy-only;
see Phase 10).

## How to use this doc

Phases are ordered by dependency: earlier phases must complete
before later phases compile. Inside each phase, the "Action"
blocks give exact file:line edits. Every action ends with a
verification step (grep / `gofmt -w` / build).

**Build command** (run after each phase and whenever the plan
says to build):

```
cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make
cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make
```

**Grep discipline**: the file:line numbers in this plan were
captured on 2026-04-15. If earlier phases shift line numbers,
re-grep before applying a later phase.

## Phase overview

| Phase | Scope | Character |
|---|---|---|
| 0 | Delete dead in-process combiner helper (`xxxSendToCombiner`) | Investigation |
| 1 | Real blocker: localize `CombinerState` + `ProcessUpdate` | **Non-mechanical** |
| 2 | Flip the 4 signature-mate aliases (`CombinerSync*`, `RejectedItem`) | Mechanical |
| 3 | Handler-surface sweep (`CombinerDebug*`, `Transaction*`) | Mechanical |
| 4 | Hsync DB status sweep | Mechanical |
| 5 | SDE queue sweep (`SyncRequest`, `HsyncStatus`, `DnskeyStatus`) | Mechanical |
| 6 | Agent / zone sweep (`Agent`, `AgentMgmt*`, `ZoneUpdate`, `OwnerData`, `AgentId`, `ZoneName`, …) | Mechanical, widest |
| 7 | Delete unused aliases | Mechanical |
| 8 | Flip all alias declarations to local types | Mechanical |
| 9 | Remove `tdns.Conf.MultiProvider` access | Small design choice |
| 10 | tdns/v2: delete `legacy_*.go`; split/move then trim `mpmethods.go` / `mptypes.go` | Cleanup |

---

# Phase 0 — Delete dead in-process combiner helper path

**Confirmed dead** (2026-04-15): the helper in tdns-mp was renamed
(e.g. to `xxxSendToCombiner`) to prove it has **zero callers** in
tdns-mp; the build stayed green. **Keep the verification greps in
sync with the actual function name** in `combiner_chunk.go`.

**Rationale (corrected)**: that helper calls
`state.ProcessUpdate(tdnsReq, nil, nil, nil)` on `*tdns.CombinerState`,
which delegates to **tdns**'s `CombinerProcessUpdate` in
`legacy_combiner_chunk.go` with `kdb == nil`. In the current tdns
code, `combinerApplyPublishInstruction` and `combinerResyncSignalKeys`
**guard on `kdb != nil`** — they do **not** dereference nil and
panic. The path is still **undesirable** (publish/DB persistence and
signal-key resync are skipped when `kdb` is nil), so it should be
**removed**, not preserved — but the old "nil would panic" claim
was inaccurate.

### Actions

1. **Delete the dead helper** (currently `xxxSendToCombiner`; the
   comment above it may still say `SendToCombiner`) from
   `tdns-mp/v2/combiner_chunk.go` — confirm the exact line range at
   edit time (roughly the block ending before
   `ConvertZoneUpdateToSyncRequest`).
2. **Check `ConvertZoneUpdateToSyncRequest`** — grep for other callers:
   ```
   grep -rn 'ConvertZoneUpdateToSyncRequest' tdns-mp/v2/ tdns/v2/
   ```
   If the only use in tdns-mp was the deleted helper (typical:
   **no other tdns-mp callers**), delete `ConvertZoneUpdateToSyncRequest`
   too. Otherwise leave it.
3. **Check `determineSyncType`** — same pattern. If only used by
   `ConvertZoneUpdateToSyncRequest`, delete together.

### Verification

```
grep -rn 'xxxSendToCombiner\|SendToCombiner' tdns-mp/v2/ tdns/v2/
```

Zero matches in tdns-mp for the dead helper name; `SendToCombiner`
may still exist in **tdns/v2** until Phase 10 deletes legacy files
(that is OK for this phase). Then:

```
gofmt -w tdns-mp/v2/combiner_chunk.go
cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make
```

Build succeeds.

### Pre-commit checkpoint

Commit: "Delete dead in-process combiner helper (SendToCombiner path)".
This simplifies Phase 1 — it becomes a pure type migration with no
behavioral component tied to that helper, since tdns-mp no longer
calls `ProcessUpdate` on `*tdns.CombinerState` for that path.

---

# Phase 1 — Localize `CombinerState` + `ProcessUpdate`

This is the one real cross-repo blocker identified in the
analysis doc Part I §1. Everything else in the plan is
mechanical.

## 1.1 Starting state (facts to verify before editing)

Verified via direct inspection:

- `CombinerState` struct is defined in `tdns/v2/mptypes.go:694-706`.
- Methods on `*CombinerState` in `tdns/v2/legacy_combiner_chunk.go`
  (line numbers drift — re-grep):
  - `ChunkHandler()`
  - `ProcessUpdate(req, localAgents, kdb, tm)` — delegates to **tdns**
    `CombinerProcessUpdate` with `*KeyDB` (third arg is `kdb *KeyDB`).
  - `SetRouter` / `SetSecureWrapper` / `SetGetPeerAddress`
- **Do not copy the tdns `ProcessUpdate` signature into tdns-mp.**
  tdns-mp's standalone `CombinerProcessUpdate` in
  `combiner_chunk.go` takes **`hdb *HsyncDB`**, not `*KeyDB`.
  The localized `CombinerState.ProcessUpdate` must match **that**
  function:
  ```go
  func (cs *CombinerState) ProcessUpdate(req *CombinerSyncRequest,
      localAgents map[string]bool, hdb *HsyncDB, tm *MPTransportBridge) *CombinerSyncResponse {
      return CombinerProcessUpdate(req, cs.ProtectedNamespaces, localAgents, hdb, tm)
  }
  ```
- There are **two** `CombinerProcessUpdate` symbols today: one in
  **tdns** (`legacy_combiner_chunk.go`, `*KeyDB`) and one in **tdns-mp**
  (`combiner_chunk.go`, `*HsyncDB`). Only the tdns-mp definition is on
  the active path (`combiner_msg_handler.go`, `apihandler_combiner.go`).
  After Phase 0, nothing in tdns-mp should call `state.ProcessUpdate` on
  `*tdns.CombinerState`.
- `CombinerState` instances are constructed in:
  - `tdns-mp/v2/main_init.go:443`
  - `tdns-mp/v2/combiner_chunk.go:1367`
  - `tdns-mp/v2/signer_chunk_handler.go:24`
  - all three write `&tdns.CombinerState{...}`.

### Verification step (run before any edits)

```
grep -n 'CombinerProcessUpdate' tdns-mp/v2/*.go
grep -n 'func CombinerProcessUpdate' tdns-mp/v2/combiner_chunk.go
grep -n '^func (.*CombinerState)' tdns-mp/v2/*.go tdns/v2/legacy_combiner_chunk.go
```

Confirm:
1. `CombinerProcessUpdate` is defined in tdns-mp.
2. Its signature takes `*CombinerSyncRequest` (local alias) —
   NOT `*tdns.CombinerSyncRequest`.
3. All 5 `*CombinerState` methods are in tdns/v2 only.

If any of these assumptions fail, pause and amend the plan.

## 1.2 Copy `CombinerState` + helpers into tdns-mp

### Action 1.2.1 — Copy the struct

Add to `tdns-mp/v2/combiner_chunk.go`, near the top of the
file (after imports):

```go
// CombinerState holds combiner-specific state that outlives
// individual CHUNK messages. Used by CLI error-journal queries
// and by CombinerProcessUpdate. Transport routing is handled by
// the unified ChunkNotifyHandler.
type CombinerState struct {
    // ErrorJournal records errors during CHUNK NOTIFY processing
    // for operational diagnostics. If nil, errors are only logged.
    ErrorJournal *ErrorJournal

    // ProtectedNamespaces: domain suffixes belonging to this
    // provider. NS records from remote agents whose targets fall
    // within these namespaces are rejected.
    ProtectedNamespaces []string

    // ChunkNotifyHandler is the underlying transport wiring.
    // Access via SetRouter / SetGetPeerAddress / SetSecureWrapper.
    ChunkNotifyHandler *transport.ChunkNotifyHandler
}
```

**Note on `ErrorJournal`**: it is defined in **`tdns/v2/error_journal.go`**
(`ErrorJournal`, `ErrorJournalEntry`, `NewErrorJournal`, methods).
tdns-mp still uses **`tdns.ErrorJournal`** / **`tdns.NewErrorJournal`**
at construction and in handlers — **localize in the same phase** as
`CombinerState`: copy the types + constructor + methods into tdns-mp
(e.g. a new `error_journal.go` next to `combiner_chunk.go`, or adjacent
in the file you prefer), then drop `tdns.` qualifiers at call sites.
Re-grep: `grep -rn 'tdns\.ErrorJournal\|tdns\.NewErrorJournal\|tdns\.ErrorJournalEntry' tdns-mp/v2/`.

### Action 1.2.2 — Copy the 5 methods

Add to `tdns-mp/v2/combiner_chunk.go`:

```go
func (cs *CombinerState) ChunkHandler() *transport.ChunkNotifyHandler {
    return cs.ChunkNotifyHandler
}

func (cs *CombinerState) ProcessUpdate(req *CombinerSyncRequest,
    localAgents map[string]bool, hdb *HsyncDB, tm *MPTransportBridge) *CombinerSyncResponse {
    return CombinerProcessUpdate(req, cs.ProtectedNamespaces, localAgents, hdb, tm)
}

func (cs *CombinerState) SetRouter(router *transport.DNSMessageRouter) {
    cs.ChunkNotifyHandler.Router = router
}

func (cs *CombinerState) SetSecureWrapper(sw *transport.SecurePayloadWrapper) {
    cs.ChunkNotifyHandler.SecureWrapper = sw
}

func (cs *CombinerState) SetGetPeerAddress(fn func(senderID string) (address string, ok bool)) {
    cs.ChunkNotifyHandler.GetPeerAddress = fn
}
```

**Important**: the `ProcessUpdate` body references
`CombinerSyncRequest` and `CombinerSyncResponse` unqualified —
those are still aliases to tdns types at this point. Phase 2
flips the aliases. Keep this in mind: after Phase 1 the code
still compiles because the aliases are still in place and
point at the tdns struct layout that matches the local one.

### Action 1.2.3 — Update construction sites and return types

Replace `&tdns.CombinerState{...}` with `&CombinerState{...}`:

| file | line | old | new |
|---|---|---|---|
| `tdns-mp/v2/main_init.go` | (grep) | `conf.InternalMp.CombinerState = &tdns.CombinerState{` | `conf.InternalMp.CombinerState = &CombinerState{` |
| `tdns-mp/v2/combiner_chunk.go` | (grep) | `state := &tdns.CombinerState{` | `state := &CombinerState{` |
| `tdns-mp/v2/signer_chunk_handler.go` | (grep) | `state := &tdns.CombinerState{` | `state := &CombinerState{` |

Also update **`RegisterCombinerChunkHandler`** and
**`RegisterSignerChunkHandler`** (same file as signer) so their
return type is **`(*CombinerState, error)`** instead of
`**(*tdns.CombinerState, error)`**, and fix every caller that
assigned the result (re-grep `RegisterCombinerChunkHandler` /
`RegisterSignerChunkHandler`).

### Action 1.2.4 — Confirm `InternalMp.CombinerState` field type

The field is already spelled **`CombinerState *CombinerState`** while
the alias exists (resolved to tdns). After deleting the alias
(Action 1.2.5), it must still be **`*CombinerState`** pointing at the
**new local struct**. If grep shows a literal `*tdns.CombinerState`,
replace it; otherwise no edit beyond removing the alias.

### Action 1.2.5 — Delete the alias

Remove `tdns-mp/v2/types.go:65`:

```
type CombinerState = tdns.CombinerState
```

(leave the surrounding section otherwise untouched).

### Verification

```
grep -rn 'tdns\.CombinerState' tdns-mp/v2/
```

Must return zero matches. Then:

```
gofmt -w tdns-mp/v2/combiner_chunk.go tdns-mp/v2/main_init.go \
         tdns-mp/v2/signer_chunk_handler.go tdns-mp/v2/config.go \
         tdns-mp/v2/types.go
```

Then build. If the build fails because `tdns/v2/legacy_combiner_chunk.go`
no longer compiles (because nothing references its methods), that
is fine — we will delete that file in Phase 10. For the duration
of Phase 1 the tdns/v2 build is expected to stay green because
its own internal references to `*CombinerState` still resolve to
the tdns/v2 struct.

### Pre-commit checkpoint

Commit: "Localize CombinerState and its methods into tdns-mp".

---

# Phase 2 — Flip the 4 signature-mate aliases

With Phase 1 complete, `CombinerSyncRequest`,
`CombinerSyncResponse`, and `RejectedItem` are no longer bound
by `ProcessUpdate`'s signature to tdns types. Copy the struct
definitions locally and flip the aliases.

### Action 2.1 — Copy the three struct definitions

From `tdns/v2/mptypes.go` into `tdns-mp/v2/types.go` (replace
the alias lines 36-38):

```go
type CombinerSyncRequest struct {
    SenderID       string
    DeliveredBy    string
    Zone           string
    ZoneClass      string
    SyncType       string
    Records        map[string][]string
    Operations     []core.RROperation
    Publish        *core.PublishInstruction
    Serial         uint32
    DistributionID string
    Timestamp      time.Time
}

type CombinerSyncResponse struct {
    DistributionID string
    Zone           string
    Nonce          string
    Status         string
    Message        string
    AppliedRecords []string
    RemovedRecords []string
    RejectedItems  []RejectedItem
    IgnoredRecords []string
    Timestamp      time.Time
    DataChanged    bool
}

type RejectedItem struct {
    Record string
    Reason string
}
```

### Action 2.2 — Clean up any leftover `tdnsReq`/`tdnsResp` conversion

Phase 0 should have **deleted** the dead helper that contained the
manual struct copy. If any similar conversion block remains elsewhere
after Phase 0, with local structs identical to the old alias targets,
replace it with direct use of `req` / `resp` and delete stale comments
about "Convert local ... to tdns...".

### Action 2.3 — Delete aliases

Remove `tdns-mp/v2/types.go:36,37,38`:

```
type CombinerSyncRequest  = tdns.CombinerSyncRequest
type CombinerSyncResponse = tdns.CombinerSyncResponse
type RejectedItem         = tdns.RejectedItem
```

### Verification

```
grep -rn 'tdns\.CombinerSyncRequest\|tdns\.CombinerSyncResponse\|tdns\.RejectedItem' tdns-mp/v2/
```

Zero matches. `gofmt -w`. Build.

### Pre-commit checkpoint

Commit: "Localize CombinerSync{Request,Response} and RejectedItem".

---

# Phase 3 — Handler-surface sweep

Pure qualifier cleanup. Both CLI client and daemon handler
live in tdns-mp.

### Action 3.1 — CombinerDebugPost / CombinerDebugResponse

| file | line | old | new |
|---|---|---|---|
| `tdns-mp/v2/apihandler_combiner_mp.go` | 21 | `var req tdns.CombinerDebugPost` | `var req CombinerDebugPost` |
| `tdns-mp/v2/apihandler_combiner_mp.go` | 31 | `resp := tdns.CombinerDebugResponse{` | `resp := CombinerDebugResponse{` |
| `tdns-mp/v2/apihandler_signer.go` | 20 | `var req tdns.CombinerDebugPost` | `var req CombinerDebugPost` |
| `tdns-mp/v2/apihandler_signer.go` | 30 | `resp := tdns.CombinerDebugResponse{` | `resp := CombinerDebugResponse{` |

### Action 3.2 — TransactionPost / Response / ErrorSummary

| file | line | old | new |
|---|---|---|---|
| `tdns-mp/v2/apihandler_combiner_routes.go` | 41 | `var req tdns.TransactionPost` | `var req TransactionPost` |
| `tdns-mp/v2/apihandler_combiner_routes.go` | 51 | `resp := tdns.TransactionResponse{` | `resp := TransactionResponse{` |
| `tdns-mp/v2/apihandler_combiner_routes.go` | 83 | `var errors []*tdns.TransactionErrorSummary` | `var errors []*TransactionErrorSummary` |
| `tdns-mp/v2/apihandler_combiner_routes.go` | 85 | `errors = append(errors, &tdns.TransactionErrorSummary{` | `errors = append(errors, &TransactionErrorSummary{` |
| `tdns-mp/v2/apihandler_combiner_routes.go` | 111 | `resp.ErrorDetail = &tdns.TransactionErrorSummary{` | `resp.ErrorDetail = &TransactionErrorSummary{` |

### Verification

```
grep -n 'tdns\.CombinerDebug\|tdns\.Transaction' tdns-mp/v2/
```

Zero matches. `gofmt -w` the affected files. Build.

### Pre-commit checkpoint

Commit: "Drop tdns. qualifier from handler surface types".

---

# Phase 4 — Hsync DB status sweep

All call sites live in `tdns-mp/v2/db_hsync.go` and the alias
declarations in `tdns-mp/v2/agent_structs.go`.

### Action 4.1

| file | line | old | new |
|---|---|---|---|
| `db_hsync.go` | 634 | `func PeerRecordToInfo(peer *PeerRecord) *tdns.HsyncPeerInfo {` | `func PeerRecordToInfo(peer *PeerRecord) *HsyncPeerInfo {` |
| `db_hsync.go` | 635 | `return &tdns.HsyncPeerInfo{` | `return &HsyncPeerInfo{` |
| `db_hsync.go` | 659 | `func SyncOpRecordToInfo(op *SyncOperationRecord) *tdns.HsyncSyncOpInfo {` | `func SyncOpRecordToInfo(op *SyncOperationRecord) *HsyncSyncOpInfo {` |
| `db_hsync.go` | 660 | `return &tdns.HsyncSyncOpInfo{` | `return &HsyncSyncOpInfo{` |
| `db_hsync.go` | 679 | `func ConfirmRecordToInfo(c *SyncConfirmationRecord) *tdns.HsyncConfirmationInfo {` | `func ConfirmRecordToInfo(c *SyncConfirmationRecord) *HsyncConfirmationInfo {` |
| `db_hsync.go` | 680 | `return &tdns.HsyncConfirmationInfo{` | `return &HsyncConfirmationInfo{` |
| `db_hsync.go` | 829 | `func (hdb *HsyncDB) ListTransportEvents(peerID string, limit int) ([]*tdns.HsyncTransportEvent, error)` | `func (hdb *HsyncDB) ListTransportEvents(peerID string, limit int) ([]*HsyncTransportEvent, error)` |
| `db_hsync.go` | 861 | `var events []*tdns.HsyncTransportEvent` | `var events []*HsyncTransportEvent` |
| `db_hsync.go` | 863 | `evt := &tdns.HsyncTransportEvent{}` | `evt := &HsyncTransportEvent{}` |
| `db_hsync.go` | 885 | `func (hdb *HsyncDB) GetAggregatedMetrics() (*tdns.HsyncMetricsInfo, error)` | `func (hdb *HsyncDB) GetAggregatedMetrics() (*HsyncMetricsInfo, error)` |
| `db_hsync.go` | 889 | `metrics := &tdns.HsyncMetricsInfo{}` | `metrics := &HsyncMetricsInfo{}` |
| `db_hsync.go` | 925 | `func (hdb *HsyncDB) RecordMetrics(peerID, zoneName string, metrics *tdns.HsyncMetricsInfo)` | `func (hdb *HsyncDB) RecordMetrics(peerID, zoneName string, metrics *HsyncMetricsInfo)` |

### Verification

```
grep -n 'tdns\.Hsync\(Peer\|SyncOp\|Confirmation\|Transport\|Metrics\)' tdns-mp/v2/
```

Zero matches. `gofmt -w db_hsync.go`. Build.

### Pre-commit checkpoint

Commit: "Drop tdns. qualifier from Hsync DB status types".

---

# Phase 5 — SDE queue sweep

### Action 5.1 — tdns.SyncRequest

| file | line | old | new |
|---|---|---|---|
| `hsync_utils.go` | 1175 | `mpzd.SyncQ <- tdns.SyncRequest{` | `mpzd.SyncQ <- SyncRequest{` |
| `hsync_utils.go` | 1192 | `mpzd.SyncQ <- tdns.SyncRequest{` | `mpzd.SyncQ <- SyncRequest{` |
| `apihandler_agent.go` | 361 | `zd.SyncQ <- tdns.SyncRequest{` | `zd.SyncQ <- SyncRequest{` |

### Action 5.2 — tdns.HsyncStatus

| file | line | old | new |
|---|---|---|---|
| `hsync_utils.go` | 22 | `func HsyncChanged(zd, newzd *tdns.ZoneData) (bool, *tdns.HsyncStatus, error)` | `func HsyncChanged(zd, newzd *tdns.ZoneData) (bool, *HsyncStatus, error)` |
| `hsync_utils.go` | 23 | `var hss = tdns.HsyncStatus{` | `var hss = HsyncStatus{` |

### Action 5.3 — tdns.DnskeyStatus

| file | line | old | new |
|---|---|---|---|
| `hsync_utils.go` | 85 | `func (mpzd *MPZoneData) LocalDnskeysChanged(new_zd *tdns.ZoneData) (bool, *tdns.DnskeyStatus, error)` | `func (mpzd *MPZoneData) LocalDnskeysChanged(new_zd *tdns.ZoneData) (bool, *DnskeyStatus, error)` |
| `hsync_utils.go` | 86 | `ds := &tdns.DnskeyStatus{` | `ds := &DnskeyStatus{` |
| `hsync_utils.go` | 159 | `func (mpzd *MPZoneData) LocalDnskeysFromKeystate() (bool, *tdns.DnskeyStatus, error)` | `func (mpzd *MPZoneData) LocalDnskeysFromKeystate() (bool, *DnskeyStatus, error)` |
| `hsync_utils.go` | 164 | `ds := &tdns.DnskeyStatus{` | `ds := &DnskeyStatus{` |
| `hsync_utils.go` | 185 | `ds := &tdns.DnskeyStatus{` | `ds := &DnskeyStatus{` |

### Verification

```
grep -n 'tdns\.\(SyncRequest\|SyncResponse\|SyncStatus\|HsyncStatus\|DnskeyStatus\)' tdns-mp/v2/
```

Zero matches. `gofmt -w hsync_utils.go apihandler_agent.go`. Build.

### Pre-commit checkpoint

Commit: "Drop tdns. qualifier from SDE queue types".

### Note on `sde_types.go` header comments

`sde_types.go` may still say `SyncRequest` **must** stay an alias because
`SyncQ` was shared with tdns on `ZoneData`. **`SyncQ` now lives on
`MPZoneData`** (`mpzonedata.go`, `main_init.go`). When you flip aliases
in Phase 8.3, **update or remove that stale comment** so future readers
are not misled.

---

# Phase 6 — Agent / zone sweep

Largest sweep by volume. Do it in three sub-phases so the
commits stay reviewable.

## 6a — `tdns.AgentId` + `tdns.ZoneName`

These are pervasive (50+ sites between v2/ and v2/cli/). Both
are simple `type X = tdns.X` aliases, zero cross-module
binding. Use the `sed`-style approach below rather than a
file:line table — the sheer count makes a table impractical.

### Action 6a.1

Run, from `tdns-mp/v2/`:

```
grep -rln 'tdns\.AgentId\|tdns\.ZoneName' .
```

For each file in the list, replace:
- `tdns.AgentId(` → `AgentId(`
- `tdns.AgentId` → `AgentId` (when used as type, not conversion)
- `tdns.ZoneName(` → `ZoneName(`
- `tdns.ZoneName` → `ZoneName`

**Important**: the CLI file `tdns-mp/v2/cli/hsync_cmds.go:352`
writes `tdns.Globals.AgentId = tdns.AgentId(...)`. The LHS
stays untouched (it references `tdns.Globals`, a config global,
not the type alias). Only the RHS conversion changes. Same
pattern anywhere else — do not touch `tdns.Globals.*`.

### Verification

```
grep -rn 'tdns\.AgentId\|tdns\.ZoneName' tdns-mp/v2/
```

Only `tdns.Globals.AgentId`-style hits should remain. Build.

### Pre-commit checkpoint

Commit: "Drop tdns. qualifier from AgentId and ZoneName".

## 6b — `tdns.ZoneUpdate` + `tdns.OwnerData`

### Action 6b.1 — ZoneUpdate

| file | line | old | new |
|---|---|---|---|
| `start_agent.go` | 297 | `zu := &tdns.ZoneUpdate{` | `zu := &ZoneUpdate{` |
| `start_agent.go` | 316 | `agentUpdate := &tdns.ZoneUpdate{` | `agentUpdate := &ZoneUpdate{` |
| `combiner_chunk.go` | (grep) | `func ConvertZoneUpdateToSyncRequest(update *tdns.ZoneUpdate, ...` | `func ConvertZoneUpdateToSyncRequest(update *ZoneUpdate, ...` |
| `combiner_chunk.go` | (grep) | `func determineSyncType(update *tdns.ZoneUpdate) string {` | `func determineSyncType(update *ZoneUpdate) string {` |
| `hsync_transport.go` | 1719 | `update, ok := msg.Payload.(*tdns.ZoneUpdate)` | `update, ok := msg.Payload.(*ZoneUpdate)` |
| `hsync_transport.go` | 1798 | `func (tm *MPTransportBridge) EnqueueForCombiner(zone tdns.ZoneName, update *tdns.ZoneUpdate) ...` | `func (tm *MPTransportBridge) EnqueueForCombiner(zone ZoneName, update *ZoneUpdate) ...` |
| `hsync_transport.go` | 1823 | (same pattern) EnqueueForZoneAgents | (strip `tdns.`) |
| `hsync_transport.go` | 1859 | (same pattern) EnqueueForSpecificAgent | (strip `tdns.`) |

Skip the two `combiner_chunk.go` rows if Phase 0 already removed
`ConvertZoneUpdateToSyncRequest` and `determineSyncType`.

Also the struct field at `hsync_transport.go:1982` (`Zone tdns.ZoneName`)
and any other `tdns.ZoneName` occurrences in that file — covered
by phase 6a but worth spot-checking.

### Action 6b.2 — OwnerData

| file | line | old | new |
|---|---|---|---|
| `combiner_utils.go` | 144 | `existingOwnerData = tdns.OwnerData{` | `existingOwnerData = OwnerData{` |
| `combiner_utils.go` | 186 | `mpzd.MP.CombinerData = core.NewCmap[tdns.OwnerData]()` | `mpzd.MP.CombinerData = core.NewCmap[OwnerData]()` |
| `combiner_utils.go` | 659 | same | same |
| `combiner_utils.go` | 720 | `ownerData = tdns.OwnerData{` | `ownerData = OwnerData{` |
| `combiner_utils.go` | 944 | same pattern | same |
| `combiner_utils.go` | 969 | same pattern | same |
| `combiner_utils.go` | 972 | `ownerData := tdns.OwnerData{` | `ownerData := OwnerData{` |
| `hsync_utils.go` | 974 | `mpzd.MP.UpstreamData = core.NewCmap[tdns.OwnerData]()` | `mpzd.MP.UpstreamData = core.NewCmap[OwnerData]()` |
| `hsync_utils.go` | 978 | `snapshotOd := tdns.OwnerData{` | `snapshotOd := OwnerData{` |
| `mp_extension.go` | 25 | `CombinerData *core.ConcurrentMap[string, tdns.OwnerData]` | `CombinerData *core.ConcurrentMap[string, OwnerData]` |
| `mp_extension.go` | 26 | `UpstreamData *core.ConcurrentMap[string, tdns.OwnerData]` | `UpstreamData *core.ConcurrentMap[string, OwnerData]` |

### Verification

```
grep -n 'tdns\.ZoneUpdate\|tdns\.OwnerData' tdns-mp/v2/
```

Zero matches. `gofmt -w` the affected files. Build.

### Pre-commit checkpoint

Commit: "Drop tdns. qualifier from ZoneUpdate and OwnerData".

## 6c — `tdns.Agent`, `tdns.AgentDetails`, `tdns.AgentState`, `tdns.AgentStateToString`, `tdns.AgentMsg*`, `tdns.AgentMgmt*`

### Design note

`tdns.Agent` is a tdns struct but tdns-mp has its own local
`Agent` type (see 2026-04-14 doc, note at the bottom of §1:
"`Agent` type in tdns-mp is locally defined, not an alias").
So referring to `tdns.Agent` in tdns-mp code means *the tdns
version*, which shadows the local one. This is confusing and
the call sites need careful reading before editing — do we
want the local `Agent` (the active MP type) or the tdns
`Agent` (a different struct)?

Check each call site's context before replacing:

| file | line | question |
|---|---|---|
| `db_hsync.go:480` | `func PeerRecordFromAgent(agent *tdns.Agent) *PeerRecord {` | Does the caller pass a local Agent or a tdns Agent? |
| `cli/hsync_cmds.go:532` | `func PrintHsyncAgent(agent *tdns.Agent, showZones bool) error {` | Same |
| `cli/agent_debug_cmds.go:259,263,267` | construct `&tdns.Agent{...}` for a test | Probably test fixtures; can switch to local Agent |

If any `*tdns.Agent` value is handed to a function that only
accepts the local `Agent` type, we have two types doing the
same job and one needs to win. Prefer the local `Agent` (it is
the one the active code path uses). If the current `*tdns.Agent`
references are all constructing tdns values that never touch
the local `Agent`, this is a simple rename. If they are mixed,
the plan for 6c becomes: "convert each site to use the local
`Agent` struct instead".

### Action 6c.1 — Read all 5 sites

Before editing, read each line above in context (±10 lines)
to determine whether `*tdns.Agent` and local `*Agent` are ever
exchanged. Record the outcome in the commit message.

### Action 6c.2 — Rename to local

Once the semantics are clear:

| file | line | old | new |
|---|---|---|---|
| `db_hsync.go` | 480 | `func PeerRecordFromAgent(agent *tdns.Agent) *PeerRecord {` | `func PeerRecordFromAgent(agent *Agent) *PeerRecord {` |
| `cli/hsync_cmds.go` | 532 | `func PrintHsyncAgent(agent *tdns.Agent, ...) error {` | `func PrintHsyncAgent(agent *Agent, ...) error {` |
| `cli/hsync_cmds.go` | 543 | `for transport, details := range map[string]*tdns.AgentDetails{` | `for transport, details := range map[string]*AgentDetails{` |
| `cli/agent_debug_cmds.go` | 259, 263, 267 | `&tdns.Agent{...}` | `&Agent{...}` |

If the local `Agent` struct is missing fields that the tdns
one has, copy them into the local struct (it is already an
independent definition per the 2026-04-14 doc). Flag any
mismatch to the reviewer.

### Action 6c.3 — AgentState + AgentStateToString

| file | line | old | new |
|---|---|---|---|
| `db_hsync.go` | 587 | `func agentStateToString(state tdns.AgentState) string {` | `func agentStateToString(state AgentState) string {` |
| `cli/hsync_cmds.go` | 533 | `tdns.AgentStateToString[agent.State]` | `AgentStateToString[agent.State]` |
| `cli/hsync_cmds.go` | 554 | `tdns.AgentStateToString[details.State]` | `AgentStateToString[details.State]` |

This assumes a local `AgentState` type and `AgentStateToString`
map exist. If not, copy them from tdns/v2 into
`tdns-mp/v2/agent_structs.go` in the same commit.

### Action 6c.4 — AgentMsgNotify / AgentMsgRfi

These are `core.AgentMsg` string constants (`"sync"`, `"rfi"`).
Move them into tdns-mp if they are not already in `core`:

| file | line | old | new |
|---|---|---|---|
| `cli/agent_debug_cmds.go` | 60 | `MessageType: tdns.AgentMsgNotify,` | `MessageType: AgentMsgNotify,` |
| `combiner_msg_handler.go` | 117 | `if msg.MessageType == tdns.AgentMsgRfi {` | `if msg.MessageType == AgentMsgRfi {` |
| `cli/agent_cmds.go` | 219 | `MessageType: tdns.AgentMsgRfi,` | `MessageType: AgentMsgRfi,` |
| `cli/agent_debug_cmds.go` | 93 | `MessageType: tdns.AgentMsgRfi,` | `MessageType: AgentMsgRfi,` |

If the constants live in `core/messages.go` (the most likely
location given the 2026-04-13 work), then the replacement is
`core.AgentMsgRfi` / `core.AgentMsgNotify` instead of local.
Verify with `grep -n 'AgentMsgRfi\|AgentMsgNotify' tdns/v2/core/`.

### Action 6c.5 — AgentMgmtPost / AgentMgmtResponse

**Starting state (corrected)**: full struct definitions for
`AgentMgmtPost` and `AgentMgmtResponse` already live in
**`tdns-mp/v2/agent_structs.go`**. There is **no** need to copy them
from `tdns/v2/mptypes.go` again.

The remaining work is **qualifier + import wiring** in **`package cli`**:
today `tdns-mp/v2/cli/*.go` imports **`tdns`** and writes
`tdns.AgentMgmtPost` / `tdns.AgentMgmtResponse`. To use the parent
types unqualified, pick **one** approach (Phase 8.4 should match):

1. **Import the parent module** (`github.com/johanix/tdns-mp/v2`, package
   name `tdnsmp`) and qualify as
   `tdnsmp.AgentMgmtPost`, **or**
2. Add **thin type aliases** in `cli/types.go` that point at the parent
   package's types (if Go version / module layout allows without cycles),
   **or**
3. Keep using the **local structs in `agent_structs.go`** by importing
   the parent package and referencing them explicitly — avoid duplicating
   struct bodies in `cli/`.

Run the mechanical sweep:

```
grep -rln 'tdns\.AgentMgmtPost\|tdns\.AgentMgmtResponse' tdns-mp/v2/cli/
```

For each file, replace `tdns.AgentMgmtPost` → the chosen local or
parent-qualified name (same for `AgentMgmtResponse`). Resolve any
**import cycle** at edit time (cli must not import a package that imports
`cli`).

Files touched (from the file:line inventory — line numbers drift):

- `cli/agent_cmds.go` (7 sites, incl. the `SendAgentMgmtCmd` func signature at line 287)
- `cli/agent_zone_cmds.go` (4 sites)
- `cli/agent_edits_cmds.go` (3 sites)
- `cli/agent_debug_cmds.go` (12 sites, incl. `SendAgentDebugCmd` at line 787)
- `cli/agent_imr_cmds.go` (4 sites)
- `cli/hsync_cmds.go` (11 sites, incl. `SendAgentHsyncCommand` at line 45)

### Verification

```
grep -n 'tdns\.Agent\b\|tdns\.AgentDetails\|tdns\.AgentState\|tdns\.AgentMsg\|tdns\.AgentMgmt' tdns-mp/v2/
```

Zero matches. `gofmt -w` every touched file. Build **including
cli**: `cd tdns-mp/cmd && make`.

### Pre-commit checkpoint

Commit 6c separately: "Drop tdns. qualifier from Agent/AgentMgmt
family". This is the largest commit in the plan — expect the
review to focus here.

---

# Phase 7 — Delete unused aliases

Simple cleanup. No call sites anywhere in tdns-mp/v2/.

### Action 7.1

Delete from `tdns-mp/v2/types.go`:

| line | content |
|---|---|
| 39 | `type CombinerSyncRequestPlus = tdns.CombinerSyncRequestPlus` |
| 47 | `type CombinerOption = tdns.CombinerOption` |

### Verification

```
grep -rn 'CombinerSyncRequestPlus\|CombinerOption' tdns-mp/v2/
```

Zero matches (except possibly `CombinerOptAddSignature` — which
is a *constant* with a similar name, keep it if it is used).
Build.

### Pre-commit checkpoint

Commit: "Delete unused aliases CombinerSyncRequestPlus, CombinerOption".

---

# Phase 8 — Flip all remaining alias declarations to local structs

By this point every consumer of the aliases uses the local name
(no `tdns.` qualifier). The aliases can now be flipped from
`type X = tdns.X` (pure alias) to `type X struct { ... }` (local
definition) without touching any consumer.

### Action 8.1 — `tdns-mp/v2/types.go`

Replace each `type X = tdns.X` with the verbatim struct
definition from `tdns/v2/mptypes.go`. The aliases to flip are:

| line | type |
|---|---|
| 17 | CombinerPost |
| 18 | CombinerResponse |
| 19 | CombinerEditPost |
| 20 | CombinerEditResponse |
| 21 | CombinerDebugPost |
| 22 | CombinerDebugResponse |
| 23 | CombinerDistribPost |
| 42 | PendingEditRecord |
| 43 | ApprovedEditRecord |
| 44 | RejectedEditRecord |
| 52 | KeyInventoryItem |
| 53 | DnssecKeyWithTimestamps |
| 56 | AgentId |
| 57 | ZoneName |
| 58 | ZoneUpdate |
| 59 | OwnerData |
| 68 | TransactionPost |
| 69 | TransactionResponse |
| 70 | TransactionSummary |
| 71 | TransactionErrorSummary |

For each: open `tdns/v2/mptypes.go`, find the struct by name,
copy the struct body verbatim, delete the `= tdns.X` line,
insert the struct. Preserve any comment above the definition.

**Watch out for cascade**: if a struct has a field typed as
another tdns type that isn't in our alias list, the field must
be updated too. `AgentMgmtResponse` has fields like
`[]*tdns.HsyncPeerInfo` — after Phase 4 + this phase, those
become `[]*HsyncPeerInfo` (local). The copy-paste step needs
to strip `tdns.` qualifiers inside the struct body before
pasting.

### Action 8.2 — `tdns-mp/v2/agent_structs.go`

| line | type |
|---|---|
| 349 | HsyncPeerInfo |
| 350 | HsyncSyncOpInfo |
| 351 | HsyncConfirmationInfo |
| 352 | HsyncTransportEvent |
| 353 | HsyncMetricsInfo |

Same procedure.

### Action 8.3 — `tdns-mp/v2/sde_types.go`

| line | type |
|---|---|
| 175 | SyncRequest |
| 176 | SyncResponse |
| 177 | SyncStatus |
| 201 | HsyncStatus |
| 206 | DnskeyStatus |

**`SyncRequest.ZoneData` (critical)** — In tdns today the field is
**`*tdns.ZoneData`**. Send sites populate it with **`mpzd.ZoneData`**
(the **embedded** `*tdns.ZoneData` on `MPZoneData`, not the wrapper).
Consumers such as **`SyncRequestHandler`** use **`Zones.Get`** and
zone fields on that pointer. **Default when flipping to a local
`SyncRequest` struct: keep `ZoneData *tdns.ZoneData`**. Do **not**
blindly change to `*MPZoneData` unless you have updated **every**
receiver to unwrap or use `MPZones` consistently (grep `SyncQ`,
`SyncRequest`, and assignments to `ZoneData:` before changing).

After the flip, **rewrite the stale header comment** in this file
that claims these types must stay aliases because `SyncQ` lived on
tdns `ZoneData` (that layout is obsolete).

### Action 8.4 — `tdns-mp/v2/cli/types.go`

The CLI package (`tdns-mp/v2/cli`) has its own small **`cli/types.go`**
aliases. **`package cli` does not import the parent `tdnsmp` package
today** — resolving Phase 6c / 8 for CLI types is **not** a one-line
sed; it requires a deliberate choice:

- **Preferred when cycle-free**: import **`github.com/johanix/tdns-mp/v2`**
  (as `tdnsmp` or similar) and use **`tdnsmp.CombinerPost`**, etc., then
  **delete duplicated aliases** from `cli/types.go`; **or**
- **If an import cycle appears**: keep minimal aliases in `cli/types.go`
  until the dependency graph is fixed, or move shared request/response
  structs to a tiny **third package** imported by both cli and v2.

Re-grep `package cli` imports after any change; **`go list`** / build
`cmd/mpcli` (or whichever binary embeds cli) is the real gate.

### Verification

```
grep -rn '= tdns\.' tdns-mp/v2/types.go tdns-mp/v2/agent_structs.go \
                    tdns-mp/v2/sde_types.go tdns-mp/v2/cli/types.go
```

Only tdns references inside struct bodies should remain —
ideally zero. Run `gofmt -w` on all four files. Build both
tdns-mp binaries.

### Pre-commit checkpoint

Commit: "Flip type aliases to local struct definitions".

---

# Phase 9 — Remove `tdns.Conf.MultiProvider` access

Not a type dependency but the last remaining **`tdns.Conf`** global
reads in tdns-mp for multi-provider identity.

### Starting state

Five call sites (re-grep `tdns.Conf.MultiProvider` — line numbers drift):

| file | (historical line) |
|---|---|
| `combiner_utils.go` | 257, 482, 561, 688 |
| `combiner_chunk.go` | 251 |

All read **`tdns.Conf.MultiProvider`** (`*tdns.MultiProviderConf`).

### Action 9.1 — Store a pointer where `*Config` already exists

**Do not** assume `EnsureMP()` can set this: `EnsureMP` in
`mp_extension.go` only allocates `mpzd.MP = &MPState{}` and has **no
`*Config` parameter**.

**Recommended pattern**: add **`MultiProvider *tdns.MultiProviderConf`**
(or a type alias if you prefer) to **`InternalMpConf`** in
`tdns-mp/v2/config.go`, and assign **once** from the loaded config in
**`main_init.go`** (or immediately after config parse), e.g.
`conf.InternalMp.MultiProvider = conf.MultiProvider` (the embedded
`*tdns.Config` field on `*Config`).

**Alternative**: add `MultiProvider` to **`MPState`** and populate it
from the same **single** early wiring point that has access to
`*Config` (not from bare `EnsureMP` unless you thread a setter).

### Action 9.2 — Thread into call sites

Options for `combiner_utils.go` (methods on `*MPZoneData` only):

- Read **`mpzd` → registry → InternalMp** if you add an accessor on
  `Config` / package init pattern used elsewhere, **or**
- Pass `*tdns.MultiProviderConf` into the few helpers that need it,
  **or**
- Store **`MultiProvider` on `MPState`** in the same commit that adds
  code in **`MainInit` / zone registration** to set
  `mpzd.MP.MultiProvider = conf.MultiProvider` for every MP zone
  (verify nil before first use — same risk as global `tdns.Conf`).

`combiner_chunk.go` call sites that already have a **`*Config` receiver
or local `conf *Config`** should use **`conf.MultiProvider`** (embedded
from `*tdns.Config`), not `tdns.Conf.MultiProvider`.

### Action 9.3 — Rewrite the reads (illustrative)

| location | old | new (pattern) |
|---|---|---|
| `combiner_utils.go` | `tdns.Conf.MultiProvider` | `conf.InternalMp.MultiProvider` or `mpzd.MP.MultiProvider` per 9.1–9.2 |
| `combiner_chunk.go` | `ourHsyncIdentities(tdns.Conf.MultiProvider)` | `ourHsyncIdentities(conf.MultiProvider)` when `conf` is in scope |

### Verification

**Do not** use `grep 'tdns\.Conf'` alone — it matches **`tdns.Config`**
as a substring. Use one of:

```
grep -rn 'tdns\.Conf\.' tdns-mp/v2/
```

Expect **zero** hits for `tdns.Conf.MultiProvider` / `tdns.Conf.` reads
you intended to remove. Legitimate **`tdns.Config{...}`** struct literals
(e.g. in tests) may still exist — that is fine.

Build.

### Pre-commit checkpoint

Commit: "Remove tdns.Conf.MultiProvider access".

---

# Phase 10 — tdns/v2: delete legacy files; relocate barrel files

At this point tdns-mp should not reference **symbols defined only in**
`legacy_*.go`. **`mpmethods.go`** and **`mptypes.go` are not legacy-only**:
they hold **live** `*ZoneData` MP accessors (`EnsureMP`, getters/setters),
`Agent` methods, `AgentId` / `ZoneName` `String`, repo constructors,
large shared **type** definitions (`Agent`, `SyncRequest`, combiner
structs, …), and more. **You cannot `rm mpmethods.go` / `mptypes.go` in
the same breath as `legacy_*.go` without first moving or splitting what
non-legacy tdns still needs.**

### Action 10.1 — Final verification (tdns-mp)

```
grep -rn '\btdns\.' tdns-mp/v2/
```

Surviving hits should only reference still-live tdns symbols:
`tdns.ZoneData` (embedding), `tdns.Globals`, `tdns.KeyDB`,
`*tdns.Config` / `*tdns.MultiProviderConf`, etc. Anything that still
names a **function or type that lives only in** a `legacy_*.go` file
must be fixed **before** touching tdns deletes.

### Action 10.2 — Delete **`legacy_*.go`** (and agreed `deadcode_*.go`)

When tdns-mp is clean and tdns `go build` no longer needs the legacy
implementations, remove the legacy sources, for example:

```
rm tdns/v2/legacy_agent_authorization.go
rm tdns/v2/legacy_agent_discovery.go
rm tdns/v2/legacy_agent_utils.go
rm tdns/v2/legacy_apihandler_transaction.go
rm tdns/v2/legacy_combiner_chunk.go
rm tdns/v2/legacy_combiner_utils.go
rm tdns/v2/legacy_db_combiner_contributions.go
rm tdns/v2/legacy_db_combiner_edits.go
rm tdns/v2/legacy_db_combiner_publish_instructions.go
rm tdns/v2/legacy_gossip.go
rm tdns/v2/legacy_hsync_beat.go
rm tdns/v2/legacy_hsync_hello.go
rm tdns/v2/legacy_hsync_transport.go
rm tdns/v2/legacy_hsync_utils.go
rm tdns/v2/legacy_hsyncengine.go
rm tdns/v2/legacy_parentsync_leader.go
rm tdns/v2/legacy_provider_groups.go
rm tdns/v2/legacy_signer_msg_handler.go
```

Also remove any **`deadcode_*.go`** / renamed discovery stubs the tree
no longer compiles with (see `2026-04-14-imr-embedding-plan.md` if
applicable). **Commit tdns green after this step alone.**

### Action 10.3 — Split / relocate **`mptypes.go`** and **`mpmethods.go`**

Until this sub-phase is done, **do not delete** those two files.

1. **`mpmethods.go`**: move **non-legacy** methods and functions
   (`*ZoneData` MP accessors, `*Agent` methods, `NewAgentRepo`,
   `NewZoneDataRepo`, `RRState.String`, `allRecipientsConfirmed`, …)
   into one or more **new** files (e.g. `zone_mp_accessors.go`,
   `agent_methods.go`) that remain in **`package tdns`**.
2. **`mptypes.go`**: for each **type**, decide whether it is still
   needed by **non-legacy tdns** after legacy deletion, or was only
   consumed from legacy / tdns-mp (which can keep its own copy). Then:
   - move definitions next to their only remaining consumers inside tdns,
   - or keep a **minimal** `mptypes.go` that only holds what **tdns core**
     still needs after legacy deletion, **or**
   - delete a type from tdns entirely once **no** package references it.

Use **`go list ./...`** / **`make`** in `tdns/cmdv2` after each move.
When `mptypes.go` and `mpmethods.go` are **empty or redundant**, delete
them in a **final** commit.

### Action 10.4 — Build both modules

```
cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make
cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make
```

If tdns fails after 10.2 only, add a **minimum shim** in tdns/v2 for the
missing symbol (per earlier appendix). If failure is after 10.3, the
split was incomplete — restore or move more symbols.

### Pre-commit checkpoint

Prefer **separate commits**:
1. tdns: "Delete legacy multi-provider / combiner / hsync sources"
2. tdns: "Relocate mpmethods/mptypes contents" (one or more commits)
3. tdns: "Remove empty mptypes.go / mpmethods.go" (only when truly redundant)

---

# Appendix A — Unused aliases (can be left alone or flipped in Phase 8)

The following aliases have zero explicit `tdns.X` references
in tdns-mp/v2/. Their consumers only use the local name, so
the alias-flip in Phase 8 is all that is needed — no sweep
phase is required for them.

- `CombinerPost`, `CombinerResponse`, `CombinerEditPost`,
  `CombinerEditResponse`, `CombinerDistribPost`
- `PendingEditRecord`, `ApprovedEditRecord`, `RejectedEditRecord`
- `TransactionSummary`
- `SyncResponse`, `SyncStatus`
- `KeyInventoryItem`, `DnssecKeyWithTimestamps`
- `RejectedItem` (already handled in Phase 2)

# Appendix B — Risk assessment

Each risk is graded on **Likelihood (L)** and **Impact (I)**,
each scored **L** (low), **M** (medium), or **H** (high), with
a brief mitigation. The plan is deliberately staged so that
almost every phase is compile-checked and revertible — the
high-impact risks cluster in Phase 1 and Phase 6c.

**Column legend** (used in every table below):

- **L** — Likelihood this risk actually materializes during
  execution. L = unlikely, M = plausible, H = expect it.
- **I** — Impact if it does materialize. L = build failure,
  reverted in minutes. M = semantic drift, caught on NetBSD
  VM smoke test, one-commit fix. H = silent wrong behavior
  that could ship if not caught early.

## B.1 Compile-time risks (caught by `go build`)

Low consequence: if something in this category goes wrong, the
build fails and nothing ships. Revert the commit and try again.

| # | Risk | L | I | Mitigation |
|---|---|---|---|---|
| B.1.1 | Line numbers drift between phases as earlier commits shift code | M | L | Re-grep before each phase; file:line tables in this plan are snapshots, not contracts |
| B.1.2 | A `tdns.Foo` reference hides inside an import alias, build tag, or generated file that grep missed | M | L | Phase 10's final verification grep catches any leftover; build is the real test |
| B.1.3 | Cascade inside flipped struct bodies (Phase 8): a struct field like `[]*tdns.HsyncPeerInfo` inside `AgentMgmtResponse` gets left qualified when the definition is copied across | H | L | Before pasting, strip `tdns.` qualifiers inside the struct body; build after each alias flip to catch it immediately. `AgentMgmtResponse` is the worst offender — do it last and alone |
| B.1.4 | A struct definition in `mptypes.go` references an unexported helper type that doesn't exist in tdns-mp | L | L | Build catches it. If it happens, copy the helper too |

## B.2 Semantic risks (build passes, behavior changes)

These are the dangerous ones. The build will pass; only testing
on the NetBSD VMs will reveal the problem.

| #     | Risk                                                                                                                                                                                                                                                                                                                                      | L   | I     | Mitigation                                                                                                                                                                                                                                   |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B.2.1 | **`tdns.Agent` vs local `Agent` confusion** (Phase 6c). tdns-mp has a locally-defined `Agent` struct that is a different type from `tdns.Agent`. Replacing `*tdns.Agent` with `*Agent` assumes the local struct has the right fields. If the tdns one has fields the local one lacks, code that reads those fields silently stops working | M   | **H** | Read each of the 5 `*tdns.Agent` sites end-to-end before editing. Diff the two struct definitions. Copy any missing fields into the local `Agent` before the rename. Write out the diff in the commit message so the reviewer can eyeball it |
| B.2.2 | **`SyncRequest.ZoneData` field type** (Phase 8.3). Senders set `ZoneData: mpzd.ZoneData` (the embedded **`*tdns.ZoneData`**). Handlers use **`Zones.Get`** and fields on that pointer. Default when defining a local `SyncRequest`: **keep `ZoneData *tdns.ZoneData`**. Changing to `*MPZoneData` requires updating every consumer to unwrap — easy to get wrong silently | M   | M     | Before editing, `grep -n 'SyncRequest{\|ZoneData:' tdns-mp/v2/*.go` and read `SyncRequestHandler` / `UpdateAgents`. Prefer **explicit `*tdns.ZoneData`** unless you have migrated the whole SDE to `*MPZoneData` |
| B.2.3 | **`ErrorJournal` semantics** (Phase 1). If `ErrorJournal` is currently defined in tdns/v2 and has internal mutex/goroutine state, a naive struct copy might preserve the layout but break concurrency invariants                                                                                                                          | L   | M     | Before copying, `grep -n 'ErrorJournal' tdns/v2/*.go` and read the full type + its methods. If it has any state beyond a slice + mutex, copy the methods verbatim too                                                                        |
| B.2.4 | **`CombinerProcessUpdate` signature assumption** (Phase 1). Phase 1 assumes tdns-mp's local `CombinerProcessUpdate` takes `*CombinerSyncRequest` (local alias). If it actually takes `*tdns.CombinerSyncRequest`, the new `ProcessUpdate` method won't type-check after Phase 2                                                           | L   | L     | Pre-edit verification step in §1.1 catches it with a grep. If the assumption fails, amend Phase 1 to also rewrite the local function's signature                                                                                             |
| B.2.5 | **`MultiProvider` pointer timing** (Phase 9). If the stored `*MultiProviderConf` is read before config parse finishes, it will be nil where `tdns.Conf.MultiProvider` was already non-nil                                                                                                                                                    | L   | M     | Populate from **`main_init`** (or equivalent) right after config load into **`InternalMpConf`** or another object that exists before zone processing. Do not rely on bare `EnsureMP()` alone — it has no `*Config` argument                                                                                |
| B.2.6 | **Hidden reflection / type switches on `tdns.Foo`** anywhere in the code                                                                                                                                                                                                                                                                  | L   | M     | `grep -rn 'reflect\.\|\.(\*tdns\.' tdns-mp/v2/` after each phase. Unlikely in this codebase but worth a sanity check                                                                                                                         |
| B.2.7 | **JSON tag mismatches** when flipping aliases to local structs (Phase 8). A copy-paste that drops a `json:"..."` tag silently changes the wire format                                                                                                                                                                                     | L   | M     | Copy struct bodies verbatim, tags included. Diff the copied struct against the original with `diff` before committing                                                                                                                        |

## B.3 Scope/process risks

| # | Risk | L | I | Mitigation |
|---|---|---|---|---|
| B.3.1 | Phase 6c (Agent/AgentMgmt sweep) is the largest commit — reviewer fatigue | H | L | Split 6c further if it exceeds 40 files or 500 lines changed. The plan already splits 6 into 6a/6b/6c; further splitting of 6c along file boundaries is fine |
| B.3.2 | **`mptypes.go` / `mpmethods.go` deletion breaks tdns** because those files contained non-legacy symbols | H | M | Treat Phase **10.3** as mandatory: **relocate** accessors and types before deleting barrel files. Legacy-only `rm` (10.2) is insufficient by itself |
| B.3.3 | A deleted helper turns out to have been the only producer of some KeyDB record | L | M | Phase 10 `rm` happens after all type work is done and the tdns-mp binaries build. A functional test on the NetBSD VM is the real safety net |
| B.3.4 | Someone lands work in tdns/v2 legacy files during cleanup | L | L | This is rare in the current project state. If it happens, rebase and re-verify |
| B.3.5 | `cli/types.go` duplication (Phase 8.4): decision deferred to edit time about whether to keep or delete | L | L | Decide once, in Phase 8, based on whether cli imports the parent tdns-mp/v2 package. Leaving it duplicated is also fine — not worth a separate decision cycle |

## B.4 Things that are NOT risks

Worth stating explicitly:

- **Wire compatibility**: tdns-mp is the only producer/consumer
  over the wire. No installed base, no legacy peers.
- **Database schema compatibility**: tdns-mp owns the
  `HsyncDB`. No schema migration required.
- **Import cycles**: tdns-mp imports tdns, not vice versa. Most
  tdns-mp edits stay cycle-safe. **Exception**: wiring **`package cli`**
  to import the parent **`tdnsmp`** module can create cycles — resolve
  in Phase 6c / 8.4 with an explicit graph check (`go list`).
  Phase 10 tdns edits are relocations and deletions, not tdns-mp imports.
- **Go module versions**: both modules already build together;
  nothing here touches `go.mod`.
- **Runtime reflection of type names**: unlikely but B.2.6 says
  to verify.

## B.5 Overall risk profile

Two phases carry real semantic risk: **Phase 1** (CombinerState
localization, B.2.3 + B.2.4) and **Phase 6c** (Agent family
sweep, B.2.1). Phase 1 is small and tightly scoped, and the
pre-edit verification step should catch its hazards before any
code is written. Phase 6c is large but every individual edit
is mechanical — the one real decision (tdns.Agent vs local
Agent) applies to five call sites and can be settled by
reading them end-to-end.

Everything else is either compile-checked (low consequence) or
purely mechanical. The plan is fundamentally safe to execute
incrementally with a build + NetBSD VM smoke test between
commits.

## B.6 Recommended review gate

After **Phase 1** commit, request an explicit review before
proceeding. That's the one step where a reviewer's second pair
of eyes on `CombinerState`, `ProcessUpdate`, `ErrorJournal`,
and `CombinerProcessUpdate`'s signature is most valuable. After
Phase 6c, a second review gate is worth it because of the
sheer volume. The remaining phases can proceed on author-only
review if the earlier gates are clean.

# Appendix C — Commit order summary

| # | Commit | Phase |
|---|---|---|
| 1 | Delete dead in-process combiner helper (SendToCombiner path) | 0 |
| 2 | Localize CombinerState and its methods into tdns-mp | 1 |
| 3 | Localize CombinerSync{Request,Response} and RejectedItem | 2 |
| 4 | Drop tdns. qualifier from handler surface types | 3 |
| 5 | Drop tdns. qualifier from Hsync DB status types | 4 |
| 6 | Drop tdns. qualifier from SDE queue types | 5 |
| 7 | Drop tdns. qualifier from AgentId and ZoneName | 6a |
| 8 | Drop tdns. qualifier from ZoneUpdate and OwnerData | 6b |
| 9 | Drop tdns. qualifier from Agent/AgentMgmt family | 6c |
| 10 | Delete unused aliases | 7 |
| 11 | Flip type aliases to local struct definitions | 8 |
| 12 | Remove `tdns.Conf.MultiProvider` reads (thread `*MultiProviderConf`) | 9 |
| 13 | tdns: delete legacy_*.go; relocate then remove mpmethods/mptypes barrels | 10 |
