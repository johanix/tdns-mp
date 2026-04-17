# Legacy Code Dependency Analysis: tdns-mp -> tdns/v2

**Date**: 2026-04-15
**Supersedes**: `2026-04-14-legacy-dependency-analysis.md`
**Purpose**: Inventory of remaining coupling between tdns-mp/v2 and
tdns/v2, cleanly separated into "real cross-repo dependencies that
need fixing" and "historical findings that turned out to be
non-issues / fake blockers / already resolved".

## TL;DR

After strict re-verification there is **one root cross-repo
blocker**: `*tdns.CombinerState` and its `ProcessUpdate` method
defined in `tdns/v2/legacy_combiner_chunk.go`. Everything else —
every other type alias, every other direct `tdns.Type` reference,
every legacy function — either is already resolved, or is a
**fake blocker**: the `tdns.` qualifier appears only in tdns-mp's
own source files and can be flipped to a local type with
tdns-mp-only edits.

## Document Structure

- **Part I — Real Cross-Repo Dependencies (need fixing)**
  - §1: The single real blocker (`CombinerState` + signature mates)
  - §2: Transitive / config coupling
  - §3: Suggested migration order
- **Part II — Fake Blockers (tdns-mp-only cleanup)**
  - §4: Aliases that can be converted to local structs today
  - §5: Direct `tdns.Type` references that are local-edit only
  - §6: Unused aliases (delete outright)
- **Part III — Already Resolved**
  - §7: Method-dependency classes already migrated
  - §8: Package-level functions re-defined locally
  - §9: Pointer to the 2026-04-14 call-site inventory

The criterion used in Part I is strict:

> **A real cross-repo dependency exists IFF tdns-mp code passes a
> value into a function, method, or struct field whose signature
> lives in tdns/v2 AND has NOT been re-implemented locally in
> tdns-mp.**
>
> `var x tdns.Foo{...}` inside tdns-mp's own `.go` files is NOT a
> real dependency — it is a qualifier-style choice that can be
> flipped to a local type by editing tdns-mp alone.

tdns-mp is the sole producer/consumer of these values on the
wire and in the database, so wire-compat and schema-compat do
not apply.

---

# PART I — REAL CROSS-REPO DEPENDENCIES

## 1. The single real blocker: `*tdns.CombinerState.ProcessUpdate`

`tdns/v2/legacy_combiner_chunk.go` still owns the
`(*CombinerState).ProcessUpdate(...)` method. tdns-mp stores a
`*tdns.CombinerState` in `main_init.go:443`, builds a
`tdns.CombinerSyncRequest` at `combiner_chunk.go:1414`, and
passes it into the tdns-side method at
`combiner_chunk.go:1428`; the response comes back as
`tdns.CombinerSyncResponse` with `tdns.RejectedItem` entries.

This one entry point is what keeps four type names bound to
tdns:

| Type | Role in the blocker |
|---|---|
| `CombinerState` | Receiver — the struct is defined in tdns/v2 |
| `CombinerSyncRequest` | Argument to `ProcessUpdate` |
| `CombinerSyncResponse` | Return value from `ProcessUpdate` |
| `RejectedItem` | Embedded slice element in `CombinerSyncResponse` |

Fix: re-implement `CombinerState` and `(*CombinerState).ProcessUpdate`
in tdns-mp (the same pattern already used for every other
legacy\_\*.go function — see §8). Once the method lives locally,
the four types drop out of Part I and join the "fake blocker"
cluster in Part II §4.

## 2. Transitive / config coupling

Not a type-system dependency, but still a real cross-repo call:

- **`tdns.Conf.MultiProvider`** — referenced from the migrated
  `combiner_utils.go` `*MPZoneData` methods. A config global,
  not a method dependency, but it still prevents a clean
  "tdns-mp imports nothing from tdns" end state. Fix by
  threading an MP-config pointer into `*MPZoneData` at
  construction time.

## 3. Suggested migration order

1. **Re-implement `CombinerState` + `ProcessUpdate` locally** in
   tdns-mp. This is the only step that requires understanding
   the combiner state machinery; everything else is mechanical.
2. **Localize the three signature-mate types** (`CombinerSyncRequest`,
   `CombinerSyncResponse`, `RejectedItem`) by flipping their
   aliases to local struct definitions.
3. **Mechanical cleanup pass (Part II §4 + §5)** — sweep
   tdns-mp/v2/ replacing `tdns.Foo` with `Foo` wherever the
   type is one of the fake-blocker aliases or direct refs, then
   flip each alias in `types.go` / `agent_structs.go` /
   `sde_types.go` to a local struct definition.
4. **Delete the unused aliases** from §6.
5. **Remove `tdns.Conf.MultiProvider`** access from
   `combiner_utils.go`.
6. **Delete `legacy_*.go`, `mpmethods.go`, `mptypes.go`** from
   tdns/v2 as a single batch.

---

# PART II — FAKE BLOCKERS (tdns-mp-only cleanup)

Everything in Part II has a `tdns.` qualifier somewhere in
tdns-mp source, but the qualifier is the only thing binding the
value to tdns/v2. A local search-and-replace plus an alias flip
is all that is required. None of these touch tdns/v2 source
files.

## 4. Aliases that can be converted to local structs today

These all live in `tdns-mp/v2/types.go`,
`tdns-mp/v2/agent_structs.go:349-353`, or
`tdns-mp/v2/sde_types.go:175-206`. Every "blocker" line for
these aliases sits inside tdns-mp itself.

### 4.1 Handler-surface aliases (CLI ↔ daemon, both sides in tdns-mp)

| Alias | Why it was mis-classified as BLOCKED |
|---|---|
| CombinerPost | JSON-only, local handler |
| CombinerResponse | JSON-only, local handler |
| CombinerEditPost | Local CLI + handler |
| CombinerEditResponse | Local CLI + handler |
| CombinerDistribPost | Local handler only |
| CombinerDebugPost | `apihandler_combiner_mp.go:21` and `apihandler_signer.go:20` write `var req tdns.CombinerDebugPost` — just replace with the alias |
| CombinerDebugResponse | Same pattern, `apihandler_combiner_mp.go:31` / `apihandler_signer.go:30` |
| TransactionPost | `apihandler_combiner_routes.go:41` uses explicit `tdns.` qualifier |
| TransactionResponse | `apihandler_combiner_routes.go:51` same |
| TransactionSummary | Embedded in `TransactionResponse` |
| TransactionErrorSummary | `apihandler_combiner_routes.go:85,111` same pattern |

### 4.2 Combiner-core aliases (unblocked by §1)

| Alias | Why |
|---|---|
| CombinerSyncRequest | Only "blocker" is `ProcessUpdate`'s signature — see §1 |
| CombinerSyncResponse | Same |
| RejectedItem | Same |
| CombinerState | Same |

### 4.3 Edit-journal record aliases

| Alias | Why |
|---|---|
| PendingEditRecord | Stored/retrieved from tdns-mp's local `HsyncDB` (see §8); the "tdns transaction flow" is itself re-defined locally |
| ApprovedEditRecord | Same |
| RejectedEditRecord | Same |

### 4.4 Hsync DB status aliases

Returned by `db_hsync.go` locally-defined functions like
`PeerRecordToInfo()`, `SyncOpRecordToInfo()`,
`ConfirmRecordToInfo()`. Pure CLI-display pipeline that never
leaves tdns-mp.

| Alias | Origin |
|---|---|
| HsyncPeerInfo | `db_hsync.go:634-635` — local function |
| HsyncSyncOpInfo | `db_hsync.go:659-660` — local function |
| HsyncConfirmationInfo | `db_hsync.go:679-680` — local function |
| HsyncTransportEvent | `db_hsync.go:829,861,863` — local function |
| HsyncMetricsInfo | `db_hsync.go:885,889,925` — local function |

### 4.5 SDE queue aliases

The `SyncQ` channel is owned by tdns-mp's SDE. Every producer
and consumer is in tdns-mp.

| Alias | Origin |
|---|---|
| SyncRequest | Constructed in `hsync_utils.go:1175`, sent to `mpzd.SyncQ` |
| SyncResponse | Consumed locally |
| SyncStatus | Embedded in the above |
| HsyncStatus | Embedded in `SyncRequest` (`sde_types.go:200`) |
| DnskeyStatus | Embedded in `SyncRequest` |

### 4.6 Pervasive local-only aliases

| Alias | Notes |
|---|---|
| AgentId | Used everywhere; zero cross-module binding |
| ZoneName | Used everywhere; zero cross-module binding |
| ZoneUpdate (alias) | The alias itself is local; see §5 for the direct-ref side |
| OwnerData (alias) | Same — direct-ref side is §5 |
| KeyInventoryItem | Signer/key-mgmt internal |
| DnssecKeyWithTimestamps | Key-state internal |

## 5. Direct `tdns.Type` references that are local-edit only

Direct `tdns.TypeName` uses (no alias in between). Every one of
these was previously flagged EASY/MEDIUM/HARD; strict
re-audit shows all of them are just qualifier cleanup.

| Type | Origin / why fake |
|---|---|
| `tdns.Agent` | `db_hsync.go:480`, `cli/hsync_cmds.go:532`, `cli/agent_debug_cmds.go:259,263,267` — all tdns-mp files. Never passed into a tdns/v2 function; `db_hsync.go` converts it into `PeerRecord` locally |
| `tdns.AgentDetails` | Field of `tdns.Agent`, same story |
| `tdns.AgentState` | Simple `iota` enum used for display only |
| `tdns.AgentStateToString` | Map lookup, display only |
| `tdns.AgentMgmtPost` | Sent via `SendAgentMgmtCmd` — defined in `tdns-mp/v2/cli/agent_cmds.go:287`, not tdns/v2 |
| `tdns.AgentMgmtResponse` | Returned from the same locally-defined `SendAgentMgmtCmd` |
| `tdns.AgentMsgNotify` | `core.AgentMsg` string constant |
| `tdns.AgentMsgRfi` | `core.AgentMsg` string constant |
| `tdns.ZoneUpdate` | Passed to `EnqueueForCombiner` / `EnqueueForZoneAgents` / `EnqueueForSpecificAgent` — all locally re-defined in `hsync_transport.go:1798,1823,1859` (see §8) |
| `tdns.DnskeyStatus` | Created at `hsync_utils.go:86` for local comparisons |
| `tdns.HsyncStatus` | Embedded in local `SyncRequest` |
| `tdns.SyncRequest` | Sent to local `mpzd.SyncQ` channel |
| `tdns.OwnerData` | Stored in `*core.ConcurrentMap[string, tdns.OwnerData]` which is a field of `MP` (local) per `mp_extension.go:25-26` — the map is owned by tdns-mp's local `MPState`, not by tdns/v2 |
| `tdns.HsyncPeerInfo` / `HsyncSyncOpInfo` / `HsyncConfirmationInfo` / `HsyncTransportEvent` / `HsyncMetricsInfo` | Same as §4.4 |
| `tdns.CombinerDebugPost` / `CombinerDebugResponse` | Same as §4.1 |
| `tdns.CombinerState` | REAL — see §1 |
| `tdns.CombinerSyncRequest` | REAL — see §1 |

## 6. Unused aliases — delete outright

| Alias | Notes |
|---|---|
| CombinerSyncRequestPlus | Zero references in tdns-mp/v2 |
| CombinerOption | Only the constant `CombinerOptAddSignature` is used; the type alias itself has no uses |

---

# PART III — ALREADY RESOLVED

## 7. Method-dependency classes already migrated

These were identified in the 2026-04-14 analysis as cross-repo
method dependencies and have all been migrated. Recorded here
so the resolution is not re-discovered later.

### 7.1 `*tdns.ZoneData` methods from `mpmethods.go`

`EnsureMP`, `GetLastKeyInventory`, `SetLastKeyInventory`,
`GetKeystateOK`, `SetKeystateOK`, `GetKeystateError`,
`SetKeystateError`, `GetKeystateTime`, `SetKeystateTime` — all
46 call sites resolved. Migrated to `*MPZoneData` receiver
methods in `tdns-mp/v2/mp_extension.go`. `Zones.Get()` returns
`*MPZoneData`. The local `mpzd.MP` field shadows the promoted
`tdns.ZoneData.MP`.

### 7.2 `*tdns.ZoneData` methods from `legacy_hsync_utils.go`

`LocalDnskeysFromKeystate` — all 4 call sites migrated to
`*MPZoneData` method in `tdns-mp/v2/hsync_utils.go`.

### 7.3 `*tdns.ZoneData` methods from `legacy_combiner_utils.go`

`CombineWithLocalChanges`, `RebuildCombinerData`,
`AddCombinerDataNG`, `GetCombinerDataNG`, `RemoveCombinerDataNG`,
`ReplaceCombinerDataByRRtype`, `InjectSignatureTXT` — all 19 call
sites migrated. Now self-contained `*MPZoneData` receiver
methods in `tdns-mp/v2/combiner_utils.go`, operating on
`mpzd.MP` (local `MPState`) rather than the promoted
`tdns.ZoneData.MultiProviderData`. `CombineWithLocalChanges` is
an enhanced reimplementation with role-based filtering.

### 7.4 `*tdns.Imr` methods from `legacy_agent_discovery_common.go`

`LookupAgentAPIEndpoint`, `LookupServiceAddresses`,
`LookupAgentTLSA`, `LookupAgentDNSEndpoint`, `LookupAgentJWK`,
`LookupAgentKEY` — all 7 call sites migrated to `*tdnsmp.Imr`
receiver methods in `tdns-mp/v2/agent_discovery_common.go`. The
`tdnsmp.Imr` type embeds `*tdns.Imr`. The 3 standalone
discovery functions (`DiscoverAgentAPI`, `DiscoverAgentDNS`,
`DiscoverAgent`) were converted to `*Imr` receivers at the same
time. The tdns/v2 file has been renamed to
`deadcode_agent_discovery_common.go`. See
`2026-04-14-imr-embedding-plan.md`.

## 8. Package-level functions re-defined locally

The following legacy files each contained package-level
functions that have been **copied** into tdns-mp. The local
definitions are the active ones; the tdns/v2 copies are dead
code within tdns/v2 and will be removed when the whole cluster
is deleted.

| tdns/v2 file | Status in tdns-mp |
|---|---|
| `legacy_hsync_transport.go` | Fully re-defined in `hsync_transport.go` (MPTransportBridge, NewMPTransportBridge, RegisterChunkNotifyHandler, StartIncomingMessageRouter, SendSyncWithFallback, SyncPeerFromAgent, SendHelloWithFallback, SendPing, SendBeatWithFallback, EnqueueForCombiner, EnqueueForZoneAgents, EnqueueForSpecificAgent, GetQueueStats, GetQueuePendingMessages, GetDistributionRecipients, TrackDnskeyPropagation, OnAgentDiscoveryComplete, StartReliableQueue) |
| `legacy_agent_authorization.go` | `IsPeerAuthorized` re-defined in `agent_authorization.go` |
| `legacy_agent_utils.go` | All symbols re-defined in `agent_utils.go` |
| `legacy_agent_discovery.go` | Re-defined in `agent_discovery.go` |
| `legacy_hsync_beat.go` | Re-defined in `hsync_beat.go` |
| `legacy_hsync_hello.go` | Re-defined in `hsync_hello.go` |
| `legacy_hsyncengine.go` | Re-defined in `hsyncengine.go` |
| `legacy_combiner_chunk.go` | Most re-defined in `combiner_chunk.go`. **Exception**: `(*CombinerState).ProcessUpdate` is NOT re-implemented — see Part I §1. |
| `legacy_combiner_utils.go` | Package functions re-defined in `combiner_utils.go`; ZoneData methods resolved per §7.3 |
| `legacy_db_combiner_edits.go` | Re-defined on local `HsyncDB` type |
| `legacy_db_combiner_contributions.go` | Re-defined on local `HsyncDB` type |
| `legacy_db_combiner_publish_instructions.go` | Re-defined on local `HsyncDB` type |
| `legacy_gossip.go` | Re-defined in `gossip.go` |
| `legacy_provider_groups.go` | Re-defined in `provider_groups.go` |
| `legacy_parentsync_leader.go` | Re-defined in `parentsync_leader.go` |
| `legacy_signer_msg_handler.go` | Re-defined in `signer_msg_handler.go` |
| `legacy_apihandler_transaction.go` | Re-defined in `apihandler_combiner_routes.go` + `apihandler_agent_routes.go` |

## 9. Original call-site inventory

For the full per-symbol inventory of call sites and line numbers
(the original 18-section exhaustive list), see
`2026-04-14-legacy-dependency-analysis.md`. That document's
sections 1–20 remain accurate as a point-in-time call-site
snapshot. Sections 21 (type aliases), 22 (direct tdns refs),
and "Implications for Cleanup" in that document are superseded
by Part I + Part II here.

---

## Cleanup Implications

1. **deadcode\_\*.go files**: Safe to delete immediately.
2. **One hard step remains**: re-implement `CombinerState` +
   `ProcessUpdate` locally in tdns-mp. This is the last
   method-level cross-repo dependency.
3. **Everything else is a mechanical sweep**: search-and-replace
   `tdns.Foo` → `Foo` for the aliases and direct refs in Part II,
   then flip the alias declarations in `types.go` /
   `agent_structs.go` / `sde_types.go` to local struct
   definitions.
4. **`tdns.Conf.MultiProvider`** in `combiner_utils.go` needs a
   config-pointer injection, but that is independent of the
   type work.
5. **Final batch delete**: `legacy_*.go`, `mpmethods.go`,
   `mptypes.go` in tdns/v2 go away together once Part I is
   empty.
