# Transport redesign plan — adversarial code review

Date: 2026-05-30  
Reviewer: code-to-plan comparison against `_test-ext` (tdns-mp) and `tdns-transport`  
Plan under review: [`2026-05-29-transport-redesign-consolidated-plan.md`](2026-05-29-transport-redesign-consolidated-plan.md)

## Executive summary

The consolidated plan is **well grounded**: the 2026-05-30 Gaps section correctly identifies the highest-risk failure modes (A1 behavior drops, A4 blast radius, A3 concurrency, C5 authz ordering, Stage 0 RED tests). A code pass against `_test-ext` and `tdns-transport` **confirms** those claims and surfaces **additional gaps** the plan should bind before execution.

**Verdict:** Proceed with the A → C → D → E → F sequence, but treat this review as a required amendment pass. The plan is not yet safe to execute step-by-step without addressing the items marked **BLOCKING** below.

**Top five additions beyond the plan's own Gaps section:**

1. **BLOCKING — A1 asymmetric add/remove path:** Agent adds go through `hsync.Engine.MarkNeeded` (hsync registry + transport); agent removes go only to `AgentRegistry.RemoveRemoteAgent` and **never** call `hsync.Registry.RemovePeerFromZone`. Swapping to `ApplyHsyncDiff` fixes removes on the hsync side but the plan does not explicitly require retiring the agent-only remove path or reconciling the two stores during transition.
2. **BLOCKING — `ReconcileHsync` is dead code:** The plan says "keep `ReconcileHsync` as safety net" (A1), but `AgentRegistry.ReconcileHsync` has **zero callers**; the live safety net is `hsync.Engine.runReconcile`. Misleading wording risks duplicate reconcile logic after A3 embed.
3. **BLOCKING — A2 scope under-specified:** At least eight additional sites read stored `agent.Zones` or raw HSYNC3 counts, including `SetConfiguredPeersFunc` (election quorum uses raw HSYNC3 RR count − 1, not `zoneParticipants`).
4. **HIGH — D1 mischaracterized:** Parallel Hello/Beat fan-out already exists in MP (`SendHelloWithFallback` / `SendBeatWithFallback`); D1 is relocation into TM, not greenfield design. Success rule is implicitly "any mechanism succeeds" today.
5. **HIGH — Stage C role-specific dispatch omitted:** Combiner `update` handler, signer subset routers, inline ACK/`ctx.Data["response"]` semantics, and a third authz layer (`AuthorizationMiddleware` after chunk handler) are not in C3 scope.

---

## Methodology

- Read-only inspection of `_test-ext/v2/**` and `tdns-transport/v2/transport/**`.
- Verified compile state: `go test ./...` in `_test-ext/v2` **fails** on the four errors cited in Stage 0.
- Cross-checked plan file:line references; noted drift where `_test-ext` (peer-discovery-engine-extraction branch) differs from stock `tdns-mp`.
- Counted `.ApiDetails`/`.DnsDetails` references: **~340** across `v2/**/*.go` (plan cites ~270).

---

## Confirmed plan strengths

| Area | Assessment |
|------|------------|
| Target architecture (two stores, PeerID join, opaque carrier) | Matches code pain points; bridge is the root of Bug 1/2 class |
| Stage ordering A before C | Correct — registry overlap is the live bug source |
| A1 re-home requirement (RFI, election, param-only recompute) | **Confirmed** at `agent_utils.go:933-1044`; `ApplyHsyncDiff` passes `nil` deferred tasks (`hsync/hsync3_diff.go:82`) and `OnHsync3Changed` only calls `RecomputeGroups` (`hsync_bridge.go:302-305`) — no election |
| A3 concurrency warning | **Confirmed** — dual mutex (`Agent.Mu`, `hsync.Peer.Mu`), `RecomputeSharedZonesAndSyncState` holds `agent.Mu` across transport calls (`agent_utils.go:61-92`) |
| A4 scope | **Confirmed** and **larger** than plan (~340 reads, 13+ files including `hsync/`, combiner/signer peers, `db_hsync.go`, CLI) |
| C infrastructure exists | `RouteToCallback`, `DNSMessageRouter`, token-keyed handlers — C is mostly relocation |
| C5 pre-crypto authz invariant | **Confirmed** — `IsPeerAuthorized(sender, "")` before fetch/decrypt (`chunk_notify_handler.go:434-447` before `:464-486`) |
| Stage 0 RED tests | **Confirmed** — `apihandler_agent_test.go:34`, `hsync_reconcile_test.go:47,97` |
| Persistence in-memory only | **Confirmed** — `db_hsync.go` CRUD never written; `ListPeers` is read-only phantom |

---

## Stage 0 — pre-work

### Confirmed

- Test compile failures block probe baseline (verified by `go test ./v2/...`).
- Dead `PeerRegistry`/`PeerZones` DB layer (`db_hsync.go`, `db_schema_hsync.go`); only consumer is CLI returning empty.

### Gaps to add

| ID | Severity | Gap |
|----|----------|-----|
| S0-1 | MEDIUM | Delete orphan converters `PeerRecordFromAgent` / `PeerRecordFromTransportPeer` (`db_hsync.go:478-561`) with CRUD — otherwise A4 leaves dead code |
| S0-2 | LOW | Test fixes must use `*MultiProviderConf` (tdnsmp type) / `conf.InternalMp.MpConfig`, not `tdns.Config.MultiProvider` — production already migrated (`config.go:29`, `agent_structs.go:268`) |

**Recommendation:** Stage 0 Step 0.1 = fix tests; Step 0.2 = delete phantom DB layer + converters. Capture probe baseline only after 0.1.

---

## Stage A — registry consolidation

### A1 — ApplyHsyncDiff migration

#### Confirmed (plan Gaps section)

- Agent `PostRefresh` → `SyncQ` → `UpdateAgents` (`hsync_utils.go:1456-1463`); auditor uses `ApplyHsyncDiff` (`:1472-1480`).
- Three behaviors to re-home before swap: upstream/downstream CONFIG RFI deferred tasks, membership-change election kick, HSYNCPARAM-only `RecomputeGroups`.

#### New gaps

| ID | Severity | Gap | Evidence |
|----|----------|-----|----------|
| A1-1 | **BLOCKING** | **Asymmetric add/remove:** `UpdateAgents` removes via `RemoveRemoteAgent` only (`agent_utils.go:1004-1005`) — does not call `hsync.Registry.RemovePeerFromZone`. Adds via `MarkAgentAsNeeded` → engine path update hsync registry. Stores diverge on incremental agent removes until engine reconcile. | `agent_utils.go:991-1006` vs `hsync/hsync3_diff.go:105` |
| A1-2 | HIGH | `ApplyHsyncDiff` always `MarkNeeded(..., nil)` — RFI tasks need explicit extension (plan mentions re-home but not API shape: extend `ApplyHsyncDiff`, `MarkNeeded` callback, or `OnHsync3Changed` with zone+diff context). | `hsync/hsync3_diff.go:82` |
| A1-3 | HIGH | `weAreInHSYNC` guard in `UpdateAgents` (`:907-910`) — early return if local identity not in HSYNC3 RRset. `ApplyHsyncDiff` has no equivalent for remote processing; `OnLocalRemoved` exists (`hsync3_diff.go:100-102`) but is **not wired** in `hsync_bridge.go`. | |
| A1-4 | MEDIUM | `CleanupZoneRelationships` is TODO stub (`agent_utils.go:869-871`), invoked on local identity removal (`:1000-1002`). Fate undecided before dropping `UpdateAgents`. | |
| A1-5 | **BLOCKING** | Plan says "keep `ReconcileHsync` as safety net" — **`ReconcileHsync` has zero call sites** (only definition at `hsync_reconcile.go:31`). Live loop: `hsync.Engine.runReconcile` (`engine.go:59`, `reconcile.go:83`). Wording must change to avoid resurrecting dead reconcile. | grep: no `ReconcileHsync(` callers |
| A1-6 | MEDIUM | Election kick must stay gated on HSYNC3 **identity** changes (`len(updatedIdentities) > 0`), not all `OnHsync3Changed` invocations — param-only changes should recompute groups but not kick election (matches `UpdateAgents` today). | `agent_utils.go:1018-1030` vs `:1037-1039` |
| A1-7 | LOW | Auditor PostRefresh calls `RecomputeGroups` directly after `ApplyHsyncDiff` (`hsync_utils.go:1482-1484`) in addition to `OnHsync3Changed` — agent branch needs parity or dedup to avoid double recompute. | |

**Recommended A1 sub-steps (bind in plan):**

- **A1.0** — Re-home RFI deferred tasks + election kick + param-only recompute (plan already says this).
- **A1.0b** — Wire `OnLocalRemoved` → `CleanupZoneRelationships` (or implement cleanup).
- **A1.1** — Route agent PostRefresh through `ApplyHsyncDiff`; **delete** agent-path `RemoveRemoteAgent` for HSYNC removes (hsync registry becomes authoritative for removes).
- **A1.2** — Delete or repoint dead `ReconcileHsync` / `reconcileZone` in `hsync_reconcile.go` (see A2).

---

### A2 — membership derivation

#### Confirmed

- `reconcileZone` uses raw `hsync3IdentitiesFromRRset` — no OFF filter, no HSYNCPARAM gate (`hsync_reconcile.go:100-102`, `:142-158`).
- `GetAgentsForZone` reads `agent.Zones` (`agent_utils.go:45-54`).
- `listPeerSharedZones` reads `agent.Zones` (`apihandler_agent_distrib.go:606-608`).
- `hsync.Engine.ReconcileZone` already uses `Participants()` (`hsync/reconcile.go:25-29`).

#### New gaps — readers plan does not list

| ID | Severity | Site | Issue |
|----|----------|------|-------|
| A2-1 | **BLOCKING** | `SetConfiguredPeersFunc` (`start_agent.go:137-145`) | Election quorum = raw HSYNC3 RR count − 1, not `zoneParticipants` |
| A2-2 | HIGH | `listAgentsForZone` | `apihandler_agent_distrib.go:649`, `apihandler_shared_distrib.go:43`, `cli/agent_cmds.go:177` |
| A2-3 | HIGH | `NotifyPeerOperational(agent.Zones)` | `hsync_transport.go:726` — election tied to stored zones |
| A2-4 | MEDIUM | `sharedZonesForAgent` / hello zone list | `hsync_hello.go:26-30`, `:162` |
| A2-5 | MEDIUM | `peer list` display filters | `apihandler_agent_distrib.go:356,414` — hides peers with `len(agent.Zones)==0` |
| A2-6 | MEDIUM | CLI debug | `cli/hsync_cmds.go:537` |
| A2-7 | MEDIUM | `RemoteAgents` map | `agent_structs.go:266` — parallel zone index, not derived |
| A2-8 | MEDIUM | OFF HSYNC3 filter mismatch | `zoneParticipants` skips OFF (`provider_groups.go:100`); `hsync3IdentitiesFromRRset` does not (`hsync_reconcile.go:149`) — A2 must pick one semantics |

**Recommendation:** Expand A2 probe prediction to include election quorum (`gossip state` leader convergence) and `peer list` visibility for role-less identities. Add explicit Step: repoint `SetConfiguredPeersFunc` to `zoneParticipants` count.

---

### A3 — embed hsync.Registry

#### Confirmed

- No embedding today; two peer maps (`agent_structs.go:264`, `hsync/registry.go:15`).
- Dual mutex: `Agent.Mu` vs `hsync.Peer.Mu`.
- Plan's `RecomputeSharedZonesAndSyncState` refactor requirement is valid.

#### New gaps

| ID | Severity | Gap |
|----|----------|-----|
| A3-1 | HIGH | **Dual hello/discovery paths:** legacy `AgentRegistry.attemptDiscovery` (`agent_utils.go:588+`), `hsync_hello.go`, `helloContexts` vs `hsync/discovery.go` + `helloCancel`. Embed without retiring one path risks duplicate HELLO goroutines. |
| A3-2 | HIGH | **`RegularS`** third agent map (`agent_structs.go:265`) — debug/API only (`apihandler_agent.go:856`, `cli/agent_debug_cmds.go:208-219`). Embed scope must decide keep/delete/merge. |
| A3-3 | HIGH | **Bridge overwrite semantics:** `SyncPeerZones` replaces full agent from hsync peer (`hsync_bridge.go:120-123`); `mergeAgentDetails` is fill-only (`hsync_bridge_sync.go:163-191`) — stale address/state can persist when hsync clears fields. |
| A3-4 | MEDIUM | **Lock ordering:** `syncHsyncPeerFromAgent` holds agent `RLock` then peer `Lock` (`hsync_bridge_sync.go:45-48`); `SendHello`/`SendBeat` read agent then call transport (`hsync_bridge.go:57-69`). Embed must define single lock order. |
| A3-5 | MEDIUM | Plan says unify reconcile loops — only engine loop runs today; `ReconcileHsync` is dead. A3 should **delete** agent reconcile, not merge two live loops. |

**Mutex rule (proposed binding):** After embed, one mutex per peer; **never hold registry mutex across transport peer registry calls** — template: refactor `RecomputeSharedZonesAndSyncState` first (plan already says this).

---

### A4 — transport sole owner of address + mechanism state

#### Confirmed

- `SyncPeerFromAgent` one caller: `OnPeerDiscovered` (`hsync_transport.go:457`).
- `KeyRR`/`TlsaRR`/`JWKData`/`KeyAlgorithm` on `AgentDetails` / `hsync.PeerDetails`, not `transport.Peer`.
- Bridge drops crypto material on hsync↔agent copy — `hsync.PeerDetails` lacks `KeyRR`/`TlsaRR` (`hsync/types.go:67-85`, `hsync_bridge_sync.go:87-109`).

#### New gaps

| ID | Severity | Gap |
|----|----------|-----|
| A4-1 | HIGH | Duplicate `agentStateToTransportStateFn` (`agent_structs.go:216-234`) alongside `agentStateToTransportState` — delete both in A4, not one. |
| A4-2 | HIGH | Infra virtual peers (`combiner_peer.go`, `signer_peer.go`) write dup fields — in A4a scope. |
| A4-3 | HIGH | **`EffectiveState` / `IsAnyTransportOperational` / `APIMechanismState`** accessors (`agent_structs.go:109-177`) — plan lists send path but not canonical accessors used widely. |
| A4-4 | MEDIUM | `db_hsync.go` conversion helpers tie to phantom persistence — delete with A4b or Stage 0. |

**A4.0 decision still open:** Put identity crypto fields on `transport.Peer` vs declare MP-only metadata until Stage E. Recommendation: **MP-only until E1** (discovery resolves keys; transport needs TLSA for wire verify only). Plan should pick one and bind probe (combiner reachability + chunk crypto).

---

### A5 / A6 — zones in transport + bridge teardown

#### Confirmed

- `transport.Peer.SharedZones`, `ByZone`, etc. (`peer.go:81,546-688`); MP callers at `agent_utils.go:87-91`, `hsync_transport.go:1493-1494`.
- No `OnPeerRemoved` anywhere.
- Nine bridge functions in `hsync_bridge_sync.go` + `OnPeerStored` (`hsync_bridge.go:299`).

#### New gaps

| ID | Severity | Gap |
|----|----------|-----|
| A5-1 | **BLOCKING** | `HandleSync` rejects zero shared zones (`handlers.go:223-246`). A5 must land **after** send/authz paths no longer depend on transport `SharedZones`, or addrr round-trip probe fails. |
| A6-1 | HIGH | Bridge teardown list incomplete: entire `mpHsyncBridge` type, `SyncPeerZones` shim, `PopulateFromAgent`, `agentStateToTransportState` path. |
| A6-2 | MEDIUM | Partial remove today via `ApplyHsyncDiff` → `RecomputeSharedZones` → `SyncPeerZones` → overwrites agent from hsync — event path for `OnPeerRemoved` still needed for gossip/CLI latency (plan EXPLAINED DELTA is correct). |

---

## Stage C — opaque-message seam

### Confirmed

- `SyncRequest` MP semantics, no `TypeToken`/`Payload` (`transport.go:153-168`).
- `RouteToCallback` live at MP `hsync_transport.go:559-561`.
- 8 MP handlers vs 4 transport-own (`handlers.go`).
- C5 cut-line and pre-crypto authz ordering correct.
- Wire `"MessageType"` in JSON payload (`chunk_notify_handler.go:256`); query-mode manifest `content` (`distrib/manifest.go:82`).

### New gaps

| ID | Severity | Gap |
|----|----------|-----|
| C-1 | HIGH | **Send method count:** plan says 12; interface has 11 typed sends (+ `TransportManager.Send`). Minor doc fix. |
| C-2 | **BLOCKING** | **Role-specific routers post-C3:** Combiner `NewCombinerSyncHandler` / `HandleUpdate` (`combiner_chunk.go:1428-1455`); signer keystate/rfi/status subset (`router_init.go:507-537`); combiner beat/hello/ping+rfi (`router_init.go:328-378`). Plan's single `RegisterAppHandler` loop is insufficient. |
| C-3 | HIGH | **Inline ACK semantics:** handlers set `ctx.Data["response"]` for NOTIFY confirm path (`HandleSync` `:266-280`, `HandleKeystate` `:380-399`, combiner pending ack). C3 must preserve or relocate — probe `ConfirmInlineResponsePrep` alone may miss combiner async confirm. |
| C-4 | HIGH | **Third authz layer:** after chunk handler zone authz, `AuthorizationMiddleware` runs again (`router_init.go:62-64`, `crypto_middleware.go:222-274`). C5 must decide keep/merge/remove — plan only discusses two `IsPeerAuthorized` calls in chunk handler. |
| C-5 | HIGH | **`ChunkHandler` MP callbacks** not enumerated: `IsPeerAuthorized`, `OnConfirmationReceived`, `GossipForPeer`, `OnPeerDiscoveryNeeded` (`hsync_transport.go:321-394`, `:405-416`). C5 scope should list them. |
| C-6 | MEDIUM | **`routeIncomingMessage` duplicate verb table** in MP (`hsync_transport.go:567-595`) — C3 must collapse with transport router, not add a third table. |
| C-7 | MEDIUM | **`SendStatusUpdate` fire-and-forget** (no confirm wait, `dns.go:904-962`) — C2 generic `Send` must preserve semantics. |
| C-8 | MEDIUM | **A5/C ordering:** `HandleSync` shared-zones gate depends on transport zones — sequence A5 before or with C3 handler move. |
| C-9 | MEDIUM | **Probe gap:** `TestTransportBoundary_ChunkToMsg` bypasses wire (injects post-decrypt message); does not assert manifest `content`. Add query-mode manifest probe per plan caveat. |
| C-10 | LOW | Uppercase `MessageType*` constants in `dns_message_router.go:23-30` unused for routing — C6 cleanup. |
| C-11 | MEDIUM | **Lock inconsistency in relocated handlers:** `routeHelloMessage` holds `agent.Mu` (`hsync_transport.go:623-632`); `routeBeatMessage` updates agent **without** `agent.Mu` (`:716-719`). C3 move must apply A3 mutex rule. |

### C5 / in-channel CHUNK collision

**Confirmed** — same files (`chunk_notify_handler.go`, `crypto.go` `IsPayloadEncrypted()`). Plan sequencing note is correct; bind: envelope-mode indicator lands with or immediately before C5.

### F1 blast radius (Stage C interaction)

`Gossip` JSON tags inconsistent: `BeatRequest` uses `json:"gossip,omitempty"` (`transport.go:137`); `DnsBeatPayload` uses `json:"Gossip,omitempty"` (`dns.go:1253`). F1 scope in plan is too narrow — list all tag sites in F1 Step.

---

## Stage D — liveness & send semantics

### Confirmed

- TM `Send` rejects Hello/Beat (`manager.go:346`).
- Manual liveness in combiner/signer handlers and `routeHello`/`routeBeat`.

### New gaps

| ID | Severity | Gap |
|----|----------|-----|
| D-1 | HIGH | **D1 is relocation, not invention:** `SendHelloWithFallback`/`SendBeatWithFallback` already try API and DNS sequentially; comment says "ANY transport succeeds" (`hsync_transport.go:1535-1604`). Open decision is formalizing rule in TM, not designing parallel send from scratch. |
| D-2 | MEDIUM | **Sequential not parallel today:** API Hello then DNS Hello — not concurrent fan-out. If D1 goal is true parallel, that's a behavior change beyond current code; probe EXPLAINED DELTA should say so. |
| D-3 | MEDIUM | D3 lifecycle scattered across role `start_*.go` and `main_init.go` — enumerate all registration sites in Step (chunk notify, incoming router, role routers). |

---

## Stage E — discovery

### Confirmed

- `DiscoveryDriver = tm`, `RunDiscovery` → `DiscoverAndRegisterAgent` (`hsync_transport.go:491-505`).
- HSYNC3-driven "who" stays in MP (MarkNeeded) — correct.

### New gaps

| ID | Severity | Gap |
|----|----------|-----|
| E-1 | **BLOCKING** | **Three discovery entry points:** (1) `hsync/discovery.go` → `DiscoverPeer` seam, (2) legacy `AgentRegistry.attemptDiscovery` (`agent_utils.go:588+`) via `DiscoveryRetrierNG` / `apihandler_peer.go:136`, (3) `OnPeerDiscoveryNeeded` on chunk handler (`hsync_transport.go:379-394`). E1/E2 must unify all three — plan cites only `agent_discovery.go` body. |
| E-2 | MEDIUM | `_test-ext` already routes `MarkAgentAsNeeded` → `HsyncEngine.MarkNeeded` when engine non-nil (`agent_utils.go:504-515`); legacy path when nil. E1 mapping must use `_test-ext`, not stock tdns-mp. |
| E-3 | MEDIUM | Post-restart KNOWN→OPERATIONAL gap (plan cross-ref) — E probe is correct; fix may touch hello state machine in both MP and hsync paths. |

---

## Stage F — finish

| ID | Severity | Gap |
|----|----------|-----|
| F-1 | MEDIUM | Expand F1 to all `gossip`/`Gossip` JSON tags across beat confirm, DNS payloads, not just `BeatRequest`/`BeatResponse`. |
| F-2 | LOW | Stale `init.go` integration guide references `IncomingChan` goroutine — production uses `RouteToCallback` (`main_init.go:440` sets `IncomingChan: nil`). F3 should include doc/code cleanup. |

---

## Lock contention & race condition matrix

| Location | Current behavior | Risk after A3/C3 | Mitigation (bind in plan) |
|----------|------------------|------------------|---------------------------|
| `RecomputeSharedZonesAndSyncState` | Holds `agent.Mu` during `PeerRegistry.GetOrCreate` + `AddSharedZone` | Deadlock with embed + transport locks | Refactor **before A3** (plan says this) |
| `SendHelloWithFallback` / `SendBeatWithFallback` | Hold `agent.Mu` around transport calls | Contention with beat receive updating same fields | A4: reads/writes move to `transport.Peer`; MP stops dual-write |
| `routeBeatMessage` | Updates `agent.DnsDetails` **without** `agent.Mu` | Data race with hello send path | Fix in A4b or C3 move; apply single-writer rule |
| `routeHelloMessage` | Holds `agent.Mu` during processing | Same | Unify with beat path under A3 mutex rule |
| Dual reconcile (agent vs engine) | Only engine runs; agent reconcile dead | After embed, accidental dual start | Delete `ReconcileHsync` in A2/A3 |
| Bridge `syncHsyncPeerFromAgent` | agent RLock → peer Lock | Lock order inversion with send path | Remove bridge in A6 |
| `ProviderGroupManager.mu` in `BeforeHeartbeats` | Held during gossip refresh | Unchanged | Document: do not acquire `agent.Mu` under PGM lock |

---

## Dropped functionality — halt conditions

If Step lands without re-home, these behaviors **silently disappear**:

| Step | Behavior | Location |
|------|----------|----------|
| A1 | Upstream CONFIG RFI deferred | `agent_utils.go:933-956` |
| A1 | Downstream CONFIG RFI deferred | `agent_utils.go:957-981` |
| A1 | Election kick on HSYNC3 identity change | `agent_utils.go:1018-1030` |
| A1 | Param-only group recompute (if only `OnHsync3Changed` wired without param path) | `agent_utils.go:1037-1039` |
| A2 incomplete | Wrong election quorum | `start_agent.go:137-145` |
| A4 before A4.0 | Combiner/signer reachability, TLSA verify | `agent_setup.go`, infra peers |
| A5 before send-path update | Sync rejected (zero shared zones) | `handlers.go:223-246` |
| C3 | NOTIFY inline ACK / combiner async confirm | `handlers.go`, `combiner_chunk.go` |
| C5 | Pre-crypto authz before fetch | `chunk_notify_handler.go:434` — **DoS vector if moved wrong** |

---

## Probe & test gaps

| Gap | Recommendation |
|-----|----------------|
| Stage 0 RED | Fix before any baseline capture — **verified failing** |
| No transport unit tests for `parsePayload`, `RouteViaRouter`, C5 split | Add minimal characterization tests in C5 Step |
| Boundary harness skips chunk wire layer | Extend `ChunkToMsg` to assert manifest `content` verb |
| No RFI/keystate/election boundary scenarios | Add before C2/C3 or accept runtime-only probe |
| A2 delta may be invisible on testbed | Probe must document "no role-less identity present → INVARIANT in practice" (plan has this — keep) |
| Mixed-fleet during C | Plan warns — add explicit upgrade runbook Step before C1 |

---

## Recommended plan amendments (checklist)

1. **A1:** Add sub-steps A1.0b (local removal / cleanup), A1.1 (fix asymmetric remove), reword "keep ReconcileHsync" → "engine reconcile only; delete dead agent reconcile."
2. **A2:** Append full reader table (A2-1 through A2-8) and `SetConfiguredPeersFunc` to Step scope.
3. **A3:** Add dual-hello retirement, `RegularS` disposition, delete-vs-merge reconcile wording.
4. **A4:** Update read count to ~340; bind A4.0 field-home decision; list infra peers + accessors.
5. **A5/A6:** Bind ordering vs `HandleSync` shared-zones gate; expand bridge teardown inventory.
6. **C3:** Add role-specific dispatch table (agent 8 handlers + combiner update + signer subset).
7. **C5:** Add `ChunkHandler` callbacks + `AuthorizationMiddleware` decision.
8. **D1:** Reword as "relocate existing fallback semantics to TM"; clarify sequential vs parallel.
9. **E1:** Enumerate three discovery entry points.
10. **F1:** Expand JSON tag inventory.
11. **Execution:** Mandate code map refresh on `_test-ext` branch at each Step (plan says this — emphasize vs tdns-mp).

---

## Open questions for operator / plan author

1. **A4.0:** `KeyRR`/`TlsaRR`/`JWKData` on `transport.Peer` or MP-only until E?
2. **A1 remove authority:** After migration, is hsync registry the sole source for add/remove with agent updated only via hooks (`OnPeerStored` / new `OnPeerRemoved`)?
3. **Delete `ReconcileHsync` + tests** or repoint to `Participants()` for documentation value?
4. **OFF HSYNC3 records:** Exclude everywhere (match `zoneParticipants`) or only in participant-gated paths?
5. **D1:** Formalize current sequential "try API then DNS, any success" vs true concurrent parallel — behavior change?
6. **C5 authz:** Keep router `AuthorizationMiddleware` for non-chunk messages only, or merge with MP post-decrypt zone check?
7. **A3 embed:** Final home for `LocalID`, `TransportManager`, `MPTransport` — embedded registry vs outer `AgentRegistry`?

---

## Conclusion

The consolidated plan is the right backbone and its self-adversarial Gaps section (2026-05-30) materially improves safety. This review does **not** recommend resequencing Stages. It recommends **binding the additional gaps above** — especially A1 asymmetric remove, dead `ReconcileHsync` wording, expanded A2 scope, C3 role dispatch, and E1 triple discovery paths — before the first implementation commit on the feature branch.

After amendments, Stage 0 → A1.0 → probe baseline capture is the correct execution entry.
