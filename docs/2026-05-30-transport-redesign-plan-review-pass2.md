# Transport redesign plan — third-pass adversarial review

Date: 2026-05-30 (pass 2, post-amendments)  
Plan: [`2026-05-29-transport-redesign-consolidated-plan.md`](2026-05-29-transport-redesign-consolidated-plan.md)  
Prior review: [`2026-05-30-transport-redesign-plan-review.md`](2026-05-30-transport-redesign-plan-review.md)

This review assumes the Amendments section (lines 250–386) is binding and asks: **what still trips implementation?** Findings are new or escalated; items fully resolved in amendments are not repeated unless the Stage body still contradicts them.

---

## Executive summary

The amendments materially improve the plan. **Implementation is still not safe** for three independent reasons:

1. **The document fights itself** — Amendments resolve D1, A3 field homes, A4 identity fields, A5/C3 ordering, and expanded A2/C scope, but Stage Steps, Open Decisions, probes, and Gaps blocks were **not reconciled**. An implementer following Stage A/C/D Steps will contradict the Amendments.

2. **A5 vs Stage ordering is structurally impossible as written** — Amendments bind A5 after C3 (`HandleSync` gate), but macro-order is **A → C** with A5/A6 inside Stage A. Something must move: A5 to post-C3, or an explicit **A5-pre** mini-step that relocates the LEGACY gate to MP before transport zones are deleted.

3. **Wire-admission layer still uses raw HSYNC3** — A2 fixes membership *display and reconcile*, but `IsPeerAuthorized`, `EvaluateHello`, and beat zone lists still admit any HSYNC3 co-presence, not `zoneParticipants`. A2’s OFF semantics do not hold at the security boundary.

Additional high-severity gaps: inbound message **triple pipeline**, three **LEGACY** definitions, A1 probe marked INVARIANT when behavior **will** change, dead code still on critical paths, and test suite encoding pre-A2 semantics.

---

## Part 1 — Internal document contradictions (will cause wrong commits)

These are not “nice to fix”; they are **fork points** where two sections give different instructions.

| # | Amendments say | Stage body / Open Decisions still say | Impact |
|---|----------------|--------------------------------------|--------|
| 1 | D1 = relocate sequential any-success; **INVARIANT**; open Q5 resolved (`:360-366`) | Stage D Goal “parallel-send”; Step D1 “OPEN DESIGN DECISION”; Open Decisions #1 blocks D1; probe **EXPLAINED DELTA** at D1 (`:664-685`, `:780-782`, `:697-700`) | Wrong D1 implementation |
| 2 | A4: identity fields **MP-side until E1**; ~340 reads; delete `agentStateToTransportStateFn` (`:314-325`) | Step A4 still mandates **A4.0 transport home** for KeyRR/TlsaRR; ~270 reads; only `agentStateToTransportState` (`:480-493`); Gaps A4 block unchanged (`:185-200`) | Wrong A4.0 work |
| 3 | A5 **after C3** or gate moved first (`:327-333`) | Stage A lists A5 before A6; macro **A → C**; no A5-pre step; A5 probe INVARIANT in Stage A (`:494-498`, `:530`) | **Broken sequencing** |
| 4 | A2 full reader set + election probe (`:283-300`) | Step A2 lists three readers only (`:458-464`); A2 probe omits election/`peer list` (`:527`) | Incomplete A2 |
| 5 | A3: delete dead reconcile; RegularS; LocalID on hsync.Registry (`:303-312`) | Step A3 silent on these; Open Decisions #2 still open (`:783-786`) | Incomplete A3 |
| 6 | A1 election kick **identity-only**; not all `OnHsync3Changed` (`:274-277`) | Gaps A1: “add election kick to `OnHsync3Changed`” without gate (`:178-180`) | Over-trigger elections |
| 7 | C3 role sets, inline ACK, third authz, C5 callbacks (`:335-358`) | Steps C3/C5 unchanged; Stage C probe omits combiner async, query-mode manifest (`:604-621`, `:631-656`) | Incomplete C |
| 8 | E1 three discovery paths (`:368-373`) | Step E1 two paths only (`:725-729`) | Incomplete E |
| 9 | F1 all gossip JSON tags (`:375-379`) | Step F1 only BeatRequest/Response (`:754-760`) | Incomplete F1 |
| 10 | A1: engine reconcile live; delete agent `ReconcileHsync` in A2 (`:451-452`) | A3 amendments also say delete on embed (`:303-305`) | Minor: pick one Step |

**Recommendation before any code:** one editorial pass that **replaces** Stage Steps and Open Decisions with amendment text, or marks Gaps/Steps as “superseded by Amendments §X” inline. Until then, treat **only lines 250–386 + Execution checklist** as authoritative for disputed items.

---

## Part 2 — New code gaps (not in amendments)

### BLOCKING

#### B1 — Auth and HELLO bypass participant semantics

A2 binds OFF excluded everywhere via deleting raw reconcile. **Wire admission does not use participants:**

- `IsPeerAuthorized` → `isInHSYNC` / `isInHSYNCAnyZone`: raw HSYNC3 RRset scan, no OFF filter, no HSYNCPARAM role (`agent_authorization.go:94-207`)
- `EvaluateHello`: same raw co-presence check (`hsync_hello.go:350-370`)

A role-less or OFF identity in HSYNC3 can still pass pre-handler auth after A2 fixes `GetAgentsForZone` and CLI display. **Bind:** repoint auth + HELLO to `zoneParticipants` (or shared helper) in **A2**, not C.

#### B2 — A5 / C3 / Stage A ordering trap

Amendments: A5 requires `HandleSync` zero-`SharedZones` gate moved to MP (C3) first.

Macro-order runs **A5 in Stage A before Stage C exists**. Options (pick one in plan):

- **Option A:** Move Step A5 to **C7** (after C3 handler move).
- **Option B:** Add **A5-pre** within Stage A: relocate LEGACY sync rejection to MP (minimal slice of C3) without full opaque seam.
- **Option C:** Keep transport `SharedZones` until end of Stage C (defer A5 entirely).

Also: Stage C probe lists `TestTransportBoundary_LegacySyncRejection` as INVARIANT (`plan:634`), but that test **requires** `peer.GetSharedZones()` empty on transport peer (`transport_integ_test.go:361-364`, `handlers.go:223-226`). At A5 this test must be **rewritten or retired** — not mentioned in either stage probe.

#### B3 — A1 probe “INVARIANT” is false

Amendments bind `OnLocalRemoved` and delete agent-only remove path. Code gaps amendments under-specify:

1. **`weAreInHSYNC` global abort** — `UpdateAgents` ignores all remote processing when local identity not in HSYNC3 (`agent_utils.go:907-910`). `ApplyHsyncDiff` has no equivalent; local removal calls `OnLocalRemoved` per remove RR but **continues processing remotes** and always fires `OnHsync3Changed` (`hsync/hsync3_diff.go:99-116`).

2. **`members == nil` fallback** — when zone view unavailable, adds proceed without participant gate (`hsync/hsync3_diff.go:47-51`, `:75-78`), contradicting A2 OFF-everywhere binding for **incremental** path.

**Bind:** A1 probe row must be **EXPLAINED DELTA** for local-dropout and transient role-less adds; add regression tests.

#### B4 — Agent PostRefresh wiring shape unspecified

Auditor calls `ApplyHsyncDiff` **directly** in PostRefresh (`hsync_utils.go:1472-1480`). Agent still enqueues SyncQ → `SyncRequestHandler` → `UpdateAgents` (`:1456-1463`, `hsyncengine.go:22-27`).

A1 must bind: agent PostRefresh **mirrors auditor** (direct `ApplyHsyncDiff` on `HsyncChanged`), not only swapping the handler body behind SyncQ. Param-only recompute depends on calling diff path when `HsyncChanged` true with empty HSYNC3 delta — `ApplyHsyncDiff` always invokes `OnHsync3Changed` at end (`hsync3_diff.go:114-115`), but only if something calls it.

Sub-step: delete or narrow `HSYNC-UPDATE` branch in `SyncRequestHandler`; SyncQ remains for `SYNC-DNSKEY-RRSET` and other commands (`hsync_utils.go:1441-1446`).

#### B5 — `OnLocalRemoved` / host callbacks not in engine factory

`newAuditorHsyncEngine` wires `OnHsync3Changed` only (`hsync_bridge.go:301-306`). No `OnLocalRemoved`. A1-3 cannot land until `HostCallbacks` extended in the shared factory used by agent and auditor.

---

### HIGH

#### H1 — Inbound DNS message triple pipeline (not in A3 scope)

Every inbound DNS beat today:

1. `routeBeatMessage` — updates `transport.PeerRegistry`, `AgentRegistry`, merges DNS gossip, enqueues `MsgQs.Beat` (`hsync_transport.go:704-789`)
2. `adaptBeatReports` — calls `AgentRegistry.HeartbeatHandler` (counters; API gossip) (`auditor_engine.go:273-274`, `hsync_beat.go:11-55`)
3. `hsync.Engine.heartbeatHandler` — updates `hsync.Peer` (`hsync/beat.go:11-30`)

Hello and app messages follow the same **route* → adapt* → engine** pattern via `routeIncomingMessage` (`hsync_transport.go:566-596`) and `HsyncDataEngine`/`AuditorEngine`.

A3 embed merges peer **maps** but does not bind collapsing this **dispatch stack**. Risk: duplicate gossip merge, torn liveness, lock races (`routeBeatMessage` without `agent.Mu` vs `HeartbeatHandler` with lock).

**Bind in A3:** single inbound path per message type after embed; delete redundant updates explicitly.

#### H2 — Three LEGACY definitions

| Definition | Location | Criterion |
|------------|----------|-----------|
| MP `AgentStateLegacy` | `RecomputeSharedZonesAndSyncState` | `len(agent.Zones)==0` (`agent_utils.go:64-73`) |
| Transport sync gate | `HandleSync` | `len(peer.GetSharedZones())==0` (`handlers.go:223-226`) |
| Auth bypass | `IsPeerAuthorized` | `agent.State == AgentStateLegacy` (`agent_authorization.go:44-52`) |

A2/A5/C3 can desync these. Plan does not define LEGACY lifecycle after membership is derived. **Bind:** one definition or explicit mapping table before A5-pre.

#### H3 — `AgentRegistry.RemoteAgents` drift (A1–A6 window)

Amendments mention repointing reads; not **write path**. Hsync removes update `hsync.Registry.RemoteAgents` (`hsync/registry.go:77-93`); bridge syncs `agent.Zones` via `SyncPeerZones` but **not** `AgentRegistry.RemoteAgents` (only `RemoveRemoteAgent` at `agent_utils.go:745-762`). Debug dump still exports stale index (`apihandler_agent.go:855-857`).

#### H4 — Fourth discovery entry (peer reset)

E1 binds three paths; **`apihandler_peer.go:136`** calls legacy `attemptDiscovery` directly on peer reset, bypassing `hsync.Engine.MarkNeeded` / `DiscoverPeer` seam. Add to E1 inventory.

#### H5 — Combiner/signer C3 without `AgentRegistry`

`initMPCombiner` / `initMPSigner` build `MPTransportBridge` with config-only `AuthorizedPeers`, no `AgentRegistry` (`main_init.go:363-384`, `:302-318`). C3 amendments say preserve role handler sets but not **where** combiner/signer register dispatch (today `main_init.go` + transport `router_init.go`). Agent-only `RegisterAppHandler` loop is insufficient.

#### H6 — Beat outbound zones still from transport `SharedZones`

Outbound beat payload zones come from `peer.GetSharedZones()` (`tdns-transport/v2/transport/dns.go:280-293`), populated from stored `agent.Zones` in `RecomputeSharedZonesAndSyncState` (`agent_utils.go:87-91`). Until A2-driven membership feeds that path, beats advertise **stored** zones, not derived participants — undermines A2 wire semantics before A5.

#### H7 — Dead code still on hot or confusing paths

| Dead / stale | Evidence |
|--------------|----------|
| `AgentRegistry.SendHeartbeats` | Defined `hsync_beat.go:57`; **zero callers** (engine `sendHeartbeats` is live) |
| `AgentRegistry.ReconcileHsync` | Zero callers; tests still target it |
| `start_auditor.go` header | “Does NOT run HsyncEngine” (`:11-13`) — false; `AuditorEngine` runs `hsync.Engine` (`auditor_engine.go:39-55`) |
| Comments referencing `DiscoveryRetrierNG` in `hsyncengine.go` | Moved to `hsync/discovery.go:retryPendingDiscoveries` |

A3 “retire one hello path” should include deleting dead `SendHeartbeats` and agent `HelloRetrierNG` **if** engine path is sole owner — verify no `HsyncEngine == nil` fallback in production.

#### H8 — Test suite encodes wrong semantics post-A2

- `hsync_reconcile_test.go` tests dead `reconcileZone` + raw HSYNC3 (`:33-68`)
- `hsync/engine_test.go` `mockZone.Participants()` returns all HSYNC3 identities (`:62-69`) — production uses OFF-filtered `zoneParticipants`

Stage 0 fixes compile only. **Bind:** Stage A2 includes rewriting or deleting agent reconcile tests; fix hsync mocks to match participant semantics or probes lie.

#### H9 — Auditor double `RecomputeGroups`

Auditor PostRefresh: `ApplyHsyncDiff` → `OnHsync3Changed` (RecomputeGroups) **plus** direct `RecomputeGroups` (`hsync_utils.go:1477-1484`). Agent branch after A1 inherits this unless deduped — gossip matrix timing can differ from INVARIANT prediction.

---

### MEDIUM

#### M1 — Verified status naming collision

Line 122–124: “membership-from-HSYNCPARAM (Stage **A3**) substantially landed” refers to **Bug-1 membership derivation**, not **Stage A Step A3 embed**. Implementers will mis-read progress on embed work.

#### M2 — Third repo build discipline

Step rule: all **three** repos build (`plan:39-40`). `go.mod` replace: `tdns`, `tdns-transport`, tdns-mp (`_test-ext/v2/go.mod:8-11`). Stage A probe runs only tdns-mp tests (`plan:509-511`). **`tdns/v2` not bound** on A-stage commits.

`cmd/transport-exercise` is a second transport consumer — not in plan; may break on C API changes if not in CI.

#### M3 — `mergeAgentDetails` fill-only stale state

Bridge only fills empty fields (`hsync_bridge_sync.go:163-190`). Cleared hsync address/state never propagates to agent until full replace via `SyncPeerZones`. Survives through A6 — amplifies Bug-2 class during transition.

#### M4 — `hsync/hello.go` `helloHandler` is stub

`helloHandler` body empty (`hsync/hello.go:11-14`). Inbound hello state changes happen in `routeHelloMessage` + API handlers, not engine. A3 “keep hsync hello path” mostly means **outbound** `helloRetrierNG` from discovery — plan should say so to avoid wiring inbound to stub.

#### M5 — Infra virtual peers (combiner/signer on agent)

Agent process registers combiner/signer as virtual peers in **AgentRegistry** (`start_agent.go:73-76`, `combiner_peer.go`, `signer_peer.go`) while combiner/signer processes use **PeerRegistry only**. A4 scope lists infra peers but not this **cross-role asymmetry** — affects reachability probes (“combiner remains reachable”).

#### M6 — `SendStatusUpdate` fire-and-forget

No confirm wait (`tdns-transport/v2/transport/dns.go:904-962`). C2 generic send must preserve; not in Stage C Steps.

#### M7 — Cross-stage heterogeneous fleet vs C mixed migration

Gaps warn half-migrated C fleets brittle (`plan:221-224`). No **upgrade runbook Step** before C1 (fleet-wide prompt). Operational gap.

---

## Part 3 — Probe and halt-condition updates needed

| Step | Current probe | Should be |
|------|---------------|-----------|
| A1 | INVARIANT membership | **EXPLAINED DELTA** for local HSYNC3 dropout, `members==nil` transient adds, election timing if double RecomputeGroups |
| A2 | Role-less identity delta | **Add** election quorum convergence, `peer list` visibility, **auth/HELLO rejection** of role-less sender |
| A5 | INVARIANT in Stage A | **Move probe** to post-C3 or split A5-pre; **rewrite** `LegacySyncRejection` test |
| Stage C | `LegacySyncRejection` INVARIANT | Contradicts A5 timing — reconcile when A5 moves |
| Stage A automated | tdns-mp only | Add `tdns/v2` compile at minimum per global Step rule |

---

## Part 4 — Recommended plan patches (priority order)

1. **Doc reconcile** — Merge amendments into Stage Steps; delete resolved Open Decisions #1 and #2; fix Verified status “A3” wording.
2. **Resolve A5 placement** — Explicit cross-stage Step ID (A5-pre, C3.5, or C7).
3. **Extend A2 scope** — `agent_authorization.go`, `EvaluateHello`, beat zone list source; bind before A2 probe.
4. **A1 sub-steps** — A1.0 host callbacks; A1.1 direct PostRefresh `ApplyHsyncDiff`; A1.2 SyncQ/`HSYNC-UPDATE` deletion scope; fix A1 probe prediction.
5. **A3 inbound pipeline** — Collapse route/adapt/engine triple path; delete dead `SendHeartbeats`.
6. **LEGACY table** — Single definition or explicit mapping before A5-pre.
7. **A2 tests** — Rewrite `hsync_reconcile_test.go`; fix `mockZone.Participants`.
8. **E1** — Add peer-reset `attemptDiscovery` path.
9. **C3** — Combiner/signer dispatch init without AgentRegistry.
10. **Stage probes** — Query-mode manifest; combiner async confirm; third-repo build.

---

## Part 5 — Open questions (still unresolved after amendments)

1. **A5 placement:** C7 vs A5-pre vs defer — which option?
2. **LEGACY after derived membership:** Keep concept, redefine, or delete with A5-pre?
3. **Inbound pipeline:** Does A3 embed collapse route*Message into engine, or does C3 move route* first?
4. **Auth participant gate:** A2 or C5? (Recommend A2 — security boundary.)
5. **`RemoteAgents` index:** Delete entirely post-embed, or derive from hsync registry on read?

---

## Conclusion

The amendments closed most first-review holes in **intent**, but the plan is now a **split document**: binding decisions live in one section while executable Steps still describe superseded work. That alone is enough to cause a failed migration.

The highest-stakes **new** finding is the **A5 vs Stage-A-before-C** impossibility, followed by **auth/HELLO still on raw HSYNC3** (A2 incomplete at the wire boundary) and the **inbound triple pipeline** (A3 embed scope too narrow).

Fix the document fork first, then bind A5 placement and A2 auth before cutting the implementation branch.
