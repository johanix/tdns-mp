# Transport redesign: consolidated implementation plan

Date: 2026-05-29
Status: SUPERSEDED 2026-06-11 by v2/v3 and 2026-08-24 by v4 (see `2026-08-24-transport-redesign-consolidated-plan-v4.md` and its 2026-09-09/10 amendments); retained as evolution trail. Original status line follows.
Status: AUTHORITATIVE PLAN (in progress — built Stage by Stage with a
code-to-doc mapping pass per Stage). This is the single source of truth
for *direction and sequencing* of the transport redesign.

## Supersession

This doc supersedes, **for planning and sequencing**, the scattered
plan/bite/review docs:
- `2026-04-15-transport-interface-redesign.md` — the 9-phase master.
  Retained as the source of the detailed **A1–A9 inventory** and the
  Phase step lists, cited here as appendices. Its *status annotations*
  and its *two-registry framing* (§C) are superseded (see below).
- `2026-05-19-peer-discovery-engine-extraction.md` — retained for its
  **decisions** (§D-1…D-5, esp. D-3 registry consolidation), folded in.
- `2026-04-30-transport-refactor-semi-easy-bites.md`,
  `2026-05-08-transport-refactor-next-bites.md`,
  `-third-bites.md`,
  `2026-04-30-peerregistry-field-disposition.md`,
  `2026-04-30-chunk-notify-handler-split.md` — retained as detailed
  **disposition tables / cut-lines**, cited per Step rather than
  re-derived. Several of their bites are already landed (see Status).
- `2026-05-28-transport-redesign-review.md` — the review that motivated
  this plan (gap analysis, effort, the opaque-message seam). Input, not
  plan.

Where this doc and an older doc disagree, **this doc wins** for what to
build next; the older docs win for the fine-grained field/method detail
they enumerate.

## Terminology

- **Stage** — a priority-ordered grouping of related work (A, C, D, E,
  F). Replaces the master doc's "Phase 1–9" numbering, which is stale
  and fragmented across docs.
- **Step** — the atomic unit of work. The test for a valid Step: it
  lands as **one commit**, leaves **all three repos building**, is
  **wire-compatible** (or explicitly flagged as a wire break), and is
  **independently verifiable** via the Stage's Characterization Probe.

(The master doc's "Phase N" and the bite docs' "Bite X" are referenced
where a Step maps to them, so cross-checking stays possible.)

## Target architecture (end state)

One sentence: **two peer-state stores, partitioned by concern, joined
only by `PeerID`; transport speaks an opaque-message vocabulary; zone
membership is derived from HSYNCPARAM, not stored-and-synced.**

1. **`transport.PeerRegistry` owns transport state** — identity,
   addresses (`Discovery`/`Operational`), per-mechanism state
   (`Mechanisms`), crypto keys, liveness, transport selection, stats.
   It is the sole source of truth the send path reads. It knows nothing
   about zones, roles, agents, combiners, signers.
2. **One MP-side registry owns app metadata** — per 2026-05-19 §D-3,
   `AgentRegistry` *embeds* `*hsync.Registry`; `hsync.Registry` owns the
   peer map + protocol methods, `AgentRegistry` retains
   gossip/groups/elections/transport-manager/local-identity. This
   collapses today's two MP-side stores into one. It holds zones/roles/
   scopes — but **derives** zone membership from HSYNCPARAM roles
   (resolved via ON HSYNC3 labels) rather than keeping a parallel
   synced copy.
3. **Coupling is by `PeerID` only.** `Agent` has a `PeerID`; when MP
   needs transport state it calls `peerRegistry.Get(peerID)`. No
   bidirectional sync functions — `SyncPeerFromAgent`,
   `agentStateToTransportState`, `hsyncPeerToAgent`,
   `mergeAgentDetails` are all deleted.
4. **Transport vocabulary is `hello / beat / ping / confirm / chunk`
   plus ONE generic opaque app-message carrier**
   (`{Scope, TypeToken, Payload}`). Every MP verb — SYNC, UPDATE, RFI
   and its subtypes KEYSTATE/EDITS/CONFIG/AUDIT/ELECT-*/STATUS — is an
   app-level `TypeToken` value transport never interprets. Send side:
   the typed `DNSTransport.Sync/Keystate/Edits/Config/Audit` methods
   collapse into the carrier. Receive side: transport dispatches only
   its own verbs and hands everything else to one tdns-mp callback as
   `(senderID, TypeToken, rawPayload)`; tdns-mp owns the verb table.

This is what makes the day-of-2026-05-28 bug class structurally
impossible: with one owner per datum there is nothing to drift (Bug 2 =
address divergence), and with membership derived there is no stale copy
to skew (Bug 1 = role-less identity treated as a member).

## Probe discipline (applies to every Stage)

Each Stage carries a **Characterization Probe** defined *before*
implementation. The goal is early observability into the behavior the
Stage changes — not a full system test. Three parts:

1. **Observable** — the specific automated tests + operator CLI commands
   that exercise the part this Stage touches.
   - *Automated (run by Claude, locally):* the boundary harness
     `TestTransportBoundary_*` (`v2/transport_integ_test.go`), the
     `v2/hsync/*_test.go` suite, `v2/syncheddataengine_test.go`, plus
     any small characterization test added for the Stage.
   - *Runtime (run by operator on the testbed):* `tdns-mpcli <role>
     peer list`, `peer zones`, `gossip state -z <zone>`,
     `zone edits list -z <zone>`, `distrib list`.
2. **Baseline** — captured before the first Step of the Stage lands.
3. **Predicted post-state** — stated up front as either **INVARIANT**
   (pure refactor; output must be comparable) or **EXPLAINED DELTA**
   ("X changes, specifically →…, because…"). After the Stage, actual
   vs predicted must match; an unpredicted difference halts the Stage
   for investigation.

Stating the prediction *before* coding is the point: it converts "huh,
that also changed" from a silent regression into a visible alarm —
which is the exact failure mode behind the 2026-05-28 bugs.

## Verified status (code-to-doc reconciliation, 2026-05-28/29)

The plan/bite docs **undercount** completed work; this section is read
from the `peer-discovery-engine-extraction` branch, not from the docs.
(Per-Stage Status subsections below carry the file:line detail.)

- **DONE:** Phase 0 harness; per-mechanism `MechanismState` on
  `transport.Peer` (master Phase 1 steps 1–4); `Agent.PeerID` (Phase 7
  step 1); early bites; semi-easy bites D/E/F/G/H; the shared
  `hsync.Engine` migration for **both** agent (`HsyncDataEngine`) and
  auditor (`AuditorEngine`) — Cut A's risky live swap is in production.
- **PARTLY DONE (landed 2026-05-28):** membership-from-HSYNCPARAM
  (Stage A3) substantially landed via the Bug-1 fix; reconcile
  apply-removes (A2) landed for the auditor; the Bug-2 address fix is a
  *tactical patch* on `GetOrCreatePeer`, not the structural A4 fix.
- **PENDING:** Stage A (registry embed + transport-side single source of
  truth + bridge teardown), Stage C (the opaque-message seam), Stages
  D/E/F.

## Sequencing & rationale

Order: **A → C → D → E → F.** Stage A first because the entire
2026-05-28 bug class lives in the registry overlap; A is ~25–30% of the
effort but retires that class and gives C a single peer-state owner to
migrate against. C (transport reusability) is the strategic goal but
not the current source of bugs. D carries an open design decision
(parallel-send semantics). After A the system is usable and more
correct than today, though tdns-transport is not yet reusable (that is
C). Effort estimate (Claude-implementation units): see the review doc;
≈8–13 sessions total.

## Implementation branching

Docs (this plan) are committed on `peer-discovery-engine-extraction`.
**Implementation starts on a new feature branch** (cut before the first
Step of Stage A); this plan is not executed in place on the
peer-discovery branch.

---

# Gaps & required pre-work (adversarial review, 2026-05-30)

A second, adversarial pass (probing what the mapping passes were *not*
asked about: persistence, locking, wire-reality, crypto/authz ordering,
blast-radius, external consumers, doc collisions) found the following.
These amend the Stage definitions below — read them as binding.

**Stage 0 (NEW — pre-work, blocks the probe discipline).** The v2 test
suite does not compile: `apihandler_agent_test.go:34` and
`hsync_reconcile_test.go:47,97` reference the removed
`tdns.MultiProviderConf` (MP-config-cutover leftovers). `go test
./v2/...` is RED. Fix these two files **first** — the entire
Characterization-Probe baseline depends on a green automated suite.
(Also delete the dead `PeerRegistry`/`PeerZones` DB layer in
`db_hsync.go`/`db_schema_hsync.go` — full CRUD that is never written,
only read by one CLI command returning empty; a phantom fourth
"registry" that should not survive the consolidation.)

**A1 is not safe as written — re-home before replacing.** Switching the
agent `PostRefresh` from `UpdateAgents` to `ApplyHsyncDiff` silently
DROPS three agent behaviors that `ApplyHsyncDiff` does not reproduce and
that exist at no other call site:
- **upstream RFI** deferred task (`agent_utils.go:934-956`),
- **downstream RFI** deferred task (`:957-981`),
- the **membership-change election kick** (`:1018-1030`).
Also the **HSYNCPARAM-only change** case (param edit, zero HSYNC3 diff)
must still trigger a group recompute — wire `ApplyHsyncDiff`/the
`OnHsync3Changed` hook to fire on param-only refreshes too. A1 must
re-home these (attach the RFI tasks via `MarkNeeded`/the host callback;
add the election kick to `OnHsync3Changed`) **before** it stops calling
`UpdateAgents`. (Auditors tolerate the drops because they never RFI or
elect; agents do — this is why the auditor branch already migrated and
the agent branch did not.)

**A4 blast radius is ~5× the map and has a missing field home.** Reads
of `Agent.ApiDetails`/`DnsDetails` are **~270 across 13 files**, not the
~30 send-path sites: also the CLI display builder
(`apihandler_agent_distrib.go:350-440`, ~21 reads), the liveness engine
`CheckState` (`hsync_beat.go:194`, which *writes* `State`), receive-side
beat counters (`hsync_beat.go:19-25`), `peer reset`
(`apihandler_peer.go:121`), `GetLeaderStatus` (`parentsync_leader.go:1368`),
and the canonical accessors (`agent_structs.go:109-177`
`EffectiveState`/`IsAnyTransportOperational`/`APIMechanismState`). And
the identity fields `KeyRR`/`TlsaRR`/`JWKData`/`KeyAlgorithm` have **no
home in `transport.Peer`** — A4 needs a destination for them first
(add to `transport.Peer`, or rule they stay MP-side as non-transport
metadata). A4 therefore gains an explicit Step A4.0 "give
`transport.Peer` a home for every field being migrated" and a 13-file
scope, and sub-splits A4a (stop writing dup fields) / A4b (delete +
redirect all reads).

**A3 must address concurrency the merge introduces.** Today the two
reconcile loops (`hsync.Engine.runReconcile`, `AgentRegistry.ReconcileHsync`)
are decoupled because they mutate *different* stores via the async
bridge; **collapsing the stores makes them contend on one lock** — A3
must unify them into a single reconcile (likely drop `ReconcileHsync`,
keep the hsync one). The embed must yield **one mutex per peer** (do not
keep both `Agent.Mu` and `hsync.Peer.Mu`). And
`RecomputeSharedZonesAndSyncState` (`agent_utils.go:60`) holds
`agent.Mu` across `PeerRegistry.GetOrCreate`+`AddSharedZone` — refactor
it to release `agent.Mu` before touching the transport peer (the
template for the "no registry lock held across a transport call" rule)
*before* the embed amplifies it.

**Stage C "INVARIANT" carries caveats.** Wire-compat is achievable but
not automatic — the verb is a JSON payload key (`"MessageType"`,
`chunk_notify_handler.go:256/281`), never a transport envelope field:
- **C6 hazard:** moving the `Dns*Payload` structs must keep marshalling
  `"MessageType"` with the same value; a renamed/`omitempty` tag is a
  silent wire break (`parsePayload` → RcodeFormatError).
- **Mixed-fleet brittleness:** `parsePayload:273-278` hard-refuses nodes
  emitting conflicting `MessageType`/`type` (or `Zone`/`zone`), so
  half-migrated fleets during C are fragile even though steady state is
  identical. Upgrade C-touching changes fleet-wide promptly.
- **Probe must cover query mode too:** the verb also rides the
  query-mode manifest `content` field (`distrib/manifest.go:82`); an
  edns0-only probe misses a query-mode divergence.
- **C5 DoS invariant (binding):** the **pre-crypto sender authz**
  (`chunk_notify_handler.go:434`, `IsPeerAuthorized(sender, "")`,
  before `fetchChunkViaQuery`+decrypt) MUST stay in transport. Only the
  **post-decrypt zone authz** (`:551`) moves to MP. Do not collapse the
  two `IsPeerAuthorized` calls into one post-seam call — that would
  decrypt/fetch before authorizing.

**C5 collides with the in-channel CHUNK design.** `2026-05-27-in-channel-chunk-transport-design.md`
(KDC→KRS DoT/DoQ) targets the same `chunk_notify_handler.go`/`crypto.go`
and wants to replace `IsPayloadEncrypted()` with an explicit envelope
indicator. Sequence C5 and that work deliberately (do the envelope-mode
indicator as part of, or immediately before, the C5 split) to avoid
double-rework on one file.

**Good news (lower risk than assumed):** peer state is **in-memory
only** (rebuilt from HSYNC3/discovery on start — no DB migration);
transport has **one consumer today** (tdns-mp), so C's API churn breaks
nothing external; the generic router + `RouteToCallback` seam already
exist (C is mostly relocation); and `SyncPeerFromAgent` has one caller.

---

# Amendments from the second review (2026-05-30)

A second, independent adversarial review
(`2026-05-30-transport-redesign-plan-review.md`) confirmed the Gaps
above and surfaced more. Its highest-stakes claims were re-verified in
code (all confirmed) and one corrected a factual error in this plan
(A1-5). These bindings amend the Steps below; resolutions to the
review's open questions are decided here.

**A1 — remove-authority model (resolves review A1-1/A1-3/A1-4 + open Q2).**
Bind the model: after A1, **`hsync.Registry` is the sole authority for
add AND remove**; `AgentRegistry` is updated only via hooks
(`OnPeerStored` + a new `OnPeerRemoved`, built in A6). Concretely:
- A1-1: the agent-only remove path (`UpdateAgents` →
  `RemoveRemoteAgent`, `agent_utils.go:1004`, which never calls
  `hsync.Registry.RemovePeerFromZone`) is **deleted** when the agent
  routes through `ApplyHsyncDiff` — removes go through the hsync side
  only, ending the store divergence on incremental removes.
- A1-3: wire `OnLocalRemoved` (`hsync3_diff.go:100`, currently unwired)
  to the local-identity-removed handling that `UpdateAgents`'
  `weAreInHSYNC` guard (`:907`) performs today.
- A1-4: `CleanupZoneRelationships` (`agent_utils.go:869`) is a TODO
  stub today; decide its fate when wiring `OnLocalRemoved` — implement
  or explicitly drop, do not leave dangling.
- A1-6: keep the election kick gated on HSYNC3 **identity** change
  (`len(updatedIdentities) > 0`), not on every `OnHsync3Changed`;
  param-only changes recompute groups but do **not** kick an election
  (matches `UpdateAgents` today, `:1018` vs `:1037`).
- RFI re-home API shape (A1-2): extend the host callback to carry
  zone+diff context so the upstream/downstream CONFIG RFI deferred
  tasks can be reattached (today `ApplyHsyncDiff` calls
  `MarkNeeded(..., nil)`).

**A2 — full reader set + the election-quorum reader (resolves A2-1…A2-8
+ open Q4).** A2 must repoint **every** stored-membership reader, not
the three originally listed. The material one: **`SetConfiguredPeersFunc`
(`start_agent.go:137`) computes election quorum as
`len(hsync3RRset.RRs) - 1`** — raw HSYNC3 count, so a role-less identity
inflates quorum (the Bug-1 class in the election path). Repoint it to
the `zoneParticipants` count. Also repoint: `listAgentsForZone`
(`apihandler_agent_distrib.go:649`, `apihandler_shared_distrib.go:43`,
`cli/agent_cmds.go:177`), `NotifyPeerOperational(agent.Zones)`
(`hsync_transport.go:726`), the hello zone list (`hsync_hello.go:26`),
the `peer list` zero-zone display filter
(`apihandler_agent_distrib.go:356,414`), and the `RemoteAgents` index
(`agent_structs.go:266`). **OFF semantics (open Q4): exclude OFF
everywhere** — this falls out for free because A2 **deletes** the raw
`reconcileZone`/`hsync3IdentitiesFromRRset` path
(`hsync_reconcile.go`), the only remaining non-OFF-filtering reader.
*Expand the A2 probe to include election-leader convergence
(`gossip state`) and role-less-identity visibility in `peer list`.*

**A3 — embed scope + dead-reconcile deletion (resolves A3-1/A3-2/A3-5 +
open Q7).** Bind: (a) the embed **deletes** the dead
`AgentRegistry.ReconcileHsync` (it is not "merged" — only the engine
loop is live); (b) retire ONE of the dual hello/discovery paths (legacy
`attemptDiscovery`+`helloContexts` vs `hsync/discovery.go`+`helloCancel`)
or the embed spawns duplicate HELLO goroutines — keep the hsync path;
(c) `RegularS` (`agent_structs.go:265`, debug/API only) is folded or
deleted, not left as a third map; (d) field homes (open Q7):
`LocalID` lives on `hsync.Registry`; `TransportManager`/`MPTransport`/
`LocalAgent`/`GossipStateTable`/`ProviderGroupManager`/
`LeaderElectionManager` stay on the outer `AgentRegistry`.

**A4 — field-home decision + true scope (resolves A4-1…A4-4 + open Q1).**
Decision (open Q1): the crypto-identity fields
`KeyRR`/`TlsaRR`/`JWKData`/`KeyAlgorithm` stay **MP-side metadata until
E1** — they are discovery outputs; transport needs only address +
per-mechanism state (+ TLSA for wire verify if used). When E1 moves
discovery into transport, these land in `transport.Peer` naturally.
So A4 migrates **address/per-mechanism/liveness only**, not identity.
Scope is **~340 reads / 13+ files** (incl. `hsync/`, infra virtual
peers `combiner_peer.go`/`signer_peer.go`, the canonical accessors
`agent_structs.go:109-177`, `db_hsync.go`); delete **both**
`agentStateToTransportState` and `agentStateToTransportStateFn`
(`agent_structs.go:216`).

**A5 — ordering vs the zero-shared-zones gate (resolves A5-1, BLOCKING).**
`HandleSync` rejects a sender with zero shared zones
(`handlers.go:223-246`, the "LEGACY agent cannot send" path) using
transport `SharedZones`. A5 (remove zones from transport) must therefore
land **after** that gate is moved to MP (it moves with the handler in
C3) — sequence A5 after C3's `HandleSync` move, or move the gate first.
Add this as an explicit A5 precondition.

**Stage C — role dispatch, inline ACK, third authz (resolves C-2…C-5).**
- C3 must preserve **role-specific handler sets**, not flatten to one:
  combiner `HandleUpdate`/`NewCombinerSyncHandler` async-confirm
  (`combiner_chunk.go:1428`), signer keystate/rfi/status subset
  (`router_init.go:507`). The single `RegisterAppHandler` *mechanism*
  is fine; each role registers a different set behind it.
- C3 must preserve **inline-ACK semantics**: handlers set
  `ctx.Data["response"]` for the NOTIFY confirm path (`HandleSync:266`,
  `HandleKeystate:380`) and the combiner async-confirm. Probe with the
  combiner async path, not only `ConfirmInlineResponsePrep`.
- **Third authz layer (C-4, resolves open Q6):** besides the two chunk-
  handler checks, `NewAuthorizationMiddleware` runs on the router
  (`router_init.go:63/295/441`). Bind: **peer-level authz (sender
  known) stays in transport** — both the pre-crypto chunk check (C5
  invariant) and the router middleware for transport-own verbs.
  **Zone-level authz moves to MP** with the app handlers. The router
  middleware for app verbs is removed (app authz is post-callback in
  MP).
- C5 scope must list the `ChunkHandler` MP callbacks to preserve:
  `IsPeerAuthorized`, `OnConfirmationReceived`, `GossipForPeer`,
  `OnPeerDiscoveryNeeded` (`hsync_transport.go:321-416`); and collapse
  the MP-side duplicate verb table `routeIncomingMessage`
  (`hsync_transport.go:567`) into the one dispatcher rather than adding
  a third.

**D1 — relocation, not invention (resolves D-1/D-2 + open Q5).**
Today `SendHelloWithFallback`/`SendBeatWithFallback` already try API
**then** DNS, "any success" (sequential, not concurrent). Decision
(open Q5): D1 **relocates the existing sequential any-success semantics
into the TM** — INVARIANT, no behavior change. True concurrent fan-out
is a **separate, optional follow-up** (EXPLAINED DELTA if pursued), not
part of D1. This removes D1's "open design decision" blocker.

**E1 — three discovery entry points (resolves E-1, BLOCKING).** E1/E2
must unify **all three**: `hsync/discovery.go`→`DiscoverPeer` seam,
legacy `AgentRegistry.attemptDiscovery` (`agent_utils.go:588`, via
`DiscoveryRetrierNG`/`apihandler_peer.go:136`), and
`OnPeerDiscoveryNeeded` on the chunk handler (`hsync_transport.go:379`).
The plan previously cited only the `agent_discovery.go` body.

**F1 — full tag inventory (resolves F-1).** The `Gossip` JSON tag is
inconsistent (`BeatRequest` `json:"gossip"` `transport.go:137` vs
`DnsBeatPayload` `json:"Gossip"` `dns.go:1253`). F1 must enumerate and
change **all** gossip tag sites (beat request/response, DNS payloads),
not just `BeatRequest`/`BeatResponse`.

**Concurrency completion (resolves C-11, A3-3, A3-4 + the lock matrix).**
Bind a single-writer / single-lock-order rule for per-peer state:
- **C-11 (data race):** `routeBeatMessage` updates `agent.DnsDetails`
  **without** taking `agent.Mu` (`hsync_transport.go:716-719`), while
  the hello send path holds `agent.Mu` over the same fields — a real
  race today. Fix in A4b (the field moves to `transport.Peer`,
  single-writer) or, if A4b is later, add the missing lock in C3's
  handler move. Do not relocate this handler without applying the rule.
- **A3-3 (stale overwrite):** the bridge merge is asymmetric —
  `SyncPeerZones` replaces the full agent from the hsync peer
  (`hsync_bridge.go:120`) while `mergeAgentDetails` is fill-only
  (`hsync_bridge_sync.go:163`), so a field the hsync side *clears*
  leaves a stale value on the agent. This disappears when A6 deletes the
  bridge; until then, do not rely on either path for freshness.
- **A3-4 (lock order):** define ONE lock order at the embed and hold to
  it everywhere: `AgentRegistry.mu → peer mutex → transport.PeerRegistry
  → transport.Peer`. Never acquire `agent`/registry mutex *under* a
  transport lock, and never hold a registry mutex across a transport
  call (the `RecomputeSharedZonesAndSyncState` rule, generalized).

**A6 — complete teardown inventory (resolves A6-1).** A6 deletes not
just the 9 `hsync_bridge_sync.go` functions but the whole bridge
surface: the `mpHsyncBridge` type, the `SyncPeerZones` shim, the
`OnPeerStored` wiring, and `Agent.PopulateFromAgent`/the
`agentStateToTransportState` path (these are the Agent→transport copy,
dead once transport owns the state after A4).

**Deliberately left to the cross-referenced review doc** (LOW /
cleanup, not duplicated here): A1-7 (auditor double-`RecomputeGroups`
dedup), A2-6 (`cli/hsync_cmds.go:537` debug reader — repoint with the
A2 set), D-3 (enumerate lifecycle registration sites at D3 time), F-2
(stale `init.go` integration-guide `IncomingChan` reference). These are
tracked in `2026-05-30-transport-redesign-plan-review.md`; fold at the
relevant Step rather than carrying them in this summary.

**Severity calibration note:** the second review marks several items
BLOCKING that are really "bind-before-that-Step" (e.g. A1-5 is a
doc-correctness fix). The substance is right; only A5-1, A2-1, E-1 and
the C5 DoS invariant are true cross-Step blockers. Treat all of them as
binding regardless.

---

# Stage A — Registry consolidation

**Goal:** collapse the three overlapping peer-state stores into two
(transport.PeerRegistry + one MP registry), joined by PeerID, with zone
membership derived from HSYNCPARAM and all bridges deleted. This retires
the entire 2026-05-28 bug class.

## Status (from the code map, 2026-05-29)

The reality is heavier than 2026-05-19 §D-3's prose implies: **two fully
populated registries run side-by-side**, kept coherent by a
**9-function bidirectional bridge** (`hsync_bridge_sync.go`), plus a
*third* field-copy of address/state in `hsync.Peer`
(`hsync/types.go:67-101`). So embedding is not a pure type change — the
bridge and the legacy agent update path must go too, or the embedded
registry is shadowed by the old `AgentRegistry.S`.

- `AgentRegistry` `agent_structs.go:263`; `hsync.Registry`
  `hsync/registry.go:15`; **no embedding today** — `AgentRegistry` holds
  `HsyncEngine *hsync.Engine` (`:276`) and the engine owns its own
  `*Registry`. Two distinct peer maps.
- Membership-from-HSYNCPARAM (A's "derive") **substantially landed
  2026-05-28** (`zoneParticipants` `provider_groups.go:82`;
  `ZoneView.Participants` `hsync/interfaces.go:23`) and is wired into
  `RecomputeGroups`, `GetZoneAgentData`, hsync `ReconcileZone`,
  `ApplyHsyncDiff`. Gossip membership is HSYNCPARAM-derived transitively.
- **Divergences the map found:**
  - The **agent** `PostRefresh` branch (`hsync_utils.go:1456`) still
    pushes `HSYNC-UPDATE` to `SyncQ` → legacy `UpdateAgents`
    (`agent_utils.go:874`, the heavy RFI/deferred path §D-4 rejected).
    Only the **auditor** branch (`hsync_utils.go:1472`) uses
    `ApplyHsyncDiff`. So §D-4 is half-done.
  - The tdnsmp reconcile `reconcileZone` (`hsync_reconcile.go:81`)
    derives `expected` from `hsync3IdentitiesFromRRset`
    (`:100,142`) — the **raw HSYNC3 set**, not participants — so it can
    re-add a role-less identity the participant-gated paths exclude.
  - `GetAgentsForZone` (`agent_utils.go:45`) and `listPeerSharedZones`
    (`apihandler_agent_distrib.go:606`) still read `agent.Zones`
    directly.
  - **No `OnPeerRemoved` hook exists anywhere** (zero hits across all
    three repos). Removal propagates only via the periodic reconcile,
    never as an event — this is the structural root of the Bug-1 "stale
    membership" surface.
  - `SyncPeerFromAgent` (`hsync_transport.go:1466`) has **exactly one
    real call site** (`hsync_transport.go:457`, the `OnPeerDiscovered`
    closure) — so the transport-side decoupling is low blast radius.
  - `PeerRegistry.ByZone` (`peer.go:688`) and `GetSharedZones` have **no
    non-test callers** in tdns-mp — nearly dead already.

## Steps (reordered from the skeleton per the map)

The skeleton put "embed" first. The map shows that is wrong: embedding
against two live membership sources just shadows the old store. So the
membership source is unified **first**, then the embed lands against a
single source, then the transport-side ownership and bridge teardown.

- **A1 — Route the agent's HSYNC3 changes through `ApplyHsyncDiff`**
  (finish §D-4). Replace the agent `PostRefresh` branch's
  `SyncQ`/`HSYNC-UPDATE`→`UpdateAgents` path
  (`hsync_utils.go:1456-1463`) with `hsync.Engine.ApplyHsyncDiff`, as
  the auditor branch already does (`:1472`). The live reconcile safety
  net is `hsync.Engine.runReconcile` (`hsync/engine.go:59`); the
  tdnsmp `AgentRegistry.ReconcileHsync` is **dead code (zero callers)**
  and is deleted in A2 — do NOT "keep it as a safety net" (corrected
  per 2nd review A1-5). *Wire-compatible.* **NOT safe as a bare swap — see
  Gaps (2026-05-30): A1 must first re-home the upstream/downstream RFI
  deferred tasks and the membership-change election kick, and handle the
  HSYNCPARAM-only-change recompute, all of which `ApplyHsyncDiff` does
  not reproduce.**
- **A2 — Make every membership read derive from participants.** Convert
  the remaining raw-HSYNC3 / stored-`Zones` readers:
  `reconcileZone` `expected` (`hsync_reconcile.go:100`) →
  `Participants()`; `GetAgentsForZone` (`agent_utils.go:45`) and
  `listPeerSharedZones` (`apihandler_agent_distrib.go:606`) → derived
  set. After A2 there is exactly one membership truth (HSYNCPARAM via
  `zoneParticipants`). *Behavior-correcting; see probe.*
- **A3 — Embed `hsync.Registry` in `AgentRegistry`** (§D-3 decision B).
  `hsync.Registry` owns `S`/`RemoteAgents`/`helloCancel` + protocol
  methods (`MarkNeeded`, heartbeat, HELLO/BEAT, zone lookups);
  `AgentRegistry` embeds `*hsync.Registry` and keeps
  `GossipStateTable`/`ProviderGroupManager`/`LeaderElectionManager`/
  `TransportManager`/`MPTransport`/`LocalAgent`. The duplicated
  `AgentRegistry.S`/`RemoteAgents`/`helloContexts` (`agent_structs.go:263`)
  are deleted; the duplicated protocol methods become delegating
  wrappers, then wrappers deleted. *Largest blast radius; lands alone;
  pure refactor (probe INVARIANT).* Naming note: §D-3 said
  `helloContexts`; actual is `helloCancel`. **Concurrency (see Gaps
  2026-05-30): embed must yield ONE mutex per peer; unify the two
  contending reconcile loops; first refactor
  `RecomputeSharedZonesAndSyncState` to drop `agent.Mu` before calling
  the transport peer.**
- **A4 — Transport becomes sole owner of address + per-mechanism
  state.** Delete `SyncPeerFromAgent` (`hsync_transport.go:1466`, 1
  caller) and `agentStateToTransportState` (`:1507`); drop the
  address/state/beat fields from `Agent.ApiDetails/DnsDetails`
  (`agent_structs.go:83`) and from `hsync.Peer` (`hsync/types.go:67`);
  switch the send/beat-gating reads (`SendHelloWithFallback`/
  `SendBeatWithFallback`, `beatTransportUsed` `hsync_bridge.go:77`) to
  `peerRegistry.Get(peerID)`. `GetOrCreatePeer`'s 2026-05-28 address
  patch is subsumed here. *The permanent Bug-2 fix; probe INVARIANT on
  addresses/convergence.* **Scope is ~270 reads across 13 files (not the
  send path only) — see Gaps (2026-05-30). Adds A4.0: give
  `transport.Peer` a home for `KeyRR`/`TlsaRR`/`JWKData`/`KeyAlgorithm`
  (no home today) before redirecting reads.** Sub-splits A4a
  stop-writing-dup-fields / A4b delete+redirect-all-reads.
- **A5 — Remove zone concepts from transport.** Delete `ZoneRelation`
  (`peer.go:155`), `Peer.SharedZones` (`:81`), `AddSharedZone`/
  `GetSharedZone(s)`/`ByZone` (`:546-688`) and their few tdns-mp callers
  (`agent_utils.go:87,91`; `hsync_transport.go:1494`). *Mostly dead
  already.*
- **A6 — Bridge teardown.** Delete the 9 bridge functions in
  `hsync_bridge_sync.go` (`hsyncPeerToAgent`, `syncHsyncPeerFromAgent`,
  `agentToHsyncPeer`, `mergeAgentDetails`, …) and the `OnPeerStored`
  wiring (`hsync_bridge.go:299`). **Add the missing removal
  propagation** — an `OnPeerRemoved`/zone-removed path so prunes are
  events, not reconcile-only. After A6 the two stores share zero fields
  and are joined only by PeerID.

## Characterization Probe — Stage A

**Observable.** Automated: `go test ./v2/... ./v2/hsync/...` (esp.
`TestTransportBoundary_HelloRejection/SenderNotInHSYNC3`,
`hsync/reconcile_test.go`, `syncheddataengine_test.go`). Runtime:
`peer list`, `peer zones`, `gossip state -z espresso.mp.axfr.net`, an
`addrr` round-trip on a multi-provider zone → `zone edits list` reaches
ACCEPTED.

**Baseline.** Capture before A1 (operator runs the runtime set; Claude
runs the automated set). Current known values from 2026-05-28 serve as
an informal reference: e.g. `peer zones` shows `auditor.mp` only under
its three audited zones; the espresso gossip matrix has no `auditor.mp`
row.

**Predicted post-state per Step:**

| Step | Prediction |
|---|---|
| A1 | **INVARIANT** — agent membership identical; only the internal apply path changes (verify `peer zones` + gossip matrix unchanged; edit round-trip still converges) |
| A2 | **EXPLAINED DELTA** — any role-less HSYNC3 identity that the *raw-HSYNC3* reconcile/`GetAgentsForZone` still admitted now disappears; everything backed by an HSYNCPARAM role identical. If no such identity exists on the testbed at probe time, this is INVARIANT in practice — note that. |
| A3 | **INVARIANT** — store moves under the readers; `peer list`/`peer zones`/gossip/edits all byte-comparable; automated suite green |
| A4 | **INVARIANT** — `peer list` addresses/states unchanged; `addrr` round-trip still ACCEPTED (proves no Bug-2 regression); the combiner remains reachable |
| A5 | **INVARIANT** vs A4 post-state |
| A6 | **INVARIANT** for steady state; **EXPLAINED DELTA** for removal latency — a pruned peer now disappears promptly (event) rather than after a reconcile interval |

An unpredicted change in any INVARIANT probe halts the Stage.

Detail sources (cited, not re-derived): 2026-05-19 §D-3/D-4/D-5;
2026-04-30 PeerRegistry field-disposition map; 2026-04-15 master §A4
(ZoneRelation removal) + Phase 7.

# Stage C — Transport cleanup / the opaque-message seam

**Goal:** tdns-transport speaks only `hello/beat/ping/confirm/chunk` +
one generic opaque app-message carrier; all MP verbs become app-level
`TypeToken` values; transport hands non-own messages to one tdns-mp
callback. This delivers the reusable-library goal.

## Status (from the code map, 2026-05-29)

Encouraging: **the hard infrastructure already exists.** The router
`DNSMessageRouter` (`dns_message_router.go:97`) is already token-keyed
(`MessageType` is `type MessageType string`, `:21`; `handlers
map[MessageType][]*HandlerRegistration`, `:102`; `Route()` `:211`;
`Register()` `:137`). A single generic delivery callback already exists
and is **live**: `RouteToCallback(func(*IncomingMessage))`
(`handlers.go:874`), used by MP at `hsync_transport.go:559`. So Stage C
is mostly **deletion and relocation**, not new dispatch machinery.

What is *not* opaque yet:
- The carrier `SyncRequest` (`transport.go:153`) carries MP semantics:
  `MessageType`(164), `RfiType`(165), `RfiSubtype`(166),
  `ZoneClass`(167), `Publish *core.PublishInstruction`(168),
  `SyncType`(156), `Operations []core.RROperation`(158). **No**
  `Scope`/`TypeToken`/`Payload` field exists.
- 12 send methods on `DNSTransport` (7 interface `transport.go:81` +
  `Keystate`(603)/`Edits`(700)/`Config`(743)/`Audit`(785)/
  `SendStatusUpdate`(907) in `dns.go`); API side implements only the 6
  generic verbs.
- 8 MP receive handlers in `handlers.go` (`HandleSync`(220),
  `HandleRfi`(289), `HandleKeystate`(332), `HandleEdits`(415),
  `HandleConfig`(475), `HandleAudit`(530), `HandleStatusUpdate`(586),
  `HandleRelocate`(640)) vs 4 to keep (`HandleHello/Beat/Ping/
  Confirmation`).
- Role routers `InitializeCombinerRouter`(283)/`InitializeSignerRouter`
  (429) + their configs (`router_init.go`), called from MP
  `main_init.go:255` / `hsync_transport.go:423`. MP has no router_init
  of its own — it calls the transport initializers directly.
- 13 exported `Dns*Payload` types (`dns.go:1203-1513`); `DetermineMessageType`
  (`router_init.go:548`) hard-codes all 13 verbs in a switch.
- transport imports ~24 `core.` types; after the seam it should keep
  only wire/crypto ones (`CHUNK`, `TypeCHUNK`, `Format*`, `JWK`,
  `TypeJWK`, `ExtractManifestData`) and shed the `Agent*Post`,
  `PublishInstruction`, `RROperation`, `StatusUpdatePost`,
  `KeyInventoryEntry` message bodies.
- **ELECT-* confirmed app-level:** no election handler in transport;
  `ELECT-CALL/VOTE/CONFIRM` are RFI `RfiType` values
  (`hsyncengine.go:263`, broadcast `parentsync_leader.go:140`). Transport
  never sees them. The plan states this explicitly so it isn't
  "discovered" mid-implementation.

## Steps

- **C1 — Define the seam.** Add `{Scope, TypeToken string, Payload
  json.RawMessage}` to the carrier (generalize `SyncRequest`/
  `IncomingMessage`); keep the existing `RouteToCallback` seam. Widen
  `IncomingMessage` to carry `TypeToken` so MP dispatches on it rather
  than the transport-known string set. Additive — both sides still work.
- **C2 — Collapse the send side.** Replace the 12 `DNSTransport` send
  methods with one generic `Send(ctx, peer, Scope, TypeToken,
  rawPayload)` (Hello/Beat/Ping/Confirm keep their own typed entry
  points as transport-own verbs; Sync/Keystate/Edits/Config/Audit/
  StatusUpdate collapse). Rewrite the MP send wrappers
  (`SendSyncWithFallback`, `sendRfiToSigner/Combiner`,
  `sendKeystateToSigner`, `sendConfigToAgent`, `sendAuditToAgent`) to
  set `TypeToken` and call the generic send.
- **C3 — Move receive handlers to tdns-mp.** Move the 8 MP handlers
  (`handlers.go:220-686`) into tdns-mp, registered behind one
  `RouteToCallback` dispatcher keyed on `TypeToken`. Delete
  `InitializeCombinerRouter`/`InitializeSignerRouter` + configs; MP gains
  a single `RegisterAppHandler(token, fn)` loop. Transport keeps
  `HandleHello/Beat/Ping/Confirmation`.
- **C4 — Move MP types out.** Move `SyncType`, `Keystate/Edits/Config/
  Audit` req+resp, `KeyInventoryEntry`, `RejectedItemDTO`
  (`transport.go:19-305`, `dns.go:1305`) to tdns-mp; remove the MP
  `core.` imports, leaving only wire/crypto types. *Validation:
  tdns-transport builds with no MP `core` body types; tdns-mp builds on
  its own copies.*
- **C5 — Split `chunk_notify_handler`.** Keep generic reassembly/decrypt
  (`extractChunkPayload` `:143`, `fetchChunkViaQuery` `:191`, decrypt
  block `:464-486`, QNAME `<distid>.<sender>` parse `:121`); move MP
  payload parsing (`parsePayload` `:255`, beat-zone parse `:534`, authz
  dispatch `:548`) into tdns-mp. After reassembly+decrypt the handler
  feeds the same single `(senderID, TypeToken, rawPayload)` callback.
- **C6 — Minimize constants + payload types.** Reduce `MessageType`
  constants to transport-own (`ChunkNotify/ChunkQuery/Hello/Beat/Ping/
  Confirm`); collapse `DetermineMessageType` (`router_init.go:548`) to
  "return the `TypeToken`"; move the 7 MP `Dns*Payload` structs
  (Sync/Relocate/Keystate/KeystateConfirm/Edits/Config/Audit/
  StatusUpdate) + their parse helpers to tdns-mp, keep the 5 own ones.

## Characterization Probe — Stage C

**Observable.** Automated: `go test ./...` in **all three** repos (C is
cross-repo; the build-green invariant is itself a probe), plus
`TestTransportBoundary_*` (esp. `ChunkToMsg`, `SyncFallback`,
`ConfirmInlineResponsePrep`, `LegacySyncRejection`). Runtime: a full
edit round-trip (`addrr` → combiner contribution → peer ACCEPTED), an
RFI (`zone debug` KEYSTATE/EDITS), and a leader election cycle
(`gossip state` shows a leader) — i.e. exercise SYNC, RFI, and ELECT-*
end to end.

**Baseline.** Captured before C1.

**Predicted post-state:** **INVARIANT across the whole Stage** — C is a
pure relocation of where message-type knowledge lives; the wire format
and observable behavior are unchanged. The one allowed exception is
**F1's `Gossip→AppData` rename**, which is a deliberate wire break and
is sequenced in Stage F, not here — so within C, beats/gossip stay
wire-identical. Any behavioral difference (a verb that stops
dispatching, an RFI that stops round-tripping, an election that stops
converging) halts the Stage.

**Per-Step note:** C1 is additive (INVARIANT, trivially). C2–C6 each
keep all three repos building and the round-trips converging; the most
likely place for a surprise is C5 (chunk handler split) — a dropped
field during payload-parse relocation would show as a verb that
delivers but no longer dispatches. The boundary harness `ChunkToMsg`
scenario is the guard there.

Detail sources (cited): 2026-04-15 master §A1–A9 + Phases 2/3/4;
2026-04-30 chunk-notify-handler split cut-line; the 2026-05-28 review's
"C refinement: the opaque-message seam".

# Stage D — Liveness & send semantics (master Phase 5 remainder)

**Goal:** finish the send/liveness model: parallel-send for the
broadcast verbs, transport-owned liveness, lifecycle wiring in the TM.

## Status (from the map)

- `tm.Send` exists (`manager.go:328`) for primary-then-fallback dispatch
  but **explicitly rejects Hello/Beat** (`manager.go:346`: "use
  Hello/Beat directly for parallel-send semantics"). So the parallel
  vs primary-then-fallback distinction is real and unresolved in code.
- MP still drives Hello/Beat via `SendHelloWithFallback`
  (`hsync_transport.go:1536`) / `SendBeatWithFallback` (`:1645`).
- Liveness is updated manually in the combiner/signer handlers (master
  §B5); the planned default middleware (was bite N9) is not in.

## Steps

- **D1 — Parallel-send for Hello/Beat.** *Carries an OPEN DESIGN
  DECISION* (see Open Decisions): Hello/Beat should fan out on all
  available mechanisms in parallel rather than primary-then-fallback
  like Sync. Define the success rule (all / any / majority) before
  implementing. Replace `SendHelloWithFallback`/`SendBeatWithFallback`
  with the chosen semantics in the TM.
- **D2 — Transport-owned liveness middleware** (was N9). A default
  middleware updates `Peer.Mechanisms[mech]` timestamps on
  hello/beat receipt; delete the manual updates in
  `combiner_msg_handler.go`/`signer_msg_handler.go`.
- **D3 — Lifecycle wiring into TM startup** (was N5). Move
  engine/middleware lifecycle setup into TransportManager startup.

## Characterization Probe — Stage D

Observable: `gossip state -z <zone>` (the beat/liveness matrix), beat
counters in `peer list`, `TestTransportBoundary_*`. Baseline before D1.
Prediction: **EXPLAINED DELTA** at D1 — liveness should become *more*
robust (a peer reachable on either mechanism stays OPERATIONAL if one
mechanism fails), which may change matrix cells under partial-failure;
**INVARIANT** under all-mechanisms-healthy. D2/D3 INVARIANT
(refactor of where liveness is written).

---

# Stage E — Discovery body into transport (master Phase 6 part 2)

**Goal:** move the discovery implementation into transport and delete
the temporary `DiscoveryDriver` seam, so transport owns peer discovery
end to end (the last big piece of the reusable-library goal).

## Status (from the map)

- The seam is live: `tm.TransportManager.DiscoveryDriver = tm`
  (`hsync_transport.go:491`); transport calls back into MP via
  `RunDiscovery` (`:504`) → `DiscoverAndRegisterAgent`
  (`agent_discovery.go:364`). The discovery body (`attemptDiscovery`
  `agent_utils.go:588`, JWK/SVCB/addr resolution in `agent_discovery.go`)
  lives in MP.
- 2026-05-19 §I-3 records that HSYNC3→discovery *translation* (which
  identities to discover) stays in MP forever; only the *mechanism*
  (resolve identity → addr/key via DNS) moves to transport.

## Steps

- **E1 — Move the discovery mechanism into transport.** Relocate the
  identity→{addr,key,SVCB} resolution (`attemptDiscovery` +
  `agent_discovery.go` resolution) into the transport `DiscoveryService`,
  producing a `*transport.Peer`. MP retains "who to discover" (the
  HSYNC3-driven `MarkNeeded`).
- **E2 — Delete the `DiscoveryDriver` seam** (`hsync_transport.go:491`,
  `RunDiscovery` `:504`). Transport's `DiscoverPeer` becomes
  self-contained; MP stops providing the driver.

## Characterization Probe — Stage E

Observable: a peer restart → rediscovery → reaches OPERATIONAL on cpt
(the exact scenario behind the 2026-05-28 KNOWN→OPERATIONAL gap);
`peer list` state transitions; `OnDiscoveryFailed` fires on failure
paths. Baseline before E1. Prediction: **INVARIANT** — discovery
outcomes (addresses/keys resolved, state transitions) identical; only
the code location moves. Watch the post-restart promotion specifically,
since that path is already fragile (a known open issue — see status
memory).

---

# Stage F — Finish

**Goal:** the deliberate wire break, the documentation tasks, and any
master Phase 8–9 leftovers.

## Steps

- **F1 — `Gossip` → `AppData` rename** (transport `BeatRequest.Gossip`
  `transport.go:137`, `BeatResponse.Gossip` `:147`). The master's
  Appendix H.4 supersedes its own earlier "wire-compatible" claim: this
  **is a deliberate wire break**, justified by the near-nil deployed
  base. Coordinate with C1's `Payload` field. *Only intentional wire
  break in the whole plan — must be flagged in release notes and
  deployed fleet-wide together.*
- **F2 — Doc tasks** (was N1/N2): per-Stage rollback criteria; the
  remaining method-disposition walkthrough. Largely subsumed by this
  plan's per-Stage probes.
- **F3 — Master Phase 8–9 leftovers** — reconcile against code at the
  time (likely small; verify nothing remains MP-coupled in transport).

## Characterization Probe — Stage F

Observable: beat/gossip round-trip across the fleet
(`gossip state`), full edit + election cycle. Baseline before F1.
Prediction: **EXPLAINED DELTA (wire break)** — old↔new nodes cannot
exchange gossip across F1; the fleet must be upgraded together. This is
the one Step where heterogeneous-version operation is *not* supported;
all other Steps in the plan preserve it.

---

# Open Decisions (gate specific Steps)

1. **D1 parallel-send success rule** — all / any / majority of
   mechanisms must succeed for Hello/Beat to count as delivered?
   Blocks D1. (Operator decision.)
2. **A3 embed scope** — confirm the §D-3 retained-field list against
   the embed PR (naming drift: `helloCancel` vs `helloContexts`; should
   `LocalID`/`transport` sit on hsync.Registry or AgentRegistry?).
   Resolved during A3 mapping, but flag at PR time.
3. **A4 sub-split** — land "stop writing duplicate fields" and "delete
   the fields" as one Step or two? Decide when A4 mapping firms up.

# Cross-Stage notes

- **Heterogeneous-fleet safety:** every Step except **F1** is
  wire-compatible, so the testbed can run mixed old/new nodes during A–E
  (as it did 2026-05-28). F1 is the single coordinated-upgrade Step.
- **The 2026-05-28 tactical patches** (`GetOrCreatePeer` address copy;
  the `zoneParticipants` derivation) are *subsumed* by A4 and A2/A3
  respectively — they are not separate work, they are partial down
  payments on Stage A.
- **Known open runtime issues** (tracked in
  `project_peer_discovery_fallout_status.md`) that touch this work:
  post-restart KNOWN→OPERATIONAL promotion gap (probe target for E),
  espresso election churn, ping-tries-API-on-DNS-peer. These are
  bugs to fix, not Stages — fix opportunistically when the relevant
  Stage touches that code.

# Execution checklist (per Step)

1. Cut/confirm the implementation feature branch (NOT
   `peer-discovery-engine-extraction`).
2. Map-to-code refresh for the Step (the maps here are 2026-05-29;
   re-verify file:line before editing).
3. Capture the Stage's Characterization Probe baseline (first Step of a
   Stage only).
4. Implement; `gofmt -w`; build all affected repos.
5. Re-run the probe; compare to the predicted post-state.
6. Commit (one Step = one commit); push; operator deploys + verifies on
   the testbed.



