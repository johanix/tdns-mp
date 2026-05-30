# Transport redesign: consolidated implementation plan — v2

Date: 2026-05-30
Status: AUTHORITATIVE & EXECUTABLE. This is the single source of truth
for the transport redesign. Each Stage below is a self-contained spec —
there are no separate "amendment" layers to cross-reference.

## Relationship to prior docs

- **v1** (`2026-05-29-transport-redesign-consolidated-plan.md`) is kept
  as the **evolution trail** (target arch → first Gaps → two amendment
  layers). v2 flattens v1 + all three adversarial reviews into coherent
  Step specs and resolves the contradictions the reviews found. Where v1
  and v2 differ, **v2 wins.**
- Reviews folded: `2026-05-30-transport-redesign-plan-review.md`
  (pass 1), `-pass2.md` (pass 2). Their findings are integrated inline,
  not appended.
- Detail appendices still cited (not re-derived): 2026-04-15 master
  (A1–A9 inventory, Phase step lists); 2026-05-19 §D-1…D-5 decisions;
  2026-04-30 PeerRegistry field-disposition + chunk-handler cut-line.

## Decisions baked in (previously open)

1. **A5 placement:** removing zone concepts from transport is **Stage C
   step C7** (after C3 moves the `HandleSync` shared-zones gate to MP),
   not a Stage A step. Resolves the "A5-after-C3 inside A-before-C"
   impossibility.
2. **Auth at the wire boundary:** `IsPeerAuthorized`/`EvaluateHello` and
   the outbound-beat zone list derive from **`zoneParticipants`** —
   bound in **A2** (security boundary), not deferred to C.
3. **Identity crypto fields** (`KeyRR`/`TlsaRR`/`JWKData`/`KeyAlgorithm`)
   stay **MP-side metadata until E1**; A4 migrates address +
   per-mechanism state + liveness only.
4. **D1** = relocate the existing *sequential, any-success* Hello/Beat
   semantics into the TM (INVARIANT). True parallel fan-out is an
   optional, separately-scheduled follow-up — not part of D1.
5. **LEGACY** has ONE definition after A2: a peer with **zero derived
   zone-participations**. The three current sites collapse to it.
6. **`RemoteAgents` index** is deleted post-embed; zone→peer is derived
   from the single registry on read.
7. **Inbound dispatch** (`route*Message` → `adapt*` → engine) collapses
   to one path per message type in A3, not just a map merge.
8. **Open-ended mechanism set (binding constraint).** Mechanisms are
   NOT a fixed {API, DNS} pair. DOQ (DNS-over-QUIC, where CHUNKs travel
   **unencrypted inside** the secure channel) is coming, and more may
   follow. Everything per-mechanism MUST be keyed by mechanism **name
   (string)** — never an enum or a 2-element shape. `transport.Peer.
   Mechanisms` is already `map[string]*MechanismState` (good); the gap
   is the send path (`SendBeatWithFallback` hardcodes API-then-DNS) and
   `supported_mechanisms` config (`config_validate.go:82-94` currently
   whitelists only `"api"`/`"dns"` — extend that validator when DOQ
   ships; not a Stage A blocker). D1's relocation must keep the
   per-mechanism send/result shape a string-keyed collection so adding
   DOQ (or per-mechanism parallel) is a local change, never an API
   break.
9. **Explicit payload-envelope label (decided).** Replace the fragile
   byte-sniffing `IsPayloadEncrypted()` with an explicit envelope
   indicator on the message: `envelope = none | jose | cose` (extensible).
   DOQ uses `none` (the channel provides confidentiality); Do53 uses
   `jose`. This is now a bound decision (operator, 2026-05-30), driven by
   the in-channel-CHUNK / DOQ direction; it lands with C5 (see C5).

---

## Target architecture (end state)

**Two peer-state stores, partitioned by concern, joined only by
`PeerID`; transport speaks an opaque-message vocabulary; zone membership
— including admission — is derived from HSYNCPARAM, never stored-and-synced.**

1. **`transport.PeerRegistry`** owns transport state: identity,
   addresses, per-mechanism state (`Mechanisms`), crypto keys used for
   the wire, liveness, transport selection, stats. Sole source the send
   path reads. Knows nothing of zones/roles/agents/combiners/signers.
2. **One MP registry** owns app metadata: per 2026-05-19 §D-3,
   `AgentRegistry` embeds `*hsync.Registry` (which owns the peer map +
   protocol methods); `AgentRegistry` keeps gossip/groups/elections/
   transport-manager/local-identity + the MP-only identity crypto
   fields. Zone membership is **derived** from HSYNCPARAM roles
   (resolved via ON HSYNC3 labels), not kept as a parallel synced map.
3. **Coupling by `PeerID` only.** No bidirectional sync functions —
   `SyncPeerFromAgent`, `agentStateToTransportState`(`Fn`),
   `hsyncPeerToAgent`, `syncHsyncPeerFromAgent`, `mergeAgentDetails`,
   `SyncPeerZones`, the `mpHsyncBridge` surface — all deleted.
4. **Transport vocabulary = `hello/beat/ping/confirm/chunk` + one
   opaque app-message carrier** `{Scope, TypeToken, Payload}`. All MP
   verbs (SYNC/UPDATE/RFI + KEYSTATE/EDITS/CONFIG/AUDIT/ELECT-*/STATUS)
   are app-level `TypeToken` values transport never interprets. Send:
   the typed `Sync/Keystate/Edits/Config/Audit` methods collapse into the
   carrier. Receive: transport dispatches only its own verbs and hands
   everything else to one tdns-mp callback `(senderID, TypeToken,
   rawPayload)`.

This makes the 2026-05-28 bug class structurally impossible: one owner
per datum (no address/state drift — Bug 2), membership derived at every
read **including admission** (no role-less identity treated as a member
or authorized — Bug 1).

## Probe discipline (every Stage)

Each Stage carries a **Characterization Probe** defined before
implementation. Three parts:
1. **Observable** — automated (run locally) + runtime (operator runs on
   testbed).
   - Automated: `go test ./...` in **all three repos** that build on the
     change (NOT tdns-mp only — bind `tdns/v2` + `tdns-transport`
     compile, and the `cmd/transport-exercise` in-repo consumer, per
     pass-2 M2); the boundary harness `TestTransportBoundary_*`; the
     `hsync/*` + `syncheddataengine` suites.
   - Runtime: `peer list`, `peer zones`, `gossip state -z <zone>`,
     `zone edits list -z <zone>`, `distrib list`.
2. **Baseline** — captured before the Stage's first Step (only after
   Stage 0 makes the suite green — pass-2 H8).
3. **Predicted post-state** — **INVARIANT** (pure refactor; comparable
   output) or **EXPLAINED DELTA** ("X changes → …, because …"). An
   unpredicted change in an INVARIANT probe halts the Stage.

## Verified status (read from code, 2026-05-30)

The plan/bite docs undercount completed work. (Naming: "membership
derivation" below is the 2026-05-28 Bug-1 fix — NOT Stage A's Step "A3
embed", which is unstarted. Pass-2 M1 collision avoided.)
- **DONE:** Phase 0 harness; per-mechanism `MechanismState` on
  `transport.Peer`; `Agent.PeerID`; early/semi-easy bites D/E/F/G/H; the
  shared `hsync.Engine` migration for both agent (`HsyncDataEngine`) and
  auditor (`AuditorEngine`) — Cut A's risky live swap is in production.
- **PARTLY DONE (2026-05-28):** membership *derivation* via
  `zoneParticipants` wired into `RecomputeGroups`/`GetZoneAgentData`/
  hsync `ReconcileZone`/`ApplyHsyncDiff`; reconcile apply-removes for the
  auditor; the Bug-2 `GetOrCreatePeer` address copy (a tactical patch,
  subsumed by A4).
- **PENDING:** all of Stage A (the embed + transport-side ownership +
  bridge teardown + the wire-boundary derivation), Stage C, D, E, F.

## Sequencing

**Stage 0 → A → C → D → E → F.** A first: the entire 2026-05-28 bug
class lives in the registry overlap; A retires it and gives C a single
peer-state owner to migrate against. C is the reusable-library goal but
not the current bug source. After A the system is usable and more
correct than today; transport is not yet reusable (that is C). All Steps
except F1 are wire-compatible (heterogeneous fleet OK during A–E).

## Implementation branching

v2 is committed on `peer-discovery-engine-extraction`. **Implementation
starts on a new feature branch**, cut before Stage 0.

---

# Stage 0 — Pre-work (unblocks the probe baseline)

**Goal:** a green automated suite that encodes *correct* (participant)
semantics, and removal of phantom/dead registry code, so every later
Stage has a trustworthy baseline.

- **0.1 — Fix the red suite.** `apihandler_agent_test.go:34`,
  `hsync_reconcile_test.go:47,97` reference the removed
  `tdns.MultiProviderConf` (MP-config-cutover leftovers). Repoint to
  `*tdnsmp.MultiProviderConf` / `conf.InternalMp.MpConfig`. (pass-1 S0,
  pass-2 H8)
- **0.2 — Fix test semantics, not just compile.** `hsync/engine_test.go`
  `mockZone.Participants()` returns *all* HSYNC3 identities
  (`:62-69`); production uses OFF-filtered `zoneParticipants`. Make the
  mock match participant semantics, or A2's probes lie. (pass-2 H8)
- **0.3 — Delete phantom + dead registry code.** The `PeerRegistry`/
  `PeerZones` DB layer + converters `PeerRecordFromAgent`/
  `PeerRecordFromTransportPeer` (`db_hsync.go:478-561`,
  `db_schema_hsync.go`) — full CRUD never written, read only by one CLI
  returning empty. And `AgentRegistry.SendHeartbeats` (`hsync_beat.go:57`,
  zero callers; engine `sendHeartbeats` is live) and
  `AgentRegistry.ReconcileHsync` + `reconcileZone`/
  `hsync3IdentitiesFromRRset` (`hsync_reconcile.go`, zero callers; the
  live net is `hsync.Engine.runReconcile`). **Delete the tests that
  exercised the dead reconcile path too** — `hsync_reconcile_test.go`
  `TestHsync3IdentitiesFromRRset` and `TestReconcileZone_removesStalePeer`
  (0.1 only fixes the `MultiProviderConf` compile lines in that file;
  0.3 removes the obsolete tests along with the code they covered). Fix
  the stale `start_auditor.go:11` "does NOT run HsyncEngine" comment.
  (pass-1 Stage 0, pass-2 H7)

**Probe.** Automated only. Baseline = green suite in all three repos.
Prediction: INVARIANT runtime (no behavior change; dead-code removal).

---

# Stage A — Registry consolidation

**Goal:** collapse the three peer-state stores into two (transport +
one MP registry), joined by PeerID, with zone membership — **including
the auth/admission boundary** — derived from HSYNCPARAM, and all bridges
deleted. Retires the 2026-05-28 bug class.

**Status fact (drives ordering):** two fully-populated registries run
side-by-side, kept coherent by a 9-function bidirectional bridge plus a
third field-copy in `hsync.Peer`. So the embed is not a pure type
change — the bridge and the legacy agent update path must go too, or the
embedded registry is shadowed by the old `AgentRegistry.S`. Therefore
membership is unified **first**, then the embed, then transport
ownership, then bridge teardown.

### A1 — Route the agent's HSYNC3 changes through `ApplyHsyncDiff`

Replace the agent `PostRefresh` path (`hsync_utils.go:1456-1463`, which
enqueues `SyncQ`→`SyncRequestHandler`→`UpdateAgents`,
`agent_utils.go:874`) with a **direct** `hsync.Engine.ApplyHsyncDiff`
call, mirroring the auditor branch (`hsync_utils.go:1472-1480`) — not
merely swapping the handler body behind `SyncQ` (pass-2 B4). `SyncQ`
remains for other commands (`SYNC-DNSKEY-RRSET`, etc.,
`hsync_utils.go:1441`); narrow/delete only the `HSYNC-UPDATE` branch in
`SyncRequestHandler`.

`ApplyHsyncDiff` does **not** reproduce three behaviors that live at no
other call site — **re-home them first** (A1.0 below):
- upstream CONFIG RFI deferred task (`agent_utils.go:934-956`),
- downstream CONFIG RFI deferred task (`:957-981`),
- the membership-change election kick (`:1018-1030`), kept gated on
  HSYNC3 **identity** change (`len(updatedIdentities)>0`) — param-only
  changes recompute groups but do NOT kick an election (`:1037`).

Plus three semantic gaps the swap exposes (pass-2 B3):
- **`weAreInHSYNC` is not the same as `OnLocalRemoved`.** The global
  abort (`UpdateAgents` stops *all* remote processing when our identity
  is absent from the zone's HSYNC3 RRset, `:907-910`) fires on every
  refresh where we are not listed — including param-only edits with no
  remove RR. `OnLocalRemoved` (`hsync/hsync3_diff.go:100`, currently
  unwired) fires only on an explicit local remove in the diff. **Bind
  both:** (1) wire `OnLocalRemoved` for the remove-RR case and decide
  the fate of `CleanupZoneRelationships` (`agent_utils.go:869`, a TODO
  stub today — implement the zone teardown there, or explicitly drop
  with a stated alternative; do not leave dangling); (2) add a
  **pre-diff guard** in `ApplyHsyncDiff` (or the host callback) that
  mirrors `weAreInHSYNC`: when the local identity is absent from the
  zone's *current* HSYNC3 RRset, skip remote add/remove processing
  (param-only group recompute via `OnHsync3Changed` must also be
  suppressed in that case — `UpdateAgents` never reached `:1037`).
- the `members==nil` fallback (`hsync3_diff.go:47-51,75-78`) lets adds
  proceed ungated when the zone view is unavailable — make it fail
  closed (no add) to honor "OFF/role-less excluded everywhere".
  **Startup invariant:** `ApplyHsyncDiff` runs only after the zone is
  registered in the `Zones` lookup (PostRefresh ordering guarantees
  this today); if the zone view is ever nil, adds are blocked and
  `hsync.Engine.runReconcile` remains authoritative.

Bind the **remove-authority model**: after A1, `hsync.Registry` is the
sole authority for add AND remove; the agent-only
`UpdateAgents`→`RemoveRemoteAgent` path (`:1004`, which never calls
`hsync.Registry.RemovePeerFromZone`) is deleted. `AgentRegistry` is
updated only via hooks (`OnPeerStored` until bridge teardown in A5, then
`OnPeerStored` + the new `OnPeerRemoved`). Between A1 and A5, hsync-side
removes propagate to the agent registry through the existing bridge
(`SyncPeerZones` / `OnPeerStored`); event-driven `OnPeerRemoved` arrives
at A5.

**Sub-steps (each = one commit — see Execution checklist):**
- **A1.0** — extend the shared engine factory `HostCallbacks`
  (`newAuditorHsyncEngine`/the agent equivalent, `hsync_bridge.go:301`)
  to carry `OnLocalRemoved`, the `weAreInHSYNC` pre-diff guard, and a
  zone+diff context so the upstream/downstream RFI tasks + election kick
  can be reattached. Wire `OnLocalRemoved` → `CleanupZoneRelationships`
  (implement or explicitly drop). (`ApplyHsyncDiff` today calls
  `MarkNeeded(...,nil)`.) Without this, A1 cannot land (pass-2 B5).
- **A1.1** — agent PostRefresh calls `ApplyHsyncDiff` directly; delete
  the `HSYNC-UPDATE` `SyncQ` branch, agent-path `RemoveRemoteAgent`, and
  the entire **`UpdateAgents` function** (`agent_utils.go:874` — its
  only caller is the deleted branch).
- **A1.2** — dedup the double `RecomputeGroups` (the auditor already
  does `ApplyHsyncDiff`→`OnHsync3Changed`(recompute) **plus** a direct
  `RecomputeGroups`, `hsync_utils.go:1477-1484`; don't inherit it on the
  agent) (pass-2 H9).

**Probe — EXPLAINED DELTA (not INVARIANT, per pass-2 B3):** common case
identical (membership, gossip, edit round-trip). Deltas: (a)
local-identity dropout and param-only refresh while local is absent
from HSYNC3 — verify the pre-diff guard + `OnLocalRemoved`/`CleanupZoneRelationships`
match today's `weAreInHSYNC` abort (including no spurious group
recompute); (b) transient role-less adds no longer slip through the
`members==nil` path; (c) **removal latency** — pruned peers may lag on
the agent registry until A5 adds `OnPeerRemoved` (bridge sync only until
then). Add regression tests for (a) and (b).

### A2 — Derive every membership read from participants (incl. the wire boundary)

Make `zoneParticipants` (HSYNCPARAM roles via ON HSYNC3 labels,
`provider_groups.go:82`) the single membership truth at **every** reader
on **agent/auditor** paths. Introduce one shared helper —
`ParticipantsForZone(zone)` in `provider_groups.go`, wrapping
`zoneParticipants` — and route every reader below through it (do not
sprout partial copies in `hsync/` or the bridge).

**Combiner/signer** processes intentionally keep config-only
`AuthorizedPeers` (`main_init.go:302-384`), not participant derivation —
that is correct for those roles.

The wire-boundary readers are the security-critical additions (pass-2
B1/H6):
- **Auth admission (BLOCKING):** `isInHSYNC`/`isInHSYNCAnyZone`
  (`agent_authorization.go:99,159`) authorize on raw HSYNC3 co-presence
  (no role, no OFF filter); `EvaluateHello` (`hsync_hello.go:323`) the
  same. Repoint both to the participant set. Without this, a role-less/
  OFF identity (e.g. espresso's `auden`) still passes `IsPeerAuthorized`
  and may SEND SYNC — the original Bug-1 at the security boundary.
- **Outbound beat zones:** the beat payload zone list comes from
  `peer.GetSharedZones()` (`tdns-transport/.../dns.go:280`), fed from
  stored `agent.Zones` (`RecomputeSharedZonesAndSyncState`,
  `agent_utils.go:87`). Source it from participants so beats advertise
  derived membership.
- **Election quorum (BLOCKING):** `SetConfiguredPeersFunc`
  (`start_agent.go:137`) computes quorum as `len(hsync3RRset.RRs)-1` —
  raw count; a role-less identity inflates it. Repoint to the
  participant count.

Plus the display/reconcile readers: `GetAgentsForZone`
(`agent_utils.go:45`), `listPeerSharedZones`
(`apihandler_agent_distrib.go:606`), `listAgentsForZone`
(`:649`, `apihandler_shared_distrib.go:43`, `cli/agent_cmds.go:177`),
`NotifyPeerOperational(agent.Zones)` (`hsync_transport.go:726`), the
hello zone list (`hsync_hello.go:26`), the `peer list` zero-zone display
filter (`apihandler_agent_distrib.go:356,414`), and the debug reader
(`cli/hsync_cmds.go:537`). **OFF excluded everywhere** — already true
once Stage 0 deleted the raw-HSYNC3 reconcile (the only non-filtering
reader).

**One documented exception:** `zoneParticipants` today falls back to
*all ON HSYNC3 identities* when a zone has HSYNC3 but **no HSYNCPARAM**
(`provider_groups.go:107-113`, mid-migration legacy with a warning).
That is the **sole** remaining non-participant-gated path — keep it as an
explicit, logged exception in A2 (do not silently widen "OFF/role-less
excluded everywhere" to cover it unless the operator decides to remove
the fallback in this Step).

**LEGACY unification (pass-2 H2):** define LEGACY once = **derived
participations == 0**. Map the three current sites to it:
`RecomputeSharedZonesAndSyncState` (`len(agent.Zones)==0`,
`agent_utils.go:64`), the `IsPeerAuthorized` Legacy bypass
(`agent_authorization.go:44`), and (later, in C3/C7) the transport
`HandleSync` zero-zones gate.

**Probe — EXPLAINED DELTA:** a role-less/OFF identity is now **rejected
at auth and HELLO**, dropped from `peer list`/beats/quorum; everything
backed by an HSYNCPARAM role identical. Add probes: election-leader
convergence (`gossip state`), and an explicit auth-reject of a role-less
sender. If no role-less identity exists on the testbed at probe time,
note "INVARIANT in practice".

### A3 — Embed `hsync.Registry`; collapse the inbound pipeline; one lock order

Embed per §D-3 (decision B): `hsync.Registry` owns
`S`/`RemoteAgents`/`helloCancel` + protocol methods; `AgentRegistry`
embeds `*hsync.Registry` and keeps gossip/groups/elections/
transport-manager/`LocalAgent` + MP identity crypto fields; `LocalID`
lives on `hsync.Registry`. Delete the duplicated
`AgentRegistry.S`/`RemoteAgents`/`helloContexts` and fold/delete
`RegularS` (`agent_structs.go:265`, debug/API only) — no third map.
Duplicated protocol methods become delegating wrappers, then deleted.
**Delete `RemoteAgents` index** entirely; derive zone→peer on read.

**Collapse the inbound triple pipeline (pass-2 H1).** Every inbound DNS
beat today updates three places via `route*Message`→`adapt*`→engine:
`routeBeatMessage` (`hsync_transport.go:704`, updates PeerRegistry +
AgentRegistry + merges DNS gossip), `adaptBeatReports`→`HeartbeatHandler`
(`hsync_beat.go:11`), and `hsync.Engine.heartbeatHandler`
(`hsync/beat.go:11`). After the embed, bind **one inbound path per
message type**; delete the redundant updates. Note `hsync/hello.go`
`helloHandler` is a stub (`:11`) — the "keep the hsync hello path" means
the **outbound** discovery-driven `HelloRetrierNG`; inbound hello state
is in `routeHelloMessage` — do not wire inbound to the stub (pass-2 M4).

**Concurrency (pass-2 C-11/A3-3/A3-4 + the lock matrix):**
- embed yields **one mutex per peer** (not both `Agent.Mu` and
  `hsync.Peer.Mu`).
- single lock order, held everywhere: `AgentRegistry.mu` → peer mutex →
  `transport.PeerRegistry` → `transport.Peer`. Never acquire a registry
  mutex under a transport lock; never hold a registry mutex across a
  transport call.
- refactor `RecomputeSharedZonesAndSyncState` (`agent_utils.go:60`,
  holds `agent.Mu` across `PeerRegistry.GetOrCreate`+`AddSharedZone`)
  **before** the embed amplifies it: compute under the lock, release,
  then touch the transport peer.
- fix the `routeBeatMessage` write-without-`agent.Mu` race
  (`hsync_transport.go:716`) as part of the pipeline collapse
  (single-writer).
- retire ONE hello/discovery path (legacy `attemptDiscovery`+
  `helloContexts` vs `hsync/discovery.go`+`helloCancel`) — keep the
  hsync path — or the embed spawns duplicate HELLO goroutines; verify no
  `HsyncEngine==nil` production fallback before deleting the legacy path.
- **stop storing synced zone membership:** after the embed, neither
  `agent.Zones` nor `hsync.Peer.Zones` is written as a parallel
  membership copy — zone participation is derived on read via
  `ParticipantsForZone`. (Transport `SharedZones` lingers until **C7**;
  A2 already sources outbound beat zones from participants.)

**Probe — INVARIANT:** `peer list`/`peer zones`/gossip/edits
byte-comparable; suite green; no new races under `-race` on the
boundary/hsync tests.

### A4 — Transport = sole owner of address + per-mechanism state

Delete `SyncPeerFromAgent` (`hsync_transport.go:1466`, one caller at
`:457`), `agentStateToTransportState` **and** `agentStateToTransportStateFn`
(`agent_structs.go:216`). Migrate **address + per-mechanism state +
liveness** to `transport.Peer`; **identity crypto fields stay MP-side
metadata until E1** (decision). Switch all readers to
`peerRegistry.Get(peerID)`.

Scope is **~340 reads across 13+ files** (not the send path only):
- send/beat gating + writes (`hsync_transport.go:1536+`,
  `hsync_infra_beat.go`),
- CLI display builder (`apihandler_agent_distrib.go:350-440`, ~21
  reads), `peer reset` (`apihandler_peer.go:121`), `GetLeaderStatus`
  (`parentsync_leader.go:1368`),
- liveness engine `CheckState` (`hsync_beat.go:194`, which **writes**
  State), receive-side beat counters (`hsync_beat.go:19-25`),
- the canonical accessors (`agent_structs.go:109-177`:
  `EffectiveState`/`IsAnyTransportOperational`/`APIMechanismState`/
  `DNSMechanismState`) — rewrite to read PeerRegistry,
- infra virtual peers (`combiner_peer.go`/`signer_peer.go`); note the
  cross-role asymmetry (the **agent** registers combiner/signer in
  `AgentRegistry`; combiner/signer processes use `PeerRegistry` only) —
  the combiner-reachability probe must hold for both (pass-2 M5).

**Sub-steps (each = one commit):** A4a stop dual-writing the migrated
fields; A4b delete the fields + redirect all reads. `SendStatusUpdate`
is fire-and-forget (`dns.go:904`, no confirm wait) — preserve that
semantics through the send-path changes (pass-2 M6).

**Probe — INVARIANT:** `peer list` addresses/states unchanged; `addrr`
round-trip still ACCEPTED; combiner reachable (both role views). Run
`-race`.

### A5 — Bridge teardown (was A6)

Delete the whole bridge surface: the 9 `hsync_bridge_sync.go` functions
(`hsyncPeerToAgent`, `syncHsyncPeerFromAgent`, `agentToHsyncPeer`,
`mergeAgentDetails`, `persistAgentAndPeer`, …), the `mpHsyncBridge` type,
the `SyncPeerZones` shim, `Agent.PopulateFromAgent`, and the
`OnPeerStored` wiring (`hsync_bridge.go:299`). **Add `OnPeerRemoved`**
(none exists today) so prunes are events, not reconcile-only. The
fill-only `mergeAgentDetails` stale-overwrite hazard (pass-2 M3/A3-3)
disappears here.

(Removing zone concepts from `transport.Peer` — old "A5" — is **C7**,
because the `HandleSync` shared-zones gate and outbound-beat zone source
move in Stage C. Decision baked in.)

**Probe — INVARIANT** for steady state; **EXPLAINED DELTA** for removal
latency — completes the delta noted at A1(c): a pruned peer now
disappears promptly via `OnPeerRemoved` (event), not after a reconcile
interval or bridge-only sync.

---

# Stage C — Transport cleanup / the opaque-message seam

**Goal:** tdns-transport speaks only `hello/beat/ping/confirm/chunk` +
one opaque carrier; all MP verbs are app-level `TypeToken`s; transport
hands non-own messages to one tdns-mp callback. Delivers the
reusable-library goal.

**Status fact:** the hard infrastructure exists — `DNSMessageRouter`
(`dns_message_router.go:97`) is token-keyed; a single generic
`RouteToCallback(func(*IncomingMessage))` (`handlers.go:874`) is live at
MP (`hsync_transport.go:559`). So C is mostly **relocation + deletion**,
not new dispatch. **ELECT-* is already app-level** (RFI `RfiType`,
`hsyncengine.go:263`); transport never sees it.

**Pre-C: mixed-fleet runbook (pass-2 M7).** `parsePayload:273-278`
hard-refuses nodes emitting conflicting `MessageType`/`type` (or
`Zone`/`zone`). Bind an explicit fleet-wide-upgrade runbook step before
C1 — C-touching changes are wire-compatible in steady state but brittle
half-migrated.

### C1 — Define the seam
Add `{Scope, TypeToken string, Payload json.RawMessage}` to the carrier
(generalize `SyncRequest`/`IncomingMessage`, `transport.go:153`); keep
the live `RouteToCallback` seam; widen `IncomingMessage` to carry
`TypeToken`. Additive — both sides still work. **Wire note:** the verb
stays a JSON payload key `"MessageType"` (`chunk_notify_handler.go:256`);
the carrier-struct field name is wire-irrelevant *as long as C6 keeps
marshalling `"MessageType"` with the same value*.

### C2 — Collapse the send side
Replace the typed `DNSTransport.Sync/Keystate/Edits/Config/Audit`(+
`SendStatusUpdate`) methods with one generic `Send(ctx, peer, Scope,
TypeToken, rawPayload)` (Hello/Beat/Ping/Confirm keep their own typed
entry points). Rewrite the MP send wrappers (`SendSyncWithFallback`,
`sendRfiToSigner/Combiner`, `sendKeystateToSigner`, `sendConfigToAgent`,
`sendAuditToAgent`) to set `TypeToken`. Preserve `SendStatusUpdate`
fire-and-forget semantics.

### C3 — Move receive handlers to tdns-mp (preserve role sets + inline ACK)
Move the 8 MP handlers (`HandleSync/Rfi/Keystate/Edits/Config/Audit/
StatusUpdate/Relocate`, `handlers.go:220-686`) into tdns-mp behind one
`RouteToCallback` dispatcher keyed on `TypeToken`; transport keeps
`HandleHello/Beat/Ping/Confirmation`. **Preserve role-specific handler
sets** (pass-2 C-2/H5): the registration *mechanism* is one loop, but
each role registers a different set — combiner `HandleUpdate`/
`NewCombinerSyncHandler` async-confirm (`combiner_chunk.go:1428`), signer
keystate/rfi/status subset (`router_init.go:507`). Combiner/signer
processes build `MPTransportBridge` with config-only `AuthorizedPeers`
and **no `AgentRegistry`** (`main_init.go:302-384`) — their dispatch
registration must work without it (not an agent-only `RegisterAppHandler`
loop). **Preserve inline-ACK** (`ctx.Data["response"]` for the NOTIFY
confirm path, `HandleSync:266`, `HandleKeystate:380`, + combiner async
confirm). Collapse the MP-side duplicate verb table `routeIncomingMessage`
(`hsync_transport.go:567`) into the one dispatcher — no third table.
Delete the role routers `InitializeCombinerRouter`/`InitializeSignerRouter`
+ configs.

### C4 — Move MP types out
Move `SyncType`, `Keystate/Edits/Config/Audit` req+resp,
`KeyInventoryEntry`, `RejectedItemDTO` (`transport.go:19-305`,
`dns.go:1305`) to tdns-mp; drop the MP `core.` imports, leaving only
wire/crypto types (`CHUNK`, `TypeCHUNK`, `Format*`, `JWK`, `TypeJWK`,
`ExtractManifestData`). *Validate: tdns-transport builds with no MP
`core` body types.*

### C5 — Split `chunk_notify_handler` (preserve the DoS gate + callbacks)
Keep generic reassembly/decrypt (`extractChunkPayload:143`,
`fetchChunkViaQuery:191`, decrypt `:464-486`, QNAME `<distid>.<sender>`
parse `:121`); move MP payload parsing (`parsePayload:255`, beat-zone
`:534`, **zone** authz `:548`) into tdns-mp. After reassembly+decrypt
the handler feeds the one `(senderID, TypeToken, rawPayload)` callback.
**Binding DoS invariant:** the pre-crypto **sender** authz
(`:434`, `IsPeerAuthorized(sender,"")`, before `fetchChunkViaQuery`+
decrypt) **stays in transport**; only the post-decrypt **zone** authz
moves to MP. Do not merge the two `IsPeerAuthorized` calls above the
seam. List the `ChunkHandler` MP callbacks to preserve:
`IsPeerAuthorized`, `OnConfirmationReceived`, `GossipForPeer`,
`OnPeerDiscoveryNeeded` (`hsync_transport.go:321-416`).
**Third authz layer (pass-2 C-4):** `NewAuthorizationMiddleware`
(`router_init.go:63/295/441`) — peer-level authz stays in transport for
transport-own verbs; the app-verb middleware is removed (app authz is
post-callback in MP).
**Envelope label + in-channel CHUNK coordination (decided).** Two
efforts edit this same file and both touch "how does the receiver know
if the payload is encrypted?" — today a fragile byte-sniff
(`IsPayloadEncrypted()`). Decision (principle 9): replace it with an
explicit `envelope = none|jose|cose` indicator on the message (DOQ →
`none`; Do53 → `jose`). Land that envelope label **as part of C5** (one
file surgery, not two), coordinating with the in-channel-CHUNK / DOQ
design (`tdns-transport` `2026-05-27-in-channel-chunk-transport-design.md`
and the related tdns-nm DOQ notes). The only residual timing question is
whether the DOQ work needs the label before C5 is scheduled — if so,
pull just the label out as a tiny pre-C5 step. **Wire note:** the
envelope indicator is an **additive** field (Do53 peers default to
`jose` when absent); Stage C probe stays INVARIANT for mixed fleets as
long as senders omitting the field behave as today.

### C6 — Minimize constants + payload types
Reduce `MessageType` constants to transport-own
(`ChunkNotify/ChunkQuery/Hello/Beat/Ping/Confirm`; the uppercase ones at
`dns_message_router.go:23` are unused for routing); collapse
`DetermineMessageType` (`router_init.go:548`) to "return the
`TypeToken`"; move the 7 MP `Dns*Payload` structs + parse helpers to MP,
keep the 5 own ones. **Wire-safety gate:** the moved structs MUST keep
marshalling `"MessageType"` with the same value — a renamed/`omitempty`
tag is a silent wire break (→ RcodeFormatError). This is the highest
wire-break risk in C.

### C7 — Remove zone concepts from transport (was Stage A "A5")
Delete `ZoneRelation` (`peer.go:155`), `Peer.SharedZones` (`:81`),
`AddSharedZone`/`GetSharedZone(s)`/`ByZone` (`:546-688`) and the MP
callers (`agent_utils.go:87,91`; `hsync_transport.go:1493`). Lands here
because the `HandleSync` zero-shared-zones gate (`handlers.go:223`, the
"LEGACY agent cannot send" path) and the outbound-beat zone source moved
to MP in C3/A2 — transport no longer needs zones. **Rewrite/retire**
`TestTransportBoundary_LegacySyncRejection` (`transport_integ_test.go:361`,
asserts empty `peer.GetSharedZones()`), which can no longer pass once
the gate is MP-side (pass-2 B2).

**Probe — Stage C: INVARIANT** (pure relocation; wire unchanged) with
caveats: exercise **both edns0 AND query modes** (the verb also rides
the query-mode manifest `content`, `distrib/manifest.go:82`); exercise
SYNC + RFI + **combiner async confirm** + an election cycle; and a
mixed-version pair to validate the runbook. The most likely surprise is
C6 (json-tag drift) and C5 (a dropped field during parse relocation
that delivers but no longer dispatches).

---

# Stage D — Liveness & send semantics (Phase 5 remainder)

**Goal:** finish liveness/send: relocate fallback into the TM, make
liveness transport-owned, wire lifecycle in TM startup.

- **D1 — Relocate Hello/Beat fallback into the TM.** Today
  `SendHelloWithFallback`/`SendBeatWithFallback` (`hsync_transport.go:1536/1645`)
  try API **then** DNS, "any success" — *sequential*, not concurrent.
  D1 relocates **that exact semantics** into the TM (TM `Send` currently
  rejects Hello/Beat, `manager.go:346`). INVARIANT, no behavior change.
  **Constraint (principle 8):** keep the per-mechanism send/result shape
  string-keyed (API/DNS/DOQ/…), not a 2-element API/DNS shape, so
  per-mechanism parallel and new mechanisms are later local changes.
  Per-**peer** beats are already concurrent (`go func` per peer in
  `hsync.Engine.sendHeartbeats`/`sendInfraBeats`), so the comms-matrix
  skew from a non-responding peer is already avoided; per-**mechanism**
  parallel (relevant only for multi-mechanism peers — moot while the
  fleet is DNS-only) is the optional follow-up. When DOQ lands, extend
  `ValidateAgentSupportedMechanisms` (`config_validate.go`) to accept it
  (principle 8).
- **D2 — Transport-owned liveness middleware.** A default middleware
  updates `Peer.Mechanisms[mech]` on hello/beat receipt; delete the
  manual updates in combiner/signer handlers.
- **D3 — Lifecycle into TM startup.** Enumerate the scattered
  registration sites (chunk-notify, incoming router, role routers across
  `start_*.go` + `main_init.go`, pass-2 D-3) and move them into TM
  startup.

**Probe — INVARIANT** under all-mechanisms-healthy; **EXPLAINED DELTA**
only if true-parallel is later pursued (out of D1 scope).

---

# Stage E — Discovery into transport (Phase 6 part 2)

**Goal:** move the discovery mechanism into transport; delete the
`DiscoveryDriver` seam. MP keeps "who to discover" (HSYNC3→`MarkNeeded`).

- **E1 — Move the discovery mechanism into transport**, unifying **all
  discovery entry points** (pass-2 E-1/H4): (1) `hsync/discovery.go`→
  `DiscoverPeer` seam, (2) legacy `AgentRegistry.attemptDiscovery`
  (`agent_utils.go:588`) via `DiscoveryRetrierNG`, (3)
  `OnPeerDiscoveryNeeded` on the chunk handler (`hsync_transport.go:379`),
  and (4) **peer reset** (`apihandler_peer.go:136`) which calls
  `attemptDiscovery` directly. Identity→{addr,key,SVCB} resolution moves
  to the transport `DiscoveryService` (and the identity crypto fields
  deferred from A4 land here naturally).
- **E2 — Delete the `DiscoveryDriver` seam** (`hsync_transport.go:491`,
  `RunDiscovery:504`).

**Probe — INVARIANT:** a peer restart → rediscovery → reaches
OPERATIONAL (the 2026-05-28 KNOWN→OPERATIONAL gap — fix opportunistically
here); `OnDiscoveryFailed` fires on all failure paths.

---

# Stage F — Finish

- **F1 — `Gossip`→`AppData` rename** — the ONLY deliberate wire break
  (master Appendix H.4). Enumerate **all** gossip tag sites: the
  inconsistent `BeatRequest` `json:"gossip"` (`transport.go:137`) vs
  `DnsBeatPayload` `json:"Gossip"` (`dns.go:1253`), plus beat-response
  and any other payloads (pass-2 F-1). Coordinate with C1's `Payload`.
  Fleet-wide coordinated upgrade.
- **F2 — Doc/cleanup** — per-Stage rollback criteria (largely subsumed
  by the probes); the stale `init.go` integration guide referencing the
  `IncomingChan` goroutine (production uses `RouteToCallback`,
  `main_init.go:440` sets `IncomingChan: nil`, pass-2 F-2).
- **F3 — Phase 8–9 leftovers** — reconcile against code; verify nothing
  remains MP-coupled in transport.

**Probe — EXPLAINED DELTA (wire break) at F1:** old↔new nodes cannot
exchange gossip; upgrade the fleet together. All other Steps preserve
heterogeneous operation.

---

# Cross-stage rules & known issues

- **Lock order (binding):** `AgentRegistry.mu` → peer mutex →
  `transport.PeerRegistry` → `transport.Peer`. Single-writer per peer
  field. Run `-race` on the boundary/hsync suites at every A/C Step.
- **Heterogeneous-fleet safety:** every Step except F1 is
  wire-compatible. C-touching Steps need the prompt fleet-wide upgrade
  runbook (the `parsePayload` strict-check brittleness).
- **The 2026-05-28 tactical patches** (`GetOrCreatePeer` address copy;
  `zoneParticipants` derivation) are **down payments** on A4 and A2 — not
  separate work.
- **Known runtime issues** (`project_peer_discovery_fallout_status.md`):
  post-restart KNOWN→OPERATIONAL gap (fix at E1), espresso election
  churn, ping-tries-API-on-DNS-peer. Fix opportunistically when a Stage
  touches that code.

# Execution checklist (per Step)

1. On the implementation feature branch (NOT
   `peer-discovery-engine-extraction`).
2. Refresh the code map for the Step against `_test-ext` (the line
   numbers here are 2026-05-30; the branch differs from stock tdns-mp —
   pass-2 E-2/Part-1).
3. Capture the Stage's probe baseline (first Step of a Stage; after
   Stage 0).
4. Implement; `gofmt -w`; build all affected repos (tdns-mp **and**
   tdns/tdns-transport where touched).
5. Re-run the probe; compare to the predicted post-state; `-race` where
   relevant.
6. One Step = one commit; push; operator deploys + verifies on the
   testbed. **Lettered sub-steps are Steps** — e.g. A1.0, A1.1, A1.2
   are three commits, not one; A4a/A4b likewise. Unlettered Stage
   entries (C1, C2, …) are one commit each.

# Remaining open decisions (few)

1. **DOQ-vs-C5 timing** — the explicit `envelope` label is decided
   (principle 9) and lands with C5. The only residual: if the DOQ /
   in-channel-CHUNK work needs the label *before* C5 is scheduled, pull
   the label out as a tiny pre-C5 step. (Timing only, not design.)
2. **Per-mechanism parallel Hello/Beat** — optional follow-up after D1,
   relevant once multi-mechanism peers (e.g. DOQ alongside DNS) exist.
   Not a one-way door; D1 just must keep the mechanism shape string-keyed
   (principle 8). Per-peer concurrency already exists.
