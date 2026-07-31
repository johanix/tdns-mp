# Transport Redesign: Phased Implementation Plan (May 2026)

Date: 2026-05-22
Status: **CURRENT** — step-level execution plan
Builds on: [2026-05-21-transport-redesign-status-and-roadmap.md](./2026-05-21-transport-redesign-status-and-roadmap.md)
Supersedes for execution: stream sequencing in §6 of the roadmap

This document turns the roadmap's streams (S1–S9) into a sequence of
**individually executable steps**. Each step is sized to be completed
without losing focus, and each is annotated with whether it leaves the
tree in a shippable state or opens a breakage window.

> Scope decisions baked into this plan (confirmed 2026-05-22):
> full **L2** (S1–S8), S9 as an optional appendix; wire-breaking work
> is **branch-isolated** (a dedicated branch that merges as a unit);
> baseline **assumes Cut A is already merged** (see §1).


## 0. How to read this plan

### 0.1 Breakage flags

Every step ends with one of:

- **[G] Green** — after this step both repos build and all seven
  `TestTransportBoundary_*` scenarios pass. Independently shippable;
  safe to stop here indefinitely.
- **[D→Sx.y] Degraded** — builds and tests pass, but a feature is
  dual-pathed or reduced until step `Sx.y`. Shippable but not "done".
- **[W→Sx.y] Window** — does **not** independently build/work in a way
  you'd ship to `main`. Opens a breakage window that closes at step
  `Sx.y`. Only used inside the dedicated wire-break branch.

The intent is that the trunk is **always [G]**. The only [W] steps in
this plan live on one isolated branch (Phase D), exactly matching the
"branch-isolated breaks" policy.

### 0.2 The verification gate (run after every step)

A step is not "done" until all of these pass:

1. tdns build: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
2. tdns-mp build: `cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make`
   (and `tdns-mp/v2` compiles)
3. transport repo build (only when the step touched it):
   `cd tdns-transport/v2 && GOROOT=/opt/local/lib/go go build ./...`
4. Harness: from `tdns-mp/v2`, `go test -run TestTransportBoundary -v`
   — all seven scenarios green.

Per project rules: this is a development machine. The build/test gate
above is for "does it compile and do the boundary tests pass" only;
runtime behaviour is validated on the NetBSD VMs, not here.

### 0.3 Two-repo coordination

`tdns-mp/v2/go.mod` pins `tdns-transport/v2` to a **published
pseudo-version**, not a local replace:

```
github.com/johanix/tdns-transport/v2 v2.0.0-20260427162659-...
```

`tdns/v2` is locally replaced (`=> ../../tdns/v2`) but transport is not.
Consequence: any step that edits the transport library cannot be
validated against tdns-mp until transport is republished — unless we
add a temporary local replace. **Prerequisite P2 (below) adds that
replace** so the whole refactor can be co-developed in-tree. The
replace is dropped (and a real version published) only when a
transport-touching branch merges.

Streams and the repos they touch:

| Stream | tdns-transport | tdns-mp |
|--------|:--------------:|:-------:|
| S1 discovery | yes (mechanics) | yes (callback) |
| S2 one registry | minor (accessors) | yes (bulk) |
| S3 peer fields | yes | small |
| S4 scope fields | yes | small |
| S5 type migration | yes (bulk) | yes (bulk) |
| S6 CHUNK split | yes | yes |
| S7 send/lifecycle | yes | yes |
| S8 bridge deletion | no | yes (bulk) |
| S9 data engine | no | yes |

Note: S6 touches transport but is **non-wire-breaking** (its spec is
explicit: "No wire format changes" — it adds one callback symbol). It
therefore stays on trunk, unlike S5.


## 1. Baseline and prerequisites

### 1.1 Assumed baseline (P0) — Cut A merged

This plan starts from the state the roadmap *describes* as as-built:
the `tdns-mp/v2/hsync/` package exists (engine, registry, peer,
discovery, dispatch, gossip, hsync3_diff, reconcile, interfaces), plus
`hsync_bridge.go`, `hsync_bridge_sync.go`, `hsync_data_engine.go`,
`hsync_agent_gossip.go`, `auditor_hsync_check.go`.

**Reality check (2026-05-22):** that code lives only on branch
`peer-discovery-engine-extraction` (= `main` + 45 clean,
fast-forwardable commits). It is **not** on `main` or on the current
`feat/sig-validity-mp-sync` branch. Merging that branch is **P0** and
is handled outside this plan. Every step below assumes P0 is done.

### 1.2 Establish a green baseline (P1)

After P0, run the full gate (§0.2) and record that all seven
`TestTransportBoundary_*` scenarios pass. This is the reference green
state. Do not start S1 until P1 is green.

### 1.3 Enable in-tree co-development (P2)

Add a local replace to `tdns-mp/v2/go.mod`, mirroring the existing tdns
block:

```
replace github.com/johanix/tdns-transport/v2 => ../../tdns-transport/v2
```

Pick a working branch in the `tdns-transport` repo (it is currently on
`transport-refactor-semi-easy-bites`; create a fresh
`transport-redesign` branch off whatever commit matches the pinned
pseudo-version). This replace stays for the duration of S1–S7 and is
removed at S5.5 / final publish.

### 1.4 Doc hygiene (S0) — do this first, it is cheap

- **S0.1** The two docs the roadmap calls "authoritative" **do exist —
  on the `peer-discovery-engine-extraction` branch**, not on `main`/
  current. `2026-04-30-peerregistry-field-disposition.md` (the 14-field
  S3 map) and `2026-04-30-chunk-notify-handler-split.md` (the S6 cut
  line) arrive with the P0 merge. They are authoritative for S3 and S6
  respectively; this plan defers to them. Nothing to write. **[G]**
- **S0.2** Refresh the `hsync_transport.go` disposition: the
  `MPTransportBridge` is ~2318 LOC / ~47 methods on the extraction
  branch (categorized in §7.1). Capture that table or delete the stale
  reference. **[G]**
- **S0.3** Add rollback/abort criteria to the roadmap: each phase below
  ends [G], so rollback = revert the phase's commits; the abort signal
  is any `TestTransportBoundary_*` regression that cannot be fixed
  within the same step. **[G]**

### 1.5 Known correctness nit to fix early

`OnPeerDiscovered` is wired as `func(peerID string)` at
`hsync_transport.go` (init block ~lines 446–481), but the roadmap and
target API specify `func(*transport.Peer)`. Fix the signature in S1.2;
don't carry the string form forward.


## 2. Phase map

| Phase | Streams | Steps | Trunk state | Calendar |
|-------|---------|-------|-------------|----------|
| **Pre** | P0–P2, S0 | merge + baseline + replace + docs | [G] | ~1 day |
| **A** | S1 | S1.0–S1.5 | all [G] | 1–1.5 wk |
| **B** | S2 | S2.0–S2.7 | all [G] (large steps) | 2–3 wk |
| **C** | S3, S4, S6 | S3.1–S3.6, S4.1–S4.2, S6.1–S6.2 | all [G] | 2–3 wk |
| **D** | S5 | S5.1–S5.5 | **branch [W]**, merges [G] | 3–4 wk |
| **E** | S7, S8 | S7.1–S7.2, S8.1–S8.5 | all [G] | 2–4 wk |
| **F** | S9 (opt) | S9.1–S9.3 | all [G] | 1–2 wk |

Hard ordering constraints:

- S1 before S2 (discovery must write one store before we delete the
  duplicates).
- S2 before S3 (mechanism state must be the sole source before legacy
  single-state fields can be deleted).
- S4.1 before S4.2; S4 has a soft dependency on S5 (see S4.1 note).
- S5 before S8.
- **S6 is independent** (non-wire-breaking, trunk) — it may land any
  time after P1, in parallel with A/B/C; it feeds S8's dispatch
  relocation.
- S7 independent of S5 but feeds S8.
- S8 last (needs S5–S7).
- S9 may run any time after S2 (independent of D/E).


## 3. Phase A — Discovery into transport (S1)

**Goal:** the IMR/URI/SVCB/JWK/TLSA mechanics and `transport.Peer`
population live in the transport library; `DiscoverPeer` no longer
delegates to an MP `DiscoveryDriver`; MP work happens only in
`OnPeerDiscovered(*Peer)`. Delete `DiscoveryDriver`,
`DiscoverAndRegisterAgent`, and the transport-write half of
`RegisterDiscoveredAgent`.

**Why first:** it is the architectural unlock for one registry — once
discovery writes only `transport.Peer`, the dual-write into
`AgentRegistry` becomes a pure MP concern that S2 can remove.

**Current shape (extraction branch):**
- `agent_discovery.go`: `DiscoverAgent` (mechanics → `AgentDiscoveryResult`),
  `DiscoverAgentAPI/DNS`, `RegisterDiscoveredAgent` (dual write to
  `PeerRegistry` + `AgentRegistry`, lines ~162–361), `DiscoverAndRegisterAgent`
  (wrapper ~364).
- `agent_discovery_common.go`: `LookupAgentAPIEndpoint`,
  `LookupAgentDNSEndpoint`, `LookupServiceAddresses`, `LookupAgentJWK`,
  `LookupAgentKEY`, `LookupAgentTLSA` — all on MP's `*Imr`.
- `transport/manager.go`: `DiscoverPeer` (~417) → `DiscoveryDriver.RunDiscovery`
  (interface ~147), a temporary seam.
- `hsync/discovery.go`: `MarkNeeded` → `attemptDiscovery` →
  `TransportBridge.DiscoverPeer`.
- `hsync_bridge.go`: `DiscoverPeer`, `RegisterDiscovered`,
  `AfterDiscoverPeer`.

**Steps:**

- **S1.0 — Harness: cover the discovery path.** Today only
  `TestTransportBoundary_DiscoveryComplete` touches discovery, and only
  the *outcome* callback. Add a scenario that drives `DiscoverPeer`
  with a fake/stub resolver and asserts the resulting `transport.Peer`
  has mechanisms, keys, and `PeerStateKnown`, and that
  `OnPeerDiscovered` fires. Pin current behaviour before refactoring.
  Files: `transport_integ_test.go`, `transport_harness_test.go`. **[G]**

- **S1.1 — Build native discovery mechanics in transport.** In
  `tdns-transport`, implement URI→SVCB→JWK/TLSA resolution and
  `transport.Peer` population using `transport.Imr`, as a new internal
  function (e.g. `(tm *TransportManager) discover(ctx, identity)`).
  Port the logic of the MP `Lookup*` helpers. Not yet wired into
  `DiscoverPeer`. Unit-test in the transport repo. Files (transport):
  new `discovery.go`, `manager.go`, `imr.go`. **[G]** (additive)

- **S1.2 — Fix callback shapes.** Change `OnPeerDiscovered` to
  `func(*Peer)` and add `OnDiscoveryFailed(*Peer, error)` in transport;
  update the MP wiring at `hsync_transport.go` (~446–481) to the new
  signatures. The MP callback body still calls into the existing
  registration for now. **[G]**

- **S1.3 — Switch `DiscoverPeer` to native mechanics; split the write.**
  Point `transport.DiscoverPeer` at S1.1's `discover()`; on success it
  populates `transport.Peer` and fires `OnPeerDiscovered(peer)`. Move
  the MP half of `RegisterDiscoveredAgent` (AgentRegistry create/update,
  zone association) **into** the `OnPeerDiscovered` callback, and
  **remove** the transport-write half (it is now done by transport).
  This is the cohesive cut: do the switch and the write-removal in one
  step so there is never a double write. Files: `transport/manager.go`,
  `agent_discovery.go`, `hsync_transport.go`, `hsync_bridge.go`. **[G]**

- **S1.4 — Delete the temporary seam.** Remove `DiscoveryDriver`,
  `RunDiscovery`, `DiscoverAndRegisterAgent`, and the emptied
  transport-write portions of `RegisterDiscoveredAgent`. Confirm
  `hsync.Engine.attemptDiscovery` → `TransportBridge.DiscoverPeer` →
  `TransportManager.DiscoverPeer` still flows. **[G]**

- **S1.5 — Retire legacy fallback discovery.** Grep for any
  `attemptDiscovery`/direct-IMR fallback outside `hsync/discovery.go`
  (pre-Cut-A this lived in `agent_utils.go`; verify it is gone on the
  extraction branch). Remove or guard so discovery has exactly one
  path. **[G]**

After Phase A: discovery mechanics are transport-owned; MP only triggers
by identity and reacts via callback. The `AgentRegistry` write is now an
explicit, isolated callback — ready to be deleted in S2.


## 4. Phase B — One peer registry (S2)

**Goal:** `transport.PeerRegistry` is the only authoritative peer map.
Eliminate the duplicated transport state held by `hsync.Peer` and
`Agent`; reduce `hsync.Registry.S` and `AgentRegistry.S` to
non-authoritative indices (or delete them).

**The duplication, precisely (extraction branch):**

Three peer representations carry overlapping per-transport state:

| Store | Where | Per-transport state |
|-------|-------|---------------------|
| `transport.Peer` | `tdns-transport/.../peer.go` | `Mechanisms map[string]*MechanismState` (canonical) + legacy single-state fields |
| `hsync.Peer` | `hsync/types.go:88` | `ApiDetails`, `DnsDetails` (`*PeerDetails`) |
| `Agent` | `agent_structs.go:58` | `ApiDetails`, `DnsDetails` (`*AgentDetails`) |

The glue is `hsync_bridge_sync.go` (9 converters:
`hsyncPeerToAgent`, `syncHsyncPeerFromAgent`, `persistAgentAndPeer`,
`agentToHsyncPeer`, `hsyncDetailsToAgent`, `agentDetailsToHsync`,
`agentForTransport`, `syncHsyncPeerToAgent`, `mergeAgentDetails`) plus
`mpHsyncBridge` in `hsync_bridge.go` (converts on every `SendHello` /
`SendBeat` / `RegisterDiscovered`).

**The seam that makes this tractable:** `hsync.Engine` looks up peers
**only** by `PeerID` via `registry.S.Get → *hsync.Peer`, and reaches
transport **only** through the `TransportBridge` interface
(`hsync/interfaces.go`). It never touches `transport.Peer` directly.
So if we (a) make `hsync.Peer` a thin overlay over a shared
`*transport.Peer`, and (b) move zone membership to the registry index,
the engine's call sites barely move.

**Recommended approach: thin overlay, then dissolve.** `hsync.Peer`
becomes `{ *transport.Peer; Zones; Deferred; IsInfraPeer }` (MP-only
extras), reading all transport state from the embedded pointer. Then
the registry stops storing peers and becomes an index.

- **S2.0 — Decide where MP-only per-peer extras live (the roadmap's
  open question).** Resolution for this plan: keep MP extras on the MP
  side, not on `transport.Peer`. Specifically: zone membership →
  `Registry.RemoteAgents` index (already exists); deferred tasks →
  engine-internal map keyed by `PeerID`; `IsInfraPeer` and
  `ApiMethod`/`DnsMethod` → derive from `transport.Peer.Mechanisms`
  presence where possible, otherwise a small `map[PeerID]peerExtras`
  on the host. Record this as a short ADR in the doc. **[doc only, G]**

- **S2.1 — Add the accessors the engine needs to `transport.Peer`.**
  Confirm/extend `transport.Peer` with mechanism-aware getters
  equivalent to `hsync.Peer.EffectiveState()`, `apiState()`,
  `dnsState()`, `IsAnyTransportOperational()`, and per-mechanism
  contact/beat reads. Most exist via `Mechanisms`; fill gaps. Files
  (transport): `peer.go`. **[G]** (additive)

- **S2.2 — Collapse transport-state duplication out of `hsync.Peer`.**
  Change `hsync.Peer` to embed `*transport.Peer`; delete its
  `ApiDetails`/`DnsDetails`/`State`/`LastState` fields; reroute
  `hsync.Peer` methods and the `transport_peer.go` helpers
  (`peerDetailsFor`, `applyInboundBeat`, `beatOutboundSequence`, …) to
  the embedded peer. Delete the now-dead transport-state converters in
  `hsync_bridge_sync.go` (`hsyncDetailsToAgent`/`agentDetailsToHsync`
  shrink to MP-extras only). Large but cohesive; ends green. Files:
  `hsync/types.go`, `hsync/transport_peer.go`, `hsync_bridge_sync.go`,
  `hsync_bridge.go`. **[G]** (large — may be split with a flagged
  [W] window if needed; prefer keeping atomic)

- **S2.3 — Share one instance.** Ensure the `hsync.Peer` overlay wraps
  the **same** `*transport.Peer` returned by
  `PeerRegistry.GetOrCreate` (no copy). `mpHsyncBridge` stops creating
  parallel peers. Files: `hsync/registry.go`, `hsync_bridge.go`. **[G]**

- **S2.4 — Zones off the peer, onto the index.** Make the engine read
  zone membership exclusively via `Registry.RemoteAgents` /
  `GetPeersForZone` / `sharedZones()` rather than `peer.Zones`. Remove
  `Zones` from the overlay. This also pre-clears S4. Files:
  `hsync/registry.go`, `hsync/reconcile.go`, `hsync/hsync3_diff.go`,
  `hsync/gossip.go`. **[G]**

- **S2.5 — Make `transport.PeerRegistry` the authoritative map.** The
  engine looks up `*transport.Peer` from `transport.PeerRegistry`;
  `hsync.Registry` keeps only the zone index, hello-cancel map, and
  deferred-task map — no peer storage. Delete `Registry.S`. Files:
  `hsync/registry.go`, `hsync/engine.go`, `hsync/{beat,hello,discovery}.go`.
  **[G]** (large)

- **S2.6 — Shrink `Agent`.** Remove `ApiDetails`/`DnsDetails`/`State`
  duplication from `Agent`; route its transport reads to
  `transport.Peer` via `PeerID`. ~40+ files reference `Agent` /
  `AgentRegistry`; do this grouped, one consumer area per sub-step,
  each green:
  - **S2.6a** combiner paths (`combiner_*`). **[G]**
  - **S2.6b** signer paths (`signer_*`). **[G]**
  - **S2.6c** agent/SDE paths (`syncheddataengine.go`, `hsync_*`). **[G]**
  - **S2.6d** CLI + API handlers (`apihandler_*`, `*_cmds.go`). **[G]**

- **S2.7 — Reduce `AgentRegistry.S`.** Either delete it or keep it as a
  non-authoritative view. `AgentRegistry` retains its real services:
  `RemoteAgents`, `LeaderElectionManager`, `ProviderGroupManager`,
  `GossipStateTable`, `HsyncEngine`. Files: `agent_structs.go`,
  `agent_utils.go`. **[G]**

After Phase B: one authoritative peer map (`transport.PeerRegistry`);
`hsync` and `AgentRegistry` hold indices/services only;
`hsync_bridge_sync.go` is largely gone.


## 5. Phase C — Peer field + scope cleanup (S3, S4)

### 5.1 S3 — delete legacy single-state fields on `transport.Peer`

**Authoritative spec:** `2026-04-30-peerregistry-field-disposition.md`
(arrives with P0). It maps **14** in-scope fields, every read site, the
replacement expression, and the precursor helpers needed. Canonical
per-mechanism state lives on `Mechanisms map[string]*MechanismState`.

In scope (14, peer.go ~55–101): `State`, `StateReason`, `StateChanged`,
`DiscoveryAddr`, `OperationalAddr`, `APIEndpoint`, `LastHelloSent`,
`LastHelloReceived`, `LastBeatSent`, `LastBeatReceived`, `BeatSequence`,
`ConsecutiveFails`, `Stats`, `PreferredTransport`. Out of scope:
identity/crypto fields, and `SharedZones`/`ZoneRelation` (that is S4).

The spec sorts these by precursor cost. Execute as six PR-sized steps,
each ending green:

- **S3.1 — Group A, one-swing deletes (no precursor).** Delete
  `StateReason`, `StateChanged`, `LastHelloSent`, `LastHelloReceived`,
  `LastBeatReceived` — zero real read sites (only dual-write plumbing).
  ~25-line diff. **[G]**

- **S3.2 — `APIURL()` helper + delete `APIEndpoint`.** Add
  `(p *Peer) APIURL() string` (the "API" mechanism `Address` is an
  `*Address`, but `APIEndpoint` is a URL string — the helper isolates
  the encoding), then convert all 13 read sites: 8 presence-only →
  `HasMechanism("API")`, 5 need the URL string. **[G]**

- **S3.3 — `AggregateStats()` helper + delete `Stats`.** Add
  `(p *Peer) AggregateStats() MessageStatsSnapshot`; of 11 read sites,
  6 want aggregates and 5 are mechanism-aware. Precursor audit: confirm
  `stats_middleware.go` carries the mechanism name in `ctx` so per-mech
  writes route correctly. **[G]**

- **S3.4 — Beat trio.** Add mech-aware
  `RecordBeatSentOn(mech)` / `RecordBeatReceivedOn(mech)` /
  `RecordFailureOn(mech)`, then delete `LastBeatSent`, `BeatSequence`,
  `ConsecutiveFails` **together** (they share the same
  `RecordBeatSent`/`RecordBeatReceived`/`RecordFailure` writers).
  **[G]**

- **S3.5 — `State` + `PreferredTransport`.** Replace with the existing
  `EffectiveState()` / `PreferredMechanism()`. Two semantic shifts to
  call out in the commit message: `IsHealthy` becomes aggregate-health;
  `PreferredMechanism()` is availability-derived (a peer whose API
  endpoint vanishes auto-falls-back to DNS) vs the old sticky
  `PreferredTransport` set once at discovery. **[G]**

- **S3.6 — `DiscoveryAddr` / `OperationalAddr` (messiest, last).**
  `db_hsync.go` (PeerRecord build ~541/554) persists the discovery and
  post-Relocate addresses separately. **Design decision required:**
  either (a) add `MechanismState.OperationalAddress` (two addresses per
  mechanism), or (b) accept `CurrentAddress()` as the only address and
  stop persisting them separately. Then restructure the db_hsync
  row-build to iterate `Mechanisms` instead of the single fields. **[G]**

### 5.2 S4 — remove `SharedZones`/`ZoneRelation` from `transport.Peer`

Zone membership becomes an MP index + hello `Scopes`, never transport
state (decision D2). Today `transport.Peer` has
`SharedZones map[string]*ZoneRelation` (peer.go ~81, type ~154) with
`AddSharedZone`/`GetSharedZone`/`GetSharedZones`/`ByZone`.

- **S4.1 — Relocate the LEGACY-peer check.** `handlers.go:694` decides
  "legacy peer" via `peer.GetSharedZones() == 0` — this is MP semantics
  inside transport. Move the decision to an app callback
  (e.g. `IsPeerScoped(senderID) bool`) that MP answers from its zone
  index, and repoint harness scenario 5. **Soft dependency on S5:** if
  you prefer not to add a callback now, defer S4.2 until the S5 branch
  where this handler moves to MP anyway. **[G]** (callback path) /
  **[D→S5.2]** (defer path)

- **S4.2 — Remove the field and its methods.** Delete `SharedZones`,
  `ZoneRelation`, `AddSharedZone`, `GetSharedZone`, `GetSharedZones`,
  `ByZone`; update harness scenarios 3 and 5. Files (transport):
  `peer.go`, plus MP call sites in `agent_utils.go` (~86–90),
  `hsync_transport.go` (~1422). **[G]**

### 5.3 S6 — CHUNK handler split (trunk, independent of S5)

**Authoritative spec:** `2026-04-30-chunk-notify-handler-split.md`
(arrives with P0). The finding that changes sequencing: the split is
explicitly **"No wire format changes."** So S6 is **not** wire-breaking,
stays on trunk as [G] steps, is independent of S1–S5, and may land any
time after P1 (good parallel work).

Cut line: **between decryption (step 6) and JSON parse (step 7)** of
`RouteViaRouter`. Transport keeps steps 1–6 (QNAME parse, EDNS0/query
reassembly, pre-crypto DoS authz, decryption); MP takes steps 7–12
(parse, ctx build, zone extract, post-crypto zone-peer authz, router
dispatch, confirm-response). The contract is one new exported symbol +
one registration field:

```go
type DecryptedChunkHandler func(
    ctx context.Context, sender, distributionID string,
    payload []byte, req *dns.Msg, w dns.ResponseWriter) error
```

Authz placement: pre-crypto `IsPeerAuthorized(sender, "")` stays in
transport (it guards the expensive crypto step / DoS); post-crypto
`IsPeerAuthorized(sender, zone)` moves to MP (zone is an MP concept).
The spec verifies **no state crosses the cut** beyond the 5 callback
args.

- **S6.1 — Add the callback (additive).** Define `DecryptedChunkHandler`
  + a registration field on `ChunkNotifyHandler`; default wiring still
  routes internally so behaviour is unchanged. Files (transport):
  `chunk_notify_handler.go`. **[G]**

- **S6.2 — Move dispatch to MP.** New `tdns-mp/v2/chunk_dispatcher.go`
  (~330 lines) takes steps 7–12 + `parsePayload` + `sendConfirmResponse`;
  `RouteViaRouter` shrinks ~580 → ~250 lines and calls the callback
  after decryption. MP becomes sole owner of the
  `IsPeerAuthorized(_, zone)` callback. Harness: scenario 1 may need a
  small construction tweak; scenario 5 (REFUSED at the pre-crypto step,
  which stays in transport) is unchanged. **[G]**


## 6. Phase D — Type migration (S5)

**This is the only branch-isolated, wire-breaking phase.** Do it on a
dedicated branch in **both** repos (`transport-redesign-types` in each),
keep the local replace (P2) in place, and merge the branch **as a unit**
after publishing a new transport version. Trunk is untouched until merge.
(CHUNK — formerly grouped here as S6 — moved to §5.3: its spec confirms
no wire change, so it does not belong on this branch.)

### 6.1 What leaks today

MP-specific types currently exported by `tdns-transport`:

- `SyncType` + `SyncTypeNS/DNSKEY/GLUE/CDS/CSYNC` (transport.go ~20).
- Fully MP payloads in `dns.go`: `DnsKeystatePayload` (~1372),
  `DnsEditsPayload` (~1415), `DnsConfigPayload` (~1443),
  `DnsAuditPayload` (~1466), `DnsStatusUpdatePayload` (~1489).
- Partly-MP payloads: `DnsSyncPayload` (~1265: `Zone`, `ZoneClass`,
  `Publish`, `RfiType/Subtype`), `DnsHelloPayload` (~1203:
  `SharedZones`, `Zone`), `DnsBeatPayload` (~1238: `Zones[]`).
- `SyncRequest`/`SyncResponse` (transport.go ~153/172:
  `Zone`, `ZoneClass`, `RfiType`, `RfiSubtype`, `MessageType` variants).
- Message-type string branching: 8 of 12 types are MP
  (`sync`, `update`, `rfi`, `keystate`, `edits`, `config`, `audit`,
  `status-update`); the generic four are `hello`, `beat`, `ping`,
  `relocate`/`confirm`. Branch sites: `handlers.go` (~258, 301, 347,
  430, 487, 542, 598), `dns.go sendNotifyWithPayload` (~966–1099),
  `router_init.go` (~151–239).

### 6.2 Steps (all on the branch)

- **S5.1 — Create the MP payload home.** In `tdns-mp/v2`, define an mp
  payloads file/package and move `SyncType` + the five fully-MP
  payloads there. Refactor `DnsSyncPayload`/`Hello`/`Beat` to drop MP
  fields (zones → hello `Scopes` / `AppData`; `ZoneClass`/`Publish`/RFI
  → MP sync payload). **[W→S5.5]**

- **S5.2 — Transport carries opaque payloads.** Replace the 8 MP
  handlers in `handlers.go` with an app-provided handler registered
  through a callback; transport keeps only `hello`/`beat`/`ping`/
  `relocate`/`confirm`. Add an app (de)serialization hook. **[W→S5.5]**

- **S5.3 — De-MP `dns.go`.** `sendNotifyWithPayload` stops branching on
  MP message types (generic send); strip
  `Zone`/`ZoneClass`/`RfiType/Subtype` from `SyncRequest`/`SyncResponse`
  (move to the MP payload). **[W→S5.5]**

- **S5.4 — MP registers its handlers.** `router_init.go` registration of
  the 8 MP handlers moves to the MP side at startup. **[W→S5.5]**

- **S5.5 — Publish + bump + merge.** Build both repos green on the
  branch; run the harness; publish a new `tdns-transport/v2`
  pseudo-version; bump the `require` in `tdns-mp/v2/go.mod`; **remove**
  the local replace (P2); merge the branch as a unit. The wire break
  lands atomically. **[G]** (closes the window)


## 7. Phase E — Send/lifecycle + bridge deletion (S7, S8)

### 7.1 S7 — send + lifecycle in the TransportManager

- **S7.1 — Router registration on TM startup.** Move the per-binary
  router init (`main_init.go` signer ~240, combiner ~424, agent,
  auditor) into `TransportManager` startup so all four binaries share
  one wiring path. **[G]**

- **S7.2 — Centralize hello/beat liveness.** Resolve the parallel-send
  vs primary-then-fallback semantics: today
  `SendHelloWithFallback`/`SendBeatWithFallback` (hsync_transport.go
  ~1522/1631) are primary-then-fallback in the bridge. Move liveness
  state updates into TM middleware / stable TM APIs. Watch combiner and
  signer paths that still read `peer.State`. **[G]** (or small
  **[D→S8.x]** if a wrapper is left temporarily)

### 7.2 S8 — delete `MPTransportBridge`

The bridge is ~2318 LOC / ~47 methods (categorized in §7.1 of the
roadmap and re-mapped here). Extract piecewise, then delete the shell.
**Do not start until S5–S7 are merged.**

- **S8.1 — Extract trackers.** Move the DNSKEY-propagation tracker
  (`TrackDnskeyPropagation`/`ProcessDnskeyConfirmation`,
  `pendingDnskeyPropagations`) and the keystate-RFI state
  (`setKeystateRfi`/`getKeystateRfi`/`deleteKeystateRfi`,
  `keystateRfiState`) into standalone MP components. **[G]**

- **S8.2 — Extract enqueue + reliable queue.** Move
  `EnqueueForCombiner`/`EnqueueForZoneAgents`/`EnqueueForSpecificAgent`,
  `deliverGenericMessage`, queue stats, and `StartReliableQueue` into
  an MP component holding `*transport.TransportManager`. **[G]**

- **S8.3 — Relocate dispatch + RFI signaling.** Most `route*Message`
  methods moved to MP in S5; relocate the remainder plus
  `sendKeystateToSigner`/`sendRfiToSigner`/`sendRfiToCombiner`. **[G]**

- **S8.4 — Move peer/agent bridge remnants.** `SyncPeerFromAgent`,
  `GetOrCreatePeer`, `agentStateToTransportState` are largely obviated
  by S2; delete or relocate the leftovers. **[G]**

- **S8.5 — Delete the shell.** Remove `MPTransportBridge`; the four
  binaries hold `*transport.TransportManager` directly and wire
  components at startup. Update `main_init.go` (signer ~188, combiner
  ~342, agent ~522, auditor ~627). **[G]** (L2 checklist complete)


## 8. Appendix F — Data engine shell (S9, optional, D4)

Independent of D/E; may run any time after S2.

- **S9.1 — Inventory `HsyncDataEngine`.** `hsync_data_engine.go`
  (`Run`, `runAgentOnly`, `onSync/Election/KeyStateMessage`,
  `handleStatusUpdate`, `handleKeystateInventory`) is an agent-only
  shell over `hsync.Engine` + `AgentRegistry`. List what is engine
  lifecycle vs agent business logic. **[G, doc]**

- **S9.2 — Fold agent-only loop into SDE / direct hooks.** Move
  `runAgentOnly`'s channel handling (SyncQ, Command, StatusUpdate,
  KeystateInventory) into `SynchedDataEngine` or direct engine hooks.
  **[G]**

- **S9.3 — Remove the shell.** Delete `HsyncDataEngine`; callers
  construct `hsync.Engine` directly. **[G]**


## 9. Breakage windows (consolidated)

The trunk stays green through Phases A, B, C, E, F. The **only**
cross-step breakage window in the whole plan is Phase D:

| Window | Opens | Closes | Isolation |
|--------|-------|--------|-----------|
| Wire/type break | S5.1 | **S5.5** | dedicated branch in both repos; merges atomically; trunk untouched |

(S6/CHUNK is no longer a window: its spec confirms no wire change, so it
runs entirely on trunk as [G].)

Soft dependency: **S4.1** can either add a callback (stays [G]) or defer
its field removal (**S4.2**) into the S5 branch. Pick the callback path
to keep S4 fully green on trunk.

Large-but-green steps to watch (atomic, end green, but sizable — split
only with a flagged [W] if an agent loses focus): **S2.2**, **S2.5**,
**S2.6** (mitigated by the a–d split).


## 10. Per-step execution checklist

For each step:

1. Branch from trunk (or the Phase-D branch for S5/S6.2). Per project
   rule, commit to a feature branch; never push to `main` or merge a PR
   without explicit approval.
2. Make the change scoped to the step (no drive-by refactors).
3. `gofmt -w` every touched `.go` file.
4. Run the full gate (§0.2). For transport-repo edits, the local
   replace (P2) makes the tdns-mp build see them.
5. Confirm the step's flag: [G] steps must leave all seven scenarios
   green; [W] steps are only acceptable on the Phase-D branch.
6. Commit with a message naming the step (e.g. "S2.4: zones off peer,
   onto registry index"). No `--amend`, no `Co-Authored-By` trailer.


## 11. Corrections to the roadmap (discrepancies found 2026-05-22)

Captured so the roadmap can be reconciled:

1. **Cut A is not merged.** Roadmap §4.2 lists the `hsync/` engine as
   "Done in tree"; it lives only on `peer-discovery-engine-extraction`
   (main + 45 commits). This plan assumes it is merged (P0).
2. **The two "authoritative" docs DO exist — on the extraction
   branch**, not on `main`/current.
   `2026-04-30-peerregistry-field-disposition.md` (14-field S3 map) and
   `2026-04-30-chunk-notify-handler-split.md` (S6 cut line) arrive with
   the P0 merge and are authoritative for S3/S6. (My first pass searched
   only the current checkout and wrongly flagged them missing — the
   correction also revealed S6 is non-wire-breaking, which moved it off
   the Phase D branch onto trunk.)
3. **`OnPeerDiscovered` is still `func(peerID string)`** in code, not
   `func(*Peer)` as the roadmap's "done" table claims (fixed in S1.2).
4. **There is no in-memory third peer "struct" beyond the overlay
   nuance:** the three stores are `transport.Peer`, `hsync.Peer`, and
   `Agent`; `PeerRecord` (db_hsync.go) is a flat DB projection, not a
   fourth live registry. S2 targets the three live ones.
5. **Cross-repo pin, not replace:** `tdns-transport` is pinned by
   pseudo-version; co-development needs the temporary local replace
   (P2) and a publish+bump at S5.5.
