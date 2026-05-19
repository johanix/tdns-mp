# Splitting HsyncEngine: Shared Sync Conversation Engine
# + Agent-Only Data Engine

**Date:** 2026-05-19
**Status:** Design
**Related:**
- `2026-04-15-transport-interface-redesign.md`
- `2026-04-25-transport-refactor-early-bites.md`
- `2026-04-30-transport-refactor-semi-easy-bites.md`

## 1. Motivation

A live debugging session on `customer.mptest.` surfaced a
production-correctness failure caused by the current architectural
split between agents and auditors:

- Only agents run `HsyncEngine`. Auditors register peers reactively,
  only when they receive a verified inbound message.
- `auditor.mp` had a registry of `{fox, hare}` — the two agents
  whose first beats reached it — and was permanently blind to
  `agent.cpt.mp` and `auditor.skrubb` because neither side ever
  reached the threshold to send the other a verifiable BEAT.
- On the agent side, `agent.cpt.mp` itself was missing `auditor.mp`
  from its registry because the HSYNC3 RRset for `customer.mptest.`
  was extended after `cpt`'s `UpdateAgents` had already done its
  initial count=3 / count=4 processing; the count=5 transition that
  added `auditor.mp` was never processed.

**Why this is a safety-contract failure, not a cosmetic bug.**
When a customer enters an auditor into the HSYNC configuration, the
semantic is *hard requirement*: "I demand that my appointed auditor
is fully integrated into the synchronization loop; you are not
allowed to proceed with changes if the auditor is not informed."
The gossip group state machine enforces this — `CheckGroupState`
fires `OnGroupOperational` only when *every* HSYNC-listed peer is
in `OPERATIONAL` state in *every* gossiped row. An undiscovered
auditor means the group is permanently `DEGRADED`, which means
agents must not proceed with state changes. The stuck-NEEDED state
we debugged is exactly that failure mode: a missing auditor blocks
the whole group's operational lifecycle.

Auditors are also designed to be optional at the group level — a
group with zero auditors is legitimate — but when present they are
load-bearing.

These symptoms have one underlying cause: **the sync conversation
is implemented only for agents.** Agents have a full
HSYNC3 → registry → discovery → HELLO → BEAT → gossip loop.
Auditors hand-roll a strict subset (message receipt only), which
silently lacks the proactive registration, HELLO emission, BEAT
emission, and gossip participation that the safety contract relies
on.

This document proposes splitting today's `HsyncEngine` into:

- **`HsyncEngine` (new, shared)** — the full peer-to-peer
  synchronization conversation: discovery, HELLO, BEAT, gossip,
  group state checks, message dispatch. Used by agents and
  auditors identically.
- **`HsyncDataEngine` (rename of current `HsyncEngine`,
  agent-only)** — zone-data emission, SDE feeding,
  KeystateInventory processing, DelegationSync triggering,
  leader-election participation (vote casting, candidacy).

Auditors run only the shared `HsyncEngine` with auditor-specific
message handlers registered. Agents run `HsyncDataEngine`, which
embeds and drives the shared `HsyncEngine`.

## 2. Background: Current Architecture

### 2.1 HsyncEngine today

Today's `HsyncEngine` is not a struct; it is a goroutine
entry-point:

```
hsyncengine.go:19   func (conf *Config) HsyncEngine(
                        ctx context.Context, msgQs *MsgQs)
```

State lives in `AgentRegistry` (`agent_structs.go:255`):

```
S                     map of registered agents
LocalAgent            local agent identity
TransportManager      transport.TransportManager
MPTransport           bridge to legacy MP-specific transport calls
LeaderElectionManager
ProviderGroupManager
GossipStateTable
```

It consumes `MsgQs` (sync, hello, beat, msg, command,
status-update, keystate-inventory) and runs the heartbeat ticker.
Wired at `start_agent.go:351-359` alongside `InfraBeatLoop`,
`DiscoveryRetrierNG`, and `SynchedDataEngine`.

### 2.2 Discovery + sync conversation flow today (agent)

```
Zone load (HSYNC3 in apex)
  → MPPostRefresh → HsyncChanged()           (hsync_utils.go:31)
  → diff: HsyncAdds, HsyncRemoves
  → enqueue SyncRequest{Command:"HSYNC-UPDATE"}
  → HsyncEngine.SyncRequestHandler
    → UpdateAgents()                         (agent_utils.go:829)
      → for each add: MarkAgentAsNeeded()    (agent_utils.go:504)
        → if IMR ready: go attemptDiscovery()(agent_utils.go:576)
        → else: DiscoveryRetrierNG retries   (hsyncengine.go:216)
          → IMR lookups populate API/DNS endpoints + JWK
          → agent.ApiDetails.State = KNOWN   (agent_utils.go:359)
          → OnAgentDiscoveryComplete syncs agent → transport.Peer
          → spawn HelloRetrierNG(agent)      (hsync_hello.go:72)
            → SingleHello → INTRODUCED       (hsync_hello.go:314)
              → FastBeatAttempts
              → SendBeatWithFallback → OPERATIONAL
                                             (hsync_transport.go:1632)
```

Heartbeat tick fires `SendHeartbeats()` (`hsync_beat.go:54`), which
sends a beat to every agent at `INTRODUCED+`. Beat success
maintains `OPERATIONAL`; beat failure degrades. Gossip state
matrix (`GossipStateTable`) rides in BEAT payloads. Group state
callbacks (`OnGroupOperational`, `OnGroupDegraded`) fire from
`CheckGroupState` whenever the matrix changes.

### 2.3 Auditor today

`start_auditor.go:7-13` explicitly notes the auditor "does NOT run
HsyncEngine, SynchedDataEngine, leader election, KeyStateWorker, or
any path that produces outbound zone data."

`auditor_msg_handler.go:31-198` consumes Beat, Hello, Ping, Msg,
Confirmation. It routes Beat/Hello through `HeartbeatHandler` /
`HelloHandler` (which add the sender to the registry on first
verified contact) and updates `AuditZoneState`. It does NOT:

- Iterate HSYNC3 to pre-register peers.
- Send HELLO to anyone.
- Send BEAT to anyone.
- Participate in or carry gossip.

The auditor reads HSYNC3 in `auditor_detectors.go:169-172`
(`expectedHSYNC3Identities`) only to log "expected but not seen"
anomalies — never to drive registration.

### 2.4 Current TransportManager API (post-Bite-8)

`tdns-transport/v2/transport/manager.go` already exposes the
primitives we rely on:

```
manager.go:417   func (tm *TransportManager) DiscoverPeer(
                    ctx context.Context, identity string,
                ) (*Peer, error)

manager.go:91    OnPeerDiscovered  func(peer *Peer)
manager.go:108   OnDiscoveryFailed func(peer *Peer, err error)
manager.go:147   DiscoveryDriver   DiscoveryDriver  // temp seam
```

`transport.Imr` exposes `LookupAgentJWK`, `LookupAgentKEY`,
`LookupAgentAPIEndpoint`, `LookupAgentDNSEndpoint`,
`LookupAgentTLSA`, `LookupServiceAddresses` (Bite 6, complete).

## 3. Target Architecture

### 3.1 Two engines, one shared core

```
+-----------------------+      +-----------------------+
|  HsyncDataEngine      |      |  AuditorEngine        |
|  (agent only)         |      |  (auditor only)       |
|  - SDE feeding        |      |  - audit log writes   |
|  - KeystateInventory  |      |  - anomaly detection  |
|  - DelegationSyncQ    |      |  - records election   |
|  - election           |      |    msgs (read-only)   |
|    participation      |      |                       |
|    (vote, candidacy)  |      |                       |
|  - SYNC/UPDATE        |      |                       |
|    emission           |      |                       |
+----------+------------+      +----------+------------+
           |                              |
           |  embeds                      |  embeds
           v                              v
       +---+------------------------------+----+
       |          HsyncEngine (shared)        |
       |  - HSYNC3 → DiscoverPeer translation |
       |  - MarkNeeded + zone reconciliation  |
       |  - DiscoveryRetrierNG loop           |
       |  - HelloRetrierNG, SingleHello       |
       |  - SendHeartbeats, BEAT ticker       |
       |  - Gossip state matrix maintenance   |
       |  - CheckGroupState, OnGroupOp/Deg    |
       |  - Inbound message dispatch          |
       |    via registered handlers           |
       +-------------------+------------------+
                           |
                           |  uses
                           v
                  +-----------------------+
                  |   TransportManager    |   role-neutral
                  |   DiscoverPeer,       |
                  |   PeerRegistry,       |
                  |   OnPeerDiscovered,   |
                  |   OnDiscoveryFailed,  |
                  |   transport.Imr       |
                  +-----------------------+
```

Both `HsyncDataEngine` and `AuditorEngine` are thin role-specific
shells that wrap the shared `HsyncEngine`. The auditor is a "full
member of the synchronization conversation" by construction: it
runs the same discovery, sends the same HELLOs, sends the same
BEATs, carries the same gossip. Its role differs only in which
inbound-message handlers it registers and which outbound messages
it never originates.

### 3.2 What HsyncEngine (shared) owns

Listed with current locations of code that will move into it:

- **HSYNC3 RRset translation:** the diff walk currently in
  `UpdateAgents` (`agent_utils.go:868-944`) and its remove
  counterpart at `:947-964`.
- **Peer registry insertion:** `MarkAgentAsNeeded`
  (`agent_utils.go:504-572`).
- **Periodic discovery retry:** `DiscoveryRetrierNG` and
  `retryPendingDiscoveries` (`hsyncengine.go:216-271`).
- **Zone reconciliation safety-net:** new function, walks current
  HSYNC3 RRset for each known zone and reconciles missed deltas.
- **HELLO machinery:** `HelloRetrierNG` (`hsync_hello.go:72`),
  `SingleHello` (`hsync_hello.go:111`), `sendHelloToAgent`
  (`hsync_hello.go:158`).
- **BEAT machinery:** `SendHeartbeats` (`hsync_beat.go:54`),
  `SendBeatWithFallback` (`hsync_transport.go:1590`), the beat
  ticker driven by `HBticker` in today's main loop
  (`hsyncengine.go:138`).
- **Gossip:** `GossipStateTable` maintenance, payload assembly in
  outbound BEATs, merge on inbound BEATs, age tracking.
- **Group state:** `CheckGroupState`, `OnGroupOperational`,
  `OnGroupDegraded` callbacks (currently fired from the gossip
  layer).
- **Per-transport state transitions:** every state assignment
  along `NEEDED → KNOWN → INTRODUCED → OPERATIONAL` for both
  `ApiDetails.State` and `DnsDetails.State`, and the top-level
  `agent.State` promotion at `hsync_beat.go:151`.
- **Inbound message dispatch:** a handler table keyed by message
  type. Handlers are registered by the embedding role
  (`HsyncDataEngine` or `AuditorEngine`). The shared engine owns
  receipt, verification, deserialization, and dispatch. It does
  not own application semantics.

### 3.3 What HsyncDataEngine (agent only, renamed) owns

The residue that genuinely depends on agent-only state:

- **SynchedDataEngine feeding:** enqueuing `SynchedDataUpdate`
  messages from refreshed zones, local edits, remote-update
  application. Today at `hsyncengine.go:374, 438, 955`.
- **KeystateInventory processing:** receiving inventory from
  signer, computing DNSKEY deltas via `LocalDnskeysFromKeystate`,
  feeding to SDE. Today at `hsyncengine.go:174-208`.
- **DelegationSync triggering:** routing STATUS-UPDATE
  `ns-changed` / `ksk-changed` events to per-zone
  `DelegationSyncQ`. Today at `hsyncengine.go:144-172`.
- **Leader election participation:** `StartGroupElection`, vote
  emission, candidacy. The state-machine-on-the-wire is shared
  (auditors carry it), but origination is agent-only.
- **SYNC / UPDATE message emission:** outbound messages carrying
  zone-data changes.
- **Handler registrations on the shared engine:**
  - `OnSyncMessageReceived  = applyZoneDataChange`
  - `OnElectionMessageReceived = applyVote / advanceElection`
  - `OnKeyStateReceived     = ingestIntoSDE`

`HsyncDataEngine.Run(ctx)` constructs and starts the shared
`HsyncEngine`, registers its handler set, then runs the
data-side goroutine work (KeystateInventory, DelegationSync,
SDE feeding).

### 3.4 What AuditorEngine owns

- **Audit log writes** for every inbound message received via the
  shared dispatcher.
- **Anomaly detection** (existing in `auditor_detectors.go`).
- **AuditZoneState** maintenance (existing in
  `auditor_msg_handler.go`).
- **Handler registrations on the shared engine:**
  - `OnSyncMessageReceived     = recordToAuditLog`
  - `OnElectionMessageReceived = recordToAuditLog`
  - `OnKeyStateReceived        = recordToAuditLog`

`AuditorEngine.Run(ctx)` constructs and starts the shared
`HsyncEngine`, registers auditor handlers, then runs the
audit-side goroutine work. It does not originate any sync,
election, or keystate message; the shared engine has no path to
do so on its behalf.

### 3.5 Auditor's place in the safety contract

Because the auditor runs the same `HsyncEngine`, it is registered
in everyone's gossip state matrix, sends BEATs on the same
schedule, and is subject to the same `CheckGroupState`
operational/degraded judgements as agents. Concretely:

- An auditor present in HSYNC3 must reach `OPERATIONAL` in every
  agent's view (and in every other auditor's view) before the
  group is `OPERATIONAL`.
- `OnGroupOperational` not firing implies the agents' protective
  gating on zone changes (the part `HsyncDataEngine` enforces)
  keeps them from emitting SYNC/UPDATE.
- A group with zero auditors is legitimate: `CheckGroupState`
  only requires `OPERATIONAL` for peers that are members.

This makes Cut A a correctness fix, not an optimisation.

## 4. Relationship to the Transport Redesign

The transport-interface-redesign points at a destination where
discovery is a Tier-1 transport concern owned by a future
`DiscoveryService` inside `tdns-transport` (see
`2026-04-15-transport-interface-redesign.md:93-104` and Phase 6 part
2). The redesign is silent on the agent / auditor split. Cut A
fills that gap from the layer above transport.

Cut A is an on-ramp to the redesign's destination, not a
divergence:

1. `HsyncEngine` (shared) is built against the transport-side
   primitives the redesign exposes: `tm.DiscoverPeer`,
   `OnPeerDiscovered`, `OnDiscoveryFailed`, `transport.Imr`. It
   takes no MP-internal concretes that don't have a natural
   transport-side counterpart.
2. Bites F and D are prerequisites; this work finishes them.
3. When Phase 6 part 2 lands, the discovery and retry pieces of
   `HsyncEngine` reduce or dissolve. HELLO/BEAT/gossip stay in
   `HsyncEngine` as app-layer concerns. The split between
   `HsyncEngine` and `HsyncDataEngine` does not move.

### 4.1 Items the transport redesign should absorb

**(I-1) Bite F completion check.**
`tm.DiscoverPeer` exists at `manager.go:417` but routes through the
temporary `DiscoveryDriver` interface. Cut A relies on it being
callable for an identity that does NOT yet exist in MP's
`AgentRegistry` (the auditor case). Verify this end-to-end; if
the `DiscoveryDriver` adapter currently requires pre-registration,
split into transport-driven and MP-driven paths. Fold into Bite F
acceptance.

**(I-2) `OnDiscoveryFailed` invocation comprehensiveness.**
The callback field exists at `manager.go:108` (Bite D seam). Cut
A treats this as the authoritative failure signal. Every
discovery failure path must fire it — including
`OnPeerDiscoveryNeeded` kicks (`hsync_transport.go:391`) when the
post-kick attempt fails. Recommend Bite D specify the full set of
invocation sites.

**(I-3) HSYNC3 stays in MP forever.**
Translating HSYNC3 RRset diff into discovery requests is
irreducibly app-layer. The redesign's "discovery in transport"
goal refers to resolution and protocol machinery; *who* decides
*whom* to discover stays in MP. Worth recording in the redesign.

**(I-4) Single dispatcher across roles — concrete evidence.**
Disposition Item 1 in the redesign (lines 269-274) advocates one
`MPMessageDispatcher` shared across roles, with role differences
expressed by which handlers each registers. Cut A is a direct
proof-point: the shared `HsyncEngine` dispatcher handles all
inbound messages identically, and the per-role handler set is the
*only* place the role appears. The redesign roadmap can cite this
when justifying Item 1.

## 5. Implementation Plan

Six phases. Each independently buildable and committable.

### Phase 0: Rename prep

**Goal:** rename the existing `HsyncEngine` → `HsyncDataEngine` in
a single, behaviour-preserving commit so no commit ever has two
things called `HsyncEngine` meaning different things.

**Mechanical only.** Rename:

- Function `(conf *Config) HsyncEngine` →
  `(conf *Config) HsyncDataEngine` at `hsyncengine.go:19`.
- File `hsyncengine.go` → `hsync_data_engine.go`.
- Call sites (start_agent.go and anywhere else).
- Log messages, comments, doc references.

The new (shared) `HsyncEngine` does not yet exist at this point.

**Acceptance:** existing test suite passes unmodified except for
the new name. No behaviour change.

**Cost:** half a day.

### Phase 1: Finish Bite F

**Goal:** `tm.DiscoverPeer(ctx, identity)` works for an identity
the caller has no prior knowledge of, returning a fully populated
`*Peer` or a typed error. This is the API the shared `HsyncEngine`
will use to drive discovery.

**Files:**

- `tdns-transport/v2/transport/manager.go` — verify `DiscoverPeer`
  body (currently lines 417-436) handles the "peer absent from
  registry" case via `PeerRegistry.GetOrCreate(identity)`.
- `tdns-transport/v2/transport/peer.go` — confirm `GetOrCreate`
  initialises sensibly (state `PeerStateNeeded`, no mechanism
  bindings).
- `agent_discovery.go` — the current `DiscoveryDriver` adapter on
  the MP side. Verify `RunDiscovery` does not assume the peer was
  inserted into `AgentRegistry` first. If it does, split into:
  - transport-driven path: produces `*Peer` only.
  - MP-driven path: also writes to `AgentRegistry`.

**Acceptance:**

- Unit test in `tdns-transport/v2/transport/`: call
  `tm.DiscoverPeer(ctx, "agent.fox.mp.axfr.net.")` with empty
  registry; returns `*Peer` with bindings populated, mock IMR.
- Integration test in `tdns-mp/v2/`: call from a path that does
  not go through `MarkAgentAsNeeded`; confirm `OnPeerDiscovered`
  fires.

**Cost:** half a day.

### Phase 2: Finish Bite D

**Goal:** every discovery failure fires `OnDiscoveryFailed(peer,
err)` exactly once per failed round.

**Failure paths to audit:**

1. `attemptDiscovery` exhausts retries
   (`agent_utils.go:576`).
2. `tm.DiscoverPeer` returns an error
   (`manager.go:417` — Phase 1 path).
3. `OnPeerDiscoveryNeeded` kick succeeds the IMR cache flush but
   post-kick discovery fails (`hsync_transport.go:391-412`).

**Files:**

- `tdns-mp/v2/agent_utils.go` — invoke `OnDiscoveryFailed` after
  retry exhaustion.
- `tdns-transport/v2/transport/manager.go` — invoke from
  `DiscoverPeer`'s failure return.
- `tdns-mp/v2/hsync_transport.go` — invoke from
  `OnPeerDiscoveryNeeded` failure.

**Wiring:** `start_agent.go` and `start_auditor.go` register
`tm.OnDiscoveryFailed = hsyncEngine.handleDiscoveryFailed`.

**Acceptance:** unit test — discovery for non-existent identity
fires the callback once per round; peer remains at `NEEDED`; next
periodic retry triggers another round and another callback.

**Cost:** 1-2 hours.

### Phase 3: Build the new shared HsyncEngine

**Goal:** introduce the new type with its own state and `Run`
loop, owning everything in §3.2.

**New file:** `tdns-mp/v2/hsync_engine.go`

```
type HsyncEngine struct {
    // injected dependencies
    tm            *transport.TransportManager
    imr           func() *Imr
    localID       AgentId
    registry      *AgentRegistry
    cfg           HsyncEngineConfig

    // handler registrations (set by embedding role)
    onSyncMessage     func(*SyncMsg)
    onElectionMessage func(*ElectionMsg)
    onKeyStateMessage func(*KeyStateMsg)
    // ... one per message type with role-divergent semantics

    // owned state
    gossipTable       *GossipStateTable
    helloContexts     map[AgentId]context.CancelFunc
    beatTicker        *time.Ticker
}

type HsyncEngineConfig struct {
    RetryInterval        time.Duration
    ReconcileInterval    time.Duration  // safety net for missed
                                        // HSYNC3 deltas
    BeatInterval         time.Duration
    HelloFastAttempts    int
    HelloFastSpacing     time.Duration
}

// Lifecycle
func NewHsyncEngine(...) *HsyncEngine
func (e *HsyncEngine) Run(ctx context.Context)

// HSYNC3 translation
func (e *HsyncEngine) ApplyHsyncDiff(
    zone ZoneName, adds, removes []dns.RR) error
func (e *HsyncEngine) ReconcileZone(
    zone ZoneName, hsync3 []dns.RR) error

// Peer lifecycle
func (e *HsyncEngine) MarkNeeded(
    id AgentId, zone ZoneName, task *DeferredAgentTask)

// Handler registration (called by embedding role at startup)
func (e *HsyncEngine) SetSyncHandler(h func(*SyncMsg))
func (e *HsyncEngine) SetElectionHandler(h func(*ElectionMsg))
func (e *HsyncEngine) SetKeyStateHandler(h func(*KeyStateMsg))

// Outbound message paths (used by HsyncDataEngine; never by
// AuditorEngine)
func (e *HsyncEngine) SendSync(peer AgentId, msg *SyncMsg) error
func (e *HsyncEngine) SendElection(peer AgentId,
    msg *ElectionMsg) error
```

**Code migration:**

- `MarkAgentAsNeeded` (`agent_utils.go:504-572`) →
  `HsyncEngine.MarkNeeded`. Replace inline `attemptDiscovery`
  spawn with `tm.DiscoverPeer`. Deferred-task table moves in.
- `attemptDiscovery` (`agent_utils.go:576`) deleted from MP;
  its retry/threshold logic moves into the transport driver
  behind `tm.DiscoverPeer`.
- `DiscoveryRetrierNG` + `retryPendingDiscoveries`
  (`hsyncengine.go:216-271`) → `HsyncEngine.Run`'s retry pass.
- HSYNC3 diff loops in `UpdateAgents` (`agent_utils.go:868-964`)
  → `HsyncEngine.ApplyHsyncDiff`.
- `HelloRetrierNG` (`hsync_hello.go:72`), `SingleHello`
  (`hsync_hello.go:111`), `sendHelloToAgent`
  (`hsync_hello.go:158`) → moved into `HsyncEngine`.
- `SendHeartbeats` (`hsync_beat.go:54`),
  `SendBeatWithFallback` (`hsync_transport.go:1590`), beat ticker
  → moved into `HsyncEngine.Run`.
- `GossipStateTable` ownership → moves from `AgentRegistry` to
  `HsyncEngine`.
- `CheckGroupState` + `OnGroupOperational` / `OnGroupDegraded`
  callbacks → `HsyncEngine`. Callbacks become hooks the
  embedding role wires up.
- State transition assignments scattered across `agent_utils.go`,
  `hsync_hello.go`, `hsync_beat.go`, `hsync_transport.go` →
  centralised in `HsyncEngine`'s state-machine methods.
- Inbound message dispatch (the select in current
  `hsync_data_engine.go:113-210` for sync/hello/beat/msg) splits:
  the message-receipt half moves into `HsyncEngine` with handler
  dispatch; the semantic application stays in
  `HsyncDataEngine` via registered handlers.

**Reconciliation safety-net (the cpt bug fix):**
`HsyncEngine.Run` adds, every `ReconcileInterval` (default
`4 × RetryInterval = 60s`), a pass that walks all known zones
and calls `ReconcileZone`. This catches missed delta events. The
reconcile is idempotent.

**Acceptance:**

- Existing agent tests still pass.
- New unit tests on `HsyncEngine` for: `ApplyHsyncDiff` (empty,
  one add, one remove, mixed); `ReconcileZone` (registry missing
  peer reinserts; registry has peer no longer in HSYNC3 removes);
  retry loop on NEEDED; beat ticker emits beats at interval;
  inbound message dispatch routes by type and fires registered
  handler.
- Integration: simulate cpt scenario — HSYNC3 count=4, then update
  to count=5 — confirm 5th peer registers via delta or
  reconcile.
- Integration: confirm agent-side behaviour byte-identical to
  pre-refactor on a captured trace.

**Cost:** 8-12 days. The bulk is the careful migration of
HELLO/BEAT/gossip plumbing without behavioural drift. Each
sub-area (HELLO, BEAT, gossip, dispatch) can land as its own
sub-commit inside Phase 3.

### Phase 4: Rewrite HsyncDataEngine as a shell around HsyncEngine

**Goal:** the renamed `HsyncDataEngine` (from Phase 0) becomes a
thin layer that constructs `HsyncEngine`, registers its agent
handler set, and runs the data-side goroutine work.

**New shape:**

```
type HsyncDataEngine struct {
    core *HsyncEngine
    // agent-only state: SDE channels, KeystateInventory chan,
    // DelegationSyncQ refs, election state
}

func (e *HsyncDataEngine) Run(ctx context.Context) {
    e.core.SetSyncHandler(e.applyZoneDataChange)
    e.core.SetElectionHandler(e.applyVote)
    e.core.SetKeyStateHandler(e.ingestIntoSDE)
    go e.core.Run(ctx)

    // existing agent-only goroutine work: KeystateInventory
    // processing, SDE feeding, DelegationSync routing, election
    // origination.
    e.runAgentOnly(ctx)
}
```

**Acceptance:** agent integration suite green; behaviour
byte-identical to pre-refactor on captured traces.

**Cost:** 2-3 days.

### Phase 5: Wire the auditor

**Goal:** auditor runs `HsyncEngine` directly with auditor-specific
handlers.

**New file:** `tdns-mp/v2/auditor_engine.go`

```
type AuditorEngine struct {
    core      *HsyncEngine
    auditLog  *AuditLog
    zoneState *AuditZoneState
}

func (e *AuditorEngine) Run(ctx context.Context) {
    e.core.SetSyncHandler(e.recordSync)
    e.core.SetElectionHandler(e.recordElection)
    e.core.SetKeyStateHandler(e.recordKeyState)
    go e.core.Run(ctx)

    // auditor-only: anomaly detection scanner over zoneState
    e.runAuditOnly(ctx)
}
```

**Removed:** `auditor_msg_handler.go` as a separate goroutine.
Its handlers fold into the auditor's registered handlers on the
shared engine.

**Auditor anomaly detection:** `expectedHSYNC3Identities` in
`auditor_detectors.go:169-172` becomes a strictly more useful
check — "registry has peer X but no recent BEAT" rather than
"HSYNC3 has X but it's not in registry."

**Acceptance:**

- Integration: auditor with HSYNC3 listing four agents starts
  with no inbound messages. `peer list` returns all four agents
  at `NEEDED`/`KNOWN` after the first reconcile interval.
- Live lab: deploy to `auditor.mp`; confirm `customer.mptest.`
  registry includes all five members without manual restart.
- Live lab: confirm gossip matrix from `auditor.mp` shows
  `OPERATIONAL` for cpt and skrubb, and vice versa.

**Cost:** 2-3 days.

## 6. File-by-File Change Summary

### Added

- `tdns-mp/v2/hsync_engine.go` — new shared engine.
- `tdns-mp/v2/hsync_engine_test.go` — unit tests.
- `tdns-mp/v2/auditor_engine.go` — auditor shell.

### Renamed (Phase 0)

- `tdns-mp/v2/hsyncengine.go` → `tdns-mp/v2/hsync_data_engine.go`.
- Function `HsyncEngine` → `HsyncDataEngine` and all its call sites.

### Modified

- `tdns-mp/v2/hsync_data_engine.go`:
  - Body of `Run` reshaped to construct + drive `HsyncEngine`,
    register handlers, then run agent-only goroutine work.
  - Discovery + HELLO + BEAT + gossip code deleted (moves into
    `HsyncEngine`).

- `tdns-mp/v2/agent_utils.go`:
  - `MarkAgentAsNeeded`, `attemptDiscovery`, HSYNC3 diff loops in
    `UpdateAgents` — moved into `HsyncEngine`.
  - `UpdateAgents` shrinks to its non-discovery residue (zone
    association bookkeeping for deferred RFI tasks,
    HSYNCPARAM-aware group recomputation).

- `tdns-mp/v2/hsync_hello.go`:
  - `HelloRetrierNG`, `SingleHello`, `sendHelloToAgent`, fast/normal
    HELLO loops — moved into `HsyncEngine`.

- `tdns-mp/v2/hsync_beat.go`:
  - `SendHeartbeats`, beat-ticker logic — moved into `HsyncEngine`.

- `tdns-mp/v2/hsync_transport.go`:
  - `SendBeatWithFallback` and its API/DNS state-transition
    writes — moved into `HsyncEngine`.

- `tdns-mp/v2/gossip.go`:
  - `GossipStateTable` ownership moves from `AgentRegistry` to
    `HsyncEngine`. `RefreshLocalStates`, merge, age tracking —
    callers updated.

- `tdns-mp/v2/agent_structs.go`:
  - `AgentRegistry`'s `helloContexts` and `GossipStateTable`
    fields removed (they live in `HsyncEngine` now).
  - `AgentRegistry` gains a `*HsyncEngine` field for back-reference.

- `tdns-mp/v2/start_agent.go`:
  - Construct `HsyncDataEngine` (which constructs and embeds
    `HsyncEngine`). Start `HsyncDataEngine.Run` in place of the
    current `HsyncEngine` goroutine and `DiscoveryRetrierNG`
    goroutine.

- `tdns-mp/v2/start_auditor.go`:
  - Construct `AuditorEngine` (which constructs and embeds
    `HsyncEngine`). Start `AuditorEngine.Run`.
  - Delete the `auditor_msg_handler` goroutine spawn; its work
    moves into `AuditorEngine`'s registered handlers.

- `tdns-mp/v2/auditor_msg_handler.go`:
  - Deleted as a separate goroutine; semantics fold into
    `AuditorEngine`'s registered handlers.

- `tdns-transport/v2/transport/manager.go`:
  - `DiscoverPeer` validated for absent peers (Phase 1).
  - `OnDiscoveryFailed` invocation sites filled in (Phase 2).

### Deleted (eventually, after migration window)

- `attemptDiscovery` in `agent_utils.go`.
- `DiscoveryRetrierNG`, `retryPendingDiscoveries` in
  `hsync_data_engine.go`.

## 7. Testing Strategy

### Unit

- `HsyncEngine`: `ApplyHsyncDiff`, `ReconcileZone`, `MarkNeeded`,
  retry loop, beat ticker, HELLO state transitions, dispatch
  table.
- `tm.DiscoverPeer` for empty registry case.
- `OnDiscoveryFailed` invocation count.

### Integration

- HSYNC3 count transition 3 → 4 → 5: each peer registers via the
  delta path. The cpt regression: start count=4, NOTIFY bumps to
  count=5, confirm new peer enters registry without restart.
- Reconciliation: programmatically remove a peer mid-test;
  confirm `ReconcileZone` re-inserts it.
- Auditor end-to-end: auditor + four agents in a test harness;
  auditor's `peer list` matches HSYNC3 on first reconcile,
  without depending on agents initiating BEATs first.
- Group operational gating: configure HSYNC3 with one auditor;
  disrupt auditor; verify agents do NOT proceed with SYNC/UPDATE
  emission until the group returns to OPERATIONAL.

### Live lab

- Deploy to training lab (NetBSD VMs).
- Confirm stuck state on `customer.mptest.` resolves without
  per-host restart.
- Confirm `tdns-mpcli auditor peer list` on `auditor.mp` shows
  all five HSYNC3 members.
- Confirm gossip matrix from every node shows OPERATIONAL for
  every other node.
- Confirm auditors emit BEATs and gossip on schedule.
- Confirm auditor audit log records election messages it observes
  without affecting agent behaviour.

## 8. Risks and Mitigations

**(R-1) Behavioural drift on the agent side.**
Moving HELLO/BEAT/gossip touches the heart of the protocol. Any
behavioural divergence between pre- and post-refactor is a
correctness risk. Mitigate with captured-trace replay tests —
record an agent's wire output over a known scenario before
refactor, replay the scenario post-refactor, assert byte
equivalence on outbound messages. Run on every Phase 3 sub-commit.

**(R-2) Auditor BEAT traffic increase.**
Auditors will now emit periodic BEATs on the same cadence as
agents. For an N-member group this multiplies BEAT traffic by
(N+M)/N where M is the auditor count. For typical 3-5 member
groups this is a 30-60% increase in BEAT volume. Acceptable: the
safety contract requires it, and BEATs are small.

**(R-3) Group-operational gating is now stricter.**
Today, agents that have not yet discovered all auditors may
proceed with SYNC/UPDATE because the protective check was
incomplete in practice. After Cut A, the check tightens — agents
will pause SYNC/UPDATE emission until the auditor is
`OPERATIONAL`. This may surface latent dependencies on the
incorrect behaviour, particularly in test scenarios where
auditors were not configured. Mitigate by auditing test fixtures
before Phase 5 deployment.

**(R-4) Phase 3 scope.**
Phase 3 is large (8-12 days). It is structurally one refactor but
naturally splits into sub-areas (HELLO, BEAT, gossip, dispatch).
Land sub-areas in their own commits. Maintain a feature-flag-style
config switch during the migration window if needed to allow a
fast revert.

**(R-5) `AgentRegistry` coupling.**
`HsyncEngine` reads and writes `AgentRegistry` directly. The
cleaner cut would have `HsyncEngine` own its own minimal peer
table. Trade-off: a separate table is a second source of truth.
For this iteration the shared engine shares the registry. When
Phase 6 part 2 of the transport redesign lands, the registry's
role shrinks to "agent-specific extension on top of
`transport.PeerRegistry`" and this coupling shrinks accordingly.

**(R-6) Reconcile interval tuning.**
Default `ReconcileInterval = 4 × RetryInterval = 60s`. Too
aggressive wastes work; too sparse and the cpt-class bug window
stays open. Idempotent operation makes overruns harmless.

## 9. Out of Scope

- Phase 6 part 2 of the transport redesign (moving discovery body
  into transport). Cut A makes Phase 6 part 2 strictly easier
  but does not require or trigger it.
- The HSYNC3-diff identity-extraction bug in cpt's history (the
  "missing `agent.` prefix" cleanup log). The diff loop's
  extraction was found to be symmetric
  (`agent_utils.go:873` and `:959` both use `hsync3.Identity`
  directly); the stale identity is from an earlier zone state and
  is cleared automatically by `ReconcileZone`.
- Combining `HsyncDataEngine` and `AuditorEngine` further. Their
  non-shared responsibilities are genuinely different;
  `HsyncEngine` is the right shared cut.

## 10. Open Items

1. **Auditor zone-refresh trigger.** Does the auditor today
   receive zone-refresh callbacks for zones it audits? If not,
   `HsyncEngine.ApplyHsyncDiff` needs a different trigger on the
   auditor side (likely: a small hook in the auditor's
   zone-subscription path). Verify before Phase 5.
2. **Per-peer goroutine bound.** `tm.DiscoverPeer` may block on
   slow IMR. `HsyncEngine.Run`'s retry pass currently has no
   bound on concurrent in-flight discoveries. Add a semaphore or
   worker pool; size to taste (suggest `min(N_peers, 8)`).
3. **Election message *receipt* on auditor side.** Auditors must
   record election messages but never act on them. Confirm the
   election-message wire type is identifiable as such by the
   shared dispatcher so the auditor's
   `OnElectionMessageReceived` handler reliably catches every
   election-related message, including votes carried as part of
   other message bodies (if any).

## 11. Future Direction: HsyncDataEngine Dissolves

`HsyncDataEngine` should be understood as a **transitional
vessel**, not a permanent agent-side engine. Cut A creates it by
renaming today's `HsyncEngine`, but the migration of work *out* of
it (into the new shared `HsyncEngine`) is the start of a longer
trajectory in which the rest of its responsibilities also find
better homes. The end state has no `HsyncDataEngine`.

This affects how to invest in it during Cut A: **don't polish or
over-engineer its API.** It is a stop along the way.

### 11.1 What remains in HsyncDataEngine after Cut A

1. KeystateInventory processing — receive from signer, compute
   DNSKEY deltas, feed to SDE.
2. DelegationSync triggering — route STATUS-UPDATE `ns-changed` /
   `ksk-changed` to per-zone `DelegationSyncQ`.
3. SYNC/UPDATE message emission — "I just changed X locally; tell
   my peers."
4. Leader-election participation — vote casting, candidacy.
5. Handler registrations on the shared `HsyncEngine`.

### 11.2 Where each piece naturally migrates

**(1) KeystateInventory → SDE.** Today it's plumbed through the
data engine only because the shared `KeystateInventory` channel is
read from the same goroutine as the other MsgQs. Once
`HsyncEngine` owns inbound message receipt and dispatch, keystate
can dispatch directly to SDE via an `IngestKeystateInventory`
method. The data engine's role evaporates.

**(2) DelegationSync triggering → SDE.** `ns-changed` and
`ksk-changed` are events SDE *generates* (those RRs live in
SDE-managed zone data). The cleaner shape is per-RR-type change
callbacks on SDE: when SDE applies a change affecting NS or KSK,
it fires a callback that subscribers (the delegation-sync work)
hook into directly.

**(3) SYNC/UPDATE emission → SDE → HsyncEngine, direct.** With
(1) and (2) gone, the orchestration value of the data engine is
also gone. SDE knows what changed; `HsyncEngine` knows how to put
it on the wire. SDE calls `hsyncEngine.SendSync(peers, change)`
directly.

**(4) Leader-election participation → its own home.** Elections
are about peer coordination, not zone data, so they don't fit SDE.
Three options:
- A small dedicated `ElectionEngine` embedding `HsyncEngine`
  (preferred — clean separation, mirrors `AuditorEngine`'s shape).
- Folded into `HsyncEngine` with a role flag — the gate pattern
  we said we'd avoid, but elections are simple enough that a
  one-bool gate may be defensible.
- Per-zone state in SDE if you reframe elections as zone
  coordination metadata. Feels forced.

Recommend the first.

**(5) Handler registrations → with the work.** Each handler ends
up where its consumer ends up.

### 11.3 End state

```
HsyncEngine (shared)
   ↑                 ↑                 ↑
   |                 |                 |
   SDE          ElectionEngine    AuditorEngine
                 (agent only)     (auditor only)
```

The agent role is no longer a distinct engine. It is "SDE +
ElectionEngine, both using `HsyncEngine`." Auditor is
`AuditorEngine` using `HsyncEngine`. Symmetry between roles is
now structural.

### 11.4 Migration order (after Cut A lands)

Each step is independently shippable and shrinks the residual
data engine.

1. SDE absorbs KeystateInventory ingestion. Smallest, lowest
   risk.
2. SDE exposes RR-type-change hooks; DelegationSync subscribes
   directly.
3. SDE emits SYNC via `HsyncEngine` directly.
4. Extract `ElectionEngine` (or fold; decide then based on
   election-code shape).
5. Delete `HsyncDataEngine` — it is now empty.

Step 5 is a deletion, not a refactor.

### 11.5 Implication for Cut A polish

Treat `HsyncDataEngine` in Cut A as a soon-to-be-removed shell.
Don't design an elaborate public API for it. Don't add
configuration knobs aimed at flexibility. Don't write
documentation about its responsibilities as if they're stable —
they aren't. Keep it minimal: enough to wire the agent's
remaining work to `HsyncEngine` and run the agent-only
goroutines, nothing more.
