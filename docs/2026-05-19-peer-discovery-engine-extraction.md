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

### 3.6 Package structure: tdns-mp/v2/hsync/ as a permanent subpackage

The new shared `HsyncEngine` lives in `tdns-mp/v2/hsync/` from
the start, and the migration progressively moves the rest of the
HSYNC-protocol code down there too. This is structural, not
transitional: the subpackage is permanent.

Motivation:

- `tdns-mp/v2/` is a single flat package with several hundred
  files spanning protocol, data engine, combiner, signer,
  auditor, API handlers, and config. Some of these are coherent
  subsystems that deserve their own boundary.
- The HSYNC protocol (discovery, HELLO, BEAT, gossip, provider
  groups, peer registry) is one of the cleaner candidates. It
  has a definable surface area and the rest of `tdnsmp` interacts
  with it through a manageable set of entry points.
- Carving it out forces a deliberate API design — internal
  helpers stay internal, exported symbols become a real contract.
- The directory structure documents the architecture. A reader
  can `ls tdns-mp/v2/hsync/` and see all and only the protocol
  code.

The shape that emerges over time:

```
tdns-mp/v2/
├── hsync/              ← protocol: HsyncEngine, discovery,
│                         HELLO, BEAT, gossip, provider groups,
│                         registry, agent state
├── *.go                ← wiring (start_agent.go, start_auditor.go),
│                         API handlers, config, SDE, combiner,
│                         signer, audit log, top-level types
```

SDE / combiner / signer may eventually get their own subpackages
too, but that is out of scope for Cut A.

**Import direction:** strictly one-way. `tdnsmp/hsync` does not
import the top-level `tdnsmp` package. Anything `hsync` needs
from the top is exposed via a narrow interface defined inside
`hsync/` that the top-level types satisfy. Concrete examples:

```go
package hsync

// ZoneLookup is satisfied by tdnsmp.Zones (top-level). HsyncEngine
// uses this rather than importing the global directly.
type ZoneLookup interface {
    Get(zone string) (ZoneView, bool)
}

type ZoneView interface {
    HSYNC3() []dns.RR
    IsMultiProvider() bool
}

// TransportDriver is satisfied by *transport.TransportManager
// (already lives in tdns-transport, no cycle risk).
type TransportDriver interface {
    DiscoverPeer(ctx context.Context, id string) (*transport.Peer, error)
    Send(ctx context.Context, peer *transport.Peer, msg interface{}) (interface{}, error)
    OnPeerDiscovered  func(*transport.Peer)
    OnDiscoveryFailed func(*transport.Peer, error)
}
```

The top-level `tdnsmp` constructs `hsync.Engine` with concrete
values that happen to satisfy these interfaces. `hsync` knows
nothing about `tdnsmp.Config`, `tdnsmp.MPZoneData`, or the
combiner/signer hierarchy.

**Where this resists the move:** code with bidirectional
dependencies between protocol and top-level concerns will not
fit cleanly. Examples that will need either interface insertion
or staying at the top level: API handlers that call
`AgentRegistry` directly; `start_*.go` wiring; HSYNC-to-SDE seam
(`SynchedDataEngine` feeding paths). The seam between protocol
and data deliberately stays at the top level inside `start_*.go`
and `HsyncDataEngine` — that's where role-specific composition
happens.

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

Six phases. The ordering is chosen so the lowest-risk role
(auditor) validates the new shared engine in production *before*
the agent migrates. Each phase ends in a real safe-checkpoint
state: even if work pauses after any phase, the codebase is
coherent and the production system is at least as healthy as it
was at the start of that phase.

The auditor migration (Phase 3) is the smallest step that fully
fixes the production failure documented in §1. Everything after
that is structural improvement, not bug fix.

### Phase 0: Finish Bite F

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
- `tdns-mp/v2/agent_discovery.go` — the current `DiscoveryDriver`
  adapter on the MP side. Verify `RunDiscovery` does not assume
  the peer was inserted into `AgentRegistry` first. If it does,
  split into:
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

### Phase 1: Finish Bite D

**Goal:** every discovery failure fires `OnDiscoveryFailed(peer,
err)` exactly once per failed round.

**Failure paths to audit:**

1. `attemptDiscovery` exhausts retries
   (`agent_utils.go:576`).
2. `tm.DiscoverPeer` returns an error
   (`manager.go:417` — Phase 0 path).
3. `OnPeerDiscoveryNeeded` kick succeeds the IMR cache flush but
   post-kick discovery fails (`hsync_transport.go:391-412`).

**Files:**

- `tdns-mp/v2/agent_utils.go` — invoke `OnDiscoveryFailed` after
  retry exhaustion.
- `tdns-transport/v2/transport/manager.go` — invoke from
  `DiscoverPeer`'s failure return.
- `tdns-mp/v2/hsync_transport.go` — invoke from
  `OnPeerDiscoveryNeeded` failure.

**Wiring:** existing callers (`start_agent.go` and
`start_auditor.go`) can register a temporary no-op handler. The
real callback wiring lands in Phases 3 and 5 when the new engine
is constructed.

**Acceptance:** unit test — discovery for non-existent identity
fires the callback once per round; peer remains at `NEEDED`; next
periodic retry triggers another round and another callback.

**Cost:** 1-2 hours.

### Phase 2: Build the new shared HsyncEngine in tdns-mp/v2/hsync/

**Goal:** introduce the new type and its supporting machinery in
the new `hsync/` subpackage. Nothing is wired to it yet — neither
agent nor auditor. The old `HsyncEngine` (the one to be renamed
to `HsyncDataEngine` eventually) continues to serve the agent
unchanged.

**Why this ordering:** during Phase 2 the new engine is a
self-contained library. It compiles, has unit tests, but has
zero production exposure. This isolates "did I get the new code
right?" from "did I rewire the existing system correctly?". The
existing agent path is untouched and untested-against — the only
production risk in Phase 2 is the cost of building unused code.

**New package:** `tdns-mp/v2/hsync/`

**New files (proposed):**

```
tdns-mp/v2/hsync/
├── engine.go          // type Engine + Run() + lifecycle
├── config.go          // type Config (renamed from HsyncEngineConfig)
├── interfaces.go      // ZoneLookup, TransportDriver, etc.
├── registry.go        // peer registry (fresh implementation)
├── hsync3_diff.go     // ApplyHsyncDiff + ReconcileZone
├── discovery.go       // MarkNeeded + retry pass
├── hello.go           // HELLO send/receive machinery
├── beat.go            // BEAT send/receive machinery
├── gossip.go          // state matrix maintenance
├── dispatch.go        // inbound message dispatch table
└── *_test.go          // unit tests
```

**Type names inside `hsync/`** (called `hsync.Engine` from
outside, but just `Engine` inside):

```go
package hsync

type Engine struct {
    // injected dependencies via interfaces, not concretes
    transport TransportDriver
    zones     ZoneLookup
    localID   PeerID
    cfg       Config

    // handler registrations (set by embedding role)
    onSyncMessage     func(*SyncMsg)
    onElectionMessage func(*ElectionMsg)
    onKeyStateMessage func(*KeyStateMsg)

    // owned state
    peers         *Registry
    gossipTable   *GossipStateTable
    helloContexts map[PeerID]context.CancelFunc
}

type Config struct {
    RetryInterval     time.Duration
    ReconcileInterval time.Duration
    BeatInterval      time.Duration
    HelloFastAttempts int
    HelloFastSpacing  time.Duration
}

// Lifecycle
func NewEngine(deps Deps, cfg Config) *Engine
func (e *Engine) Run(ctx context.Context)

// HSYNC3 translation
func (e *Engine) ApplyHsyncDiff(
    zone ZoneName, adds, removes []dns.RR) error
func (e *Engine) ReconcileZone(
    zone ZoneName, hsync3 []dns.RR) error

// Peer lifecycle
func (e *Engine) MarkNeeded(
    id PeerID, zone ZoneName, task *DeferredTask)

// Handler registration (called by embedding role at startup)
func (e *Engine) SetSyncHandler(h func(*SyncMsg))
func (e *Engine) SetElectionHandler(h func(*ElectionMsg))
func (e *Engine) SetKeyStateHandler(h func(*KeyStateMsg))

// Outbound (used by agent-side composition; never by auditor)
func (e *Engine) SendSync(peer PeerID, msg *SyncMsg) error
func (e *Engine) SendElection(peer PeerID, msg *ElectionMsg) error
```

**Code source:** the new engine is built by **copying** logic out
of the existing top-level files (`hsync_hello.go`, `hsync_beat.go`,
`agent_utils.go`, `gossip.go`, etc.), not by moving them. The
old code keeps working for the agent. A brief duplication window
exists between Phase 2 and Phase 5; see Risk (R-7).

Where the copy is mechanical (e.g., HELLO retry loop logic), keep
the existing comments and field names where reasonable. Where
the new shape demands changes (interface-typed dependencies
instead of global package access), accept the divergence.

**The reconciliation safety-net (the cpt bug fix)** is built in
from the start: `Engine.Run` runs a `ReconcileZone` pass every
`ReconcileInterval` (default `4 × RetryInterval = 60s`) for every
known zone. Idempotent.

**Acceptance:**

- The `hsync/` package compiles in isolation. It has no import
  of `tdnsmp` (the top-level package).
- Unit tests for `Engine` cover: `ApplyHsyncDiff` (empty, one
  add, one remove, mixed); `ReconcileZone` (registry missing
  peer reinserts); retry loop on NEEDED; beat ticker emits
  beats; inbound message dispatch routes by type.
- Existing agent test suite still passes (untouched).

**Cost:** 6-9 days. The bulk is interface design and unit test
coverage. No behavioural-equivalence testing yet (no production
caller).

### Phase 3: Wire the auditor to hsync.Engine

**Goal:** auditor stops running its hand-rolled handlers and
starts using `hsync.Engine` directly. Agent path unchanged.

**This is the smallest step that fully resolves the production
failure documented in §1.** If the project pauses here, auditors
discover HSYNC3 peers proactively, send HELLO/BEAT, participate
in gossip, and the safety contract holds. The agent's missed-
delta failure (F4 in the tactical-fix doc) is also covered if the
agent has already absorbed the `HsyncReconcile` change from
`auditor-discovery-fix` — which it has.

**New file:** `tdns-mp/v2/auditor_engine.go`

```go
package tdnsmp

import "github.com/johanix/tdns-mp/v2/hsync"

type AuditorEngine struct {
    core      *hsync.Engine
    auditLog  *AuditLog
    zoneState *AuditZoneState
}

func (e *AuditorEngine) Run(ctx context.Context) {
    e.core.SetSyncHandler(e.recordSync)
    e.core.SetElectionHandler(e.recordElection)
    e.core.SetKeyStateHandler(e.recordKeyState)
    go e.core.Run(ctx)

    e.runAuditOnly(ctx)  // anomaly detection over zoneState
}
```

**Wiring in `start_auditor.go`:**

- Construct `hsync.Engine` with auditor-appropriate `Deps`
  (transport from `TransportManager`, zone lookup that wraps
  `Zones`, identity, etc.).
- Construct `AuditorEngine` around it.
- Start `AuditorEngine.Run`.
- Delete the existing `AuditorMsgHandler` goroutine spawn; its
  message-receipt work is now in `hsync.Engine.dispatch`, its
  audit-recording work moves into `AuditorEngine` handler
  registrations.
- The existing `DiscoveryRetrierNG`, `InfraBeatLoop`, and
  `AuditorHeartbeatLoop` goroutines stop being needed — their
  responsibilities are owned by `hsync.Engine.Run`. Remove
  their spawns.

**Acceptance:**

- Integration: auditor with HSYNC3 listing four agents starts
  with no inbound messages. `peer list` returns all four agents
  at `NEEDED`/`KNOWN`/`OPERATIONAL` after the first reconcile
  interval.
- Live lab: deploy to `auditor.mp`; confirm `customer.mptest.`
  registry includes all five members.
- Live lab: confirm gossip matrix from `auditor.mp` shows
  `OPERATIONAL` for cpt and skrubb, and vice versa.
- Live lab: bake-in period (1-2 weeks) with auditor on the new
  engine before Phase 4 starts. Real production exposure
  validates the shared core under traffic.

**Cost:** 3-4 days plus the bake-in period.

### Phase 4: Build the new HsyncDataEngine (not yet wired)

**Goal:** introduce `HsyncDataEngine`, the agent-only shell around
`hsync.Engine`. It exists in the codebase but the agent does NOT
yet use it. The old top-level `HsyncEngine` continues to serve
the agent unchanged.

**Why this ordering:** separating "build the new wrapper" from
"swap the agent to use it" gives reviewers a focused diff in each
step. Phase 4 is pure addition — easy to review, easy to revert
if something is missed.

**New file:** `tdns-mp/v2/hsync_data_engine.go` (new file —
nothing is renamed yet; the old `hsyncengine.go` still exists).

```go
package tdnsmp

import "github.com/johanix/tdns-mp/v2/hsync"

type HsyncDataEngine struct {
    core *hsync.Engine
    // agent-only state: SDE channels, KeystateInventory chan,
    // DelegationSyncQ refs, election state
}

func (e *HsyncDataEngine) Run(ctx context.Context) {
    e.core.SetSyncHandler(e.applyZoneDataChange)
    e.core.SetElectionHandler(e.applyVote)
    e.core.SetKeyStateHandler(e.ingestIntoSDE)
    go e.core.Run(ctx)

    e.runAgentOnly(ctx)  // SDE feeding, KeystateInventory,
                         // DelegationSync routing, election origination
}
```

The agent-only goroutine work is **copied** from the existing
`hsyncengine.go` (which still exists, still serves the agent).
At this point the codebase has two complete copies of the agent's
handler logic — the old one running in production, the new one
waiting to be wired.

**Acceptance:** new code compiles and has unit tests. No
behaviour change in the agent.

**Cost:** 2-3 days.

### Phase 5: Swap the agent to HsyncDataEngine, delete the old engine

**Goal:** the agent stops using the legacy `HsyncEngine` and starts
using `HsyncDataEngine`. The old code is deleted.

**Atomic in one commit:** this is the only commit that changes
agent behaviour. The diff is reviewable as a swap, not a
restructure.

**Changes:**

- `tdns-mp/v2/start_agent.go`: replace the goroutines that call
  the old `(*Config).HsyncEngine` and `DiscoveryRetrierNG` with a
  single `HsyncDataEngine.Run` call.
- `tdns-mp/v2/hsyncengine.go`: deleted.
- `tdns-mp/v2/agent_utils.go`: `MarkAgentAsNeeded`,
  `attemptDiscovery`, HSYNC3 diff loops in `UpdateAgents` deleted
  (the agent now uses the implementations in `hsync/`).
- `tdns-mp/v2/hsync_hello.go`, `hsync_beat.go`, `gossip.go`,
  parts of `hsync_transport.go`: deleted or trimmed to the bits
  not yet moved to `hsync/`.
- Top-level `AgentRegistry` either deleted (if all callers can
  use `hsync.Registry` directly) or kept as a thin façade. To be
  decided during implementation based on the call-site survey.

**Acceptance:**

- Existing agent integration suite green.
- Captured-trace replay test confirms agent wire output is
  byte-identical to pre-Phase-5 behaviour on a known scenario.
- Live lab: deploy to one agent; confirm normal operation; bake
  for a week before deploying to all agents.

**Cost:** 4-6 days for the swap + deletions. Plus per-agent
rolling deployment time.

## 6. File-by-File Change Summary

### Phase 0 (Bite F)

- `tdns-transport/v2/transport/manager.go` — modified:
  `DiscoverPeer` body verified/extended for absent peers.
- `tdns-transport/v2/transport/peer.go` — modified: `GetOrCreate`
  initialisation confirmed.
- `tdns-mp/v2/agent_discovery.go` — modified: `DiscoveryDriver`
  adapter split if needed.

### Phase 1 (Bite D)

- `tdns-mp/v2/agent_utils.go` — modified: `OnDiscoveryFailed`
  invoked from `attemptDiscovery` failure return.
- `tdns-transport/v2/transport/manager.go` — modified:
  `OnDiscoveryFailed` invoked from `DiscoverPeer` failure.
- `tdns-mp/v2/hsync_transport.go` — modified: `OnDiscoveryFailed`
  invoked from `OnPeerDiscoveryNeeded` post-kick failure.

### Phase 2 (new shared engine in subpackage)

Added — new subpackage `tdns-mp/v2/hsync/`:

```
hsync/
├── engine.go
├── config.go
├── interfaces.go
├── registry.go
├── hsync3_diff.go
├── discovery.go
├── hello.go
├── beat.go
├── gossip.go
├── dispatch.go
└── *_test.go
```

No top-level files modified. The old protocol code in
`tdns-mp/v2/hsync_*.go`, `gossip.go`, `agent_utils.go`,
`agent_structs.go`, `hsyncengine.go` is untouched.

### Phase 3 (wire auditor)

- `tdns-mp/v2/auditor_engine.go` — new: shell that composes
  `hsync.Engine` with auditor-specific handlers.
- `tdns-mp/v2/start_auditor.go` — modified: construct
  `hsync.Engine` + `AuditorEngine`; replace the existing
  `AuditorMsgHandler`, `DiscoveryRetrierNG`, `InfraBeatLoop`, and
  `AuditorHeartbeatLoop` goroutine spawns with a single
  `AuditorEngine.Run` spawn.
- `tdns-mp/v2/auditor_msg_handler.go` — deleted; its work moves
  into `AuditorEngine`'s registered handlers on `hsync.Engine`.

### Phase 4 (new HsyncDataEngine, not wired)

- `tdns-mp/v2/hsync_data_engine.go` — new file (note: not a
  rename of `hsyncengine.go` — both exist briefly during the
  Phase 4 ⇒ Phase 5 window). Composes `hsync.Engine` with
  agent-specific handlers.

No other files modified. The old `hsyncengine.go` still serves
the agent.

### Phase 5 (swap agent, delete old engine)

- `tdns-mp/v2/start_agent.go` — modified: replace the goroutines
  that called `(*Config).HsyncEngine` and `DiscoveryRetrierNG`
  with a single `HsyncDataEngine.Run` call.
- `tdns-mp/v2/hsyncengine.go` — deleted.
- `tdns-mp/v2/agent_utils.go` — modified:
  `MarkAgentAsNeeded`, `attemptDiscovery`, the HSYNC3 diff loops
  in `UpdateAgents` — deleted. `UpdateAgents` shrinks to its
  non-discovery residue (deferred-task scheduling,
  HSYNCPARAM-aware group recomputation).
- `tdns-mp/v2/hsync_hello.go` — deleted (logic now in
  `hsync/hello.go`).
- `tdns-mp/v2/hsync_beat.go` — deleted (logic now in
  `hsync/beat.go`).
- `tdns-mp/v2/gossip.go` — deleted (logic now in
  `hsync/gossip.go`).
- `tdns-mp/v2/hsync_transport.go` — trimmed: parts not yet
  moved to `hsync/` stay; rest deleted.
- `tdns-mp/v2/agent_structs.go` — modified or deleted: depending
  on the call-site survey, `AgentRegistry` either becomes a thin
  façade over `hsync.Registry` or is deleted entirely. The
  decision is made during implementation, not in this doc.

Top-level callers that referenced `AgentRegistry` directly (API
handlers, CLI commands) either use the façade or migrate to
`hsync.Registry`. The choice between these two depends on how
many call sites exist; if a small number, migrate them; if many,
keep a façade.

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

**(R-1) Agent-side behavioural drift at Phase 5.**
Phase 5 is the single moment where agent behaviour changes —
from the legacy `HsyncEngine` to `HsyncDataEngine` composing
`hsync.Engine`. Any divergence between old and new protocol code
is a correctness risk. Mitigate with captured-trace replay
tests: record an agent's wire output over a known scenario
before Phase 5, replay post-Phase 5, assert byte equivalence on
outbound messages. The auditor bake-in period (between Phase 3
and Phase 4) reduces this risk by validating the shared engine
in production before agents migrate.

**(R-2) Brief code duplication window (Phase 2 through Phase 5).**
During Phase 2, the new `hsync/` subpackage *copies* logic from
the existing top-level files rather than moving them. The
duplication exists until Phase 5 deletes the old code. If
bugs are found in the legacy protocol code during this window,
the fix must be applied to both copies. Mitigate by keeping the
window short — Phase 2 through Phase 5 should be a contiguous
work stretch, not an indefinite parking lot. Track legacy fixes
in a checklist and verify each has been mirrored to `hsync/`
before Phase 5.

**(R-3) Auditor BEAT traffic increase.**
Auditors will now emit periodic BEATs on the same cadence as
agents. For an N-member group this multiplies BEAT traffic by
(N+M)/N where M is the auditor count. For typical 3-5 member
groups this is a 30-60% increase in BEAT volume. Acceptable: the
safety contract requires it, BEATs are small, and this load is
identical to what an additional agent in the group would
generate.

**(R-4) Group-operational gating becomes stricter.**
Today, agents that have not yet discovered all auditors may
proceed with SYNC/UPDATE because the protective check was
incomplete in practice. After Cut A, the check tightens — agents
will pause SYNC/UPDATE emission until the auditor is
`OPERATIONAL`. This may surface latent dependencies on the
incorrect behaviour, particularly in test scenarios where
auditors were not configured. Mitigate by auditing test fixtures
before Phase 5 deployment.

**(R-5) Import cycles when moving more code into hsync/.**
The first-wave migration (Phase 2) only contains new code with
deliberately narrow interface dependencies. Later waves (moving
existing files like `agent_utils.go` and `agent_structs.go` into
`hsync/`) may surface bidirectional dependencies — top-level
`tdnsmp` types that today freely call into `AgentRegistry`, and
HSYNC code that freely reaches into config and zone globals.
Mitigate by treating each file move as its own commit, fixing
import direction at the move boundary with interface insertion
in `hsync/interfaces.go`. The pattern is: identify what the
moved file needs from top-level → define an interface in
`hsync/` describing exactly that need → make top-level types
satisfy the interface → inject at construction in `start_*.go`.

**(R-6) Phase 2 cost (6-9 days, no production exposure).**
Phase 2 is a meaningful chunk of build effort with no
deliverable visible to users. If priorities shift mid-Phase-2,
work is stranded. Mitigate by keeping Phase 2 narrow: only the
new `hsync.Engine` and its directly-owned helpers. Don't try to
move existing top-level files into `hsync/` during Phase 2 —
those moves can happen incrementally after Phase 5 lands.

**(R-7) Reconcile interval tuning.**
Default `ReconcileInterval = 4 × RetryInterval = 60s`. Too
aggressive wastes work; too sparse and the cpt-class bug window
stays open. Idempotent operation makes overruns harmless. (This
is the same setting already shipped in
`auditor-discovery-fix`/`HsyncReconcile` and works in
production.)

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

1. **Per-peer goroutine bound.** `tm.DiscoverPeer` may block on
   slow IMR. `hsync.Engine.Run`'s retry pass currently has no
   bound on concurrent in-flight discoveries. Add a semaphore or
   worker pool; size to taste (suggest `min(N_peers, 8)`).
2. **Election message *receipt* on auditor side.** Auditors must
   record election messages but never act on them. Confirm the
   election-message wire type is identifiable as such by the
   shared dispatcher so the auditor's
   `OnElectionMessageReceived` handler reliably catches every
   election-related message, including votes carried as part of
   other message bodies (if any).
3. **`AgentRegistry` façade vs. delete.** Phase 5 decides whether
   top-level `AgentRegistry` becomes a thin façade over
   `hsync.Registry` or is deleted entirely. The decision depends
   on a call-site survey done during Phase 5 implementation.
   Surveying the call sites earlier (during Phase 2 or 3) would
   make Phase 5 cheaper to plan.

## 10a. Already shipped: tactical fix on auditor-discovery-fix branch

The immediate production correctness gap was closed by the
`auditor-discovery-fix` branch (commits `84841f7`, `e98bcb4`),
which adds a periodic `HsyncReconcile` pass that walks every MP
zone's HSYNC3 RRset and calls `MarkAgentAsNeeded` for missing
peers. This runs on both agents and auditors. It does not
extract the shared engine — it works inside the current
implementation framework — but it removes the production
urgency of Cut A.

Cut A still has value (drift prevention, cleaner separation,
on-ramp to transport redesign Phase 6 part 2), but it is no
longer time-pressured. This affects sequencing: Cut A can be
scheduled around other priorities rather than treated as a
must-fix-now correctness item.

## 11. Future Direction: HsyncDataEngine Dissolves

`HsyncDataEngine` should be understood as a **transitional
vessel**, not a permanent agent-side engine. Cut A introduces it
as a thin shell around `hsync.Engine`, but the rest of its
responsibilities migrate out over time and the shell eventually
disappears. The end state has no `HsyncDataEngine` at the
top-level — only the role-specific engines `AuditorEngine` (and
eventually a small `ElectionEngine`) on top of `hsync.Engine`,
all alongside SDE.

This affects how to invest in it during Cut A: **don't polish or
over-engineer its API.** It is a stop along the way.

Note that `hsync.Engine` itself is *not* transitional — the
subpackage is permanent (see §3.6), and continues to grow as
additional protocol code migrates down from the top-level
package after Cut A lands.

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
