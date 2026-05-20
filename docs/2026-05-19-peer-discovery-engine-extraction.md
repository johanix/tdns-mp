# Splitting HsyncEngine: Shared Sync Conversation Engine
# + Agent-Only Data Engine

**Date:** 2026-05-19 (updated 2026-05-20)
**Status:** Design — in progress on feature branch (see §5.0, §5.1)
**Branch policy:** `main` is frozen for external interop; all Cut A work
lives on the feature branch stack described in §5.0.
**Related:**
- `2026-04-15-transport-interface-redesign.md`
- `2026-04-25-transport-refactor-early-bites.md`
- `2026-04-30-transport-refactor-semi-easy-bites.md`

## 1. Motivation

A live debugging session on `customer.mptest.` (May 2026) surfaced a
production-correctness failure caused by the architectural split
between agents and auditors. **The immediate symptoms are fixed on
`main`** (see §10a); this document describes the structural refactor
that prevents them from recurring.

### 1.1 What failed (historical)

Before the tactical fix:

- Only agents ran the full `HsyncEngine` goroutine. Auditors had no
  HSYNC3-driven registration path (`SyncQ` / `UpdateAgents` is
  agent-only).
- `auditor.mp` had a registry of `{fox, hare}` — peers whose first
  beats reached it — and was blind to `agent.cpt.mp` and
  `auditor.skrubb` until inbound traffic established them.
- On the agent side, `agent.cpt.mp` missed `auditor.mp` when the
  HSYNC3 RRset grew from count=4 to count=5 after `UpdateAgents`
  had already run for the earlier transition.

**Why this is a safety-contract failure, not a cosmetic bug.**
When a customer enters an auditor into the HSYNC configuration, the
semantic is *hard requirement*: "I demand that my appointed auditor
is fully integrated into the synchronization loop; you are not
allowed to proceed with changes if the auditor is not informed."
The gossip group state machine enforces this — `CheckGroupState`
(using `pg.Members`, which includes auditors) requires every
HSYNC-listed peer to appear `OPERATIONAL` in every gossip row
before the group is mutually operational. An undiscovered auditor
keeps the group `DEGRADED`. That blocks **`OnGroupOperational`**
callbacks (leader-election initiation, deferred elections) and
leaves peers stuck in `NEEDED`. It is **not** a single centralized
gate on all SYNC/UPDATE emission; per-peer operational checks and
election state still apply elsewhere.

Auditors are also designed to be optional at the group level — a
group with zero auditors is legitimate — but when present they are
load-bearing.

The underlying structural problem remains: **there is no single
shared sync-conversation implementation.** Agents run
`HsyncEngine`; auditors run a parallel set of goroutines
(`DiscoveryRetrierNG`, `ReconcileHsync`, `AuditorHeartbeatLoop`,
`AuditorMsgHandler`) that duplicate protocol logic and drift easily
(see §2.3).

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

### 2.3 Auditor today (on `main`, post `auditor-discovery-fix`)

The auditor still does **not** run `HsyncEngine`, `SynchedDataEngine,
leader-election origination, KeyStateWorker, or outbound zone-data
paths. It **does** participate in the sync conversation via duplicated
machinery wired in `start_auditor.go`:

| Goroutine | Source | Role |
|-----------|--------|------|
| `DiscoveryRetrierNG` | `hsyncengine.go` | Retry `NEEDED` peers |
| `HsyncReconcile` | `hsync_reconcile.go` | Periodic HSYNC3 → `MarkAgentAsNeeded` |
| `AuditorHeartbeatLoop` | `start_auditor.go` | Ticker → `SendHeartbeats()` |
| `InfraBeatLoop` | `hsync_infra_beat.go` | Infra peers (no-op if unset) |
| `AuditorMsgHandler` | `auditor_msg_handler.go` | MsgQs consumer + audit log |

Proactive discovery → HELLO → BEAT → outbound gossip **works** on the
auditor today via `MarkAgentAsNeeded` / `attemptDiscovery` /
`HelloRetrierNG` / `SendHeartbeats` — the same `AgentRegistry` methods
the agent uses, minus the `HsyncEngine` main loop.

**Gaps vs agents (why Cut A remains necessary):**

| Area | Agent | Auditor |
|------|-------|---------|
| Event-driven HSYNC3 registration | `PostRefresh` → `SyncQ` → `UpdateAgents` | `PostRefresh` only `RecomputeGroups()`; registration waits for `ReconcileHsync` (up to ~60s) |
| Single protocol owner | `HsyncEngine` | Four separate goroutines + `AuditorMsgHandler` |
| `SyncQ` / `HSYNC-UPDATE` | Yes | No (`SyncQ` not created in `initMPAuditor`) |
| HSYNC3 removes from registry | `UpdateAgents` / `HsyncRemoves` | **Not applied today** — `ReconcileHsync` is additive-only (known gap; fixed in Phase P, §5.0) |
| `OnGroupOperational` election wiring | Set in `HsyncEngine` startup | Not set (auditor observes elections via gossip only) |
| Inbound dispatch | `HsyncEngine` + transport routing | `AuditorMsgHandler` + transport routing (duplicate) |

`auditor_detectors.go` still logs "expected but not seen" for HSYNC3
identities as a **belt-and-suspenders** check; registration is driven
by `ReconcileHsync`, not the detector.

### 2.4 Current TransportManager API

On **`main`**, transport exposes `DiscoverPeer`, `DiscoveryDriver`,
`OnPeerDiscovered`, and `OnDiscoveryFailed` in
`tdns-transport/v2/transport/manager.go`, but **tdns-mp does not use
them yet** (discovery still flows through `attemptDiscovery` →
`RegisterDiscoveredAgent`).

On branch **`transport-refactor-semi-easy-bites`** (both repos), Bites
C/D/E/F/G/H are implemented: `OnPeerDiscovered func(*Peer)`,
`OnDiscoveryFailed` wired from `attemptDiscovery`, `DiscoveryDriver`
on `MPTransportBridge` (`RunDiscovery` → `DiscoverAndRegisterAgent`),
and `SyncPeerFromAgent` split (Bite H). **Cut A Phases 0–1 are
complete on that branch** — see §5.0.

### 2.5 TransportManager API (reference)

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
- `OnGroupOperational` not firing blocks leader-election progression
  and leaves deferred elections pending; combined with gossip
  `DEGRADED`, agents cannot treat the group as coordination-ready.
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

### 3.7 Design decisions (resolved 2026-05-20)

These were open questions from the pre-implementation review.
Alternatives were evaluated against the current codebase (see §6a).

#### D-1: Message dispatch boundary

| Alternative | Summary | Verdict |
|-------------|---------|---------|
| A. `hsync.Engine` owns everything including transport decode | Move `MPTransportBridge` routing into `hsync/` | **Reject** — transport bridge is large, couples TLS/DNS/CHUNK to protocol package, fights import direction |
| B. Transport routes wire → MsgQs; `hsync.Engine.Run` owns the `select` loop | Same split as today, unified loop | **Accept** |
| C. Keep separate `AuditorMsgHandler` forever | Minimal Phase 3 diff | **Reject** — permanent drift |

**Decision:** **B.** `MPTransportBridge` continues to verify, decode, update
`PeerRegistry`, merge inbound gossip, and enqueue `AgentMsgReport` /
`AgentMsgPostPlus` to `MsgQs`. `hsync.Engine.Run` owns the **single**
`select` on `Beat`, `Hello`, `Msg`, and the beat/discovery/reconcile
tickers. Role-specific work is **handler callbacks** registered at
startup (`AuditorEngine`, `HsyncDataEngine`).

Agent-only channels (`Command`, `DebugCommand`, `SyncStatusQ`,
`StatusUpdate`, `KeystateInventory`, `SyncQ`) stay in
`HsyncDataEngine.Run` — not in shared `hsync.Engine`.

#### D-2: Discovery API for `hsync.Engine`

| Alternative | Summary | Verdict |
|-------------|---------|---------|
| A. Build Phase 2 on legacy `attemptDiscovery` only | Ignore `DiscoverPeer` until Phase 6 | **Reject** — duplicates work when semi-easy lands |
| B. `hsync` calls `tm.DiscoverPeer` after `MarkNeeded` creates registry entry | Uses semi-easy stack | **Accept** |
| C. Move all IMR lookups into `hsync/` | Self-contained package | **Reject** — IMR stays app-layer |

**Decision:** **B.** After semi-easy merge, discovery in `hsync/discovery.go`
calls `TransportDriver.DiscoverPeer` (wrapper around `tm.DiscoverPeer`).
`MarkNeeded` still inserts into `AgentRegistry` / peer map first; driver
updates both registries via existing `RegisterDiscoveredAgent`.

#### D-3: `AgentRegistry` vs `hsync.Registry`

| Alternative | Summary | Verdict |
|-------------|---------|---------|
| A. Delete `AgentRegistry`; migrate all call sites to `hsync.Registry` in Phase 5 | ~25 files change in one commit | **Reject** — high blast radius for CLI/API |
| B. `AgentRegistry` embeds `*hsync.Registry`; protocol methods move to `hsync` | Stable external type | **Accept** |
| C. `AgentRegistry` is a thin alias over `hsync.Engine` | One pointer everywhere | **Reject** — conflates registry with goroutine lifecycle |

**Decision:** **B.** `hsync.Registry` owns `S`, `RemoteAgents`, `helloContexts`,
and protocol methods (`MarkNeeded`, `SendHeartbeats`, HELLO/BEAT handlers).
`AgentRegistry` embeds `*hsync.Registry` and retains
`GossipStateTable`, `ProviderGroupManager`, `LeaderElectionManager`,
`TransportManager`, `MPTransport`, `LocalAgent` (election and group
state stay at `tdnsmp` level because combiner/signer/API handlers
reference them). Existing `(*AgentRegistry).Method` signatures on
protocol paths become wrappers delegating to `hsync.Registry` during
migration, then delete wrappers in Phase 5.

#### D-4: Auditor HSYNC3 registration path

| Alternative | Summary | Verdict |
|-------------|---------|---------|
| A. Reconcile-only (60s max latency) | Status quo | **Reject** — unnecessary agent/auditor asymmetry |
| B. Shared `ApplyHsyncDiff` from `PostRefresh` for all MP roles | Event-driven + reconcile safety net | **Accept** |
| C. Create `SyncQ` on auditor and run full `UpdateAgents` | Maximum parity | **Reject** — pulls agent-only side effects (election triggers, deferred tasks) |

**Decision:** **B.** `MPPostRefresh` auditor branch calls
`hsync.Engine.ApplyHsyncDiff` (adds/removes) instead of only
`RecomputeGroups`. `ReconcileHsync` remains as safety net.

#### D-5: HSYNC3 removes (all roles)

| Alternative | Summary | Verdict |
|-------------|---------|---------|
| A. Additive reconcile only | Status quo on `main` | **Reject** — stale registry entries skew gossip matrices and `peer list`; not acceptable even before Cut A lands |
| B. Symmetric reconcile: diff HSYNC3 vs registry per zone | Same semantics as `HsyncRemoves` in `UpdateAgents` | **Accept** |
| C. Auditor relies on agent-only `UpdateAgents` | No auditor path | **Reject** |

**Decision:** **B.** `ReconcileZone` and `ApplyHsyncDiff` must both
**add** missing HSYNC3 identities and **remove** registry entries for
identities no longer listed (per zone: `RemoveRemoteAgent`; recompute
shared zones when an identity drops off all zones). Implementation
lands in **Phase P** on the feature branch (before or alongside Phase 2
`hsync/` extraction — see §5.0). Extraction copies the symmetric logic
into `hsync/hsync3_diff.go` / `hsync/reconcile.go`; do not ship
additive-only reconcile on the Cut A branch.

#### D-6: Phase ordering

| Alternative | Summary | Verdict |
|-------------|---------|---------|
| A. Auditor-first (Phase 3 before agent) | Original plan | **Accept** — validates shared engine under traffic before Phase 5 |
| B. Agent-first | Shorter duplication on agent | **Reject** — higher production risk |

**Decision:** **A**, unchanged. Phase 3 value is **validation and
deduplication**, not correctness.

#### D-7: `HsyncDataEngine` investment level

**Decision:** unchanged from §11 — minimal transitional shell; no stable
public API.

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
2. Bites F and D are prerequisites; satisfied on the semi-easy stack
   (§5.0).
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

### 5.0 Branching and repository policy (mandatory)

**Constraint (May 2026):** `main` in `tdns-mp` and `tdns-transport` must
**not** be modified while external interop testing is in progress.
Semi-easy bites **cannot** be merged to `main` before Cut A starts.
Semi-easy cannot be exercised in production on its own branch during
interop.

**All Cut A work — including capturing commits that exist only on
`main` today — stays on feature branches.** Nothing merges to `main`
until interop allows it.

#### Stack (bottom → top)

```
main                          ← frozen; no commits for Cut A / semi-easy
  ↑ merge main in (one-time + as needed)
transport-refactor-semi-easy-bites   ← Phases 0–1 (Bites C/D/E/F/G/H)
  ↑ branch
peer-discovery-engine-extraction     ← Cut A (this document)
```

**Step 1 — Integrate `main` into semi-easy (both repos):**

```text
git checkout transport-refactor-semi-easy-bites
git merge main          # NOT merge semi-easy into main
# resolve conflicts (tdns-mp: v2/enums.go, v2/transport_integ_test.go, …)
# tdns-mp: bump go.mod transport pin to semi-easy transport commit
```

This pulls `auditor-discovery-fix` / `HsyncReconcile` and any other
`main`-only fixes onto the semi-easy stack without touching `main`.

**Step 2 — Create Cut A branch from updated semi-easy:**

```text
git checkout -b peer-discovery-engine-extraction
```

**Step 3 — All implementation** on `peer-discovery-engine-extraction`
(and short-lived topic branches merged into it). Repeat Step 1 on
semi-easy only when `main` gains fixes that must be captured before
interop ends.

**Later (post-interop):** merge semi-easy (+ Cut A) to `main` in one
or two PRs — out of scope until testing allows.

**Phases 0–1:** satisfied on `transport-refactor-semi-easy-bites` after
Step 1 brings in current `main`.

**Tactical fix on `main`:** `HsyncReconcile` (additive-only today) is
included via Step 1 but **must be extended** per §3.7 D-5 in Phase P.

---

### Phase P: Prep — merge `main` → semi-easy, symmetric reconcile

**Goal:** branch stack ready; fix additive-only `ReconcileHsync` before
or as the first Cut A code.

**Tasks:**

1. Merge `main` into `transport-refactor-semi-easy-bites` (`tdns-mp`,
   `tdns-transport`).
2. Create `peer-discovery-engine-extraction` from updated semi-easy.
3. Extend `reconcileZone` (and later `ApplyHsyncDiff`) to remove peers
   present in the registry for a zone but absent from the current HSYNC3
   RRset — mirror `UpdateAgents` `HsyncRemoves` handling
   (`RemoveRemoteAgent`, `RecomputeSharedZonesAndSyncState`).

**Acceptance:** integration test — HSYNC3 count drops; removed identity
disappears from auditor and agent `peer list` without restart.

**Status:** complete on `peer-discovery-engine-extraction` (2026-05-20)

Delivered:

- `main` merged into `transport-refactor-semi-easy-bites` (`f9e6be0`, tdns-mp).
- Branch `peer-discovery-engine-extraction` created from that stack.
- Symmetric `reconcileZone` (+ tests); `tdns-transport` semi-easy already
  contained `main`.
- Local `go.mod` replaces for `tdns` + `tdns-transport` (in-tree builds).

---

### 5.1 Progress and work units

Cut A is split along **phase boundaries** (natural PR / review units).
This document is the **living record** — update the status row when a
phase completes. No Linear.

| Phase | Description | Status | Branch / notes |
|-------|-------------|--------|----------------|
| P | Prep: merge `main`→semi-easy, symmetric reconcile | **done** | `peer-discovery-engine-extraction` |
| 0 | Bite F (`DiscoverPeer` / `DiscoveryDriver`) | done on semi-easy | semi-easy stack |
| 1 | Bite D (`OnDiscoveryFailed`) | done on semi-easy | semi-easy stack |
| 2 | Build `tdns-mp/v2/hsync/` (unwired) | **done** | `peer-discovery-engine-extraction` — `hsync/` package + unit tests |
| 3 | Wire `AuditorEngine` | **done** | `peer-discovery-engine-extraction` — `AuditorEngine` + `ApplyHsyncDiff` on auditor PostRefresh |
| 4 | Build `HsyncDataEngine` (unwired) | **done** | `peer-discovery-engine-extraction` — `hsync_data_engine.go` |
| 5 | Swap agent, delete legacy engine | **done** | `peer-discovery-engine-extraction` — agent uses `HsyncDataEngine`; legacy `HsyncEngine` loop removed |

---

Six phases (0–1 on semi-easy stack). Ordering keeps
auditor validation before agent migration. Each phase ends in a
coherent, deployable state.

Phase 3 is **no longer a correctness fix** (§10a); it is the first
production exercise of the shared engine. Phase 5 remains the only
agent behaviour change.

### Phase 0: Finish Bite F — DONE on `transport-refactor-semi-easy-bites`

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

**Status:** Implemented — `MPTransportBridge.RunDiscovery` delegates to
`DiscoverAndRegisterAgent`; `tm.DiscoveryDriver = tm` at bridge init.

### Phase 1: Finish Bite D — DONE on `transport-refactor-semi-easy-bites`

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

**Status:** Implemented — `fireOnDiscoveryFailed` in `attemptDiscovery`;
`OnDiscoveryFailed` registered on `TransportManager` at bridge init.

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

**Reconciliation safety-net (cpt bug fix):** `Engine.Run` runs
`ReconcileZone` every `ReconcileInterval` (default 60s) for every MP
zone. **Symmetric** per §3.7 D-5: adds missing HSYNC3 identities and
removes stale ones. Idempotent.

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

**Production correctness is already on `main` via `HsyncReconcile`
(§10a).** Phase 3 validates the shared engine in production and
replaces the duplicated auditor goroutines with `AuditorEngine` +
`hsync.Engine`. If the project pauses after Phase 3, the codebase
has one protocol implementation exercised on the read-only role
before the agent migration (Phase 5).

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

### Phase P (prep)

- `tdns-mp` / `tdns-transport` — merge `main` into
  `transport-refactor-semi-easy-bites` (no changes on `main`).
- `tdns-mp/v2/hsync_reconcile.go` — symmetric `reconcileZone`
  (removes + adds); update package comment (no longer additive-only).
- `tdns-mp/v2/go.mod` — transport pseudo-version bump if needed after
  merge.

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

## 6a. `AgentRegistry` call-site survey (2026-05-20)

Survey of `tdns-mp/v2` on `main`. Goal: plan the §3.7 D-3 façade
without a Phase 5 surprise.

### Summary counts

| Category | Files | Action for Cut A |
|----------|-------|------------------|
| Protocol methods on `*AgentRegistry` | 9 files, ~45 methods | Move implementation to `hsync/`; leave delegating wrappers until Phase 5 |
| `conf.InternalMp.AgentRegistry` field access | 14 files, ~35 sites | Keep `*AgentRegistry`; no CLI/API renames |
| `MPTransportBridge.agentRegistry` | `hsync_transport.go` (~25 refs) | Keep; bridge needs registry for routing — inject `*AgentRegistry` embedding `hsync.Registry` |
| Tests / harness | `transport_harness_test.go` | Construct `AgentRegistry` with embedded `hsync.Registry` |

### Protocol layer — move to `hsync/` (Phase 2 copy, Phase 5 delete wrappers)

| File | Methods / symbols |
|------|-------------------|
| `agent_utils.go` | `MarkAgentAsNeeded`, `attemptDiscovery`, `DiscoverAgentAsync`, `UpdateAgents`, `GetAgentsForZone`, zone association helpers |
| `hsyncengine.go` | `DiscoveryRetrierNG`, `retryPendingDiscoveries`, `SyncRequestHandler` (HSYNC-UPDATE path only) |
| `hsync_hello.go` | `HelloRetrierNG`, `SingleHello`, `sendHelloToAgent`, `EvaluateHello`, `HelloHandler`, … |
| `hsync_beat.go` | `SendHeartbeats`, `HeartbeatHandler` |
| `hsync_infra_beat.go` | `StartInfraBeatLoop` |
| `hsync_reconcile.go` | `ReconcileHsync`, `reconcileZone` |
| `agent_discovery.go` | `RegisterDiscoveredAgent` stays on bridge; discovery **orchestration** moves to `hsync/discovery.go` |

### Shared infrastructure — stay on `AgentRegistry` at `tdnsmp` level

| File | Why |
|------|-----|
| `gossip.go`, `gossip_types.go` | Used by transport beat path and API; references `ProviderGroupManager` |
| `provider_groups.go` | Zone-data-derived; not pure protocol |
| `parentsync_leader.go` | Election origination (agent); `GetParentSyncStatus` takes `*AgentRegistry` |
| `combiner_peer.go`, `signer_peer.go` | Virtual peer setup at agent start |

### Wiring — `start_*.go`, `main_init.go`

| Site | Role |
|------|------|
| `main_init.go` | `NewAgentRegistry()`, wire `TransportManager` / `MPTransport` |
| `start_agent.go` | Combiner/signer init; spawn engines (becomes `HsyncDataEngine.Run` in Phase 5) |
| `start_auditor.go` | Spawn engines (becomes `AuditorEngine.Run` in Phase 3) |
| `hsyncengine.go` | `HsyncEngine` loop → absorbed by `HsyncDataEngine` + `hsync.Engine` |

### API / CLI — keep `*AgentRegistry` type through Cut A

| File | Usage |
|------|-------|
| `apihandler_peer.go` | `/peer` ping, reset — `APIpeer(..., ar *AgentRegistry)` |
| `apihandler_gossip.go` | `APIgossip(ar, lem)` |
| `apihandler_agent.go` | Discovery triggers, `EvaluateHello`, agent listing |
| `apihandler_agent_distrib.go` | Zone agent lists, registry iteration |
| `apihandler_agent_hsync.go` | `GetZoneAgentData` |
| `apihandler_*_routes.go` | Pass registry into handlers (agent, auditor, combiner, signer) |
| `apirouter_sync.go` | TLS client cert lookup in `AgentRegistry.S` |
| `auditor_web.go`, `auditor_dto.go`, `apihandler_auditor.go` | `SnapshotGossip(ar)` |
| `cli/agent_debug_cmds.go` | Dump registry |
| `cli/hsync_cmds.go` | User-facing "AgentRegistry" messages |
| `cli/peer_cmds.go` | Documents agent-only reset |

### Other

| File | Usage |
|------|-------|
| `hsync_utils.go` | `RequestAndWaitForConfig/Audit` — agent RFI; stay top-level |
| `auditor_msg_handler.go` | Deleted Phase 3 when `hsync.Engine` owns MsgQs loop |
| `config.go` | `InternalMpConf.AgentRegistry` field — unchanged |

### Conclusion (feeds §3.7 D-3)

**Do not delete `AgentRegistry` in Phase 5.** Embed `*hsync.Registry`,
move protocol bodies into `hsync/`, delete delegating wrappers and
duplicate goroutine spawns. API and CLI keep importing `tdnsmp`
only — no `hsync` in HTTP handler signatures unless we choose to
later.

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
- Reconciliation adds: remove peer from registry mid-test; confirm
  `ReconcileZone` re-inserts it.
- Reconciliation removes: drop identity from HSYNC3; confirm
  `ReconcileZone` removes it from agent and auditor registry.
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

## 10. Open items

| # | Item | Status |
|---|------|--------|
| 1 | Per-peer discovery concurrency bound | **Open** — add semaphore in `hsync/discovery.go` (`min(N_peers, 8)`); implement in Phase 2 |
| 2 | Election message receipt on auditor | **Open** — verify during Phase 3 that `MsgHandler` election subtypes reach auditor `recordToAuditLog`; add dispatcher test |
| 3 | `AgentRegistry` façade vs delete | **Resolved** — embed `*hsync.Registry`; see §6a, §3.7 D-3 |

## 10a. Tactical fix (shipped on `main`)

Merged via PR #24 (`auditor-discovery-fix`). `HsyncReconcile`
(`hsync_reconcile.go`) walks every MP zone's HSYNC3 RRset and calls
`MarkAgentAsNeeded` for missing peers on **both** agents and auditors.
Wired in `start_agent.go` and `start_auditor.go`.

This does not extract the shared engine — it duplicates protocol
machinery across roles — but it closed the production gap described
in §1.1.

**Cut A** proceeds on the feature branch stack (§5.0) without merging
to `main` during interop. Symmetric HSYNC3 reconcile (§3.7 D-5) is
required on that branch even before the `hsync/` package exists (Phase P).

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
