# Transport Interface Redesign: Clean Separation of
# Transport and Application Layers

Date: 2026-04-15 (revised 2026-04-16, 2026-04-23, 2026-04-30)
Status: PLAN — Phase 0 (integration test harness) **DONE**;
        all 8 early bites + the harness implemented. Phases
        1+ ready to begin; remaining pre-work is items
        I, L, N, O (see Status Update).

**Revision 2026-04-16 summary** (see "Re-evaluation" section
below for details):
- Zero progress on A/B/C items since 2026-04-15; plan
  diagnosis remains accurate.
- Gossip placement **deferred** — keep in MP, rename wire
  field to `AppData`, revisit Tier 2 placement later when
  a second application materializes. Closes OQ1 and item G.
- Integration tests (formerly "Bite 2") promoted to
  **mandatory Phase 0**. The rest of the plan does not
  begin until the harness exists.
- Bite 1 scope expanded to include dual-write plumbing
  (otherwise `Peer.Mechanisms` lands as dead code).
- Method count in `hsync_transport.go` is now **54**, not
  48. Phase 7 re-decomposed into 8 substeps.
- `Agent.PeerID` added as explicit Phase 7 step 1.
- tdns-mp post-migration cleanup is ~98% done and is
  **not** a prerequisite for this refactor.

Builds on: 2026-03-24-transport-manager-redesign.md,
           2026-03-23-transport-extraction-implementation-plan.md,
           2026-03-21-transport-extraction-analysis.md

> **EARLY BITES COMPLETE (2026-04-30).** All 9 items from
> [2026-04-25-transport-refactor-early-bites.md](./2026-04-25-transport-refactor-early-bites.md)
> are implemented and merged: Bites 0, 1, 3, 4, 6, 7, 8
> plus Bite 2 (the test harness). Bite 5 closed as a
> verified no-op.
>
> **NEXT: SEMI-EASY BITES (2026-04-30).** A second tier
> of additive work is now tractable. See
> [2026-04-30-transport-refactor-semi-easy-bites.md](./2026-04-30-transport-refactor-semi-easy-bites.md)
> for nine more bites (I, C, E, A, B, D, F, G, H —
> recommended order) that close open items L and I and
> partially complete Phases 1, 5, 6, 7. Total cost
> ~4–5 working days.
>
> The harness in
> [2026-04-23-transport-boundary-test-harness.md](./2026-04-23-transport-boundary-test-harness.md)
> lives at `tdns-mp/v2/transport_harness_test.go` +
> `tdns-mp/v2/transport_integ_test.go`. All seven
> `TestTransportBoundary_*` scenarios pass. Phase 0 exit
> gate satisfied.
>
> Net effect on the 9-phase plan below: Phase 0 done;
> Phase 1 collapses to a deletion (per-mechanism state
> already in place via Bites 1 + 7); Phase 5 partially
> collapsed (sync path delegates to `tm.Send`; Hello/Beat
> still need their parallel-send semantics resolved);
> Phase 6 part 1 done (IMR helpers in transport via
> parallel embedding); Phase 6 part 2 seam installed via
> `OnPeerDiscovered`; Phase 7 step 1 done (`Agent.PeerID`);
> Phase 7 steps 2–3 partially done (`PopulateFromAgent`
> + wrapper switch landed; `SyncPeerFromAgent` itself
> still has 9 write-shaped call sites awaiting Phase 7
> proper).
>
> Per-phase status is annotated inline below.

## Problem Statement

The extraction of tdns-transport into a standalone repo is
structurally complete, but the interface boundary between
transport and application is not clean. Application-specific
concepts leak into the transport layer, and generic transport
operations remain in the application layer.

The goal of tdns-transport is: **a reusable library for any
application that needs secure, reliable, DNS-based (or
API-based) peer-to-peer messaging.** A new application with no
knowledge of HSYNC, multi-provider DNSSEC, zones, agents,
combiners, or signers should be able to import tdns-transport
and build on it.

Today that is not possible. The transport layer has intimate
knowledge of DNS multi-provider concepts, and any new
application would inherit a large surface area of irrelevant
types and assumptions.

## Design Principles

1. **Transport delivers opaque payloads between authenticated
   peers.** It does not interpret message content.

2. **Transport provides a tiered API.** Applications choose
   how much functionality they need:
   - Tier 1: Core messaging (peer discovery, send by
     identity, JOSE crypto, DNS/API mechanisms)
   - Tier 2: Ongoing relationships (hello, beat, ping, peer
     state machine, liveness tracking)
   - Tier 3: Reliable delivery (RMQ, confirmations,
     distribution tracking)

   Peer discovery is Tier 1 — it's foundational. Without
   it, "send to peer X" is meaningless. Transport resolves
   identities to contact information so every application
   gets this for free.

3. **Message types are opaque strings.** Transport pre-handles
   hello/beat/ping. All other message types are
   application-defined and dispatched via registered handlers.

4. **No role awareness.** Transport knows about "peers", not
   "agents", "combiners", or "signers". All recipients are
   peer IDs (strings).

5. **Scoping is generic.** Where transport currently uses
   "zone", it should use a generic "scope" or "resource"
   concept. The application interprets the scope.

6. **Security model is JOSE.** HPKE remains available as a
   crypto backend but JOSE (JWS/JWE) is the primary security
   model for payload signing and encryption.

7. **Authorization is a callback.** Transport calls an
   application-provided authorization function. The
   application decides the policy.

## Re-evaluation (2026-04-16)

The original 2026-04-15 review flagged the plan as "not
ready". A day-later re-check against the current code
confirms **no progress has been made on A, B, or C items**;
the diagnosis remains correct to the letter. What has
changed is context:

**Migration is done.** The tdns → tdns-mp/tdns-transport
migration completed. Legacy cleanup of tdns-mp itself is
~98% done (see `2026-04-15-legacy-cleanup-implementation-plan.md`)
and the remainder (Phase 10 of that plan) is safe to defer.
tdns-mp is clean enough to begin the transport interface
work directly. No pre-cleanup pass is needed.

**Gossip placement can be deferred.** `BeatRequest.Gossip`
is already `json.RawMessage`; transport never interprets
it. Gossip code is fully contained in tdns-mp (`gossip.go`,
`gossip_types.go`, `provider_groups.go`, and assembly in
`hsync_transport.go`). Renaming the field to `AppData` in
Phase 2 is wire-compatible regardless of final placement.
Shipping transport as a reusable library without gossip is
a legitimate, useful state. See revised OQ1 / item G below.

**Integration tests are a hard prerequisite.** Zero
transport-boundary tests exist. The original "Bite 2" is
promoted to a mandatory **Phase 0** — nothing else begins
until the harness is in place.

**Drift in numbers.** `hsync_transport.go` is 54 methods
(not 48) and 2210 lines. `Dns*Payload` is 13 exported types
(not 18). Phase 7 load grew accordingly.

**What this revision does not change:** the 9-phase
structure, the target public API, the design principles,
the migration direction, the tiered API model, or any of
the other three resolved OQs (scope, QNAME, hello content).

## Status Update (2026-04-15, revised 2026-04-16,
## 2026-04-30)

**2026-04-30 update.** All eight early bites from
[2026-04-25-transport-refactor-early-bites.md](./2026-04-25-transport-refactor-early-bites.md)
plus the test harness from
[2026-04-23-transport-boundary-test-harness.md](./2026-04-23-transport-boundary-test-harness.md)
are implemented. Phase 0 exit gate satisfied (seven
`TestTransportBoundary_*` scenarios pass). Open items K
and J close. Per-phase status is now annotated inline at
each phase heading. Phase 1 unblocked.

The plan remains structurally sound. The 9-phase
restructure is now meaningfully smaller: Phase 0 done;
Phase 1 is per-mechanism state already in place + pure
deletion of single-state fields + removal of
`ZoneRelation`/`SharedZones`; Phase 5 partial (sync via
`tm.Send`, Hello/Beat parallel-send pattern still TODO);
Phase 6 part 1 done (parallel-embedded `transport.Imr`
with six lookup helpers); Phase 6 part 2 has its callback
seam (`OnPeerDiscovered`) in place; Phase 7 step 1
(`Agent.PeerID`) done.

### Decisions Made

**OQ1 (gossip placement) — REVISED 2026-04-16: DEFERRED.**
Original resolution was "transport, Tier 2". On
re-examination, the decision can and should be deferred
until after the main refactor lands. Rationale:

- `BeatRequest.Gossip` is already `json.RawMessage`;
  transport has zero typed dependency on gossip.
- Gossip code is fully contained in tdns-mp today
  (`gossip.go`, `gossip_types.go`, `provider_groups.go`,
  assembly at `hsync_transport.go`).
- Phase 2 renames the wire field `Gossip` → `AppData`.
  This rename is wire-compatible (same bytes; `json.RawMessage`
  either way) and correct for both placements.
- Tier 2 gossip in transport is a valid future state;
  moving later costs: extract types, register merge
  callback, move piggyback assembly. No wire break, no
  deployed-agent impact.
- The plan's own Risks section already commits to this
  property (lines ~1146–1150).

**New default:** gossip stays in MP indefinitely. Phase 2
introduces `AppData json.RawMessage` as the generic hook.
If a second application emerges that needs gossip, the
Tier 2 extraction becomes a focused follow-up project;
otherwise the status quo is not tech debt, it is the
Tier 2 opt-in model working as designed.

Provider groups, leader elections, OPERATIONAL detection
stay in MP (unchanged).

**OQ2 (scope) — RESOLVED: first-class but minimal.**
Scope is an opaque string with exactly two transport
affordances:
1. The authorization callback receives `(peerID, scope)`
2. Optional per-scope handler registration, with fallback
   to a global default handler

The application can register dedicated handlers for some
scopes and let the default handler deal with the rest. No
scope-to-peer indexing, no scope-aware discovery, no
wire-level filtering by scope. Transport never compares two
scopes for anything except equality.

**OQ3 (QNAME format) — RESOLVED: keep current structure.**
QNAME format is a transport concern; the application should
not see it. Current `{distID}.{sender}` (Phase 1) and
`{receiver}.{distID}.{sender}` ± `{chunknum}` (Phase 2 query)
fits DNS limits with comfortable margin. Two implicit
contracts should be documented in Phase 4:
- `distributionID` is transport-generated and opaque to the
  app; the app neither sets nor reads it
- `sender` must be the peer's transport identity (the same
  string used as the PeerRegistry key)

Multi-app coexistence on a single identity is a discovery
limitation, not a QNAME issue. If ever needed, the extension
point is a new SVCB SvcParamKey, not the QNAME structure.

**OQ4 (hello content) — RESOLVED: app-name + version +
opaque app data.**

```go
type HelloRequest struct {
    SenderID   string
    AppName    string          // e.g. "tdns-mp-agent"
    AppVersion string          // recommended (cheap, future-proof)
    Mechanisms []string        // transport: "DNS", "API"
    Scopes     []string        // generic; MP fills with zones
    AppData    json.RawMessage // opaque app-specific content
}
```

Transport-level capability negotiation (mechanisms, crypto)
stays in transport. App-specific content goes in `AppData`.
`Scopes` is the generic replacement for `SharedZones` and
pairs with the scope decision: the app's hello handler can
do LEGACY-agent rejection (empty scope intersection → refuse
hello) instead of waiting until `HandleSync`.

**Disposition Item 1 — RESOLVED: single MPMessageDispatcher
across all roles.** All three roles (agent, combiner, signer)
should be as equal as possible regarding transport
capabilities. One dispatcher with role differences expressed
as which message types each role registers handlers for.

**Disposition Item 2 — RESOLVED: DnskeyPropagationTracker as
a separate struct.** Owned by `SynchedDataEngine` as a
field, but distinct for testability and clean wiring as a
confirmation observer.

**Disposition Item 3 — RESOLVED: RFITracker generalized to
all four RFI subtypes** (KEYSTATE, EDITS, CONFIG, AUDIT).
One struct, one keyed map.

**Disposition Item 4 — RESOLVED: confirmation observer
pattern.** TM exposes
`OnConfirmationReceived(callback func(*ConfirmationEvent))`.
The RMQ's `sendFunc` becomes fully generic — just
`tm.Send(ctx, msg.PeerID, msg.Payload)`. MP wires three
observers at startup:

1. `MPMessageDispatcher` — unwraps the app payload and
   pushes to `msgQs.Confirmation` (for SDE consumption)
2. `DnskeyPropagationTracker` — DNSKEY-specific accounting,
   fires KEYSTATE to signer when all agents confirm
3. RMQ-internal `MarkConfirmed` (already in TM, stops
   retries)

Both inline-response and async-NOTIFY confirmation paths
flow through the same callback chain. New observers (audit
log, metrics) can be added without touching TM or RMQ.

**Gossip cell identity — RESOLVED: set-derived, not
app-named.** Group ID is a stable hash of the sorted member
set. Same members → same group, automatically deduped by
transport. API:

```go
tm.GetOrCreateGossipGroup(members []peerID, mergeFn) *GossipGroup
```

Refcounted: identical registrations return the same handle
with refcount incremented; `Release()` decrements; group is
GC'd at zero. Rationale: app-named groups create a serious
failure mode where N zones with the same agents accidentally
produce N parallel cells (think: agents sharing 10,000 zones
among the same set). Set-derived identity prevents this by
construction.

### Open Issues (must be resolved before Phase 1)

**G. Gossip details — CLOSED 2026-04-16 (deferred with OQ1).**
All six subquestions (membership change semantics, cell
size limits, discovery interaction, beat assembly rules,
per-(group, peer) state, default merge helper) become
implementation details of a future Tier 2 gossip extraction
*if and when* that work happens. They do not block any
phase of this refactor. The `GetOrCreateGossipGroup` API
sketch is parked for that future session; current MP code
remains authoritative. No further resolution required here.

**H. Phase 2 type migration map.** Every JSON field in
every moved type must be enumerated with destination
package and field tag preserved verbatim. ~25
wire-format-critical fields across `DnsSyncPayload`,
`DnsBeatPayload`, `DnsKeystatePayload`, `DnsConfirmPayload`,
etc. Phase 2 must not start without this map written down.

**I. Phase 4 chunk_notify_handler split — concrete cut
line.** Crypto, parse, and authz are interleaved in the
current 580-line file. The encrypted blob is opaque until
decrypted, so the split is non-trivial. Need a written
sequence: (1) receive NOTIFY, (2) extract sender from
QNAME, (3) pre-crypto authz on sender, (4) reassemble
chunks, (5) decrypt, (6) callback to app with raw payload.
Decide where post-crypto/scope authz happens (transport or
app callback).

**J. Phase 6 IMR dependency audit — CLOSED 2026-04-23.**
The premise that IMR might drag MP coupling into transport
was wrong. IMR is a pure `tdns/v2` component; verified
imports are `tdns/v2/cache`, `tdns/v2/core`, `tdns/v2/edns0`
and external libs only. Zero references to tdns-mp or
tdns-transport.

The `tdns/v2/core` imports are not a coupling problem.
Custom RRtypes registered there (CHUNK, JWK, etc.) are
opaque payload to IMR; it does no type-specific
processing. The types are just DNS records.

**Decision: alternative (b) via struct embedding, not
interface.** IMR stays in `tdns/v2`. Transport defines:

```go
// tdns-transport/v2/transport/imr.go
type Imr struct {
    *tdns.Imr  // embedded, not composed through an interface
}
```

Rationale for embedding over interface:
- Embedded types allow adding new receiver functions on
  `transport.Imr` later without touching `tdns.Imr`
- All current IMR methods promote through the embed with
  zero boilerplate
- If transport ever needs an IMR method that tdns doesn't
  have, define it on `transport.Imr` directly
- An interface would fix the method set at the boundary
  and require updates in lockstep

Phase 6 work under this resolution: instantiate a
`transport.Imr` wrapper, use it for discovery lookups.
Nothing moves out of `tdns/v2`; nothing changes in IMR.

**K. Tests for the transport boundary — CLOSED 2026-04-30.**
Harness implemented at
`tdns-mp/v2/transport_harness_test.go` +
`tdns-mp/v2/transport_integ_test.go`. All seven
`TestTransportBoundary_*` scenarios pass:
- ChunkToMsg
- HelloRejection
- SyncFallback
- ConfirmInlineResponsePrep
- ConfirmAsyncToChannel
- LegacySyncRejection
- DiscoveryComplete

Phase 0 exit gate satisfied. Phase 1+ unblocked.

Without this safety net, a 9-phase refactor of this scope
is a serious gamble.

**L. Phase 1 PeerRegistry shim specification.** Phase 1
adds per-mechanism state and removes
`ZoneRelation`/`SharedZones`. Both transport (~25
references) and tdns-mp (5+ `SyncPeerFromAgent` call sites)
break simultaneously without a deliberate compatibility
shim. Specify which old fields stay as deprecated
accessors, for how long, and the deletion phase.

**M. Destination package for moved MP types — CLOSED
2026-04-23.** Inline in `tdns-mp/v2/`. No subpackage. See
Appendix H.

**N. Rollback / abort criteria per phase.** No phase has
explicit "if X breaks, revert and reconsider" criteria.
For a refactor of this scope, define abort gates.

**O. Disposition table walk-through (added 2026-04-16).**
`hsync_transport.go` has grown from 48 to 54
methods/functions since the table was written. Before
Phase 1 begins, walk the current file and place the 6+ new
methods into the disposition table with a phase
assignment. Spot-check that phase dependencies are still
correct (Phase 1 → 3 → 5 → 7 chain).

### MPTransportBridge Disposition Table

Categorization of the methods/functions in
`hsync_transport.go` and their migration targets.

**2026-04-16 count update:** current grep shows **54**
methods/functions (up from 48 in the original table).
The 6-method delta likely reflects helpers added during
HSYNC3, SIG(0) publication, and gossip work since the
table was first written. A walk-through to place the new
methods is a pre-Phase-1 task (see open item **O** below).

New MP-side homes introduced by this refactor:

- **`MPMessageDispatcher`** — owns the `route*Message`
  family, registered with TM as default handler + per-type
  handlers
- **`DnskeyPropagationTracker`** — DNSKEY confirmation
  fan-in, KEYSTATE-to-signer signaling
- **`RFITracker`** — RFI request-response channel registry,
  generalized over all four RFI subtypes
- **`Agent.PeerID`** — string field linking Agent to its
  PeerRegistry entry; replaces `SyncPeerFromAgent`

| # | Method | Destination | Phase |
|---|---|---|---|
| **A. Thin wrappers** | | | |
| 1 | `isTransportSupported` | TM (private) | 5 |
| 2 | `SelectTransport` | TM (private, used by `Send`) | 5 |
| 3 | `HasDNSTransport` / `HasAPITransport` | `Peer.HasMechanism()` | 1 |
| 4 | `GetQueueStats` / `GetQueuePendingMessages` | TM (drop wrapper) | 5 |
| **B. Send / fallback** | | | |
| 5 | `SendSyncWithFallback` | TM `Send(ctx, peerID, msg)` | 5 |
| 6 | `SendHelloWithFallback` | TM `Hello(...)` + per-mechanism middleware | 5 |
| 7 | `SendBeatWithFallback` | TM `Beat(...)` + gossip plumbing | 5 |
| 8 | `SendPing` | TM `Ping(...)` (drop duplicate) | 5 |
| **C. AgentRegistry ↔ PeerRegistry sync** | | | |
| 9 | `SyncPeerFromAgent` | **DELETED** (Agent gets `PeerID`) | 7 |
| 10 | `agentStateToTransportState` | **DELETED** | 7 |
| 11 | `OnAgentDiscoveryComplete` | MP `OnPeerDiscovered` callback on TM | 6 |
| **D. Routing (route*Message family)** | | | |
| 12 | `RegisterChunkNotifyHandler` | TM startup (private) | 5 |
| 13 | `StartIncomingMessageRouter` | TM startup (private) | 5 |
| 14 | `routeIncomingMessage` | `MPMessageDispatcher.Dispatch` | 3 + 7 |
| 15 | `routeHelloMessage` | `MPMessageDispatcher` | 3 |
| 16 | `routeBeatMessage` | `MPMessageDispatcher`; liveness → TM middleware | 3, 5 |
| 17 | `routePingMessage` | `MPMessageDispatcher`; liveness → TM middleware | 3, 5 |
| 18 | `routeSyncMessage` | `MPMessageDispatcher` | 3 |
| 19 | `routeKeystateMessage` | `MPMessageDispatcher` (uses `RFITracker`) | 3 |
| 20 | `routeEditsMessage` | `MPMessageDispatcher` | 3 |
| 21 | `routeConfigMessage` | `MPMessageDispatcher` | 3 |
| 22 | `routeAuditMessage` | `MPMessageDispatcher` | 3 |
| 23 | `routeStatusUpdateMessage` | `MPMessageDispatcher` | 3 |
| 24 | `routeRelocateMessage` | `MPMessageDispatcher` | 3 |
| **E. Confirmations** | | | |
| 25 | `sendSyncConfirmation` | `MPMessageDispatcher` (private) | 3 |
| 26 | `sendImmediateConfirmation` | `MPMessageDispatcher` (private) | 3 |
| 27 | `sendRemoteConfirmation` | `SynchedDataEngine` (consumer of `OnRemoteConfirmationReady`) | 3 |
| 28 | `MarkDeliveryConfirmed` | TM (drop wrapper) | 5 |
| **F. DNSKEY propagation** | | | |
| 29 | `TrackDnskeyPropagation` | `DnskeyPropagationTracker.Track` | 7 |
| 30 | `ProcessDnskeyConfirmation` | `DnskeyPropagationTracker.OnConfirmation` (TM observer) | 7 |
| 31 | `sendKeystateToSigner` | `DnskeyPropagationTracker` (uses TM `Send`) | 7 |
| **G. Keystate / RFI request-response** | | | |
| 32 | `set/get/deleteKeystateRfi` | `RFITracker` | 7 |
| 33 | `sendRfiToSigner` | `HsyncEngine` (uses TM `Send`) | 7 |
| **H. Cross-role helpers** | | | |
| 34 | `sendConfigToAgent` | `Combiner` (uses TM `Send`) | 7 |
| 35 | `sendAuditToAgent` | `Combiner` (uses TM `Send`) | 7 |
| **I. Registry / lookup** | | | |
| 36 | `getCombinerID` | `AgentRegistry` (or config accessor) | 7 |
| 37 | `getAllAgentsForZone` | `AgentRegistry` (drop wrapper) | 7 |
| 38 | `GetDistributionRecipients` | `SynchedDataEngine` helper | 7 |
| 39 | `GetPreferredTransportName` | `Peer.PreferredMechanism()` | 1 |
| **J. Reliable queue integration** | | | |
| 40 | `StartReliableQueue` | TM startup (private) | 5 |
| 41 | `deliverGenericMessage` | TM-internal `sendFunc` (fully generic) | 5 |
| 42 | `EnqueueForCombiner` | `SynchedDataEngine.EnqueueForCombiner` | 7 |
| 43 | `EnqueueForZoneAgents` | `SynchedDataEngine.EnqueueForZoneAgents` | 7 |
| 44 | `EnqueueForSpecificAgent` | `SynchedDataEngine.EnqueueForAgent` | 7 |
| **K. Construction & utility** | | | |
| 45 | `NewMPTransportBridge` | **DELETED**; MP wires TM + components directly | 7 |
| 46 | `generatePingNonce` | TM (private, with `Ping`) | 5 |
| 47 | `parseHostPort` | MP utility | 7 |
| 48 | `groupRRStringsByOwner` | **DELETED** (unused — verify first) | 7 |

**Phase load** (2026-04-16: expect +6 methods once item O
walk-through completes; load per phase may shift slightly):
- Phase 0: 0 methods (pure test harness)
- Phase 1: 2 methods (per-mechanism state on Peer)
- Phase 3: 14 methods (route* family + confirmation senders)
- Phase 5: 13 methods (send/fallback, queue lifecycle, middleware)
- Phase 6: 1 method (discovery callback)
- Phase 7: 18+ methods (bridge deletion, state-sync removal,
  helpers, DNSKEY, RFI, MP-side rehoming)

Phase 7 carries the largest load and decomposes into 8
substeps (revised 2026-04-16; Agent.PeerID is now its own
explicit gate step):

1. **Add `Agent.PeerID string` field.** Pure addition. No
   call-site changes yet. Set it from existing identity
   on Agent construction.
2. **Migrate the 11 `SyncPeerFromAgent` call sites** to
   read transport state via `peerRegistry.Get(agent.PeerID)`.
   Leave the function defined but unused.
3. **Delete `SyncPeerFromAgent` and
   `agentStateToTransportState`** (#9, #10). Both must be
   uncalled by this point.
4. Migrate the remaining `route*` family finalization
   (#27). Most landed in Phase 3.
5. Create `DnskeyPropagationTracker` (#29–31).
6. Create `RFITracker` (#32, #33).
7. Move enqueue helpers into `SynchedDataEngine` (#42–44).
8. Delete `NewMPTransportBridge`; rewire startup (#45);
   update MP config to hold `*transport.TransportManager`
   directly.

Each substep leaves the tree building. Substeps 1–3 are
the dependency unlock for the rest — they eliminate the
AgentRegistry/PeerRegistry state coupling.

## Quick Wins (bite-size isolated parts)

**2026-04-16 revision:** former "Bite 2" (integration
tests) is now **Phase 0** — mandatory pre-work, not
optional. The remaining two (Bite 1 and Bite 3) are still
bite-sized and can land independently. They appear below
in recommended order.

> **2026-04-25:** The three Quick Wins below have been
> superseded by the full early-bites plan in
> [2026-04-25-transport-refactor-early-bites.md](./2026-04-25-transport-refactor-early-bites.md),
> which adds five further bites (4–8) targeting the
> dual-registry / discovery problem. Treat that doc as
> authoritative for execution; the text below remains for
> historical context only.

### Bite 1: Additive Peer enhancements (Phase 1 subset)

**What:** The additive parts of Phase 1 only. Add the new
per-mechanism state to `Peer` alongside the existing
fields, without removing anything yet.

**Revision 2026-04-16:** Bite 1 must include the dual-write
plumbing in handlers.go (step 4 below). Landing the struct
alone would leave `Peer.Mechanisms` as dead code until
Phase 7. Either do Bite 1 fully or defer it.

**Concrete steps:**

1. In `tdns-transport/v2/transport/peer.go`, add the
   `MechanismState` struct:
   ```go
   type MechanismState struct {
       State            PeerState
       StateReason      string
       StateChanged     time.Time
       Address          *Address
       LastHelloSent    time.Time
       LastHelloRecv    time.Time
       LastBeatSent     time.Time
       LastBeatRecv     time.Time
       BeatSequence     uint64
       ConsecutiveFails int
       Stats            MessageStats
   }
   ```
2. Add `Mechanisms map[string]*MechanismState` to `Peer`
   alongside the existing single-state fields. Keys:
   `"API"`, `"DNS"`.
3. Add methods on `Peer`:
   - `EffectiveState() PeerState` — returns the best
     state across all mechanisms (same semantics as
     `Agent.EffectiveState()` today)
   - `HasMechanism(name string) bool`
   - `PreferredMechanism() string` — returns `"API"`,
     `"DNS"`, or `""` based on mechanism availability and
     health
   - `SetMechanismState(name string, state PeerState, reason string)`
4. In the code paths that currently update the
   single-state fields (hello/beat receipt, discovery
   completion, etc.), *also* update the corresponding
   `MechanismState`. Dual-write for now.
5. In tdns-mp, rewrite three disposition-table wrappers
   to read from the new fields — they collapse to
   one-liners:
   - `HasDNSTransport(agent)` →
     `agent.peer().HasMechanism("DNS")`
   - `HasAPITransport(agent)` →
     `agent.peer().HasMechanism("API")`
   - `GetPreferredTransportName(agent)` →
     `agent.peer().PreferredMechanism()`
   (Keep the old wrappers in place; just switch their
   implementation. Call-site migration comes later.)

**Do NOT:**
- Remove `ZoneRelation` or `SharedZones` — they stay as
  the primary source of truth for scope/zone tracking
  until the bigger refactor moves scope handling.
- Remove the single `Peer.State` field — keep it in sync
  with `EffectiveState()` via dual-write.
- Delete `SyncPeerFromAgent` or any call site — still
  needed.

**Files touched:**
- `tdns-transport/v2/transport/peer.go` (primary)
- `tdns-transport/v2/transport/handlers.go` (dual-write
  on hello/beat receipt — small edits only)
- `tdns-mp/v2/hsync_transport.go` (the three wrapper
  bodies change, signatures stay)

**Why it's safe:** Zero wire-format change, zero public
API break. Everything new is additive. The existing code
paths are untouched except for adding parallel writes.
If something goes wrong, the old fields still carry the
canonical state.

**Value delivered:** Three disposition-table items land
(#3, #39 × 2). More importantly, the future Phase 1
"remove the old fields" step becomes a pure deletion —
all the replacement plumbing is already in place.

**Estimated cost:** 1–2 days (includes dual-write plumbing
in handlers.go).

---

### Bite 2 → Phase 0: Transport-boundary integration tests

**Status 2026-04-16: PROMOTED to mandatory Phase 0.** See
the Implementation Plan section below. The content below
is retained for historical context; the authoritative
version is Phase 0.

**What:** Integration test coverage for the transport
boundary in tdns-mp. Currently zero. This is the single
highest-ROI item — it catches regressions in the meantime
AND becomes the safety net when the bigger refactor
resumes.

**Test scenarios to cover (minimum viable):** (seven;
implementation detail:
[2026-04-23-transport-boundary-test-harness.md](./2026-04-23-transport-boundary-test-harness.md))

1. **CHUNK NOTIFY round trip.** Two agents, one sends a
   sync, the other receives it. Assert the message
   appears on `msgQs.Msg` with the expected payload,
   sender, zone, message type.
2. **SYNC with API→DNS fallback.** Agent with both
   transports configured. Kill the API endpoint mid-test.
   Assert the sync lands on the receiver via DNS. Assert
   the fallback is observable (peer stats or log).
3. **Confirmation routing, inline path.** Send a sync
   where the receiver returns immediate confirmation.
   Assert `msgQs.Confirmation` fires with the expected
   distribution ID and status.
4. **Confirmation routing, async NOTIFY path.** Send a
   sync that produces a pending response. Receiver sends
   a separate NOTIFY confirmation later. Assert the same
   confirmation arrives via `msgQs.Confirmation`.
5. **LEGACY / zero-scope sync rejection.** Peer with empty
   `SharedZones` attempts to send a sync. Assert
   `HandleSync` rejects it with the expected error.
6. **Hello rejection (HSYNC / zone policy).** Exercise
   `EvaluateHello` (or equivalent HTTP surface) with a
   hello that must be refused (e.g. remote identity absent
   from HSYNC3 RRset). Assert rejection with stable reason.
   See harness doc scenario 6.
7. **Discovery completion path.** Register an agent in
   NEEDED state. Simulate discovery completion. Assert
   the peer transitions to KNOWN and
   `OnAgentDiscoveryComplete` fires.

**Where tests live:** New package, e.g.
`tdns-mp/v2/transport_integration_test.go`, or a
`tdns-mp/v2/integration/` subdirectory if the project
prefers isolation.

**Infrastructure to build (if not already present):**
- Test harness that spins up two in-process
  TransportManagers with a shared in-memory DNS
  implementation (or loopback UDP on random ports)
- Fake `AgentRegistry` + `MsgQs` for the receiving side
- Helper to construct a minimal `MPTransportBridge` for
  each agent
- Assertions helper for reading from `msgQs.*` channels
  with timeout

**Why it's safe:** Tests only add. No production code
changes. The infrastructure investment (harness, fakes)
is reusable for the eventual refactor.

**Value delivered:** Regression safety net covering the
current behavior. Every subsequent refactor phase can
run these tests and gain confidence.

**Estimated cost:** 2–3 days, most of which is building
the harness. If the project already has any multi-agent
test fixtures, this drops significantly.

**Risk:** The one real risk is that building the harness
surfaces bugs in the current code (tests exposing
existing flaws). That is ultimately a feature, not a
bug, but plan for the possibility.

---

### Bite 3: Unified `TM.Send` shim (Phase 5 subset)

**What:** Introduce a single generic send method on
TransportManager that subsumes the three
`SendXWithFallback` variants. Existing methods become
thin deprecation shims; call-site migration is
opportunistic.

**Concrete steps:**

1. In `tdns-transport/v2/transport/manager.go`, add:
   ```go
   // Send delivers a message to peerID using the best
   // available mechanism, falling back to alternatives
   // on failure. Message type is determined by the
   // payload concrete type (or an explicit type field).
   func (tm *TransportManager) Send(
       ctx context.Context,
       peerID string,
       msg interface{},
   ) (interface{}, error)
   ```
   Implementation: look up peer, call `SelectTransport`
   internally, invoke the right method on the chosen
   transport, fall back to the other on error.
2. Rewrite `MPTransportBridge.SendSyncWithFallback` body
   to delegate to `tm.Send`. Keep the signature
   identical — it's now a thin adapter.
3. Same for `SendHelloWithFallback` and
   `SendBeatWithFallback`.
4. Delete the duplicate `SendPing` implementation in
   `MPTransportBridge`; callers use `tm.Send` or
   `tm.Ping` directly.
5. Optional: migrate 2–3 call sites to use `tm.Send`
   directly as a pilot. Leave the rest for later.

**Do NOT:**
- Change any method signatures on the bridge wrappers.
- Touch wire format or message structs.
- Delete the wrapper methods — they stay as shims so
  existing call sites don't break.
- Move any types between packages.

**Files touched:**
- `tdns-transport/v2/transport/manager.go` (new `Send`
  method)
- `tdns-mp/v2/hsync_transport.go` (rewrite 4 method
  bodies as delegations)

**Why it's safe:** Pure internal refactor. All public
APIs unchanged. All call sites continue to work.
Fallback behavior is preserved (the new `Send` does the
same thing the wrappers did, just in one place).

**Value delivered:** One place for fallback logic instead
of three. Phase 5 of the full refactor becomes much
smaller. Sets up the eventual per-mechanism fallback
routing (once Bite 1 lands, `Send` can consult
`MechanismState` for smarter selection).

**Estimated cost:** ~1 day.

**Dependency on Bite 1:** None required. `Send` works
with the current single-state model. If Bite 1 has
already landed, `Send` can optionally read per-mechanism
health; if not, it uses the existing logic.

---

### Recommended order (revised 2026-04-16)

1. **Phase 0** (formerly Bite 2) — integration test
   harness. Mandatory. Nothing else begins until this
   lands.
2. **Bite 1** — additive Peer enhancements with
   dual-write. Small, clean, sets up Phase 1.
3. **Bite 3** — unified send. Optional ergonomic
   improvement; can land before or after Phase 1
   begins.

Phase 0 is now a gate. Bites 1 and 3 remain independent
opportunistic improvements.

## Current State: What's Wrong

### A. App concepts in tdns-transport (must move OUT)

These types and concepts in tdns-transport encode MP/DNS
application knowledge and must move to tdns-mp:

#### A1. DNS record type enum (transport.go)
```go
// REMOVE from transport
type SyncType uint8
const (
    SyncTypeNS     SyncType = iota + 1
    SyncTypeDNSKEY
    SyncTypeGLUE
    SyncTypeCDS
    SyncTypeCSYNC
)
```
Transport should not enumerate what kinds of data are being
synchronized. Application defines its own sync types.

#### A2. MP protocol message types (transport.go)
These request/response types encode HSYNC protocol knowledge:
- `KeystateRequest/Response` — DNSKEY lifecycle signaling
- `EditsRequest/Response` — combiner contributions
- `ConfigRequest/Response` — RFI CONFIG with subtypes
  "upstream", "downstream", "sig0key"
- `AuditRequest/Response` — zone data snapshots
- `KeyInventoryEntry` — DNSKEY inventory with states
  "published", "active", "retired", "foreign"
- `RejectedItemDTO` — "RR rejected by combiner"

These are all HSYNC/MP protocol types. They belong in tdns-mp.

#### A3. MP fields on generic messages (transport.go)
- `SyncRequest.Publish` (*core.PublishInstruction) —
  combiner-specific
- `SyncRequest.RfiType`, `RfiSubtype` — RFI protocol
- `SyncRequest.MessageType` ("sync", "update", "rfi") —
  HSYNC protocol verbs
- `BeatRequest.Gossip` — MP coordination data

These fields must be removed from transport-level types.
Application data rides in a generic `AppData` or `Payload`
field.

#### A4. ZoneRelation on Peer (peer.go)
```go
// REMOVE from transport
type ZoneRelation struct {
    Zone        string
    Role        string    // "primary", "secondary", "multi-signer"
    PeerRole    string
    LastSync    time.Time
    SyncSerial  uint32
    SyncPending bool
}
```
And `Peer.SharedZones`, `PeerRegistry.ByZone()`. These are
DNS zone concepts. Transport tracks peers, not zones.

The application maintains its own scope-to-peer mappings.

#### A5. Role-specific router initialization (router_init.go)
- `CombinerRouterConfig` struct
- `SignerRouterConfig` struct
- `InitializeCombinerRouter()` function
- `InitializeSignerRouter()` function

These encode MP roles directly in transport. Only the generic
`RouterConfig` and `InitializeRouter()` should exist.
Applications register their own handlers.

#### A6. MP message handlers (handlers.go)
These handlers process MP-specific message types:
- `HandleSync`, `HandleRfi`, `HandleKeystate`,
  `HandleEdits`, `HandleConfig`, `HandleAudit`,
  `HandleStatusUpdate`, `HandleRelocate`

Transport should only provide handlers for its own messages:
hello, beat, ping, confirm. All other handlers are
application-provided.

#### A7. DNS payload types (dns.go)
13 exported `Dns*Payload` types (count corrected
2026-04-16 — down from 18 originally, some consolidated
during migration) are DNS wire format helpers that should
be internal (unexported) or moved to the application. Most
contain MP-specific fields (OriginatorID, MessageType,
Zone, Nonce).

#### A8. chunk_notify_handler.go — MP protocol handler
This file does far more than CHUNK reassembly:
- Parses QNAME to extract agent identity
- Parses JSON payload to extract zone, message type,
  originator
- Does zone-peer authorization
- Routes to "hsyncengine"
- Understands beat/sync/update message types

Must be split into:
- Generic CHUNK reassembly + decryption (stays in transport)
- MP message parsing + routing (moves to tdns-mp)

#### A9. Heavy core package coupling
Transport imports 15+ types from `tdns/v2/core`:
`AgentHelloPost`, `AgentBeatPost`, `AgentMsgPost`,
`AgentKeystatePost`, `AgentEditsPost`, `PublishInstruction`,
`RROperation`, `StatusUpdatePost`, `KeyInventoryEntry`, etc.

After cleanup, transport should import only truly shared
types: `CHUNK`, `TypeCHUNK`, format constants, and
possibly `RROperation` if it's generic enough.

### B. Transport stuff in tdns-mp (must move IN)

These operations in MPTransportBridge are generic transport
concerns and should move into TransportManager:

#### B1. Peer discovery
The entire peer discovery pipeline — from identity string
to validated contact information — is a transport concern.
Every application using tdns-transport needs to answer
"how do I reach peer X?". Forcing each app to implement
this complex infrastructure (DNS lookups for URI, SVCB,
TLSA, JWK records; DANE validation; address extraction;
key verification) would dramatically reduce the value of
tdns-transport as a reusable library.

Today this lives in tdns-mp: `DiscoverAndRegisterAgent`,
IMR-based DNS lookups, discovery retry with backoff. It
should move to transport.

**Transport owns:**
- Discovery mechanics: given an identity, look up contact
  info (addresses, ports, JOSE keys, TLSA records)
- Validating contact info (DANE, key verification)
- Populating the Peer in PeerRegistry with results
- State transitions: NEEDED → DISCOVERING → KNOWN
- Discovery retry with backoff on failure
- IMR (Iterative Message Resolution) engine — the DNS
  lookup machinery that resolves identities to contact
  records

**Application owns:**
- Deciding which peers are needed (registers them as
  NEEDED in PeerRegistry)
- Reacting to discovery completion via callback
  `OnPeerDiscovered(peer)` (e.g. "peer is KNOWN, now
  send hello with my zone list")
- Any app-specific metadata interpretation

**Interface:**
- App calls `tm.DiscoverPeer(identity)` explicitly, or
  adds a peer in NEEDED state and transport's discovery
  loop picks it up automatically
- Transport calls `OnPeerDiscovered(peer)` when discovery
  completes successfully
- Transport calls `OnDiscoveryFailed(peerID, err)` on
  permanent failure (after retries exhausted)

#### B2. Transport selection and fallback
- `SelectTransport(peer)` — choose API vs DNS
- `SendSyncWithFallback()` — try preferred, fall back
- `SendHelloWithFallback()` — same pattern
- `SendBeatWithFallback()` — same pattern

Transport owns the mechanism; it should handle fallback.
The application says "send this to peer X", transport
decides how.

#### B3. Lifecycle management
- `RegisterChunkNotifyHandler()` — wiring transport
  components
- `StartIncomingMessageRouter()` — starting the router
- `isTransportSupported()` — config checking

These are internal transport lifecycle operations.

#### B4. Pure transport operations
- `SendPing()` — already partly in TM, but MPTransportBridge
  adds its own version

#### B5. Peer state from message events
Combiner and signer message handlers directly manipulate
PeerRegistry on beat/hello received. This should be
transport-level middleware or callbacks — when transport
delivers a beat, it updates peer liveness automatically.

### C. Dual registry problem

PeerRegistry (transport) and AgentRegistry (tdns-mp) track
overlapping state with manual synchronization:

| Field | PeerRegistry | AgentRegistry |
|-------|-------------|---------------|
| Identity | ID | Identity |
| State | PeerState (1) | AgentState (per-transport) |
| Addresses | DiscoveryAddr, APIEndpoint | ApiDetails.Addrs, DnsDetails.Addrs |
| Crypto | LongTermPubKey | JWKData, KeyRR, TlsaRR |
| Liveness | LastBeatSent/Received | LatestSBeat/RBeat per transport |
| Zones | SharedZones | Zones |
| Transport | PreferredTransport | ApiMethod, DnsMethod |

Kept in sync via `SyncPeerFromAgent()` and
`agentStateToTransportState()`. Every beat and hello updates
both registries. This is fragile and redundant.

### C1. Resolution: single source of truth per concern

**PeerRegistry (transport)** becomes the sole owner of:
- Identity, addresses, crypto keys
- Per-mechanism state (enhance Peer to track API and DNS
  state independently, like Agent does today)
- Liveness (beat/hello timestamps, per mechanism)
- Transport selection (preferred mechanism, fallback)
- Message statistics

**AgentRegistry (tdns-mp)** becomes MP-only metadata:
- Which zones/scopes this agent participates in
- MP-specific discovery records (URI, SVCB for discovery
  process itself)
- Per-zone roles
- LEGACY state (agent with no active zones)
- Deferred tasks
- Provider group membership, leader election state

**Coupling**: Agent has a `PeerID string` field. When MP
needs transport state, it calls
`peerRegistry.Get(agent.PeerID)`. Transport never knows
Agents exist. No embedding — loose coupling via ID.

### C2. Per-mechanism state on Peer

Today Peer has a single state. Agent tracks API and DNS
independently. The right answer is to enhance Peer:

```go
type Peer struct {
    ID          string
    Mechanisms  map[string]*MechanismState  // "API", "DNS"
    // ...
}

type MechanismState struct {
    State           PeerState
    StateReason     string
    StateChanged    time.Time
    Address         *Address
    LastHelloSent   time.Time
    LastHelloRecv   time.Time
    LastBeatSent    time.Time
    LastBeatRecv    time.Time
    BeatSequence    uint64
    ConsecutiveFails int
    Stats           MessageStats
}
```

Transport selects mechanism based on per-mechanism health.
Peer-level `GetState()` returns the best of all mechanisms
(like Agent.EffectiveState() does today).

## Implementation Plan

### Phase 0: Transport-boundary integration test harness

**Added 2026-04-16. DONE 2026-04-27.** All seven scenarios
implemented at `tdns-mp/v2/transport_harness_test.go` +
`tdns-mp/v2/transport_integ_test.go`. The text below is
retained for historical context.

**Goal**: establish a regression safety net before touching
any production code. The original "Bite 2" was listed as
optional; re-evaluation flagged that as a mistake — a
9-phase refactor across three repos without integration
tests is a gamble.

**Test scenarios (minimum viable):** seven; see
[2026-04-23-transport-boundary-test-harness.md](./2026-04-23-transport-boundary-test-harness.md).
1. CHUNK NOTIFY round trip (two in-process TMs, sync
   delivered to `msgQs.Msg`)
2. SYNC with API→DNS fallback (kill API mid-test, assert
   receiver gets it via DNS, observable in peer stats)
3. Confirmation routing, inline path
4. Confirmation routing, async NOTIFY path
5. LEGACY / zero-scope sync rejection (`HandleSync`, empty
   `SharedZones`)
6. Hello rejection (`EvaluateHello` / HSYNC3 policy)
7. Discovery completion path (NEEDED → KNOWN transition,
   `OnAgentDiscoveryComplete` fires)

**Deliverables:**
- Implementation specification and per-scenario detail:
  [2026-04-23-transport-boundary-test-harness.md](./2026-04-23-transport-boundary-test-harness.md)
- Test harness spinning up two in-process
  TransportManagers with shared in-memory DNS (or loopback
  UDP on random ports)
- Fake `AgentRegistry` + `MsgQs` for the receiving side
- Helper to construct a minimal `MPTransportBridge` for
  each agent
- Assertions helper for reading from `msgQs.*` channels
  with timeout
- Location: `tdns-mp/v2/transport_integration_test.go` or
  `tdns-mp/v2/integration/` subdirectory

**Estimated cost:** 2–3 days, most of which is harness
construction. Surfaced bugs in current code are a feature,
not a regression.

**Exit gate:** all **7** scenarios passing on CI (harness
spec:
[2026-04-23-transport-boundary-test-harness.md](./2026-04-23-transport-boundary-test-harness.md)).
Open item **K** is satisfied at this gate. Phase 1 is
unblocked.

### Phase 1: Enhance PeerRegistry (transport-only changes)

**Goal**: Make PeerRegistry capable of replacing
AgentRegistry's transport-related tracking.

**Status 2026-04-30: steps 1–4 DONE via Bites 1 + 7.**
`MechanismState` struct, `Peer.Mechanisms` map, and the
four accessors (`EffectiveState`, `HasMechanism`,
`PreferredMechanism`, `SetMechanismState`) all live in
`tdns-transport/v2/transport/peer.go`. Dual-write is
active across all hello/beat/ping receipt sites in
tdns-mp; `Peer.PopulateFromAgent` mirrors per-mechanism
state from `Agent.ApiDetails` / `DnsDetails`. Three
disposition-table wrappers (`HasDNSTransport`,
`HasAPITransport`, `GetPreferredTransportName`) now
delegate to the Peer methods.

Remaining steps (Phase 1 proper):
1. ~~Add `MechanismState` struct and `Peer.Mechanisms` map~~ — DONE
2. ~~Move per-mechanism fields into MechanismState~~ — DONE
3. ~~Add `Peer.EffectiveState()`~~ — DONE
4. ~~Add `Peer.SetMechanismState(...)`~~ — DONE
5. Remove `ZoneRelation` and `SharedZones` from Peer —
   replace with generic `Peer.Scopes map[string]any` or
   remove entirely (let app track scope-to-peer mapping).
   **Still TODO** — Bite 1 explicitly did NOT touch
   these.
6. Drop the now-redundant single-state fields on Peer
   (everything dual-write currently maintains). Pure
   deletion now that `Mechanisms` is the canonical
   source.
7. Ensure PeerRegistry API is stable and sufficient.

Validate: tdns-mp still builds; integration harness's
seven scenarios still pass.

### Phase 2: Strip MP types from transport API

**Goal**: Remove all HSYNC/MP-specific types from the
transport package's public API.

Steps:
1. Remove `SyncType` enum (NS, DNSKEY, GLUE, CDS, CSYNC)
2. Remove `KeystateRequest/Response`,
   `EditsRequest/Response`, `ConfigRequest/Response`,
   `AuditRequest/Response`, `KeyInventoryEntry`
3. Remove MP fields from `SyncRequest` (Publish, RfiType,
   RfiSubtype, MessageType)
4. Replace `BeatRequest.Gossip` with generic `AppData
   json.RawMessage`. This rename is wire-compatible (same
   bytes in the field either way) and correct regardless
   of whether gossip later moves to transport Tier 2 or
   stays in MP indefinitely. MP continues to serialize its
   existing gossip messages into `AppData`.
5. Remove `RejectedItemDTO`
6. Redesign `SyncRequest`/`SyncResponse` as generic payload
   containers:
   ```go
   type SyncRequest struct {
       Scope    string          // app-defined scope
       Payload  json.RawMessage // app-defined content
       Nonce    string
       // transport-level fields only
   }
   ```
7. Move removed types to tdns-mp (they become MP's
   application-level message types)

Validate: tdns-transport builds with no MP imports from core.
tdns-mp builds using its own copies of moved types.

### Phase 3: Clean up handlers and router initialization

**Goal**: Remove role-specific router setup from transport.

Steps:
1. Delete `CombinerRouterConfig`, `SignerRouterConfig`
2. Delete `InitializeCombinerRouter()`,
   `InitializeSignerRouter()`
3. Delete MP-specific handlers from transport: `HandleSync`,
   `HandleRfi`, `HandleKeystate`, `HandleEdits`,
   `HandleConfig`, `HandleAudit`, `HandleStatusUpdate`,
   `HandleRelocate`
4. Keep only: `HandleHello`, `HandleBeat`, `HandlePing`,
   `HandleConfirmation`, `DefaultUnsupportedHandler`
5. Move deleted handlers to tdns-mp — they become
   app-registered handlers
6. Make `MessageType` constants minimal: keep
   `CHUNK_NOTIFY`, `CHUNK_QUERY`, `HELLO`, `BEAT`, `PING`,
   `CONFIRM`. Remove `UPDATE`, `RELOCATE` as pre-defined
   constants (app registers these as needed)

Validate: all three repos build.

### Phase 4: Split chunk_notify_handler

**Goal**: Separate generic CHUNK reassembly from MP message
parsing.

Steps:
1. Extract generic CHUNK handling into a clean handler that:
   - Receives NOTIFY(CHUNK)
   - Reassembles multi-chunk payloads
   - Decrypts if encrypted
   - Calls a callback with (senderID, rawPayload)
   - Sends DNS response
2. Move MP-specific logic to tdns-mp:
   - QNAME parsing for agent identity (or generalize: the
     QNAME format `<distributionID>.<sender>` is arguably
     transport-level addressing)
   - JSON payload parsing for zone/messageType/originator
   - Zone-peer authorization
   - Beat/sync message type dispatch

Validate: a non-MP application can use ChunkNotifyHandler
with its own callback.

### Phase 5: Move transport operations down from tdns-mp

**Goal**: Generic transport operations move from
MPTransportBridge into TransportManager.

**Status 2026-04-30: partially done via Bite 3.**
`TransportManager.Send` exists and dispatches by
type-switch over `*SyncRequest`, `*PingRequest`,
`*RelocateRequest`. `SendSyncWithFallback` is now a thin
delegation. Hello and Beat were intentionally NOT
migrated by Bite 3 because their semantics are
send-on-all-transports-in-parallel, not
primary-then-fallback — Phase 5 still needs to address
that distinct pattern.

Remaining steps:
1. ~~Move `SelectTransport()` into TransportManager~~ — DONE (Bite 3 uses it internally)
2. ~~Implement `SendWithFallback()` for sync~~ — DONE for sync; **TODO for Hello/Beat** under their parallel-send semantics
3. Move lifecycle management (RegisterChunkNotifyHandler,
   StartIncomingMessageRouter) into TM startup
4. Add transport-level middleware that automatically updates
   PeerRegistry liveness on hello/beat receipt (removes
   manual updates from combiner/signer handlers)
5. Remove `SendPing` duplicate from MPTransportBridge —
   Bite 3 explicitly skipped this (small caller surface);
   still TODO

Validate: MPTransportBridge's generic methods are gone.

### Phase 6: Move peer discovery into transport

**Goal**: Peer discovery becomes a transport service. Any
application can resolve a peer identity to validated
contact information without implementing its own discovery.

**Status 2026-04-30:** Phase 6 split into two parts; part
1 (lookup helpers) and the part-2 callback seam are both
DONE.

**Part 1 (mechanics) — DONE via Bites 0 + 6.**
`transport.Imr` lives in `tdns-transport/v2/transport/imr.go`
as `type Imr struct { *tdns.Imr }`. The six lookup helpers
(`LookupAgentJWK`, `LookupAgentKEY`,
`LookupAgentAPIEndpoint`, `LookupAgentDNSEndpoint`,
`LookupAgentTLSA`, `LookupServiceAddresses`) are present
on it. Implemented as **parallel embedding**: tdns-mp's
`tdnsmp.Imr` and its copy of the helpers stay in place;
both wrappers point at the same singleton `*tdns.Imr`
guaranteed by Bite 0's idempotency guard in
`tdns/v2/imrengine.go`. Call-site migration to
`*transport.Imr` is a follow-up.

**Part 2 (orchestration) — seam DONE via Bite 8; body
TODO.** `TransportManager.OnPeerDiscovered func(peerID string)`
exists; tdns-mp wires the existing
`OnAgentDiscoveryComplete` body into it at startup.
Discovery itself (`DiscoverAndRegisterAgent`,
`attemptDiscovery`, `DiscoveryRetrierNG`) still lives in
tdns-mp. When it moves, the callback wiring is already
in place.

Remaining steps:
1. ~~Define `transport.Imr` embedding `*tdns.Imr`~~ — DONE (Bite 6)
2. Create `DiscoveryService` in transport that:
   - Watches PeerRegistry for peers in NEEDED state
   - Runs DNS lookups: URI, SVCB, TLSA, JWK records
   - Validates results (DANE, key verification)
   - Populates Peer with addresses, JOSE keys, ports
   - Transitions peer: NEEDED → DISCOVERING → KNOWN
   - Retries with backoff on failure
3. ~~Add `OnPeerDiscovered` to TransportManagerConfig~~ — DONE (Bite 8). Add `OnDiscoveryFailed` — TODO
4. Add `tm.DiscoverPeer(identity string)` for explicit
   discovery trigger (creates NEEDED peer, kicks discovery)
5. Move `DiscoverAndRegisterAgent` logic from tdns-mp:
   - Generic discovery mechanics → transport
   - MP-specific agent metadata → stays in tdns-mp's
     `OnPeerDiscovered` callback (already wired)
6. Move discovery retry/backoff infrastructure from
   tdns-mp (`DiscoveryRetrierNG` or equivalent)
7. After discovery moves, deduplicate the lookup helpers
   on `tdnsmp.Imr` against `transport.Imr` (parallel
   embedding cleanup).

Validate: transport can discover a peer given only an
identity string, without any MP code involved.

### Phase 7: Eliminate MPTransportBridge

**Goal**: MPTransportBridge disappears entirely. MP code uses
TransportManager directly.

**Status 2026-04-30:** Sub-step 1 (`Agent.PeerID`) DONE
via Bite 4. The `Peer.PopulateFromAgent` bridge from
Bite 7 mirrors per-mechanism state from Agent onto Peer,
documenting the canonical Agent→Peer mapping in code.
The three disposition-table wrappers
(`HasDNSTransport`, `HasAPITransport`,
`GetPreferredTransportName`) now delegate to Peer methods.

Bite 5 audit found all 9 `SyncPeerFromAgent` call sites
are write-shaped (each acquires a peer to immediately
send through it). The genuine decoupling work — split
"get-or-create peer" from "sync state from agent" on
hot send paths — is bigger than a bite and properly
belongs here in Phase 7.

Steps:
1. ~~Add `Agent.PeerID string` field~~ — DONE (Bite 4)
2. Split `SyncPeerFromAgent` into "get-or-create peer"
   (cheap lookup) and "populate from agent" (currently
   `Peer.PopulateFromAgent`, already exists). Migrate
   the 9 hot send-path call sites to the cheap lookup.
3. Move remaining MP methods from MPTransportBridge onto
   appropriate MP structs (HsyncEngine, CombinerMsgHandler,
   etc.)
4. Replace `*MPTransportBridge` with
   `*transport.TransportManager` in MP config
5. AgentRegistry drops transport-overlapping fields, reads
   from PeerRegistry via ID lookup
6. Remove `SyncPeerFromAgent()`,
   `agentStateToTransportState()` — no longer needed
7. Delete MPTransportBridge type

Validate: all binaries build; integration harness's
seven scenarios still pass.

### Phase 8: Reduce core package coupling

**Goal**: tdns-transport imports only truly generic types
from core.

Steps:
1. Audit remaining core imports in tdns-transport
2. Move generic types (CHUNK, TypeCHUNK, format constants)
   into a minimal shared package or keep in core
3. Ensure no MP-specific core types are imported
4. Consider whether `core` itself needs splitting (transport
   types vs DNS types vs MP types)

Validate: `go list -m all` shows minimal dependency graph.

### Phase 9: Unexport internal types

**Goal**: Clean up the public API surface.

Steps:
1. Unexport `Dns*Payload` types (they're wire format
   helpers, not public API)
2. Unexport payload parse functions that are implementation
   details
3. Review all 73 exported types — each must justify its
   presence in the public API
4. Target: < 30 exported types in the transport package

Validate: tdns-mp builds using only the public API.

## Transport Package Public API (Target State)

After all phases, the transport package exports roughly:

### Types
```
Transport           interface (Hello, Beat, Ping, Send,
                    Confirm, Name)
TransportManager    struct (orchestrator)
TransportManagerConfig
DiscoveryService    struct (peer discovery)
DNSTransport        struct (DNS mechanism)
APITransport        struct (API mechanism)
DNSMessageRouter    struct (message dispatch)
MessageContext      struct (handler context)
MessageHandlerFunc  func type
MiddlewareFunc      func type
Peer                struct (remote peer)
PeerState           enum
MechanismState      struct (per-mechanism tracking)
PeerRegistry        struct
ReliableMessageQueue struct
OutgoingMessage     struct
PendingMessage      struct
IncomingMessage     struct (generic: sender, scope, payload)
ChunkNotifyHandler  struct (CHUNK reassembly)
PayloadCrypto       struct (JOSE encryption)
SecurePayloadWrapper struct
Address             struct
TransportError      struct
ConfirmStatus       enum (success/failed/rejected/pending)
MessageType         string type
QueueStats, RouterMetrics, MessageStats (observability)
```

### What's gone
```
SyncType enum (NS, DNSKEY, GLUE, CDS, CSYNC)
SyncRequest/SyncResponse (replaced by generic Send)
KeystateRequest/Response
EditsRequest/Response
ConfigRequest/Response
AuditRequest/Response
KeyInventoryEntry
RejectedItemDTO
ZoneRelation
CombinerRouterConfig, SignerRouterConfig
InitializeCombinerRouter, InitializeSignerRouter
HandleSync, HandleRfi, HandleKeystate, HandleEdits,
    HandleConfig, HandleAudit, HandleStatusUpdate
18 Dns*Payload types (unexported)
All parse functions (unexported or removed)
```

## Risks and Mitigations

**Risk**: Large refactoring across three repos simultaneously.
**Mitigation**: Phases are ordered so each phase leaves all
repos building. No big-bang step.

**Risk**: Breaking the wire protocol between agents.
**Mitigation**: Wire format (JSON payloads over CHUNK) does
not change. Only the Go type hierarchy changes. The same
JSON hits the wire; it's just parsed by MP types instead of
transport types.

**Risk**: Gossip placement (still undecided).
**Mitigation**: Phase 2 replaces `Gossip` with generic
`AppData`. This works regardless of where gossip logic
lives. If we later decide gossip belongs in transport, we
add it as a Tier 2 feature without changing the field name.

## Relationship to Existing Design Docs

- **2026-03-24 TM Redesign**: This plan completes what that
  doc started. Step 4g (MPTransportBridge) becomes Phase 6
  here. We go further by cleaning up the type system.

- **2026-03-23 Extraction Plan**: Phase 1 (extraction) is
  done. This plan is effectively "Phase 2: clean the
  interface" from that doc, but with concrete specifics.

- **2026-02-05 Unified Transport Structs**: That plan
  proposed eliminating API/DNS struct duplication. This plan
  subsumes it — we eliminate the MP-specific structs
  entirely, not just unify them.

- **2026-03-12 API Transport Gap Analysis**: Gaps 1-5
  (missing API methods for Keystate/Edits/Config/Audit)
  become moot once those types move to MP. The generic
  `Send()` method handles all message types over both
  transports.

## Open Questions

**2026-04-16 status:**
- **OQ1 (gossip placement)** — REVISED to DEFERRED. Gossip
  stays in MP; `BeatRequest.Gossip` renames to `AppData`
  in Phase 2. Tier 2 extraction is a future opt-in, not a
  blocker.
- **OQ2 (scope)**, **OQ3 (QNAME)**, **OQ4 (hello content)**
  — RESOLVED unchanged. See Status Update section.

Remaining open items tracked as **G–O** in the Status
Update section. Closed: **G** (gossip, with OQ1), **H**
(type migration map, appendix below), **J** (IMR audit —
embed `*tdns.Imr` in `transport.Imr`), **K** (integration
tests — harness landed 2026-04-27, seven scenarios pass),
**M** (destination package — inline in `tdns-mp/v2/`,
appendix H). Items I, L, N, O remain as concrete pre-work:
- **L** (PeerRegistry shim spec) → pre-Phase-1 task
- **I** (chunk_notify_handler split) → pre-Phase-4 task
- **N, O** → pre-Phase-2 / throughout as noted

## Appendix H: Phase 2 Type Migration Map

Closes open issue **H**. Enumerates every exported type
that Phase 2 moves out of `tdns-transport/v2/transport/`,
with every field and JSON tag recorded as it exists today.

**Destination package — closes item M.** All moved types
land inline in `tdns-mp/v2/` (no subpackage). Labels below
read `→ tdns-mp/v2/`.

**Wire compat — deliberate break.** Deployed agent base is
nil. Phase 2 takes the opportunity to normalize tags
rather than preserve quirks. The enumeration below records
**current state** (source of truth for what moves); §H.7
specifies the **target state** after normalization.
Wire-break decisions: Gossip → AppData (tag + field),
snake_case / CamelCase mix → CamelCase, legacy+standard
duals → standard only.

**Verbatim enumeration, not verbatim migration.** Tags in
§H.1–H.4 below are byte-exact current state for the record.
The migration itself drops/renames per §H.7.

**Custom JSON.** Grep confirmed zero `MarshalJSON`/
`UnmarshalJSON` methods on any of these types. Standard
encoding/json semantics apply throughout.

### H.1 Application-level message types (transport.go)

All 11 types below move to `mp/<pkg>`. They have no JSON
tags — they are Go-level request/response containers used
inside the app; the Dns\*Payload types (H.2) are the
wire-format mirrors. They can be renamed freely during the
move; only the Dns\*Payload tags are wire-critical.

#### SyncType enum (transport.go:20) → `tdns-mp/v2/`
```go
type SyncType uint8
const (
    SyncTypeNS     SyncType = iota + 1
    SyncTypeDNSKEY
    SyncTypeGLUE
    SyncTypeCDS
    SyncTypeCSYNC
)
// method: String() string
```

#### SyncRequest (transport.go:153) → `tdns-mp/v2/`
Fields: `SenderID string`, `Zone string`, `SyncType SyncType`,
`Records map[string][]string`, `Operations []core.RROperation`,
`Timestamp time.Time`, `Serial uint32`,
`DistributionID string`, `Nonce string`, `Signature []byte`,
`MessageType string`, `RfiType string`, `RfiSubtype string`,
`ZoneClass string`, `Publish *core.PublishInstruction`.

`MessageType`, `RfiType`, `RfiSubtype`, `Publish` are the
MP-leak fields the plan's §A3 calls out. They move as part
of the whole type; no field-level split needed here.

#### SyncResponse (transport.go:172) → `tdns-mp/v2/`
Fields: `ResponderID string`, `Zone string`,
`DistributionID string`, `Status ConfirmStatus`,
`Message string`, `Timestamp time.Time`,
`AppliedRecords []string`, `RemovedRecords []string`,
`RejectedItems []RejectedItemDTO`, `Truncated bool`.

Note: `ConfirmStatus` stays in transport; MP imports it.

#### KeystateRequest (transport.go:233) → `tdns-mp/v2/`
Fields: `SenderID string`, `Zone string`, `KeyTag uint16`,
`Algorithm uint8`, `Signal string`, `Message string`,
`KeyInventory []KeyInventoryEntry`, `Timestamp time.Time`.

#### KeystateResponse (transport.go:245) → `tdns-mp/v2/`
Fields: `ResponderID string`, `Zone string`, `KeyTag uint16`,
`Signal string`, `Accepted bool`, `Message string`,
`Timestamp time.Time`.

#### EditsRequest (transport.go:257) → `tdns-mp/v2/`
Fields: `SenderID string`, `Zone string`,
`AgentRecords map[string]map[string][]string`,
`Message string`, `Timestamp time.Time`.

#### EditsResponse (transport.go:266) → `tdns-mp/v2/`
Fields: `ResponderID string`, `Zone string`, `Accepted bool`,
`Message string`, `Timestamp time.Time`.

#### ConfigRequest (transport.go:276) → `tdns-mp/v2/`
Fields: `SenderID string`, `Zone string`, `Subtype string`,
`ConfigData map[string]string`, `Message string`,
`Timestamp time.Time`.

#### ConfigResponse (transport.go:286) → `tdns-mp/v2/`
Fields: `ResponderID string`, `Zone string`, `Accepted bool`,
`Message string`, `Timestamp time.Time`.

#### AuditRequest (transport.go:296) → `tdns-mp/v2/`
Fields: `SenderID string`, `Zone string`,
`AuditData interface{}`, `Message string`,
`Timestamp time.Time`.

`AuditData` is `interface{}` today — flagged as a
placeholder. Typing it is MP's problem post-move.

#### AuditResponse (transport.go:305) → `tdns-mp/v2/`
Fields: `ResponderID string`, `Zone string`, `Accepted bool`,
`Message string`, `Timestamp time.Time`.

#### KeyInventoryEntry (transport.go:222) → `tdns-mp/v2/` — HAS TAGS
```go
type KeyInventoryEntry struct {
    KeyTag    uint16 `json:"key_tag"`
    Algorithm uint8  `json:"algorithm"`
    Flags     uint16 `json:"flags"`
    State     string `json:"state"`
    KeyRR     string `json:"keyrr"`
}
```

#### RejectedItemDTO (dns.go:1305) → `tdns-mp/v2/` — HAS TAGS
```go
type RejectedItemDTO struct {
    Record string `json:"record"`
    Reason string `json:"reason"`
}
```
Embedded in `DnsConfirmPayload.RejectedItems` and
`SyncResponse.RejectedItems`. Both moved types and the
embedding types land inline in `tdns-mp/v2/`.

### H.2 Wire-format payload types (dns.go) — CURRENT STATE

All 13 `Dns*Payload` types move to `tdns-mp/v2/`. Tags
below record current state byte-exact. Post-move
normalization (§H.7) drops legacy duals and aligns tag
casing; treat §H.2 as the inventory, not the target.

#### DnsHelloPayload (dns.go:1203)
```go
Type         string   `json:"type"`
SenderID     string   `json:"sender_id"`
Capabilities []string `json:"capabilities,omitempty"`
SharedZones  []string `json:"shared_zones,omitempty"`
Timestamp    int64    `json:"timestamp"`
Nonce        string   `json:"nonce,omitempty"`
MessageType  string   `json:"MessageType"`
MyIdentity   string   `json:"MyIdentity"`
YourIdentity string   `json:"YourIdentity"`
Zone         string   `json:"Zone"`
Time         string   `json:"Time"`
// methods: GetSenderID(), GetSharedZones()
```

#### DnsBeatPayload (dns.go:1238)
```go
Type           string          `json:"type"`
SenderID       string          `json:"sender_id"`
Timestamp      int64           `json:"timestamp"`
Sequence       uint64          `json:"sequence"`
State          string          `json:"state,omitempty"`
MessageType    string          `json:"MessageType"`
MyIdentity     string          `json:"MyIdentity"`
YourIdentity   string          `json:"YourIdentity"`
MyBeatInterval uint32          `json:"MyBeatInterval"`
Zones          []string        `json:"Zones"`
Time           string          `json:"Time"`
Gossip         json.RawMessage `json:"Gossip,omitempty"`
// methods: GetSenderID()
```
Phase 2: `Gossip` → `AppData` (both field and tag). Wire
break accepted. Legacy fields dropped per §H.7.

#### DnsSyncPayload (dns.go:1265)
```go
MessageType    string                   `json:"MessageType"`
OriginatorID   string                   `json:"OriginatorID"`
YourIdentity   string                   `json:"YourIdentity"`
Zone           string                   `json:"Zone"`
Nonce          string                   `json:"nonce,omitempty"`
Records        map[string][]string      `json:"Records"`
Operations     []core.RROperation       `json:"Operations,omitempty"`
Time           string                   `json:"Time"`
RfiType        string                   `json:"RfiType"`
RfiSubtype     string                   `json:"rfi_subtype,omitempty"`
Timestamp      int64                    `json:"timestamp"`
DistributionID string                   `json:"distribution_id"`
ZoneClass      string                   `json:"zone_class,omitempty"`
Publish        *core.PublishInstruction `json:"publish,omitempty"`
// methods: GetPublish(), GetSenderID(), GetRecords(), GetOperations()
```
Note the mixed-case tags: `RfiType` (CamelCase) vs
`rfi_subtype` (snake_case). Normalized to CamelCase per
§H.7.

#### DnsRelocatePayload (dns.go:1296)
```go
Type       string     `json:"type"`
SenderID   string     `json:"sender_id"`
NewAddress DnsAddress `json:"new_address"`
Reason     string     `json:"reason"`
ValidUntil int64      `json:"valid_until"`
```
Embedded type `DnsAddress` — verify whether it's transport
or MP; if transport, MP needs to import it. (Pre-Phase-2
item; not a blocker for the map itself.)

#### DnsConfirmPayload (dns.go:1311)
```go
Type           string            `json:"type"`
SenderID       string            `json:"sender_id"`
Zone           string            `json:"zone"`
DistributionID string            `json:"distribution_id"`
Nonce          string            `json:"nonce,omitempty"`
Status         string            `json:"status"`
Message        string            `json:"message,omitempty"`
AppliedCount   int               `json:"applied_count,omitempty"`
RemovedCount   int               `json:"removed_count,omitempty"`
RejectedCount  int               `json:"rejected_count,omitempty"`
AppliedRecords []string          `json:"applied_records,omitempty"`
RemovedRecords []string          `json:"removed_records,omitempty"`
RejectedItems  []RejectedItemDTO `json:"rejected_items,omitempty"`
IgnoredCount   int               `json:"ignored_count,omitempty"`
IgnoredRecords []string          `json:"ignored_records,omitempty"`
Truncated      bool              `json:"truncated,omitempty"`
Timestamp      int64             `json:"timestamp"`
```

#### DnsPingPayload (dns.go:1348)
```go
Type         string `json:"type"`
SenderID     string `json:"sender_id"`
Nonce        string `json:"nonce"`
Timestamp    int64  `json:"timestamp"`
MessageType  string `json:"MessageType"`
MyIdentity   string `json:"MyIdentity"`
YourIdentity string `json:"YourIdentity"`
Time         string `json:"Time"`
// methods: GetSenderID()
```

#### DnsKeystatePayload (dns.go:1372)
```go
MessageType  string              `json:"MessageType"`
MyIdentity   string              `json:"MyIdentity"`
YourIdentity string              `json:"YourIdentity"`
Zone         string              `json:"Zone"`
KeyTag       uint16              `json:"KeyTag"`
Algorithm    uint8               `json:"Algorithm"`
Signal       string              `json:"Signal"`
Message      string              `json:"Message,omitempty"`
KeyInventory []KeyInventoryEntry `json:"KeyInventory,omitempty"`
Timestamp    int64               `json:"timestamp"`
Type         string              `json:"type"`
SenderID     string              `json:"sender_id"`
// methods: GetSenderID()
```

#### DnsKeystateConfirmPayload (dns.go:1401)
```go
Type      string `json:"type"`
SenderID  string `json:"sender_id"`
Zone      string `json:"zone"`
KeyTag    uint16 `json:"key_tag"`
Signal    string `json:"signal"`
Status    string `json:"status"`
Message   string `json:"message,omitempty"`
Timestamp int64  `json:"timestamp"`
```

#### DnsEditsPayload (dns.go:1415)
```go
MessageType  string                         `json:"MessageType"`
MyIdentity   string                         `json:"MyIdentity"`
YourIdentity string                         `json:"YourIdentity"`
Zone         string                         `json:"Zone"`
AgentRecords map[string]map[string][]string `json:"AgentRecords,omitempty"`
Message      string                         `json:"Message,omitempty"`
Timestamp    int64                          `json:"timestamp"`
Type         string                         `json:"type"`
SenderID     string                         `json:"sender_id"`
// methods: GetSenderID()
```

#### DnsConfigPayload (dns.go:1443)
```go
MessageType  string            `json:"MessageType"`
MyIdentity   string            `json:"MyIdentity"`
YourIdentity string            `json:"YourIdentity"`
Zone         string            `json:"Zone"`
Subtype      string            `json:"Subtype"`
ConfigData   map[string]string `json:"ConfigData,omitempty"`
Message      string            `json:"Message,omitempty"`
Timestamp    int64             `json:"timestamp"`
Type         string            `json:"type"`
SenderID     string            `json:"sender_id"`
// methods: GetSenderID()
```

#### DnsAuditPayload (dns.go:1466)
```go
MessageType  string      `json:"MessageType"`
MyIdentity   string      `json:"MyIdentity"`
YourIdentity string      `json:"YourIdentity"`
Zone         string      `json:"Zone"`
AuditData    interface{} `json:"AuditData,omitempty"`
Message      string      `json:"Message,omitempty"`
Timestamp    int64       `json:"timestamp"`
Type         string      `json:"type"`
SenderID     string      `json:"sender_id"`
// methods: GetSenderID()
```

#### DnsStatusUpdatePayload (dns.go:1489)
```go
MessageType  string   `json:"MessageType"`
MyIdentity   string   `json:"MyIdentity"`
YourIdentity string   `json:"YourIdentity"`
Zone         string   `json:"Zone"`
SubType      string   `json:"SubType"`
NSRecords    []string `json:"NSRecords,omitempty"`
DSRecords    []string `json:"DSRecords,omitempty"`
Result       string   `json:"Result,omitempty"`
Msg          string   `json:"Msg,omitempty"`
Timestamp    int64    `json:"timestamp"`
Type         string   `json:"type"`
SenderID     string   `json:"sender_id"`
// methods: GetSenderID()
```

#### DnsPingConfirmPayload (dns.go:1513)
```go
Type           string `json:"type"`
SenderID       string `json:"sender_id"`
Nonce          string `json:"nonce"`
DistributionID string `json:"distribution_id"`
Status         string `json:"status"`
Message        string `json:"message,omitempty"`
Timestamp      int64  `json:"timestamp"`
```

### H.3 Peer struct field removal (peer.go)

`Peer` stays in transport; only these fields/types move
out:

- **`SharedZones map[string]*ZoneRelation`** — delete from
  `Peer`. No JSON tag (Peer has no tags). Replace with
  scope tracking on the MP side per plan §C1.
- **`ZoneRelation` struct** (peer.go:126) — move to
  `mp/<pkg>`. No JSON tags on the type. Fields:
  `Zone string`, `Role string`, `PeerRole string`,
  `LastSync time.Time`, `SyncSerial uint32`,
  `SyncPending bool`.

### H.4 BeatRequest field rename (transport.go:132)

Stays in transport; field renames:

```go
// Before
Gossip json.RawMessage `json:"gossip,omitempty"`
// After
AppData json.RawMessage `json:"AppData,omitempty"`
```

Wire break accepted. `DnsBeatPayload.Gossip` (§H.2) gets
the same rename and casing. Plan text earlier in this doc
calling the rename "wire-compatible" is superseded: it is
a deliberate wire break, justified by nil deployed base.

### H.5 Field-count check (current state)

Plan text: "~25 wire-format-critical fields". Actual count
across the 13 Dns\*Payload types + 2 tagged struct types
(KeyInventoryEntry, RejectedItemDTO):

- DnsHelloPayload: 11
- DnsBeatPayload: 12
- DnsSyncPayload: 14
- DnsRelocatePayload: 5
- DnsConfirmPayload: 17
- DnsPingPayload: 8
- DnsKeystatePayload: 12
- DnsKeystateConfirmPayload: 8
- DnsEditsPayload: 9
- DnsConfigPayload: 10
- DnsAuditPayload: 9
- DnsStatusUpdatePayload: 12
- DnsPingConfirmPayload: 7
- KeyInventoryEntry: 5
- RejectedItemDTO: 2

**Total: 141 fields current state.** Normalization (§H.7)
drops the legacy duals — see recomputed count there.

### H.6 Normalization target (post-move state)

**Legacy fields dropped.** Every Dns\*Payload carries a
"Legacy" block (some combination of `Type`, `SenderID`,
`Timestamp` with snake_case tags) alongside "Standard"
fields that duplicate the same information in CamelCase
(`MessageType`, `MyIdentity`, `Time`). The legacy block
was fallback for pre-standard agents. With nil deployed
base, drop legacy fields entirely. Any getter method that
reads them (`GetSenderID`, `GetSharedZones`) reads the
standard field instead.

**Tag casing normalized to CamelCase.** Pick one
convention and apply uniformly. The majority of new fields
already use CamelCase (`MessageType`, `MyIdentity`, `Zone`,
`KeyTag`, `Signal`, `AppData`). Align everything — fields
currently using snake_case tags (`nonce`, `rfi_subtype`,
`distribution_id`, `zone_class`, `publish`,
`applied_count`, etc.) move to CamelCase
(`Nonce`, `RfiSubtype`, `DistributionID`, `ZoneClass`,
`Publish`, `AppliedCount`, ...). The Go field name already
matches; only the tag string changes.

**`omitempty` policy.** Keep as-is — it's about JSON size,
not casing. Any field currently `omitempty` stays
`omitempty`.

**Concrete target per type** (fields that survive after
legacy removal; tag strings CamelCase-normalized):

| Type | Surviving fields |
|---|---|
| DnsHelloPayload | MessageType, MyIdentity, YourIdentity, Zone, Time, Capabilities, SharedZones, Nonce |
| DnsBeatPayload | MessageType, MyIdentity, YourIdentity, MyBeatInterval, Zones, Time, State, Sequence, AppData |
| DnsSyncPayload | MessageType, OriginatorID, YourIdentity, Zone, Nonce, Records, Operations, Time, RfiType, RfiSubtype, DistributionID, ZoneClass, Publish |
| DnsRelocatePayload | MessageType, MyIdentity, NewAddress, Reason, ValidUntil |
| DnsConfirmPayload | MessageType, MyIdentity, Zone, DistributionID, Nonce, Status, Message, AppliedCount, RemovedCount, RejectedCount, AppliedRecords, RemovedRecords, RejectedItems, IgnoredCount, IgnoredRecords, Truncated, Time |
| DnsPingPayload | MessageType, MyIdentity, YourIdentity, Nonce, Time |
| DnsKeystatePayload | MessageType, MyIdentity, YourIdentity, Zone, KeyTag, Algorithm, Signal, Message, KeyInventory, Time |
| DnsKeystateConfirmPayload | MessageType, MyIdentity, Zone, KeyTag, Signal, Status, Message, Time |
| DnsEditsPayload | MessageType, MyIdentity, YourIdentity, Zone, AgentRecords, Message, Time |
| DnsConfigPayload | MessageType, MyIdentity, YourIdentity, Zone, Subtype, ConfigData, Message, Time |
| DnsAuditPayload | MessageType, MyIdentity, YourIdentity, Zone, AuditData, Message, Time |
| DnsStatusUpdatePayload | MessageType, MyIdentity, YourIdentity, Zone, SubType, NSRecords, DSRecords, Result, Msg, Time |
| DnsPingConfirmPayload | MessageType, MyIdentity, Nonce, DistributionID, Status, Message, Time |
| KeyInventoryEntry | KeyTag, Algorithm, Flags, State, KeyRR |
| RejectedItemDTO | Record, Reason |

**Per-type notes:**

- `Timestamp int64` (unix) fields collapse into the
  existing `Time string` (RFC3339) field where both are
  present. For payloads that only had `Timestamp` (e.g.
  `DnsConfirmPayload`, `DnsRelocatePayload`,
  `DnsPingConfirmPayload`), rename it to `Time` with RFC3339
  content — consistency win. One field, one format.
- `Type string` (legacy discriminator like `"keystate"`)
  drops entirely; `MessageType` is the discriminator.
- `SenderID string` drops; `MyIdentity` is the sender.
- `DnsPingPayload`'s legacy `Nonce` tag `json:"nonce"` was
  shared between legacy and standard. Retain as
  `json:"Nonce"` (CamelCase).
- `DnsConfirmPayload` has no Standard-block equivalents
  for all fields today. When normalizing, add
  `MessageType` and `MyIdentity` (currently only has
  legacy `Type`/`SenderID`). This is a genuine schema
  addition, not just renaming.
- `DnsRelocatePayload` is entirely legacy-style today.
  Convert fully: `type` → `MessageType`, `sender_id` →
  `MyIdentity`, `new_address` → `NewAddress`, `reason` →
  `Reason`, `valid_until` → `ValidUntil`.
- `DnsPingConfirmPayload` same: entirely legacy.
  Normalize all six fields.

**Recomputed field count (post-normalization):**

- DnsHelloPayload: 8 (−3)
- DnsBeatPayload: 9 (−3)
- DnsSyncPayload: 13 (−1; Timestamp collapsed into Time)
- DnsRelocatePayload: 5 (unchanged count; all renamed)
- DnsConfirmPayload: 17 (unchanged; MessageType/MyIdentity added, Type/SenderID/Timestamp removed)
- DnsPingPayload: 5 (−3)
- DnsKeystatePayload: 10 (−2)
- DnsKeystateConfirmPayload: 8 (unchanged count; all renamed)
- DnsEditsPayload: 7 (−2)
- DnsConfigPayload: 8 (−2)
- DnsAuditPayload: 7 (−2)
- DnsStatusUpdatePayload: 10 (−2)
- DnsPingConfirmPayload: 7 (unchanged count; all renamed)
- KeyInventoryEntry: 5 (unchanged; already CamelCase-worthy, currently snake; tags re-cased)
- RejectedItemDTO: 2 (unchanged; tags re-cased)

**Total: 121 fields.** Net −20 from dropping legacy duals.
Per-type field count stabilizes; tag strings are
CamelCase across the board; one timestamp format (RFC3339
string `Time`) instead of two.

### H.7 What stays in transport

For completeness, types the plan keeps in transport that
were verified present during enumeration:

- `ConfirmStatus` (enum) — imported by moved SyncResponse
- `RouterConfig`, `InitializeRouter` — generic only; role
  variants move per Phase 3
- `Peer`, `PeerRegistry`, `PeerState` — stay; field
  surgery per H.3
- `BeatRequest`, `HelloRequest`, `PingRequest` — stay;
  field-level changes only
- `ChunkNotifyHandler`, `IncomingMessage`, `MessageContext`
  — stay (split per item I, not H)

Post-move, the 13 Dns\*Payload types become unexported on
the MP side per Phase 9 — subsequent cleanup, not a Phase 2
requirement.
