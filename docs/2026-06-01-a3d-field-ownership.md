# A3d design addendum — peer-state ownership & field rehoming

Date: 2026-06-01. Branch: `transport-redesign-v1-A`.
Companion to `2026-05-30-transport-redesign-consolidated-plan-v2.md` §A3.
This addendum closes the design gap that §A3 left open: the plan settled
the *registry* embed (decision B) but never the *peer-element* type-merge —
what type the unified peer map holds, where `Agent`'s surplus fields go,
and how that interacts with A4's field ownership. Implement A3d against
THIS document.

## 1. The acceptance test (why each placement is what it is)

Dependency direction is one-way: **tdns-mp imports tdns-transport, never the
reverse** (`hsync` is a tdns-mp sub-package and already imports `transport`).
From that single fact:

> Every datum lives in the layer that will OWN it in the end state, and
> nothing lands somewhere that would force a future dependency inversion.

The end-state contract between the layers — the thing A3d must establish and
Stages C/D/E must NOT have to change:

- The app/engine expresses **intent** ("I need peer X reachable") and reads
  back **one** `EffectiveState()`. It never sees per-mechanism (DNS/API/DoQ)
  state and never selects a transport.
- **Transport owns the whole connection lifecycle** behind that intent:
  discovery→KNOWN, HELLO→INTRODUCED, BEAT→OPERATIONAL, beat-timeout→
  DEGRADED/INTERRUPTED. The cross-mechanism integration is transport's job
  and already exists (`transport.Peer.EffectiveState()`).
- `LEGACY` is the one MP overlay (participations==0), computed MP-side,
  **never** seen by transport (it is a zones concept; transport knows nothing
  of zones).

The forcing consequence: Stages D (liveness) and E (discovery) relocate the
discovery/hello/beat **handlers** *into* transport. Those handlers will run
inside transport and cannot import tdns-mp to learn which peers are needed or
what their state is. Therefore **all connection state — including the NEEDED
intent — must live on `transport.Peer` now.** The engine declares a need by
setting `transport.Peer` to NEEDED; the discovery handler (still tdns-mp in
A3d) reads NEEDED peers out of the `PeerRegistry`; Stage E then relocates that
handler and it finds everything already in its own registry. If A3d left
"who's needed" on `hsync.Peer`/`Agent`, Stage E would be unbuildable. That is
the test passing or failing.

## 2. Current topology (verified 2026-06-01)

Two parallel peer maps, kept coherent by the bridge (`hsync_bridge_sync.go`):
- `AgentRegistry.S : ConcurrentMap[AgentId,*Agent]`
- `hsync.Registry.S : ConcurrentMap[PeerID,*hsync.Peer]`

`transport.Peer` **already owns** the connection-state slots:
`Mechanisms map[string]*MechanismState` (per-mech State/address/hello/beat/
fails/stats), `DiscoveryAddr`/`OperationalAddr`/`APIEndpoint`,
`EffectiveState()`, `SetState`/`SetMechanismState`, liveness
(`RecordBeat*`/`IsHealthy`), crypto slots (`LongTermPubKey`/`KeyType`/
`TLSARecord`), `SharedZones`. `routeBeatMessage` already dual-writes
`peer.SetMechanismState(...)` — so transport's mechanism state is already
maintained; A3d deletes the *duplicate* Agent/hsync copies, it does not invent
the store.

The discovery/hello/beat **handlers** are tdns-mp's today (`agent_discovery.go`,
`hsync_hello.go`, `hsync_beat.go`/`hsync_transport.go`) plus the hsync engine.
A3d does NOT move them — that is Stage D (liveness) + Stage E (discovery). A3d
makes them write the single store and stop maintaining duplicates.

## 3. Target types

```
// transport.Peer (tdns-transport, generic) — the connection-state owner.
// Already exists. Gains nothing new in A3d; becomes the SOLE store for
// state/address/per-mechanism/liveness, read via EffectiveState().

// hsync.Peer (tdns-mp/v2/hsync, generic coordination) — goes THIN.
type Peer struct {
    ID       PeerID
    Mu       sync.RWMutex          // the single peer mutex
    Zones    map[ZoneName]bool     // transitional; membership is derived (A2)
    Deferred []DeferredTask        // post-OPERATIONAL coordination tasks
    // IsInfraPeer stays as a role hint
    // NO State / ApiDetails / DnsDetails — read connection state from transport.Peer
}

// agentMeta (tdns-mp, MP-side sidecar keyed by PeerID) — TRANSITIONAL holding
// pen for MP-only fields whose final home is transport but is deferred.
type agentMeta struct {
    InitialZone ZoneName
    Api         *AgentApi                  // → transport (mechanism client), later
    Crypto      map[string]*mechCrypto     // per-mechanism: "API","DNS"
}
type mechCrypto struct {                   // → transport.Peer crypto slots @ E1
    KeyRR        *dns.KEY
    TlsaRR       *dns.TLSA
    UriRR        *dns.URI
    JWKData      string
    KeyAlgorithm string
}

// Agent (tdns-mp) — a VIEW, not a store.
type Agent struct {
    *hsync.Peer   // Zones / Deferred / ID promote
    *agentMeta    // Api / Crypto / InitialZone
    // State accessors (EffectiveState, IsAnyTransportOperational, …) read
    // transport.Peer via PeerRegistry.Get(ID), then apply the LEGACY overlay.
}
```

`AgentRegistry embeds *hsync.Registry` (plan decision B). `hsync.Registry`
owns the single peer map + protocol methods + `helloCancel` + `LocalID`. The
MP side keeps the `agentMeta` map + gossip/groups/elections/transport-manager
+ `LocalAgent`.

## 4. Field-ownership table

`A3d home` is where the field lives when A3d lands. `end-state home` is where
it lives after C/D/E/E1. A3d home MUST equal end-state home, OR be a marked,
dependency-respecting waypoint (the `agentMeta` holding pen).

### Agent

| field | A3d home | end-state home | notes |
|---|---|---|---|
| Identity, PeerID | = `hsync.Peer.ID` | PeerID join key | dedupe to one id |
| Mu | `hsync.Peer.Mu` | single peer mutex | delete Agent.Mu |
| Zones | `hsync.Peer.Zones` | **derived** (not stored) | reads via `ParticipantsForZone` (A2); field is transitional |
| DeferredTasks | `hsync.Peer.Deferred` | hsync (coordination) | type unifies |
| IsInfraPeer | `hsync.Peer` | MP role hint | |
| ApiMethod, DnsMethod | `transport.Peer.HasMechanism` | transport | capability = mechanism presence |
| State, LastState | `transport.Peer` (read `EffectiveState`/`StateChanged`) | transport + LEGACY overlay | NOT stored MP-side |
| ErrorMsg | `transport.Peer.StateReason` | transport | low real usage on Agent |
| Api (*AgentApi) | `agentMeta` | **transport** (mechanism client) | holding pen — can't go on hsync.Peer (circular) |
| InitialZone | `agentMeta` | MP (or drop) | 2 uses |
| ApiDetails/DnsDetails ptr | dissolved | — | see AgentDetails |

### AgentDetails (per-mechanism)

| field | A3d home | end-state home | notes |
|---|---|---|---|
| Addrs, Port, BaseUri, Host | `transport.Peer` (Address/APIEndpoint) | transport | already owned |
| ContactInfo | `transport.Peer` | transport (discovery status) | |
| State | `transport.Peer.Mechanisms[m].State` | transport | already maintained |
| LatestError, LatestErrorTime | `transport.Peer.Mechanisms[m]` | transport | StateReason + time |
| DiscoveryFailures | `transport.Peer` (`ConsecutiveFails`) | transport | |
| HelloTime | `transport.Peer` (`LastHelloRecv/Sent`) | transport | |
| LastContactTime | `transport.Peer` (`LastBeatRecv`) | transport | |
| BeatInterval | `transport.Peer` | transport (liveness param) | |
| SentBeats, ReceivedBeats | `transport.Peer.Stats` | transport | already owned |
| LatestSBeat, LatestRBeat | `transport.Peer.Mechanisms[m]` | transport | LastBeatSent/Recv |
| KeyRR, TlsaRR, UriRR, JWKData, KeyAlgorithm | `agentMeta.Crypto[m]` | **transport** @ E1 | holding pen (crypto stays MP-side until E1 per plan) |
| Endpoint | **delete** | — | 0 uses |

## 5. Resolved decisions

- **State store = `transport.Peer`.** Canonical connection-lifecycle enum is
  transport's `PeerState`. MP keeps NO competing source of truth — the Agent
  view's `State` accessor returns `transport.Peer.EffectiveState()` with the
  `LEGACY` overlay applied (participations==0). `NEEDED` is set on
  `transport.Peer` by the engine (the intent lives in the transport registry).
- **Enum reconciliation:** transport `PeerState` has DISCOVERING/INTRODUCING
  (transient) and no LEGACY; MP `AgentState` has LEGACY/INTRODUCED. Map MP→
  transport once, and represent `LEGACY` only as the MP overlay value. Do not
  carry two enums as parallel truth.
- **`agentMeta` is transitional.** Its crypto sub-struct migrates into
  `transport.Peer`'s crypto slots at **E1**; `Api` migrates when the API
  mechanism owns its client. Mark every `agentMeta` field with its final
  transport destination so the sidecar is never mistaken for permanent.
- **Permanently MP-side:** only derived membership (zones/roles, not stored)
  and the `LEGACY` overlay. In the true end state the MP per-peer record is
  nearly empty — the plan's "two stores joined by PeerID."

## 6. Sequencing — the A3d/A4 binary dissolves

Because `transport.Peer` already owns the transport-state slots, the migration
repoints transport-state reads **straight to `transport.Peer`** — which *is*
A4's redirect. So do not run "A3d then A4" (it would rewrite the ~302
`.ApiDetails`/`.DnsDetails` sites twice). Run **one field-partition migration**:
transport-state reads → `transport.Peer` accessors; crypto/api → `agentMeta`;
coordination → `hsync.Peer`.

Consequence: **A3d absorbs the core of A4.** A4's "switch all readers to
`peerRegistry.Get` + rewrite the canonical accessors" happens here; the
residual A4 shrinks to deleting the now-dead sync funcs (`SyncPeerFromAgent`,
`agentStateToTransportState`(`Fn`)), which fall out with the bridge teardown.
Treat "A3d" as **embed + transport-state ownership**; revisit whether A4
remains a distinct stage or is just that dead-code sweep.

## 7. Non-mechanical work (design decided here; agent executes)

- **Inbound pipeline collapse.** After the single store, the beat path
  (`routeBeatMessage` + `HeartbeatHandler` + engine `heartbeatHandler`)
  converges to ONE writer per message type, writing `transport.Peer`
  (mechanism state + counters); gossip/election stays. Delete the duplicate
  Agent/hsync writes. Handlers stay in tdns-mp (Stage D/E relocate them). The
  `routeBeatMessage` no-lock race is already fixed (ad19c48); keep the
  single-writer rule across the collapse.
- **Hello/discovery during A3d.** Handlers stay tdns-mp; they read NEEDED from
  `transport.Peer` and write KNOWN/INTRODUCED to `transport.Peer`. Keep the
  hsync discovery path (`HelloRetrierNG`/`hsync/discovery.go`); retire the
  legacy `attemptDiscovery`+`helloContexts` path (the `HsyncEngine==nil`
  fallback in `MarkAgentAsNeeded`) — verify no production nil-fallback first.
- **Lock order (binding, from A3a):** `AgentRegistry.mu → peer mutex (one) →
  transport.PeerRegistry → transport.Peer`. The Agent view holds `*hsync.Peer`
  (the mutex) + `*agentMeta` and reaches `transport.Peer` by ID. Never hold a
  registry/peer mutex across a transport call (use the A3a `ReplaceSharedZones`
  pattern). Run `-race` on the boundary/hsync suites at every sub-step.
- **Bridge teardown.** The single store + view make the `hsync_bridge_sync.go`
  converters dead (no Agent↔hsync.Peer copying; no state-sync to transport —
  handlers write transport directly). Remove what falls out. The event-driven
  `OnPeerRemoved` is A5.

## 8. Suggested sub-decomposition (each = one commit; build green + -race + INVARIANT)

0. **A3d.0** — add `agentMeta` (+ per-mech `mechCrypto`), the `Agent` view
   embedding `*hsync.Peer`+`*agentMeta`, and the State accessor that reads
   `transport.Peer.EffectiveState()` + LEGACY overlay. Converters in place, NO
   behavior change. **Operator checkpoint on the type design before A3d.1.**
1. **A3d.1** — `AgentRegistry` embeds `*hsync.Registry`; keep `AgentRegistry.S`
   temporarily; delegating accessors. Still dual-mapped.
2. **A3d.2** — redirect the canonical accessors + the ~302 transport-state
   reads to `transport.Peer` (A4's core, folded in). Build per file.
3. **A3d.3** — move crypto/api/initialzone reads to `agentMeta`; coordination
   to `hsync.Peer`.
4. **A3d.4** — delete `AgentRegistry.S`, the `AgentDetails` struct, the bridge
   converters, `SyncPeerFromAgent`/`agentStateToTransportState`(`Fn`); collapse
   the inbound pipeline to one writer.
5. **A3d.5** — retire the legacy hello/discovery path; delete
   `hsync.Registry.RemoteAgents` (derive zone→peer on read).

**Operator checkpoint** after the embed lands (A3d.4) — deploy + confirm
INVARIANT convergence on the testbed before any further stage. Probe stays
INVARIANT throughout (pure refactor): `peer list`/`peer zones`/`gossip state`/
`addrr` round-trip byte-comparable.

### 8.1 Resequencing (2026-06-01, after the A3d.1 embed + read audit)

A per-field writer audit (run before starting A3d.2) showed the "redirect reads,
then collapse writers" order in §8.2/§8.4 is **backwards** for most fields:
`transport.Peer` is only *partially* the single source today, so reads cannot be
redirected ahead of their writers without observing a half-populated peer. The
gate is per-field: *"is `transport.Peer` already kept current for this datum by
an existing writer on every live path?"* — not the field's category.

Findings driving the change:
- **`.State` FAILS the gate.** `CheckState` beat-health (DEGRADED/INTERRUPTED,
  `hsync_beat.go:101-106`), the A3a LEGACY/OPERATIONAL transition
  (`RecomputeSharedZonesAndSyncState`), and `peer reset` (`apihandler_peer.go`)
  all write the Agent state with **no** `transport.Peer` counterpart;
  `transport.Peer` is never set DEGRADED/INTERRUPTED anywhere. So
  `effectiveAgentState()` is not byte-identical to `Agent.EffectiveState()`
  until those writers are unified.
- **Addresses are path-dependent.** Live NG discovery dual-writes; the
  deprecated `LocateAgent` (`agent_utils.go`) writes Agent-side only (retired in
  A3d.5).
- **Most "Group 3" telemetry already has a `transport.MechanismState`/`Stats`
  home** — `HelloTime→LastHelloRecv`, `LastContactTime`/`LatestRBeat→
  LastBeatRecv`, `LatestSBeat→LastBeatSent`, `SentBeats`/`ReceivedBeats→Stats`,
  `DiscoveryFailures→ConsecutiveFails`, `LatestError(+Time)→StateReason`/
  `StateChanged`. Only **`BeatInterval`** is a genuinely new transport field;
  **`ContactInfo`** must be proven load-bearing or dropped (likely derivable).
  Don't add redundant transport surface.

**New plan — per-field vertical slices.** A3d.2 and A3d.4's reader/writer work
**merge into per-field commits**. Each slice = one commit, green + `-race` +
INVARIANT: (1) make the field's single live writer target `transport.Peer`
(for `.State`: relocate `CheckState` DEGRADED/INTERRUPTED to set
`Mechanisms[m].State`; keep LEGACY as the MP overlay); (2) redirect that field's
reads to `transport.Peer`; (3) stop writing the Agent-side field. `AgentDetails`
is deleted once empty (end of the slice sequence). `.State` is sliced **last**
(most writers to unify). A3d.3 (crypto/api→`agentMeta`) is unchanged. The
post-A3d.4 operator checkpoint becomes "after the AgentDetails deletion lands."

**Legacy-path retirement pulled forward (2026-06-01).** The A3d.5 legacy
hello/discovery/locate retirement was done **first**, before the field slices,
because several Agent-side field writers (address population in `LocateAgent`,
`DiscoveryFailures++` in `attemptDiscovery`) live *only* in that path —
retiring it deletes those writers outright and removes the legacy-vs-NG
duality from every per-field proof. Retired: the `HsyncEngine==nil` fallback in
`MarkAgentAsNeeded`, `attemptDiscovery`, `LocateAgent` (deprecated), and the
MP-side hello cluster `HelloRetrier`/`HelloRetrierNG`/`agentNeedsHello`/
`sendHelloToAgent`/`FastBeatAttempts`/`SingleHello`/`sharedZonesForAgent`/
`configureInterval` + `helloContexts`. `peer reset` rerouted to NG
`MarkAgentAsNeeded`. `hsync.Registry.RemoteAgents` deletion remains for the
end of A3d. `FetchSVCB` is now orphaned (kept pending operator decision).

> **Naming note (resolves an apparent doc conflict).** This addendum §7 says
> "keep `HelloRetrierNG`/hsync/discovery.go"; the consolidated-plan/prompt says
> "delete `HelloRetrierNG`". These name **different functions**: the retired one
> is MP's `(ar *AgentRegistry) HelloRetrierNG` in `hsync_hello.go` (reachable
> only via the legacy path); the kept one is the hsync-package NG path
> `(e *Engine) helloRetrierNG` + `hsync/discovery.go`, which runs in production
> when `HsyncEngine != nil`. No design conflict — only a name collision.
