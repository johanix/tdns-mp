# A3d spine-cluster migration — detailed scope

Date: 2026-06-03. Branch: `transport-redesign-v1-A`.
The last real A3d migration: the remaining live `AgentDetails` fields →
`transport.Peer`. (Crypto already moved to `agentMeta` in A3d.3; dead code
swept; `AgentDetails` is now crypto-free.) Companion to
`2026-06-01-a3d-field-ownership.md`.

## 0. The governing finding — THREE state stores, not two

The audit surfaced that per-peer connection state lives in **three** parallel
stores, not the two the plan assumed:

| Store | Maintained by | Reads |
|---|---|---|
| **`AgentDetails`** (MP) | the inbound DNS hello/beat handlers + discovery + `RecomputeSharedZonesAndSyncState` (dual-writing) | the `peer list` display + the canonical `Agent.EffectiveState`/`IsAnyTransportOperational` |
| **`hsync.PeerDetails`** (NG) | the NG engine: `applyInboundBeat` + `checkPeerState` | NG `checkPeerState` only — **not displayed** |
| **`transport.Peer`** | the same inbound handlers dual-write `SetMechanismState`/`SetMechanism*Recv`; `Stats` maintained *inside* tdns-transport; one discovery-time `PopulateFromAgent` snapshot | the send path; nothing reads its *state* for display yet |

Consequences that shape the slice:
- **DEGRADED/INTERRUPTED is NG-only.** Only `checkPeerState` produces it, on
  `hsync.PeerDetails`. Neither `AgentDetails` (MP `CheckState` is dead) nor
  `transport.Peer` ever goes DEGRADED/INTERRUPTED. So the display **already**
  never shows those — and `effectiveAgentState` (reads `transport.Peer`) will
  match that. Unifying NG liveness onto `transport.Peer` so the display shows
  *real* liveness is **Stage D**, explicitly OUT of this slice. This slice
  preserves the current (divergent) behavior → INVARIANT vs today.
- **`transport.Peer` state is kept current by the same dual-writing handlers**
  that write `AgentDetails.State`, so `transport.Peer.EffectiveState()` tracks
  `AgentDetails.State` across KNOWN/INTRODUCED/OPERATIONAL. LEGACY is the MP
  overlay on both. This is what makes the `.State` reader-redirect viable.

## 1. Per-field breakdown

| `AgentDetails` field | live MP readers | transport.Peer target | transport coverage today | verdict |
|---|---|---|---|---|
| `State` (+`LastState`) | `EffectiveState`/`IsAnyTransportOperational` (~15 callers) + display per-mechanism | `EffectiveState()` + LEGACY overlay (`effectiveAgentState`, already written in A3d.0, unused) | KNOWN/INTRODUCING/OPERATIONAL dual-written by handlers; DEGRADED/INTERRUPTED never (NG-only, matches display) | redirect readers to `effectiveAgentState` |
| `Addrs`,`Port` (DNS) | display; `GetOrCreatePeer` address restore | `Mechanisms["DNS"].Address` / `DiscoveryAddr` | written on discovery + infra + config paths | redirect, verify all paths |
| `BaseUri` | display (`apiAddr`/`dnsAddr`, `APIUri`/`DNSUri`) | `APIEndpoint` (API); DNS-URI has no transport string home | `APIEndpoint` set on discovery + infra + config | API→`APIEndpoint`; DNS-URI needs a home decision |
| `HelloTime` | display `LastUsed` | `Mechanisms[m].LastHelloRecv/Sent` | **DNS only** (`:617`); API hello + outbound not written | **needs added writes** (API + sent) or accept partial |
| `LatestSBeat`/`LatestRBeat` | display `LastUsed` | `Mechanisms[m].LastBeatSent/Recv` | **DNS only**; API not written | **needs added writes** |
| `SentBeats` | **functional**: beat-sequence (`hsync_hello.go`, `hsync_infra_beat.go`), gossip-sent detect (`hsync_bridge.go`) | `BeatSequence` / `Stats.BeatSent` | `Stats` maintained *inside tdns-transport* (live); `BeatSequence` via `RecordBeatSent` (0 MP callers — verify tdns-transport maintains it) | map sequence→`BeatSequence`, verify |
| `DiscoveryFailures` | snapshot only (feeds `ConsecutiveFails`) | `ConsecutiveFails` | `RecordFailure` has 0 MP callers — verify tdns-transport | low usage; verify |

(`LatestError`/`LatestErrorTime`, `LastContactTime`, `BeatInterval`,
`ReceivedBeats` are the (B)-kept / A5-deferred dead-on-read fields — NOT in
this slice.)

## 2. The `.State` sub-problem (the anchor)

`effectiveAgentState(id)` already exists (A3d.0): maps
`transport.Peer.EffectiveState()` → `AgentState` + applies the LEGACY overlay
(participations==0). It is currently **unused**. The slice wires it in:

- **Readers to redirect** (~15): `Agent.EffectiveState()` at `auditor_engine.go:210`,
  `gossip.go:354`, `parentsync_leader.go:1375`, `hsyncengine.go` (×5 RFI
  operational checks); `Agent.IsAnyTransportOperational()` at `start_agent.go`
  (×2), `parentsync_leader.go` (×2), `hsyncengine.go` (×5). Plus the display's
  per-mechanism `effectiveState` computation (`apihandler_agent_distrib.go`,
  which already does its own LEGACY overlay).
- **Rewrite the canonical accessors** `Agent.EffectiveState`/
  `IsAnyTransportOperational` to delegate to `effectiveAgentState` (needs the
  `AgentRegistry`/`PeerRegistry` in scope — today they're pure `*Agent`
  methods; either pass the registry or move callers to `ar.effectiveAgentState`).
- **Stop writing `AgentDetails.State`**: the handler dual-writes to
  `agent.{Api,Dns}Details.State` + `agent.State` become redundant once readers
  use `transport.Peer`; `RecomputeSharedZonesAndSyncState`'s LEGACY/OPERATIONAL
  flips become no-ops (overlay derives them). Remove after readers migrate.
- **Bonus dead**: `Agent.apiState()`/`dnsState()` — 0 callers, delete.
- **INVARIANT proof obligation**: per-transition equivalence of
  `effectiveAgentState` vs today's display State across KNOWN→INTRODUCED→
  OPERATIONAL→LEGACY↔OPERATIONAL, on the testbed (`gossip state`, `peer list`
  State column byte-comparable). DEGRADED/INTERRUPTED: confirmed not shown
  either way.

## 3. The snapshot/`PopulateFromAgent` inversion (residual A4)

Today Agent→transport population flows: `SyncPeerFromAgent`
(`hsync_transport.go:457`, one caller, discovery completion) → `PopulateFromAgent`
← the snapshot accessors `Agent.APIMechanismState()`/`DNSMechanismState()`
(`agent_structs.go`). Once `transport.Peer` is the source (handlers write it
directly, which they already do), this whole path is **dead**:
- delete `SyncPeerFromAgent`, `APIMechanismState`, `DNSMechanismState`,
  `agentStateToTransportStateFn`, and `transport.Peer.PopulateFromAgent`/
  `AgentLike`/`AgentMechanismSnapshot` (tdns-transport) — this is the
  **residual A4 dead-code sweep** the addendum predicted falls out here.
- `GetOrCreatePeer` (the hot-path, no-snapshot variant) stays.

## 4. Bridge-clobber check (the recurring hazard)

`syncHsyncPeerFromAgent` wholesale-replaces `peer.{Api,Dns}Details`
(hsync side) from the Agent. For any spine field the **NG side reads**
(`checkPeerState` reads `hsync.PeerDetails.{State,BeatInterval,LatestRBeat,
LatestSBeat}`), dropping its bridge copy would zero the live NG value — the
same trap that re-filed `BeatInterval` to A5. **So the hsync.PeerDetails spine
fields stay until A5** (bridge teardown). This slice migrates the **MP
`AgentDetails`** spine → `transport.Peer` and redirects MP readers; it does
**not** touch `hsync.PeerDetails` (NG) — that, and unifying NG liveness, is
Stage D / A5.

## 5. Proposed sub-slice decomposition (each = commit, green + -race + probe)

1. **Spine-1 `.State`** — wire `effectiveAgentState`; redirect the ~15
   `EffectiveState`/`IsAnyTransportOperational` callers + the display; rewrite
   the canonical accessors; delete dead `apiState`/`dnsState`. Stop writing
   `AgentDetails.State`/`LastState` + retire the `RecomputeSharedZonesAndSyncState`
   state-flip. **Highest-value, highest-proof-obligation.** Testbed-verify.
2. **Spine-2 Address** — redirect `Addrs`/`Port`/`BaseUri` reads to
   `transport.Peer` (`CurrentAddress`/`APIEndpoint`); decide the DNS-URI display
   home; drop the `AgentDetails` address fields + bridge copies (verify NG
   doesn't read them).
3. **Spine-3 Telemetry** — complete the per-mechanism transport-write coverage
   (add API-side `LastHelloRecv`/beat times; confirm `Stats`/`BeatSequence`/
   `ConsecutiveFails` are tdns-transport-maintained); redirect display `LastUsed`
   + the `SentBeats` sequence use; drop the `AgentDetails` telemetry fields.
4. **Spine-4 Inversion** — delete `SyncPeerFromAgent`/snapshot accessors/
   `PopulateFromAgent`/`AgentLike` (residual A4). Falls out once 1–3 land.

Recommend **Spine-1 first and alone** (it's the anchor and the biggest INVARIANT
risk); reassess 2–4 after it's testbed-confirmed.

## 6. Explicitly OUT of this slice
- Unifying NG liveness (`checkPeerState`/`hsync.PeerDetails`) onto
  `transport.Peer` so DEGRADED/INTERRUPTED is displayed → **Stage D**.
- `hsync.PeerDetails` field removal + the bridge wholesale-replace teardown →
  **A5**.
- The (B)-kept dead-on-read fields (`LatestError`/`Time`, `LastContactTime`,
  `BeatInterval`, `ReceivedBeats`) → A5 / finish-presentation.

## 7. Risks
- **INVARIANT proof for `.State`** is the real risk — many readers, the
  LEGACY↔OPERATIONAL transition, the enum mapping. Mitigation: Spine-1 alone +
  testbed `gossip state`/`peer list` byte-compare before proceeding.
- **Canonical-accessor signature change** (`Agent.EffectiveState` needs the
  registry) ripples to ~15 call sites — mechanical but wide.
- **Telemetry partial coverage** (DNS-only) means Spine-3 must *add* transport
  writes, not just redirect — small behavior surface (display `LastUsed`).
- **No new bridge clobber** as long as we leave `hsync.PeerDetails` alone.
