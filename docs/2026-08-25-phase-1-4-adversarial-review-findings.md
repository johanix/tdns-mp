# Adversarial review of the stacked Phases 1–4 — findings

Date: 2026-08-25
Status: REVIEW FINDINGS, awaiting testbed verification. Companion to
`2026-08-25-phase-1-4-adversarial-review-prompt.md` (the review brief).
Feeds the stacked-testbed checkpoint defined in
`2026-08-24-transport-redesign-consolidated-plan-v4.md` ("Next action").
Each finding carries a **Testbed disposition** line to be filled in
during the pass (CONFIRMED / REFUTED / FIXED / DECLARED-DELTA).

Review basis (static, no deploys):

- tdns-mp `phase-4-c0-gate`, range `388dd3b..92e64a6` (7 code commits),
  plus the pre-range undeployed pair `3fbeffd` (E1.a) and `edfa079`
  (IsRecipientReady fix) where the brief required it.
- tdns-transport `phase-2.6-discovery`, range `892e5de..37c0dfb`.
- Method: full read of every code commit's diff; independent re-derivation
  of the embed-trap census (fields AND promoted methods); mechanical scan
  of every manual mutex window in mp/v2 for early returns; writer/reader
  inventory for every field the stack retired; wire scan of both ranges
  for JSON-tag/verb/payload changes; trace of all five carried
  peer-state-truth fixes through the Phase 2.6 relocation.

Summary verdict: **no wire break, no state-machine regression, no
deadlock on a production path.** Two items should be acted on BEFORE
the checkpoint: Finding 1 trips the plan's own INVARIANT probe as
written, and Finding 2 is an undeclared wire-visible delta that the
probe discipline would otherwise treat as a halt.

---

## Finding 1 — State-display fix is half-implemented: three surfaces
## still show the frozen `Agent.State` shadow (probe-breaking)

Severity: HIGH for the checkpoint (trips a declared INVARIANT probe);
MEDIUM intrinsically (display plane only).
Introduced by: `31d0dd7` (E1.b) — deleted the per-beat wrapper-replace
that refreshed the shadow; stamped only one of four display surfaces.

**Defect.** Post-stack, `Agent.State` has exactly ONE production
writer: the `GetZoneAgentData` stamp (`agent_utils.go:280`, from
`effectiveAgentState`). Three other surfaces still read the shadow raw:

1. `peer zones` — `listPeerSharedZones` reads and emits it
   (`apihandler_agent_distrib.go:653`, emitted at `:687`).
2. `hsync agent-status` — returns `resp.Agents = []*Agent{agent}`
   (`apihandler_agent.go:339`) marshaled via `Agent.MarshalJSON`,
   which serializes the shadow (`agent_utils.go:479`).
3. `hsync locate` — same shape (`apihandler_agent.go:391`).

A never-stamped view has the AgentState zero value; the enum starts at
`iota + 1` (`agent_structs.go:21`), so `AgentStateToString[0]` is the
missing key ⇒ **empty string** ("" in the state column; `"State": 0`
in agent-status JSON). Pre-stack the same columns showed the NG-lagged
value — imperfect but non-empty; v4 declares the disagreement fixed.

**Failure scenario.** Deploy the stack; wait for a fully OPERATIONAL
gossip matrix; run `agent peer zones`. Every dynamically discovered
peer shows state "" while `peer list` and `gossip state` show
OPERATIONAL. The v4 probe set asserts "peer list / peer zones —
address columns and State agree with gossip … if it still appears, it
is a regression" ⇒ the checkpoint halts on its own discipline.

**Related nit (same probe surface).** `ListKnownPeers` applies the
LEGACY overlay to KNOWN as well (`apihandler_agent_distrib.go:375`,
`:457`) while `effectiveAgentState` overlays only
OPERATIONAL/INTRODUCED (`agent_view.go:106`). A zero-participation
peer at KNOWN shows LEGACY in `peer list` but KNOWN in gossip —
transient (between discovery and first successful beat), narrow, but a
peer-list-vs-gossip disagreement of exactly the probed kind.

Confidence: high (writer inventory exhaustive). Settled by: first
`peer zones` after convergence; also reproducible in a 5-minute
two-node local run. Fix shape (not applied): stamp from
`effectiveAgentState` at the three read sites, as `GetZoneAgentData`
already does — or declare the delta in v4 and park the fix for F2's
DTO rework.

**Testbed disposition:** _pending_

---

## Finding 2 — agent-to-agent beats now carry wire `"sequence": 0`
## forever (undeclared wire-value delta; answers v4's open D0 question)

Severity: MEDIUM (no functional consumer; wire-visible, undeclared).
Introduced by: `234933d` (Phase 2) + `31d0dd7` (E1.b) in combination.

**Defect.** `beatOutboundSequence` (`hsync/transport_peer.go:85–92`)
reads `hsync.PeerDetails.SentBeats`. The stack deleted its last
production writers: Phase 2 removed the send-path `SentBeats++`
(pre-range `hsync_transport.go:1681`/`:1726`), E1.b removed the bridge
copy-back that mirrored AgentDetails→PeerDetails. The engine beat path
(`sendBeatToPeer` → bridge `SendBeat` → `BeatRequest.Sequence`,
wire tag `"sequence"`) therefore sends 0 on every beat. Inconsistent
with the infra loop, which uses the live transport counter
(`MechanismBeatSequence("DNS")`, `hsync_infra_beat.go:75`).

**Consumer trace (complete).** `HandleBeat` (transport
`handlers.go:166`) never reads Sequence; `routeBeatMessage` never
reads it; responses echo it; `beatTransportUsed` uses the
transport-side counters. Nothing acts on the value — the freeze is
functionally benign. But it is a wire-visible VALUE change absent from
v4's predicted-delta list; in the mixed fleet, old nodes send
incrementing sequences while new nodes send 0. This also closes v4's
open D0 question ("confirm whether anyone still consumes that
sequence"): nobody does, and it has been frozen since Phase 2.

Confidence: high. Settled by: capture one beat exchange in each
direction across the version boundary; confirm no old-side reaction.
Action before C1: add to v4's predicted deltas, or repoint the reader
at `MechanismBeatSequence` like the infra loop (one-line fix; wire
then resumes incrementing).

**Testbed disposition:** _pending_

---

## Finding 3 — E1.b aliasing created formal data races on the send
## paths (unlocked reads of the now-shared view)

Severity: MEDIUM as a formal race; operational impact likely benign.
Introduced by: `31d0dd7` (E1.b) — the reads pre-existed, but they used
to target a bridge-private deep copy; now they target the live shared
object that `OnPeerDiscovered` writes concurrently.

**Defect.** `SendHelloWithFallback` / `SendBeatWithFallback` read
`agent.ApiMethod` / `agent.DnsMethod` / `agent.State` without the peer
mutex (`hsync_transport.go:1471`, `:1500`, `:1576`, `:1589`, `:1625`),
while the OnPeerDiscovered callback writes those fields under
`agent.Mu` (`hsync_transport.go:488–491`) on every discovery
completion.

**Failure scenario.** A chunk-notify or hello-triggered re-discovery
completes concurrently with a beat tick. Worst cases: stale bool read
(benign, next tick corrects); torn read of `agent.State` (string, two
words) into the beat payload — formally undefined behavior in Go.
The unit suite's `-race` is green only because nothing exercises
discovery concurrently with the beat loop.

Confidence: high that the race exists; low-medium that it bites.
Settled by: one testbed node on a `-race` build through a restart →
rediscovery → beat overlap (extends the plan's existing testbed-prep
`-race` mandate to a short live soak).

**Testbed disposition:** _pending_

---

## Finding 4 — CARRIED (not introduced): partial re-discovery wipes a
## stored TLSA; the inbound-mTLS gate then fails closed

Severity: LOW-MEDIUM today (latent — fleet is DNS-only); flagged for
the C5/D0 window. Carried verbatim from pre-range MP code through
Phases 2.5/2.6 ("replace semantics" was a deliberate carry).

**Defect.** `RegisterDiscoveredPeer` stamps
`SetMechanismTLSA("API", result.TLSA)` unconditionally in the
apiUsable branch (`transport/discovery.go:325`). A re-discovery where
URI+SVCB resolve but the TLSA lookup transiently fails (result.TLSA ==
nil, Partial) replaces a good pinned cert with nil. The inbound gate
401s on nil TLSA (`apirouter_sync.go:88–95`, fail-closed). Nothing
re-triggers discovery on TLSA absence (retrier keys on NEEDED; the
chunk-kick keys on a missing JWK), so inbound API from that peer stays
dead until a manual `peer reset`. JWK has non-empty wipe-protection
(`discovery.go:347`); TLSA does not.

**Trigger on the testbed:** the planned fox-NS break/restore during
any re-discovery (chunk-kick / hello-from-unknown) is exactly this
scenario — relevant only if an API mechanism is ever exercised.

Confidence: high on mechanism; low on live impact today. Suggested
disposition: give TLSA the same non-empty gating as JWK in the C5/D0
slice; note the asymmetry in D0's census.

**Testbed disposition:** _pending_

---

## Finding 5 — dead but loaded: two exported task constructors still
## gate on the retired shadow (the IsRecipientReady shape, U1000-blind)

Severity: LOW (zero callers today); a booby trap for Stage C/D work.

**Defect.** `CreateOperationalAgentTask` and `CreateAgentUpstreamRFI`
(`agent_utils.go:432–453`) build preconditions
`agent.State == AgentStateOperational` — reading a field with no
functional writer (Finding 1). Verified zero callers. They survived
the Phase 3d sweep because staticcheck U1000 does not flag exported
symbols. The two production RFI preconditions were correctly repointed
to `isAgentOperational` (`agent_utils.go:360`, `:395`).

**Failure scenario (future).** A new deferred action wired through the
convenient existing constructor never fires on an idle fleet (shadow
unstamped) — the third silent-stall instance of this bug class.

Disposition: delete both, or repoint to `isAgentOperational`, in the
D0 slice. No testbed action needed.

**Testbed disposition:** _n/a (code hygiene)_

---

## Finding 6 — Phase 2's operator-facing pointer is false:
## `hsync-peer-status` is a "Found 0 peers" stub

Severity: LOW (doc/UX). The stub predates the range; the CLAIM is
`234933d`'s.

**Defect.** Phase 2 dropped the CLI `peer status` per-transport block
with the justification "working heartbeat data lives in
hsync-peer-status (HsyncPeerInfo, backed by HsyncDB)"
(`cli/hsync_cmds.go:541–546`); the server case returns a hardcoded
stub (`apihandler_agent_hsync.go:88–89`) and nothing populates
`HsyncPeers`. The deleted CLI data was genuinely dead over the wire
(MarshalJSON never serialized it), so nothing functional was lost —
but `tdns-cli agent hsync peers` reports "No peers found in database"
on a healthy fleet.

Disposition: either implement the endpoint (F2 presentation finish) or
fix the comment/help text so operators are not pointed at a stub.

**Testbed disposition:** _pending (confirm operator-facing effect)_

---

## Informational notes

- **hsync-internal gossip fallback.** With `deps.Gossip == nil` the
  engine defaults to hsync's own table (`hsync/engine.go:28`), whose
  `RefreshLocalStates` does `peer.Mu.RLock()` then calls
  `EffectiveState()` which RLocks the same mutex again
  (`hsync/gossip.go:217–219`) — the recursive-RLock writer-starvation
  pattern — and reads the retired store. Production always wires the
  port (harness-only exposure). Ensure D0's `GossipStateTable`
  deletion takes the engine default with it.
- **`removePeerView`** (`agent_structs.go:166`) drops the ar.S view
  and the transport peer but not payload-crypto keys, gossip rows, or
  election state. Irrelevant while `RemovePeer` has no production
  caller; relevant the day operator `peer delete` is built (v4 open
  decision 5).
- **Pre-existing, for the record** (untouched by the stack): the
  inbound API beat handler records no `LastBeatRecv("API")` evidence
  (DNS paths do); `peer.LastBeatReceived` / `LastHelloReceived` are
  plain-field writes without the peer lock (`hsync_transport.go:688`,
  `:765`).

---

## Verified sound (checked, no defect found)

- **Embed trap held.** Zero field-level `.ApiDetails`/`.DnsDetails`
  references outside hsync/ (comments only). The promoted-METHOD
  variant has exactly one candidate — `hsync.Peer.EffectiveState()` —
  and no MP code calls it through the view. Phase 2's hand enumeration
  survives independent re-derivation.
- **Wire compatibility.** Zero JSON-tag, payload-struct, or
  verb-string changes in either range. The golden suite locks
  byte-exact marshals of all 13 payload types plus the
  `DetermineMessageType` verb set. The only wire-visible change in the
  stack is Finding 2's frozen sequence VALUE.
- **Lock discipline.** Mechanical scan of every manual mutex window in
  mp/v2: no `return` between any acquire and its release — the
  SendBeatWithFallback leak class is structurally gone (the send paths
  no longer take `agent.Mu` at all). No transport calls under a peer
  mutex; no ar-map/engine-map acquisition-order inversion.
- **Carried invariants (Fixes A/B/C/E + OnDiscoveryFailed).**
  OPERATIONAL only on outbound beat round-trip success
  (`hsync_transport.go:1610`, `:1647`; all three inbound routes are
  evidence-only). Decay-on-read intact on transport.Peer. Fix C
  partial-discovery keeps the mechanism NEEDED end-to-end, including
  through `DiscoverPeer`'s ≥KNOWN short-circuit (checked against every
  caller's state precondition). Fix E local-mechanism gating survived
  the 2.6 move (`SetSupportedMechanisms` / `IsTransportSupported`).
  `OnDiscoveryFailed` fires on the single error path of
  `attemptDiscovery`; its no-regress guard is correct.
- **New/dead seams.** `OnPeerDiscovered` fires once, at the end of
  registration, no locks held; concurrent double-discovery converges
  via Upsert-atomic view materialization; it can fire for a
  registered-but-unusable peer, but the callback derives `anyUsable`
  correctly and the retrier still revisits. `OnPeerRemoved`'s "no
  production caller" is TRUE (tests only). `peer reset` works
  end-to-end — the API handler resets canonical transport state before
  `Rediscover` (`apihandler_peer.go:120–130`); a candidate finding
  raised against `Rediscover` alone was refuted by this.
- **Phase 3d sweep.** All four spot-checked "pre-existing orphan"
  deletions had zero callers already at `388dd3b`; the flush-threshold
  consts were decorative (all four `FlushDomain` sites survive); no
  reflection / interface-satisfaction hazard applies.
- **Declared deltas #2/#3/#4 implemented as described:** distrib
  NEEDED row from the canonical store; dual-mech `PreferredTransport`
  ends "API" (callback re-stamp after transport's inline "DNS");
  stale offered-flag via persistent ContactInfo. Delta #1 is the
  half-implemented one (Finding 1).
- **2.5→2.6 crypto seam.** JWK non-empty merge gating moved into
  transport verbatim (`discovery.go:347`); `agentViewForIdentity`
  capability seeding matches `MarkNeeded`'s.
- **edfa079 (IsRecipientReady) is complete.** The predicate reads the
  canonical store (`hsync_transport.go:121–135`); the sibling sweep
  found only Finding 5's caller-less constructors.

---

## For the testbed pass (what static review cannot determine)

Cross-references the v4 probe set; items 1–2 map to Findings 1–2.

1. `peer zones` state column on a converged fleet (Finding 1) —
   confirm, then fix-before-C1 or declare.
2. Capture one beat exchange each direction across the version
   boundary (Finding 2) — confirm nothing old-side reacts to the
   sequence freeze.
3. One node on a `-race` build through restart → rediscovery → beat
   overlap (Finding 3).
4. Concurrent-discovery interleaving in the OTHER direction from the
   OnDiscoveryFailed guard: can a STALE successful DiscoverAgent
   result (old address) land after a fresh one via last-wins
   `SetDiscoveryAddress`? Only concurrent live discoveries show this.
5. First-ever live run of the decay ladder on stacked readers:
   fox-NS break/restore → OPERATIONAL→DEGRADED→INTERRUPTED→recovery;
   include the TLSA-wipe trigger (Finding 4) if an API mechanism is
   ever exercised.
6. Post-restart KNOWN→OPERATIONAL gap: confirm
   `retryPendingDiscoveries` → `startHelloRetrier` closes it (v4
   already lists this as an opportunistic check) — this also exercises
   the hello-retrier cancel bookkeeping under a real restart.
7. Infra liveness on stacked code: combiner/signer rows never dip
   below OPERATIONAL between 10-minute beats (600 s LivenessInterval,
   testbed-confirmed only pre-stack).
8. Operator-tooling sweep: run every runbook probe command once on the
   stack (`gossip state`, `peer list`, `peer zones`, `distrib list`,
   `zone edits list`, `hsync peers`) — Findings 1 and 6 both surfaced
   from display paths no unit test renders.

## Recommended pre-checkpoint actions

1. Finding 1: stamp the three surfaces from `effectiveAgentState` (or
   explicitly declare the empty-state delta in v4 before deploying).
2. Finding 2: add the frozen beat sequence to v4's predicted-delta
   list (or take the one-line `MechanismBeatSequence` repoint).
3. Fold Findings 4/5 and the informational notes into the D0 census so
   the PeerDetails deletion slice closes them.
