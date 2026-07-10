# Road to Stage C — finish the transport.Peer consolidation, then build the Stage-C starting point

Date: 2026-06-14
Status: PROPOSED. A from-here-to-Stage-C plan that replaces the
remaining INVARIANT microstep grind with a smaller number of
consequential commits, grounded in a full code-surface measurement
(2026-06-14, tip tdns-mp `e0186be`, tdns-transport `892e5de`).
Supersedes, for the END/A5/discovery-prep work, the corresponding
sections of `2026-06-11-transport-redesign-consolidated-plan-v3.md`
(v3 stays authoritative for Stage C itself and everything it specifies
that this doc does not change). Where this doc and v3 differ for the
work below, **this doc wins.**

## Why this plan exists (the decision behind it)

The redesign has run ~12 weeks / 475 commits and is still inside Stage
A. The method here is chosen per the property that decides it: the
"keep it compiling and functional at every microstep" discipline pays
off **where intermediate behavior is oracle-visible** (wire format,
liveness deltas — Stage C and the testbed-verified bug work) and not
where it is invisible (INVARIANT state-store consolidation, where each
intermediate must be hand-designed coherent — dual-write windows, shadow
fields, bridge converters — with nothing observable to verify).

So this plan is **hybrid by design**:
- The remaining **consolidation** (embed finish + bridge teardown +
  AgentDetails removal) switches to *delete-the-scaffolding* commits:
  larger, mechanical, verified by the compiler + one testbed pass,
  NOT a sequence of individually-coherent dual-state intermediates.
- **Stage C** (the opaque-message seam — wire-observable, mixed-fleet
  risk) stays incremental, exactly as v3 specifies. This plan stops at
  Stage C's doorstep.

### What the measurement found (the reason this is now low-risk)

The consolidation is FAR more done than "before the embed" implies.
Verified 2026-06-14:
- **END.0 DONE + testbed-confirmed** (`dbcb166`+`7d1ec60`): transport.Peer
  is the canonical connection-state store.
- **D2.5 DONE + testbed-confirmed** (`6b97300`+`74368c0`): the hsync
  engine's send-gate triggers (`agentNeedsHello`/`fastBeatAttempts` in
  `hsync/hello.go`) read `transport.Peer` via `mechPeerState`; the END.0
  dual-write to `hsync.PeerDetails.State` is RETIRED.
- **END.1 E1.a DONE** (`3fbeffd`): `Agent` embeds `*hsync.Peer`; ID/Mu/
  Zones/Deferred/ApiMethod/DnsMethod/IsInfraPeer/LastState all PROMOTE
  from the embed (one copy). Three type aliases keep ~440 call sites
  compatible. NOT yet deployed (pure structural intermediate).
- **All 11 `AgentDetails` fields are write-only or DEAD** — ZERO
  functional read sites in production. `Agent.MarshalJSON` already omits
  `*AgentDetails`, so it is dead over the wire too.
  **[CORRECTED 2026-07-10: the measurement missed ONE functional reader
  — the ReliableMessageQueue's `IsRecipientReady` gate (`isTransportReady`,
  hsync_transport.go) read `{Api,Dns}Details.State`, silently deferring
  every queued zone update to an agent recipient until the 24h expiry.
  Fixed pre-Phase-1 (mp `edfa079`): the gate now reads `transport.Peer`
  raw mechanism state. The ZERO-readers claim holds as of that commit
  for the 11 FIELDS. Separately, the `ApiDetails`/`DnsDetails` POINTERS
  are read as presence-gates in three places (`apirouter_sync.go` inbound
  mTLS, the distrib display row-gates + state fallback, the dead
  `NewAgentSyncApiClient`) — Phase 2's struct deletion must replace those
  semantically (e.g. a transport-side has-mechanism predicate), not just
  delete writes.]**
- The deep-copy bridge is 8 functions, 1 already dead (`agentToHsyncPeer`).

Translation: the embed's hard, inventive part (make transport canonical
without breaking the live state machine) is **already paid for and
verified**. What remains is mostly *deleting the now-dead duplicate
stores and the bridge that kept them in sync* — exactly the work that
is cheap to do in a batch and expensive to do as INVARIANT slices.

Restart tag for the whole block: `end0-complete-pre-d2`
(mp `2f00cca` / transport `892e5de`). Current tip `e0186be` is E1.a +
docs on top of that.

## Scope decision (what this plan covers, and what it deliberately does NOT)

**IN — take us to the Stage-C starting point:**
- Phase 1: E1.b — one allocation per peer, two typed views, bridge gone.
- Phase 2: AgentDetails struct deletion + write-site cleanup (was A5 +
  END.5 telemetry orphans).
- Phase 3: inbound-pipeline collapse (END.3) + `RemoteAgents` removal
  (END.4) + the dead-code sweep (END.5) + A5 residue (`OnPeerRemoved`).
- Phase 4: the Stage-C **prerequisites only** (C0 gate): golden-wire
  test, standalone builds green, mixed-fleet runbook, envelope-timing
  decision. This is the "starting point for Stage C" the prompt asks for.

**EXPANDED SCOPE — Phase 2.5 IN; discovery relocation (Phase 2.6) per
open decision #5.** The prompt allows extending through "discovery."
- **Phase 2.5 (IN): finish `agentMeta.Crypto` → `transport.Peer`
  crypto-slot migration** (the addendum's deferred "E1" crypto move).
  Small, pure consolidation (an MP sidecar duplicating a transport-owned
  concept). After it, `transport.Peer` owns ALL per-peer
  connection+crypto state — a clean seam for Stage C.
- **Phase 2.6 (per decision #5): relocate the discovery PROCESS into
  transport.** See the gate/process principle below.

**Gate ≠ process.** The *gate* — "which peers do I need?" — is MP: it
needs HSYNC3/zones, which transport never knows. MP computes shared-zone
participants, finds an unknown needed peer, and declares intent via
`transport.DiscoverPeer(identity)` / setting the peer NEEDED on
`transport.Peer`. The *process* — lookups → resolve → register → KNOWN —
is transport: it needs only an identity. This is addendum §1 ("the engine
declares a need by setting `transport.Peer` to NEEDED; the discovery
handler reads NEEDED out of the `PeerRegistry`").

Transport is already equipped for the process: it imports `tdns/v2`
(`imr.go:37`, `init.go:17`); `transport.Imr` (embeds `*tdns.Imr`)
implements every lookup (`LookupAgentJWK/KEY/APIEndpoint/DNSEndpoint/
TLSA/ServiceAddresses`); `DiscoverPeer` + the `DiscoveryDriver` seam
(`manager.go:130-158`) are built to be retired when the process lands.

Residual MP-coupling in the process (`RegisterDiscoveredAgent`, measured
2026-06-14): its real work already writes `transport.Peer`
(ContactInfo/mechanism-KNOWN/address/usability). Its only non-transport
writes are crypto (Phase 2.5 moves it to `transport.Peer`),
`ApiMethod/DnsMethod` (= `transport.Peer.HasMechanism`, addendum §4), and
`ar.S.Set` (materialize the `*Agent` view — what `OnPeerDiscovered`
already does). So after Phase 2.5 the process is transport-only code
still living in the MP package; Phase 2.6 relocates it.

## The method (how each phase is executed and verified)

Not "compile + functional at every commit." Instead, per phase:

1. **One branch per phase off the prior phase's verified tip.** A phase
   may have a RED window internally (does not build mid-phase); that is
   allowed and expected. The phase's FINAL commit builds + passes.
2. **The compiler is the primary oracle for deletions.** Removing a
   store/field/bridge func is compiler-proven complete: every dangling
   reference is a build error. This is why batched deletion is SAFE here
   — Go's type checker enumerates the work for you.
3. **Two test oracles before the testbed:**
   - `tdns-transport/v2` standalone `go build ./... && go test ./... -count=1 -race`
     (validates the transport target IN ISOLATION — the Gate-2 property,
     our defense against "N bugs at once").
   - `tdns-mp/v2` `go test ./... -count=1 -race` incl. all
     `TestTransportBoundary_*` + hsync suites, after the phase builds.
4. **One testbed checkpoint per phase** (not per commit): deploy to
   `cpt`, run the INVARIANT probe set, confirm convergence, THEN tag and
   start the next phase. Probe set (byte-comparable on a healthy fleet):
   `agent gossip state -z espresso.mp.axfr.net`, `agent peer list`,
   `agent peer zones`, `agent peer reset <id>` (NEEDED→KNOWN→OPERATIONAL),
   combiner/signer stay OPERATIONAL. Testbed: `ssh -A root@mptest92.axfr.net -p 5101`,
   log `/var/log/tdns/tdns-mpagent.log`.
5. **Tag at each phase boundary** (`phase-1-e1b-complete`, …) so a bad
   reconverge rolls back to a known-good fleet, not into a half-state.

Binding throughout (carried from v3 / addendum §7, NON-NEGOTIABLE):
- **Lock order:** `AgentRegistry.mu → the ONE peer mutex (hsync.Peer.Mu
  after E1.b) → transport.PeerRegistry → transport.Peer`. Never hold a
  registry/peer mutex across a transport call. `-race` every phase.
- **Single writer per peer field.**
- Never touch `tdns/tdns/` (v1), `tdns/obe/`, `tdns/music/`.
- `gofmt -w` after every .go edit. `git -C <repo>`. No amend. No
  Co-Authored-By. Feature branch only; never push main / merge alone.
- A recommendation is not approval — operator decides at each phase gate.

---

# Phase 1 — E1.b: one allocation per peer, kill the deep-copy bridge

**STATUS 2026-07-10: CODE DONE (mp `31d0dd7` on branch `phase-1-e1b`),
build + full suite `-race` green, TESTBED CHECKPOINT PENDING (testbed
unavailable at implementation time). The branch was cut from
`transport-redesign-v1-A` @ `388dd3b` precisely so the branch point marks
where the pre-Phase-1 tip (E1.a + the `edfa079` readiness fix, both
undeployed) must be testbed-verified before Phase 1 is declared. Tag
`phase-1-e1b-complete` deferred until the operator confirms. Predicted
delta for the checkpoint: `peer status` State now derives from
`effectiveAgentState` (same source as peer list/gossip) instead of the
stale NG-lagged shadow; everything else INVARIANT. Findings during
implementation: the old bridge's per-store/hello/beat wrapper-replace
was silently wiping MP-only view fields (meta/Api/ErrorMsg) — crypto
survived only because RegisterDiscoveredAgent rebuilt it; fixed
structurally by materializeAgentView's never-replace contract.**

**Goal (the achievable end-state, per v3's re-census — NOT "one map"):**
The `*Agent` in `AgentRegistry.S` and the `*hsync.Peer` in
`hsync.Registry.S` reference the SAME underlying `hsync.Peer`
(`agent.Peer == that peer`). Two typed views, ONE allocation, NO
field-copying bridge. Two maps PERSIST by necessity — the hsync engine
(`hsync/` pkg) cannot import the main package, so its map must stay
`[PeerID]*hsync.Peer` (22 engine sites force this); MP's map stays
`[AgentId]*Agent` (38 sites want the MP-only fields). They become
consistent via the shared pointer, not via the bridge.

**Why this is now mostly deletion, not design:** E1.a already made the
discovered path share the pointer (`hsyncPeerToAgent` → `&Agent{Peer:
peer, …}`). The connection-state fields the bridge used to copy
(`ApiDetails`/`DnsDetails`/`State`) are ALL write-only/dead (measurement
§2) — nothing functional reads them — so the copying is already pointless
motion. The risk is concentrated in the ONE shared mutex and the
create/update paths, not in inventing new behavior.

**Steps (one branch; internal RED ok; final commit green):**
1. Make pointer-sharing UNIVERSAL on every peer create/update path:
   - discovered: the `OnPeerDiscovered` → `hsyncPeerToAgent` path already
     shares the pointer (E1.a). **BUT [added 2026-07-10] the
     `RegisterDiscoveredAgent` create-if-missing branch
     (`agent_discovery.go:310`) still allocates a FRESH `hsync.NewPeer`
     for an agent not yet in `ar.S`** — it must wrap the engine's
     existing peer, or the two views diverge on exactly the path
     Phase 1 exists to unify. "Already shared" is only half the
     discovered path.
   - `MarkNeeded`/engine-created peers: ensure the `*Agent` view wraps the
     engine's `*hsync.Peer`, not a fresh one.
   - infra peers (`combiner_peer.go`/`signer_peer.go`): these live ONLY in
     `ar.S` (never `hsync.Registry.S` — the engine loop `hsync/beat.go:42`
     never iterates them, by design; the MP infra-beat loop
     `hsync_infra_beat.go:49` iterates `ar.S`). Allocate their
     `hsync.Peer` once via `NewAgent`/`hsync.NewPeer` and keep the single
     pointer. NewAgent (`agent_structs.go:102`) already does this shape.
2. Delete the deep-copy bridge (compiler will confirm completeness):
   - `syncHsyncPeerFromAgent` (2 callers), `syncHsyncPeerToAgent` (1, the
     `OnPeerStored` hook), `persistAgentAndPeer`'s copy (3 callers),
     `hsyncDetailsToAgent`/`agentDetailsToHsync` (the type-bridge
     converters), `agentToHsyncPeer` (already dead).
   - Reduce `hsyncPeerToAgent`/`agentForTransport` to trivial wrappers
     (return the `*Agent` view of an existing shared peer) or remove.
   - Rework the `OnPeerStored`→`syncHsyncPeerToAgent` hook
     (`hsync_bridge.go:~309`): with shared pointers there is nothing to
     sync; the hook becomes a no-op or is removed (it may still need to
     ensure the `*Agent` view exists in `ar.S` for an engine-created
     peer — keep ONLY that, as a view-materialization, not a copy).
3. **END.2 is absorbed here** (per v3): decide `ar.S`'s fate. Recommended
   (and assumed by this plan): `ar.S` SURVIVES as the MP `*Agent` view
   map; the embedded `hsync.Registry.S` is the engine's `*hsync.Peer`
   map; both hold views of the same allocations. Do NOT try to collapse
   to one Go map — the re-census proved it impossible (different types,
   different packages). The `AgentRegistry.S`/`mu` shadow of the embedded
   registry stays (it IS the MP view map), but its CONTENTS now share
   pointers with the embed.

**Concurrency note (the real risk):** after this, there is ONE mutex per
peer (`hsync.Peer.Mu`, promoted to `Agent.Mu` via the embed). Audit that
no path takes `Agent.Mu` and a separate `hsync.Peer.Mu` (there is only
one now, but verify no code dereferences `agent.Peer.Mu` and `agent.Mu`
as if distinct). `-race` is the gate.

**Verify:** transport standalone green; tdns-mp build + `-race` + all
boundary/hsync tests; testbed checkpoint (INVARIANT — peer list/gossip/
zones byte-comparable, reset works, infra OPERATIONAL). Tag
`phase-1-e1b-complete`. **This is the riskiest phase — operator deploys
and confirms before Phase 2.**

---

# Phase 2 — delete AgentDetails (the dead store) + telemetry write cleanup

**STATUS 2026-07-10: CODE DONE (mp `234933d` on branch
`phase-2-agentdetails`, cut from phase-1 tip `66be160`), full suite
`-race` green, net −250 lines. TESTBED CHECKPOINT PENDING (stacked with
Phase 1's; operator chose to continue without testbed). Step-1a
decisions executed as approved: TLSA-as-gate (mTLS), NEEDED-not-skip-row
(distrib display — the predicted delta), CLI heartbeat block dropped
(dead over the wire since END.0). Two findings: (1) the compiler could
NOT prove this deletion complete — deleting the shadows makes
`agent.{Api,Dns}Details` silently re-resolve to the embedded
hsync.Peer's `*hsync.PeerDetails` (same field names, the retired NG
store); every site was hand-enumerated + a grep-zero check added; the
Stage-D/Phase-3 hsync.PeerDetails deletion removes the trap for good.
(2) SendBeatWithFallback's failure branches leaked agent.Mu — harmless
pre-E1.a (per-call wrapper mutex), a guaranteed first-failed-beat
deadlock since E1.a; deleted with the telemetry blocks. Residual: the
`parentsync_leader.go` transport-label display reads were already
transport-based; `Agent.State` shadow survives as the DTO display field.**

**Goal:** remove `AgentDetails` entirely. All 11 fields are write-only/
dead (measurement §2), so this is the cleanest possible deletion: rip out
the struct, and the compiler lists every write site to delete.

**Steps (one branch):**
1. Delete the write sites (they feed nothing — 0 FIELD readers as of the
   2026-07-10 `edfa079` fix; see the corrected measurement note above):
   - `HelloTime` (hsync_transport.go:673,1515,1550),
     `LastContactTime` (×7), `BeatInterval` (hsync_beat.go:21,25),
     `SentBeats` (hsync_transport.go:1654), `ReceivedBeats`
     (hsync_beat.go:20,24), `LatestRBeat` (hsync_beat.go:19;
     hsync_transport.go:754,…), `State`/`LastError*`/`DiscoveryFailures`/
     `LatestSBeat` (already dead).
   - These are telemetry. Their REAL homes already exist on
     `transport.Peer` (`Stats`, `LastHelloRecv/Sent`, `LastBeatRecv/Sent`,
     `ConsecutiveFails`) and are already maintained (S3 + Fix A/B/C). So
     deletion loses NOTHING observable — verify each by confirming the
     transport-side equivalent is written on the same path.
1a. **[added 2026-07-10] Presence-gate reads need SEMANTIC replacements,
   not deletion.** Three sites read the `ApiDetails`/`DnsDetails`
   POINTERS as "does this peer have this mechanism" gates; the compiler
   will flag them at step 2, but the replacement is a decision, not
   mechanics — decide each BEFORE the batch (writer-path-audit spirit):
   - `apirouter_sync.go:84` — the inbound-mTLS middleware rejects on
     `agent.ApiDetails == nil`. Replace with a transport-side predicate
     (peer has an API mechanism / `APIEndpoint != ""` / TLSA present via
     `cryptoFor("API")`, which the same block already consults). This is
     authz-adjacent: decide the predicate deliberately, don't improvise
     it mid-compile. (API transport is not in production use today, so
     risk is low — but the gate's semantics must be stated.)
   - the distrib display row-gates (`agent.{Api,Dns}Details != nil`,
     `apihandler_agent_distrib.go:354,439`) + the S1b `effectiveState`
     fallback reads (`:369,452`). Deleting the fallback ends S1b's
     transitional safety; predict IN WRITING what a peer not yet in the
     PeerRegistry displays (skip the row vs show NEEDED) — this is a
     small predictable EXPLAINED DELTA, fold it into the existing
     Phase-2 delta prediction alongside the CLI heartbeat line.
   - `NewAgentSyncApiClient` (`agent_setup.go`, 0 callers, kept
     "future-ready") — delete outright rather than migrate; its
     replacement is designed when the API mechanism owns its client
     (v3 E1 note).
2. Delete the `AgentDetails` struct and the `Agent.ApiDetails`/
   `Agent.DnsDetails` fields. Compiler-prove complete.
3. **CLI `peer status` check:** confirm the heartbeat line
   (`cli/hsync_cmds.go:558-560`) — its data path was already verified
   dead over the wire in END.0 (`Agent.MarshalJSON` omits AgentDetails).
   If the CLI still references the fields, repoint to the
   `transport.Peer` Stats/timestamps via the existing API response, or
   drop the line if the server no longer sends the data. Decide at
   execution: feed from `transport.Peer` (preferred) vs drop.
4. Retire the `RecomputeSharedZonesAndSyncState` LEGACY/OPERATIONAL flip
   if any residue remains (the LEGACY overlay derives it MP-side).

**Verify:** as Phase 1. EXPLAINED DELTA possible ONLY in the CLI
`peer status` heartbeat line (predict in writing before deploy: either
identical via transport feed, or the line is dropped) and in the distrib
display for a peer not yet in the PeerRegistry (step 1a: the S1b
fallback ends — predict skip-row vs NEEDED). Everything else
INVARIANT. Tag `phase-2-agentdetails-gone`.

---

# Phase 2.5 — agentMeta.Crypto → transport.Peer crypto slots (the cheap discovery-prep)

**Goal:** retire the transitional `agentMeta.Crypto` sidecar; move
per-mechanism crypto (`KeyRR`/`TlsaRR`/`JWKData`/`KeyAlgorithm`) onto
`transport.Peer` crypto slots (`LongTermPubKey`/`KeyType`/`TLSARecord`
already exist; add per-mechanism slots if needed). This is the
addendum's deferred "E1 crypto move," done now because it is pure
sidecar-deletion and it makes `transport.Peer` the SOLE per-peer state
owner before Stage C.

**Why now (not Stage E):** the crypto is *written* by discovery
(`RegisterDiscoveredAgent`, the sole writer per addendum §8.5) and *read*
by the TLS/JOSE setup paths. Moving its STORAGE to transport.Peer does
NOT require moving discovery — discovery (still MP) writes
`transport.Peer` crypto directly instead of the sidecar. That is the
same shape as every other field we've rehomed. It removes the last
MP-side per-peer state duplicate.

**Steps (one branch):**
1. Add the per-mechanism crypto slots to `transport.Peer` if the
   existing `LongTermPubKey`/`KeyType`/`TLSARecord` are insufficient
   (measurement: API uses TLSA, DNS uses JWK/KEY — likely a small
   per-mechanism crypto struct mirroring `mechCrypto`).
2. Repoint the writer (`RegisterDiscoveredAgent` crypto block) to write
   `transport.Peer`.
3. Repoint the readers (TLS client setup `agent_setup.go`, inbound
   mTLS verify `apirouter_sync.go`, JOSE/HPKE key registration) to read
   `transport.Peer`. **Touches live TLS/JOSE paths — flag for testbed
   on API-transport peers; DNS-only fleets less affected** (per §8.5b's
   warning, which bit a prior crypto slice).
4. Delete `agentMeta.Crypto`, `mechCrypto`, `ensureCrypto`/`cryptoFor`.
   `agentMeta` may become empty except `Api`/`InitialZone` — if so, fold
   those out too and delete `agentMeta` (the addendum's end-state).

**Verify:** as Phase 1, PLUS exercise an actual discovery + secure
exchange on the testbed (the TLS/JOSE paths are the risk). INVARIANT.
Tag `phase-2.5-crypto-rehomed`.

**Decision gate (operator):** Phase 2.5 is additive — if it overruns it
can defer to Stage E without affecting Phases 3-4. Decide at the Phase 2
gate. NOTE: 2.5 is also the PREREQUISITE for Phase 2.6 (option C) — it
repoints discovery's crypto/capability writes to `transport.Peer`, which
is what leaves the discovery *process* as transport-only code.

---

# Phase 2.6 — relocate the discovery PROCESS into transport (IN scope — decision #5 = C)

Prereq: Phase 2.5.

**Principle: gate stays MP, process moves to transport.** MP keeps the
HSYNC3 gate (compute shared-zone participants → find unknown needed peer)
and expresses intent via `transport.DiscoverPeer(identity)` /
`transport.Peer` NEEDED. The lookups + resolve + register + KNOWN
promotion move into transport.

**Steps (one branch):**
1. De-dup the lookups: delete MP's `Lookup*` (agent_discovery.go's IMR
   calls); the process uses `transport.Imr.Lookup*` (already present).
2. Move `DiscoverAgent` orchestration + the process half of
   `RegisterDiscoveredAgent` (everything that writes `transport.Peer` —
   ContactInfo/mechanism-KNOWN/address/usability — plus the crypto +
   capability writes that Phase 2.5 already repointed to `transport.Peer`)
   into the transport package, behind `DiscoveryService`/`DiscoverPeer`.
3. MP keeps ONLY the gate + the `*Agent`-view materialization: the
   `OnPeerDiscovered` callback fires after the process completes and
   does `ar.S.Set` (the one MP-only residue). Retire the `DiscoveryDriver`
   TEMPORARY seam (`manager.go:130-158`) per its own doc comment.
4. Carry forward (do NOT revert) the peer-state-truth fixes already in
   this path: discovery gated on locally-supported transports (Fix E),
   URI-without-address not marked usable (Fix C), discovery-failure must
   not regress an established peer (`0bb1d5d`). They must survive the move.

**Verify:** transport standalone build + `-race` (the process now lives
there — its tests move too); tdns-mp build + suites; **dedicated testbed
pass: restart → rediscovery → NEEDED→KNOWN→OPERATIONAL for a real peer,
+ `peer reset` re-drives discovery.** Behavior-observable, so this is its
own checkpoint. Tag `phase-2.6-discovery-relocated`. This satisfies the
prompt's "all the way incl. discovery" option and overlaps most of v3's
Stage E (E1/E2) — record that in v3 if taken.

---

# Phase 3 — inbound-pipeline collapse + RemoteAgents + dead-code sweep + OnPeerRemoved

These are independent deletions; group as one phase (each its own commit,
phase builds at the end).

**3a — inbound-pipeline collapse (END.3).** Measurement §4: beat has 3
writers (transport.Peer + AgentDetails + gossip), hello has 2. After
Phase 2 the AgentDetails writer is GONE, so this is already half-done.
Finish it: `routeBeatMessage` (hsync_transport.go) + `HeartbeatHandler`
(hsync_beat.go) + engine `heartbeatHandler` converge to ONE writer of
`transport.Peer` mechanism-state+counters per message type;
gossip/election side-effects preserved; delete redundant writers. Same
for hello via `routeHelloMessage`. Do NOT wire inbound hello to the
`hsync/hello.go` stub (it is a stub — pass-2 M4). Single-writer rule +
lock order throughout.

**3b — delete `hsync.Registry.RemoteAgents`** (`hsync/registry.go:17`);
derive zone→peer on read via `ParticipantsForZone` (END.4). Compiler-
proven.

**3c — `OnPeerRemoved`** (the A5 residue): add the event so prunes are
events, not reconcile-only. EXPLAINED DELTA: pruned peers disappear
promptly. Small.

**3d — dead-code sweep (END.5).** ONE `staticcheck U1000` pass over
tdns-mp/v2 + hsync; single reviewed commit. Known inventory: the
dead-code triage doc + `FetchSVCB` + whatever Phases 1-3 orphaned. Per
the standing rule, do NOT remove U1000 hits without confirming intent —
this is the one sanctioned sweep; review the list with the operator
before deleting.

**Verify:** as Phase 1. INVARIANT except the `OnPeerRemoved` latency
delta (predict in writing). Tag `phase-3-consolidation-complete`. **This
tag IS the end of the transport.Peer consolidation** — `transport.Peer`
is the sole per-peer connection+crypto+state store; `Agent` is a pure
view; one allocation per peer; no bridge; no dead stores.

---

# Phase 4 — Stage-C starting point (the C0 gate)

This phase writes NO consolidation code. It establishes the
preconditions v3 requires before C1, so the next agent starts Stage C
from a defined line. All four are BLOCKING for C1 (v3 C0).

1. **Standalone builds green at the tag** (Gate-2 still holds):
   tdns-transport/v2 `go build ./... && go test ./... -count=1 -race`
   standalone; `cmd/transport-exercise` builds. Add to the probe run.
2. **Golden-wire regression test** (the Stage-C safety net). Characterize
   current wire bytes BEFORE anything moves in C: golden JSON for the 13
   `Dns*Payload` types (measurement §5c: dns.go:1207-1517) + the
   query-mode manifest `content`, asserting byte-exact tag names and
   `"MessageType"` values. Lives in the boundary suite. This converts
   C6's silent tag-drift risk into a CI failure. **Highest-value item in
   Phase 4** — it is what makes Stage C safe to do incrementally.
3. **Mixed-fleet runbook** (one page, docs/): which node upgrades first,
   what `parsePayload`'s strict conflicting-keys refusal does to a
   half-migrated pair, observable symptoms, rollback. Stage C is the
   wire-touching stage; this is its operational safety doc.
4. **Envelope/DOQ timing decision** (v3 open decision 4): does the
   in-channel-CHUNK work need the `envelope = none|jose|cose` label
   before C5? If yes, note it as a tiny pre-C5 step. Decision only;
   no code.

**Verify:** the golden test passes (locks current wire); standalone
builds green; runbook reviewed. Tag `stage-C-start`. **Hand off to Stage
C (v3 C1-C7), which proceeds INCREMENTALLY per v3 — this plan ends
here.**

---

# Effort & risk

| Phase | Shape | Est. sessions | Risk | Oracle |
|---|---|---|---|---|
| 1 — E1.b | mostly deletion + 1 shared mutex | 1–2 | **high** (concurrency) | compiler + -race + testbed |
| 2 — AgentDetails delete | pure deletion | 0.5–1 | low (all fields dead) | compiler + testbed (CLI line) |
| 2.5 — crypto rehome | sidecar deletion | 0.5–1 | medium (live TLS/JOSE) | testbed secure exchange |
| 2.6 — discovery relocation (ONLY if #5=C) | code move (gate stays MP) | 1–2 | medium (behavior-observable) | transport -race + testbed rediscovery |
| 3 — collapse+sweep | deletion | 1–1.5 | low-medium | compiler + -race + testbed |
| 4 — C0 gate | test+docs, no consolidation code | 0.5–1 | low | golden test |
| **Total to Stage-C start (A/B, no 2.6)** | | **~3.5–6.5** | | |
| **Total incl. 2.6 (option C, ≈ also clears v3 Stage E)** | | **~4.5–8.5** | | |

Compare v3's "13–20 sessions remaining" for the WHOLE thing: this plan
asserts the *consolidation half* (the part v3 spreads across END.1-5 +
A5 + part of D) collapses to ~3.5–6.5 sessions because the hard part
(END.0/D2.5/E1.a — making transport canonical) is already done and
verified, leaving deletion. Stage C (C1-C7, ~5-7 sessions) and Stage
E/F are unchanged and stay incremental.

The risk is concentrated in Phase 1's shared mutex and Phase 2.5's TLS
paths — both have a standalone-transport oracle (`-race` on the isolated
package) BEFORE the testbed, which is the specific mitigation for the
"big-bang reconverge hits N bugs at once" failure mode. Every other
phase is compiler-proven deletion.

## Open decisions for the operator (decide at the phase gates, not now)

1. **Phase 2.5 in or out?** (crypto rehome) — recommend IN; defer-able to
   Stage E if it looks risky at the Phase 2 gate.
2. **CLI `peer status` heartbeat line** (Phase 2 step 3): feed from
   transport.Peer (preferred, keeps the line) vs drop it.
3. **`agentMeta.Api`/`InitialZone`** (Phase 2.5 step 4): fold out and
   delete `agentMeta` entirely, or keep the sidecar for `Api` until
   Stage E.
4. **Phase grouping:** run Phases 2+2.5+3 as one longer push (they are
   all deletion off the Phase-1 base) vs separate testbed checkpoints.
   Recommend separate checkpoints for 1 and 2.5 (behavior-touching),
   batch 2+3 if the testbed pass after 2 is clean.
5. **Discovery relocation — DECIDED: C (full relocation, Phase 2.6).**
   The gate stays MP; the discovery process moves to transport. Phase 2.6
   is IN scope: move `DiscoverAgent` + the process half of
   `RegisterDiscoveredAgent` into transport; MP keeps only the gate
   (compute-needed → `DiscoverPeer(identity)`); retire `DiscoveryDriver`;
   `OnPeerDiscovered` materializes the `*Agent` view. This clears most of
   v3's Stage E (E1/E2). Run it right after Phase 2.5 (which repoints the
   crypto/capability writes), so `RegisterDiscoveredAgent` is rewritten
   once, not twice.
