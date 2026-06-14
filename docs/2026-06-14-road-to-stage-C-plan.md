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
A. A re-examination (2026-06-14) asked: is the "keep it compiling and
functional at every microstep" discipline still earning its cost?
Finding: it earns its cost **where intermediate behavior is
oracle-visible** (wire format, liveness deltas, the testbed catching
the three peer-state truth bugs this month) and **wastes cost where it
is not** (the long chain of INVARIANT state-store-consolidation slices,
each of which had to be *designed coherent* on its own — dual-write
windows, shadow fields, bridge converters — while the testbed could
see no change). The END.0 episode is the proof: a step whose purpose
was to *reduce* state-store coupling had to *re-add* a dual-write to
keep the fleet alive, caught only on the testbed because unit tests
structurally can't see the engine trigger.

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

**EXPANDED SCOPE — partly IN, the discovery boundary is an OPERATOR
DECISION (see correction below):**
The prompt allows extending through "discovery and associated bits."
- **IN (Phase 2.5): finish the `agentMeta.Crypto` → `transport.Peer`
  crypto-slot migration** (the addendum's deferred "E1" crypto move).
  Reason: it is small, it is pure consolidation (another MP-side sidecar
  that duplicates a transport-owned concept), and leaving it makes both
  A5 and Stage E messier. Doing it here means `transport.Peer` owns ALL
  per-peer connection+crypto state when we reach Stage C — a clean seam.
- **DISCOVERY MECHANISM RELOCATION — boundary CORRECTED 2026-06-14
  (operator caught a factual error; see below). UNDECIDED pending
  operator call at the Phase 2 gate.**

**CORRECTION (2026-06-14).** An earlier draft of this section scoped
discovery relocation OUT on the claim that "transport cannot import the
IMR engine (tdns/v2)." **That is false.** `tdns-transport/v2/transport`
already imports `github.com/johanix/tdns/v2` (`imr.go:37`, `init.go:17`),
and `transport.Imr` (embeds `*tdns.Imr`) ALREADY implements every
discovery lookup — `LookupAgentJWK`, `LookupAgentKEY`,
`LookupAgentAPIEndpoint`, `LookupAgentDNSEndpoint`, `LookupAgentTLSA`,
`LookupServiceAddresses` (`transport/imr.go`). Its own header calls these
"parallel copies of the same helpers on `*tdnsmp.Imr`" — i.e. MP and
transport hold DUPLICATE discovery primitives over the same singleton
`*tdns.Imr`. Furthermore `transport.TransportManager.DiscoverPeer` +
the `DiscoveryDriver` interface (`manager.go:130-158`) are explicitly
documented as a "TEMPORARY seam... Phase 6 part 2 moves the discovery
loop into transport and deletes this interface." So discovery relocation
is a PLANNED, already-scaffolded move, NOT blocked by layering.

**Revised assessment.** With the IMR objection gone, discovery
relocation is materially more tractable than the prior draft claimed.
The genuine residual MP-coupling, measured 2026-06-14:
  - `RegisterDiscoveredAgent` writes MP state: `ar.S.Set` (the `*Agent`
    view), `agentMeta.Crypto` via `ensureCrypto`, `ApiMethod/DnsMethod`
    flags. BUT: Phase 2.5 moves crypto onto `transport.Peer`, and
    ApiMethod/DnsMethod become `transport.Peer.HasMechanism` (addendum
    §4). After Phase 2.5 the ONLY MP-only write left is materializing the
    `*Agent` view in `ar.S` — which `OnPeerDiscovered` already does.
  - Zone-gating: the engine decides WHO to discover from HSYNC3 via
    `MarkNeeded(id, zone, …)`. Addendum §1 already settled that the
    NEEDED INTENT lives on `transport.Peer` and the engine sets it. So
    "MP decides intent, transport runs the mechanism" is the CORRECT
    end-state split — the zone-gating stays MP-side and is not a blocker.
  - The duplicate Imr helpers (MP-side + transport-side) want
    de-duplicating to the transport copy — that IS scaffolding deletion.

**So the deciding test cuts BOTH ways now:** consolidating the duplicate
lookups + retiring the `DiscoveryDriver` seam is scaffolding-deletion
(fits this plan); but the orchestration move still has a behavior-
observable surface (restart→rediscover→OPERATIONAL; the
OnPeerDiscovered→ar.S view materialization) that wants a testbed pass.
It is a genuine mix, which is why it is now an OPERATOR DECISION at the
Phase 2 gate rather than a unilateral OUT. Options A/B/C are listed in
"Open decisions" #5. The prior draft's confident OUT was built on the
false IMR premise and is retracted.

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
   - discovered: already shared (E1.a).
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

**Goal:** remove `AgentDetails` entirely. All 11 fields are write-only/
dead (measurement §2), so this is the cleanest possible deletion: rip out
the struct, and the compiler lists every write site to delete.

**Steps (one branch):**
1. Delete the write sites (they feed nothing — confirmed 0 readers):
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
identical via transport feed, or the line is dropped). Everything else
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

**Decision gate (operator):** Phase 2.5 is the one piece of "expanded
scope." If it looks riskier than estimated at execution time, it can be
DEFERRED to Stage E without affecting Phases 3-4 — it is additive, not a
Stage-C prerequisite. Decide at the Phase 2 gate whether to include it.

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
| 3 — collapse+sweep | deletion | 1–1.5 | low-medium | compiler + -race + testbed |
| 4 — C0 gate | test+docs, no consolidation code | 0.5–1 | low | golden test |
| **Total to Stage-C start** | | **~3.5–6.5** | | |

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
5. **Discovery mechanism relocation — how much, if any, into this plan?**
   (The IMR-blocker premise that justified a clean OUT was false; see the
   corrected Scope section.) Three options:
   - **A — keep OUT (Stage E after Stage C):** smallest scope to reach
     the Stage-C start; discovery stays MP-driven via the existing
     (correct) `OnPeerDiscovered` seam. The seam is not debt, so parking
     it costs nothing toward Stage C.
   - **B — fold in only the scaffolding-deletion slice:** de-duplicate
     the MP-side vs transport-side Imr lookup helpers down to the
     transport copy (they already exist there), and have MP discovery
     call `transport.Imr`. Pure consolidation, fits this plan; does NOT
     move the orchestration. Leaves `DiscoveryDriver` seam in place.
   - **C — full relocation:** move `DiscoverAgent` orchestration +
     `RegisterDiscoveredAgent` into transport, retire the
     `DiscoveryDriver` seam, transport owns discovery end-to-end. Most
     scope; behavior-observable (needs its own testbed pass); best done
     AFTER Phase 2.5 (so crypto + capability flags already live on
     `transport.Peer`, removing discovery's last MP-only writes).
   Recommendation: **B** if you want the duplicate-lookup debt gone while
   reaching Stage C; **A** if you want the shortest path to Stage C and
   prefer to do discovery as one clean Stage-E unit later. **C** is
   viable but expands "to Stage C" into "to Stage C + most of E" — only
   pick it if you'd rather finish discovery now than context-switch to
   the wire seam. I lean **B**: it captures the cheap win the corrected
   facts expose, without turning this into a discovery project.
