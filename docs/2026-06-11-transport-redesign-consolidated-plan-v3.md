# Transport redesign: consolidated implementation plan — v3
# (remaining work)

Date: 2026-06-11
Status: AUTHORITATIVE & EXECUTABLE. Single source of truth for all
REMAINING transport-redesign work. Supersedes, for everything not
yet implemented: `2026-05-30-transport-redesign-consolidated-plan-v2.md`,
the A3d addendum chain (`2026-06-01-a3d-field-ownership.md` §6–8.5),
`2026-06-03-a3d-spine-cluster-scope.md`, and the open items from
`2026-06-11-transport-redesign-progress-review.md`. Where v2 or an
addendum differs from v3, **v3 wins.**

Completed work is recorded here as a status table only (with commit
hashes); its specs live in the superseded docs as the evolution
trail. The A3d *design* (field-ownership acceptance test, target
types, lock order) is NOT re-derived — it is carried forward intact
from `2026-06-01-a3d-field-ownership.md` §1–5 and remains binding.

## Relationship to prior docs

- **v2** (2026-05-30): plan of record for Stage A's first half;
  retained as evolution trail. Its Stage C/D/E/F sections are
  folded into v3 with updates (see "What v3 changes").
- **A3d addendum** (2026-06-01) §1–5: still the binding A3d design.
  §6–8.5 (sequencing, slice log): superseded — outcomes recorded
  in the status table below.
- **Spine scope** (2026-06-03): its remaining slices are now
  Steps A3d-S1b…S4 below, updated against code verified 2026-06-11.
- **Dead-code triage** (2026-06-03): the (A) deletions are done;
  the (B) KEEP decisions are carried into A5 below with a
  concrete disposition.
- **Progress review** (2026-06-11): findings F1–F6 are converted
  into bound Steps here (Gate-1/Gate-2, C0, F2 items).

## What v3 changes vs v2 (supersession list)

1. **A3d sub-decomposition replaced.** v2 §A3d / addendum §8
   (A3d.2/.4/.5 ordering) is superseded by the per-field slice
   plan (addendum §8.1) — now Steps A3d-S1b…S4 + A3d-END below.
2. **`AgentDetails` struct deletion moves to A5** (was "end of the
   slice sequence"). Reason: the bridge converters reference the
   struct; deleting it requires the bridge teardown. Resolves an
   ambiguity the addendum left open.
3. **(B)-kept diagnostics fields get a disposition** (A5 below):
   live writes redirect to their existing `transport.Peer` homes;
   presentation finish becomes a small post-A5 task. (Operator
   confirmed KEEP on 2026-06-03; this is the "how".)
4. **Stage A exit gate added** (tag + stage branch + go.mod
   story). Operator policy: main is untouched until Stage F.
5. **Pre-C gate (C0) added**: three-repo standalone build restored
   (review F1), hpke Examples fixed (F2), golden-JSON wire
   regression test, mixed-fleet runbook as a written procedure.
6. **Stage D expanded** with D0 (the `hsync.PeerDetails`
   writer-path audit) per the spine doc's three-stores finding;
   D2 is bound as the one deliberate displayed-behavior change
   before F1.
7. **E1 inventory updated**: the legacy `attemptDiscovery` path
   was already retired (`6b671ac`); `peer reset` now routes via
   `Engine.Rediscover` (`d4577d4`). Three entry points remain,
   not four.
8. **Probe discipline amended**: the "all three repos" automated
   leg is currently fiction (review F1) — restored at Gate-2 and
   mandatory from C0 onward.
9. **Effort re-estimated bottom-up** (table at end); supersedes
   both the 05-28 table and the review's top-down figure.

## Verified baseline (code-verified 2026-06-11)

| Step | Status | Evidence |
|---|---|---|
| Stage 0 (0.1–0.3) | DONE | `4ba559b`, `3c59382`+`bad9b87`, `6e04424` |
| A1 (A1.0–A1.2) | DONE, testbed-confirmed | `c0de553`, `88955d8`, `7e65286` |
| A2 (incl. auth/HELLO boundary) | DONE, testbed-confirmed | `5efdd8f` |
| A3a (lock order) | DONE | mp `14d8f4b` + transport `614417f` |
| A3b | dissolved into A3d | `f018e7b` |
| A3c (`AgentRegistry.RemoteAgents` — note: `hsync.Registry.RemoteAgents` is separate, deleted later in END.4) | DONE | `16415f4` |
| A3d.0 view types + `effectiveAgentState` | DONE | `431f9d1` |
| A3d.1 registry embed (dual-mapped) | DONE | `eb584f7` |
| Legacy hello/discovery retirement | DONE, testbed-confirmed | `6b671ac`, `b304e1f`; `peer reset` fix `d4577d4` |
| ContactInfo slice | DONE (after revert `d8eb11d`) | transport `495eab4` + mp `3a536dd` |
| Dead-code sweep (A) | DONE | `512c864`, `0e87326` |
| A3d.3a/3b crypto → `agentMeta` | DONE | `67363b3`, `dc8bb8d`; `AgentDetails` crypto-free |
| Spine-1a (`.State` canonical readers) | DONE, **testbed verify outstanding** | `95c3cf6`; see Gate-1 |
| Gate-2 (three-repo standalone build) | DONE | transport `e65b057`, mp `b2dd2f6`, tdns `40bda34` |
| Gate-1 (Spine-1a redirect verify) | redirect SOUND; uncovered peer-state bugs | run 2026-06-11; see Gate-1 below |
| Peer-state truth fix (E/C/A/B) | DONE, testbed-confirmed | mp `fc0c189`, transport `3b85754`; pulls D2 core + Spine-2 display forward |
| Gate-3 (CleanupZoneRelationships) | DONE | mp `18ac2d7` (explanatory no-op) |
| A3d-S1b (State **display** redirect) | DONE | mp `68e7a69`; functional State retirement re-scoped to A3d-END.0 |
| A3d-S2 (address redirect + drop fields) | DONE | this commit; transport `DNSEndpoint` accessor; AgentDetails.Addrs/Port/BaseUri removed |
| A3d-S3 (transport-internal stats + functional redirect) | DONE; field-drop deferred to END.0 | transport `RecordMechanismBeatSent`/`MechanismBeatSequence`; mp redirects the 2 functional SentBeats readers; 5 fields stay as wire-DTO carrier (see S3) |
| A3d-S4 (snapshot inversion) | DONE | deleted SyncPeerFromAgent/PopulateFromAgent/AgentLike/AgentMechanismSnapshot + snapshot accessors; OnPeerDiscovered writes peer directly; transport `MechanismRawState`; ~420 lines net deleted |
| A3d-END.0 (State functional-merge) | DONE, TESTBED-CONFIRMED 2026-06-13 | mp `dbcb166` + fix `7d1ec60`; marker model (top-level `peer.State`=discovery-phase NEEDED/KNOWN/ERROR only); send-gates/inbound-hello/functional-gates read `transport.Peer` per-mechanism via `mechStateForGate`; inbound API-hello gap fixed; infra peers seed OPERATIONAL. tdns-transport UNCHANGED. Plan: `2026-06-13-a3d-end0-plan.md`. **Residual dual-write → D2.5 below.** |
| D2.5 (hsync engine reads transport; dual-write retired) | DONE, TESTBED-CONFIRMED 2026-06-13 | mp `6b97300` + out-of-band-hello fix `74368c0`; PULLED FORWARD ahead of END.1; `mechPeerState` helper; deleted 7 dual-writes + dead NG decay; engine-path tests. Unblocks END.1. See D2 item 5. |
| A3d-END.1 E1.a (Agent embeds *hsync.Peer) | DONE 2026-06-13, build+`-race` green, NOT YET DEPLOYED | mp `3fbeffd`; field dedup via type aliases (AgentId/ZoneName/DeferredAgentTask = hsync types); ~440 sites compatible; STILL two objects + dual map. Testbed checkpoint deferred to after E1.b. |
| IsRecipientReady missed-reader fix | DONE 2026-07-10, build+`-race` green, NOT YET DEPLOYED | mp `edfa079`; the ReliableMessageQueue readiness gate (`isTransportReady`, hsync_transport.go) was the ONE functional `AgentDetails.State` reader the END.0 census missed — after END.0/D2.5 retired the sidecar's writers it deferred every queued zone update to an AGENT recipient (`EnqueueForZoneAgents`/`EnqueueForSpecificAgent`) until the 24h expiry (combiner/signer unaffected: struct-literal OPERATIONAL seed). Now reads `transport.Peer` raw mechanism state via `mechStateForGate` (extracted `recipientTransportReady`); regression tests `reliable_ready_test.go`. Found by the 2026-07-10 plan-vs-code re-verification. |
| A3d-END.1 E1.b (object collapse + bridge teardown; ABSORBS END.2) | CODE DONE 2026-07-10 (road-to-C Phase 1), build+full-suite `-race` green, **TESTBED CHECKPOINT PENDING** (testbed unavailable; phase tag deferred) | Branch `phase-1-e1b` (cut from `388dd3b`; the branch point marks "verify pre-Phase-1 tip on testbed first"), mp `31d0dd7`. One allocation per peer on EVERY create path; `materializeAgentView` (Upsert-atomic, never replaces — the old bridge wiped MP-only fields on every store/hello/beat); `agentViewForIdentity` wraps/creates the ENGINE's peer for out-of-band discoveries; `hsync_bridge_sync.go` deleted whole; OnPeerStored/AfterDiscoverPeer = view-materialization; `GetZoneAgentData` stamps the DTO State from `effectiveAgentState` (predicted delta: `peer status` State now matches gossip/peer-list instead of the stale NG-lagged value). E1.b pointer-identity tests in `e1b_view_test.go`. tdns-transport UNCHANGED. |
| A3d-END.3…END.5 | NOT STARTED | inbound pipeline → RemoteAgents → dead-code sweep |
| Everything below this line | NOT STARTED | review §1 |

Build/test at tip (2026-06-13, post-S4 + testbed fixes: tdns-mp
`168c999`, tdns-transport `892e5de`): tdns-mp/v2 green incl. `-race`
and all `TestTransportBoundary_*`; tdns-transport/v2 builds and tests
standalone (`-count=1` + `-race`); `cmd/transport-exercise` builds
(Gate-2 closed); tdns/v2 main builds (5 binaries each via Makefile).
**S3 and S4 are TESTBED-CONFIRMED 2026-06-13** on the espresso.mp fleet
(cpt/fox/hare/auditor): post-restart convergence reaches a fully
OPERATIONAL matrix with correct leader election. Verification surfaced
three truth-model bugs (KNOWN/NEEDED contradiction `44f06bd`; infra
false-INTERRUPTED `6b07ed8`+`892e5de`; ERROR-clobbers-established-peer
`0bb1d5d`) — all fixed, regression-tested, and re-verified clean on the
testbed (operator: "all looks good now"). The remaining benign item is
the documented convergence-window gossip-vs-peerlist difference, which
closes at END.0/D2 when `peer list` reads `transport.Peer` as the sole
store. The deliberate Gate-1 fox-NS break/restore (FAILURE+RECOVERY
directions) is still a nice-to-have but no longer blocking, since the
ERROR/decay paths were exercised live.

## Target architecture (unchanged — restated for reference)

Two peer-state stores, partitioned by concern, joined only by
`PeerID`; transport speaks an opaque-message vocabulary; zone
membership — including admission — derived from HSYNCPARAM, never
stored-and-synced. `transport.PeerRegistry` owns identity, address,
per-mechanism state, liveness, wire crypto, stats. One MP registry
(`AgentRegistry` embedding `*hsync.Registry`) owns app metadata;
the MP per-peer record is nearly empty in the end state. LEGACY is
the one MP overlay (participations==0), never seen by transport.
Transport vocabulary = `hello/beat/ping/confirm/chunk` + one opaque
carrier `{Scope, TypeToken, Payload}`. Full statement: v2 "Target
architecture" + addendum §1 (the acceptance test). Both binding.

## Probe discipline (amended)

As v2, with one amendment: the automated leg is
- `go test ./... -count=1` in **tdns-mp/v2 AND tdns-transport/v2
  standalone** (the latter restored at Gate-2; until then,
  tdns-mp-only is an acknowledged temporary state, valid for
  Stage A only),
- `tdns/v2` compile, `cmd/transport-exercise` build (from C0 on),
- the boundary harness + `hsync/*` suites; `-race` on every A/C
  Step.

Runtime probes unchanged: `peer list`, `peer zones`,
`gossip state -z`, `zone edits list -z`, `distrib list`.
INVARIANT vs EXPLAINED DELTA semantics unchanged: an unpredicted
change in an INVARIANT probe halts the Stage.

## Baseline & branching strategy (bound 2026-06-11)

- **main is untouched until Stage F is proven** (operator policy).
- At the Stage A exit gate (below): tag `stage-A-complete` in BOTH
  repos (they move in lock-step); cut `transport-redesign-v1-C`
  from the tags for Stage C. Same pattern at each later stage
  boundary (`stage-C-complete`, …).
- The tagged baselines MUST build standalone (hence Gate-2 sits
  inside Stage A, not before C).
- go.mod local replaces ("Revert before publishing") stay on the
  working branches; each tag records, in its message, the sibling
  commits it was verified against. The true publishing story
  (pushed tags fetchable by the module proxy) is decided once, at
  the Stage F merge — not re-litigated per stage.

---

# Stage A — remainder

## Gate-1 — Spine-1a testbed verification (operator) — REDIRECT VERIFIED; uncovered the peer-state bugs (now fixed)

Outstanding since 2026-06-03; run 2026-06-11. Deploying the tip and
exercising `gossip state`/`peer list` did NOT show a Spine-1a
redirect regression — the redirect is mechanically correct. What it
exposed was a pre-existing, hidden state-machine bug: a peer
(`agent.fox`) read OPERATIONAL with an address while every send to
it failed (`no address available`). Spine-1a surfaced it by reading
`transport.Peer`, which was fed the WRONG signal.

Root cause and the complete fix are in
`2026-06-11-peer-state-and-discovery-truth-fix.md`. Four bugs, one
disease (success asserted on incomplete evidence, never retracted):
- **E** discovery probed unsupported transports (API on a DNS-only
  fleet) → log spam + spurious `Partial`;
- **C** partial discovery (URI without resolved address) registered
  as "complete"/KNOWN → phantom address in `peer list`;
- **A** OPERATIONAL set by INBOUND receipt, not the OUTBOUND beat
  round-trip the definition requires;
- **B** demotion (DEGRADED/INTERRUPTED) lived only in the NG store
  nobody operational reads.

**Fixed and testbed-confirmed 2026-06-11** (tdns-mp `fc0c189`,
tdns-transport `3b85754`): with the upgraded fleet, the matrix now
moves through the real progression NEEDED→KNOWN→OPERATIONAL,
`peer ping` to a discovered peer succeeds, the contradiction is
gone, and a transient `KNOWN` correctly shows during convergence
(no longer slammed to OPERATIONAL by inbound beats). The
"DEGRADED/INTERRUPTED displayed by neither side" line in the
original Gate-1 wording was wrong for the gossip-matrix path — that
path always derived from `EffectiveState`; it now decays truthfully
(Fix B, decay-on-read).

Spine-1a's `transport.Peer.EffectiveState()` as the canonical read
is CONFIRMED sound — it just needed a truthful machine behind it.
Net effect on sequencing: Fix B is Stage-D "transport-owned
liveness" pulled forward; Fix C's display side is Spine-2 pulled
forward (see those steps). A3d may continue on the now-trustworthy
`transport.Peer`.

**Still TODO before declaring the slice fully clean:** a homogeneous
all-tip fleet pass (fox/hare were old during the run) and the
deliberate break/restore of fox's NS to confirm the FAILURE +
RECOVERY directions (the controllable-trigger test; `agent zone
bump` now exists for it).

**Two more truth-model bugs found + fixed during S3/S4 testbed
verification (2026-06-13)** — same disease (a failure/secondary signal
asserting top-level State over a peer another path proved good), both
surfaced because `EffectiveState()` falls back to top-level `peer.State`:
- **KNOWN/NEEDED contradiction** (mp `44f06bd`): two sites set top-level
  `peer.State = KNOWN` unconditionally even with no usable address, so
  gossip showed KNOWN while `peer list` correctly showed NEEDED for an
  unreachable peer (fox). Fixed: promote to KNOWN only if a mechanism is
  usable (`OnPeerDiscovered` + `RegisterDiscoveredAgent`).
- **ERROR clobbers established peer** (mp `0bb1d5d`): discovery
  attempts RACE — a chunk-notify "missing key" kick fires a discovery
  while a startup/retry leg is still in flight, so a stale failing leg
  (resolver i/o timeout) fired `OnDiscoveryFailed` AFTER a concurrent
  attempt had already succeeded + registered the address; the
  unconditional `SetState(ERROR)` then clobbered a peer that was
  demonstrably reachable (and actively exchanging election votes),
  surfacing a transient ERROR in the gossip matrix. Confirmed from cpt
  logs (08:40:47 `successfully discovered and registered` → 08:40:48
  `peer discovery failed` i/o timeout → ERROR). Fixed: `OnDiscoveryFailed`
  does not regress a peer already KNOWN+ or with a resolved address.
  Regression tests added for both (boundary suite).

**Infra-peer false INTERRUPTED also fixed** (D2 item #2 infra slice,
pulled forward; mp `6b07ed8` + transport `892e5de`) — see D2 below.

## Gate-2 — restore the three-repo build (small; before A3d-S2) — DONE 2026-06-11

Review finding F1. In `tdns-transport/v2`: add the johanix/dns
fork replace (mirror tdns-mp/v2 `go.mod:80`) + `go mod tidy`
(picks up `johanix/dnssec-algorithms` indirect). Verify
`go build ./... && go test ./... -count=1` standalone. Fix or
neutralize the four hpke `Example*` Output blocks (review F2 —
placeholders can never match; either correct the expectations or
drop the `// Output:` markers). Verify `cmd/transport-exercise`
builds. One commit per repo touched.

**Probe — INVARIANT** (build/test infrastructure only).

**Outcome (transport `e65b057`, mp `b2dd2f6`, tdns `40bda34`):**
Root cause confirmed — Go ignores `replace` directives from
dependencies, so each main module must restate the
`miekg/dns => johanix/dns` replace that `tdns/v2`'s algorithm
registry (`dns.Algorithm`/`dns.RegisterAlgorithm`, absent from
upstream miekg/dns v1.1.72) requires. The fork API is NOT
upstreamed, so the replace cannot be dropped anywhere short of
the Stage F publishing decision; the achievable cleanup was
making it identical everywhere. All modules (tdns/v2
root+core+edns0+cache, tdns-mp/v2, transport/v2,
`cmd/transport-exercise`) now pin the same algorithm-registry tip
`2a28f8f1484d` (2026-06-08). `cmd/transport-exercise/go.mod` also
needed the `tdns/v2` root + `cache` local replaces (it now
imports `tdns/v2` transitively). hpke `Example*` `// Output:`
placeholder markers dropped (F2). One incidental fix:
`testHandler`/`testMiddleware` `.called` counters, raced by
`TestConcurrentAccess` once the package built standalone, made
`atomic.Int64`. Transport standalone `go build` + `-count=1` +
`-race` green; both Makefile builds (tdns 5 binaries, tdns-mp 5
binaries) green; boundary suite `-race` green. The tdns dep bump
landed on a generic branch (`johanix-dns-bump-jun8`), not the
redesign branch, since it is plain dependency maintenance.

## Gate-3 — close the dangling A1 loose end (decision + tiny commit) — DONE 2026-06-11

`CleanupZoneRelationships` (`agent_utils.go:300`) was a TODO stub
wired as the `OnLocalRemoved` hook (`hsync_bridge.go:285`). A1.0
bound "implement or explicitly drop; do not leave dangling".
**Resolved (operator-confirmed):** with membership now derived
(A2), local-removal teardown is automatic — `ParticipantsForZone`
recomputes from HSYNCPARAM on every read, so participation simply
stops being derived; groups recompute via `OnHsync3Changed`. There
is no stored per-zone relationship to scrub. The stub body is
replaced with an explanatory no-op (Info log + comment stating the
derivation reasoning). Revisit only if the testbed shows orphaned
per-zone state after a local removal — which would mean some state
is still stored, and should be moved to derivation rather than
scrubbed here.

## A3d-S1b — `.State`: display redirect (DISPLAY-ONLY; functional retirement → A3d-END)

Prereq: Gate-1 green.

**RE-SCOPED 2026-06-11.** S1b is now ONLY the display redirect.
Redirect the peer-list display's per-mechanism State to the canonical
`transport.Peer` (decayed per-mechanism via the new
`MechanismEffectiveState(name)` accessor → `transportToAgentState`),
keeping the LEGACY overlay (it becomes the overlay's only display
site). Sites: the API + DNS blocks in `apihandler_agent_distrib.go`.
AgentDetails fallback retained for peers not yet in the PeerRegistry
(transitional). With Fix B, the displayed State now also decays.

The original S1b parts 2–3 (stop writing `AgentDetails.State`/
`LastState`; retire the `RecomputeSharedZonesAndSyncState` flip) are
MOVED TO A3d-END. Reason discovered during S1b: `AgentDetails.State`
is still the FUNCTIONAL store driving the beat/hello state machine —
~45 read/write sites, incl. the `SendBeatWithFallback`/
`SendHelloWithFallback` send gates. Stopping the writes requires
migrating all those readers to `transport.Peer` first, which is the
embed/State-merge — it belongs with A3d-END's type-merge under one
commit + the post-embed testbed checkpoint, NOT bolted onto a display
slice. The display now reads `transport.Peer` (truthful), while
`AgentDetails.State` remains the internal functional store until the
embed (documented dual-write window).

**Probe — INVARIANT:** `peer list` State column + `gossip state`
byte-comparable on a healthy fleet; the displayed State now decays
(EXPLAINED DELTA, already landed via Fix B); suite + `-race` green.

## A3d-S2 — address: redirect reads, drop fields — DONE 2026-06-11

**Done** (transport `809ebb6`-followup + this commit). `DNSEndpoint`
added to `transport.Peer` (Decision 1a), set at every DNS write site
(discovery, combiner/signer Initialize*AsPeer, main_init config
agents, apihandler_peer). Peer-list address columns now read
`transport.Peer` (`DNSEndpoint`/`APIEndpoint` + `CurrentAddress()`).
The `GetOrCreatePeer` AgentDetails→transport address restore was
DELETED — infra peers (combiner/signer) now populate their
`transport.Peer` address at startup registration (the restore's only
remaining justification), so transport.Peer is the sole address
source. `AgentDetails.Addrs/Port/BaseUri` + all bridge copies
removed; `mergeAgentDetails` deleted (it only preserved address
fields). API-functional readers migrated: the two API send gates read
`peer.APIEndpoint != ""`; `NewAgentSyncApiClient` (0 callers) takes a
`*transport.Peer`. NG (`hsync.PeerDetails`) has no functional reader
of the fields (bridge-clobber check passed; its struct fields are now
dead, droppable later). Build (5 bins) + suite + boundary `-race`
green.

Prereq was the **DNS-URI display home decision** (Open decision 1) —
DECIDED (a), see below.
1. Per the rule: enumerate ALL writer paths for `Addrs`/`Port`/
   `BaseUri` — discovery (`RegisterDiscoveredAgent`), config-infra
   (`combiner_peer.go`/`signer_peer.go`), `GetOrCreatePeer`
   address restore — and confirm `transport.Peer` is written
   identically on each (it is for discovered + infra per the
   ContactInfo slice work; re-verify).
2. Redirect display reads (`apihandler_agent_distrib.go:363,378,
   380,425,444,446`) to `transport.Peer`
   (`Mechanisms["DNS"].Address`/`DiscoveryAddr` for DNS;
   `APIEndpoint` for API; DNS-URI per the decision).
3. Redirect the `GetOrCreatePeer` address restore to read
   transport state (or delete the restore if transport is now
   always populated first — prove it).
4. Drop `AgentDetails.Addrs/Port/BaseUri` + their bridge copies.
   **Verify NG (`hsync.PeerDetails`) does not read them** before
   dropping the copies (bridge-clobber check, spine doc §4).

**Probe — INVARIANT:** `peer list` address columns byte-comparable
(all three peer kinds: discovered / config-infra / registry-only);
`addrr` round-trip ACCEPTED; combiner reachable from the agent.

## A3d-S3 — telemetry: transport-internal stats + functional redirect — DONE (item 4 deferred to END.0)

**RE-SCOPED 2026-06-11.** Item 1's premise was stale: the peer-state
truth fix (`fc0c189`) already gave the API path full hello/beat-time
coverage (`HeartbeatHandler` writes both API+DNS inbound; the outbound
Hello :1555/:1583 and Beat :1673-1676/:1714-1717 paths are symmetric;
the API beat path already calls `SetMechanismLastBeatSent("API")`).
So there was NO coverage gap to add — S3 became a pure INVARIANT
slice, NOT the EXPLAINED-DELTA "adds writes" slice originally framed.

1. ~~Add API-side coverage~~ — already present (Fix A). No-op.
2. **DONE (transport-first, operator-chosen).** `RecordBeatSent` had
   0 callers and transport's `Beat()` did not maintain `BeatSequence`/
   `Stats` — they were maintained only by MP's `AgentDetails.SentBeats`.
   Added `Peer.RecordMechanismBeatSent(name)` (transport `292b0ea`→
   `31f38da`): `APITransport.Beat`/`DNSTransport.Beat` now bump
   per-mechanism `Mechanisms[m].{BeatSequence,LastBeatSent}` +
   top-level aggregate + `Stats` on their Ack-true success path.
   `Peer.MechanismBeatSequence(name)` read accessor added (`f932f4e`).
   `ConsecutiveFails` left as-is (it is a Stage-D liveness field, not
   an S3 concern).
3. **DONE (mp `56dec3d`).** Redirected the two FUNCTIONAL `SentBeats`
   readers to `transport.Peer.MechanismBeatSequence`: infra-beat
   sequence seeding (`hsync_infra_beat.go`) and gossip-sent detection
   (`beatTransportUsed`, `hsync_bridge.go`). Display `LastUsed`: the
   `AgentDetails.HelloTime` fallbacks in `apihandler_agent_distrib.go`
   were already dead (unconditionally overwritten by the
   `transport.Peer` `Stats.LastUsed` path) — deleted. `peer reset` no
   longer touches `AgentDetails.DiscoveryFailures`.
4. **DEFERRED to A3d-END.0** (was: drop the 5 fields + bridge copies).
   Reason discovered during S3: `AgentDetails` doubles as the WIRE DTO
   — `GetZoneAgentData` serializes the live `Agent` (incl. `*AgentDetails`)
   into the `peer status`/hsync API response, and the CLI client
   (`cli/hsync_cmds.go:558-560`, no `transport.Peer` client-side) reads
   `SentBeats/LatestSBeat/LatestRBeat` off the deserialized DTO for its
   "Heartbeats: Sent/received" line. Dropping the fields breaks that
   line unless the DTO is first fed from `transport.Peer`. Two of the
   same line's fields (`ReceivedBeats`→A5, `BeatInterval`→Stage D) can't
   move in S3 regardless. So the 5 fields stay as a write-mostly DTO
   carrier (no live FUNCTIONAL reads remain after item 3) until END.0/
   END.1 give `Agent` a transport-fed view and answer the DTO question
   once for all fields. The converter/bridge copies
   (`hsync_bridge_sync.go`, `agent_structs.go` snapshot methods) stay
   with them. NG `checkPeerState` reads the *hsync*-side
   `LatestRBeat/SBeat` (separate struct) — untouched, stays until D.

**Probe — INVARIANT:** `transport.Peer` now maintains its own beat
counters; the two MP functional readers consume them; no display or
wire change (the dropped `HelloTime` display fallback was already
dead). Suite + boundary + `-race` green; 5 binaries build.

## A3d-S4 — the snapshot inversion (residual A4) — DONE 2026-06-12

Deleted: `SyncPeerFromAgent` + `agentStateToTransportState`
(`hsync_transport.go`), `agentStateToTransportStateFn` +
`APIMechanismState`/`DNSMechanismState` (`agent_structs.go`);
tdns-transport side: `Peer.PopulateFromAgent`, `AgentLike`,
`AgentMechanismSnapshot`, and the now-dead `peer_test.go` (its
entire content was `PopulateFromAgent` tests). `GetOrCreatePeer`
(hot-path, no-snapshot) stays.

**NOT pure dead-code** — one live caller had to be inverted first.
`SyncPeerFromAgent` was still called by the `OnPeerDiscovered`
closure (`hsync_transport.go`) at discovery completion. Audited what
it actually contributed there post-S1b/S2/S3:
- TLSA block: a no-op stub (`TLSARecord = []byte{}`).
- top-level `SetState`: dead — overwritten 1 line later by the
  closure's own `SetState(KNOWN, "discovery complete")`.
- zone-seeding (`agent.Zones`→`AddSharedZone`): redundant AND wrong
  source — `peer.SharedZones` is populated synchronously by the
  participant-derived `RecomputeSharedZonesAndSyncState`→
  `ReplaceSharedZones` inside `ApplyHsyncDiff`, before discovery
  completes; beats only go to READY peers, so no empty-zone window.
  `agent.Zones` was the banned stored set, not the derived one.
- `PopulateFromAgent`: the only real contribution was promoting each
  usable mechanism's per-mechanism State to KNOWN (address/beat
  fields are already canonical on the peer post-S2/S3 and guarded
  against clobber).
So the closure now writes the canonical peer DIRECTLY: for each
mechanism with `MechanismContactInfo == "complete"`, promote to
KNOWN guarded against regression (`MechanismRawState < KNOWN`) —
mirroring `RegisterDiscoveredAgent`'s `state <= NEEDED -> KNOWN`.
That is the "snapshot inversion": discovery writes the peer instead
of round-tripping through an Agent snapshot. New transport accessor
`Peer.MechanismRawState(name)` (non-decayed read) supports the guard.

**Probe — INVARIANT** (verified). 5 binaries build; transport
standalone + tdns-mp + hsync + all 7 `TestTransportBoundary_*`
(incl. `_DiscoveryComplete` across API/DNS/both) green under `-race`;
`cmd/transport-exercise` builds.

## A3d-END — embed finalization (the concurrency-sensitive chunk)

One session; sub-steps are separate commits, each green +
`-race` + INVARIANT.

- **END.0 — State functional-merge (moved here from S1b).** Make
  `transport.Peer.Mechanisms[m].State` the SOLE State store:
  redirect the ~45 FUNCTIONAL readers/writers of
  `AgentDetails.State`/`LastState` — chiefly the beat/hello send
  gates in `SendBeatWithFallback`/`SendHelloWithFallback`
  (`hsync_transport.go` ~1551/1579/1672/1711) and the
  NEEDED/KNOWN/INTRODUCED/OPERATIONAL transitions — to read/write
  `transport.Peer`. Then stop writing `AgentDetails.State`/
  `LastState` (the residual writer sites; note Fix A already moved
  the OPERATIONAL writes and removed the inbound-receipt ones) and
  retire the `RecomputeSharedZonesAndSyncState` LEGACY/OPERATIONAL
  flip (`agent_utils.go:67-74`) — the display LEGACY overlay derives
  it. **This is load-bearing** (the beat state machine, just
  hardened by Fixes A/B) — do it as its own commit with its own
  `-race` + testbed check before END.1. The display side already
  reads `transport.Peer` (S1b), so END.0 closes the write side and
  retires the dual State store.
- **END.1 — type-merge. Split into E1.a (DONE) + E1.b (NOT
  STARTED). Sequencing decided 2026-06-13: E1.a → E1.b → END.3 →
  END.4 → END.5; END.2 is ABSORBED INTO E1.b (see below).**

  **E1.a — DONE 2026-06-13 (mp `3fbeffd`), build + all tests green
  `-race`, tdns-transport untouched, NOT YET DEPLOYED (pure
  structural intermediate, no behavior change — testbed checkpoint
  is after E1.b).** `Agent` now embeds `*hsync.Peer` and PROMOTES
  every same-typed field (no type cascade): `ID` (was
  `Identity`/`PeerID`), `Mu`, `Zones`, `Deferred` (was
  `DeferredTasks`), `ApiMethod`, `DnsMethod`, `IsInfraPeer`,
  `LastState`. Enabled by three TYPE ALIASES so ~440 call sites
  stay compatible: `AgentId = hsync.PeerID`,
  `ZoneName = hsync.ZoneName`, `DeferredAgentTask =
  hsync.DeferredTask` (added `hsync.ZoneName.String()` for
  `core.Stringer`; deleted the now-redundant MP `String()`s). The
  DIFFERENT-typed connection-state fields stay on `Agent`,
  shadowing the embed's same-named ones: `ApiDetails`/`DnsDetails`
  (`*AgentDetails` vs `*hsync.PeerDetails`) and `State` (`AgentState`
  vs `hsync.PeerState`) — retire in A5/D. New `NewAgent(id)`
  constructor wraps `hsync.NewPeer`. `hsyncPeerToAgent` now SHARES
  the peer pointer (`&Agent{Peer: peer, …}`), starting the E1.b
  collapse; `syncHsyncPeerFromAgent` got a `peer == agent.Peer`
  near-noop fast path. STILL TWO OBJECTS per peer (the bridge still
  deep-copies the non-promoted State on the non-shared paths) and
  the dual map remains.

  **E1.b — NOT STARTED. Re-census 2026-06-13 CHANGED ITS SHAPE —
  read this before starting.** The original framing ("collapse to
  ONE Go map / one object type") is NOT ACHIEVABLE, because of a
  hard package-boundary constraint:
  - The hsync ENGINE lives in `hsync/` and CANNOT import the main
    package (import cycle). It constructs/iterates/operates on
    `*hsync.Peer` in ~31 sites, so `hsync.Registry.S` MUST stay
    `[PeerID]*hsync.Peer`.
  - MP's ~27 `ar.S` sites want `*Agent` (which carries the MP-only
    fields `ApiDetails`/`DnsDetails`/`State`/`Api`/`meta`).
  - `*Agent` and `*hsync.Peer` are different Go types in different
    packages; neither map can hold the other's type. So there will
    ALWAYS be a `*hsync.Peer` map (engine's) + a `*Agent` map (MP's).

  **The achievable E1.b end-state is ONE ALLOCATION per peer, two
  typed views, NO deep-copy** — i.e. the `*Agent` in
  `AgentRegistry.S` and the `*hsync.Peer` in `hsync.Registry.S`
  reference the SAME underlying `hsync.Peer` (`agent.Peer == that
  peer`). E1.a already started this on the discovered path
  (`RegisterDiscovered` → `hsyncPeerToAgent` shares the pointer).
  E1.b's real work:
  1. Make pointer-sharing UNIVERSAL on every peer create/update path
     (discovery, `MarkNeeded`, infra-peer registration in
     `combiner_peer.go`/`signer_peer.go` — note infra peers are
     ONLY in `ar.S`, never `hsync.Registry.S`; the MP infra-beat
     loop `hsync_infra_beat.go:49` iterates `ar.S`, the engine loop
     `hsync/beat.go:42` iterates `hsync.Registry.S` and never sees
     them — by design).
  2. Delete the deep-copy bridge: `syncHsyncPeerFromAgent`,
     `agentToHsyncPeer` (already orphaned/dead),
     `persistAgentAndPeer`'s copy, and reduce `hsyncPeerToAgent`/
     `agentForTransport` to trivial wrappers or remove. The
     `OnPeerStored`→`syncHsyncPeerToAgent` hook
     (`hsync_bridge.go:~309`) is the sync trigger to rework.
  3. The two maps PERSIST (engine needs its typed one) but stop
     being independently-stored copies — consistent via the shared
     pointer, not field-copying. This is the addendum's "two stores
     joined by PeerID."

  **END.2 (delete the dual-map shadow `AgentRegistry.S`/`mu`) is
  ABSORBED HERE** — it is NOT a clean standalone deletion because
  `ar.S` (`[AgentId]*Agent`) and the embedded `hsync.Registry.S`
  (`[PeerID]*hsync.Peer`) hold different types; the shadow can't
  simply be removed to fall through to the embedded map. Whether
  `ar.S` survives as the MP `*Agent` view (recommended) or is
  replaced needs deciding at E1.b execution time.

  **E1.b is the riskiest commit of the stage** (one shared mutex,
  bridge teardown, concurrency). Stopped before it on 2026-06-13
  (long session, two regressions already surfaced+fixed). REQUIRES a
  testbed checkpoint after. Restart tag for the whole END.1+ block:
  `end0-complete-pre-d2` (mp `2f00cca` / transport `892e5de`).

  **`AgentDetails` wire-DTO note (carried):** the 5 telemetry fields
  + `ReceivedBeats` are serialized as the `GetZoneAgentData` DTO read
  by the CLI `peer status` line. Verified DEAD over the wire in END.0
  (`Agent.MarshalJSON` omits `*AgentDetails`), so the struct deletion
  in A5 needs no DTO-feed step. No action in E1.b.
- **END.2 — ABSORBED INTO E1.b** (see END.1 above). The dual-map
  shadow cannot be deleted independently of the object-collapse,
  because `ar.S` (`[AgentId]*Agent`) and the embedded
  `hsync.Registry.S` (`[PeerID]*hsync.Peer`) hold different types.
- **END.3 — collapse the inbound pipeline.** One writer per
  message type. Beat: `routeBeatMessage`
  (`hsync_transport.go:689`) + `adaptBeatReports`→
  `HeartbeatHandler` (`hsync_beat.go:11`) + engine
  `heartbeatHandler` converge on a single path writing
  `transport.Peer` (mechanism state + counters); gossip/election
  side-effects preserved; delete the redundant writers. Hello
  likewise via `routeHelloMessage`; do NOT wire inbound hello to
  the `hsync/hello.go` stub (pass-2 M4). Keep the single-writer
  rule and the A3a lock order throughout.
- **END.4 — delete `hsync.Registry.RemoteAgents`**
  (`hsync/registry.go:17`); derive zone→peer on read via
  `ParticipantsForZone`.
- **END.5 — deferred dead-code sweep.** One `staticcheck U1000`
  pass over tdns-mp/v2 (+hsync); single reviewed commit. Known
  inventory: triage doc + whatever S1b–S4 orphaned.

**Probe — INVARIANT:** `peer list`/`peer zones`/gossip/edits
byte-comparable; no new races under `-race` on boundary + hsync
suites. **Operator checkpoint: deploy + testbed-confirm before
A5** (this is the addendum's post-embed checkpoint, relocated).

## A5 — bridge teardown

1. **(B)-fields disposition first** (operator KEEP, 2026-06-03;
   disposition proposed here, confirm before implementing):
   - `LatestError`/`LatestErrorTime` → per-mechanism
     `MechanismState.StateReason`/`StateChanged` (exists; verify
     the hello/beat fail paths write it on every mechanism).
   - `LastContactTime` → `LastBeatRecv`/`LastHelloRecv` (exists).
   - `ReceivedBeats` → `Stats` (exists, transport-maintained).
   - `BeatInterval` → **Stage D** (it is the NG liveness param).
   - Presentation finish (`peer list -v` reading transport.Peer)
     becomes a small standalone task, schedulable any time after
     A5; `HsyncPeerInfo` DTO remains UNDETERMINED.
   - The no-consumer NG mirrors
     (`hsync.PeerDetails.{LatestError,LatestErrorTime,
     LastContactTime,ReceivedBeats}`) are deleted here; the
     `checkPeerState`-read fields
     (`State,BeatInterval,LatestRBeat,LatestSBeat`) stay until D.
2. Delete the bridge: all 9 `hsync_bridge_sync.go` functions
   (`hsyncPeerToAgent`, `syncHsyncPeerFromAgent`,
   `agentToHsyncPeer`, `mergeAgentDetails`,
   `persistAgentAndPeer`, …), the `mpHsyncBridge` type, the
   `SyncPeerZones` shim, the `OnPeerStored` wiring
   (`hsync_bridge.go:314`).
3. Delete the now-empty `AgentDetails` struct.
4. **Add `OnPeerRemoved`** (the only new machinery left in
   Stage A) so prunes are events, not reconcile-only — completes
   the A1(c) removal-latency delta.

**Probe — INVARIANT** steady state; **EXPLAINED DELTA**: pruned
peers disappear promptly (event) instead of after a reconcile
interval.

## Stage A exit gate

1. Full probe pass on the testbed (all runtime probes, all three
   peer kinds).
2. Tag `stage-A-complete` in tdns-mp AND tdns-transport; tag
   message records the sibling commit pair + the tdns/v2 commit
   verified against.
3. Cut `transport-redesign-v1-C` from the tags.
4. Re-verify the standalone builds at the tag (Gate-2 must still
   hold).

---

# Stage C — transport cleanup / the opaque-message seam

Goal unchanged (v2): transport speaks only
`hello/beat/ping/confirm/chunk` + one opaque carrier; all MP verbs
are app-level `TypeToken`s; one tdns-mp callback. Delivers the
reusable-library goal. The hard infrastructure exists
(`DNSMessageRouter` token-keyed; `RouteToCallback` live at MP) —
C is mostly relocation + deletion.

## C0 — pre-C gate (NEW; all four items BLOCKING for C1)

1. **Standalone builds green** (Gate-2 done and still holding at
   the stage-A tag), `cmd/transport-exercise` in the probe run.
2. **Golden-wire regression test.** Characterize the current wire
   bytes BEFORE anything moves: golden JSON for the 13
   `Dns*Payload` types + the query-mode manifest `content`
   (`distrib/manifest.go:82`), asserting byte-exact tag names and
   `"MessageType"` values. Lives in the boundary suite; it is the
   mechanical enforcement of C6's wire-safety gate ("highest
   wire-break risk in C") and converts silent tag drift into a CI
   failure.
3. **Mixed-fleet runbook as a written procedure** (not a bullet):
   which node upgrades first, what `parsePayload`'s strict
   conflicting-keys refusal (`chunk_notify_handler.go:273-278`,
   v2 numbering) does to a half-migrated pair, observable
   symptoms, rollback step. One page, in docs/.
4. **DOQ/envelope timing decided** (Open decision 4): does the
   in-channel-CHUNK work need the `envelope` label before C5? If
   yes, pull the label out as a tiny pre-C5 step.

## C1 — define the seam

Add `{Scope, TypeToken string, Payload json.RawMessage}` to the
carrier (generalize `SyncRequest`/`IncomingMessage`); keep the
live `RouteToCallback` seam; widen `IncomingMessage` to carry
`TypeToken`. Additive — both sides still work. Wire note: the
verb stays the JSON payload key `"MessageType"`; carrier-struct
field names are wire-irrelevant as long as C6 keeps marshalling
`"MessageType"` with the same value (now enforced by the C0
golden test).

## C2 — collapse the send side

Replace typed `DNSTransport.Sync/Keystate/Edits/Config/Audit`
(+`SendStatusUpdate`) with one generic
`Send(ctx, peer, Scope, TypeToken, rawPayload)`;
Hello/Beat/Ping/Confirm keep typed entry points. Rewrite the MP
send wrappers (`SendSyncWithFallback`, `sendRfiToSigner/Combiner`,
`sendKeystateToSigner`, `sendConfigToAgent`, `sendAuditToAgent`)
to set `TypeToken`. Preserve `SendStatusUpdate` fire-and-forget
semantics (pass-2 M6). Keep the per-mechanism send/result shape
string-keyed (principle 8 — DOQ is coming; never a 2-element
API/DNS shape).

## C3 — move receive handlers to tdns-mp

Move the 8 MP handlers (`HandleSync/Rfi/Keystate/Edits/Config/
Audit/StatusUpdate/Relocate`, `handlers.go:220-686`) behind one
`RouteToCallback` dispatcher keyed on `TypeToken`; transport keeps
`HandleHello/Beat/Ping/Confirmation`. Preserve: role-specific
handler sets (combiner `HandleUpdate`/`NewCombinerSyncHandler`
async-confirm; signer keystate/rfi/status subset); combiner/signer
registration MUST work without an `AgentRegistry` (they build
with config-only `AuthorizedPeers`, `main_init.go:302-384`);
inline-ACK (`ctx.Data["response"]` NOTIFY-confirm path). Collapse
the MP-side duplicate verb table `routeIncomingMessage` into the
one dispatcher — no third table. Delete
`InitializeCombinerRouter`/`InitializeSignerRouter` + configs
(`router_init.go:253/283/404/429`).

## C4 — move MP types out

Move `SyncType`, `Keystate/Edits/Config/Audit` req+resp,
`KeyInventoryEntry`, `RejectedItemDTO` to tdns-mp; drop the MP
`core.` imports (verified 2026-06-11: `core.AgentMsg*`,
`core.Agent*Post`, `core.KeyInventoryEntry`,
`core.PublishInstruction`, `core.RROperation`,
`core.StatusUpdatePost` across 6 transport files), leaving only
wire/crypto types (`CHUNK`, `TypeCHUNK`, `Format*`, `JWK`,
`TypeJWK`, `ExtractManifestData`). Validate: tdns-transport
builds with no MP `core` body types; transport-exercise builds.

## C5 — split `chunk_notify_handler`

Keep generic reassembly/decrypt + QNAME parse in transport; move
MP payload parsing + post-decrypt **zone** authz to tdns-mp; feed
the one `(senderID, TypeToken, rawPayload)` callback. **Binding
DoS invariant:** the pre-crypto **sender** authz
(`IsPeerAuthorized(sender,"")` before fetch+decrypt) STAYS in
transport; do not merge the two authz calls across the seam.
Preserve the `ChunkHandler` MP callbacks (`IsPeerAuthorized`,
`OnConfirmationReceived`, `GossipForPeer`,
`OnPeerDiscoveryNeeded`). Peer-level authz middleware stays for
transport-own verbs; the app-verb middleware is removed (app
authz is post-callback in MP). **Envelope label lands here**
(decided, principle 9): explicit `envelope = none|jose|cose`
replacing the `IsPayloadEncrypted()` byte-sniff; additive field,
absent ⇒ `jose` (Do53 default), so mixed fleets stay INVARIANT.

**Scope note — receive path only.** C5 splits the *receive* path
(`chunk_notify_handler`). It deliberately does NOT touch the
query-mode *serve* path that still lives in tdns-mp
(`chunk_store.go`, `chunk_query_handler.go`, the signer's
`fetchChunkPayloadViaQuery`, the `ChunkPayloadStore` config field
+ `main_init.go` wiring). Moving those is post-refactor cleanup —
see the "Transport owns the full transportation chain" item in F2.

## C6 — minimize constants + payload types

Reduce `MessageType` constants to transport-own; collapse
`DetermineMessageType` to "return the TypeToken"; move the 7 MP
`Dns*Payload` structs + parse helpers to MP, keep the 5
transport-own. **Wire-safety gate enforced by the C0 golden
test** — moved structs keep marshalling `"MessageType"` (and all
tags) byte-identically.

## C7 — remove zone concepts from transport

Delete `ZoneRelation` (`peer.go:159`), `Peer.SharedZones`
(`peer.go:81`), `AddSharedZone`/`GetSharedZone(s)`/
`ReplaceSharedZones`/`ByZone` (`peer.go:587-622,738`) and the MP
callers. The `HandleSync` zero-shared-zones gate
(`handlers.go:225`) moved to MP in C3; the outbound-beat zone
source is participant-derived since A2. **Rewrite or retire
`TestTransportBoundary_LegacySyncRejection`**
(`transport_integ_test.go:404`) — it asserts the transport-side
gate that no longer exists.

**Stage C probe — INVARIANT** (pure relocation; wire unchanged,
golden test enforcing): exercise BOTH edns0 and query modes;
SYNC + RFI + combiner async confirm + an election cycle; one
mixed-version pair per the C0 runbook. Most likely surprises
remain C6 (tag drift — now CI-caught) and C5 (a dropped field
that delivers but no longer dispatches — add a dispatch-count
probe to the harness if cheap).

---

# Stage D — liveness & send semantics

Stage D inherits the **fourth state store**: NG liveness on
`hsync.PeerDetails` (`State`, `BeatInterval`, `LatestRBeat/SBeat`,
read by `checkPeerState`, `hsync/beat.go:126`), which Stage A
deliberately did not touch. The plan was three bullets; given the
A3d experience (the census grew at every audit), D now starts
with its own audit step.

**PARTIALLY PULLED FORWARD 2026-06-11.** The peer-state truth fix
(Gate-1 fallout; see `2026-06-11-peer-state-and-discovery-truth-fix.md`)
already moved the CORE of D2 onto `transport.Peer`:
- **OPERATIONAL** is now set on `transport.Peer.Mechanisms[m]` by the
  outbound beat-success path (Fix A), with all inbound-receipt
  promotions removed from combiner/signer/agent handlers.
- **Decay** (OPERATIONAL→DEGRADED→INTERRUPTED) now happens on
  `transport.Peer` via decay-on-read in `EffectiveState()`
  (`decayedMechanismState`, Fix B) — keyed on outbound-beat age
  (`LastBeatSent`), thresholds mirroring NG `checkPeerState`. The
  EXPLAINED DELTA (DEGRADED/INTERRUPTED becoming visible in
  `gossip state`) has effectively landed for the gossip-matrix path,
  which derives from `EffectiveState`.

So D2's hard part is done and verified. What REMAINS for Stage D
(see the amended D2 below): retiring the now-redundant NG
`checkPeerState`/`hsync.PeerDetails` decay so there is one store, and
wiring the exact local beat interval. D0/D1/D3 stand as written.

## D0 — `hsync.PeerDetails` writer-path audit (NEW; one session-part)

Before any D implementation: per-field table for
`hsync.PeerDetails` in the A3d-addendum §4 style — every writer
path (`applyInboundBeat`, `checkPeerState`, discovery), every
reader, the `transport.Peer` target slot, coverage gaps. Output:
a short scope doc (or a section appended to this plan) binding
D1/D2 slices. The known target mapping: `State` →
`Mechanisms[m].State` (DEGRADED/INTERRUPTED become real transport
states), `BeatInterval` → new `transport.Peer` liveness param,
`LatestRBeat/SBeat` → `LastBeatRecv/Sent` (exist). **The audit MUST
enumerate the END.0 dual-write feed and the hsync-engine send-trigger
readers (`agentNeedsHello`/`fastBeatAttempts`, `hsync/hello.go`) — these
are the `hsync.PeerDetails.State` readers/writers D2.5 retires; see D2
item 5.**

## D1 — relocate Hello/Beat fallback into the TM

Relocate the EXISTING sequential, any-success semantics of
`SendHelloWithFallback`/`SendBeatWithFallback` into the TM
(`TM.Send` currently rejects Hello/Beat, `manager.go:346`).
INVARIANT — no behavior change. String-keyed mechanism shape
(principle 8). Per-peer beats are already concurrent;
per-mechanism parallel remains an optional follow-up (Open
decision 5).

## D2 — transport-owned liveness (the one deliberate behavior delta) — CORE DONE 2026-06-11; cleanup remains

**Done (peer-state truth fix):** liveness evaluation now reads from
`transport.Peer` (`EffectiveState` decay-on-read); OPERATIONAL is set
on `Mechanisms[m]` by the outbound beat path; inbound-receipt
OPERATIONAL writes deleted from the combiner/signer/agent handlers.
The EXPLAINED DELTA (DEGRADED/INTERRUPTED now visible) has landed for
the gossip-matrix path.

**Remaining D2 cleanup:**
1. **Retire the NG decay duplicate.** `hsync/beat.go:checkPeerState`
   still computes the same decay on `hsync.PeerDetails`; it is now
   redundant for everything reading `transport.Peer`. Delete it (and
   the `hsync.PeerDetails` liveness fields `State`/`BeatInterval`/
   `LatestRBeat`/`LatestSBeat`) once nothing reads the NG store —
   verify no remaining NG-store reader first. Until then the two
   coexist (one decay computed in two places); they agree because the
   thresholds were deliberately mirrored.
2. **Wire the exact local beat interval.** `transport.Peer.LivenessInterval`
   (the decay's threshold base) defaults to 30s when unset.
   **INFRA SLICE DONE 2026-06-13 (pulled forward).** The testbed showed
   combiner/signer (`peer list`) stuck at INTERRUPTED while healthy:
   infra peers beat on the 600s `StartInfraBeatLoop` cadence but were
   decayed by the 30s default (INTERRUPTED at 300s, before the next
   600s beat). Added `Peer.SetLivenessInterval(seconds)` (transport) and
   stamped `defaultInfraBeatInterval` (600s) onto the combiner/signer
   transport.Peer in `InitializeCombinerAsPeer`/`InitializeSignerAsPeer`.
   This was NOT an S3/S4 regression — the decay-on-read predates them
   (`3b85754`); the canonical-state reads merely surfaced it.
   **STILL TODO (agent slice):** stamp `LivenessInterval` from
   `mp.Remote.BeatInterval` on AGENT peers (discovered + config). It is
   correct on a 30s fleet via the default, so not a blocker; cleanest
   via a field on `MPTransportBridge` (set once at construction; 4
   `NewMPTransportBridge` sites in `main_init.go` + the harness) stamped
   alongside `SetMechanismLastBeatSent`, OR a `PeerRegistry` default that
   `NewPeer`/`GetOrCreate` inherit.
3. **`peer list` State column still reads AgentDetails** (Spine-1b
   territory, not yet redirected). After Spine-1b/this cleanup it
   should read `transport.Peer` too, so `peer list` and `gossip state`
   are driven by one store. Until then they can momentarily differ
   (AgentDetails has no decay). **Observed 2026-06-13 (post-restart
   convergence):** during reconvergence the two readouts briefly showed
   different states for the same agent peer (e.g. gossip OPERATIONAL vs
   peer list NEEDED/INTRODUCED), self-healing within a beat round-trip.
   Root cause: `peer list` falls back to `agent.DnsDetails.State`, which
   the outbound-HELLO success path advances (to INTRODUCED) WITHOUT
   writing the transport stores — a coupling the deleted
   `PopulateFromAgent` used to provide. TRANSIENT (the next beat
   round-trip writes the transport mechanism state and they reconverge),
   not a stable desync; fully resolved when `peer list` reads
   `transport.Peer` as the sole store (END.0 DTO + this item).
4. Per the original D2: default liveness middleware updates
   `Peer.Mechanisms[m]` on hello/beat receipt — the inbound-liveness
   *evidence* writes (`LastBeatRecv`) are already in place from Fix A;
   formalize as middleware if desired.
5. **Migrate the hsync-engine SEND-TRIGGER off `hsync.PeerDetails.State`
   — DONE 2026-06-13, TESTBED-CONFIRMED (mp `6b97300` + fix `74368c0`),
   PULLED FORWARD ahead of END.1** (it was the END.0 dual-write residual;
   the deferral had already failed once, so we finished it). The hsync
   engine's Hello/Beat/discovery/beat-readiness gates (`agentNeedsHello`,
   `fastBeatAttempts`, `retryPendingDiscoveries`/`attemptDiscovery`,
   `peerAnyTransportReady`) now read connection state from `transport.Peer`
   via a new `mechPeerState` helper (raw, default NEEDED on absence). All 7
   END.0 dual-write sites deleted; the now-dead NG decay (`checkPeerState`)
   + dead helpers (`apiState`/`dnsState`/`IsAnyTransportOperational`)
   removed. `EffectiveState` + the hsync `GossipStateTable` KEPT — dead in
   production (agent/auditor wire the no-op `agentGossipPort`; real gossip
   refreshes MP-side from `transport.Peer`) but entangled, for a later
   dedicated removal. **One regression found+fixed on the testbed
   (`74368c0`):** `helloRetrierNG` was launched ONLY from the engine's
   `attemptDiscovery`; a peer discovered out-of-band (the chunk-notify
   "missing key" kick → MP `DiscoverAndRegisterAgent`, reaching KNOWN
   without entering `attemptDiscovery`) stranded at KNOWN. Pre-D2.5 this
   worked by accident (the lagging NG store made the scan re-run discovery,
   incidentally launching Hello). Fix: `retryPendingDiscoveries` now starts
   the Hello for any KNOWN-no-retrier peer via the idempotent
   `startHelloRetrier`; `helloRetrierNG` clears its cancel on exit so the
   guard tracks "running" not "ever ran". Engine-path regression tests
   added (`hsync/d25_test.go`). **This UNBLOCKS END.1** — the bridge is no
   longer state-load-bearing. Original framing (kept for the trail):
   Distinct from item 1's *decay* reader
   (`checkPeerState`): the engine's send *decision* reads
   `hsync.PeerDetails.State` too — `agentNeedsHello`
   (`hsync/hello.go:17`, gates Hello on `== PeerStateKnown`) and
   `fastBeatAttempts` (`hsync/hello.go:79`, gates Beat on
   `== PeerStateIntroduced`). END.0 stopped writing
   `agent.{Api,Dns}Details.State` as the *functional read* source
   (gates/display now read `transport.Peer`) but, because this engine
   trigger still reads the NG store, END.0 had to RESTORE those writes as
   a transitional **dual-write** (mp `7d1ec60`) — else the engine never
   fires Hello/Beat (the testbed regression: agents stuck at KNOWN, no
   handshake, election storm; root-caused 2026-06-13). The dual-write
   sites, each tagged `// END.0 dual-write (transitional, retire in
   Stage D)`: discovery KNOWN (`agent_discovery.go`, API+DNS),
   Hello-success INTRODUCED + inbound-hello INTRODUCED + Beat-success
   OPERATIONAL (`hsync_transport.go`). They reach the NG store via the
   bridge (`agentDetailsToHsync`/`syncHsyncPeerFromAgent`). **D2.5 = point
   `agentNeedsHello`/`fastBeatAttempts` at `transport.Peer` mechanism
   state, then delete the 4 dual-write sites + the `hsync.PeerDetails`
   non-liveness `State` reads.** Needs the hsync `Transport` dep (or a
   state-getter) to expose per-mechanism state into the `hsync/`
   subpackage — same plumbing END.3 wants for the inbound pipeline, so
   sequence D2.5 with END.3 if convenient. Until done, `transport.Peer` is
   canonical for reads/display/gossip/send-gates/the top-level marker, and
   the dual-write is ONLY the feed to this not-yet-migrated trigger.

## D3 — lifecycle into TM startup

Enumerate the scattered registration sites (chunk-notify,
incoming router, role-router replacements post-C3, across
`start_*.go` + `main_init.go`) and move them into TM startup.

**Probe — INVARIANT** under all-mechanisms-healthy except the D2
delta, which must be predicted in writing before D2 lands.

---

# Stage E — discovery into transport

## E1 — move the discovery mechanism into transport

Create the transport `DiscoveryService`; move identity→
{addr,key,SVCB} resolution from `tdns-mp/v2/hsync/discovery.go`.
**Updated entry-point inventory (3, not 4):** (1) the
`hsync/discovery.go` → `DiscoverPeer` seam, (2)
`OnPeerDiscoveryNeeded` on the chunk handler, (3)
`Engine.Rediscover` (`peer reset`, since `d4577d4`). The legacy
`attemptDiscovery` path no longer exists (`6b671ac`). MP keeps
"who to discover" (HSYNC3 → NEEDED intent on `transport.Peer`,
already the case since A3d.0). **`agentMeta.Crypto` migrates to
`transport.Peer` crypto slots here** (the addendum's E1
deferral); `agentMeta.Api` migrates when the API mechanism owns
its client — if that is not natural at E1, record the residual
explicitly rather than letting the sidecar silently persist.
`OnDiscoveryFailed` must fire on all failure paths. Fix the
post-restart KNOWN→OPERATIONAL gap opportunistically (known
runtime issue, v2 cross-stage list). **Carry forward (do not
revert) the peer-state-truth fixes already in this path** (mp
`fc0c189`): discovery is gated on locally-supported transports
(Fix E — `DiscoverAgent(…, apiSupported, dnsSupported)`), and a
URI-without-resolved-address is NOT marked usable/"complete"
(Fix C — `dnsUsable`/`apiUsable` in `RegisterDiscoveredAgent`).
When this logic moves into the transport `DiscoveryService`, both
properties must survive the move.

## E2 — delete the `DiscoveryDriver` seam

`manager.go:395-417` ("TEMPORARY seam… Phase 6 part 2 removes
it") + the MP `RunDiscovery` wiring.

**Probe — INVARIANT:** peer restart → rediscovery → OPERATIONAL;
discovery works for a non-MP consumer (transport-exercise gains a
discovery smoke test — this is the reusability proof point).

---

# Stage F — finish

- **F1 — `Gossip`→`AppData` rename.** The ONLY deliberate wire
  break. Enumerate ALL gossip tag sites (`BeatRequest`
  `json:"gossip"` `transport.go:137`; `DnsBeatPayload`
  `json:"Gossip"`; beat-response; master Appendix H.4).
  Fleet-wide coordinated upgrade; EXPLAINED DELTA (old↔new cannot
  exchange gossip).
- **F2 — docs/cleanup.** Stale `init.go` integration guide
  (references the `IncomingChan` goroutine; production uses
  `RouteToCallback`); editor backup files (`Makefile~`,
  `types.go~`, `combiner_chunk.go~`, doc `~` duplicates); mark
  superseded docs' Status lines; the (B)-fields presentation
  finish if not already done.
- **F2b — transport owns the FULL transportation chain (deferred
  goal; design at execution time, not now).** End state (operator
  intent, 2026-06-13): the application says to transport "send this
  data to this recipient and tell me when it has been received" —
  and touches NO framing, chunking, query-mode, payload store, or
  fetch mechanics. The opaque-message seam (C1–C3) + receive-path
  split (C5) get the *receive* side there; this item finishes the
  *send/serve* side that the C-stages deliberately leave in tdns-mp.
  Remnant inventory to move into transport (verified 2026-06-13):
  - `chunk_store.go` — `ChunkPayloadStore` iface + `MemChunkPayloadStore`
    (serve-side TTL payload cache).
  - `chunk_query_handler.go` — `RegisterChunkQueryHandler`,
    `chunkQueryHandler`, `serveChunkRR` (answers inbound CHUNK queries).
  - `signer_chunk_handler.go` — `fetchChunkPayloadViaQuery` (the
    query-mode fetch callback) + the `RegisterSignerChunkHandler`
    wiring (the role-router half collapses in C3; the fetch half
    lands here).
  - `config.go` `ChunkPayloadStore` field + the ~4 `main_init.go`
    wiring sites (agent/auditor/combiner/signer:
    `NewMemChunkPayloadStore`, `RegisterChunkQueryHandler`,
    `conf.InternalMp.ChunkPayloadStore`).
  - `chunk_mode` / `chunk_query_endpoint` operator config become
    transport-internal (the app should not choose edns0-vs-query).
  After F2b, tdns-mp retains NO chunk *framing* — only application
  semantics over the reassembled payload (combiner edit logic in
  `combiner_chunk.go`, which is misnamed and should lose the "chunk"
  name). Scope/risk: medium; touches the serve path + config surface;
  do it as its own slice AFTER the merge proves the receive side, so
  the C-stage wire risk and this are never entangled. NOT C-stage work.
- **F3 — Phase 8–9 leftovers.** Exported-type count
  (88 → target <30; most of the reduction falls out of C4/C6/C7 —
  F3 verifies and unexports the remainder, e.g. the 5 kept
  `Dns*Payload` types where possible); verify zero MP-coupled
  imports remain; `imr.go`'s full `tdns/v2` import reviewed.
- **Merge to main** + resolve the go.mod publishing story (drop
  local replaces, push fetchable tags). Operator policy satisfied:
  main is touched exactly once, with the proven system.

---

# Cross-stage rules (carried, binding)

- **Lock order:** `AgentRegistry.mu` → peer mutex (one, =
  `hsync.Peer.Mu` after A3d-END) → `transport.PeerRegistry` →
  `transport.Peer`. Never hold a registry/peer mutex across a
  transport call. Single-writer per peer field. `-race` on
  boundary/hsync suites at every A/C Step.
- **Heterogeneous-fleet safety:** every Step except F1 is
  wire-compatible; C-touching Steps follow the C0 runbook.
- **Writer-path-audit rule** (addendum §8.3, now global): before
  redirecting any field's reads, enumerate ALL writer paths and
  confirm the target store is written identically on each; never
  derive a field from a sibling field.
- **One Step = one commit**; lettered sub-steps are commits.
  Refresh the code map per Step (line numbers in this doc are
  2026-06-11 for verified items, 2026-05-30 for carried v2 refs).
- Operator deploys + verifies on the testbed at every Stage
  checkpoint and at the explicitly marked Gates.

# Execution checklist (per Step)

1. On the stage branch (`transport-redesign-v1-A` through the
   Stage A exit gate; `-v1-C` thereafter).
2. Refresh the Step's code map against the branch.
3. Capture the Stage probe baseline (first Step of a Stage).
4. Implement; `gofmt -w`; build all affected repos — which, from
   Gate-2 on, includes tdns-transport/v2 **standalone** and
   `cmd/transport-exercise`.
5. Re-run probes; compare to prediction; `-race` where relevant.
6. Commit; push; operator deploys + verifies per the Stage's
   probe.

# Effort (re-derived bottom-up, 2026-06-11)

Sessions = burst days incl. the testbed loop, per the 05-28
convention. Calibration: the 06-03 session landed six A3d slices.

| Work | Sessions | Risk |
|---|---|---|
| Gates 1–3 + A3d-S1b…S4 | 1.5–2.5 | medium (S3 adds writes) |
| A3d-END (embed finalization) | 1 | medium-high (concurrency) |
| A5 + Stage A exit gate | 1–1.5 | medium (clobber release) |
| C0 (golden tests, runbook, build) | 0.5–1 | low |
| C1–C7 | 5–7 | high (wire; mitigated by C0) |
| D0–D3 | 2–3 | medium-high (D2 behavior delta) |
| E1–E2 | 1–2 | medium |
| F1–F3 + merge | 1–2 | low-medium (F1 wire break) |
| **Total remaining** | **≈ 13–20** | |

Supersedes the 05-28 table (8–13 total) and the review's
top-down 12–18 total: D was expanded (D0), C0 added, and the
Stage A growth factor applied to C. Re-check this table at every
stage exit gate; if a stage exceeds its top range, re-estimate
the remainder before continuing rather than after.

# Remaining open decisions (operator)

1. **DNS-URI display home (blocks A3d-S2). DECIDED 2026-06-11: (a).**
   Add `DNSEndpoint string` to `transport.Peer`, symmetric with the
   existing `APIEndpoint`. Rationale: discovery output is
   transport-owned (acceptance test), and `APIEndpoint` already
   sets the precedent — DNS having no endpoint home is the anomaly.
   Option (b) (derive the display URI from
   `Mechanisms["DNS"].Address`) is REJECTED with concrete evidence:
   the fox bug showed the URI (looked up at `<id>`) and the resolved
   IP (looked up at `dns.<id>`) are independent facts from separate
   lookups that genuinely disagree (Fix C keeps them separate), so
   deriving one from the other is exactly the banned sibling
   derivation. Note `DNSEndpoint` (human-readable `dns://…` URI, for
   display/diagnostics) is distinct from `Mechanisms["DNS"].Address`
   (resolved IP, used by the send path) — both are real peer
   attributes and both live on `transport.Peer`. (c) contradicts the
   end state (keeps it in dying AgentDetails). S2 is now UNBLOCKED.
2. **`CleanupZoneRelationships` (Gate-3):** confirm the proposed
   log-only resolution, or specify the teardown to implement.
3. **(B)-kept fields disposition at A5:** confirm the
   redirect-to-transport mapping proposed in A5.1, and whether
   the presentation finish (`peer list -v`) is worth scheduling
   immediately after A5 or parks until F2.
4. **DOQ-vs-C5 envelope timing (C0.4):** does the
   in-channel-CHUNK work need the `envelope` label before C5?
5. **Per-mechanism parallel Hello/Beat:** optional follow-up
   after D1, relevant once multi-mechanism peers exist. Not a
   one-way door (D1 keeps the shape string-keyed).
