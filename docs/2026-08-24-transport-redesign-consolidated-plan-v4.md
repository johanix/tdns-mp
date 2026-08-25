# Transport redesign: consolidated implementation plan — v4
# (remaining work)

Date: 2026-08-24
Status: AUTHORITATIVE & EXECUTABLE. Single source of truth for all
REMAINING transport-redesign work. Supersedes, for everything not
yet implemented: `2026-06-11-transport-redesign-consolidated-plan-v3.md`
and `2026-06-14-road-to-stage-C-plan.md`. Where v3 or the road-to-C
plan differs from v4, **v4 wins.**

Completed work is recorded here as a status table only (with commit
hashes and the branch it lives on); its specs live in the superseded
docs as the evolution trail. Binding designs carried intact, not
re-derived:

- Target architecture: v2 "Target architecture" + A3d addendum
  (`2026-06-01-a3d-field-ownership.md`) §1–5 (acceptance test,
  lock order, field ownership).
- Stage C step specs: v3 C1–C7 (carried below, line numbers
  refreshed 2026-08-24).
- Mixed-fleet procedure: `2026-07-10-stage-c-mixed-fleet-runbook.md`
  (still the C-stage operational doc).
- Peer-state truth model: `2026-06-11-peer-state-and-discovery-truth-fix.md`
  (Fixes A/B/C/E — carried into transport discovery in Phase 2.6).

## Relationship to prior docs

- **v3** (2026-06-11): plan of record through the A3d-END / A5
  window. Its remaining-work table is STALE as of 2026-07-10
  (it still listed END.3–END.5 / A5 / C0 / E as not started).
  Retained as evolution trail for Stage 0 through A3d-END.0 /
  D2.5 / E1.a.
- **Road-to-C** (2026-06-14, last updated 2026-07-10): the plan
  that actually executed the Stage A remainder. Hybrid method
  (batched deletion for consolidation; incremental for Stage C).
  Phases 1–4 are CODE DONE. The plan ends at the Stage C
  doorstep; v4 takes over from that doorstep, including the
  still-pending testbed of the stacked phases.
- **A3d addendum** (2026-06-01) §1–5: still the binding A3d
  design. Sequencing addenda are superseded.
- **Progress review** (2026-06-11): historical. Findings F1–F6
  were converted into v3 Gates and are closed in code.

## What v4 changes vs v3 (supersession list)

1. **The Stage A remainder is CODE DONE**, via the road-to-C
   phases, not via v3's original END.1–END.5 / A5 microsteps.
   E1.b, AgentDetails deletion, crypto rehome, discovery
   relocation, inbound-pipeline collapse, RemoteAgents deletion,
   OnPeerRemoved, U1000 sweep, and the C0 gate all landed
   2026-07-10. v3's "NOT STARTED" lines for END.3–END.5 / A5 /
   C0 / E1–E2 are wrong.
2. **Stage E is mostly done.** Phase 2.6 moved the discovery
   *process* into transport and deleted `DiscoveryDriver`.
   Residual is the transport-exercise discovery smoke test
   (reusability proof) — a Phase 4 candidate that was not
   taken. The *gate* (who to discover) stays MP, as designed.
3. **The next action is not C1.** It is a **stacked testbed
   pass** of undeployed Phases 1–4 (six weeks parked,
   2026-07-10 → 2026-08-24). No phase-complete or
   `stage-A-complete` / `stage-C-start` tags exist; only
   `end0-complete-pre-d2`. C1 is blocked on that checkpoint
   by the project's own probe discipline.
4. **Working branches replaced `transport-redesign-v1-A`.**
   tdns-mp tip is `phase-4-c0-gate`; tdns-transport tip is
   `phase-2.6-discovery`. `transport-redesign-v1-A` is frozen
   at the pre-Phase-1 cut (`388dd3b` / `892e5de`). There is
   no `transport-redesign-v1-C` yet.
5. **Two-repo lockstep is asymmetric and correct:** Phases 3–4
   did not touch transport, so transport stopping at 2.6 while
   mp carries 3–4 is expected. They must still be deployed as
   a pair (mp `phase-4-c0-gate` + transport `phase-2.6-discovery`).
6. **D2 item 3 (peer-list State column) is DONE** — S1b plus
   E1.b's `GetZoneAgentData` stamp from `effectiveAgentState`.
   Remaining D is: `hsync.PeerDetails` deletion (closes the
   embed trap), agent `LivenessInterval` stamping, D1 (Hello/Beat
   into TM.Send), D3 (startup registration).
7. **Open decisions 1–4 and road-to-C #5 are closed.** Remaining
   opens are listed at the end.
8. **Effort re-estimated** against the 2026-08-24 code census.

## Verified baseline (code-verified 2026-08-24)

Checked at: tdns-mp `phase-4-c0-gate` `92e64a6`; tdns-transport
`phase-2.6-discovery` `37c0dfb`. No testbed re-run (none since
2026-06-13). TESTBED PENDING covers everything from E1.b onward.

| Step | Status | Evidence |
|---|---|---|
| Stage 0 through A3d-S4, Gates 1–3 | DONE, most testbed-confirmed | see v3 status table |
| A3d-END.0 (State functional-merge) | DONE, TESTBED-CONFIRMED 2026-06-13 | mp `dbcb166` + `7d1ec60` |
| D2.5 (engine reads transport; dual-write retired) | DONE, TESTBED-CONFIRMED 2026-06-13 | mp `6b97300` + `74368c0` |
| A3d-END.1 E1.a (Agent embeds `*hsync.Peer`) | DONE, never deployed | mp `3fbeffd` |
| IsRecipientReady missed-reader fix | DONE, never deployed | mp `edfa079` |
| **Phase 1 = E1.b** (one alloc, bridge gone) | CODE DONE 2026-07-10, **TESTBED PENDING** | mp `31d0dd7` on `phase-1-e1b`; `hsync_bridge_sync.go` deleted; `materializeAgentView` / `e1b_view_test.go` |
| **Phase 2** (AgentDetails deleted) | CODE DONE 2026-07-10, **TESTBED PENDING** | mp `234933d`; struct gone; CLI heartbeat block dropped |
| **Phase 2.5** (crypto → transport.Peer) | CODE DONE 2026-07-10, **TESTBED PENDING** | mp `c181439` + transport `c5604ae`; `MechanismCrypto` + SetMechanismTLSA/JWK/KeyRR; `agentMeta` gone |
| **Phase 2.6** (discovery process → transport) | CODE DONE 2026-07-10, **TESTBED PENDING** | transport `37c0dfb` + mp `a17deb0`; `transport/discovery.go`; `DiscoveryDriver` gone; MP keeps the gate |
| **Phase 3a–c** (END.3/4 + OnPeerRemoved) | CODE DONE 2026-07-10, **TESTBED PENDING** | mp `8c3611f`; `applyInboundBeat` gone; `RemoteAgents` gone; `Engine.RemovePeer` + hook wired; **no production caller** of `RemovePeer` |
| **Phase 3d** (U1000 sweep) | CODE DONE 2026-07-10, **TESTBED PENDING** | mp `4ffc0bc`; `AgentRegistry.mu` shadow gone |
| **Phase 4 = C0 gate** | CODE DONE 2026-07-10 | mp `92e64a6`; `golden_wire_test.go` + 14 goldens; mixed-fleet runbook; envelope deferred to C5 |
| Stage A exit gate (tags / `transport-redesign-v1-C`) | NOT STARTED | only tag: `end0-complete-pre-d2` |
| C1–C7 | NOT STARTED | typed `SyncRequest` / `IncomingMessage`; handlers still in transport; `SharedZones` still on `transport.Peer` |
| D0 (PeerDetails writer-path audit) | NOT STARTED | struct still exists; residual writers in `hsync/discovery.go` |
| D1 (Hello/Beat into TM.Send) | NOT STARTED | `manager.go:307–338` still rejects Hello/Beat |
| D2 core (outbound OPERATIONAL + decay-on-read) | DONE, testbed-confirmed | transport `3b85754` |
| D2 infra `LivenessInterval` | DONE | combiner/signer `SetLivenessInterval(600)` |
| D2 agent `LivenessInterval` | NOT STARTED | 30s default only; `mp.Remote.BeatInterval` is engine config, not stamped on `transport.Peer` |
| D2 item 3 (peer-list State from transport) | DONE | S1b + `GetZoneAgentData` stamps `agent.State` from `effectiveAgentState` |
| D3 (lifecycle into TM startup) | NOT STARTED | routers still registered from `main_init.go` / `start_*.go` |
| E1/E2 (discovery into transport) | DONE in code (Phase 2.6) | residual: transport-exercise discovery smoke test |
| F1–F3, F2b | NOT STARTED | `json:"gossip"` / `json:"Gossip"` unchanged; `chunk_store.go` / `chunk_query_handler.go` still in mp |

## Where the code actually is (2026-08-24)

This is a mid-flight refactor parked for ~6 weeks after a
burst that finished the transport.Peer consolidation **in
code, never on the testbed**.

```
tdns-mp:        phase-4-c0-gate         92e64a6
tdns-transport: phase-2.6-discovery     37c0dfb
tdns-mp   transport-redesign-v1-A       388dd3b   (frozen pre-Phase-1)
tdns-transport  transport-redesign-v1-A 892e5de   (frozen pre-Phase-2.5)
restart tag:    end0-complete-pre-d2    (mp 2f00cca / transport 892e5de)
main:           untouched (operator policy until Stage F)
```

Linear stack on mp (every phase is an ancestor of HEAD):

```
31d0dd7  Phase 1  E1.b
234933d  Phase 2  AgentDetails gone
c181439  Phase 2.5 crypto rehome          (+ transport c5604ae)
a17deb0  Phase 2.6 discovery relocation   (+ transport 37c0dfb)
8c3611f  Phase 3a–c
4ffc0bc  Phase 3d
92e64a6  Phase 4  C0 gate
```

**End-state of the landed consolidation (code, unverified live):**
two stores joined by `PeerID`; `transport.Peer` owns identity,
address, per-mechanism state, liveness, wire crypto, stats;
`Agent` is a view embedding `*hsync.Peer` (one allocation, two
typed maps — engine cannot import the main package); no
deep-copy bridge; no `AgentDetails`; no `agentMeta`; discovery
process in transport, gate in MP. That is the A3d acceptance
test, minus the residual `hsync.PeerDetails` sidecar (Stage D)
and minus zone concepts still on `transport.Peer` (C7).

## Standing cautions (do not regress)

1. **Embed trap.** `Agent` has no `ApiDetails`/`DnsDetails`
   fields, but the embed makes `agent.ApiDetails` resolve to
   `hsync.Peer.ApiDetails` (`*hsync.PeerDetails`, the retired
   NG store). Documented at `agent_structs.go:69–74`. Do not
   reintroduce readers/writers through those names. Deleting
   `hsync.PeerDetails` (D2 leftover) removes the trap.
2. **Two maps by necessity.** `AgentRegistry.S` (`*Agent`) and
   `hsync.Registry.S` (`*hsync.Peer`) persist. Consistency is
   the shared pointer (`agent.Peer == that peer`), not
   field-copying. Do not attempt a single Go map.
3. **`mpHsyncBridge` is the live TransportBridge adapter**
   (SendHello/SendBeat/DiscoverPeer), not the deleted sync
   bridge. Do not delete it under an A5 heading.
4. **`OnPeerRemoved` is wired but unused in production.**
   Only `Engine.RemovePeer` fires it; only tests call
   `RemovePeer`. Zero-zone peers stay LEGACY by design.
   Adding an operator `peer delete` is a product decision,
   not a missing Stage A piece.
5. **Fixes E/C/A/B must survive every later move.** Discovery
   probes only locally-supported transports; URI-without-
   address is not KNOWN; OPERATIONAL only on outbound beat
   success; decay-on-read on `transport.Peer`. Phase 2.6
   carried E/C into `transport/discovery.go`; do not revert.

## Target architecture (unchanged — restated)

Two peer-state stores, partitioned by concern, joined only by
`PeerID`; transport speaks an opaque-message vocabulary; zone
membership — including admission — derived from HSYNCPARAM,
never stored-and-synced. `transport.PeerRegistry` owns identity,
address, per-mechanism state, liveness, wire crypto, stats. One
MP registry (`AgentRegistry` embedding `*hsync.Registry`) owns
app metadata; the MP per-peer record is nearly empty (`Agent`
is a view: `InitialZone`, `Api`, DTO `State`/`ErrorMsg`).
LEGACY is the one MP overlay (participations==0), never seen
by transport. Transport vocabulary = `hello/beat/ping/confirm/chunk`
+ one opaque carrier `{Scope, TypeToken, Payload}`. Full
statement: v2 "Target architecture" + addendum §1. Both binding.

## Probe discipline (unchanged, now executable)

Automated:

- `go test ./... -count=1` in **tdns-mp/v2 AND tdns-transport/v2
  standalone** (Gate-2 restored; hold it),
- `tdns/v2` compile, `cmd/transport-exercise` build,
- boundary harness + `hsync/*` suites; `-race` on every A/C
  Step (and on the testbed-prep rebuild of the stacked tip).

Runtime: `peer list`, `peer zones`, `gossip state -z`,
`zone edits list -z`, `distrib list`. Plus, because Phase 2.6
is behaviour-observable and undeployed: restart → rediscovery
→ NEEDED→KNOWN→OPERATIONAL, and `peer reset <id>`.

INVARIANT vs EXPLAINED DELTA semantics unchanged: an
unpredicted change in an INVARIANT probe **halts the Stage.**

Predicted deltas already documented for the undeployed stack
(confirm them on the testbed, do not treat as surprises):

- `peer status` State now matches gossip/peer-list
  (`effectiveAgentState`), not the stale NG-lagged shadow
  (Phase 1).
- Distrib row for a peer not yet in PeerRegistry shows NEEDED
  rather than skipping the row (Phase 2).
- Dual-mechanism `PreferredTransport` now ends `"API"`
  (Phase 2.6; DNS-only fleets unaffected).
- A peer that stops publishing a transport keeps a stale
  offered-flag until ContactInfo cleanup (Phase 2.6; Stage D
  note, not a C concern).

## Baseline & branching strategy (updated 2026-08-24)

- **main is untouched until Stage F is proven** (operator
  policy — unchanged).
- Current working pair: mp `phase-4-c0-gate` + transport
  `phase-2.6-discovery`. Continue Stage C on branches cut
  from these tips *after* the testbed checkpoint, named
  `transport-redesign-v1-C` in both repos (or keep the
  phase-branch convention; pick one at the checkpoint and
  stick to it).
- After the stacked testbed pass: tag `stage-A-complete` in
  BOTH repos (mp `92e64a6` + transport `37c0dfb`, or whatever
  SHAs actually verified). That pair IS the Stage C starting
  point; a separate `stage-C-start` tag is optional
  duplication. The per-phase tags (`phase-1-e1b-complete`,
  …) were deferred so long that tagging them now on
  unverified SHAs is ceremony — skip unless a rollback
  story needs them. The rollback tag that exists and is
  meaningful is still `end0-complete-pre-d2`.
- go.mod local replaces stay on working branches; each tag
  records the sibling commits it was verified against. The
  publishing story is decided once, at the Stage F merge.

---

# Next action — stacked testbed of Phases 1–4 (BLOCKING for C1)

This is the addendum's post-embed checkpoint, relocated, then
stacked with four more phases, then parked. It is the single
point of schedule and confidence loss.

**Deploy** the current pair (mp `phase-4-c0-gate` / transport
`phase-2.6-discovery`) to the espresso.mp fleet. Do **not**
try to verify Phases 1–4 incrementally on the live fleet —
the operator already chose to stack, and the only clean
rollback is `end0-complete-pre-d2`.

**Probe set** (byte-comparable on a healthy fleet, plus the
Phase 2.6 observables):

- `agent gossip state -z espresso.mp.axfr.net` — fully
  OPERATIONAL matrix after convergence.
- `agent peer list` / `agent peer zones` — address columns
  and State agree with gossip (the old convergence-window
  gossip-vs-peerlist delta should be gone; if it still
  appears, it is a regression, not the documented transient).
- Combiner/signer stay OPERATIONAL (infra `LivenessInterval`
  600s must still hold).
- Restart one agent → rediscovery → NEEDED→KNOWN→OPERATIONAL.
- `agent peer reset <id>` re-drives discovery.
- One SYNC + one RFI + one election cycle.
- Confirm the predicted deltas above; anything else halts.

**Still nice-to-have, not blocking C1** (carried from Gate-1):
homogeneous all-tip fleet; deliberate fox-NS break/restore
for FAILURE+RECOVERY. Worth doing on this same deploy if the
fleet is available — the stacked code has never seen a live
ERROR/decay path.

**Do not start C1 on a failed or skipped checkpoint.** Stage C
is the wire-risk stage; it must start from a known-good live
baseline, not from "the tests were green in July."

# Stage A exit gate (after the testbed pass)

1. Tag `stage-A-complete` in tdns-mp AND tdns-transport; tag
   message records the sibling commit pair + the tdns/v2
   commit verified against.
2. Cut `transport-redesign-v1-C` from the tags (or rename the
   current pair — see branching strategy).
3. Re-verify standalone builds at the tag (Gate-2 must still
   hold): tdns-transport/v2 `go build ./... && go test ./...
   -count=1 -race`; `cmd/transport-exercise` build; tdns-mp
   5 binaries + full `-race`.

---

# Stage C — transport cleanup / the opaque-message seam

Goal unchanged (v2/v3): transport speaks only
`hello/beat/ping/confirm/chunk` + one opaque carrier; all MP
verbs are app-level `TypeToken`s; one tdns-mp callback.
Delivers the reusable-library goal. The hard infrastructure
exists (`DNSMessageRouter` token-keyed; `RouteToCallback`
live at MP) — C is mostly relocation + deletion.

**C0 is DONE** (Phase 4). The four blocking items hold in
code: standalone builds, golden-wire suite
(`tdns-mp/v2/golden_wire_test.go` + `testdata/golden-wire/`,
14 goldens), mixed-fleet runbook, envelope deferred to C5.
Re-run the goldens after the testbed pass before C1; they
are the mechanical enforcement of C6's wire-safety gate.

C-touching Steps follow
`2026-07-10-stage-c-mixed-fleet-runbook.md`. One observer
agent first (cpt); combiner/signer last on C3/C5.

## C1 — define the seam

Add `{Scope, TypeToken string, Payload json.RawMessage}` to
the carrier (generalize `SyncRequest`/`IncomingMessage`);
keep the live `RouteToCallback` seam; widen `IncomingMessage`
to carry `TypeToken`. Additive — both sides still work.

**Verified 2026-08-24, still the starting shape:**

```go
// transport/handler.go:17 — no Scope, no TypeToken
type IncomingMessage struct {
    Type, DistributionID, SenderID, TransportSender, Zone, Nonce string
    Payload []byte
    ...
}
// transport/transport.go:153 — still fully typed
type SyncRequest struct { SenderID, Zone string; SyncType SyncType; Records map[string][]string; ... }
```

Wire note: the verb stays the JSON payload key `"MessageType"`;
carrier-struct field names are wire-irrelevant as long as C6
keeps marshalling `"MessageType"` with the same value (enforced
by the C0 golden test).

## C2 — collapse the send side

Replace typed `DNSTransport.Sync/Keystate/Edits/Config/Audit`
(+`SendStatusUpdate`) with one generic
`Send(ctx, peer, Scope, TypeToken, rawPayload)`;
Hello/Beat/Ping/Confirm keep typed entry points. Rewrite the
MP send wrappers (`SendSyncWithFallback`, `sendRfiToSigner/Combiner`,
`sendKeystateToSigner`, `sendConfigToAgent`, `sendAuditToAgent`)
to set `TypeToken`. Preserve `SendStatusUpdate` fire-and-forget
semantics (pass-2 M6). Keep the per-mechanism send/result shape
string-keyed (principle 8 — DOQ is coming; never a 2-element
API/DNS shape).

**Verified 2026-08-24:** the typed methods still exist
(`dns.go` Sync `:332`, Keystate `:607`, Edits `:704`, Config
`:747`, Audit `:789`, SendStatusUpdate `:911`).
`TransportManager.Send` (`manager.go:320`) still dispatches
only Sync/Ping/Relocate and rejects Hello/Beat — that rejection
is D1, not C2; do not "fix" it here.

## C3 — move receive handlers to tdns-mp

Move the 8 MP handlers (`HandleSync/Rfi/Keystate/Edits/Config/
Audit/StatusUpdate/Relocate`, `handlers.go:220–640`) behind one
`RouteToCallback` dispatcher keyed on `TypeToken`; transport
keeps `HandleHello/Beat/Ping/Confirmation`. Preserve: role-
specific handler sets (combiner `HandleUpdate` /
`NewCombinerSyncHandler` async-confirm; signer keystate/rfi/
status subset); combiner/signer registration MUST work without
an `AgentRegistry` (they build with config-only
`AuthorizedPeers`, `main_init.go`); inline-ACK
(`ctx.Data["response"]` NOTIFY-confirm path). Collapse the
MP-side duplicate verb table `routeIncomingMessage`
(`hsync_transport.go:637–665`) into the one dispatcher — no
third table. Delete `InitializeCombinerRouter` /
`InitializeSignerRouter` + configs (`router_init.go:283/429`).

## C4 — move MP types out

Move `SyncType`, `Keystate/Edits/Config/Audit` req+resp,
`KeyInventoryEntry`, `RejectedItemDTO` to tdns-mp; drop the MP
`core.` imports (still present 2026-08-24 across ~7 transport
files: `core.AgentMsg*`, `core.Agent*Post`,
`core.KeyInventoryEntry`, `core.PublishInstruction`,
`core.RROperation`, `core.StatusUpdatePost`), leaving only
wire/crypto types (`CHUNK`, `TypeCHUNK`, `Format*`, `JWK`,
`TypeJWK`, `ExtractManifestData`). Validate: tdns-transport
builds with no MP `core` body types; transport-exercise builds.

## C5 — split `chunk_notify_handler`

Keep generic reassembly/decrypt + QNAME parse in transport;
move MP payload parsing + post-decrypt **zone** authz to
tdns-mp; feed the one `(senderID, TypeToken, rawPayload)`
callback. **Binding DoS invariant:** the pre-crypto **sender**
authz (`IsPeerAuthorized(sender,"")` before fetch+decrypt)
STAYS in transport; do not merge the two authz calls across
the seam. Preserve the `ChunkHandler` MP callbacks
(`IsPeerAuthorized`, `OnConfirmationReceived`, `GossipForPeer`,
`OnPeerDiscoveryNeeded`). Peer-level authz middleware stays
for transport-own verbs; the app-verb middleware is removed
(app authz is post-callback in MP).

**Envelope label lands here** (decided, principle 9; C0.4
closed 2026-07-10): explicit `envelope = none|jose|cose`
replacing the `IsPayloadEncrypted()` byte-sniff; additive
field, absent ⇒ `jose` (Do53 default), so mixed fleets stay
INVARIANT. The C0 goldens lock today's bytes WITHOUT the
field; C5 regenerates them (`go test -run TestGoldenWire
-update ./...`) and the diff is reviewed in the same commit.
Revisit the deferral ONLY if in-channel-CHUNK implementation
starts before C5.

**Scope note — receive path only.** C5 splits the *receive*
path (`chunk_notify_handler.go`, still monolithic ~581 lines,
`parsePayload` ~`:255`). It deliberately does NOT touch the
query-mode *serve* path that still lives in tdns-mp
(`chunk_store.go`, `chunk_query_handler.go`, the signer's
`fetchChunkPayloadViaQuery`, the `ChunkPayloadStore` config
field + `main_init.go` wiring). Moving those is F2b.

## C6 — minimize constants + payload types

Reduce `MessageType` constants to transport-own; collapse
`DetermineMessageType` (`router_init.go:546–585`, 13-case
switch) to "return the TypeToken"; move the 7 MP
`Dns*Payload` structs + parse helpers to MP, keep the 5
transport-own. **Wire-safety gate enforced by the C0 golden
test** — moved structs keep marshalling `"MessageType"` (and
all tags) byte-identically.

## C7 — remove zone concepts from transport

Delete `ZoneRelation` (`peer.go:189`), `Peer.SharedZones`
(`peer.go:85`), `AddSharedZone`/`GetSharedZone(s)` /
`ReplaceSharedZones`/`ByZone` (`peer.go:723–756`) and the MP
callers. The `HandleSync` zero-shared-zones gate
(`handlers.go:225`) moved to MP in C3; the outbound-beat zone
source is participant-derived since A2. **Rewrite or retire
`TestTransportBoundary_LegacySyncRejection`**
(`transport_integ_test.go`) — it asserts the transport-side
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

Stage D inherited a fourth state store: NG liveness on
`hsync.PeerDetails`. D2 core (outbound OPERATIONAL +
decay-on-read) and D2.5 (engine send-triggers read
`transport.Peer` via `mechPeerState`) already landed and were
testbed-confirmed 2026-06-13. `checkPeerState` is **gone**.
What remains is the leftover sidecar and the two TM chores.

## D0 — `hsync.PeerDetails` writer-path audit (still required)

The struct is retired as a *functional* store but **still
allocated and still written**. Before deleting it, per-field
table in the A3d-addendum §4 style. Known 2026-08-24 census
(starting point, not a substitute for the audit):

| Field | Residual writers (hsync/) | Functional readers |
|---|---|---|
| `PeerDetails.State` | `Rediscover` (`discovery.go:73–77`) | `hsync.Peer.EffectiveState` — dead in production (only the leftover hsync GossipStateTable / tests) |
| `DiscoveryFailures` / `LatestError*` | `attemptDiscovery` fail/success (`discovery.go:190–206`) | none found in production gates |
| `BeatInterval` / `LatestRBeat/SBeat` / `SentBeats` / `ReceivedBeats` / `HelloTime` / `LastContactTime` / `Addrs`/`Port`/`BaseUri` | init in `NewPeer`; `beatOutboundSequence` still *reads* `SentBeats` | `beatOutboundSequence` (`transport_peer.go:85–92`) — confirm whether anyone still consumes that sequence |
| `hsync.Peer.ApiDetails`/`DnsDetails` | `NewPeer` always allocates | the Agent embed trap (caution #1) |

Output of D0: a short section appended here binding the
deletion slices. Do not delete `PeerDetails` without this
census — Stage A taught that lesson three times.

Also enumerate, and schedule for the same deletion commit or
a dedicated follow-up: `hsync.Peer.EffectiveState` and the
dead-in-production hsync `GossipStateTable` (D2.5 kept them
as entangled). MP gossip already refreshes from
`transport.Peer`.

## D1 — relocate Hello/Beat fallback into the TM

Relocate the EXISTING sequential, any-success semantics of
`SendHelloWithFallback` / `SendBeatWithFallback`
(`hsync_transport.go:1452` / `:1559`) into the TM.
`TM.Send` currently rejects Hello/Beat (`manager.go:307–338`).
INVARIANT — no behaviour change. String-keyed mechanism shape
(principle 8). Per-peer beats are already concurrent;
per-mechanism parallel remains an optional follow-up (Open
decision 5).

## D2 leftovers (core DONE; these three items remain)

1. **Delete `hsync.PeerDetails`** (and `Peer.ApiDetails` /
   `DnsDetails`) once D0 shows zero functional readers. This
   is the embed-trap closer. Also drop the residual
   Rediscover/discovery-failure writers — those facts already
   live on `transport.Peer` (mechanism state, `OnDiscoveryFailed`).
2. **Stamp `LivenessInterval` on AGENT peers** from
   `mp.Remote.BeatInterval`. Infra already stamps 600s
   (`combiner_peer.go:89`, `signer_peer.go:90`). Correct on a
   30s fleet via the default, so not a correctness blocker;
   cleanest via a field on `MPTransportBridge` (set once at
   construction; `NewMPTransportBridge` sites in `main_init.go`
   + the harness) stamped alongside peer create / discovery
   complete, OR a `PeerRegistry` default that `NewPeer` /
   `GetOrCreate` inherit.
3. **(done)** `peer list` / `peer status` State read
   `transport.Peer` via `effectiveAgentState`. The DTO field
   `Agent.State` remains as a shadow stamped at
   `GetZoneAgentData` time (`agent_utils.go:278–281`); it
   retires with the DTO rework (presentation finish / F2),
   not here.

Inbound-liveness *evidence* (`LastBeatRecv`) is already in
place from Fix A; formalizing it as middleware is optional.

## D3 — lifecycle into TM startup

Enumerate the scattered registration sites (chunk-notify,
incoming router, role-router replacements post-C3, across
`start_*.go` + `main_init.go`) and move them into TM startup.

**Probe — INVARIANT** under all-mechanisms-healthy except any
D2 leftover that still changes displayed decay for non-30s
agent intervals (item 2), which must be predicted in writing
before it lands.

---

# Stage E — residual

E1/E2 as specified in v3 are **done in code** (Phase 2.6):
`transport/discovery.go` owns `DiscoverAgent*` /
`RegisterDiscoveredPeer` / `DiscoverAndRegisterPeer`;
`OnPeerDiscovered` is live and fired by transport; MP keeps
`DiscoverAndRegisterAgent` as a 26-line shim plus the
HSYNC3 gate (`MarkNeeded` / `attemptDiscovery` →
`DiscoverPeer`); `DiscoveryDriver` is gone; Fixes E/C
carried verbatim; `agentMeta.Api` was already deleted in
2.5.

**E-residual — transport-exercise discovery smoke test.**
`cmd/transport-exercise` still has no discovery path. This
is the reusability proof point (a non-MP consumer discovers
a peer). Cheap; do it as a small commit before or during F,
or as the first C-adjacent hygiene commit after the testbed
pass. Not a C1 blocker.

**Carry forward (do not revert)** the peer-state-truth
fixes already in this path (see Standing caution #5).
`OnDiscoveryFailed` must keep firing on all failure paths.

**Opportunistic, on the stacked testbed:** the historical
post-restart KNOWN→OPERATIONAL gap. D2.5's
`retryPendingDiscoveries` → `startHelloRetrier` was the
intended closer; confirm live.

---

# Stage F — finish

- **F1 — `Gossip`→`AppData` rename.** The ONLY deliberate
  wire break. Enumerate ALL gossip tag sites
  (`BeatRequest` `json:"gossip"` `transport.go:137`;
  `DnsBeatPayload` `json:"Gossip"` `dns.go:1257`;
  `apiBeatRequest` `json:"gossip"` `api.go:390`; beat-response;
  master Appendix H.4). Fleet-wide coordinated upgrade;
  EXPLAINED DELTA (old↔new cannot exchange gossip).
  Regenerates C0 goldens.
- **F2 — docs/cleanup.** Stale `init.go` integration guide
  (references the `IncomingChan` goroutine; production uses
  `RouteToCallback`); editor backup files (the
  `2026-03-30-mp-regression-test-plan.md~` duplicate is
  still in `tdns-mp/docs/`); mark superseded docs' Status
  lines (v2, v3, road-to-C, bite-era docs); the (B)-fields
  presentation finish (`peer list -v` reading transport.Peer)
  if not already done; drop stale comments that still mention
  `AgentRegistry.mu` (`agent_structs.go:197`, `agent_utils.go:63`)
  and "until A3d.4".
- **F2b — transport owns the FULL transportation chain
  (deferred goal; design at execution time, not now).**
  Unchanged from v3. After C5 the *receive* side is there;
  this item finishes the *send/serve* side still in tdns-mp:
  `chunk_store.go`, `chunk_query_handler.go`,
  `signer_chunk_handler.go` (`fetchChunkPayloadViaQuery`),
  `config.go` `ChunkPayloadStore` + `main_init.go` wiring,
  `chunk_mode` / `chunk_query_endpoint` becoming
  transport-internal. Do it AFTER the C-stage merge proves
  the receive side. NOT C-stage work.
- **F3 — Phase 8–9 leftovers.** Exported-type count (~87
  today → target <30; most of the reduction falls out of
  C4/C6/C7 — F3 verifies and unexports the remainder);
  verify zero MP-coupled imports remain; `imr.go`'s full
  `tdns/v2` import reviewed.
- **Merge to main** + resolve the go.mod publishing story
  (drop local replaces, push fetchable tags). Operator
  policy satisfied: main is touched exactly once, with the
  proven system.

---

# Cross-stage rules (carried, binding)

- **Lock order:** `AgentRegistry.S`'s ConcurrentMap (no
  outer `mu` — Phase 3d) → the ONE peer mutex
  (`hsync.Peer.Mu` == `Agent.Mu` via the embed) →
  `transport.PeerRegistry` → `transport.Peer`. Never hold a
  registry/peer mutex across a transport call. Single-writer
  per peer field. `-race` on boundary/hsync suites at every
  C/D Step.
- **Heterogeneous-fleet safety:** every Step except F1 is
  wire-compatible; C-touching Steps follow the C0 runbook.
- **Writer-path-audit rule** (addendum §8.3, now global):
  before redirecting any field's reads, enumerate ALL writer
  paths and confirm the target store is written identically
  on each; never derive a field from a sibling field.
- **One Step = one commit**; lettered sub-steps are commits.
  Refresh the code map per Step (line numbers in this doc
  are 2026-08-24 for remaining items).
- Operator deploys + verifies on the testbed at every Stage
  checkpoint. The current stacked undeployed window is the
  exception that must be closed before C, not a precedent.

# Execution checklist (per Step)

1. On the stage branch (`phase-4-c0-gate` / `phase-2.6-discovery`
   through the Stage A exit gate; `transport-redesign-v1-C`
   thereafter).
2. Refresh the Step's code map against the branch.
3. Capture the Stage probe baseline (first Step of a Stage).
4. Implement; `gofmt -w`; build all affected repos — including
   tdns-transport/v2 **standalone** and `cmd/transport-exercise`.
5. Re-run probes; compare to prediction; `-race` where relevant.
6. Commit; push; operator deploys + verifies per the Stage's
   probe. Follow the mixed-fleet runbook for every C-stage
   deploy.

# Effort (re-derived 2026-08-24)

Sessions = burst days incl. the testbed loop, per the 05-28
convention. The 13–20 remaining in v3 assumed END/A5/C0/E
were still ahead; they are not. Calibration: the 07-10 burst
landed Phases 1–4 in code without a testbed loop — that
debt is item 1, not "free."

| Work | Sessions | Risk |
|---|---|---|
| Stacked testbed of Phases 1–4 + Stage A exit tags | 0.5–1.5 | **high** (six weeks undeployed, four phases stacked; operational, not design) |
| C1–C7 | 5–7 | high (wire; mitigated by C0 goldens + runbook) |
| D0–D3 leftovers | 1.5–2.5 | medium (`PeerDetails` deletion is the embed-trap closer; D1 concurrency) |
| E residual (transport-exercise smoke) | 0.5 | low |
| F1–F3 + F2b + merge | 1.5–2.5 | low-medium (F1 wire break; F2b is its own slice) |
| **Total remaining** | **≈ 9–14** | |

Supersedes v3's 13–20. Re-check this table at the Stage C
exit gate; if C exceeds its top range, re-estimate the
remainder before D rather than after.

# Remaining open decisions (operator)

Closed since v3, recorded so they are not re-litigated:

1. **DNS-URI display home.** DECIDED 2026-06-11: (a)
   `transport.Peer.DNSEndpoint`. S2 landed.
2. **`CleanupZoneRelationships`.** DECIDED 2026-06-11:
   explanatory no-op (Gate-3, mp `18ac2d7`).
3. **(B)-kept fields.** Executed by Phase 2 (struct deleted)
   + Phase 2.5 (crypto). Presentation finish (`peer list -v`)
   and `HsyncPeerInfo` DTO remain parked at F2.
4. **DOQ-vs-C5 envelope timing.** DECIDED 2026-07-10: defer
   to C5 as planned.
5. **Discovery relocation.** DECIDED 2026-06-14 (road-to-C
   #5 = C): process in transport, gate in MP. Phase 2.6
   landed.

Still open:

1. **Stacked-testbed strategy.** Recommended: deploy the
   current pair as one checkpoint; rollback is
   `end0-complete-pre-d2`. Alternative (verify Phase 1 from
   `388dd3b` first) is cleaner isolation but spends a testbed
   cycle the operator already chose to skip in July.
2. **Pull `hsync.PeerDetails` deletion before C?** It closes
   the embed trap. Recommended: **no** — keep D after C so
   the wire-risk stage does not share a window with a
   store-deletion. The standing caution is sufficient unless
   someone reintroduces an `ApiDetails` reader during C.
3. **Per-mechanism parallel Hello/Beat:** optional follow-up
   after D1. Not a one-way door (D1 keeps the shape
   string-keyed).
4. **Branch naming at the C cut:** reuse `phase-*` or start
   `transport-redesign-v1-C` as v3 specified. Pick at the
   Stage A exit gate.
5. **Operator `peer delete`:** `OnPeerRemoved` is ready; no
   production caller. Product decision, not Stage C work.
