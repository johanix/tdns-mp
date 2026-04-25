# Transport Interface Redesign:
# Early Bites — Pre-Refactor Quick Wins

Date: 2026-04-25
Status: PLAN — recommended pre-work before initiating
        the larger transport interface redesign.

Companion to:
[2026-04-15-transport-interface-redesign.md](./2026-04-15-transport-interface-redesign.md)
[2026-04-23-transport-boundary-test-harness.md](./2026-04-23-transport-boundary-test-harness.md)

## Purpose

The 2026-04-15 transport interface redesign is a serious
multi-repo restructure (9 phases, ~54 methods on
`MPTransportBridge`, three repos kept building at every
step). Re-evaluation on 2026-04-25 concluded that we are
not ready to commit to the whole elephant yet, but several
constituent pieces are ready to land independently.

This document collects the **early bites** — small,
additive, individually revertible changes that:

1. Move the codebase incrementally toward the target
   architecture without committing to the full refactor.
2. Reduce the scope of the eventual phases when we do
   start them (most bites turn a phase rewrite into a
   phase deletion).
3. Keep wire format unchanged. Every bite below is
   wire-compatible.
4. Each leaves all three repos building. No bite depends
   on a later bite (unless explicitly stated).
5. Each can be reverted with a single `git revert` or by
   deleting one file.

**Strong recommendation:** complete all eight bites below
before starting Phase 0 of the main plan. The total cost
estimate is on the order of 1–2 working weeks; the
de-risking effect on the subsequent 9-phase refactor is
substantial.

## Bite ordering

Bites are numbered 0–8 below. Bites 1–3 are the original
"Quick Wins" from the 2026-04-15 plan, repeated here with
no semantic changes (the authoritative version is still
the main plan, but they are re-stated for completeness so
this doc reads as a single execution plan). Bites 4–8 are
new and target the dual-registry / discovery problem
specifically. Bite 0 is a small but critical prerequisite
in the underlying tdns repo and is the **only** bite that
changes anything outside tdns-mp and tdns-transport.

**Repo scope (important):** Bites 1–8 are all confined to
`tdns-mp/` and `tdns-transport/`. The base `tdns/` repo
is *not* touched by any of them. Bite 0 is the sole
exception — it lands a small idempotency guard in
`tdns/v2/imrengine.go` so that subsequent bites (in
particular Bite 6) can rely on a single shared IMR
instance regardless of which application initialises it.
This separation matters operationally because other work
may be in flight in the `tdns/` working tree
concurrently.

**Recommended execution order** (revised from the main
plan to interleave the new bites; Bite 0 first because
it is a prerequisite for Bite 6 and lands in a different
repo with its own merge cycle):

| # | Bite | Repo | Cost | Status | Unlocks |
|---|---|---|---|---|---|
| 0 | Idempotent `InitImrEngine` | **tdns** | 30 min | ✅ DONE | Bite 6; safe shared IMR for non-MP apps |
| 4 | `Agent.PeerID` field | tdns-mp | 30 min | ✅ DONE | Bites 5, 7, 8; Phase 7 sub-step 1 |
| 8 | `OnPeerDiscovered` callback seam | tdns-mp + tdns-transport | 2 hours | ✅ DONE | Phase 6 part 2 |
| 1 | Additive `MechanismState` on Peer with dual-write | tdns-mp + tdns-transport | 1–2 days | ✅ DONE | Phase 1 deletion |
| 6 | Add IMR lookup helpers to transport (parallel embedding) | tdns-transport only | 0.5 day | ✅ DONE | Phase 6 part 1 |
| 2 | Phase 0 — integration test harness | tdns-mp | 2–3 days | ⏳ pending | Phase 1+ exit gate |
| 7 | `Peer.PopulateFromAgent` from Agent's per-mechanism state | tdns-mp + tdns-transport | 1 day | ✅ DONE | Phase 7 deletion of `SyncPeerFromAgent` |
| 5 | Migrate read-shaped `SyncPeerFromAgent` call sites | tdns-mp | 0.5 day | ⏳ pending | Phase 7 |
| 3 | Unified `tm.Send` shim | tdns-mp + tdns-transport | 1 day | ⏳ pending | Phase 5 deletion |

**Progress (2026-04-25):** Bites 0, 4, 8, 1, 6, 7 complete.
Bite 0 merged to `tdns/main` via PR #204 and
cherry-picked onto the in-flight `fast-roller-1`
feature branch. Bites 4, 8, 1 landed on
`transport-early-bites-1` in tdns-mp; Bite 8's and
Bite 1's transport-side changes landed on
`transport-early-bites-1` in tdns-transport. Bite 1's
scope was refined during execution: the wrapper-body
switch (originally step 5) deferred to Bite 7, where
`Peer.PopulateFromAgent` populates the per-mechanism
`Address` field that the wrapper bodies need. Bite 6's
shape resolved on execution to **parallel embedding**
rather than movement: `tdnsmp.Imr` stays put (still has
non-discovery users), and a separate `transport.Imr`
wrapper is added with its own copy of the lookup
helpers. Both wrap the same singleton `*tdns.Imr`,
guaranteed by Bite 0's idempotency guard. Bite 7
landed `transport.AgentMechanismSnapshot`,
`transport.AgentLike`, and `Peer.PopulateFromAgent`
with four passing unit tests; in tdns-mp, `*Agent` now
implements `AgentLike` via two new methods, and the
three disposition-table wrappers (`HasDNSTransport`,
`HasAPITransport`, `GetPreferredTransportName`) now
delegate to `peer.HasMechanism()` /
`peer.PreferredMechanism()` with a fallback to the
agent flags for peers not yet synced. Bite 7 also
absorbed Bite 1's deferred wrapper-body switch, closing
that loose end. As a side effect, `tdns-transport`'s
`go.mod` now requires `github.com/johanix/tdns/v2` and
`tdns/v2/cache` (added via `replace` directives) —
needed because `transport.Imr` embeds `*tdns.Imr`.

Build of all four mp binaries (`tdns-mpagent`,
`tdns-mpcombiner`, `tdns-mpsigner`, `tdns-mpcli`)
verified clean after each bite.

**Pre-existing test failure noted:**
`TestNewDNSMessageRouter` in
`tdns-transport/v2/transport/dns_message_router_test.go`
asserts `router.middleware != nil` but
`NewDNSMessageRouter()` does not initialise that slice.
Pre-dates this work; not introduced by Bite 7. Tracked
for a separate fix.

Bite 2 (the test harness) is non-negotiable as the gate
for the main refactor's Phase 1 — but the additive bites
4, 8, 1, and 6 are safe to land before the harness exists,
since they do not change runtime behaviour. Bites 5 and 7
should land **after** the harness, because they migrate
state-coupling code paths that benefit from coverage.

The original plan's recommended order (Phase 0 → Bite 1
→ Bite 3) remains valid; the table above interleaves new
bites at points where they unlock or de-risk the original
sequence.

Bite 0 must complete its merge cycle in the tdns repo
before Bite 6 begins, because Bite 6 depends on the
idempotency guard for safety. Bites 4, 8, 1 can proceed
in tdns-mp / tdns-transport in parallel with Bite 0's
review.

---

## Bite 0: Idempotent `InitImrEngine`

**Source:** New (extracted from the IMR audit conducted
2026-04-25). Prerequisite for Bite 6.

### Repo scope and operational note

This is the **only** bite that touches the base `tdns/`
repository. All other bites are confined to `tdns-mp/`
and `tdns-transport/`.

**Branching:** Land this on a dedicated feature branch
in the tdns repo, named `transport-early-bites-1` (or
similar, following the pattern of design-doc-name +
suffix), cut from `origin/main`. PR target is `main`.
Merge to main before starting Bite 6.

**Concurrency caution:** Other work may be in flight in
the `tdns/` working tree at the same time. Do this work
in an isolated worktree (`git worktree add …`) outside
the active `tdns-project/tdns/` directory, so the in-flight
work is not disturbed. After the PR is merged and the
worktree is no longer needed, remove it with
`git worktree remove`.

### What

Add a two-line idempotency guard to
[tdns/v2/imrengine.go](../../tdns/v2/imrengine.go) so
that `InitImrEngine` becomes safely callable from any
process startup path, including non-MP applications, in
any order, any number of times.

### Why this is needed

The IMR (Iterative Message Resolution) engine is a
process singleton by intent: there must be exactly one
instance per process, because the priming cache, root
hints, and validation state are expensive to construct
and would diverge between two instances. The current
`InitImrEngine` implementation is *not* idempotent —
calling it twice silently allocates a fresh `RRsetCache`
and a fresh `Imr`, overwriting both
`conf.Internal.ImrEngine` and `Globals.ImrEngine`. Any
embedding wrapper or stale pointer that still references
the first instance keeps using the dead cache.

The current code works only because tdns-mp explicitly
serialises one synchronous `InitImrEngine` call (in
`start_agent.go`) before the async engine starts; the
async engine's `ImrEngine()` then has a nil-check that
prevents a second init in that one specific code path.
A long warning comment at
[tdns/v2/imrengine.go:70-75](../../tdns/v2/imrengine.go#L70-L75)
documents this fragility-by-construction.

For Bite 6 (move IMR lookup helpers into transport), we
want to be able to assert that the embedded `*tdns.Imr`
in any `transport.Imr` wrapper points to the **same**
shared instance regardless of which application
initialised it, regardless of order. The two-line guard
makes that property hold by construction.

### Concrete steps

1. In
   [tdns/v2/imrengine.go](../../tdns/v2/imrengine.go) at
   the top of `(conf *Config) InitImrEngine`, add:
   ```go
   func (conf *Config) InitImrEngine(quiet bool) error {
       if conf.Internal.ImrEngine != nil {
           lgImr.Debug("InitImrEngine: already initialized, returning existing instance")
           return nil
       }
       // ... existing body unchanged ...
   }
   ```
2. Audit current callers of `InitImrEngine` (across
   tdns, tdns-mp, and any other apps in
   `tdns-project/`). Where a caller has its own
   pre-flight nil-check (because of the current
   non-idempotency), simplify it — the caller no longer
   needs to guard.
3. Audit `(conf *Config) ImrEngine` (the async engine
   entry point) at line 152. Its existing nil-check
   before calling `InitImrEngine` is now redundant from
   a correctness perspective, but it is cheap and
   self-documenting; **leave it in place**.
4. Update the warning comment block at lines 70-75
   that documents the start-order fragility. After this
   bite, the constraint is no longer "must be called
   synchronously before the async engine starts" — it
   is just "must be called before the first dereference
   of `conf.Internal.ImrEngine`". Reword the comment to
   reflect the new property: idempotent, first-init
   wins, callers can rely on it.
5. Run `gofmt -w tdns/v2/imrengine.go`.
6. Build verification: this is a base-repo change; the
   tdns repo's own build must pass. Then build tdns-mp
   per
   [CLAUDE.md](../../CLAUDE.md) to confirm no
   downstream regressions.

### First-init-wins semantics

If the first caller passes `quiet=true` and a later
caller would have wanted `quiet=false`, the second
caller's preference is silently dropped. This is
acceptable: `quiet` is a logging-verbosity hint, not
semantically load-bearing, and first-init-wins is the
natural singleton behaviour. **Document this in the
comment block** updated in step 4.

### Do NOT

- Apply a `sync.Once` wrapper — the existing nil-check
  pattern is consistent with the rest of the file and
  no extra synchronisation primitive is needed (init is
  serialised by the application's startup sequence in
  practice).
- Change the function signature.
- Remove the existing `Globals.ImrEngine` assignment —
  it remains the package-level access point for legacy
  call sites.
- Add idempotency at the caller level instead — the
  guard belongs inside `InitImrEngine` so every caller
  benefits.

### Files touched

- [tdns/v2/imrengine.go](../../tdns/v2/imrengine.go)
  (the guard plus a comment refresh; ~15 lines net)
- Possibly 1–2 callers if their pre-flight nil-checks
  are simplified (audit step 2).

### Why it's safe

Two-line additive change. The new behaviour is a strict
superset of the old: every existing call site still
works exactly as before for the first call, and the
second-and-later calls become no-ops instead of
destructive overwrites. Wire format unchanged. No
semantic change for any application that already calls
`InitImrEngine` exactly once.

### Value delivered

- IMR is genuinely a process singleton, by construction
  rather than by careful caller discipline.
- Bite 6 (and any other future bite that wants to
  initialise the IMR from a different starting point)
  becomes safe.
- The fragility comment block at lines 70-75 stops
  being a smoking gun.
- A non-MP application can call
  `conf.InitImrEngine(quiet)` at its own startup
  without coordinating with whatever other code may
  also call it.

### Estimated cost

~30 minutes total: 5 minutes for the guard, 15 minutes
for the caller audit and comment refresh, 10 minutes
for build verification.

### Dependencies

None.

### Required by

- **Bite 6** (move IMR lookup helpers into transport) —
  the embedded `*tdns.Imr` in any `transport.Imr`
  wrapper must reliably point to the singleton; this
  bite guarantees that.
- Any future non-MP application that uses transport
  with its own IMR initialisation path.

---

## Bite 1: Additive `Peer` mechanism state with dual-write

**Source:** Quick Wins § "Bite 1" in the main plan.
Re-stated here verbatim in intent; cross-reference for the
authoritative text.

### What

Add per-mechanism state to `transport.Peer` alongside the
existing single-state fields. Do not remove the old
fields. Dual-write the new fields from the same code paths
that update the old ones.

### Concrete steps

1. In [tdns-transport/v2/transport/peer.go](../../tdns-transport/v2/transport/peer.go),
   add the `MechanismState` struct:
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
4. In code paths that currently update the single-state
   fields (hello/beat receipt, discovery completion,
   etc.), *also* update the corresponding
   `MechanismState`. Dual-write for now.
5. **Deferred to Bite 7.** Originally Bite 1 also rewrote
   three disposition-table wrappers (`HasDNSTransport`,
   `HasAPITransport`, `GetPreferredTransportName`) to
   read from `peer.Mechanisms`. On execution
   (2026-04-25) we found the wrappers can't switch yet:
   `peer.HasMechanism("DNS")` returns true only when
   `Mechanisms["DNS"].Address` is set, but Bite 1's
   dual-write only populates state and timestamps — not
   the per-mechanism `Address`. The address comes from
   the Agent's `DnsDetails.Addrs` and is mirrored onto
   the Peer by `Peer.PopulateFromAgent`, which is
   Bite 7. Switching the wrapper bodies before that
   would silently regress every caller.

   The wrapper-body switch therefore moves to Bite 7,
   right after `PopulateFromAgent` lands. Bite 1 keeps
   the wrappers untouched.

### Do NOT

- Remove `ZoneRelation` or `SharedZones` — they stay as
  the primary source of truth for scope/zone tracking
  until the bigger refactor moves scope handling.
- Remove the single `Peer.State` field — keep it in sync
  with `EffectiveState()` via dual-write.
- Delete `SyncPeerFromAgent` or any call site — still
  needed.

### Files touched

- [tdns-transport/v2/transport/peer.go](../../tdns-transport/v2/transport/peer.go)
  (struct + methods + `NewPeer` initialisation)
- [tdns-mp/v2/hsync_transport.go](../../tdns-mp/v2/hsync_transport.go)
  (dual-write at three DNS receipt sites: hello, beat,
  ping)
- [tdns-mp/v2/combiner_msg_handler.go](../../tdns-mp/v2/combiner_msg_handler.go)
  (dual-write at downstream beat consumer)
- [tdns-mp/v2/signer_msg_handler.go](../../tdns-mp/v2/signer_msg_handler.go)
  (dual-write at downstream beat consumer)

The transport `handlers.go` mentioned in the original
plan does not contain hello/beat receipt logic in this
code base — those live in tdns-mp. Bite 1 follows the
actual code; the original plan's reference was based on
a different code organisation.

### Why it's safe

Zero wire-format change, zero public API break.
Everything is additive. Existing code paths are untouched
except for adding parallel writes. If something goes
wrong, the old fields still carry canonical state.

### Value delivered

The `MechanismState` struct, the `Mechanisms` map on
`Peer`, and the four accessor methods
(`EffectiveState`, `HasMechanism`, `PreferredMechanism`,
`SetMechanismState`) are now in place. Per-mechanism
state and per-mechanism timestamps are populated on
every DNS hello/beat/ping receipt across all three
roles (agent, combiner, signer).

The three disposition-table wrapper items (#3, #39 × 2)
land in Bite 7, once `Peer.PopulateFromAgent`
populates the per-mechanism `Address` field — see
the deferral note in step 5 above.

The future Phase 1 "remove the old fields" step still
becomes a pure deletion: every receipt site already
writes both old and new state.

### Estimated cost

1–2 days (includes dual-write plumbing in handlers.go).

### Dependencies

None. Bite 4 (`Agent.PeerID`) makes the wrapper bodies
slightly cleaner but is not required.

---

## Bite 2: Transport-boundary integration test harness

**Source:** Quick Wins § "Bite 2" in the main plan,
promoted to **mandatory Phase 0** of the main refactor.
Re-stated here for completeness as part of the early-bites
sequence.

### What

Integration test coverage for the transport boundary in
tdns-mp. Currently zero. This is the highest-ROI item —
it catches regressions in the meantime AND becomes the
safety net when the bigger refactor begins.

### Authoritative spec

Implementation specification and per-scenario detail are
in
[2026-04-23-transport-boundary-test-harness.md](./2026-04-23-transport-boundary-test-harness.md).
The summary below is recap; the harness doc governs.

### Test scenarios (minimum viable: seven)

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
5. **LEGACY / zero-scope sync rejection.** Peer with
   empty `SharedZones` attempts to send a sync. Assert
   `HandleSync` rejects it with the expected error.
6. **Hello rejection (HSYNC / zone policy).** Exercise
   `EvaluateHello` (or equivalent HTTP surface) with a
   hello that must be refused. Assert rejection with
   stable reason.
7. **Discovery completion path.** Register an agent in
   NEEDED state. Simulate discovery completion. Assert
   the peer transitions to KNOWN and the discovery
   callback fires (after Bite 8 lands, this is
   `OnPeerDiscovered`).

### Where tests live

New package, e.g. `tdns-mp/v2/transport_integration_test.go`,
or a `tdns-mp/v2/integration/` subdirectory if isolation
is preferred.

### Infrastructure to build (if not already present)

- Test harness that spins up two in-process
  `TransportManager`s with a shared in-memory DNS
  implementation (or loopback UDP on random ports)
- Fake `AgentRegistry` + `MsgQs` for the receiving side
- Helper to construct a minimal `MPTransportBridge` for
  each agent
- Assertions helper for reading from `msgQs.*` channels
  with timeout

### Why it's safe

Tests only add. No production code changes. The
infrastructure investment is reusable for the eventual
refactor.

### Value delivered

Regression safety net covering current behaviour. Every
subsequent refactor phase can run these tests and gain
confidence. **Exit gate for Phase 1 of the main plan.**

### Estimated cost

2–3 days, most of which is harness construction. Surfaced
bugs in current code are a feature, not a regression.

### Dependencies

None. But: Bite 8 (`OnPeerDiscovered`) makes scenario 7
cleaner to assert.

---

## Bite 3: Unified `tm.Send` shim

**Source:** Quick Wins § "Bite 3" in the main plan.
Re-stated here verbatim in intent.

### What

Introduce a single generic send method on
`TransportManager` that subsumes the three
`SendXWithFallback` variants. Existing methods become
thin deprecation shims; call-site migration is
opportunistic.

### Concrete steps

1. In
   [tdns-transport/v2/transport/manager.go](../../tdns-transport/v2/transport/manager.go),
   add:
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

### Do NOT

- Change any method signatures on the bridge wrappers.
- Touch wire format or message structs.
- Delete the wrapper methods — they stay as shims so
  existing call sites don't break.
- Move any types between packages.

### Files touched

- [tdns-transport/v2/transport/manager.go](../../tdns-transport/v2/transport/manager.go)
  (new `Send` method)
- [tdns-mp/v2/hsync_transport.go](../../tdns-mp/v2/hsync_transport.go)
  (rewrite 4 method bodies as delegations)

### Why it's safe

Pure internal refactor. All public APIs unchanged. All
call sites continue to work. Fallback behaviour preserved
(the new `Send` does the same thing the wrappers did,
just in one place).

### Value delivered

One place for fallback logic instead of three. Phase 5 of
the main refactor becomes much smaller. Sets up the
eventual per-mechanism fallback routing (with Bite 1
landed, `Send` can consult `MechanismState` for smarter
selection).

### Estimated cost

~1 day.

### Dependencies

None required. Optional synergy with Bite 1 (per-mechanism
health for selection); without Bite 1, `Send` uses
existing logic.

---

## Bite 4: `Agent.PeerID` field — pure addition

**Source:** Phase 7 sub-step 1 in the main plan, lifted
out as a standalone bite.

### What

Add a `PeerID string` field to the `Agent` struct.
Populate it from `Identity` (lower-cased / FQDN as the
existing identity-handling code does) at every Agent
construction site. **No call-site changes** —
`SyncPeerFromAgent` keeps working exactly as before.

### Why this is the leadoff bite

Establishes the loose-coupling key the main plan
repeatedly references (`peerRegistry.Get(agent.PeerID)`)
without removing or changing anything. Once the field
exists, every later bite has a stable, documented handle
to use. With no call-site changes, the diff is trivial
and the risk is essentially zero.

### Concrete steps

1. Find the `Agent` struct definition (in
   `tdns-mp/v2/agent_structs.go` per current layout) and
   add:
   ```go
   // PeerID is the transport-layer identifier for this
   // agent. Used as the key into the transport
   // PeerRegistry. Currently identical to Identity but
   // kept as a separate field so future identity
   // schemes (e.g. UUID-based peer IDs) can decouple
   // transport identity from MP agent identity.
   PeerID string
   ```
2. Find every Agent constructor / initialiser. The main
   ones are in `agent_registry.go` (or whatever file
   contains `NewAgent` / `RegisterAgent` /
   `EnsureAgent`). Set `PeerID = Identity` after
   `Identity` is normalized.
3. Audit: grep for direct field assignment
   `Agent{Identity:` to catch struct literals — set
   `PeerID` there too.

### Do NOT

- Migrate any call site to use `PeerID` instead of
  `Identity` — that's Bite 5 and Phase 7 work.
- Delete or change the `Identity` field — it remains the
  MP-level identity.
- Add validation that `PeerID == Identity` — pointless
  now and will block future divergence.

### Files touched

- `tdns-mp/v2/agent_structs.go` (field addition)
- 3–6 Agent construction sites (one-line additions)

### Why it's safe

Pure data-structure addition. No code reads the new
field yet. Old code paths untouched.

### Value delivered

- Every later bite (and Phase 7) can refer to
  `agent.PeerID` as if it has always existed.
- Establishes the documented contract: PeerRegistry is
  keyed by Agent.PeerID.

### Estimated cost

~30 minutes.

### Dependencies

None. This bite is the foundation for Bites 5 and 8.

---

## Bite 5: Migrate read-shaped `SyncPeerFromAgent` call sites

**Source:** New (extracted from the dual-registry
analysis 2026-04-25).

### What

`SyncPeerFromAgent` has 9 call sites
(per [hsync_transport.go](../../tdns-mp/v2/hsync_transport.go)
and surrounding files). Several are **read-shaped**:
they call `SyncPeerFromAgent` only to obtain a `*Peer`
for inspection, not to write through the agent state.
Migrate just those to read from `peerRegistry.Get(agent.PeerID)`
directly.

### Identified call sites

From the survey conducted 2026-04-25:

| Site | Purpose | Shape |
|---|---|---|
| `hsync_transport.go:1422` (SendHelloWithFallback) | Get peer to send | **write** (sync-then-send) |
| `hsync_transport.go:1547` (SendBeatWithFallback) | Get peer to send | **write** |
| `hsync_transport.go:1666` (SendSyncWithFallback) | Get peer to send | **write** |
| `hsync_transport.go:1742` (SendConfirmWithFallback) | Get peer to send | **write** |
| `hsync_transport.go:2203` (SendInfraBeat) | Get peer to send | **write** |
| `hsyncengine.go:711` (HelloHandler callback) | Update peer post-hello | **write** |
| `hsyncengine.go:964` (HeartbeatHandler callback) | Update peer post-beat | **write** |
| `apihandler_agent.go:988` (debugGetAgentStatus) | Export status | **read** ✓ |
| `agent_utils.go` (OnAgentDiscoveryComplete) | Initial sync after discovery | **write** (legitimate first sync) |

Bite 5 covers only the **read** sites. The 7 write sites
remain on the old code path until Bite 7 + Phase 7.

### Concrete steps

1. For `apihandler_agent.go:988`: replace
   ```go
   peer := tm.SyncPeerFromAgent(agent)
   ```
   with
   ```go
   peer := tm.PeerRegistry().Get(agent.PeerID)
   if peer == nil {
       // fall back to old path — peer not yet
       // registered (e.g. discovery in flight)
       peer = tm.SyncPeerFromAgent(agent)
   }
   ```
2. Audit other read-shaped sites surfaced during the
   audit conducted as part of Bite 5 (the table above is
   the starting point; grep may surface more).
3. Add a comment at each migrated site:
   `// Bite 5 migration; old code: tm.SyncPeerFromAgent(agent)`
   so the reverse direction stays cheap.

### Do NOT

- Migrate any write-shaped site. The old path keeps the
  AgentRegistry → PeerRegistry sync running.
- Add new `Peer.Get`-style accessors on Agent yet — that
  is a sub-step of Bite 7 / Phase 7.

### Files touched

- `tdns-mp/v2/apihandler_agent.go` (one site)
- Possibly 1–2 other read-shaped paths surfaced by audit

### Why it's safe

The read path returns the same `*Peer` either way. The
fallback branch ensures we never return nil even if the
peer isn't yet registered. Wire format unchanged.

### Value delivered

- Proves the loose-coupling pattern in production code
  paths.
- Demonstrates that `peerRegistry.Get(agent.PeerID)` is
  sufficient for read consumers.
- Reduces the count `SyncPeerFromAgent` call sites,
  shrinking Phase 7 sub-step 2.

### Estimated cost

Half a day (mostly the audit; the edits themselves are
minutes).

### Dependencies

- **Bite 4** (`Agent.PeerID` field) — required.
- **Bite 2** (test harness) — strongly recommended; this
  bite touches state-coupling code paths and benefits
  from coverage.

---

## Bite 6: Move IMR lookup helpers into transport

**Source:** New (extracted from Phase 6 — splits Phase 6
into part 1 (mechanics, easy) and part 2 (orchestration,
hard); this bite is part 1).

### What

[agent_discovery_common.go](../../tdns-mp/v2/agent_discovery_common.go)
contains six DNS-record-parsing methods on `*Imr`.
Verified 2026-04-25: they have **zero MP-specific
coupling** beyond imports of `core.TypeJWK`, `core.JWK`,
and `core.ValidateJWK`. They are exactly the helpers a
non-MP application using transport would need first.

The methods are:

- `LookupAgentJWK(ctx, identity) (jwkData, pubKey, alg, error)`
- `LookupAgentKEY(ctx, identity) (*dns.KEY, error)` —
  legacy fallback
- `LookupAgentAPIEndpoint(ctx, identity) (uri, host, port, error)`
- `LookupAgentDNSEndpoint(ctx, identity) (uri, host, port, error)`
- `LookupAgentTLSA(ctx, identity, port) (*dns.TLSA, error)`
- `LookupServiceAddresses(ctx, serviceName) ([]string, error)`

Total: ~297 lines, single file.

### Decision (2026-04-25): Option B (parallel embedding,
not move)

After discussion: **Option B**, with one important
clarification — this is **parallel embedding**, not
movement. `tdnsmp.Imr` stays put because there are
existing MP-side users of it that are independent of
discovery lookups (e.g. `delegation_sync.go`,
`apihandler_agent.go`, `main_init.go`). The transport
side gets its own `transport.Imr` wrapper that embeds
the same singleton `*tdns.Imr` from
`conf.Internal.ImrEngine` and `Globals.ImrEngine`.

This is the structural reason Bite 0 (idempotent
`InitImrEngine`) had to land first: with two embedding
wrappers in different packages, both must point to the
same underlying `*tdns.Imr`, which the Bite 0 guard
makes hold by construction.

The Lookup\* helpers exist as methods on both wrappers.
This is intentional duplication. It will be resolved
later when MP migrates its lookup-helper callers to
use `*transport.Imr` (or when the helpers move to a
shared location). For now, two parallel implementations
of the same logic, both reading from the same shared
singleton.

### Concrete steps

1. Create `tdns-transport/v2/transport/imr.go` with:
   ```go
   type Imr struct {
       *tdns.Imr
   }
   ```
   Mirror of `tdnsmp.Imr` in
   [tdns-mp/v2/imr.go](../../tdns-mp/v2/imr.go), in the
   transport package.
2. Copy the six lookup helpers from
   [tdns-mp/v2/agent_discovery_common.go](../../tdns-mp/v2/agent_discovery_common.go)
   into the new `imr.go`, attached as receivers on
   `*transport.Imr`. Adapt logging from MP's
   `lgAgent` to transport's `lgTransport()`.
3. Leave MP's copies untouched. Both wrappers continue
   to exist with the same method set.
4. Verify the build:
   `cd tdns-mp/cmd && GOROOT=... make` (transitively
   builds transport).

### Do NOT

- **Move** any of the existing MP-side lookup helpers.
  This is parallel addition, not relocation —
  `tdnsmp.Imr` and its method set remain.
- Move `DiscoverAndRegisterAgent`. That orchestration
  function lives in
  [tdns-mp/v2/agent_discovery.go:362](../../tdns-mp/v2/agent_discovery.go#L362)
  and depends on AgentRegistry, retry policy, and MP
  state. It is Phase 6 part 2.
- Move `attemptDiscovery`
  ([tdns-mp/v2/agent_utils.go:566](../../tdns-mp/v2/agent_utils.go#L566)).
  Same reason.
- Move `DiscoveryRetrierNG`. Same reason.
- Refactor the lookup methods themselves. Copy first,
  refactor later.
- Migrate any MP call site to use `*transport.Imr`.
  Call-site migration is a follow-up; for now the two
  wrappers coexist.

### Files touched

- New: [tdns-transport/v2/transport/imr.go](../../tdns-transport/v2/transport/imr.go)
  (~300 lines: `transport.Imr` wrapper struct +
  six Lookup\* receiver methods)
- Unchanged:
  [tdns-mp/v2/agent_discovery_common.go](../../tdns-mp/v2/agent_discovery_common.go)
  and [tdns-mp/v2/imr.go](../../tdns-mp/v2/imr.go) —
  parallel embedding, not movement.

### Why it's safe

Pure parallel addition. No code is moved out of MP. No
existing call site changes. No semantic change. Wire
format unchanged. The new transport-side helpers are
not yet called by anything; they are infrastructure for
future bites and external consumers.

The structural correctness of two wrappers around the
same `*tdns.Imr` rests on Bite 0's idempotency guard:
both `tdnsmp.Imr` and `transport.Imr` end up holding
the same singleton pointer regardless of who initialises
it first.

### Value delivered

- Largest single chunk (~297 lines) of "discovery" code
  moves into transport with zero coupling cost.
- A non-MP application using transport gets the lookup
  helpers for free.
- Phase 6 work is reduced to part 2 (orchestration +
  state machine), which is the genuinely hard part.

### Estimated cost

Half a day under the parallel-embedding approach
chosen — the helpers are mechanical copy-and-adapt;
no call-site changes.

### Dependencies

- **Bite 0** (idempotent `InitImrEngine`) — required.
  Without it, the parallel embedding could in
  principle wrap two different `*tdns.Imr` instances
  if init were ever invoked twice.

---

## Bite 7: `Peer.PopulateFromAgent` — mirror Agent's per-mechanism state

**Source:** New (extracted from the dual-registry
analysis 2026-04-25). Strengthens Bite 1 by adding a
documented Peer-from-Agent constructor.

### What

`Agent` already tracks per-mechanism state cleanly via
`ApiDetails` and `DnsDetails` (both
`AgentDetails` structs with independent `State`,
`LatestError`, `DiscoveryFailures`, `HelloTime`,
`LastContactTime`, `BeatInterval`). Verified 2026-04-25
in `tdns-mp/v2/agent_structs.go`.

After Bite 1 lands, `Peer` has the parallel structure
(`Mechanisms map[string]*MechanismState`). This bite adds
the bridge:

```go
// PopulateFromAgent copies per-mechanism state from an
// Agent into this Peer's Mechanisms map. Used by
// SyncPeerFromAgent during the dual-registry transition;
// scheduled for inlining once Phase 7 deletes the
// AgentRegistry → PeerRegistry sync.
func (p *Peer) PopulateFromAgent(a interface{ ... }) {
    // read a.ApiDetails → p.Mechanisms["API"]
    // read a.DnsDetails → p.Mechanisms["DNS"]
}
```

### Why this matters

The hardest part of the eventual Peer-becomes-canonical
work — "what does per-mechanism state look like on the
transport side?" — is already solved on the Agent side.
This bite mirrors that shape onto Peer with explicit
field-by-field correspondence. Once both sides agree on
shape, the Phase 7 "delete the duplicate Agent state"
step becomes a pure deletion.

### Concrete steps

1. Define a small interface in transport (so transport
   does not need to import the MP `Agent` type):
   ```go
   // AgentLike is satisfied by tdns-mp's Agent. It
   // exposes the per-mechanism state needed to
   // populate a Peer. Defined as an interface so
   // transport stays decoupled from MP.
   type AgentLike interface {
       APIState() (state PeerState, addr *Address,
           lastHello, lastBeat time.Time,
           beatSeq uint64, fails int)
       DNSState() (state PeerState, addr *Address,
           lastHello, lastBeat time.Time,
           beatSeq uint64, fails int)
   }
   ```
2. Add `Peer.PopulateFromAgent(a AgentLike)` that fills
   `p.Mechanisms["API"]` and `p.Mechanisms["DNS"]` from
   the interface.
3. In MP, add the interface methods on `*Agent` reading
   from `ApiDetails` / `DnsDetails`. Map MP's
   `AgentState` enum to transport's `PeerState` via the
   existing `agentStateToTransportState` helper.
4. Rewrite `SyncPeerFromAgent` body to call
   `peer.PopulateFromAgent(agent)` plus the existing
   single-state writes. Both old and new field sets are
   updated; dual-write continues exactly as in Bite 1.
5. Add a unit test that constructs an Agent with known
   `ApiDetails`/`DnsDetails`, calls
   `peer.PopulateFromAgent(agent)`, and asserts the
   resulting Peer state matches.
6. **Inherited from Bite 1.** Now that
   `Mechanisms["API"].APIEndpoint` (via
   `peer.APIEndpoint`) and `Mechanisms["DNS"].Address`
   are populated by `PopulateFromAgent`, switch the
   three disposition-table wrappers in
   `tdns-mp/v2/hsync_transport.go` to the one-line
   delegations originally planned for Bite 1:
   - `HasDNSTransport(agent)` →
     `tm.DNSTransport != nil && tm.PeerRegistry.peer(agent).HasMechanism("DNS")`
   - `HasAPITransport(agent)` →
     `tm.APITransport != nil && tm.PeerRegistry.peer(agent).HasMechanism("API")`
   - `GetPreferredTransportName(agent)` →
     `tm.PeerRegistry.peer(agent).PreferredMechanism()`
     (return `"none"` for empty result to preserve the
     current contract)

### Do NOT

- Delete `SyncPeerFromAgent` — the wrapper still does
  the single-state writes plus
  `peer.PopulateFromAgent(agent)`. Deletion is Phase 7.
- Drop `agentStateToTransportState` — used in step 3 of
  this bite.
- Change the `AgentLike` interface to take a concrete
  `*Agent`. Keeping it as an interface preserves
  transport's decoupling from MP.

### Files touched

- `tdns-transport/v2/transport/peer.go` (add interface
  and method)
- `tdns-mp/v2/agent_structs.go` (add `APIState` /
  `DNSState` interface methods on `*Agent`)
- `tdns-mp/v2/hsync_transport.go` (rewrite
  `SyncPeerFromAgent` body)
- New: `tdns-transport/v2/transport/peer_test.go` (small
  unit test)

### Why it's safe

`SyncPeerFromAgent` semantics preserved exactly: every
field it wrote before, it still writes. Adds parallel
writes to `Peer.Mechanisms`. Wire format unchanged.

### Value delivered

- Documents the Agent → Peer state mapping in code, not
  just in the design doc.
- Phase 7's "drop duplicated transport state on Agent"
  step becomes a deletion — the canonical path is
  already through `Peer.Mechanisms`.
- The unit test catches state-mapping regressions for
  free.

### Estimated cost

1 day.

### Dependencies

- **Bite 1** (per-mechanism state on Peer) — required.
- **Bite 4** (`Agent.PeerID`) — recommended for cleaner
  test fixtures.
- **Bite 2** (harness) — strongly recommended;
  state-coupling change.

---

## Bite 8: `OnPeerDiscovered` callback seam

**Source:** New (extracted from Phase 6 — the discovery
completion seam can be installed without moving discovery
itself).

### What

[hsync_transport.go:1665](../../tdns-mp/v2/hsync_transport.go#L1665)
defines `OnAgentDiscoveryComplete`, a 20-line function
called once per agent after discovery succeeds. It does
three things:

1. Calls `SyncPeerFromAgent(agent)`.
2. Sets `peer.PreferredTransport` based on
   `agent.ApiMethod` / `agent.DnsMethod` (verified
   2026-04-25).
3. Calls `peer.SetState(transport.PeerStateKnown,
   "discovery complete")`.

It is invoked from `agent_utils.go` after
`attemptDiscovery` succeeds.

This bite installs the callback **seam** required by
Phase 6 part 2 — without moving discovery itself.

### Concrete steps

1. Add a field on `TransportManagerConfig` (or wherever
   transport configuration is held):
   ```go
   // OnPeerDiscovered is called by transport when peer
   // discovery completes. Optional; if nil, transport
   // takes no action beyond updating PeerRegistry.
   //
   // Currently invoked by MP's discovery loop; will be
   // invoked by transport itself once discovery moves
   // (Phase 6 of the transport interface redesign).
   OnPeerDiscovered func(peerID string)
   ```
2. Wire MP startup to register a function whose body is
   the **existing** `OnAgentDiscoveryComplete` logic,
   adapted to take a `peerID string`:
   ```go
   tm.OnPeerDiscovered = func(peerID string) {
       agent, ok := tm.agentRegistry.S.Get(AgentId(peerID))
       if !ok { return }
       peer := tm.SyncPeerFromAgent(agent)
       // ...preferred transport selection (existing logic)...
       peer.SetState(transport.PeerStateKnown,
           "discovery complete")
   }
   ```
3. In `agent_utils.go`, change the call site that
   currently invokes `tm.OnAgentDiscoveryComplete(agent)`
   to invoke `tm.OnPeerDiscovered(agent.PeerID)`
   (requires Bite 4).
4. Keep `OnAgentDiscoveryComplete` defined as a thin
   wrapper that delegates to `tm.OnPeerDiscovered`, in
   case other call sites surface during the audit.

### Do NOT

- Move discovery itself (the IMR queries, the retry
  loop, the `attemptDiscovery` body) into transport.
  That is Phase 6 part 2.
- Change the body of the discovery-completion logic.
  Same code runs; only the dispatch path changes.
- Remove `OnAgentDiscoveryComplete` until a grep
  confirms zero remaining call sites.

### Files touched

- `tdns-transport/v2/transport/manager.go` (or config
  file): add `OnPeerDiscovered` field
- `tdns-mp/v2/hsync_transport.go`: register
  `OnPeerDiscovered` at startup; keep
  `OnAgentDiscoveryComplete` as a deprecation shim
- `tdns-mp/v2/agent_utils.go`: update the single call
  site

### Why it's safe

The same code runs in the same place. Only the dispatch
indirection changes. If `OnPeerDiscovered` is nil, MP
falls back to the old path. Wire format unchanged.

### Value delivered

- The discovery-completion seam required by Phase 6 part 2
  is installed.
- When discovery later moves into transport, the
  callback wiring is already there; transport just
  invokes it directly instead of MP's discovery loop
  invoking it.
- Test scenario 7 from Bite 2 has a stable assertion
  surface: "did `OnPeerDiscovered` fire?"

### Estimated cost

~2 hours.

### Dependencies

- **Bite 4** (`Agent.PeerID`) — required (the callback
  takes a `peerID string`).

---

## Cumulative effect

If all nine bites (0–8) land, the entry conditions for
the main refactor become substantially more favourable:

- **IMR initialisation** is genuinely idempotent (Bite 0).
  The fragility-by-construction comment in
  `tdns/v2/imrengine.go` becomes a property
  guaranteed by code rather than by caller discipline.

- **Phase 0** is satisfied (Bite 2).
- **Phase 1**: per-mechanism state on Peer is already
  there with dual-write (Bites 1, 7). The phase
  collapses to "delete the old single-state fields and
  remove dual-write" — pure deletion.
- **Phase 5**: `tm.Send` already exists (Bite 3); the
  `SendXWithFallback` wrappers are already shims. The
  phase collapses to "delete the shims and migrate call
  sites".
- **Phase 6 part 1**: IMR lookup helpers already in
  transport (Bite 6). The phase loses its largest single
  chunk of code-motion.
- **Phase 6 part 2**: discovery-completion seam already
  installed (Bite 8). When discovery moves, the
  callback wiring is in place.
- **Phase 7 sub-step 1** (`Agent.PeerID`): already done
  (Bite 4).
- **Phase 7 sub-steps 2–3**: read-shaped
  `SyncPeerFromAgent` sites already migrated (Bite 5);
  the canonical Peer-from-Agent path is documented in
  code (Bite 7). Sub-steps 2–3 become a much smaller
  migration of the remaining write sites.

The eventual main refactor turns from "9 phases of
restructure" into "9 phases mostly deleting things that
no longer have any consumers". That is the right shape
for a refactor of this scope.

## Risks and mitigations

**Risk:** A bite is harder than estimated and bleeds into
the next.
**Mitigation:** Each bite is independently revertible.
Stop at any boundary and the codebase is in a coherent
state.

**Risk:** Dual-write in Bites 1 and 7 introduces drift
between old and new fields if a code path is missed.
**Mitigation:** The unit test in Bite 7 step 5 asserts
field-by-field equivalence. Add a periodic dev-only
consistency check if drift is suspected.

**Risk:** Bite 6 (Option B) breaks call sites in
unexpected ways.
**Mitigation:** Default to Option A. Option B is
post-merge if desired.

**Risk:** Bite 5 surfaces a Peer that should exist but
doesn't (e.g. discovery not yet complete).
**Mitigation:** The fallback branch falls through to
`SyncPeerFromAgent` on nil, preserving old semantics.

## What this doc does NOT change

- The 9-phase structure of the main plan.
- The target public API of transport.
- Any wire format.
- Any of the resolved Open Questions in the main plan.
- The Phase 0 exit gate (7 scenarios on CI).

This doc only re-orders and decomposes the pre-refactor
work to maximize what can land safely without committing
to the larger restructure.
