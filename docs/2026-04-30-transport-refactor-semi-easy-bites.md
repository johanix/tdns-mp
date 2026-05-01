# Transport Interface Redesign:
# Semi-Easy Bites — Post-Early-Bites Quick Wins

Date: 2026-04-30
Status: PLAN — recommended pre-work before initiating
        the larger transport interface redesign phases.

Companion to:
[2026-04-15-transport-interface-redesign.md](./2026-04-15-transport-interface-redesign.md)
[2026-04-25-transport-refactor-early-bites.md](./2026-04-25-transport-refactor-early-bites.md)
[2026-04-23-transport-boundary-test-harness.md](./2026-04-23-transport-boundary-test-harness.md)

## Purpose

The 2026-04-25 early-bites work landed nine items
including the transport-boundary integration test
harness. With that foundation in place, a second tier of
small additive changes is now tractable that wasn't
before. Several were unlocked specifically by:

- `Agent.PeerID` field (Bite 4) → safe peer-by-ID lookup
  from MP code
- `Peer.Mechanisms` map + `MechanismState` (Bite 1) →
  per-mechanism state is the canonical source
- `Peer.PopulateFromAgent` (Bite 7) → Agent→Peer state
  refresh is a documented standalone operation
- `tm.Send` for sync (Bite 3) → the
  `SendXWithFallback` pattern has a generic home
- `OnPeerDiscovered` callback seam (Bite 8) → discovery
  completion is dispatched, not directly called
- `transport.Imr` parallel embedding (Bite 6) → IMR
  lookups have a transport-side surface
- Seven `TestTransportBoundary_*` scenarios on CI →
  state-coupling refactors have a regression net

This document collects the **semi-easy bites** that
become possible because of those foundations. Same
ground rules as before:

1. Each is wire-compatible.
2. Each leaves all three repos building.
3. Each is independently revertible (one commit, one
   `git revert`).
4. Each is small enough that it fits inside a single
   working day, with two exceptions called out below.

**Total cost estimate:** roughly 4–5 working days for
the full set, dominated by Bite H (the
`SyncPeerFromAgent` split).

**Strong recommendation:** complete the doc/audit bites
(A, B) and the trivial cleanups (I, C, E) before
starting any of the main-plan phases. The mechanical
migrations (D, F, G, H) can land opportunistically.

## Bite ordering

Bites are lettered to mirror the discussion order, not
implementation order. The recommended execution order is
**I → C → E → A → B → D → F → G → H**: hygiene first,
then trivial cleanups, then doc audits, then mechanical
migrations, then the chunky one.

| # | Bite | Repo | Cost | Unlocks |
|---|---|---|---|---|
| I | Fix `TestNewDNSMessageRouter` | tdns-transport | 30 min | clean CI |
| C | Drop `OnAgentDiscoveryComplete` shim | tdns-mp | 30 min | hsync_transport.go simplification |
| E | Promote `OnPeerDiscovered` to `func(*Peer)` | tdns-mp + tdns-transport | 30 min | Phase 6 step 3 |
| A | PeerRegistry field disposition map | doc only | 2–3 hrs | Phase 1 step 6 deletion bite (closes item L) |
| B | chunk_notify_handler cut-line spec | doc only | 2–3 hrs | Phase 4 (closes item I) |
| D | Add `OnDiscoveryFailed` callback | tdns-mp + tdns-transport | 1 hr | Phase 6 step 3 |
| F | `tm.DiscoverPeer(identity)` explicit trigger | tdns-mp + tdns-transport | half day | Phase 6 step 4 |
| G | Migrate `SendPing` through `tm.Send` | tdns-mp + tdns-transport | half day | Phase 5 (Bite 3 deferred leg) |
| H | Split `SyncPeerFromAgent` into get-or-create + populate | tdns-mp | 1 day | Phase 7 step 2 (eliminates redundant per-send mutation) |

Bite H is the largest. If time pressure dictates, defer
H to its own session. Everything else fits comfortably
inside a working week.

---

## Bite I: Fix `TestNewDNSMessageRouter`

**Source:** Pre-existing test failure flagged in the
2026-04-25 early-bites doc during Bite 7 work.

### What

`TestNewDNSMessageRouter` at
[tdns-transport/v2/transport/dns_message_router_test.go:51](../../tdns-transport/v2/transport/dns_message_router_test.go#L51)
asserts `router.middleware != nil`, but
`NewDNSMessageRouter` at
[tdns-transport/v2/transport/dns_message_router.go:126](../../tdns-transport/v2/transport/dns_message_router.go#L126)
does not initialise that slice. The test fails on every
run.

### Concrete steps

1. In `dns_message_router.go`, modify the constructor:
   ```go
   func NewDNSMessageRouter() *DNSMessageRouter {
       return &DNSMessageRouter{
           handlers:   make(map[MessageType][]*HandlerRegistration),
           middleware: []MiddlewareFunc{},   // add this line
           metrics: RouterMetrics{
               UnhandledTypes: make(map[MessageType]uint64),
           },
       }
   }
   ```
2. Run the test:
   ```bash
   cd tdns-transport/v2/transport && go test -run TestNewDNSMessageRouter
   ```
3. Run the integration harness in tdns-mp to confirm
   no regression.

### Do NOT

- Change the test itself. The test's expectation is the
  correct one; the constructor was missing init.
- Initialise `middleware` to `nil` and adjust the test —
  several places in the codebase append to this slice;
  initialised-empty is the right invariant.

### Files touched

- [tdns-transport/v2/transport/dns_message_router.go](../../tdns-transport/v2/transport/dns_message_router.go)
  (one-line addition in the constructor)

### Why it's safe

Pure additive. An initialised empty slice behaves
identically to nil for `append`, `len`, and range
iteration in Go. The only observable change is that the
test now passes.

### Value delivered

CI clean. No more "ignore the failing test, it's
unrelated" footnote in every transport-side commit.

### Estimated cost

30 minutes including build verification.

### Dependencies

None.

---

## Bite C: Drop `OnAgentDiscoveryComplete` shim

**Source:** Bite 8 left this as a deprecation shim;
post-Bite-8 grep can now retire it.

### What

After Bite 8, the canonical discovery-completion path is
`tm.TransportManager.OnPeerDiscovered`. The legacy
`MPTransportBridge.OnAgentDiscoveryComplete` was kept as
a fallback in case other call sites surfaced. Audit
2026-04-30 finds three callers:

| Site | Purpose |
|---|---|
| [tdns-mp/v2/agent_utils.go:406](../../tdns-mp/v2/agent_utils.go#L406) | Fallback if `tm.OnPeerDiscovered == nil` |
| [tdns-mp/v2/hsync_transport.go:466](../../tdns-mp/v2/hsync_transport.go#L466) | Inside the `OnPeerDiscovered` callback wired by Bite 8 — this is the seam that would call back into the shim if the seam itself were absent |
| [tdns-mp/v2/transport_integ_test.go:440](../../tdns-mp/v2/transport_integ_test.go#L440) | Test scenario 7 — exercises discovery completion |

Of these, only the test caller is genuinely independent;
the other two are sides of the same seam. After Bite 8,
the production path always goes through `OnPeerDiscovered`
(Bite 8 sets it unconditionally at MP startup), so the
fallback at agent_utils.go:406 is unreachable.

### Concrete steps

1. In
   [tdns-mp/v2/agent_utils.go](../../tdns-mp/v2/agent_utils.go)
   around line 399–406, delete the `if/else` and keep
   only the `OnPeerDiscovered` branch. Verify
   `tm.OnPeerDiscovered` is set unconditionally at startup
   (Bite 8 wired it in `hsync_transport.go:458`); if there
   is any path that leaves it nil, fix that first.
2. Move the body of `OnAgentDiscoveryComplete`
   ([tdns-mp/v2/hsync_transport.go:1692](../../tdns-mp/v2/hsync_transport.go#L1692))
   inline into the `OnPeerDiscovered` closure at
   [hsync_transport.go:458](../../tdns-mp/v2/hsync_transport.go#L458).
   The closure already does most of this; verify field
   parity (preferred-transport selection +
   `peer.SetState(PeerStateKnown, ...)`) before deletion.
3. Delete the `OnAgentDiscoveryComplete` method
   declaration.
4. Update the integration test
   ([transport_integ_test.go:440](../../tdns-mp/v2/transport_integ_test.go#L440))
   to invoke `tm.OnPeerDiscovered(agent.PeerID)` directly
   instead of the deleted shim.
5. Build all four mp binaries; run the integration
   harness.

### Do NOT

- Delete the shim before the integration test is
  migrated — the test will fail.
- Inline the closure body without first verifying that
  every line of `OnAgentDiscoveryComplete` is represented
  in the closure. Bite 8 was careful to preserve
  semantics; this bite must preserve them too.

### Files touched

- [tdns-mp/v2/agent_utils.go](../../tdns-mp/v2/agent_utils.go)
  (delete fallback branch, ~5 lines)
- [tdns-mp/v2/hsync_transport.go](../../tdns-mp/v2/hsync_transport.go)
  (inline + delete shim, ~25 lines)
- [tdns-mp/v2/transport_integ_test.go](../../tdns-mp/v2/transport_integ_test.go)
  (update test to call `OnPeerDiscovered` directly)

### Why it's safe

The shim is unreachable in production after Bite 8. The
test caller is updated in lockstep. Same code runs in
the same order; one indirection is removed.

### Value delivered

`MPTransportBridge` shrinks by one method. The dual-path
in `agent_utils.go` becomes a single path. Future
readers of the discovery completion path don't have to
ask "which entry point fires when?"

### Estimated cost

30 minutes.

### Dependencies

- **Bite 8** (`OnPeerDiscovered` seam) — already done.

---

## Bite E: Promote `OnPeerDiscovered` to `func(*Peer)`

**Source:** Phase 6 step 3 of the parent plan. Bite 8
chose `func(peerID string)` for the seam to keep the
diff minimal; the parent plan's target is
`func(peer *Peer)`. Promote now that the seam has
exactly one production caller.

### What

Change the field at
[tdns-transport/v2/transport/manager.go:101](../../tdns-transport/v2/transport/manager.go#L101)
from:
```go
OnPeerDiscovered func(peerID string)
```
to:
```go
OnPeerDiscovered func(peer *Peer)
```

Transport does the `PeerRegistry.Get` lookup before
invoking the callback; the callback gets a resolved
`*Peer` and never has to do the lookup itself.

### Why this matters

- Aligns the seam with the parent plan's Phase 6 target.
- Removes a `PeerRegistry.Get` call from MP's discovery
  closure (the seam owner does it once, not every
  caller).
- Eliminates a class of bug where the callback
  legitimately fires but the peer has been evicted
  between the lookup and the invocation.
- Sets up Phase 6 step 5 cleanly: when discovery moves
  into transport, the callback already takes the type
  transport will produce.

### Concrete steps

1. In
   [tdns-transport/v2/transport/manager.go](../../tdns-transport/v2/transport/manager.go)
   around line 91–101, change the type of
   `OnPeerDiscovered` and update its doc comment.
2. Find every site that *invokes* the callback (today:
   [tdns-mp/v2/agent_utils.go:404](../../tdns-mp/v2/agent_utils.go#L404)).
   Wrap the invocation: look up the peer first, then
   call. If the lookup fails, log and skip.
3. Find every site that *registers* the callback
   (today:
   [tdns-mp/v2/hsync_transport.go:458](../../tdns-mp/v2/hsync_transport.go#L458)).
   Update the closure signature; drop the internal
   `peerRegistry.Get(AgentId(peerID))` call since the
   peer is now passed in.
4. Build; run the integration harness.

### Do NOT

- Forget the integration test scenario 7
  (`TestTransportBoundary_DiscoveryComplete`) — it asserts
  the callback fires. The signature change must be
  reflected in the test.
- Treat a nil peer as an error inside the callback. The
  invocation site already filters; the callback can
  assume non-nil.

### Files touched

- [tdns-transport/v2/transport/manager.go](../../tdns-transport/v2/transport/manager.go)
  (field type + doc comment)
- [tdns-mp/v2/agent_utils.go](../../tdns-mp/v2/agent_utils.go)
  (invocation site)
- [tdns-mp/v2/hsync_transport.go](../../tdns-mp/v2/hsync_transport.go)
  (registration site / closure body)
- [tdns-mp/v2/transport_integ_test.go](../../tdns-mp/v2/transport_integ_test.go)
  (test scenario 7 if it observes the callback signature)

### Why it's safe

Single field type change with three known call sites.
Compile-time enforces full propagation. Wire format
unchanged.

### Value delivered

Exact alignment with Phase 6 step 3. Callback contract
matches what transport will own once discovery moves.
Slightly cleaner MP closure body.

### Estimated cost

30 minutes.

### Dependencies

- **Bite 8** (`OnPeerDiscovered` seam) — already done.
- **Bite C** is not strictly required, but doing C
  first makes E touch one fewer file
  (`OnAgentDiscoveryComplete` is gone before E starts).

---

## Bite A: PeerRegistry field disposition map (doc only)

**Source:** Closes open issue **L** in the parent plan
(PeerRegistry shim spec). Pre-work for the eventual
Phase 1 step 6 deletion bite.

### What

After Bites 1 + 7, `Peer.Mechanisms` is the canonical
per-mechanism state. The original single-state fields on
`Peer` are now duplicates: every receipt site
dual-writes them. Phase 1 step 6 plans to delete the
duplicates outright.

This bite produces the audit table that turns step 6
into a mechanical deletion. For each old single-state
field, document:

1. Its name and type.
2. Whether `Peer.Mechanisms` already provides equivalent
   information, and how.
3. Every read site in tdns-mp (with file:line) and
   tdns-transport.
4. The replacement expression at each read site (e.g.
   `peer.State` → `peer.EffectiveState()`,
   `peer.LastBeatReceived` →
   `peer.Mechanisms[mechName].LastBeatRecv`).
5. Any read site whose semantics aren't trivially
   preserved by `Mechanisms` — those need follow-up
   (likely small, but the audit must surface them
   before the deletion bite begins).

### Fields to audit

From
[tdns-transport/v2/transport/peer.go](../../tdns-transport/v2/transport/peer.go)
lines 55–101 (the `Peer` struct):

- `State PeerState`
- `StateReason string`
- `StateChanged time.Time`
- `DiscoveryAddr *Address`
- `OperationalAddr *Address`
- `APIEndpoint string`
- `LastHelloSent time.Time`
- `LastHelloReceived time.Time`
- `LastBeatSent time.Time`
- `LastBeatReceived time.Time`
- `BeatSequence uint64`
- `ConsecutiveFails int`
- `Stats MessageStats`
- `PreferredTransport string`

Out of scope for this bite (different concerns):
`SharedZones`, `ZoneRelation`, `Capabilities`,
`LongTermPubKey`, `KeyType`, `TLSARecord`, `ID`,
`DisplayName`. Scope/zone fields are addressed
separately (parent plan §A4); identity/crypto fields
stay.

### Concrete steps

1. Create a new doc:
   `tdns-mp/docs/2026-04-30-peerregistry-field-disposition.md`.
2. For each field in the list above, run:
   ```bash
   grep -rn "peer\.<FieldName>\|p\.<FieldName>\|\.<FieldName>" \
       tdns-mp/v2/ tdns-transport/v2/transport/
   ```
   and tabulate read sites. Skip writes — every receipt
   site already dual-writes; deletion plan is to drop
   the writes too.
3. For each read site, write the replacement
   expression. The patterns are:
   - State queries → `peer.EffectiveState()`,
     `peer.HasMechanism(name)`,
     `peer.PreferredMechanism()`
   - Per-mechanism timestamps →
     `peer.Mechanisms[name].LastHelloRecv` etc.
   - Per-mechanism addresses →
     `peer.Mechanisms[name].Address`
   - `peer.APIEndpoint` →
     `peer.Mechanisms["API"].Address.String()` or
     similar (need to check exact representation)
4. Flag any read site whose replacement is non-trivial.
5. End the doc with a "Deletion phase" section listing,
   in dependency order, which fields can be deleted in
   one swing vs which need a precursor migration.

### Do NOT

- Make any code changes during this bite. The output
  is a doc; the deletion is a separate later bite (or
  Phase 1 step 6).
- Audit fields outside the listed set. `SharedZones`
  and friends are bigger and belong to the scope-handling
  refactor.

### Files touched

- New:
  `tdns-mp/docs/2026-04-30-peerregistry-field-disposition.md`

### Why it's safe

Pure documentation. No code changes.

### Value delivered

- Closes parent-plan open item **L** with concrete
  per-field disposition instead of a vague "shim spec".
- The eventual deletion bite becomes a pure mechanical
  pass — no surprises mid-deletion.
- The dual-write code paths in the receipt sites are
  pre-mapped to their deletion target.

### Estimated cost

2–3 hours.

### Dependencies

- **Bites 1, 7** (per-mechanism state in place) —
  already done.

---

## Bite B: chunk_notify_handler cut-line spec (doc only)

**Source:** Closes open issue **I** in the parent plan
(Phase 4 chunk_notify_handler split — concrete cut
line). Pre-work for Phase 4.

### What

[tdns-transport/v2/transport/chunk_notify_handler.go](../../tdns-transport/v2/transport/chunk_notify_handler.go)
is ~580 lines and does many things at once:

- Parses QNAME to extract sender identity
- Reassembles multi-chunk payloads
- Decrypts the encrypted blob
- Parses JSON to extract zone, message type,
  originator
- Does zone-peer authorization
- Routes to "hsyncengine"
- Understands beat/sync/update message types

Phase 4 of the parent plan splits this into a generic
CHUNK reassembly handler (stays in transport) and an
MP-specific message dispatcher (moves to MP). The split
is non-trivial because crypto, parse, and authz are
interleaved.

This bite writes the cut-line spec. Once the spec
exists, Phase 4 becomes a mechanical extraction.

### Required content

The output doc must contain:

1. **Sequence diagram** of the current flow with every
   step numbered (~10–12 steps from "NOTIFY arrives" to
   "DNS response sent").
2. **Cut line**: which steps stay in transport (generic
   CHUNK reassembly + decryption) vs which move to MP
   (QNAME parse, JSON parse, zone authz, message-type
   dispatch).
3. **Authz placement decision**: the parent plan's open
   item I asks specifically whether post-crypto / scope
   authz happens in transport or in the app callback.
   Answer with rationale.
4. **Callback contract**: signature for the
   transport→app handoff after decryption. Likely:
   ```go
   type DecryptedChunkHandler func(
       ctx context.Context,
       sender string,        // pre-crypto QNAME extraction
       payload []byte,       // decrypted JSON blob
   ) error
   ```
   Document the contract: when does the callback fire,
   what is `sender` derived from, what error semantics
   abort the DNS response vs return REFUSED.
5. **State that crosses the cut**: what does transport
   hand to MP that isn't in the callback signature?
   Likely: nothing, but verify by reading the current
   handler.
6. **Test impact**: which of the seven harness
   scenarios exercise this path? Scenarios 1, 5 likely.
   Confirm and note any harness changes required by
   the eventual split.

### Concrete steps

1. Read
   [chunk_notify_handler.go](../../tdns-transport/v2/transport/chunk_notify_handler.go)
   end to end. Number the steps.
2. Create
   `tdns-mp/docs/2026-04-30-chunk-notify-handler-split.md`.
3. Write the sequence diagram (markdown ordered list
   is fine, or ASCII-art if helpful).
4. Mark each step as **T** (transport, stays) or **M**
   (MP, moves).
5. Identify the cut line: the boundary between the last
   T step and the first M step.
6. Define the callback signature (above).
7. Decide post-crypto authz placement. Default
   recommendation: **MP**, because authz depends on
   zone-peer relationships that are MP concepts. The
   transport-side pre-crypto authz (sender is a known
   peer) stays in transport.
8. List harness scenario impact.

### Do NOT

- Make code changes. Output is a doc.
- Move the actual split work into this bite. Phase 4
  is its own thing.

### Files touched

- New:
  `tdns-mp/docs/2026-04-30-chunk-notify-handler-split.md`

### Why it's safe

Pure documentation.

### Value delivered

- Closes parent-plan open item **I**.
- Phase 4 becomes a mechanical extraction with a
  decided cut line and a defined callback contract.

### Estimated cost

2–3 hours, dominated by reading the existing 580-line
handler carefully.

### Dependencies

None.

---

## Bite D: Add `OnDiscoveryFailed` callback

**Source:** Phase 6 step 3 of the parent plan;
symmetric to Bite 8.

### What

Bite 8 installed the success seam:
`tm.OnPeerDiscovered`. The failure seam was deferred.
Add it now — same shape, same wiring, just for the
failure path.

### Concrete steps

1. In
   [tdns-transport/v2/transport/manager.go](../../tdns-transport/v2/transport/manager.go)
   alongside `OnPeerDiscovered` (line 91–101), add:
   ```go
   // OnDiscoveryFailed is invoked when peer discovery
   // fails permanently (after retries are exhausted).
   // Optional; if nil, transport takes no action beyond
   // marking the peer FAILED in PeerRegistry.
   //
   // Currently invoked by MP's discovery loop when
   // attemptDiscovery returns an error after retries;
   // will be invoked by transport itself once discovery
   // moves (Phase 6 of the transport interface
   // redesign).
   OnDiscoveryFailed func(peer *Peer, err error)
   ```
   Note: signature uses `*Peer` per Bite E. If E hasn't
   landed yet, use `func(peerID string, err error)` and
   migrate alongside E.
2. In tdns-mp's discovery failure path
   (likely
   [agent_utils.go](../../tdns-mp/v2/agent_utils.go)
   near where `attemptDiscovery` returns an error after
   retry exhaustion — grep for the retry counter or
   error-return path), invoke
   `tm.OnDiscoveryFailed` if non-nil. Pass the peer
   (or peerID) and the final error.
3. In MP startup
   ([hsync_transport.go:458](../../tdns-mp/v2/hsync_transport.go#L458)
   alongside the `OnPeerDiscovered` registration),
   register an `OnDiscoveryFailed` closure. Body: log
   the failure, mark the agent state appropriately.
   Initial body can mirror what MP already does on
   discovery failure today.
4. Add an integration test scenario or extend an
   existing one to assert the callback fires on
   discovery failure. Optional but recommended.
5. Build; run harness.

### Do NOT

- Move discovery itself in this bite. Same scope as
  Bite 8: install the seam without moving the loop.
- Treat `OnDiscoveryFailed` as terminal — discovery
  may be retried later for the same peer (e.g.
  manually, or after a config change). The callback
  fires once per round of retries, not once forever.

### Files touched

- [tdns-transport/v2/transport/manager.go](../../tdns-transport/v2/transport/manager.go)
  (add field)
- [tdns-mp/v2/hsync_transport.go](../../tdns-mp/v2/hsync_transport.go)
  (register closure at startup)
- [tdns-mp/v2/agent_utils.go](../../tdns-mp/v2/agent_utils.go)
  (invoke at failure site)
- Optional:
  [tdns-mp/v2/transport_integ_test.go](../../tdns-mp/v2/transport_integ_test.go)
  (assertion)

### Why it's safe

Same shape as Bite 8. Same code runs at the same place
in the failure path; one indirection added.

### Value delivered

- Phase 6 step 3 fully satisfied.
- Discovery failure has a documented dispatch surface
  for future observers (metrics, audit).
- When discovery moves (Phase 6 part 2), the failure
  callback is already wired.

### Estimated cost

1 hour.

### Dependencies

- **Bite 8** (`OnPeerDiscovered`) — already done.
- **Bite E** (callback signature) — recommended to
  land first so D inherits the new signature shape.

---

## Bite F: `tm.DiscoverPeer(identity)` explicit trigger

**Source:** Phase 6 step 4 of the parent plan.

### What

Today, peer discovery is kicked off implicitly by MP's
discovery loop watching the AgentRegistry. Phase 6 step
4 calls for an explicit transport-side method:
```go
func (tm *TransportManager) DiscoverPeer(identity string) (*Peer, error)
```
that creates a NEEDED peer entry (if not already
present) and triggers discovery.

This bite adds the method. It does not move the
discovery loop — Phase 6 part 2 still owns that. The
method is a thin wrapper around the existing
machinery: insert a peer in NEEDED state, kick the
discovery process (or block until completion,
depending on chosen semantics).

### Open design choice

Two reasonable shapes:

- **Async**: returns immediately with a NEEDED peer;
  caller relies on `OnPeerDiscovered` for completion.
- **Sync**: blocks until discovery finishes (or
  context times out); returns the resolved peer or
  error.

Recommend **sync** for the explicit-trigger API. The
async path is already covered by the watching loop;
the explicit API is for callers who want the result
inline (e.g. CLI commands, test scenarios). If a
caller wants async, they can launch a goroutine.

### Concrete steps

1. In
   [tdns-transport/v2/transport/manager.go](../../tdns-transport/v2/transport/manager.go),
   add `DiscoverPeer`:
   ```go
   // DiscoverPeer initiates peer discovery for the
   // given identity. Blocks until discovery completes
   // or the context is cancelled. Returns the resolved
   // peer on success.
   //
   // If a peer with this identity already exists in
   // KNOWN state, returns it without re-discovery. If
   // it exists in NEEDED or DISCOVERING state, joins
   // the in-flight discovery.
   func (tm *TransportManager) DiscoverPeer(
       ctx context.Context,
       identity string,
   ) (*Peer, error)
   ```
2. Implementation: lookup or create peer; if KNOWN,
   return; otherwise call into the existing IMR-driven
   lookup path (the methods already on
   `*transport.Imr` from Bite 6: `LookupAgentJWK`,
   `LookupAgentAPIEndpoint`, `LookupAgentDNSEndpoint`,
   `LookupAgentTLSA`); populate the peer; transition
   state; return.
3. The actual discovery body for now can call into
   tdns-mp's discovery code via the same callback
   pattern — this bite does not move the loop. If
   that's awkward (transport calls back into MP),
   define a temporary `DiscoveryDriver` interface that
   MP implements, attached to `TransportManager`. Phase
   6 part 2 deletes the interface when discovery moves
   wholesale.
4. Add a CLI command in tdns-mp that exercises the
   method (e.g. `tdns-mpcli debug discover-peer
   <identity>`). Optional but useful for testing.
5. Add an integration test that calls `DiscoverPeer`
   directly and asserts the result. Optional.
6. Build; run harness.

### Do NOT

- Move the discovery loop. Phase 6 part 2.
- Change the existing implicit discovery path. The new
  method is additive; the loop continues to discover
  NEEDED peers automatically.
- Define a permanent `DiscoveryDriver` interface. If
  one is needed temporarily, mark it as such; it goes
  away in Phase 6 part 2.

### Files touched

- [tdns-transport/v2/transport/manager.go](../../tdns-transport/v2/transport/manager.go)
  (new method, ~50 lines)
- Possibly
  [tdns-transport/v2/transport/imr.go](../../tdns-transport/v2/transport/imr.go)
  if a small helper is needed
- Optional new CLI command in
  [tdns-mp/cli/](../../tdns-mp/cli/) or wherever
  mpcli debug commands live.

### Why it's safe

Additive. Existing implicit discovery loop continues
unchanged. The new explicit API is opt-in; no caller
is forced to use it.

### Value delivered

- Phase 6 step 4 satisfied.
- CLI/test/external callers get a clean way to
  discover a peer on demand.
- Sets up Phase 6 part 2: when the implicit loop
  moves into transport, it will likely call
  `DiscoverPeer` for each NEEDED peer it sees.

### Estimated cost

Half a day. Most of the time is wiring the existing
discovery body into the new entry point cleanly.

### Dependencies

- **Bite 6** (`transport.Imr` lookup helpers) —
  already done.
- **Bite E** (callback signature) — recommended; if
  `DiscoverPeer` resolves to a `*Peer`, returning
  `*Peer` is consistent.

---

## Bite G: Migrate `SendPing` through `tm.Send`

**Source:** Bite 3's deferred third leg.

### What

Bite 3 added `tm.Send` and migrated
`SendSyncWithFallback`. Hello and Beat were excluded
because their semantics are send-on-all-transports-
in-parallel rather than primary-then-fallback — that's
properly Phase 5 work. Ping was excluded for a
different reason: small caller surface, not worth the
per-bite churn at the time.

That reason is gone. With `tm.Send` already supporting
`*PingRequest` in its type-switch (per the
verification), `MPTransportBridge.SendPing` can become
a thin delegation, then disappear entirely.

### Audit

Today there are two `SendPing` methods:

- [tdns-mp/v2/hsync_transport.go:1554](../../tdns-mp/v2/hsync_transport.go#L1554)
  — `MPTransportBridge.SendPing` (the wrapper)
- [tdns-transport/v2/transport/manager.go:342](../../tdns-transport/v2/transport/manager.go#L342)
  — `TransportManager.SendPing` (the actual impl)

The MP wrapper exists for symmetry with `SendSync`,
`SendHello`, `SendBeat`. Now that `tm.Send` is the
canonical path, the wrapper is redundant.

### Concrete steps

1. Confirm the `tm.Send` type-switch handles
   `*PingRequest` correctly (per verification, it
   does — line 274 of manager.go).
2. Rewrite `MPTransportBridge.SendPing`'s body to
   delegate:
   ```go
   func (tm *MPTransportBridge) SendPing(
       ctx context.Context,
       peer *transport.Peer,
   ) (*transport.PingResponse, error) {
       req := &transport.PingRequest{ /* … */ }
       resp, err := tm.TransportManager.Send(ctx, peer, req)
       if err != nil {
           return nil, err
       }
       return resp.(*transport.PingResponse), nil
   }
   ```
3. Grep for callers of `MPTransportBridge.SendPing`. If
   the caller surface is genuinely small (per the
   plan), migrate them to call `tm.TransportManager.Send`
   directly with a `*PingRequest`, and delete the
   wrapper. If it's not small, keep the wrapper as a
   thin shim — same as `SendSyncWithFallback` today.
4. Also delete the older
   `TransportManager.SendPing` if it's now redundant
   with the type-switched `Send`. It might still be
   useful for callers that want the explicit method;
   keep if so. Verdict during execution.
5. Build; run harness; run any ping-specific tests.

### Do NOT

- Touch `SendHelloWithFallback` or
  `SendBeatWithFallback`. Different semantics; Phase 5
  work.
- Remove `tm.SendPing` if any external caller
  (CLI, scripts) imports the transport package
  directly and uses it. Grep first.

### Files touched

- [tdns-mp/v2/hsync_transport.go](../../tdns-mp/v2/hsync_transport.go)
  (delegate or delete `SendPing` wrapper)
- [tdns-transport/v2/transport/manager.go](../../tdns-transport/v2/transport/manager.go)
  (possibly delete `SendPing` if unused)
- Caller migrations (small)

### Why it's safe

Same shape as Bite 3. The type-switched path is
already proven for sync; ping is the same pattern with
a different request type.

### Value delivered

- One more `SendXWithFallback` wrapper retired.
- Phase 5 shrinks by exactly the body of
  `MPTransportBridge.SendPing`.

### Estimated cost

Half a day.

### Dependencies

- **Bite 3** (`tm.Send`) — already done.

---

## Bite H: Split `SyncPeerFromAgent` into get-or-create
## and state-refresh

**Source:** Phase 7 step 2 of the parent plan. Bite 5
audit established the shape of the work; this bite
executes it.

### What

`SyncPeerFromAgent` is called on every send. Each call
does both:

1. **Get or create** a peer in PeerRegistry keyed by the
   agent's identity.
2. **Populate** that peer's per-mechanism state from
   the agent's `ApiDetails` / `DnsDetails`.

The Bite 5 audit confirmed all 9 call sites are
write-shaped (each acquires a peer to immediately send
through it). On every send, step 2 mutates ~20 fields
even though the peer's state usually hasn't changed
since the last send.

After Bite 7, step 2 is a separate documented method:
`Peer.PopulateFromAgent`. This bite splits
`SyncPeerFromAgent` so callers can opt out of step 2
when they don't need it.

### Target shape

After this bite:

```go
// GetOrCreatePeer returns the Peer keyed by
// agent.PeerID, creating it (in NEEDED state) if it
// does not exist. Does not refresh state from the
// agent — call SyncPeerFromAgent (or
// peer.PopulateFromAgent directly) when fresh state
// is needed.
func (tm *MPTransportBridge) GetOrCreatePeer(agent *Agent) *transport.Peer

// SyncPeerFromAgent returns the Peer for this agent
// and refreshes its per-mechanism state from the
// agent. Equivalent to GetOrCreatePeer followed by
// peer.PopulateFromAgent. Use when state is known to
// be stale (e.g. after discovery completion).
func (tm *MPTransportBridge) SyncPeerFromAgent(agent *Agent) *transport.Peer
```

The 9 call sites then split:

- **Hot send paths (8 sites)** call `GetOrCreatePeer`.
  No per-send state mutation.
- **Discovery completion (1 site,
  `OnPeerDiscovered` closure)** calls
  `SyncPeerFromAgent` because state is genuinely fresh.

### Concrete steps

1. In
   [tdns-mp/v2/hsync_transport.go:1378](../../tdns-mp/v2/hsync_transport.go#L1378),
   read the current `SyncPeerFromAgent` body. Identify
   the get-or-create portion (PeerRegistry lookup,
   conditional creation, ID/identity setup) and
   separate it from the state-refresh portion (every
   field write that comes from `agent.ApiDetails` /
   `agent.DnsDetails` / agent state).
2. Add `GetOrCreatePeer` containing only the
   get-or-create portion. Most of the existing body
   that touches `peer.ID`, `peer.DisplayName`,
   `peer.LongTermPubKey`, etc., on first creation
   stays here. State-refresh fields move out.
3. Rewrite `SyncPeerFromAgent` as:
   ```go
   func (tm *MPTransportBridge) SyncPeerFromAgent(agent *Agent) *transport.Peer {
       peer := tm.GetOrCreatePeer(agent)
       peer.PopulateFromAgent(agent)
       return peer
   }
   ```
4. Verify field parity: every write that the original
   `SyncPeerFromAgent` did is now done either in
   `GetOrCreatePeer` (one-time setup) or in
   `peer.PopulateFromAgent` (state refresh). The
   integration harness scenario 7 will catch
   regressions in the discovery completion path.
5. Migrate the 8 hot send-path call sites:

   | File:Line | Caller | New call |
   |---|---|---|
   | hsync_transport.go:1449 | SendHelloWithFallback | `GetOrCreatePeer` |
   | hsync_transport.go:1574 | SendBeatWithFallback | `GetOrCreatePeer` |
   | hsync_transport.go:1693 | SendSyncWithFallback | `GetOrCreatePeer` |
   | hsync_transport.go:1803 | SendConfirmWithFallback | `GetOrCreatePeer` |
   | hsync_transport.go:2264 | SendInfraBeat | `GetOrCreatePeer` |
   | hsyncengine.go:711 | HelloHandler callback | `GetOrCreatePeer` |
   | hsyncengine.go:964 | sendRfiToAgent | `GetOrCreatePeer` |
   | apihandler_agent.go:1076 | debug send-sync | `GetOrCreatePeer` |

6. The 9th call site is the discovery-completion path
   inside the `OnPeerDiscovered` closure
   (hsync_transport.go:458 area). Leave this one as
   `SyncPeerFromAgent` — discovery-completion is
   exactly when full state refresh is wanted.
7. Run the integration harness. **All seven scenarios
   must pass.** Pay particular attention to scenarios
   1, 2, 3 (which exercise the hot send paths) and
   scenario 7 (discovery completion). If any scenario
   fails, the field parity in step 4 is wrong.
8. Build all four mp binaries; run any unit tests in
   the affected files.

### Verification: per-mechanism state is preserved

The risk is that a hot send path relies on
`SyncPeerFromAgent`'s side effect of refreshing state
that the dual-write didn't set. To verify:

- Before the migration, observe a peer's state during
  a hot send via debug-print or breakpoint. Note
  fields that change between two consecutive sends.
- After the migration, repeat. The fields should be
  populated by the dual-write at hello/beat receipt
  sites already; per-send refresh is redundant.
- If something does change between sends that
  dual-write doesn't capture, that's a missing
  dual-write site. Fix it before completing this bite.

### Do NOT

- Delete `SyncPeerFromAgent`. It stays for the
  discovery-completion path. Phase 7 deletes it
  outright after full Phase 7 work.
- Add new functionality during the split. The two
  new functions together do exactly what
  `SyncPeerFromAgent` did before. Refactor only.
- Skip the harness verification step. State-coupling
  refactors require it.

### Files touched

- [tdns-mp/v2/hsync_transport.go](../../tdns-mp/v2/hsync_transport.go)
  (split + 5 call site migrations)
- [tdns-mp/v2/hsyncengine.go](../../tdns-mp/v2/hsyncengine.go)
  (2 call site migrations)
- [tdns-mp/v2/apihandler_agent.go](../../tdns-mp/v2/apihandler_agent.go)
  (1 call site migration)

### Why it's safe

`SyncPeerFromAgent` semantics preserved exactly via
the wrapper. Hot send paths get a strictly cheaper
operation (the same lookup, no redundant state
refresh). The integration harness catches any drift.

### Value delivered

- Eliminates ~20 redundant field writes per send across
  all hot paths.
- Phase 7's eventual deletion of `SyncPeerFromAgent`
  becomes a deletion of one wrapper plus one call site,
  not 9.
- Documents the get-or-create vs sync-state distinction
  in code, not just in commentary.

### Estimated cost

1 day. Most of the cost is the field-parity audit in
step 4 and the post-migration harness verification.

### Dependencies

- **Bite 7** (`Peer.PopulateFromAgent`) — already done.
- **Bite 4** (`Agent.PeerID`) — already done.
- **Bite 2** (test harness) — already done; required
  here as the regression net.

---

## Cumulative effect

After all nine semi-easy bites:

- **Phase 1 step 6** has a complete deletion playbook
  (Bite A).
- **Phase 4** has a decided cut line and callback
  contract (Bite B).
- **Phase 5** sheds another wrapper (Bite G); only the
  Hello/Beat parallel-send pattern remains as Phase 5
  work.
- **Phase 6 step 3** is fully populated (Bites D + E).
- **Phase 6 step 4** has its explicit-trigger API
  (Bite F).
- **Phase 7 step 2** is mostly done (Bite H); only the
  final deletion of `SyncPeerFromAgent` remains.
- **CI** is clean (Bite I).
- **`MPTransportBridge`** sheds `OnAgentDiscoveryComplete`
  (Bite C) and possibly `SendPing` (Bite G), getting
  closer to the eventual Phase 7 deletion.

Open items remaining after this set: **N** (per-phase
rollback criteria, doc), **O** (disposition table
walk-through for the 6 method delta in
hsync_transport.go, doc). Both are doc tasks suitable
for the Phase 1 kickoff.

The 9-phase main refactor turns from "structurally
sound but needs Phase 0 first" into "Phases 0 done,
1+5+6+7 partial via bites, with the remaining work in
each phase reduced to specific deletions and the
genuinely hard chunks (Phase 2 type migration, Phase 3
handler cleanup, Phase 4 chunk handler split, Phase 5
parallel-send semantics, Phase 7 final deletion)."

## Risks and mitigations

**Risk:** Bite H surfaces a missing dual-write site —
some field that the per-send `SyncPeerFromAgent` was
silently keeping fresh, that the receipt-site
dual-write doesn't capture.
**Mitigation:** The verification step in Bite H step 7
explicitly hunts for this. The integration harness
covers the obvious paths.

**Risk:** Bite F's `DiscoveryDriver` interface (if
needed temporarily) leaks into the transport API and
becomes hard to remove in Phase 6 part 2.
**Mitigation:** Only define the interface if step 3
of Bite F genuinely needs it. Mark it as temporary in
the doc comment. Keep it unexported if possible.

**Risk:** Bites C, E, D land in close succession and
introduce a partial-state where the seam signature is
inconsistent across files.
**Mitigation:** Stick to the recommended order
(I → C → E → A → B → D → F → G → H). Each lands
self-contained.

**Risk:** Bite A's audit surfaces fields with
non-trivial replacement semantics, blocking the
eventual Phase 1 step 6 deletion.
**Mitigation:** That is exactly what the audit is for.
Surfacing such fields is value, not failure. Add them
to the deletion-phase ordering at the end of the doc.

## What this doc does NOT change

- The 9-phase structure of the main plan.
- The target public API of transport.
- Any wire format.
- Any of the resolved Open Questions.
- The early-bites (Bites 0–8).

This doc only adds a second tier of additive work that
becomes safe and useful given what the early bites
already landed.
