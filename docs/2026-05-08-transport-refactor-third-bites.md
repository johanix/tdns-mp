# Transport Interface Redesign:
# Third Bites — Post-Semi-Easy-Bites Quick Wins

Date: 2026-05-08
Status: PLAN — proposed next set of small, low-risk
        bites following the merge of the
        `transport-refactor-semi-easy-bites` branch.

Companion to:
[2026-04-15-transport-interface-redesign.md](./2026-04-15-transport-interface-redesign.md)
[2026-04-25-transport-refactor-early-bites.md](./2026-04-25-transport-refactor-early-bites.md)
[2026-04-30-transport-refactor-semi-easy-bites.md](./2026-04-30-transport-refactor-semi-easy-bites.md)
[2026-04-30-peerregistry-field-disposition.md](./2026-04-30-peerregistry-field-disposition.md)
[2026-04-30-chunk-notify-handler-split.md](./2026-04-30-chunk-notify-handler-split.md)

## Purpose

The semi-easy bites (A–H) landed two important
foundations on top of what early-bites already provided:

- A fully audited PeerRegistry **field disposition map**
  (Bite A) — every read site for the 14 single-state
  fields is enumerated with replacement expressions and
  a three-group deletion ordering.
- A precise **cut line for chunk_notify_handler** (Bite
  B) — twelve-step request flow with the transport/MP
  split documented down to the callback signature.
- The `OnPeerDiscovered` and `OnDiscoveryFailed` seams,
  with `func(*Peer)` signatures (Bites C, D, E) and the
  temporary `DiscoveryDriver` interface (Bite F).
- `SyncPeerFromAgent` split into `GetOrCreatePeer` plus
  state-refresh, with hot send-path callers migrated
  away from per-send full-state-refresh (Bite H).

With those foundations in place, a third tier of bites
becomes tractable. Same ground rules:

1. Each is wire-compatible.
2. Each leaves all three repos building (tdns,
   tdns-transport, tdns-mp).
3. Each is independently revertible (one commit, one
   `git revert`).
4. Each fits inside a single working session — most
   under two hours, two larger ones called out.
5. Each lands behind the seven
   `TestTransportBoundary_*` scenarios as the
   regression net.

**Total cost estimate:** roughly 2–3 working days for
the full set, dominated by Bite δ (parallel
Hello/Beat sends) and Bite ε (move discovery into
transport).

**Strong recommendation:** land the trivial bites
(α, β, γ) first as a warm-up batch (under three hours
combined). They're pure cleanup that the field
disposition audit unblocks. The mechanical migrations
(δ, ε) can land opportunistically. The MP message
dispatcher extraction (ζ) is large enough to be its
own session.

## Bite ordering

Bites are letter-suffixed (Greek to distinguish from
prior sets). Recommended execution order is
**α → β → γ → δ → ε → ζ**: hygiene first, then
mechanical migrations, then the chunky structural ones.

| # | Bite | Repo | Cost | Unlocks |
|---|---|---|---|---|
| α | Remove `ZoneRelation` + `SharedZones` from `Peer` | tdns-transport | 1 hr | Phase 1 step 5 |
| β | Rename `BeatRequest.Gossip` → `AppData` | tdns-transport + tdns-mp | 30 min | Phase 2 prep |
| γ | Group A read-site migration (5 fields) | tdns-mp | 2 hrs | Phase 1 step 6 deletion bite |
| δ | Hello/Beat parallel-send semantics | tdns-mp | 5 hrs | Phase 5 completion |
| ε | Move discovery loop into transport | tdns-mp + tdns-transport | 1.5 days | Phase 6 part 2 + DiscoveryDriver removal |
| ζ | Extract `MPMessageDispatcher` (route\*Message family) | tdns-mp | 1 day | Phase 3 entry |

If time pressure dictates, do **α + β + γ** as a single
warm-up commit batch and defer δ, ε, ζ to dedicated
sessions.

---

## Bite α: Remove `ZoneRelation` and `SharedZones` from `Peer`

**Repo:** tdns-transport (and one or two MP read sites if any).

**Cost:** ~1 hour.

**Why this is safe now:** Bite A's audit confirms these
two fields are out-of-scope for the transport's peer
representation — they encode an MP-specific concept
(which zones two peers share). The transport doesn't
read them. They were already flagged as out-of-scope in
the original early-bites doc but never actually
removed.

**The change:**

1. Delete `ZoneRelation string` and
   `SharedZones []string` from
   `tdns-transport/v2/transport/peer.go`.
2. Audit MP read sites with
   `grep -rn 'ZoneRelation\|SharedZones'
   tdns-mp/v2/`. Per Bite A's audit, expect zero or near-zero
   hits in transport-facing code paths.
3. If MP retains the concept internally, move the data
   onto an MP-side struct that wraps `*Peer` (e.g.
   `MPPeerContext` keyed by `Peer.Identity`) — but
   only if a real read site requires it. The most
   likely outcome is no MP-side replacement is needed.

**Success criteria:**
- Both fields gone from `Peer`.
- No build break in any of the three repos.
- All seven integration scenarios pass.

**Risk:** Very low. Pure deletion. If a read site is
missed, the build fails immediately.

**Closes:** Phase 1 step 5 of master plan.

---

## Bite β: Rename `BeatRequest.Gossip` → `AppData`

**Repo:** tdns-transport (struct field rename) + tdns-mp
(callers).

**Cost:** ~30 minutes.

**Why this is safe now:** The field is JSON-tagged
`json:"gossip,omitempty"`. Renaming the Go field while
preserving the JSON tag is wire-compatible. Phase 2 of
the master plan calls for `BeatRequest` to expose
opaque application data rather than a transport-aware
"gossip" payload. This is the prep step that makes
Phase 2's larger generic-payload work possible without
a wire change.

**The change:**

1. In `tdns-transport/v2/transport/types.go` (or
   wherever `BeatRequest` is defined), rename the field
   `Gossip json.RawMessage` →
   `AppData json.RawMessage`. **Keep the JSON tag as
   `json:"gossip,omitempty"` for wire compatibility.**
2. Update the ~3 MP call sites in
   `tdns-mp/v2/hsync_transport.go` (the callers that
   marshal gossip into `BeatRequest.Gossip`).
3. Update any test scaffolding that references the old
   name.

**Success criteria:**
- Field renamed.
- JSON tag unchanged (verify via a roundtrip test if
  any exists, or inspect with `go doc`).
- `TestTransportBoundary_BeatExchange` (scenario 3 if
  numbered that way; whichever exercises beats) passes.

**Risk:** Very low. Pure rename. Wire-compatible. The
compiler catches every read site.

**Closes:** Phase 2 preparatory work.

**Note:** Once Phase 2 proper lands, the JSON tag can
also be renamed (with a wire migration). Bite β is the
Go-level rename only; wire stays gossip-tagged.

---

## Bite γ: Group A read-site migration

**Repo:** tdns-mp.

**Cost:** ~2 hours.

**Why this is safe now:** Bite A's audit identified
five fields in **Group A** as having only zero-read or
dual-write call sites — meaning their reads can be
replaced mechanically with per-mechanism accessors. The
audit table provides the exact replacement expression
for every site.

The five fields in Group A:
- `Peer.State` → `peer.EffectiveState()`
- `Peer.StateReason` (no replacement; drop the read
  sites that surface it; they're diagnostic only)
- `Peer.StateChanged` (same as StateReason)
- `Peer.LastHelloSent` →
  `peer.Mechanisms[mech].LastHelloSent` (where `mech`
  is determined by call context; in send-path code it's
  the mechanism the send was attempted on)
- `Peer.LastBeatReceived` →
  `peer.Mechanisms[mech].LastBeatRecv`

**The change:**

1. Open `2026-04-30-peerregistry-field-disposition.md`
   to the Group A table.
2. For each of ~20 read sites in `tdns-mp/v2/`, replace
   the field read with the per-mechanism accessor.
   Mostly mechanical sed/replace; a handful of sites
   where the mechanism context is non-obvious will need
   a 1-line lookup.
3. Do **NOT** delete the fields themselves yet — that
   is Phase 1 step 6 proper, after Group B and Group C
   are also migrated. This bite makes Group A's
   eventual deletion mechanical (zero read sites
   remain).
4. After this bite, the only callers of the Group A
   fields will be the registry's own dual-write
   plumbing, which deletes cleanly with the field.

**Success criteria:**
- All Group A field reads replaced per the audit
  table.
- No build break.
- All seven integration scenarios pass.
- The fields themselves remain in the struct (deletion
  is Phase 1.6).

**Risk:** Low. Audit table is authoritative; if a site
was missed, it surfaces as either a stale read (caught
by tests) or, more likely, gets caught when the field
is actually deleted in Phase 1.6.

**Closes:** Phase 1 step 6 prep — the deletion bite
becomes a one-liner per field.

---

## Bite δ: Hello/Beat parallel-send semantics

**Repo:** tdns-mp.

**Cost:** ~5 hours.

**Why this is safe now:** The integration test harness
covers Hello and Beat exchange (scenarios 1, 3,
possibly 6). Bite H's split of `SyncPeerFromAgent`
removed the redundant per-send full-state-refresh that
would have made parallel sends costly. The Group A
migration (Bite γ) ensures per-mechanism state is the
authoritative source for "last sent on mech X" — which
is exactly what parallel-send needs to record.

**The change:**

Today, `SendHelloWithFallback` and
`SendBeatWithFallback` try API first, then fall back to
DNS on failure. Phase 5 of the master plan calls for
**both transports being attempted in parallel**, with
success on either counted as success.

1. Refactor `SendHelloWithFallback` in
   `tdns-mp/v2/hsync_transport.go`:
   - Spawn one goroutine per available mechanism
     (typically two: API and DNS).
   - Each goroutine attempts its mechanism's send and
     records per-mechanism state on success or failure.
   - A `sync.WaitGroup` or `chan` collects results.
   - The function returns success if any mechanism
     succeeded; aggregates failure detail if all
     failed.
2. Same refactor for `SendBeatWithFallback`.
3. Rename both functions to drop "WithFallback" — they
   no longer fall back; they parallelize. Suggested
   names: `SendHelloAllMechanisms`,
   `SendBeatAllMechanisms`. Adjust call sites.
4. Verify no caller depends on the old "API-preferred,
   DNS-fallback" ordering for any side effect (e.g.
   logging, peer state updates). All such side effects
   should be expressed in per-mechanism state already
   after Bite γ.

**Success criteria:**
- Both functions send on every available mechanism.
- A failure on one mechanism does not block success on
  another.
- Per-mechanism send timestamps update correctly
  (verify in scenario 3's beat-exchange assertions).
- All seven integration scenarios pass.

**Risk:** Medium. Goroutine + channel logic must be
race-free (especially around peer-state updates).
Existing scenarios are the regression net; consider
adding a scenario specifically for "API fails, DNS
succeeds" and the inverse to confirm parallel
semantics.

**Closes:** Phase 5 completion.

**Caveat:** Beware of message duplication on the
receiver. If both API and DNS Hello/Beat arrive
"simultaneously" at the peer, the peer's handler must
be idempotent. Verify by inspecting the
`HandleHello`/`HandleBeat` code paths — they likely
already are (they update per-sender state, not
cumulative counters), but worth a explicit check before
landing.

---

## Bite ε: Move discovery loop into transport

**Repo:** tdns-mp + tdns-transport.

**Cost:** ~1.5 days.

**Why this is safe now:** Bite F installed the
temporary `DiscoveryDriver` interface as the inversion
point. Bite F's comment explicitly marks the interface
as temporary: "Phase 6 part 2 of the transport
interface redesign moves discovery into the transport
package and removes both the DiscoveryDriver interface
and this implementation." This bite is exactly that
work.

**The change:**

1. Identify what discovery does in MP today:
   - `attemptDiscovery` loop in
     `tdns-mp/v2/agent_utils.go` — IMR-based identity →
     agent lookup, retry/backoff, DANE validation, key
     verification.
   - On success: invoke `OnPeerDiscovered(peer *Peer)`.
   - On failure: invoke `OnDiscoveryFailed(peer *Peer,
     err error)`.
2. Move the loop into transport:
   - New file `tdns-transport/v2/transport/discovery.go`.
   - `TransportManager` owns the loop and the retry
     state.
   - Identity → agent resolution uses
     `transport.Imr` (already in transport per Bite 6).
   - DANE/key verification uses transport-side helpers
     (already exist for SIG(0) etc.).
3. MP-specific post-processing (set preferred
   mechanism, wire the hello sender, etc.) stays in MP
   via the `OnPeerDiscovered` callback. The callback
   contract is already documented (Bite E).
4. Delete `MPTransportBridge.RunDiscovery` from
   `tdns-mp/v2/hsync_transport.go`.
5. Delete the `DiscoveryDriver` interface from
   `tdns-transport/v2/transport/manager.go`.
6. Delete `attemptDiscovery` and the
   `fireOnDiscoveryFailed` helper from
   `tdns-mp/v2/agent_utils.go`.
7. `tm.DiscoverPeer(identity)` (Bite F's API) now
   delegates to the transport-side loop directly.

**Success criteria:**
- Discovery loop runs from inside transport.
- MP-side post-processing happens via
  `OnPeerDiscovered`.
- `DiscoveryDriver` interface deleted.
- `MPTransportBridge.RunDiscovery` deleted.
- All seven integration scenarios pass; scenario 7
  (discovery-completion) and scenarios 1, 2 (which
  trigger discovery as a precondition) are the
  regression gate.

**Risk:** Medium-high. Discovery touches DANE
validation, key verification, IMR retries, and several
state machines. The integration harness is the main
gate; consider running each scenario individually with
verbose logging during the bite to verify state
transitions match pre-refactor behavior.

**Closes:** Phase 6 part 2 completion. Removes the
temporary `DiscoveryDriver` scaffold.

**Sequencing note:** Should land *after* Bite α
(ZoneRelation/SharedZones removal) so transport's
`Peer` is fully stripped of MP concepts before the
discovery loop becomes transport-internal.

---

## Bite ζ: Extract `MPMessageDispatcher`

**Repo:** tdns-mp.

**Cost:** ~1 day.

**Why this is safe now:** The `route*Message` family
in `tdns-mp/v2/hsync_transport.go` is one large method
collection (~12 methods, ~300 lines combined) that
collectively implements MP-specific message-type
routing. Phase 3 of the master plan calls for these to
become a registered handler chain on
`TransportManager`. Extracting them into their own
struct first is the prep step.

**The change:**

1. New file `tdns-mp/v2/mp_message_dispatcher.go`:
   ```go
   type MPMessageDispatcher struct {
       tm  *transport.TransportManager
       reg *MPRegistry  // or whatever wraps the MP-side state
   }

   func (d *MPMessageDispatcher) Dispatch(
       ctx context.Context,
       msgType string,
       sender *Peer,
       payload json.RawMessage,
   ) error {
       switch msgType {
       case "hello":
           return d.routeHelloMessage(ctx, sender, payload)
       case "beat":
           return d.routeBeatMessage(ctx, sender, payload)
       // ... 10 more cases
       }
   }
   ```
2. Move all 12 `route*Message` methods from
   `hsync_transport.go` into the dispatcher struct.
   No logic changes; pure relocation.
3. In `NewMPTransportBridge`, instantiate the
   dispatcher and register it with the transport
   manager (the registration mechanism is Phase 3
   proper — for this bite, just hold the dispatcher on
   the bridge and call its `Dispatch` from the existing
   handler-callback site).
4. Remove the methods from `hsync_transport.go`.

**Success criteria:**
- All 12 methods relocated.
- One `Dispatch` entry point on the dispatcher struct.
- `hsync_transport.go` shrinks by ~300 lines.
- Behavior unchanged: scenarios 1–5 (which exercise
  every message type) pass.

**Risk:** Medium. Large code movement (~300 lines).
Pure relocation, but easy to break by losing a method
or mistyping a case in the switch. Integration harness
is the gate.

**Closes:** Phase 3 entry. Once the dispatcher is its
own type, registering it with `TransportManager` (the
actual Phase 3 work) becomes a small follow-up bite.

---

## Notes on what's NOT in this set

The following are deliberately deferred to dedicated
sessions, not bites:

- **Phase 1 step 6 deletion** — once Bites α, γ, and
  the Group B/C migrations are done, the actual field
  deletion is mechanical, but it touches the Peer
  struct directly and benefits from being its own
  reviewed change.
- **Phase 2 generic-payload `SyncRequest`/`SyncResponse`
  redesign** — large enough that it needs its own
  design doc and probably its own branch.
- **Phase 4 chunk_notify_handler extraction** — Bite B
  specified the cut line; the extraction itself is a
  multi-file refactor that benefits from a dedicated
  session.
- **Bite A Group B helper additions** — the
  `EffectiveState` etc. wrappers exist already; what's
  missing is the audit-table-prescribed direct field
  replacement on the Peer struct. This can be folded
  into Phase 1 step 6 deletion when it lands.
- **Bite A Group C precursor migrations** — the
  `APIEndpoint` / `OperationalAddr` / Beat-trio fields
  need their own per-mechanism shape designed first.
  Out of scope for this set.

---

## Summary table

| Bite | Hours | Risk | Repo | Phase Impact |
|------|-------|------|------|--------------|
| α | 1 | Very Low | transport | Phase 1.5 |
| β | 0.5 | Very Low | transport + mp | Phase 2 prep |
| γ | 2 | Low | mp | Phase 1.6 prep |
| δ | 5 | Medium | mp | Phase 5 done |
| ε | 12 | Med-High | transport + mp | Phase 6.2 done |
| ζ | 8 | Medium | mp | Phase 3 entry |
| **Total** | **~28.5** | | | |

After this bite set lands, the master plan progress
should look like:

- Phase 0: ✓ Done
- Phase 1: ~95% (only Group B/C migrations and step 6
  deletion remain, both mechanical)
- Phase 2: prep done, generic-payload redesign still
  open
- Phase 3: entered (dispatcher extracted)
- Phase 4: cut line specified, extraction open
- Phase 5: ✓ Done (after Bite δ)
- Phase 6: ✓ Done (after Bite ε)
- Phase 7: substantially advanced (Bite H delivered the
  split; final cleanup awaits)

That leaves Phases 2, 4, and 7-cleanup as the only
remaining substantive work — each large enough to
warrant its own design doc, but the foundations to
attempt them will all be in place.
