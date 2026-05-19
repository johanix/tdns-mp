# Transport Interface Redesign:
# Next Bites — Post-Semi-Easy-Bites Quick Wins

Date: 2026-05-08
Status: PLAN — recommended pre-work to land **after** the
        semi-easy bites complete and **before** initiating
        the larger main-plan phases (2/3/4 + remaining
        chunks of 5/6/7).

Companion to:
[2026-04-15-transport-interface-redesign.md](./2026-04-15-transport-interface-redesign.md)
[2026-04-25-transport-refactor-early-bites.md](./2026-04-25-transport-refactor-early-bites.md)
[2026-04-30-transport-refactor-semi-easy-bites.md](./2026-04-30-transport-refactor-semi-easy-bites.md)
[2026-04-23-transport-boundary-test-harness.md](./2026-04-23-transport-boundary-test-harness.md)

## Purpose

The 2026-04-25 early-bites set landed nine items, including
the transport-boundary test harness. The 2026-04-30
semi-easy bites (I, C, E, A, B, D, F, G, H) close two of the
remaining open items and partially complete Phases 1, 5, 6,
and 7 of the parent plan.

After both tiers are merged, the residue per the parent
plan's *Cumulative effect* section is:

- **Phase 1**: step 5 (`ZoneRelation`/`SharedZones` removal)
  and step 6 (delete dual-written single-state fields on
  `Peer`) — the latter has a per-field deletion playbook
  from semi-easy Bite A.
- **Phase 2**: not started; the type migration map
  (Appendix H) is written.
- **Phase 3**: not started.
- **Phase 4**: cut line written by semi-easy Bite B; no
  extraction yet.
- **Phase 5**: step 3 (lifecycle move into TM startup),
  step 4 (transport-level liveness middleware), and the
  Hello/Beat parallel-send semantics still TODO.
- **Phase 6 part 2**: discovery-body move still TODO; step 7
  (deduplicate `tdnsmp.Imr` against `transport.Imr`) is
  small and mechanical.
- **Phase 7**: substeps 4–8 still TODO. Several
  ([§D-K table rows 29–48](./2026-04-15-transport-interface-redesign.md#mptransportbridge-disposition-table))
  are isolated extractions that fit the bite shape.
- **Open items**: **N** (per-phase rollback criteria) and
  **O** (6-method delta walkthrough) remain.

This document collects the **next-tier bites** — the items
in that residue that are still bite-shaped: additive,
wire-compatible, ≤1 working day, single-PR revertible,
all three repos building at every step.

The genuinely large remaining chunks — Phase 2 type
migration (~141 → 121 fields across 13 payload types),
Phase 3 handler/router cleanup, Phase 4 chunk handler
split, Phase 5 parallel-send semantics, Phase 6 part 2
discovery body, Phase 7 final bridge deletion — are **not**
in this set. Each is properly a phase, not a bite.

**Total cost estimate:** roughly 5–7 working days for the
full set, dominated by Bites N6, N7, N9 (the
sub-tracker / middleware items that touch state-coupling
code paths).

**Strong recommendation:** complete the doc bites
(N1, N2) before starting any main-plan phase. The
deletion bite (N3) closes Phase 1 step 6 and is the next
natural step after semi-easy Bite A's audit lands. The
extraction bites (N6, N7, N8) shrink Phase 7's load
substantially without committing to bridge deletion.

## Bite ordering

Bites are numbered N1–N10. Recommended execution order is
**N1 → N2 → N3 → N5 → N4 → N9 → N6 → N7 → N8 → (optional N10)**:
hygiene first, then the unblocked deletion, then
mechanical lifecycle moves, then liveness middleware,
then sub-tracker extractions, then the optional wire-format
gateway bite.

| # | Bite | Repo | Cost | Unlocks |
|---|---|---|---|---|
| N1 | Per-phase rollback criteria | doc only | half day | open item N |
| N2 | 6-method disposition-table walkthrough | doc only | half day | open item O; pre-Phase-1 |
| N3 | Delete dual-written single-state fields on `Peer` | tdns-mp + tdns-transport | 1 day | Phase 1 step 6 |
| N4 | Migrate MP callers to `*transport.Imr`; dedup helpers | tdns-mp | half day | Phase 6 part 2 step 7 |
| N5 | Move `RegisterChunkNotifyHandler` + `StartIncomingMessageRouter` into TM startup | tdns-mp + tdns-transport | half day | Phase 5 step 3 |
| N6 | Extract `DnskeyPropagationTracker` | tdns-mp | 1 day | Phase 7 step 5 |
| N7 | Extract `RFITracker` | tdns-mp | 1 day | Phase 7 step 6 |
| N8 | Move enqueue helpers onto `SynchedDataEngine` | tdns-mp | half day | Phase 7 step 7 |
| N9 | Transport-level liveness middleware on hello/beat | tdns-mp + tdns-transport | 1 day | Phase 5 step 4 |
| N10 | (Optional) Rename `BeatRequest.Gossip` → `AppData` | tdns-mp + tdns-transport | half day | Phase 2 step 4; first wire break |

Total committed (N1–N9): ~6.5 days. N10 is optional and is
flagged separately because it is the **first deliberate
wire break**; the previous two tiers are uniformly
wire-compatible, so N10 changes the safety profile.

---

## Bite N1: Per-phase rollback criteria (doc only)

**Source:** Closes parent-plan open item **N**.

### What

For a 9-phase refactor across three repos, no phase has
explicit "if X breaks, revert and reconsider" criteria.
This bite produces them.

For each of Phases 1–9, document:

1. **Pre-flight check.** What must be green before the
   phase starts (build status, harness scenarios passing,
   dependent bites landed).
2. **Mid-phase abort gate.** A specific failure signature
   that means "stop, revert what's landed, reassess" rather
   than "push through". Examples: harness scenario X red
   for >1 commit, > Y% wire-format test failures, MP
   binary regressions in basic operation.
3. **Post-phase confirmation.** What must hold for the
   phase to be considered complete (harness state,
   binary smoke tests, follow-up cleanup tasks logged).

### Concrete steps

1. Create `tdns-mp/docs/2026-05-08-transport-refactor-rollback-criteria.md`.
2. For each phase, three bullets per the structure above.
3. Identify which bites are pure-additive (no rollback
   gate needed beyond build) vs state-coupling (gate
   needed). Mark accordingly.
4. Cross-link from the parent plan's open-items list.

### Do NOT

- Make code changes.
- Re-litigate the phase definitions. The structure is the
  parent plan's.

### Files touched

- New: `tdns-mp/docs/2026-05-08-transport-refactor-rollback-criteria.md`

### Why it's safe

Pure documentation.

### Value delivered

Closes parent-plan open item **N**. Subsequent phase
landings have explicit go/no-go criteria rather than
"feels OK to push on".

### Estimated cost

Half a day.

### Dependencies

None.

---

## Bite N2: 6-method disposition-table walkthrough (doc only)

**Source:** Closes parent-plan open item **O**.

### What

`hsync_transport.go` grew from 48 to 54 methods/functions
since the disposition table was written. Six methods are
not yet placed in the table. This bite walks the current
file and assigns a destination + phase to each new method.
Spot-check that the existing 48 entries' phase
dependencies (Phase 1 → 3 → 5 → 7 chain) are still
correct after the early/semi-easy work.

### Concrete steps

1. Run:
   ```bash
   grep -nE "^func (\([^)]*\) )?[A-Za-z_]+\(" tdns-mp/v2/hsync_transport.go
   ```
   to list all method/function declarations.
2. Diff against the 48-row table in the parent plan
   §"MPTransportBridge Disposition Table". Identify the
   ~6 new entries.
3. For each new entry, assign:
   - Destination (TM, MP struct name, or DELETED)
   - Phase (1, 3, 5, 7)
   - Brief rationale (one sentence)
4. Spot-check: any prior entries whose semantics changed
   under early/semi-easy bites? Annotate.
5. Patch the parent plan's table inline (this is the one
   doc edit that *isn't* a separate file — the table
   should always reflect current state).

### Do NOT

- Move methods. This is a doc bite.
- Re-decompose Phase 7's substeps. They were re-split in
  2026-04-16 and remain accurate.

### Files touched

- `tdns-mp/docs/2026-04-15-transport-interface-redesign.md`
  (table entries + count update)

### Why it's safe

Pure documentation.

### Value delivered

Closes parent-plan open item **O**. The disposition table
is the source of truth for Phases 5 and 7; it must reflect
reality before they begin.

### Estimated cost

Half a day, dominated by careful reading of
`hsync_transport.go` against the table.

### Dependencies

- Semi-easy Bite C (drops `OnAgentDiscoveryComplete`) —
  recommended; the table will be off-by-one if C is
  ahead and the walkthrough is behind.

---

## Bite N3: Delete dual-written single-state fields on `Peer`

**Source:** Phase 1 step 6 of the parent plan. Executes
the deletion that semi-easy Bite A's per-field disposition
map prepared.

### What

After Bites 1 + 7, `Peer.Mechanisms` is the canonical
per-mechanism state. The original single-state fields on
`Peer` are duplicates maintained by dual-write at every
receipt site. Bite A audited each duplicate field and
mapped read sites to their `Mechanisms`-based replacement
expressions. This bite executes the audit:

1. Delete the duplicate fields from the `Peer` struct.
2. Delete the dual-write at every receipt site.
3. Migrate every read site to the replacement expression
   from Bite A's table.

The fields in scope are exactly those listed in semi-easy
Bite A's "Fields to audit" section:

`State`, `StateReason`, `StateChanged`, `DiscoveryAddr`,
`OperationalAddr`, `APIEndpoint`, `LastHelloSent`,
`LastHelloReceived`, `LastBeatSent`, `LastBeatReceived`,
`BeatSequence`, `ConsecutiveFails`, `Stats`,
`PreferredTransport`.

`SharedZones`, `ZoneRelation`, `Capabilities`,
`LongTermPubKey`, `KeyType`, `TLSARecord`, `ID`,
`DisplayName` stay (different concerns; Phase 1 step 5 and
Phase 7 territory).

### Concrete steps

1. Open the disposition map produced by semi-easy Bite A
   (`tdns-mp/docs/2026-04-30-peerregistry-field-disposition.md`).
2. For each field, in the order listed in the map's
   "Deletion phase" section:
   1. Delete the dual-write at every receipt site
      identified by Bite A.
   2. Migrate every read site to the replacement
      expression from the table.
   3. Remove the field from the `Peer` struct in
      `tdns-transport/v2/transport/peer.go`.
   4. Re-run the integration harness (all 7 scenarios
      must pass).
3. After every field is gone, search for any stragglers:
   ```bash
   grep -rnE "peer\.(State|StateReason|...|PreferredTransport)\b" \
       tdns-mp/v2/ tdns-transport/v2/
   ```
4. Build all four mp binaries.

### Do NOT

- Skip a field's harness re-run. Per-field iteration is
  cheaper than debugging a multi-field regression.
- Touch `EffectiveState()`, `HasMechanism()`,
  `PreferredMechanism()`, or `SetMechanismState()`. They
  read `Mechanisms` and are the canonical replacements.
- Delete `SyncPeerFromAgent`. Phase 7 territory.
- Touch fields outside the audited set (zone/identity/
  crypto). Different concerns.

### Files touched

- `tdns-transport/v2/transport/peer.go` (struct surgery)
- Receipt sites identified by Bite A in
  `tdns-mp/v2/hsync_transport.go`,
  `combiner_msg_handler.go`, `signer_msg_handler.go`
- Read sites identified by Bite A — likely scattered
  across `hsync_transport.go`, `agent_utils.go`,
  `apihandler_*.go`, and a handful of routing files

### Why it's safe

Bite A's audit confirmed every replacement expression in
advance. The harness scenarios cover the hot read paths
(state queries, address lookups, liveness fields). Any
field whose replacement is non-trivial was flagged in
Bite A's "Deletion phase" tail and is handled there.

### Value delivered

- Closes Phase 1 step 6 fully.
- Eliminates the dual-write code paths (~3 receipt sites
  × ~14 fields = ~40 lines of mechanical mutation per
  hello/beat receipt).
- `Peer` struct shrinks by 14 fields; `MechanismState`
  becomes the only place per-mechanism state lives.
- The dual-write footnote in
  [Phase 1 step 6](./2026-04-15-transport-interface-redesign.md)
  becomes a closed deletion.

### Estimated cost

1 day. Most of the cost is the per-field harness
iteration. If Bite A's "Deletion phase" section grouped
fields into joint-deletable bundles, this can be shorter.

### Dependencies

- **Semi-easy Bite A** (per-field disposition map) — required.
- **Early Bite 1** (`Mechanisms` map + dual-write) — done.
- **Early Bite 7** (`PopulateFromAgent` populating
  per-mechanism `Address`) — done.
- **Early Bite 2** (test harness) — required as the
  regression net.

---

## Bite N4: Migrate MP callers to `*transport.Imr`

**Source:** Phase 6 part 2 step 7 of the parent plan
(deduplicate `tdnsmp.Imr` against `transport.Imr`).

### What

Early Bite 6 created the parallel embedding: both
`tdnsmp.Imr` (in `tdns-mp/v2/imr.go`) and `transport.Imr`
(in `tdns-transport/v2/transport/imr.go`) wrap the same
singleton `*tdns.Imr` and carry the same six lookup-helper
methods (`LookupAgentJWK`, `LookupAgentKEY`,
`LookupAgentAPIEndpoint`, `LookupAgentDNSEndpoint`,
`LookupAgentTLSA`, `LookupServiceAddresses`).

This bite migrates MP's callers of those helpers from
`tdnsmp.Imr` to `*transport.Imr`, then deletes the
duplicate methods from `tdnsmp.Imr` (the wrapper struct
itself stays — non-discovery users still depend on it).

### Concrete steps

1. Grep for callers of each helper in tdns-mp:
   ```bash
   for fn in LookupAgentJWK LookupAgentKEY LookupAgentAPIEndpoint \
             LookupAgentDNSEndpoint LookupAgentTLSA LookupServiceAddresses; do
       echo "=== $fn ==="
       grep -rn "\.${fn}(" tdns-mp/v2/
   done
   ```
2. For each caller, retrieve the shared `*transport.Imr`
   from the transport manager (or wherever it is wired)
   and call the helper through it.
3. Once all callers are migrated, delete the six methods
   from `tdns-mp/v2/agent_discovery_common.go` (Bite 6
   left them in place as parallel copies).
4. Build all four mp binaries.
5. Run the integration harness.

### Do NOT

- Delete the `tdnsmp.Imr` *struct*. Non-discovery callers
  in `delegation_sync.go`, `apihandler_agent.go`,
  `main_init.go` (per Bite 6's note) still use it for
  unrelated lookups.
- Touch `transport.Imr`'s methods. They are the
  destination, unchanged.
- Move `DiscoverAndRegisterAgent`, `attemptDiscovery`, or
  `DiscoveryRetrierNG`. Those are the discovery-body
  move (Phase 6 part 2 proper) — bigger than a bite.

### Files touched

- `tdns-mp/v2/agent_discovery_common.go` (delete six
  duplicated methods, ~297 lines)
- ~5–10 caller migrations across tdns-mp

### Why it's safe

The two embeds wrap the same singleton (Bite 0's
idempotency guard). Calling through `*transport.Imr` vs
`*tdnsmp.Imr` is byte-equivalent at runtime. Wire format
unchanged.

### Value delivered

- Closes Phase 6 part 2 step 7.
- Removes ~297 lines of duplicated code.
- The transport package's lookup helpers become the only
  copy; consistent surface for non-MP applications.

### Estimated cost

Half a day, dominated by call-site migration.

### Dependencies

- **Early Bites 0, 6** — done.

---

## Bite N5: Move lifecycle wiring into TM startup

**Source:** Phase 5 step 3 of the parent plan.

### What

`MPTransportBridge.RegisterChunkNotifyHandler` (#12) and
`MPTransportBridge.StartIncomingMessageRouter` (#13) per
the disposition table are pure transport lifecycle —
neither has MP-specific dependencies beyond the components
that already live in `TransportManager`. Move them into
`TransportManager.Start` (or equivalent startup path) and
delete the wrappers.

### Concrete steps

1. Read the bodies of `RegisterChunkNotifyHandler` and
   `StartIncomingMessageRouter` in
   `tdns-mp/v2/hsync_transport.go`.
2. Confirm zero MP-specific dependencies (the disposition
   table marks them "TM startup (private)" and predicts
   no MP coupling). If there is any, leave a callback
   seam at the boundary — same pattern as Bite 8's
   `OnPeerDiscovered`.
3. Add the relevant calls into `TransportManager.Start`
   in `tdns-transport/v2/transport/manager.go`.
4. Delete the two methods from `MPTransportBridge`.
5. Update MP startup (the file currently calling these
   methods on the bridge) to drop the calls — TM does it
   now.
6. Build all four mp binaries.
7. Run the integration harness — scenarios 1, 5 are most
   likely to surface a lifecycle ordering regression.

### Do NOT

- Touch `isTransportSupported` (#1) or `SelectTransport`
  (#2) — Bite 3 already moved selection into TM
  internally; the wrappers can disappear in Phase 5
  proper, not here.
- Move `StartReliableQueue` (#40) — bigger scope; involves
  the RMQ's `sendFunc` becoming generic per Disposition
  Item 4. Phase 5 territory.

### Files touched

- `tdns-transport/v2/transport/manager.go` (additions in
  `Start` body)
- `tdns-mp/v2/hsync_transport.go` (two method
  deletions)
- One or two MP startup files (drop the explicit calls)

### Why it's safe

Same code runs in the same order; only the dispatch
location changes. Wire format unchanged. Phase 5's
"lifecycle into TM" is a documented destination.

### Value delivered

- Phase 5 step 3 satisfied.
- Two more methods retired from `MPTransportBridge`.
- TM's `Start` becomes self-contained: callers do not
  have to remember to call extra registration methods.

### Estimated cost

Half a day.

### Dependencies

- **Early Bite 2** (test harness) — required.

---

## Bite N6: Extract `DnskeyPropagationTracker`

**Source:** Phase 7 step 5 of the parent plan;
disposition-table rows 29–31.

### What

Three methods on `MPTransportBridge` form a tight unit:

- `TrackDnskeyPropagation` (#29)
- `ProcessDnskeyConfirmation` (#30)
- `sendKeystateToSigner` (#31)

They share state (DNSKEY-specific fan-in accounting,
agent-confirmation tracking) and a single trigger
(receiving a confirmation, then deciding whether all
agents have confirmed and signaling KEYSTATE to the
signer).

This bite extracts them into a new struct
`DnskeyPropagationTracker` in tdns-mp, owned by
`SynchedDataEngine` per Disposition Item 2. Wire it as a
confirmation observer of TM (the
`OnConfirmationReceived(callback)` pattern from
Disposition Item 4 — already on TM today, per the parent
plan's notes).

### Concrete steps

1. Identify the state currently sitting on
   `MPTransportBridge` that the three methods read/write
   (likely a per-zone or per-distribution map). It moves
   onto the new struct.
2. Create `tdns-mp/v2/dnskey_propagation_tracker.go`:
   ```go
   type DnskeyPropagationTracker struct {
       tm     *transport.TransportManager
       sde    *SynchedDataEngine
       state  /* whatever map(s) MPTransportBridge held */
   }

   func NewDnskeyPropagationTracker(...) *DnskeyPropagationTracker

   func (t *DnskeyPropagationTracker) Track(...)            // was #29
   func (t *DnskeyPropagationTracker) OnConfirmation(...)   // was #30
   func (t *DnskeyPropagationTracker) sendKeystateToSigner(...) // was #31
   ```
3. Wire `OnConfirmation` as a TM confirmation observer at
   MP startup.
4. Migrate callers of `TrackDnskeyPropagation` to call the
   new struct's `Track` (likely 1–2 sites).
5. Delete the three methods from `MPTransportBridge`.
6. Build; run harness.

### Do NOT

- Confuse this with `KeystateRequest`/`KeystateResponse`
  (parent plan §A2 / Phase 2). Those types stay where they
  are until Phase 2 moves them out of transport. This bite
  is purely about restructuring MP-side methods.
- Inline `sendKeystateToSigner`'s body. Keep it as a
  method; the body should now use `tm.Send` (the generic
  send from Bite 3).

### Files touched

- New: `tdns-mp/v2/dnskey_propagation_tracker.go` (~150
  lines)
- `tdns-mp/v2/hsync_transport.go` (three method deletions
  + state field migration)
- Caller sites of `TrackDnskeyPropagation` in MP

### Why it's safe

The three methods already share state and trigger. Moving
them into a struct with that shared state externalized is
the canonical Go refactor. The TM `OnConfirmationReceived`
seam is the documented integration point. Wire format
unchanged.

### Value delivered

- Three methods retired from `MPTransportBridge`.
- DNSKEY-specific accounting becomes self-contained
  (testable in isolation).
- Phase 7 step 5 done.

### Estimated cost

1 day. Most of the cost is identifying the precise state
boundary (which fields move, which stay) and writing the
construction wiring at MP startup.

### Dependencies

- **Early Bite 3** (`tm.Send`) — done; `sendKeystateToSigner`
  uses it.
- **Early Bite 2** (test harness) — strongly recommended;
  state-coupling refactor.
- TM's `OnConfirmationReceived` callback existing.
  Confirm during execution; if it does not, install it
  first (small additive bite).

---

## Bite N7: Extract `RFITracker`

**Source:** Phase 7 step 6 of the parent plan;
disposition-table rows 32–33.

### What

Symmetric to Bite N6 but for RFI request-response:

- `set/get/deleteKeystateRfi` family (#32)
- `sendRfiToSigner` (#33)

Per Disposition Item 3, the new struct is generalized
across all four RFI subtypes (KEYSTATE, EDITS, CONFIG,
AUDIT). One struct, one keyed map.

### Concrete steps

1. Find the existing keystate-RFI state map on
   `MPTransportBridge` (#32 implies a map keyed by
   request ID or similar).
2. Create `tdns-mp/v2/rfi_tracker.go`:
   ```go
   type RFITracker struct {
       requests map[string]*RFIRequest  // keyed by
                                        // request ID;
                                        // subtype is a
                                        // field on the
                                        // value
       /* synchronisation */
   }

   type RFISubtype int   // KEYSTATE | EDITS | CONFIG | AUDIT

   func (t *RFITracker) Set(id string, req *RFIRequest)
   func (t *RFITracker) Get(id string) (*RFIRequest, bool)
   func (t *RFITracker) Delete(id string)
   ```
3. Replace the keystate-only methods (#32) with calls to
   the generalized methods on `RFITracker`.
4. Move `sendRfiToSigner` (#33) onto `HsyncEngine` (per
   the disposition table). Body uses `tm.Send`.
5. If EDITS / CONFIG / AUDIT RFIs are *currently* tracked
   by separate structures, migrate those callers to
   `RFITracker` too. If not, leave the generalized struct
   ready for future use.
6. Delete the keystate-RFI methods (#32) and
   `sendRfiToSigner` (#33) from `MPTransportBridge`.
7. Build; run harness.

### Do NOT

- Define a separate map per subtype. Disposition Item 3
  is explicit: one map, subtype as a field.
- Inline `sendRfiToSigner` into the call sites. Method on
  `HsyncEngine` is the documented destination.

### Files touched

- New: `tdns-mp/v2/rfi_tracker.go`
- `tdns-mp/v2/hsync_transport.go` (delete #32, #33)
- `tdns-mp/v2/hsyncengine.go` (add `sendRfiToSigner`)
- Caller sites of #32 in MP

### Why it's safe

Same shape as Bite N6. State move + caller migration.
Wire format unchanged.

### Value delivered

- Disposition Item 3 satisfied.
- Phase 7 step 6 done.
- A unified RFI surface ready for future subtype additions
  without state-management churn.

### Estimated cost

1 day.

### Dependencies

- **Early Bite 3** (`tm.Send`) — done.
- **Early Bite 2** (test harness) — strongly recommended.

---

## Bite N8: Move enqueue helpers onto `SynchedDataEngine`

**Source:** Phase 7 step 7 of the parent plan;
disposition-table rows 42–44.

### What

Three enqueue helpers on `MPTransportBridge`:

- `EnqueueForCombiner` (#42)
- `EnqueueForZoneAgents` (#43)
- `EnqueueForSpecificAgent` (#44)

These are SDE concerns — they wrap calls into the reliable
message queue with MP routing logic (combiner vs zone vs
specific agent). They belong on
`SynchedDataEngine` per the disposition table.

### Concrete steps

1. Read each method's body. Identify dependencies (likely
   `AgentRegistry`, `tm.Send` or RMQ enqueue).
2. Add the three methods on `*SynchedDataEngine` in
   `tdns-mp/v2/synched_data_engine.go` (or the
   equivalent file). Bodies remain the same; receiver
   changes from `*MPTransportBridge` to
   `*SynchedDataEngine`.
3. Migrate the callers (likely 5–15 sites across SDE,
   apihandlers, hsyncengine). Compile-time enforces full
   coverage.
4. Delete the three methods from `MPTransportBridge`.
5. Build; run harness.

### Do NOT

- Change method signatures or bodies. Pure receiver swap.
- Touch `EnqueueForX`'s underlying RMQ wiring. Phase 5 /
  Disposition Item 4 territory.

### Files touched

- `tdns-mp/v2/synched_data_engine.go` (add three
  methods)
- `tdns-mp/v2/hsync_transport.go` (delete three methods)
- Caller sites across MP

### Why it's safe

Pure receiver swap. The bodies do not change. Compile-time
enforces full caller migration.

### Value delivered

- Three methods retired from `MPTransportBridge`.
- `SynchedDataEngine` becomes the documented home for SDE
  enqueue surface.
- Phase 7 step 7 done.

### Estimated cost

Half a day, mostly mechanical caller migration.

### Dependencies

- **Early Bite 2** (test harness) — recommended;
  state-touching code paths.

---

## Bite N9: Transport-level liveness middleware

**Source:** Phase 5 step 4 of the parent plan.

### What

Today, `combiner_msg_handler.go` and `signer_msg_handler.go`
manually update PeerRegistry liveness fields on hello/beat
receipt (the dual-write paths Bite 1 introduced and Bite N3
deletes the duplicate-side of). After N3, the only writes
remaining are the per-mechanism `MechanismState`
timestamps. This bite moves *those* writes from MP
handlers into transport-level middleware — TM updates
liveness automatically when it delivers a hello/beat.

### Concrete steps

1. Define a middleware interface in transport (likely
   already partly present via `MiddlewareFunc` in
   `dns_message_router.go`):
   ```go
   func livenessMiddleware(p *Peer, msgType MessageType, t time.Time)
   ```
   Or a dedicated callback hook on TM, e.g.
   `tm.OnHelloReceived(callback)` and
   `tm.OnBeatReceived(callback)` with a default that
   updates `p.Mechanisms[mech]` timestamps.
2. Register a default middleware/callback in TM that:
   - Looks up the `*Peer` from `PeerRegistry` by sender
     identity.
   - Updates `p.Mechanisms[mech].LastHelloRecv` /
     `LastBeatRecv` / `BeatSequence` /
     `ConsecutiveFails = 0`.
3. Delete the manual liveness updates from
   `combiner_msg_handler.go` and
   `signer_msg_handler.go` (and any other handler that
   still does this after N3).
4. Build; run harness — scenario 1 (CHUNK NOTIFY round
   trip) and scenario 2 (SYNC fallback) cover the
   liveness paths.

### Do NOT

- Move the application-level reactions (e.g. zone
  bookkeeping on hello receipt) into transport. Liveness
  only.
- Touch `route*Message` family — that's Phase 3.

### Files touched

- `tdns-transport/v2/transport/manager.go` (or a new
  middleware file) — middleware/hook + default
  registration
- `tdns-mp/v2/combiner_msg_handler.go` (delete liveness
  updates)
- `tdns-mp/v2/signer_msg_handler.go` (delete liveness
  updates)
- Possibly `tdns-mp/v2/agent_msg_handler.go` if the same
  pattern exists there

### Why it's safe

Same writes happen, in the same order, just moved into
TM where they belong. The harness asserts liveness fields
update post-receipt; that assertion exercises the new
path.

### Value delivered

- Phase 5 step 4 done.
- Combiner and signer handlers shed manual PeerRegistry
  manipulation — they are now strictly application-level.
- A non-MP application using transport gets liveness
  tracking for free.

### Estimated cost

1 day. Most of the cost is auditing the current MP-side
liveness updates and ensuring no app-level logic is
entangled with the transport-level updates.

### Dependencies

- **Bite N3** (single-state field deletion) — strongly
  recommended; doing N3 first means N9 only has to
  consider per-mechanism state, not dual-write.
- **Early Bite 2** (test harness) — required.

---

## Bite N10 (optional): Rename `BeatRequest.Gossip` → `AppData`

**Source:** Phase 2 step 4 of the parent plan;
Appendix H.4. **First deliberate wire break in the bite
sequence.**

### What

Per Appendix H.4, `BeatRequest.Gossip
json.RawMessage `json:"gossip,omitempty"`` becomes
`AppData json.RawMessage `json:"AppData,omitempty"``.
Wire break accepted because the deployed agent base is
nil. The same rename applies to
`DnsBeatPayload.Gossip` (the wire-format mirror in
`dns.go`).

This is the smallest, most isolated wire-break in the
plan. Landing it ahead of the rest of Phase 2 proves the
wire-break mechanics on a tight scope before doing all
of Appendix H's normalization.

### Why optional

The previous two tiers and Bites N1–N9 are uniformly
wire-compatible. N10 changes the safety profile:

- A running combiner with old wire format will not
  understand `AppData` and vice versa.
- The build is fine; the binaries are fine; only the
  protocol changes.

If the team prefers to keep the entire bite sequence
wire-compatible and bundle all wire breaks into Phase 2
proper, **defer N10** to that phase.

### Concrete steps (if executed)

1. In `tdns-transport/v2/transport/transport.go`:
   ```go
   // Before
   Gossip  json.RawMessage `json:"gossip,omitempty"`
   // After
   AppData json.RawMessage `json:"AppData,omitempty"`
   ```
2. In `tdns-transport/v2/transport/dns.go`,
   `DnsBeatPayload`:
   ```go
   // Before
   Gossip json.RawMessage `json:"Gossip,omitempty"`
   // After
   AppData json.RawMessage `json:"AppData,omitempty"`
   ```
3. Find every read/write of `.Gossip` on either type and
   rename to `.AppData`. Compile-time enforces full
   coverage.
4. MP code in `gossip.go`, `gossip_types.go`,
   `provider_groups.go`, and
   `hsync_transport.go`'s gossip assembly continues to
   marshal/unmarshal exactly the same JSON value into the
   field — only the field name and JSON key change.
5. Build all four mp binaries.
6. Run the integration harness. Scenarios that exercise
   beats (1, 2, 7) cover the wire path.
7. Coordinate deployment: any running agent must be
   restarted on the new build before it tries to
   exchange beats with another upgraded agent.

### Do NOT

- Land alongside other bites. This bite must be its own
  PR with the wire-break called out in the description.
- Change the field's semantics. `json.RawMessage`,
  opt-empty, opaque-to-transport — exactly as today.
- Apply other H.7 normalizations (legacy field drops,
  CamelCase tag flips). Those belong in Phase 2 proper
  where they can be reviewed as a single coherent
  migration.

### Files touched

- `tdns-transport/v2/transport/transport.go`
- `tdns-transport/v2/transport/dns.go`
- `tdns-mp/v2/hsync_transport.go` (gossip assembly read
  sites)
- `tdns-mp/v2/gossip.go`, `gossip_types.go`,
  `provider_groups.go` (depending on which references
  the field by name vs treats `RawMessage` as opaque)

### Why it's safe (modulo wire break)

Compile-time catches every renamed reference. The JSON
bytes inside the field are unchanged — MP marshals the
same gossip messages. Only the outer field name flips.
The deployed agent base is nil, so no production
incompatibility.

### Value delivered

- Phase 2's first wire break lands on a small scope,
  exercising the wire-break review and deployment
  mechanics before Appendix H's full normalization
  arrives.
- The transport surface no longer carries the MP-flavored
  field name `Gossip`. `AppData` is the documented Tier
  2 hook.

### Estimated cost

Half a day, including coordination on the wire-break
review.

### Dependencies

- None technically. The plan agreement to accept a wire
  break here is a non-technical prerequisite.

---

## Cumulative effect

After Bites N1–N9 (and optionally N10):

- **Phase 1** — COMPLETE. Step 5 (`ZoneRelation` /
  `SharedZones`) is the only remaining piece of Phase 1
  and is **not** a bite (it touches scope tracking, which
  is a parent-plan §A4 concern — properly Phase 2 / 3
  territory).
- **Phase 2** — kick-off bite landed (N10) if executed;
  otherwise unchanged.
- **Phase 5** — steps 3 (lifecycle), 4 (liveness
  middleware) done. Only the Hello/Beat
  parallel-send-with-MP-state-tracking pattern remains.
- **Phase 6 part 2** — step 7 (helper dedup) done. The
  discovery body move is the only remaining piece.
- **Phase 7** — substeps 5, 6, 7 done (sub-tracker
  extractions + enqueue migration). Substeps 4, 8
  (remaining `MPTransportBridge` cleanup + bridge
  deletion) plus the final `SyncPeerFromAgent` deletion
  are the remaining work.
- **Open items** — **N**, **O** closed.

`MPTransportBridge` shrinks by approximately 8 methods
(N5: 2; N6: 3; N7: 2; N8: 3; possibly N3 deletion
ripple effects) — from ~54 to ~46. Combined with the
shrinkage from semi-easy Bites C and G, the bridge is
visibly closer to its eventual deletion in Phase 7.

After this set, the only "big chunks" remaining are
those the parent plan and the semi-easy doc both
already named as full-phase work:

- Phase 1 step 5 (scope/zone tracking refactor)
- Phase 2 type migration (Appendix H normalization)
- Phase 3 handler / role-router cleanup
- Phase 4 chunk handler split
- Phase 5 Hello/Beat parallel-send semantics
- Phase 6 part 2 discovery body move
- Phase 7 final bridge deletion + AgentRegistry slimming

Each is properly a phase, not a bite.

## Risks and mitigations

**Risk:** N3's per-field deletion surfaces a Bite A
disposition entry that's wrong (read site whose
replacement expression is incorrect or whose semantics
differ subtly).
**Mitigation:** Per-field iteration with harness re-run
between fields. The harness's seven scenarios cover the
hot read paths; surfacing a wrong replacement is a sign
that Bite A's audit needed an entry it missed, not that
N3 should push through.

**Risk:** N6 / N7 surface state on `MPTransportBridge`
that crosses between DNSKEY-tracking and RFI-tracking
(e.g. a single map shared between the two). The
extractions assume independence.
**Mitigation:** Read step 1 of each bite carefully before
starting. If state is shared, define the boundary
explicitly: which fields move with the new struct, which
stay on the bridge as a temporary cross-reference.
Document the temporary cross-reference and remove it in
Phase 7 substep 8.

**Risk:** N9's middleware fires for a peer that doesn't
exist in `PeerRegistry` yet (e.g. hello from a discovered
peer arrives before the discovery callback completes
PeerRegistry insertion).
**Mitigation:** The middleware should no-op cleanly on
nil peer (log + return, no panic). Verify by exercising
scenario 7 in the harness.

**Risk:** N10's wire break is reviewed and merged but a
stale binary in someone's dev environment continues
running with the old field name, producing silent gossip
loss until restart.
**Mitigation:** Document the rebuild requirement in the
PR description and in the release notes. Beat assembly
in MP that fails to find the expected field should log a
loud warning, not silently drop.

**Risk:** The bite ordering N1 → ... → N9 is recommended,
but execution under time pressure picks a different
order and creates partial-state regressions.
**Mitigation:** N1 and N2 are pure doc bites; they can
land any time. N3 strictly depends on semi-easy Bite A.
N9 strictly benefits from N3 first. N4, N5, N6, N7, N8
are independent of each other and can land in any order.
N10 is independent and optional.

## What this doc does NOT change

- The 9-phase structure of the main plan.
- The target public API of transport.
- Any of the resolved Open Questions.
- Any earlier bite (early or semi-easy).
- Wire format, except the optional N10.

This doc adds a third tier of additive work that becomes
safe and useful given what the early and semi-easy bites
already landed (or will land). After this tier, the
remaining transport-redesign work consists of
named-and-scoped phases of the main plan, each with its
own pre-flight criteria from Bite N1.
