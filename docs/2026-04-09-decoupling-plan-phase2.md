# MP Decoupling — Phase 2 Analysis

**Date**: 2026-04-09
**Parent docs**:
- `2026-04-04-tdns-mp-decoupling-plan.md` (original inventory)
- `2026-04-04-implementation-plan.md` (Tasks A–O, all done)

**Purpose**: Audit of Phase 1 completion status (Tasks A–O)
and prioritized plan for the remaining open items.

---

## Guiding principle: no `AppTypeMP*` branching in tdns

tdns must not contain any code path that branches on
`AppTypeMPAgent`, `AppTypeMPSigner`, `AppTypeMPCombiner`,
or `AppTypeMPAuditor`. The constants exist as registered
enum values so external apps can identify themselves, but
tdns code must not inspect them.

Where gating is needed, use a **positive allow-list on
tdns's own app types** (`AppTypeAuth`, `AppTypeAgent`,
`AppTypeScanner`) — never a negative exclusion like
`!= AppTypeMPSigner`. The reason is that tdns should not
know or care about the details or capabilities of
non-tdns applications, only that they exist. A negative
check embeds exactly that unwanted knowledge.

This principle applies to every item in this plan. Any
time the fix text below says "gate on tdns's own types,"
that means a positive `case AppTypeAuth, AppTypeAgent:`
(or similar), not a `!=` check against MP types.

---

## Phase 1 completion audit

All 15 tasks in the implementation plan (A through O) are
**DONE** in the current code. The decoupling plan has been
updated in-place with `**Status:**` markers and file:line
evidence on every item.

### Items closed by Phase 1 tasks

| Item | Description | Closed by |
|------|-------------|-----------|
| 2 | MainInit KeyDB init gate | Task E |
| 4 | OptMultiProvider handler registration | Task C |
| 7 | StartAuth commented MP signer engines | Task A |
| 9 | DNSSEC policies init gate | Task F |
| 10 | ParseAuthOptions export | Task D |
| 11 | ParseConfig KeyDB init gate | Task E |
| 12a | ParseConfig DB file auto-create gate | Task E |
| 12b | OutgoingSerials → DefaultTables | Task H |
| 15 | MP KEY publication OnFirstLoad | removed in Phase 1 without a dedicated task |
| 19 | ValidateDatabaseFile internal gate | Task I |
| 20 | apirouters.go MP gate (keystore/truststore/…) | Task J |
| 21 | keys_cmd.go missing MP types | Task B |
| 28 | list-mp-zones → /zone/mplist | Task K |

### Items partially closed by Phase 1 tasks

| Item | Description | State |
|------|-------------|-------|
| 27 | /agent endpoint split | 4 of ~9 slices done (L, M, N, O: hsync, router, peer, gossip) |
| 26b | DelegationSyncher pluggable handler | 1 of ~3 subtasks done (`notifyPeersParentSyncDone` removed); core function still monolithic |

### Items still open

**Closed in Wave A (2026-04-09):** 5, 6, 13, 23.
**Closed in Wave B (2026-04-10):** 14, 14b, 16, 17, 18
(all sub-items 18a-e).
**Reclassified out of Phase 2:** 25 (moved to tdns-auth
key management revisit).

**Remaining open:** 1, 3, 8, 22, 24, 26, 26b (partial),
27 (partial), 29.

Items 1 and 8 were "Keep" / "No action" in the original
plan — no work needed. After Waves A+B, 7 items remain
in active Phase 2 scope (Waves C–F).

---

## Status of remaining open items

Each item below has verified file:line evidence from the
current code as of 2026-04-09.

**Tier 1 (Wave A) is complete as of 2026-04-09.** Items
5, 6, 13, and 23 are DONE in tdns commit 4c95c6a. Item
25 was investigated and reclassified — the original
description was incorrect and the actual file is not
part of Phase 2 scope. See individual items for details.

**Tiers 2+3 (Wave B) are complete as of 2026-04-10.**
Items 14, 14b, 16, 17, 18 (all sub-items 18a-e) are
DONE. Four infrastructure prerequisites (D, A, C, B) were
landed first, then all items. See Tier 2/3 sections below
and `2026-04-10-tier2-working-doc.md` for details.

Both tdns and tdns-mp build clean after every step.

### Tier 1 — mechanical cleanup (low risk, small diff)

**Item 5 — Commented-out Agent/Signer/Combiner init blocks**
- AppTypeAgent block at `tdns/v2/main_initfuncs.go:262-394`
- AppTypeAuth block at `tdns/v2/main_initfuncs.go:396-672`
- Before deleting: diff each commented block line-by-line
  against tdns-mp's `main_init.go` / `start_agent.go` /
  `start_auth.go` to confirm every statement has a live
  counterpart. Commented-out code is exactly where subtle
  drops happen during a migration — a "looks migrated"
  skim is not sufficient.
- **Status: DONE (2026-04-09, tdns 4c95c6a).** Entire dead
  switch statement deleted (421 lines). Coverage verified
  in tdns-mp: `SetupAgent` in `agent_setup.go:239`,
  `NewAgentRegistry` in `agent_utils.go:97`,
  `InitHsyncTables` in `main_init.go:380`, distribution
  cache in `main_init.go:91,245,389`,
  `NewMPTransportBridge` in `hsync_transport.go:191`,
  `initSignerCrypto` in `signer_transport.go:23`,
  `RegisterSignerChunkHandler` in
  `signer_chunk_handler.go:23`, `InitCombinerEditTables`
  in `combiner_db_schema.go:16`, `InitCombinerCrypto` in
  `combiner_crypto.go:32`, `RegisterCombinerChunkHandler`
  in `combiner_chunk.go:1251`, `NewCombinerSyncHandler`
  in `combiner_chunk.go:1218`.

**Item 6 — Commented-out StartCombiner function**
- Entire function at `tdns/v2/main_initfuncs.go:680-792`
- Same line-by-line diff against
  `tdns-mp/v2/start_combiner.go` before deletion.
- **Status: DONE (2026-04-09, tdns 4c95c6a).** Function
  body (113 lines) deleted. Coverage verified:
  `LoadAllContributions` in
  `tdns-mp/v2/db_combiner_contributions.go:63`,
  `StartIncomingMessageRouter` used from
  `tdns-mp/v2/start_combiner.go:53`, `CombinerMsgHandler`
  in `tdns-mp/v2/combiner_msg_handler.go:29`,
  `SetupCombinerSyncRouter` called from
  `tdns-mp/v2/start_combiner.go:70`, `APIdispatcherNG`
  wired from `tdns-mp/v2/start_combiner.go:76`.

**Item 13 — MPPreRefresh/MPPostRefresh registration in
ParseZones**
- Registration still at `tdns/v2/parseconfig.go:714-716`
- Functions defined in tdns at
  `legacy_hsync_utils.go:907, 1047` (legacy-flagged) AND in
  tdns-mp at `hsync_utils.go:1000, 1141`
- **First action: grep for all registration sites** and
  confirm whether tdns-mp also registers these callbacks
  (it should). Three cases:
  1. **Both sides register, tdns-mp wins at runtime.**
     Safe to delete the tdns-side registration plus the
     legacy_* function bodies.
  2. **Both sides register, tdns wins at runtime** (e.g.
     because tdns registers last, or ordering is
     non-deterministic). Same fix as case 1, but diagnose
     the ordering first — don't assume tdns-mp is winning
     just because it's also registered. Check actual
     registration order.
  3. **Only tdns registers.** Add tdns-mp registration
     first, verify it runs, then delete tdns side.
- Per the workflow rule on unused code, the legacy_*
  function bodies become unreachable once the tdns-side
  registration is removed. Confirm with the user before
  deleting those function bodies, even though the
  unreachability proof is trivial.
- **Status: DONE (2026-04-09, tdns 4c95c6a).** Diagnosis:
  **case 1 with a twist.** Both sides register on the
  same `OnZonePreRefresh`/`OnZonePostRefresh` slices:
  tdns appends its 2-arg `MPPreRefresh`/`MPPostRefresh`
  during `ParseZones`, then tdns-mp's
  `RegisterMPRefreshCallbacks` (called from
  `StartAgent`/`StartSigner`/`StartCombiner` in
  `tdns-mp/v2/config.go:29`) appends closures wrapping
  the 5-arg versions. tdns ran first; its analysis was
  overwritten on every refresh by tdns-mp's PreRefresh.
  Worse, tdns's PostRefresh ran first after the flip and
  used tdns-mp's analysis before clearing it to nil,
  causing tdns-mp's PostRefresh to see nil and no-op.
  Removing the tdns-side registration fixes this. The
  legacy_* function bodies are now unreachable but left
  in place per the workflow rule — flag for explicit
  cleanup approval later.

**Item 25 — key_state_worker.go MP state checks**
- MP checks at `tdns/v2/key_state_worker.go:181, 213, 224`
- tdns-mp has its own `key_state_worker.go`
- **Status: ORIGINAL DESCRIPTION WAS WRONG (2026-04-09).**
  Investigation found both sub-actions in the original
  plan were based on misreads of the code:

  1. **Sub-action 1 (gate startup positively) is moot.**
     tdns's `KeyStateWorker` is not registered anywhere
     in tdns/v2/. There is no startup to gate. The only
     live registration is tdns-mp's own copy, started
     from `tdns-mp/v2/start_signer.go:43` for the
     mpsigner role.

  2. **Sub-action 2 (strip MP branches) does not apply.**
     The checks at lines 181/213/224 are
     `zd.Options[OptMultiProvider]` **zone-option**
     checks, not `AppTypeMP*` **app-type** branches. The
     guiding principle forbids branching on the external
     app-type constants; zone options are a separate,
     legitimate mechanism. The checks guard real MP
     behavior (`DnskeyStateMpremove` transitions,
     `pushKeystateInventoryToAllAgents`) that would
     break MP if stripped.

- **Actual state.** `tdns/v2/key_state_worker.go` is an
  unreferenced file. tdns-mp has a near-identical live
  copy at `tdns-mp/v2/key_state_worker.go`. The two
  files have diverged only superficially.

- **Decision (2026-04-09).** Leave the file in place as
  the reference implementation for the eventual tdns-auth
  wiring. A header comment has been added explaining
  that it is not yet wired and should be picked up when
  the tdns-auth key management logic is revisited more
  broadly (tdns commit 56ede5a). When that work lands:
  - Register `KeyStateWorker` from `StartAuth` gated
    positively on `AppTypeAuth`.
  - Decide whether tdns and tdns-mp should share the
    file or keep separate copies.
  - Review the `OptMultiProvider` branches —
    `DnskeyStateMpremove` and
    `pushKeystateInventoryToAllAgents` are MP concepts
    that a plain tdns-auth signer can ignore entirely.

- **Reclassification.** This item is **no longer Tier 1**
  and is not part of Wave A. It belongs with the
  tdns-auth key management revisit, whenever that lands.
  Priority table updated to reflect the move.

### Tier 2 — move MP logic into tdns-mp (low–medium risk)

> **Tier 2 planning has moved to a dedicated working doc:
> `2026-04-10-tier2-working-doc.md`.** That doc captures
> the full item-level details, infrastructure prerequisites
> (option validator hook, per-zone MP callback attachment,
> post-validate hook, dnsengine-in-default fix), cross-
> cutting findings, open questions, and a per-item deletion
> discipline checklist. The summary below remains here for
> cross-reference; the working doc is the authoritative
> source for Tier 2 implementation work.

**Item 16 — OptMultiProvider zone option validation**
- **Status: DONE (2026-04-10, tdns `d9aa8d7`, tdns-mp
  `e83096a`).** Fallback validation removed from tdns
  `parseoptions.go`. Validator registered via
  `RegisterZoneOptionValidator` in tdns-mp `main_init.go`.

**Item 17 — OptMPManualApproval validation**
- **Status: DONE (2026-04-10, tdns `d9aa8d7`, tdns-mp
  `e83096a`).** The `!= AppTypeMPCombiner` negative
  exclusion (exact forbidden pattern) removed from tdns.
  Validator registered in tdns-mp.

**Item 18 — config_validate.go MP section list + MP-only
validators**
- **Status: DONE (2026-04-10).** Four sub-items:
  - 18a: MP types removed from case list (tdns `dc33eab`).
    `dnsengine` added to default case first (prereq D,
    tdns `c8216b8`) to prevent silent regression.
  - 18b/c/d: `ValidateAgentNameservers`,
    `ValidateAgentSupportedMechanisms`, `ValidateCryptoFiles`
    moved to `tdns-mp/v2/config_validate.go` and registered
    via `PostValidateConfigHook` (tdns `35ef049`, tdns-mp
    `812ac08`).
  - 18e: `ValidateMultiProviderBlock` added for role/identity
    validation of the `multi-provider:` block (in-scope per
    decision, same commit `812ac08`).

**Item 14 — MP inline signing OnFirstLoad**
- **Status: DONE (2026-04-10, tdns `9effbde`, tdns-mp
  `dca946e`).** Block removed from tdns `parseconfig.go`.
  Counterpart registered via `ForEachMPZone` second-pass
  loop in tdns-mp `main_init.go`. Investigation confirmed
  this was load-bearing for mpsigner (Q2).

### Tier 3 — ParseZones second pass (medium risk, design
work first)

**Item 14b — MPdata population in ParseZones**
- **Status: DONE (2026-04-10, tdns `2b8c56b`, tdns-mp
  `05da49f`).** MPdata population removed from tdns
  `parseconfig.go`. Counterpart in `ForEachMPZone`
  second-pass loop in tdns-mp `main_init.go`.

  The original "Wave B keystone" framing turned out to be
  overstated — the parse-time MPdata population was a
  near-no-op (nothing later in ParseZones consumed it).
  The second-pass loop (`ForEachMPZone`) was confirmed
  safe: `OnFirstLoad` fires in `RefreshEngine.
  initialLoadZone` (refreshengine.go:101-109), well after
  the loop runs. Items 14, 16, 17 each needed their own
  infrastructure (option validator hook for 16/17, second-
  pass loop for 14) and were not actually blocked on 14b.

  Investigation answers:
  - OnFirstLoad fires **after** ParseZones (in
    RefreshEngine), so the second-pass loop is safe.
  - Nothing in ParseZones consumes `zdp.MP.MPdata` after
    the population block.
  - A simple `ForEachMPZone` loop suffices — no new
    infrastructure in tdns was needed, only tdns-mp code.

### Tier 4 — /agent split continuation (medium risk,
several slices)

**Item 27 (remaining) — /agent endpoint slices**

Current `APIagent` in `tdns/v2/apihandler_agent.go` has 29
active cases after Phase 1. Remaining MP-specific command
groups (by estimated effort, smallest first):

1. **imr-*** (4 commands): `imr-query`, `imr-flush`,
   `imr-reset`, `imr-show`. New `/imr` endpoint. Parallel
   to Task O pattern. Smallest.
2. **parentsync-*** (4 commands): `parentsync-status`,
   `parentsync-election`, `parentsync-inquire`,
   `parentsync-bootstrap`. New `/parentsync` endpoint.
   Role-scoped to agent. Medium.
3. **Discovery group** (4 commands): `hsync-locate`,
   `hsync-agentstatus`, `discover`, `refresh-keys`. New
   `/discovery` endpoint (or similar). Depends on
   AgentRegistry. Medium.
4. **Data modification** (2 commands): `add-rr`, `del-rr`.
   New `/update` endpoint. Touches combiner contribution
   paths. Medium.
5. **Combiner debug grab-bag** (6 commands):
   `hsync-chunk-send`, `hsync-chunk-recv`, `hsync-init-db`,
   `hsync-sync-state`, `show-combiner-data`,
   `send-sync-to`. Can migrate as a single `/combiner/debug`
   group or split further.

Each slice follows the established pattern: new
`/<group>` route, per-group Post/Response types, CLI
workers with `runXxx(role, args)`, delete legacy tdns
copies.

**Item 3 — MsgQs creation** (blocked on item 27 +
ref-audit)
- `tdns/v2/main_initfuncs.go:205-222` still unconditionally
  creates `conf.Internal.MsgQs`
- 15 active references remain across
  `apihandler_agent.go` and `main_initfuncs.go`
- tdns-mp already uses its own `NewMsgQs()`
  (`tdns-mp/v2/main_init.go:89`)
- **Unblock prerequisite (MsgQs ref-audit)**: *before*
  starting item 27, grep `conf.Internal.MsgQs` in
  `tdns/v2/` and map each of the 15 references to the
  specific slice that will migrate it. Produce a written
  mapping (even a checklist in a scratch file is fine).
  Any reference that falls outside all 5 planned slices
  needs either a 6th slice or an explicit note
  documenting why it stays in tdns. Item 3 is *not*
  unblocked the moment slice 5 lands — it's unblocked
  when the ref-audit checklist is 100% accounted for.
  The priority table reflects this: item 3's blocker is
  "27 complete **and** MsgQs ref-audit clean," not just
  "27 complete." Skipping the ref-audit means Wave C
  will almost certainly need a follow-up cleanup pass.

### Tier 5 — signing/keystore engine decoupling (mostly
deferred, high coupling)

Most items here are deferred pending a signing-engine
refactor. **Exception: item 23 is a quick win and should
be scheduled into Wave A or B, not left in Tier 5.** It's
listed here only for topical grouping with the other
signing items; its difficulty ("Easy") and blast radius
(MP startup code, no tdns-signing-engine coupling) are
closer to Tier 1/2 than Tier 5. The priority table
reflects its earlier scheduling, not this topical
grouping.

**Item 22 — sign.go OptMultiProvider/OptMultiSigner gates**
- Gates at `tdns/v2/sign.go:243, 363`
- Deeply wired into signing pipeline
- Verdict: revisit when signing engine is modularized.
  Not recommended as a standalone task.

**Item 23 — resigner.go skip MP zones**
- Check at `tdns/v2/resigner.go:76`
- Recommended approach: manage `ZonesToKeepSigned` list
  on the MP side rather than checking `OptMultiProvider`
  at resign time. Low effort if approached this way;
  touches MP startup code.
- **Status: DONE (2026-04-09, tdns 4c95c6a).** Applied a
  simpler fix than the original recommendation:
  replaced the `OptMultiProvider && !weAreASigner()`
  check with a generic
  `!OptInlineSigning && !OptOnlineSigning` check. MP
  zones already toggle `OptInlineSigning` dynamically
  via `MPPreRefresh` based on HSYNC analysis, so the
  generic option check is functionally equivalent and
  removes the resigner's knowledge of MP concepts
  (`weAreASigner`, `OptMultiProvider`). No changes to
  MP startup code were needed. `ResignerEngine` is now
  generic — it treats every zone identically.

**Item 24 — keystore.go DnskeyStateMpremove**
- Referenced at `tdns/v2/keystore.go:470, 878, 889`
- Deferred pending DNSSEC engine modularization. Lowest
  priority of the signing items.

**Item 26 — delegation_sync.go MP DNSKEY sync** (moved to
Wave D alongside 26b)
- Block at `tdns/v2/delegation_sync.go:169-179`
- Sends NOTIFY for DNSKEY RRset sync to controller when
  zone is MP. Analysis ("what does this actually do?")
  is folded into Wave D's design phase for 26b — item 26
  is a consumer of the `DelegationSyncher` being
  restructured, so the two must be designed together.

### Tier 6 — structural / biggest blast radius

**Item 26b — DelegationSyncher pluggable handler**
- `notifyPeersParentSyncDone` no longer found in tdns
  (already removed)
- `DelegationSyncher` still monolithic at
  `tdns/v2/delegation_sync.go:25-194` with MP
  SYNC-DNSKEY-RRSET handling
- tdns-mp invokes the same function from
  `tdns-mp/v2/start_agent.go:370-371`
- Design needed: pluggable handler mechanism analogous to
  NOTIFY/query handlers. tdns registers a default handler;
  tdns-mp registers an MP-aware one with LeaderElection
  checks and peer notification.
- Medium–hard, well-scoped once designed.

**Item 29 — zd.MP → zd.AppData interface{}**
- `zd.MP *ZoneMPExtension` at `tdns/v2/structs.go:134`
- `ZoneMPExtension` defined at `tdns/v2/structs.go:80-111`
- No AppData replacement in progress
- Largest mechanical diff by far: every getter/setter on
  `ZoneMPExtension`, every call site, every tdns-mp
  consumer
- Best done after items 14, 14b, and 27 have cleared out
  most of the MP-in-tdns coupling so remaining usages are
  concentrated and visible.

---

## Priority-ordered summary table

| Order | Item | Wave | Tier | Difficulty | Blockers |
|-------|------|------|------|------------|----------|
| 1 | 5 | A | 1 | Trivial | **DONE** (tdns 4c95c6a) |
| 2 | 6 | A | 1 | Trivial | **DONE** (tdns 4c95c6a) |
| 3 | 13 | A | 1 | Easy | **DONE** (tdns 4c95c6a) |
| — | 25 | (deferred) | — | — | **RECLASSIFIED** — moved to tdns-auth key mgmt revisit; see item body |
| 4 | 23 | A | (5) | Easy | **DONE** (tdns 4c95c6a) — promoted from Tier 5 |
| 5 | 14b | B | 3 | Medium | **DONE** (tdns `2b8c56b`, tdns-mp `05da49f`) |
| 6 | 16 | B | 2 | Easy | **DONE** (tdns `d9aa8d7`, tdns-mp `e83096a`) |
| 7 | 17 | B | 2 | Easy | **DONE** (tdns `d9aa8d7`, tdns-mp `e83096a`) |
| 8 | 14 | B | 2 | Easy | **DONE** (tdns `9effbde`, tdns-mp `dca946e`) |
| 9 | 18 | B | 2 | Medium | **DONE** (tdns `c8216b8`+`dc33eab`+`35ef049`, tdns-mp `812ac08`) |
| 11 | 27 (imr) | C | 4 | Easy | None |
| 12 | 27 (parentsync) | C | 4 | Medium | None |
| 13 | 27 (discovery) | C | 4 | Medium | None |
| 14 | 27 (add-rr/del-rr) | C | 4 | Medium | None |
| 15 | 27 (combiner debug) | C | 4 | Medium | None |
| 16 | 3 | C | 4 | Easy | 27 complete **and** MsgQs ref-audit clean |
| 17 | 26 | D | 5 | Unknown | Analyze as part of 26b |
| 18 | 26b | D | 6 | Hard | Design needed; includes 26 |
| 19 | 22 | E | 5 | Deferred | Signing engine refactor |
| 20 | 24 | E | 5 | Deferred | DNSSEC engine refactor |
| 21 | 29 | F | 6 | Very hard | Zero MP-type refs in tdns/v2/ (see precondition) |

---

## Natural sequencing recommendation

### Wave A — cleanup (Tier 1 + item 23) — **COMPLETE**

Items 5, 6, 13, 23 — **DONE (2026-04-09, tdns 4c95c6a).**
Item 25 was investigated and reclassified out of Wave A
(the original description was wrong; see Item 25 above).
Both tdns and tdns-mp built clean after every step.

Wave A removed:
- 421 lines of commented-out init blocks from
  `main_initfuncs.go` (item 5).
- 113 lines of commented-out `StartCombiner` function
  from the same file (item 6).
- Double-registration of `MPPreRefresh`/`MPPostRefresh`
  from `parseconfig.go` (item 13).
- MP-specific `weAreASigner()` check from
  `resigner.go:76`, replaced with a generic
  `OptInlineSigning`/`OptOnlineSigning` check (item 23).

Follow-up items from Wave A:
- `MPPreRefresh`/`MPPostRefresh` function bodies in
  `legacy_hsync_utils.go:907-1116` are now unreachable.
  Flagged for explicit cleanup approval.
- `tdns/v2/key_state_worker.go` is not wired anywhere
  but should eventually be registered from `StartAuth`.
  A header comment has been added documenting this
  (tdns commit 56ede5a). Belongs with the tdns-auth key
  management revisit, not Phase 2.

### Wave B — ParseZones second pass (Tier 3 + 2) — **COMPLETE**

Items 14, 14b, 16, 17, 18 (all sub-items) — **DONE
(2026-04-10).** Four infrastructure prerequisites were
landed first (D, A, C, B), then all items implemented.

Key decisions and findings:
- **14b was NOT a keystone.** The parse-time MPdata
  population was a near-no-op; nothing in ParseZones
  consumed it. Items 14/16/17 each needed their own
  infrastructure (option validator hook for 16/17,
  second-pass loop for 14/14b) and were independent.
- **OnFirstLoad fires after ParseZones** (in RefreshEngine
  `initialLoadZone`), so `ForEachMPZone` second-pass
  loop is safe.
- **Items 16/17 used `RegisterZoneOptionValidator`** (new
  mechanism in `option_handlers.go`), not OnFirstLoad.
- **Items 18b/c/d used `PostValidateConfigHook`** (new
  hook on `Config.Internal`).
- **Item 18e (multi-provider: block validation) was
  in-scope** — added `ValidateMultiProviderBlock` for
  role/identity validation.

See `2026-04-10-tier2-working-doc.md` for full details.

### Wave C — /agent split continuation (Tier 4)

Item 27 slices, in the order imr → parentsync → discovery
→ add-rr/del-rr → combiner debug. Each slice is
independent and follows the Task L/M/N/O pattern. Can
proceed in parallel with Wave B if desired. Once all
slices land, item 3 (MsgQs) becomes a trivial follow-up.

### Wave D — DelegationSyncher restructure (Tier 6 + 5)

Items 26b **and 26**. Item 26 (`delegation_sync.go:169-179`
MP DNSKEY sync block) is a consumer of the
`DelegationSyncher` that 26b restructures — its "what
does this actually do?" analysis belongs *inside* the 26b
design phase, not deferred. Designing a pluggable handler
without knowing one of its real users invites rework.

Process:
1. Analyze item 26's block first (it's the blocker question
   from the parent doc).
2. Design the pluggable handler mechanism with item 26's
   behavior as one of the known use cases. tdns registers
   a default, tdns-mp registers an MP-aware one with
   LeaderElection checks and peer notification.
3. Implement. Natural extension of the transport-handler
   patterns established by Phase 1 M/N/O and Wave C.

### Wave E — signing engine decoupling (Tier 5)

Items 22, 24. Bundle with any future signing-engine
refactor. Not recommended as standalone MP-decoupling
tasks — the coupling is too deep and the benefit per unit
of work is too low. Item 23 has moved to Wave A (quick
win, no signing-engine coupling). Item 26 has moved to
Wave D.

### Wave F — AppData conversion (Tier 6)

Item 29. The final structural change. After Waves A–D,
`zd.MP` call sites should be concentrated enough to make
the `zd.AppData interface{}` conversion tractable. This is
the endgame of the decoupling effort.

**Wave F precondition**: zero MP-type references in
`tdns/v2/` outside the struct definition itself. If
Waves A–D leave stragglers, item 29 degenerates from a
concentrated conversion into a cross-cutting change and
loses most of its leverage.

Run all of the following greps before starting and
expect the only hits to be inside `structs.go`:

```sh
# Field access via the primary receiver name
grep -rn 'zd\.MP\.' tdns/v2/
grep -rn 'zdp\.MP\.' tdns/v2/

# Bare references (catches method receivers, assignments,
# type assertions, and alternative variable names)
grep -rn '\.MP\b' tdns/v2/

# Type name — catches declarations, parameter types,
# composite literals, and any helper that takes
# *ZoneMPExtension as an argument
grep -rn 'ZoneMPExtension' tdns/v2/
```

The `\.MP\b` grep is deliberately broad and will produce
false positives (e.g. `AppTypeMP*` constants, `MP` in
comments). Triage those manually — the goal is that
every hit either (a) is unrelated to `ZoneMPExtension`
or (b) lives in `structs.go`. The `ZoneMPExtension` grep
is the strictest check and is the one that must come
back clean.

---

## Verification per wave

Every wave needs a concrete definition of "done that
didn't break anything." Build-clean is table stakes,
not a verification strategy. This table captures the
minimum verification each wave needs; individual items
may need more.

| Wave | Minimum verification |
|------|----------------------|
| A | **COMPLETE 2026-04-09.** Build verified clean on tdns (auth/agent/scanner/cli/imr/dog) and tdns-mp (mpagent/mpsigner/mpcombiner/mpauditor/mpcli) after each item. NetBSD lab verification for item 13 (MPPreRefresh/MPPostRefresh firing on refresh) still pending — to be confirmed by inspecting logs in the test lab. Item 25 lab verification no longer applicable (item reclassified). |
| B | NetBSD lab: zone first-load on mpagent, mpsigner, mpcombiner, mpauditor. Confirm MPdata is populated at the right point by logging zone state immediately after `initialLoadZone`. If Wave B collapses to OnFirstLoad callbacks, verify callback ordering against any code that consumes MPdata during or after initial load. |
| C | CLI smoke test every migrated command group on the new endpoints. Specifically: run every command in each slice against a live agent and compare output to pre-migration behavior. Delete the legacy tdns copies *only after* the smoke test passes — not before. Item 3: after the MsgQs ref-audit checklist is clean, confirm `conf.Internal.MsgQs` has zero references in `tdns/v2/` via grep. |
| D | Delegation sync integration test in the NetBSD lab. Specifically exercise: (a) the path that currently runs `delegation_sync.go:169-179` — confirm the behavior is preserved by the new pluggable handler; (b) LeaderElection gating — confirm non-leaders do not trigger peer notification; (c) the default (non-MP) handler path still works for plain tdns auth. |
| E | Deferred wave. Verification strategy will be defined when the signing engine refactor is scoped. |
| F | Full regression: build clean, all tests, NetBSD lab zone first-load on all four app types, plus a spot-check of every `AppData` call site introduced by the conversion. The final grep precondition (`ZoneMPExtension` should only appear in tdns-mp) must come back clean *after* the conversion lands, not just before. |

**Build-clean caveat.** The local Makefile build
(`cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`,
plus `cd tdns-mp/cmd && ... make` if tdns-mp is touched)
is a necessary but insufficient check. It catches
compile errors and unused imports; it does not catch
runtime regressions, callback ordering issues, or
missing MP-side coverage. Never declare a wave done
based on build-clean alone.

---

## Investigation checklist

Before starting Wave B (item 14b), answer:

- [ ] **Can OnFirstLoad carry MPdata population?** The
      single most important question — if yes, Wave B
      collapses to callback registration and no new
      second-pass loop is needed.
- [ ] When does tdns-mp's MainInit currently run relative
      to tdns's ParseZones? (Determines whether a second
      pass is even reachable at the right time.)
- [ ] Are there any existing tdns-mp callbacks that
      already run per-zone after ParseZones? (Might be
      extensible rather than requiring a new loop.)
- [ ] Does `zd.MP.MPdata` get consulted *during* the
      remainder of tdns's ParseZones after line 705? (If
      yes, moving population out of tdns requires
      additional care.)
- [ ] Is `zd.MP.MPdata` consulted during `initialLoadZone`
      (HSYNC processing, signing setup, combiner
      contributions)? If yes, the second pass must run
      *before* initial load — OnFirstLoad may be too
      late. If no, OnFirstLoad is sufficient.
- [ ] What iteration model fits best: per-zone callback
      (hooks into existing OnFirstLoad infrastructure) vs.
      a single explicit loop over `Zones.Items()` at a
      well-defined point in tdns-mp MainInit?
- [ ] Does the design's accessor shape survive item 29's
      `zd.AppData interface{}` conversion without needing
      tdns changes? (Avoids building 14b in a way that
      creates rework for Wave F.)

Before starting Wave D (items 26 + 26b), answer:

- [ ] What exactly does `delegation_sync.go:169-179` do?
      (Item 26 — now answered as part of Wave D, not
      deferred.) Who triggers it, what does the NOTIFY
      carry, what does the controller do on receipt?
- [ ] What is the current relationship between
      `DelegationSyncher` and `LeaderElectionManager` in
      the MP case?
- [ ] Can the pluggable handler reuse the existing
      NOTIFY-handler registration pattern, or does it
      need a new one?
- [ ] With item 26's behavior understood, does the
      pluggable handler interface cover it cleanly, or
      does it need a second registration point?
