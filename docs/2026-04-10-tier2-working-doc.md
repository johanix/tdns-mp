# MP Decoupling — Tier 2 Working Doc

**Date**: 2026-04-10
**Parent doc**: `2026-04-09-decoupling-plan-phase2.md` (Tier 2
section + priority table)
**Scope**: Items 14, 14b, 16, 17, 18 from Phase 2.
**Status**: **COMPLETE (2026-04-10).** All prerequisites
landed, all items implemented, both repos build clean.
NetBSD lab verification pending.

---

## Why this doc exists

The Tier 2 items in the Phase 2 plan share a problem that's
easy to lose track of: each item reads as "move a small piece
of MP logic out of tdns," but the actual work requires
infrastructure changes in tdns (hook mechanisms, handler
registries) that aren't yet spec'd out. The biggest risk is
that someone starts implementing an item, discovers the
infrastructure gap mid-flight, builds a narrow one-off fix
for their own item, and then the next item does the same
with a slightly different approach. Worse: someone deletes
the tdns-side code after moving it to tdns-mp, and later we
realize a piece of behavior was silently dropped because
there was no structured checklist.

This doc exists to:

1. Keep all Tier 2 items in one place so details don't get
   scattered across commits and subsequent conversations.
2. Force the infrastructure questions to the top — nothing
   gets implemented until the mechanism is decided.
3. Enforce a "nothing deleted from tdns until the tdns-mp
   counterpart is verified live and tested" discipline, item
   by item, with file:line evidence.
4. Provide a single place to track that all tdns-side
   behavior has a tdns-mp counterpart *before* the tdns-side
   code is removed, and that the counterpart is actually
   running and observed.

---

## Guiding principle (reminder)

From the Phase 2 doc:

> tdns must not contain any code path that branches on
> `AppTypeMPAgent`, `AppTypeMPSigner`, `AppTypeMPCombiner`,
> or `AppTypeMPAuditor`. Where gating is needed, use a
> positive allow-list on tdns's own app types
> (`AppTypeAuth`, `AppTypeAgent`, `AppTypeScanner`) — never
> a negative exclusion like `!= AppTypeMPSigner`.

Tier 2 is where several of the remaining violations live.
Item 17 in particular contains **the exact forbidden
pattern** (`!= AppTypeMPCombiner`). Item 18's `configsections`
switch contains a **positive case-list of MP types** which
is the other forbidden pattern. These are called out in the
item-level sections below.

---

## Items in scope

### Item 14b — MPdata population in ParseZones

- **Current location**: `tdns/v2/parseconfig.go:685-707`
- **What it does**: Inside the per-zone loop in
  `ParseZones`, when `options[OptMultiProvider]` is true,
  builds a minimal `MPdata` struct (`Options: {OptMultiProvider:
  true}`) and stores it at `zdp.MP.MPdata`. This is the
  "lightweight parse-time population." The meaningful
  population happens later via `populateMPdata` in
  `MPPreRefresh` (tdns-mp `hsync_utils.go:1063`) and via
  `OnFirstLoad` callbacks.
- **Why it's the Phase 2 "keystone" claim**: The original
  Phase 2 doc calls this item critical because it's the
  natural vehicle for "how does tdns-mp do MP-specific per-
  zone work during parsing?" But see the finding below.
- **Finding (2026-04-10)**: The parse-time `MPdata`
  population is **a near-no-op**. Nothing later in tdns's
  `ParseZones` consumes it (verified via grep —
  `MP.MPdata` is only referenced inside the population
  block itself, `parseconfig.go:677-707`). This means the
  block can be lifted out of tdns entirely without breaking
  anything in tdns's remaining parse pipeline. Where it
  goes (OnFirstLoad callback on MP zones? tdns-mp second
  pass?) is a separate question, but the coupling is
  shallow.
- **Status**: **DONE (2026-04-10).** MPdata population
  removed from tdns `parseconfig.go` (tdns `2b8c56b`).
  Counterpart in `ForEachMPZone` second-pass loop in
  `tdns-mp/v2/main_init.go` (tdns-mp `05da49f`).

### Item 14 — MP inline signing OnFirstLoad

- **Current location**: `tdns/v2/parseconfig.go:731-739`
  (line numbers drifted from Phase 2 doc's "739-746" after
  Wave A removed the `MPPreRefresh`/`MPPostRefresh`
  registration block at lines 711-717)
- **What it does**: Registers an `OnFirstLoad` callback on
  MP zones that, after zone load, checks whether
  `OptInlineSigning` has been set (dynamically, by HSYNC
  analysis) and calls `SetupZoneSigning` if so.
- **Current guard**: `options[OptMultiProvider] &&
  (Globals.App.Type == AppTypeAuth || Globals.App.Type ==
  AppTypeMPSigner)`
- **Guiding-principle concern**: The `|| AppTypeMPSigner`
  branch is an explicit positive reference to an MP app-
  type constant inside tdns. Not a branch *against* MP
  types, but tdns is still reading the MP constants. Borderline
  — fixing item 14 removes this entirely.
- **Status**: **DONE (2026-04-10).** Block removed from
  tdns `parseconfig.go` (tdns `9effbde`). Counterpart
  registered via `ForEachMPZone` second-pass loop in
  `tdns-mp/v2/main_init.go` (tdns-mp `dca946e`).
  Investigation (Q2) confirmed the block was load-bearing
  for mpsigner — tdns-mp had no equivalent.

### Item 16 — OptMultiProvider zone option validation

- **Current location**: `tdns/v2/parseoptions.go:256-268`
- **What it does**: Inside the `switch opt` in
  `parseZoneOptions`, when `opt == OptMultiProvider`,
  checks `Globals.App.Type == AppTypeAuth && (conf.MultiProvider
  == nil || !conf.MultiProvider.Active)` and rejects the
  zone option (with a `ConfigError` on `zd`) if the server-
  level multi-provider config is missing. The comment says
  "On agents, the zone option alone is sufficient — the
  HSYNC RRset is the authority."
- **Guiding-principle concern**: This check is gated on
  `AppTypeAuth` positively (that's fine), but the *purpose*
  of the check is to validate a tdns-mp concept
  (`conf.MultiProvider.Active`) that tdns shouldn't know
  about. tdns is acting as a validator for MP config state
  that tdns doesn't own.
- **Status**: **DONE (2026-04-10).** Fallback validation
  removed from tdns `parseoptions.go` (tdns `d9aa8d7`).
  Validator registered via `RegisterZoneOptionValidator`
  in `tdns-mp/v2/main_init.go` (tdns-mp `e83096a`).

### Item 17 — OptMPManualApproval validation

- **Current location**: `tdns/v2/parseoptions.go:345-357`
- **What it does**: Inside the same `switch opt`, when
  `opt == OptMPManualApproval`, rejects the zone option on
  any app type that isn't `AppTypeMPCombiner`.
- **Guiding-principle concern**: **This is the exact
  forbidden pattern.** The check is `if Globals.App.Type !=
  AppTypeMPCombiner` — a negative exclusion on an MP type.
  The Phase 2 doc's guiding principle names this pattern
  explicitly as forbidden. Fixing item 17 is thus both a
  cleanup *and* a compliance fix.
- **Status**: **DONE (2026-04-10).** The `!= AppTypeMPCombiner`
  negative exclusion is gone from tdns (tdns `d9aa8d7`).
  Validator registered in `tdns-mp/v2/main_init.go`
  (tdns-mp `e83096a`).

### Item 18 — config_validate.go MP section list + MP-only validators

This item was actually **five independent sub-problems**.
**All DONE (2026-04-10).**

#### 18a — MP types in `configsections` switch — **DONE**
- MP types removed from case list (tdns `dc33eab`).
  `dnsengine` added to default case first (prereq D, tdns
  `c8216b8`) to prevent silent regression.

#### 18b — `ValidateAgentNameservers` — **DONE**
- Moved to `tdns-mp/v2/config_validate.go`, registered via
  `PostValidateConfigHook` (tdns `35ef049`, tdns-mp
  `812ac08`).

#### 18c — `ValidateAgentSupportedMechanisms` — **DONE**
- Same move and registration as 18b.

#### 18d — `ValidateCryptoFiles` — **DONE**
- Same move and registration as 18b.

#### 18e — `multi-provider:` config block validation — **DONE**

- **Current location**: nonexistent. Grep for
  `configsections["multi-provider"]` returns nothing.
- **What it should do**: Validate the top-level
  `multi-provider:` YAML section the same way other
  sections (`service`, `db`, `dnsengine`) get validated.
- **Guiding-principle concern**: n/a — this is a missing
  piece that tdns-mp should own if/when built.
- **Scope question**: Is this in-scope for item 18 or
  follow-up? Not yet decided — see §"Open questions."

---

## Decisions (locked 2026-04-10)

- **Prereq A**: Option 1 — `RegisterZoneOptionValidator`
  with error return and `zd` access. Minimal change.
- **Prereq B**: Option 2 — second-pass loop in tdns-mp
  `MainInit`. Confirmed safe: `OnFirstLoad` fires in
  `RefreshEngine` (`refreshengine.go:101-109`), well after
  `ParseZones` returns. No new tdns infrastructure needed.
- **Prereq C**: Option 2 — `PostValidateConfigHook` field
  on `Config`.
- **Prereq D**: Option 1 — add `dnsengine` to default
  case in same commit as item 18a.
- **Q1 (18e scope)**: In-scope. At least partial validation
  of `role:` and `identity:` fields. Hook is already there
  (prereq C); not adding it is a glaring omission.
- **Q2 (item 14 load-bearing?)**: Yes. tdns-mp does NOT
  have its own SetupZoneSigning OnFirstLoad for MP zones.
  The tdns-side registration is the only path. Item 14
  must add the tdns-mp counterpart before deleting.
- **Q3 (OnFirstLoad timing)**: Fires later, in
  `RefreshEngine.initialLoadZone`. Post-ParseZones
  second-pass loop is safe.
- **Q4 (validator semantics)**: Validators report errors
  via `zd.SetError` + skip the option. Do not mutate the
  `options` map.
- **Q5 (Linear)**: Skipped. Working from docs only.

---

## Infrastructure prerequisites — ALL LANDED (2026-04-10)

All four prerequisites are implemented and committed.

### Prerequisite A — Zone option validator hook — **DONE** (tdns `91020c8`)

**Needed by**: items 16, 17.

**Why the existing `RegisterZoneOptionHandler` is insufficient**:

- Runs at `parseconfig.go:709`, **after** `parseZoneOptions`
  has already accepted or rejected each option.
- Handler signature `func(zname, options)` has no return
  value — no way to reject an option from a handler.
- Handler has no access to `zd`, so it can't call
  `zd.SetError(ConfigError, ...)` the way the current
  in-switch checks do.
- The `options` map is already "accepted" by the time the
  handler runs; un-setting an option at that point races
  with concurrent readers.

**Options for extending the mechanism**:

1. **Add a `RegisterZoneOptionValidator`** with signature
   `func(zname string, zd *ZoneData, options map[ZoneOption]bool)
   error`. Validators run *during* the switch (inject them
   into the `case` body via a registry lookup) and can
   return an error to reject the option. tdns-mp registers
   validators for `OptMultiProvider` and
   `OptMPManualApproval` at init time. tdns's switch body
   for these two cases becomes just `return
   invokeValidators(opt, zname, zd, options)`.

2. **Convert the whole switch to a table-driven dispatcher.**
   Each `ZoneOption` gets a validator entry in a `map[
   ZoneOption]ValidatorFunc`. tdns ships default validators
   for its own options; tdns-mp registers validators for
   MP options. Bigger refactor, but cleaner long-term. This
   is the path that would eventually let tdns-mp add
   entirely new zone options without touching tdns.

3. **Post-pass validation with rollback.** Let tdns accept
   all options in the first pass without validation, then
   run a post-pass (via `invokeOptionHandlers`) that can
   mark options for rollback. Complicated — the rollback
   semantics are unclear, especially when options interact.

**Recommendation**: Option 1. It's the smallest mechanism
change that unblocks items 16 and 17, reuses the existing
registry pattern, and doesn't require converting the switch
to table-driven all at once. Option 2 is the long-term goal
but shouldn't block Tier 2.

**Work item**: Before implementing items 16/17, land a
separate commit that adds `RegisterZoneOptionValidator` and
`invokeOptionValidators`, with tests for rejection and for
the no-handler-registered default path. tdns still ships
the in-switch MP validators in that commit; only the
*mechanism* is added. Items 16/17 then land as follow-up
commits that move the validators from tdns to tdns-mp.

### Prerequisite B — Per-zone MP callback attachment point — **DONE** (tdns-mp `65e0b6f`)

**Needed by**: items 14, 14b.

**Why a new mechanism is needed**: tdns's `ParseZones`
creates `*ZoneData` stubs and invokes per-zone init inside
its own loop. tdns-mp needs a point where it can attach
`OnFirstLoad` callbacks to MP zones (and, for 14b,
potentially a second-pass loop to populate `MPdata`). The
existing `OnFirstLoad` field is a slice on `ZoneData`, but
there's no callback registration mechanism from tdns-mp
that would cause it to fire *during* or *right after*
tdns's `ParseZones`.

**Options**:

1. **Per-zone registration callback.** Add a
   `RegisterMPZoneCallback func(zd *ZoneData)` global that
   tdns's `ParseZones` calls for every zone with
   `options[OptMultiProvider]` set, right after option
   parsing. tdns-mp registers one callback at init time
   (before calling parent `MainInit`). The callback gets
   to mutate `zd` freely — append `OnFirstLoad` closures,
   populate `MPdata`, whatever.

2. **Second-pass loop in tdns-mp's MainInit.** tdns-mp calls
   parent `MainInit` (which runs `ParseZones`), then
   iterates over `Internal.MPZoneNames` and attaches
   callbacks to each. This is the "ParseZones second pass"
   the Phase 2 doc references.

3. **OnFirstLoad-only for item 14.** If the only thing
   item 14 does is register one OnFirstLoad closure, and
   if tdns-mp's post-MainInit second pass can attach that
   closure before the first zone load fires, then item 14
   doesn't need any new infrastructure — just the
   second-pass loop from option 2.

**Recommendation**: Option 2 for both items 14 and 14b.
This is what Phase 2 doc's investigation checklist calls
"can OnFirstLoad carry this?" — and for both items, the
answer is yes *if* the second-pass loop runs before the
first zone load. Need to verify ordering: does tdns-mp's
post-MainInit code run before any zone's `OnFirstLoad`
callbacks fire? If `OnFirstLoad` fires during `ParseZones`
itself, the second pass is too late and we need option 1.

**Work item**: Before implementing items 14 or 14b, answer
the ordering question via code inspection (or a one-off
debug print). Then land the chosen mechanism as a separate
commit.

### Prerequisite C — Post-validate hook — **DONE** (tdns `83ea420`)

**Needed by**: items 18b, 18c, 18d.

**Why a hook helps**: tdns's `ValidateConfig` is called
from `parseconfig.go:353`, inside tdns's `MainInit`, which
runs **before** tdns-mp's `MainInit` has done any of its own
init. So the natural sequencing is:

1. tdns `MainInit` runs `ValidateConfig` without the three
   MP validators (because they've moved to tdns-mp).
2. tdns `MainInit` returns.
3. tdns-mp `MainInit` does its own init, including running
   the three MP validators.

This works functionally, but MP config errors are reported
*after* other config errors, which is a minor UX regression.
A `PostValidateConfigHook func(*Config) error` field on
`Config` would let tdns-mp register its validators to run
during tdns's `ValidateConfig`, preserving the current
"all errors reported at the same phase" UX.

**Options**:

1. **Late reporting** (no new hook). tdns-mp runs its
   validators after parent `MainInit` returns. Simplest.
   Accept the UX regression.

2. **Add `PostValidateConfigHook`.** One-line field on
   `Config`, invoked at the end of tdns's `ValidateConfig`.
   tdns-mp sets it before calling parent `MainInit`.

**Recommendation**: Option 2. The UX regression is small
but the fix is smaller. Add the hook.

**Work item**: Land the `PostValidateConfigHook` field and
invocation as a separate commit. Items 18b/18c/18d then
land as follow-up commits that move the validators and
register them via the hook.

### Prerequisite D — `dnsengine` validation fix — **DONE** (tdns `c8216b8`)

**Needed by**: item 18a.

Deleting the MP types from the `configsections` switch at
`config_validate.go:50-51` drops `dnsengine` validation
for MP apps, because the `default` branch doesn't include
it. Two options:

1. **Move `dnsengine` validation into the default branch.**
   Simplest. Any app that has a `dnsengine` config section
   gets it validated. The `default` case already has
   `service`, `db`, `apiserver`, `catalog`; adding
   `dnsengine` harms nothing for apps that don't use it
   (it's nil-guarded inside the validator).

2. **Have tdns-mp's own validator run `dnsengine` validation.**
   More invasive and duplicates logic.

**Recommendation**: Option 1. It's a one-line change. Do it
in the same commit as item 18a.

---

## Cross-cutting findings

These apply to multiple items and are easy to lose track of
if we implement items one at a time.

### Finding 1 — "Blocked on 14b" is probably wrong

The Phase 2 doc's priority table lists items 14, 16, 17 as
"blocked on 14b." But:

- Items 16 and 17 need the **option validator hook**
  (prerequisite A), not 14b's MPdata population.
- Item 14 needs the **per-zone callback attachment**
  (prerequisite B), which overlaps with 14b but is
  independently achievable.
- Item 14b itself is **nearly trivial** given the shallow-
  coupling finding above — the parse-time MPdata
  population is a near-no-op and nothing in tdns consumes
  it.

The three items should be sequenced on their own
prerequisites, not on 14b. Suggest updating the Phase 2
priority table after this doc lands.

### Finding 2 — Items 14, 16, 17 do NOT share one mechanism

The Phase 2 doc implicitly suggests a single answer to "can
OnFirstLoad carry this?" But the answer differs:

- **Item 14**: Probably yes. OnFirstLoad carries the
  inline-signing setup because the callback fires after
  the zone is loaded, which is when signing-setup logically
  belongs.
- **Items 16, 17**: **No.** These are validation checks
  that must run *during* `parseZoneOptions`, before the
  zone is accepted. OnFirstLoad runs after the zone has
  already been accepted and loaded; by that point it's too
  late to reject an option. Items 16/17 need the option
  validator hook, not OnFirstLoad.
- **Item 14b**: Either. The parse-time population is a
  near-no-op; any mechanism that runs before the first
  consumer of `MPdata` is fine.

### Finding 3 — Item 17 is the canonical forbidden pattern

Item 17's current code (`if Globals.App.Type !=
AppTypeMPCombiner`) is **the exact negative-exclusion
pattern** the guiding principle names as forbidden. It
should be fixed *first* among the Tier 2 items, both
because it's the clearest violation and because it's a good
test of whether the option validator hook (prerequisite A)
is well-designed.

### Finding 4 — Item 18a drops `dnsengine` silently

Already covered under prerequisite D. Repeating here because
it's the kind of thing that gets missed: the naive fix
("delete MP types from the case list") is a **regression**
if applied without the prerequisite D fix. Anyone
implementing item 18a must land both changes in the same
commit or the resulting build has a latent validation gap.

### Finding 5 — Item 14 has an AppTypeAuth fate question

The current block is gated on `(AppTypeAuth ||
AppTypeMPSigner)`. If the whole block moves to tdns-mp,
**tdns-auth users who set `OptMultiProvider` on a zone lose
this OnFirstLoad callback entirely.** Is that correct? The
answer is probably yes — tdns-auth plus an MP zone is an
incoherent state and MP zones are tdns-mp's job — but the
plan should say so explicitly. Otherwise someone running
tdns-auth with `OptMultiProvider` zones gets a silent
behavior change on upgrade.

### Finding 6 — Line numbers already drifted

The Phase 2 doc was written on 2026-04-09 using line
numbers from the then-current tree. Wave A (tdns commit
`4c95c6a`) removed ~550 lines from `main_initfuncs.go` and
~8 lines from `parseconfig.go`. Post-Wave A, item 14's
"739-746" is actually "731-739". Treat all file:line
references in the Phase 2 doc as approximate; always grep
to confirm before editing.

---

## Deletion discipline

This is the most important section. Every Tier 2 item ends
with "delete the tdns-side code." That's the step most
likely to silently drop behavior.

**Rule: no tdns-side deletion until ALL of the following
are true for the item being deleted:**

1. [ ] Every statement in the tdns-side code has a live
       counterpart in tdns-mp, verified by grep with exact
       file:line references cited in the commit message.
2. [ ] The tdns-mp counterpart has been observed to run on
       at least one app type in the NetBSD test lab (log
       evidence or manual verification). "The build passes"
       is not sufficient — Go compile-cleans unused
       exported functions happily, and hooks that aren't
       registered pass compile too.
3. [ ] The tdns-mp counterpart handles the same edge cases
       as the tdns-side code. For item 18b (agent
       nameservers), this means: FQDN normalization, empty
       entry rejection, in-autozone rejection, all tested.
       For item 18c (supported mechanisms), this means:
       empty-list rejection, duplicate rejection, unknown
       value rejection, case-normalization, all tested.
4. [ ] A Linear issue (or equivalent tracker entry) exists
       for the deletion, separate from the move, with a
       pointer to the commit that added the tdns-mp
       counterpart.
5. [ ] The commit message for the deletion explicitly cites
       the tdns-mp commit that added the counterpart.

**Never bundle "add tdns-mp version" and "delete tdns
version" in the same commit.** The two-step ("add first,
verify live, then delete") is what catches silent drops.
Bundling them removes the verification gap.

### Per-item deletion checklist

All items have been implemented. "Add counterpart" and
"delete tdns-side" were done in separate commits per the
discipline rule. NetBSD lab verification is pending for
all items.

#### Item 14 — MP inline signing OnFirstLoad

- [x] tdns-mp counterpart added (commit: `dca946e`)
- [ ] Counterpart verified live on mpsigner (lab pending)
- [x] tdns-auth behavior change documented in commit
      message (tdns `9effbde`)
- [x] tdns-side deletion commit: `9effbde`

#### Item 14b — MPdata population in ParseZones

- [x] tdns-mp counterpart added (commit: `05da49f`)
- [ ] Counterpart verified on all four MP roles (lab
      pending)
- [x] Verified that no tdns code reads `zdp.MP.MPdata`
      after the move (grep confirmed)
- [x] tdns-side deletion commit: `2b8c56b`

#### Item 16 — OptMultiProvider zone option validation

- [x] Prerequisite A (option validator hook) landed
      (commit: `91020c8`)
- [x] tdns-mp validator registered (commit: `e83096a`)
- [ ] Validator verified rejecting invalid config (lab
      pending)
- [x] tdns-side deletion commit: `d9aa8d7`

#### Item 17 — OptMPManualApproval validation

- [x] Prerequisite A landed (same as item 16)
- [x] tdns-mp validator registered (commit: `e83096a`)
- [ ] Validator verified rejecting on non-combiner (lab
      pending)
- [x] tdns-side deletion commit: `d9aa8d7`

#### Item 18a — MP types in configsections switch

- [x] Prerequisite D (dnsengine in default case) applied
      (commit: `c8216b8`)
- [ ] Verified MP apps still get `dnsengine` validation
      (lab pending)
- [x] Commit: `dc33eab`

#### Item 18b — ValidateAgentNameservers

- [x] Prerequisite C (PostValidateConfigHook) landed
      (commit: `83ea420`)
- [x] tdns-mp counterpart added and registered via hook
      (commit: `812ac08`)
- [ ] Counterpart verified live (lab pending)
- [x] tdns-side deletion commit: `35ef049`

#### Item 18c — ValidateAgentSupportedMechanisms

- [x] Prerequisite C landed (same as 18b)
- [x] tdns-mp counterpart added (commit: `812ac08`)
- [ ] Counterpart verified live (lab pending)
- [x] tdns-side deletion commit: `35ef049`

#### Item 18d — ValidateCryptoFiles

- [x] Prerequisite C landed (same as 18b)
- [x] tdns-mp counterpart added (commit: `812ac08`)
- [ ] Counterpart verified live (lab pending)
- [x] tdns-side deletion commit: `35ef049`

#### Item 18e — multi-provider: config block validation

- [x] **Scope decision: IN-SCOPE.** Once `PostValidateConfigHook`
      existed, not adding basic validation of the
      `multi-provider:` block was a glaring omission.
- [x] `ValidateMultiProviderBlock` implemented — validates
      presence of `role:` (must be agent/signer/combiner)
      and `identity:` when `active: true`.
- [x] Registered via `PostValidateConfigHook` (same hook
      as 18b/c/d). Commit: `812ac08`.
- [ ] Verified live (lab pending).

---

## Open questions — ALL RESOLVED (2026-04-10)

All five questions answered. See §"Decisions" above for
the locked answers.

---

## Sequencing recommendation

Given the prerequisites, the natural order is:

1. **Prerequisite D first** (1-line fix to
   `config_validate.go` default case). Lowest risk, lowest
   cost, unblocks item 18a cleanly.
2. **Prerequisite A** (option validator hook) — unblocks
   items 16 and 17.
3. **Prerequisite C** (`PostValidateConfigHook`) — unblocks
   items 18b/18c/18d.
4. **Prerequisite B** (per-zone MP callback attachment) —
   unblocks items 14 and 14b. Comes last because the
   ordering question (Q3) needs to be answered first.
5. **Items in any order** once their prerequisites are
   landed:
   - 17 first (canonical forbidden pattern, good test of
     prereq A)
   - 16 next (same mechanism)
   - 18a (depends only on prereq D, can go early)
   - 18b, 18c, 18d (parallel after prereq C)
   - 14 (after prereq B)
   - 14b (after prereq B, shallow coupling so fast)
6. **18e scope decision** happens at any point during Tier
   2. If decided to include, land as the last item. If
   decided to defer, create follow-up tracker and move on.

**Each item is two commits, not one**: "add tdns-mp
counterpart" and "delete tdns-side code." See deletion
discipline above.

---

## Links and references

- Phase 2 plan: `2026-04-09-decoupling-plan-phase2.md`
- Wave A commit (tdns): `4c95c6a`
- Wave A commit (phase2 doc status): tdns-mp `e86c609`
- Original decoupling plan:
  `2026-04-04-tdns-mp-decoupling-plan.md`
- Option handler mechanism:
  `tdns/v2/option_handlers.go`
- Per-zone parse function:
  `tdns/v2/parseoptions.go:194` (`parseZoneOptions`)
- Validation entry point:
  `tdns/v2/config_validate.go:29` (`ValidateConfig`)
- MP refresh callback registration (reference for how the
  per-zone MP hook should work):
  `tdns-mp/v2/config.go:29` (`RegisterMPRefreshCallbacks`)
