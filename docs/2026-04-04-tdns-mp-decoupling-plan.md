# Decoupling Plan: Migrate MP-Gated Code from tdns to tdns-mp

**Date**: 2026-04-04
**Status**: Planning (revised after discussion)
**Goal**: Remove all `AppTypeMP*` gates and MP-specific code
paths from tdns. The constants `AppTypeMPAgent`,
`AppTypeMPSigner`, `AppTypeMPCombiner` stay as registered
enum values in tdns, but tdns code must not branch on them.
MP apps are responsible for their own initialization, just
like tdns-nm and tdns-es.

## Guiding Principles

tdns is a DNS infrastructure library. Apps built on top of
it must handle their own setup. Adding a new external app
should **never** require a pull request to tdns to wire in
new guards or code paths.

**Safety rule**: The MP apps (mpagent, mpsigner, mpcombiner)
must keep working throughout this migration. For every gate
removed from tdns, **first** ensure that tdns-mp already has
its own equivalent code, **then** remove the gate. Never
remove first and add later — the apps must not break.

---

## Inventory of MP Gates in tdns

### 1. MainInit — Flag Parsing & Startup Message

**File**: main_initfuncs.go:108-130

MP types listed in "all known app types" switch for flag
parsing and startup banner.

**Verdict**: **Keep.** This enumerates known types to
distinguish valid from invalid. The default case is an error
return. Unavoidable and harmless.

---

### 2. MainInit — KeyDB Initialization

**File**: main_initfuncs.go:141-154

```go
case AppTypeAuth, AppTypeAgent, AppTypeScanner,
     AppTypeMPSigner, AppTypeMPAgent, AppTypeMPCombiner,
     AppTypeMPAuditor:
    conf.InitializeKeyDB()
```

**Verdict**: **Remove MP types from this gate.** First
ensure tdns-mp's `MainInit` calls `InitializeKeyDB()`
itself, then remove the MP types from this switch. Only
tdns's own apps that need a KeyDB should be listed here.

**Implementation**: See Task E in `2026-04-04-implementation-plan.md`.

---

### 3. MainInit — MsgQs Creation

**File**: main_initfuncs.go:207-224

Creates `conf.Internal.MsgQs` unconditionally.

**Verdict**: **Move to tdns-mp.** MsgQs is MP-only. tdns-mp
already has its own `NewMsgQs()` but doesn't use it yet.
Remove from tdns MainInit. Update tdns-mp to use its local
MsgQs. (If non-legacy tdns code still references
`conf.Internal.MsgQs`, defer until those references are
cleaned up.)

---

### 4. MainInit — OptMultiProvider Zone Option Handler

**File**: main_initfuncs.go:241-243

Registers a handler that collects MP zone names during
ParseZones.

**Verdict**: **Move to tdns-mp.** tdns-mp registers this
handler in its own MainInit, before calling
`conf.ParseZones()`. The `RegisterZoneOptionHandler` API
stays in tdns (it's a general registration mechanism).

**Implementation**: See Task C in `2026-04-04-implementation-plan.md`.

---

### 5. MainInit — Commented-Out Agent/Signer/Combiner Init

**File**: main_initfuncs.go:266-688

Large commented-out `/* ... */` blocks for AppTypeAgent,
AppTypeAuth (signer), and combiner initialization.

**Verdict**: **Verify, then delete.** These blocks were
commented out during migration. Before deleting, verify
that every piece of code in them has been migrated to
tdns-mp's `main_init.go`. Once verified, delete. Do NOT
delete before verification.

---

### 6. StartCombiner — Commented Out Entirely

**File**: main_initfuncs.go:691-803

Entire `StartCombiner` function inside `/* ... */`.

**Verdict**: **Verify, then delete.** Same as item 5.

---

### 7. StartAuth — Commented-Out MP Signer Engines

**File**: main_initfuncs.go:850-877

Commented-out `!= AppTypeMPSigner` block.

**Verdict**: **Delete.** tdns-mp's `StartMPSigner` calls
`StartAuth()` then adds its own SignerMsgHandler and
KeyStateWorker. This dead code can go.

**Implementation**: See Task A in `2026-04-04-implementation-plan.md`.

---

### 8. StartAgent — Already Clean

**File**: main_initfuncs.go:881-908

No MP gates remain. Comment says MP engines moved to
tdns-mp.

**Verdict**: **No action.**

---

### 9. ParseConfig — DNSSEC Policies Initialization

**File**: parseconfig.go:268-275

```go
case AppTypeAuth, AppTypeAgent,
     AppTypeMPSigner, AppTypeMPAgent, AppTypeMPAuditor:
    // init DnssecPolicies
```

**Verdict**: **Remove MP types from gate — but only after
tdns-mp does its own init.** First add DNSSEC policy
initialization to tdns-mp startup code, then remove the
MP types from this switch.

**Implementation**: See Task F in `2026-04-04-implementation-plan.md`.

---

### 10. ParseConfig — Auth Options Parsing

**File**: parseconfig.go:335-339

```go
case ..., AppTypeMPSigner, AppTypeMPAgent,
     AppTypeMPCombiner, AppTypeMPAuditor:
    conf.parseAuthOptions()
```

**Verdict**: **Remove MP types from gate — but only after
tdns-mp calls it.** Export `parseAuthOptions` as
`ParseAuthOptions()`. First ensure tdns-mp startup code
actually calls `ParseAuthOptions()`, then remove the MP
types from this switch.

**Implementation**: See Task D in `2026-04-04-implementation-plan.md`.

---

### 11. ParseConfig — KeyDB Init on Config Load

**File**: parseconfig.go:347-354

**Verdict**: **Remove MP types from gate — but only after
tdns-mp handles it.** First ensure tdns-mp apps do their
own KeyDB init, then remove the MP types from this switch.
Same reasoning as item 2.

**Implementation**: See Task E in `2026-04-04-implementation-plan.md`.

---

### 12. ParseConfig — DB File Auto-Create

**File**: parseconfig.go:417-444

Two parts:

**(a)** Lines 417-430: Auto-creation of DB file and parent
directory, gated on app types including MP types.

**Verdict**: **Remove MP types from gate — but only after
tdns-mp handles it.** `InitializeKeyDB()` already handles
file creation + `NewKeyDB()` as a single function. The
internal app-type gate should be removed; callers decide
whether to call the function.

**Implementation**: Merged into Task E in
`2026-04-04-implementation-plan.md` (was Task G, now
part of E).

**(b)** Lines 438-444: `OutgoingSerials` table creation,
currently inside `InitHsyncTables()`.

**Verdict**: **Move OutgoingSerials schema out of
HsyncTables.** This table is generally useful (persists
outgoing SOA serials across restarts) and should stay in
tdns, but `HsyncTables` will migrate to tdns-mp. Move the
`OutgoingSerials` CREATE TABLE to a general-purpose DB
schema location in tdns (e.g. `InitCoreTables` or similar).

**Implementation**: See Task H in `2026-04-04-implementation-plan.md`.

---

### 13. ParseZones — MP Pre/Post Refresh Callbacks

**File**: parseconfig.go:726-729

```go
if zdp.FirstZoneLoad && options[OptMultiProvider] {
    zdp.OnZonePreRefresh = append(..., MPPreRefresh)
    zdp.OnZonePostRefresh = append(..., MPPostRefresh)
}
```

**Verdict**: **Investigate, likely remove.** tdns-mp already
registers its own versions via `RegisterMPRefreshCallbacks`.
If `MPPreRefresh`/`MPPostRefresh` are defined in legacy
files, they'll go when legacy is deleted. Check for double
registration.

---

### 14. ParseZones — MP Inline Signing OnFirstLoad

**File**: parseconfig.go:751-759

Registers signing callback for MP zones on signer-type apps.

**Verdict**: **Needs investigation.** Check whether tdns-mp
already handles MP zone signing setup. If yes, remove from
tdns. If no, move to tdns-mp (e.g. in a callback
registration function).

---

### 14b. ParseZones — MP Zone Parsing (lines 697-719)

**File**: parseconfig.go:697-719

Population of `zdp.MP.MPdata` struct, MP zone option
handling, and related MP-specific zone parsing logic.

**Verdict**: **CRITICAL — must migrate to tdns-mp.** This
code must not be forgotten. It should be part of a tdns-mp
second-pass zone parsing loop (see "ParseZones Strategy"
section below).

---

### 15. ParseZones — MP KEY Publication OnFirstLoad

**File**: parseconfig.go:810-846

Sends SIG(0) KEY to combiner on zone first-load via
`conf.Internal.MPTransport`.

**Verdict**: **Needs investigation.** Check execution order:
does `MPTransport` exist when ParseZones runs during
MainInit? If nil at that point, this code is dead for MP
apps. Likely move to tdns-mp's OnFirstLoad callback
registration.

---

### 16. parseoptions.go — OptMultiProvider Validation

**File**: parseoptions.go:256-269

Validates that signer (AppTypeAuth) has server-level MP
config when OptMultiProvider is set.

**Verdict**: **Move to tdns-mp.** tdns should mostly ignore
OptMultiProvider beyond knowing the constant exists.
Implement a tdns-mp `ParseZoneOptions()` that handles
MP-specific option validation, and move this logic there.

---

### 17. parseoptions.go — OptMPManualApproval Validation

**File**: parseoptions.go:345-357

Validates that mp-manual-approval is only set on combiner.

**Verdict**: **Move to tdns-mp** as part of implementing the
tdns-mp `ParseZoneOptions()` (same function as item 16).

---

### 18. config_validate.go — Config Section Validation

**File**: config_validate.go:50-67

MP types in "apps that validate service/db/apiserver/
dnsengine sections" list.

**Verdict**: **Move to tdns-mp.** Build config validation
infrastructure in tdns-mp. Note: the existing tdns
`ValidateConfig` completely forgets the `multi-provider:`
config block. MP config validation should be in tdns-mp,
not tdns.

Specific validation functions that are MP-only and should
migrate:
- `ValidateAgentNameservers()`
- `ValidateAgentSupportedMechanisms()`
- `ValidateCryptoFiles()`

---

### 19. config_validate.go — Database File Requirement

**File**: config_validate.go:330-341

`ValidateDatabaseFile()` has internal gate on app types.

**Verdict**: **Move gate to callers.** The function itself
should not check app types — callers decide whether to call
it. tdns apps call it where needed. Ensure that tdns-mp apps
call it from their own validation.

**Implementation**: See Task I in `2026-04-04-implementation-plan.md`.

---

### 20. apirouters.go — Keystore/Truststore/Dsync Endpoints

**File**: apirouters.go:104-106

MP types in the list of apps that register keystore,
truststore, zone/dsync endpoints.

**Verdict**: **Remove MP types from gate — but only after
tdns-mp registers equivalents.** First implement tdns-mp
registration of these endpoints (keystore, truststore,
zone/dsync) using the existing API route registration
mechanism. Then remove the MP types from the tdns gate.

**Implementation**: See Task J in `2026-04-04-implementation-plan.md`.

---

### 21. keys_cmd.go — JOSE Key Path Lookup

**File**: keys_cmd.go:140-166

`getKeysPrivKeyPath()` has cases for AppTypeAgent and
AppTypeMPCombiner only.

**Verdict**: **Leave where it is, fix the code.** The
function doesn't handle AppTypeMPAgent or AppTypeMPSigner.
The key path is the same for all MP app types
(`conf.MultiProvider.LongTermJosePrivKey`), so this is a
trivial fix: add the missing cases.

**Implementation**: See Task B in `2026-04-04-implementation-plan.md`.

---

### 22. sign.go — MP Multi-Signer DNSKEY Handling

**File**: sign.go:243, 363

Guards on OptMultiProvider and OptMultiSigner for DNSKEY
handling modes (modes 2-4).

**Verdict**: **Leave for now.** Deeply integrated with the
signing pipeline. Revisit when/if the signing engine gets
modularized.

---

### 23. resigner.go — Skip MP Zones

**File**: resigner.go:76

```go
if zd.Options[OptMultiProvider] && ... NOSIGN ...
```

**Verdict**: **Leave for now, add comment.** The likely best
untangling approach: instead of checking OptMultiProvider +
weAreSigner() each time, the MP code should remove
non-qualifying zones from the ZonesToKeepSigned list (or
better: never add them). Add a comment noting this.

---

### 24. keystore.go — DnskeyStateMpremove

**File**: keystore.go:469

**Verdict**: **Leave for now.** Complicated DNSSEC engine
integration.

---

### 25. key_state_worker.go — MP State Checks

**File**: key_state_worker.go:181, 213, 224

**Verdict**: **Needs investigation, then split.** We will
likely need separate KeyStateWorker goroutines in tdns and
tdns-mp (MP has extra complexity). The tdns KeyStateWorker
must run ONLY for AppTypeAuth (the only tdns app with key
rollover logic). tdns-mp starts its own version for MP apps.

Need a mechanism to ensure the tdns KeyStateWorker does not
start for MP apps (e.g. gate its startup in StartAuth on
`!= AppTypeMPSigner`, or have tdns-mp suppress it).

---

### 26. delegation_sync.go — MP Zone DNSKEY Sync (line 169)

**File**: delegation_sync.go:169

**Verdict**: **Leave for now, needs later analysis.** I don't
fully understand what this code does yet. Mark for future
investigation.

---

### 26b. delegation_sync.go — notifyPeersParentSyncDone()

**File**: delegation_sync.go

MP-only function that references TransportManager,
PeerRegistry, etc. — all of which will disappear from tdns.

**Verdict**: **Must migrate to tdns-mp.** The caller is
`DelegationSyncher()` itself, which also references
`LeaderElectionManager`. This means we need a separate
DelegationSyncher in tdns-mp, or (preferred) restructure
the existing one.

**Proposed approach**: Replace the core of
`DelegationSyncher()` (lines 36-194) with a call to a
pluggable handler function. Add support for registering
a different handler. This follows the same pattern already
used for NOTIFY handlers and query handlers. tdns registers
a default handler for its own delegation sync; tdns-mp
registers one that includes LeaderElectionManager checks
and peer notification.

---

### 27. apihandler_agent.go — Almost Entirely MP-Only

**File**: apihandler_agent.go

The `/agent` endpoint handled by `APIagent()` multiplexes
many sub-commands. ~95% are MP-only, but a few (config, imr)
are also relevant for the plain tdns agent.

**Verdict**: **Split the /agent endpoint.** The monolithic
`/agent` handler must be split into multiple endpoints:

- `/agent` — tdns handles core commands (config, imr)
- `/agent/hsync` — tdns-mp registers for HSYNC commands
- `/agent/gossip` — tdns-mp registers for gossip commands
- `/agent/peer` — tdns-mp registers for peer commands
- `/agent/update` — tdns-mp registers for addrr/delrr
- etc.

This is a restructuring effort. tdns-mp already has its own
`apihandler_agent.go` — wire it to the new sub-endpoints.

**Note**: The endpoint split requires corresponding changes
in the CLI clients. Both the tdns CLI (`tdns-cli agent ...`)
and the tdns-mp CLIs (`mpcli agent ...`, `mpcli signer ...`,
`mpcli combiner ...`) must be updated to use the new
endpoint paths.

---

### 28. apihandler_zone.go — list-mp-zones

**File**: apihandler_zone.go:192-210

The `list-mp-zones` sub-command requires access to MP data
that will disappear from tdns.

**Verdict**: **Move to new endpoint /zone/mplist.** Register
the handler for `/zone/mplist` from tdns-mp.

**Note**: Requires corresponding changes in the CLI clients
(`mpcli agent ...`, `mpcli signer ...`, `mpcli combiner ...`)
to call `/zone/mplist` instead of `/zone` with the
`list-mp-zones` sub-command.

---

### 29. structs.go — ZoneMPExtension & EnsureMP

**File**: structs.go:81-267

ZoneData carries MP state via `zd.MP` field typed as
`*ZoneMPExtension`.

**Verdict**: **Future work.** Replace `zd.MP` with a generic
`zd.AppData interface{}` field. Move `ZoneMPExtension`
definition and all its getters/setters/types to tdns-mp.
tdns-mp casts `zd.AppData` to `*ZoneMPExtension` when
needed. Big structural change — do later, but the plan is
clear.

---

## ParseZones Strategy

ParseZones() is critical and has MP details in many corners.
The recommended approach:

1. **tdns ParseZones()** — does basic zone identification
   and parsing as far as tdns understands. Sets up zone
   stubs, options, refresh configuration. No MP-specific
   logic.

2. **tdns-mp second pass** — a tdns-mp function (e.g.
   `ParseMPZones()` or `PostParseZones()`) loops through
   all zones and handles:
   - MP zone option validation (items 16, 17)
   - `zdp.MP.MPdata` population (item 14b, **critical**)
   - OnFirstLoad callback registration (items 13, 14, 15)
   - Pre/Post refresh callback registration
   - Any other MP-specific zone setup

This is analogous to how tdns-mp already calls
`RegisterMPRefreshCallbacks()` after `ParseZones()`.

**Action**: After the first round of migration, do a
thorough second pass through `ParseZones()` to find and
extract any remaining MP-specific logic.

---

## Summary: What to Do

### Immediate (safe, mechanical)

1. **Delete commented-out dead code** (items 7) — the
   signer engine block in StartAuth.

2. **Verify then delete** (items 5, 6) — the large
   commented-out blocks in MainInit and StartCombiner.
   Verify each piece against tdns-mp before deleting.

### Remove MP Gates from tdns (add-first, remove-second)

For each item below: **first** add the equivalent call to
tdns-mp startup code, verify the MP apps still work, **then**
remove the MP types from the tdns gate.

3. **Remove AppTypeMP* from switch cases** in:
   - KeyDB initialization (items 2, 11, 12a — all covered
     by Task E; `InitializeKeyDB()` handles file creation
     + NewKeyDB as one function)
   - DNSSEC policies (item 9)
   - Auth options parsing (item 10) — export as
     `ParseAuthOptions()`
   - API route registration (item 20)

   For each: MP apps call the function themselves from
   tdns-mp startup code.

### Move MP-Specific Code to tdns-mp

4. **MsgQs creation** (item 3) — remove from tdns, use
   tdns-mp's local MsgQs.

5. **OptMultiProvider handler registration** (item 4) —
   move to tdns-mp MainInit.

6. **Config validation** (items 18, 19) — build tdns-mp
   validation infrastructure. Move
   `ValidateAgentNameservers()`,
   `ValidateAgentSupportedMechanisms()`,
   `ValidateCryptoFiles()` to tdns-mp. Make
   `ValidateDatabaseFile()` caller-gated.

7. **Zone option validation** (items 16, 17) — create
   tdns-mp `ParseZoneOptions()`.

8. **MP zone parsing** (item 14b) — create tdns-mp
   second-pass zone parsing for MPdata population.
   **Critical — do not lose this.**

9. **list-mp-zones** (item 28) — move to `/zone/mplist`,
   register from tdns-mp.

### Restructuring

10. **Split /agent endpoint** (item 27) — separate
    sub-endpoints for tdns core vs MP-specific commands.

11. **DelegationSyncher handler registration** (item 26b)
    — replace core with pluggable handler. tdns-mp
    registers handler with LeaderElection + peer
    notification.

12. **OutgoingSerials table** (item 12b) — move schema
    out of HsyncTables into general-purpose tdns DB
    schema.

### Investigation Required

13. **MP OnFirstLoad callbacks** (items 13, 14, 15) —
    check for double registration, execution order,
    whether tdns-mp already covers these.

14. **KeyStateWorker split** (item 25) — design mechanism
    for tdns-mp to run its own and suppress tdns's.

15. **delegation_sync.go line 169** (item 26) — later
    analysis needed to understand.

16. **Second pass through ParseZones()** — after first
    round of changes, comprehensive audit for remaining
    MP logic.

### Future Work

17. **zd.MP → zd.AppData interface{}** (item 29) — replace
    typed MP field with generic extension point.

18. **Signing engine MP awareness** (items 22, 23, 24) —
    revisit when signing engine gets modularized. For
    item 23 (resigner), the preferred approach is to
    manage the ZonesToKeepSigned list rather than checking
    OptMultiProvider at resign time.

19. **keys_cmd.go** (item 21) — fix broken
    getKeysPrivKeyPath (missing MPAgent/MPSigner cases).

---

## Investigation Checklist

Before implementing, answer these questions:

- [ ] Is `conf.Internal.MsgQs` used in any non-legacy,
      non-commented-out tdns code?
- [ ] Are `MPPreRefresh`/`MPPostRefresh` defined in
      non-legacy tdns code, or only in legacy files?
- [ ] Does tdns-mp register signing callbacks for MP zones
      (covering item 14)?
- [ ] Does the KEY publication OnFirstLoad (item 15)
      actually fire for MP apps? (Is MPTransport set when
      ParseZones runs?)
- [ ] Which tdns KeyStateWorker code runs for
      AppTypeMPSigner vs tdns-mp's KeyStateWorker?
- [ ] What non-legacy, non-commented-out tdns code
      references types from `mptypes.go`/`mpmethods.go`?
- [ ] Verify all commented-out code in items 5+6 is
      migrated to tdns-mp before deleting.
- [ ] What does delegation_sync.go:169 actually do?
