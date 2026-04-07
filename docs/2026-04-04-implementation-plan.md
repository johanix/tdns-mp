# Implementation Plan: MP Decoupling — Ready Items

**Date**: 2026-04-04
**Parent doc**: `2026-04-04-tdns-mp-decoupling-plan.md`
**Scope**: Only items that are sufficiently well understood.
Items marked "investigate", "later", or "future work" in the
decoupling plan are excluded.

**Safety rule**: For every gate removed from tdns, first
ensure tdns-mp has its own equivalent, then remove the gate.

---

## Task A: Delete Commented-Out Signer Engines

**Decoupling item**: 7
**Risk**: None — dead code deletion
**Repos**: tdns only

### What to do

Delete the commented-out MP signer engine block in
`tdns/v2/main_initfuncs.go` lines 850-877. This code is
inside `//` comments and is dead. tdns-mp's `StartMPSigner`
already calls `StartAuth()` then starts its own
`SignerMsgHandler` and `KeyStateWorker`.

### Steps

1. In `tdns/v2/main_initfuncs.go`, delete lines 850-877
   (the `// MP signer engines` commented-out block and the
   `// Start signer sync API router` commented-out block).
2. Build tdns: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
3. Build tdns-mp: `cd tdns-mp && make`

---

## Task B: Fix keys_cmd.go for All MP Types

**Decoupling item**: 21
**Risk**: Trivial — adding switch cases
**Repos**: tdns only

### What to do

`getKeysPrivKeyPath()` in `tdns/v2/keys_cmd.go` only handles
`AppTypeAgent` and `AppTypeMPCombiner`. Add
`AppTypeMPAgent` and `AppTypeMPSigner` — they all use the
same path: `conf.MultiProvider.LongTermJosePrivKey`.

Also update `printKeysUsage()` to handle the new types.

### Steps

1. In `getKeysPrivKeyPath()`, add cases for
   `AppTypeMPAgent` and `AppTypeMPSigner` returning
   `conf.MultiProvider.LongTermJosePrivKey`.
2. In `printKeysUsage()`, extend the conditional to map
   `AppTypeMPAgent` → `"tdns-mpagent"` and
   `AppTypeMPSigner` → `"tdns-mpsigner"`.
3. Run `gofmt -w tdns/v2/keys_cmd.go`
4. Build tdns.

---

## Task C: Move OptMultiProvider Handler to tdns-mp

**Decoupling item**: 4
**Risk**: Low — registration moves, API stays
**Repos**: tdns (remove), tdns-mp (add)

### What to do

The `RegisterZoneOptionHandler(OptMultiProvider, ...)` call
in `tdns/v2/main_initfuncs.go:241-243` collects MP zone
names during ParseZones. Move this registration to tdns-mp's
`MainInit`, before the call to `conf.Config.MainInit()` (so
it's registered before ParseZones runs).

### Current code in tdns (main_initfuncs.go:236-243)

```go
RegisterZoneOptionHandler(OptMultiProvider,
    func(zname string, options map[ZoneOption]bool) {
        conf.Internal.MPZoneNames = append(
            conf.Internal.MPZoneNames, zname)
    })
```

### Steps

1. **tdns-mp** (`v2/main_init.go`): Before the call to
   `conf.Config.MainInit(ctx, defaultcfg)`, add:
   ```go
   tdns.RegisterZoneOptionHandler(tdns.OptMultiProvider,
       func(zname string, options map[tdns.ZoneOption]bool) {
           conf.Config.Internal.MPZoneNames = append(
               conf.Config.Internal.MPZoneNames, zname)
       })
   ```
2. **tdns** (`v2/main_initfuncs.go`): Remove lines 236-243
   (the `RegisterZoneOptionHandler` call and its preceding
   comments).
3. Build both repos.
4. Test: start mpagent, verify MP zones are discovered
   (check log for "multi-provider zones from config").

### Note

`RegisterZoneOptionHandler` and `OptMultiProvider` stay
exported from tdns. Only the call site moves.

---

## Task D: Export ParseAuthOptions

**Decoupling item**: 10
**Risk**: Low — rename + add call
**Repos**: tdns (export), tdns-mp (add call)

### What to do

`parseAuthOptions()` in `tdns/v2/parseoptions.go` is
unexported. Export it as `ParseAuthOptions()`. Then add a
call in tdns-mp's MainInit and remove `AppTypeMP*` from the
gate in tdns.

### Steps

1. **tdns** (`v2/parseoptions.go`): Rename
   `func (conf *Config) parseAuthOptions()` to
   `func (conf *Config) ParseAuthOptions()`.
2. **tdns** (`v2/parseconfig.go`): Update the call site
   at line 337 from `conf.parseAuthOptions()` to
   `conf.ParseAuthOptions()`.
3. **tdns-mp** (`v2/main_init.go`): In `MainInit`, after
   the call to `conf.Config.MainInit(ctx, defaultcfg)`,
   add:
   ```go
   conf.Config.ParseAuthOptions()
   ```
4. **tdns** (`v2/parseconfig.go:335-339`): Remove the MP
   types from the switch case, leaving only:
   ```go
   case AppTypeAuth, AppTypeAgent:
       conf.ParseAuthOptions()
   ```
5. Run `gofmt -w` on all changed files.
6. Build both repos.
7. Test: start mpagent, verify auth options are parsed
   (check log for auth option messages).

---

## Task E: tdns-mp Owns KeyDB Initialization

**Decoupling items**: 2, 11, 12a
**Risk**: Low — add call before removing gate
**Repos**: tdns (remove gates), tdns-mp (add call)

### What to do

`InitializeKeyDB()` is a single function that handles
the entire KeyDB setup: path validation, file/directory
creation, `NewKeyDB()` call, and OutgoingSerials table
setup. It is called from two places in tdns, both gated
on app types that include MP types:

1. `ParseConfig` (primary, on first load, `!reload` guard)
2. `MainInit` (defensive fallback, `kdb == nil` guard)

tdns-mp should call `InitializeKeyDB()` itself. Then
remove MP types from both gates. No extraction or
restructuring needed — the function already does
everything.

### Steps

1. **tdns-mp** (`v2/main_init.go`): After the call to
   `conf.Config.MainInit(ctx, defaultcfg)`, add:
   ```go
   if err := conf.Config.InitializeKeyDB(); err != nil {
       return fmt.Errorf("error initializing KeyDB: %v", err)
   }
   ```
   No nil guard needed — tdns will no longer init KeyDB
   for MP types, so this is the sole init path.
2. **tdns** (`v2/main_initfuncs.go:141-154`): Remove MP
   types from the switch, leaving:
   ```go
   case AppTypeAuth, AppTypeAgent, AppTypeScanner:
       ...
   ```
3. **tdns** (`v2/parseconfig.go:347-354`): Remove MP types
   from the switch, leaving:
   ```go
   case AppTypeAuth, AppTypeAgent:
       ...
   ```
4. **tdns** (`v2/parseconfig.go`, inside
   `InitializeKeyDB`): Remove the app-type switch that
   wraps the file-creation + NewKeyDB block. The function
   should unconditionally do its work — callers decide
   whether to call it. (The path validation and security
   checks before the switch already apply to all callers.)
5. Build both repos.
6. Test: start mpagent, verify KeyDB is initialized
   (check log for KeyDB messages).

### Note

Task H (OutgoingSerials) should land before or with this
task, since `InitializeKeyDB` references
`HsyncTables["OutgoingSerials"]` which Task H moves to
`DefaultTables`.

---

## Task F: tdns-mp Owns DNSSEC Policy Initialization

**Decoupling item**: 9
**Risk**: Low — add call before removing gate
**Repos**: tdns (remove gate), tdns-mp (add call)

### What to do

The DNSSEC policies init in `parseconfig.go:268-275` is
gated on app types including MP types. tdns-mp should do
its own init.

### Steps

1. **tdns-mp** (`v2/main_init.go`): After the call to
   `conf.Config.MainInit(ctx, defaultcfg)`, add:
   ```go
   if conf.Config.Internal.DnssecPolicies == nil {
       conf.Config.Internal.DnssecPolicies =
           make(map[string]tdns.DnssecPolicy)
   }
   for name, dp := range conf.Config.DnssecPolicies {
       conf.Config.Internal.DnssecPolicies[name] = dp
   }
   ```
   (Check exact field names against parseconfig.go:268-275.)
2. **tdns** (`v2/parseconfig.go:268-275`): Remove MP types
   from the switch, leaving:
   ```go
   case AppTypeAuth, AppTypeAgent:
       ...
   ```
3. Build both repos.
4. Test: start mpsigner (which needs DNSSEC policies),
   verify signing works.

### Note

Need to verify that `DnssecPolicy` type and
`DnssecPolicies` field are exported. If not, export them.

---

## ~~Task G: Move DB File Auto-Create Gate to Callers~~

**Merged into Task E.** `InitializeKeyDB()` already handles
file creation + `NewKeyDB()` as a single function. No need
for a separate `EnsureDatabaseFile` extraction. Task E now
covers removing the internal app-type gate from
`InitializeKeyDB()` and having callers decide whether to
call it.

---

## Task H: Move OutgoingSerials Out of HsyncTables

**Decoupling item**: 12b
**Risk**: Low — schema reorganization
**Repos**: tdns, tdns-mp

### What to do

The `OutgoingSerials` CREATE TABLE is currently in the
`HsyncTables` map in `db_schema_hsync.go`. This table is
generally useful and should stay in tdns, but `HsyncTables`
will migrate to tdns-mp. Move the schema to
`DefaultTables` so that tdns creates it during general DB
init. tdns-mp's `InitCombinerEditTables` should not
initialize it.

### Current locations

- Schema definition: `db_schema_hsync.go:290-296`
  (in `HsyncTables` map)
- Table listed in combiner init: `db_schema_hsync.go:410`
  (in `InitCombinerEditTables` combinerTables list)
- Table listed in tdns-mp combiner init:
  `tdns-mp/v2/combiner_db_schema.go:26`
- Access functions: `db_outgoing_serial.go` (stays in tdns)
- Creation call: `parseconfig.go:438-444`

### Steps

1. In `tdns/v2/db_schema_hsync.go`, remove the
   `"OutgoingSerials"` entry from the `HsyncTables` map
   (lines 290-296).
2. In `tdns/v2/db_schema_hsync.go`, remove
   `"OutgoingSerials"` from the `combinerTables` list in
   `InitCombinerEditTables` (line 410). Without this,
   the function fails at runtime on the
   `HsyncTables[name]` lookup.
3. In `tdns/v2/db_schema.go`, add the `OutgoingSerials`
   schema to the existing `DefaultTables` map. tdns's
   general DB init iterates `DefaultTables` and creates
   each table — this is how the table gets created for
   tdns apps.
4. In `parseconfig.go:438-444`, update the reference from
   `HsyncTables["OutgoingSerials"]` to
   `DefaultTables["OutgoingSerials"]`.
5. In `tdns-mp/v2/combiner_db_schema.go`, remove
   `"OutgoingSerials"` from the combiner tables list
   (line 26). tdns-mp runs `InitCombinerEditTables` for
   combiner-specific tables; OutgoingSerials is no longer
   one of them.
6. `db_outgoing_serial.go` stays unchanged.
7. Build both repos.

---

## Task I: Caller-Gate ValidateDatabaseFile

**Decoupling item**: 19
**Risk**: Low — restructure validation
**Repos**: tdns (simplify), tdns-mp (add call)

### What to do

`ValidateDatabaseFile()` in `config_validate.go:330-341`
has an internal app-type gate. Remove the gate from the
function; callers decide whether to call it.

### Steps

1. **tdns** (`v2/config_validate.go`): Remove the
   `switch Globals.App.Type` from inside
   `ValidateDatabaseFile()`. The function should just
   validate and return error if `db.file` is empty.
2. **tdns** (caller): Wrap the call to
   `ValidateDatabaseFile()` in the caller with the
   appropriate app-type check for tdns apps only:
   ```go
   switch Globals.App.Type {
   case AppTypeAuth, AppTypeAgent, AppTypeScanner:
       if err := ValidateDatabaseFile(config); err != nil {
           ...
       }
   }
   ```
3. **tdns-mp** (`v2/main_init.go` or validation code):
   Call `tdns.ValidateDatabaseFile(conf.Config)` from
   tdns-mp's own validation path.
4. Build both repos.

---

## Task J: Move API Route Registration to tdns-mp

**Decoupling item**: 20
**Risk**: Low — routes already registered by tdns-mp
**Repos**: tdns (remove gate), tdns-mp (add routes)

### What to do

`apirouters.go:104-110` gates registration of `/keystore`,
`/truststore`, `/zone/dsync`, and `/delegation` endpoints
on AppTypeMP* types. tdns-mp already has `SetupMPAgentRoutes`,
`SetupMPCombinerRoutes`, and `SetupMPSignerRoutes` that
register routes via direct `HandleFunc` calls on the mux
router. Add these four endpoints to the appropriate
`SetupMP*Routes()` functions, then remove the AppTypeMP*
types from the gate in tdns.

### Current gate in tdns (apirouters.go:104-110)

```go
if Globals.App.Type == AppTypeAuth ||
   Globals.App.Type == AppTypeAgent ||
   Globals.App.Type == AppTypeMPSigner ||
   Globals.App.Type == AppTypeMPAgent ||
   Globals.App.Type == AppTypeMPAuditor {
    sr.HandleFunc("/keystore", kdb.APIkeystore(conf)).Methods("POST")
    sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
    sr.HandleFunc("/zone/dsync", APIzoneDsync(...)).Methods("POST")
    sr.HandleFunc("/delegation", APIdelegation(...)).Methods("POST")
}
```

### Steps

1. **tdns-mp**: Add `ctx context.Context` parameter to all
   `SetupMP*Routes` signatures. All callers already have
   `ctx` available but don't pass it today:
   - `SetupMPAgentRoutes(ctx, apirouter)` — called from
     `cmd/mpagent/main.go` (has `ctx` from
     `signal.NotifyContext`)
   - `SetupMPSignerRoutes(ctx, apirouter)` — called from
     `start_signer.go` (receives `ctx` parameter)
   - `SetupMPCombinerRoutes(ctx, apirouter)` — called from
     `start_combiner.go` (receives `ctx` parameter)
   Update all call sites to pass `ctx`.
2. **tdns-mp**: Add an empty `SetupMPAuditorRoutes`
   placeholder:
   ```go
   func (conf *Config) SetupMPAuditorRoutes(
       ctx context.Context, apirouter *mux.Router) {
       // MPAuditor routes — future work.
   }
   ```
3. **tdns** (`v2/apihandler_funcs.go`): Add a nil guard
   for the `delsyncq` channel in `APIdelegation`. The
   "status" and "sync" commands send directly to
   `delsyncq` with no check — this panics if nil. Add
   a guard before the send:
   ```go
   if delsyncq == nil {
       resp.Error = true
       resp.ErrorMsg = "delegation sync not available"
       return
   }
   ```
   Currently only mpagent initializes
   `DelegationSyncQ`; the nil guard protects mpsigner
   and mpauditor until the DelegationSyncher is
   restructured in a later issue.
4. **tdns-mp**: Add the four `HandleFunc` registrations
   to `SetupMPAgentRoutes` and `SetupMPSignerRoutes`:
   ```go
   kdb := conf.Config.Internal.KeyDB
   sr.HandleFunc("/keystore",
       kdb.APIkeystore(conf.Config)).Methods("POST")
   sr.HandleFunc("/truststore",
       kdb.APItruststore()).Methods("POST")
   sr.HandleFunc("/zone/dsync",
       tdns.APIzoneDsync(ctx, &tdns.Globals.App,
           conf.Config.Internal.RefreshZoneCh,
           kdb)).Methods("POST")
   sr.HandleFunc("/delegation",
       tdns.APIdelegation(
           conf.Config.Internal.DelegationSyncQ,
       )).Methods("POST")
   ```
   The handler functions are all exported from tdns.
   `DelegationSyncQ` may be nil for mpsigner — the nil
   guard added in step 3 handles this safely.
5. **tdns** (`v2/apirouters.go`): Remove the MP types
   from the gate, leaving only:
   ```go
   if Globals.App.Type == AppTypeAuth ||
      Globals.App.Type == AppTypeAgent {
   ```
6. Build both repos.
7. Test: start mpagent, verify `/keystore`,
   `/truststore`, `/zone/dsync`, `/delegation` endpoints
   respond.

---

## Recommended Implementation Order

Start with the easiest, lowest-risk items first. Each builds
confidence for the next.

| Order | Task | Risk | Summary |
|-------|------|------|---------|
| 1 | **A** | None | Delete commented-out signer engines |
| 2 | **B** | Trivial | Fix keys_cmd.go for all MP types |
| 3 | **H** | Low | Move OutgoingSerials out of HsyncTables |
| 4 | **C** | Low | Move OptMultiProvider handler to tdns-mp |
| 5 | **D** | Low | Export ParseAuthOptions, add tdns-mp call |
| 6 | **E** | Low | tdns-mp owns KeyDB init (includes G) |
| 7 | **F** | Low | tdns-mp owns DNSSEC policy init |
| 8 | **I** | Low | ValidateDatabaseFile: gate in callers |
| 9 | **J** | Low | Move API route registration to tdns-mp |

**Rationale**: Tasks A-B are pure tdns changes with zero risk
of breaking MP apps. Task H is schema reorganization and
must land before E (which references OutgoingSerials).
Task G merged into E. Tasks C-J all follow the "add first,
remove second" pattern and touch both repos.

---

## Items NOT Planned Here (deferred)

These items from the decoupling plan need investigation or
are future work:

- **Item 3** (MsgQs): `conf.Internal.MsgQs` is actively
  used in `apihandler_agent.go` (13 call sites). Cannot
  remove until the /agent endpoint is split (item 27).
  Deferred.
- **Items 5, 6** (commented-out blocks): Need verification
  that all code is migrated before deletion.
- **Items 13, 14, 15** (ParseZones OnFirstLoad): Need
  investigation.
- **Item 14b** (MPdata population): Critical, needs
  ParseZones second-pass design.
- **Items 16, 17** (ParseZoneOptions): Need tdns-mp
  ParseZoneOptions() design.
- **Item 18** (config validation): Larger effort, needs
  design.
- **Item 20** (API route registration): Planned as Task J.
- **Items 22-24** (signing engine): Leave for now.
- **Item 25** (KeyStateWorker split): Needs investigation.
- **Items 26, 26b** (DelegationSyncher): Needs design.
- **Items 27, 28** (/agent split, /zone/mplist): Larger
  restructuring effort.
- **Item 29** (zd.AppData): Future work.
