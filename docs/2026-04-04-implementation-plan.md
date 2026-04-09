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

## Task F: Make DNSSEC Policy Initialization Unconditional

**Decoupling item**: 9
**Risk**: Low — remove app-type gate entirely
**Repos**: tdns only

### What to do

The DNSSEC policies init in `parseconfig.go:267-294`
must run before ParseZones, which validates each zone's
`dnssec_policy` reference against
`Internal.DnssecPolicies`. Both `ParseConfig` and
`ParseZones` run inside tdns's `MainInit`, so tdns-mp
cannot inject a per-app init between them. The fix is
to remove the app-type gate from the init block
entirely: it runs for every app that calls `ParseConfig`.

tdns-imr and tdns-cli end up with an empty
`Internal.DnssecPolicies` map plus the built-in "default"
policy. This is harmless — they never consult the map.

This is strictly more decoupled than the original gate:
tdns's `ParseConfig` has zero MP knowledge after this
change.

### Note on earlier plan

An earlier version of this task had tdns-mp do its own
DNSSEC policy init in `main_init.go` after
`conf.Config.MainInit()` returned. That approach was
incorrect: by the time `MainInit` returns, `ParseZones`
has already run and logged zone errors for unresolved
`dnssec_policy` references. The initialization must
happen before `ParseZones`, which means inside
`ParseConfig`. The regression was caught on the test
lab by observing `mpsigner` refusing to sign zones with
messages like "DNSSEC policy "" does not exist".

### Steps

1. **tdns** (`v2/parseconfig.go`): Remove the
   `switch Globals.App.Type { case AppTypeAuth,
   AppTypeAgent: ... }` wrapper around the DNSSEC
   policy init block. The block runs unconditionally.
2. **tdns**: `BuiltinDefaultDnssecPolicy()` is already
   exported from Task F (first iteration). Leave it
   exported — it's used from within the same file and
   having it exported costs nothing.
3. **tdns-mp** (`v2/main_init.go`): Remove the DNSSEC
   policy init block added in Task F's first iteration.
   It runs too late to be useful and is now dead code.
4. Build both repos.
5. Test (on NetBSD test lab): start mpsigner, verify
   `tdns-mpcli signer zone list` shows no
   `DNSSEC policy "" does not exist` errors.

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

## Task K: Move list-mp-zones to /zone/mplist in tdns-mp

**Decoupling item**: 28
**Risk**: Low — self-contained case statement, 3 CLI callers
**Repos**: tdns (remove case), tdns-mp (add endpoint)

### What to do

`list-mp-zones` is a sub-command of tdns's `/zone` endpoint
that iterates zones with `OptMultiProvider`, extracts
HSYNCPARAM data, and returns a `map[string]MPZoneInfo`.
The handler lives in tdns's `APIzone` switch and is
MP-specific. Move it to a new `/zone/mplist` endpoint
owned by tdns-mp. Three CLI commands call it today; they
all use the shared `SendZoneCommand` helper which
hardcodes `/zone`, so they need a new helper.

### Current state

- **Handler**: `tdns/v2/apihandler_zone.go`, `APIzone`
  case `"list-mp-zones"` (~70 lines). Accesses `Zones`,
  `zd.Options[OptMultiProvider]`, `zd.MP.MPdata.Options`,
  `zd.GetOwner(zd.ZoneName)`, and `core.TypeHSYNCPARAM`
  RR getters (`GetNSmgmt`, `GetParentSync`, `GetServers`,
  `GetSigners`, `GetAuditors`, `GetSuffix`).
- **Response types**:
  - `MPZoneInfo` struct at `tdns/v2/api_structs.go:114-122`
  - `MPZones map[string]MPZoneInfo` field in
    `ZoneResponse` at `tdns/v2/api_structs.go:107`
- **CLI callers** (all three use
  `SendZoneCommand`/`tdnscli.SendZoneCommand` which posts
  to `/zone`):
  1. `tdns/v2/cli/zone_cmds.go:243-264` —
     `zoneMPListCmd` (command: `zone mplist`)
  2. `tdns-mp/v2/cli/agent_zone_cmds.go:25-46` —
     `agentZoneMPListCmd` (command: `agent zone mplist`)
  3. `tdns-mp/v2/cli/combiner_edits_cmds.go:62-82` —
     `combinerZoneMPListCmd` (command:
     `combiner zone mplist`)
- **Shared output helper**: `ListMPZones(cr
  tdns.ZoneResponse)` at `tdns/v2/cli/zone_cmds.go:385`
  (used by all three commands for formatting).
- **Route**: `/zone` is registered in tdns's
  `SetupAPIRouter` and is NOT yet registered from
  tdns-mp — tdns-mp apps today reuse tdns's `/zone`
  endpoint via `SetupAPIRouter`.

### Design decisions

- **Response type moves to tdns-mp**: `MPZoneInfo` and
  the response wrapper move to tdns-mp/v2 (new file,
  e.g. `api_mplist_structs.go`). tdns's `ZoneResponse`
  loses the `MPZones` field entirely.
- **New response type**: Create a standalone
  `MPListResponse` struct in tdns-mp rather than reusing
  `ZoneResponse` — cleaner, decouples from tdns.
- **Registration on all three MP roles**: Register
  `/zone/mplist` in all three of
  `SetupMPAgentRoutes`, `SetupMPCombinerRoutes`, and
  `SetupMPSignerRoutes`. The combiner is the primary
  listing target but agent and signer should support it
  for symmetry and diagnostics.
- **CLI helper**: Add a new
  `SendMPListCommand(api)` helper in tdns-mp's CLI
  package that posts to `/zone/mplist`. Do not extend
  `SendZoneCommand` with path parameters.
- **Handler signature**: `APImplist(conf *Config)
  func(w, r)` — no need for the full
  `APIzone`-style signature because this endpoint has
  no sub-commands. Takes no request body (or accepts an
  empty one).
- **`zd.MP` usage**: The handler still reads
  `zd.MP.MPdata.Options` directly. Item 29 (`zd.AppData`
  generic extension) is future work; keep the direct
  access until then. This is fine because tdns-mp
  already depends on `tdns/v2`.

### Steps

1. **tdns-mp**: Create
   `tdns-mp/v2/api_mplist_structs.go` with:
   ```go
   type MPZoneInfo struct { ... }  // copy from tdns
   type MPListResponse struct {
       Time     time.Time             `json:"time"`
       Error    bool                  `json:"error,omitempty"`
       ErrorMsg string                `json:"error_msg,omitempty"`
       MPZones  map[string]MPZoneInfo `json:"mp_zones"`
   }
   ```
2. **tdns-mp**: Create
   `tdns-mp/v2/apihandler_mplist.go` with `APImplist`.
   Port the logic from tdns's `list-mp-zones` case
   verbatim, adapted for tdns-mp:
   - Use `tdns.Zones.IterBuffered()`,
     `tdns.OptMultiProvider`, `tdns.GetOwner(...)`,
     `core.TypeHSYNCPARAM`, etc.
   - Return `MPListResponse` (JSON-encoded) instead of
     mutating a `ZoneResponse`.
3. **tdns-mp**: Register the route in all three route
   setup functions:
   ```go
   sr.HandleFunc("/zone/mplist",
       conf.APImplist()).Methods("POST")
   ```
   Add to `SetupMPAgentRoutes`,
   `SetupMPCombinerRoutes`, and
   `SetupMPSignerRoutes` (and the auditor placeholder
   can stay empty).
4. **tdns-mp**: In `tdns-mp/v2/cli/`, add a
   `SendMPListCommand(api *tdns.ApiClient)
   (tdnsmp.MPListResponse, error)` helper that posts
   to `/zone/mplist`. Place it in a new file or in an
   existing CLI support file — wherever matches tdns-mp
   CLI conventions.
5. **tdns-mp**: Update the two tdns-mp CLI commands to
   use the new helper and the new response type:
   - `agentZoneMPListCmd` in
     `tdns-mp/v2/cli/agent_zone_cmds.go`
   - `combinerZoneMPListCmd` in
     `tdns-mp/v2/cli/combiner_edits_cmds.go`
   Both should call `SendMPListCommand` and then
   format via a tdns-mp-local `ListMPZones` helper
   (ported from `tdns/v2/cli/zone_cmds.go:385`).
6. **tdns-mp**: Create
   `tdns-mp/v2/cli/mplist_output.go` (or similar) with
   the ported `ListMPZones(resp MPListResponse)`
   output helper.
7. **tdns**: Delete the `case "list-mp-zones":` block
   from `APIzone` in `tdns/v2/apihandler_zone.go`.
8. **tdns**: Remove `MPZoneInfo` struct from
   `tdns/v2/api_structs.go` and the `MPZones` field
   from `ZoneResponse`. Verify nothing else in tdns
   references them (grep).
9. **tdns**: Delete `zoneMPListCmd` from
   `tdns/v2/cli/zone_cmds.go` and remove its registration
   from `ZoneCmd.AddCommand(...)`. Also delete the
   `ListMPZones` output helper if it has no other
   callers (verify with grep).
10. Build both repos.
11. Test: run `mpcli agent zone mplist` and
    `mpcli combiner zone mplist` against running MP
    apps, verify output matches previous behavior.

### Notes

- `tdns-cli zone mplist` goes away entirely. The
  command is MP-specific and tdns-cli has no business
  with MP zones.
- This task does not depend on any of tasks A-J beyond
  the build-working state after J. It can run
  independently.
- Risk of breakage is low because the three CLI callers
  are the only known callers (verified by grep). If some
  external script posts directly to `/zone` with
  `list-mp-zones`, it will get a "unknown command"
  response after this task lands — acceptable.

---

## Task L: Move /agent HSYNC commands to /agent/hsync in tdns-mp

**Decoupling item**: 27 (first slice)
**Risk**: Medium — ~8 CLI callers, shared response types
**Repos**: tdns (remove cases), tdns-mp (add endpoint)

### What to do

tdns's `APIagent` handles 30+ sub-commands in a single
switch. Six of them are HSYNC-state-reporting commands
that read from KeyDB and from `AgentRegistry`:

- `hsync-zonestatus`
- `hsync-peer-status`
- `hsync-sync-ops`
- `hsync-confirmations`
- `hsync-transport-events`
- `hsync-metrics`

Move them to a new `/agent/hsync` endpoint in tdns-mp.
This is the first of several command-group migrations
needed to remove MP code from tdns's `APIagent`. It is
deliberately scoped small to validate the migration
pattern before tackling larger groups (peer, gossip,
parentsync, data-modification).

### Current state: tdns vs tdns-mp drift

**Both repos already have `apihandler_agent.go` with
a full `APIagent` implementation**:
- `tdns/v2/apihandler_agent.go` — 41 active cases (30
  main + 11 debug; one commented-out
  `"list-known-agents"`)
- `tdns-mp/v2/apihandler_agent.go` — same 41 cases,
  with identical logic, differing only in:
  - Type qualifications (`tdns.ZoneRefresher`,
    `tdns.KeyDB`, `tdns.PeerRecordToInfo`, etc.)
  - Config field paths (`conf.InternalMp.*` vs
    `conf.Internal.*`)
  - Package-qualified helper calls
  - Does NOT have the commented-out
    `"list-known-agents"` case

**Key implication**: tdns-mp's `APIagent` is a
maintained parallel copy. tdns-mp is already using its
own copy in `SetupMPAgentRoutes` (see Task J result),
so the tdns version is only used by the tdns agent
app today. This drift is the whole reason the
migration is tractable: the MP-side handlers already
exist and work.

**Helper functions** (defined in tdns only, used by
both):
- `PeerRecordToInfo`, `SyncOpRecordToInfo`,
  `ConfirmRecordToInfo` — in
  `tdns/v2/db_hsync.go`
- KeyDB methods: `GetPeer`, `ListPeers`,
  `ListSyncOperations`, `ListSyncConfirmations`,
  `ListTransportEvents`, `GetAggregatedMetrics` —
  in `tdns/v2/db_hsync.go`
- `AgentRegistry.GetZoneAgentData` — in
  `tdns/v2/legacy_agent_utils.go`

**Response types** (in tdns, used by both via tdns
import):
- `HsyncPeerInfo`, `HsyncSyncOpInfo`,
  `HsyncConfirmationInfo`, `HsyncTransportEvent`,
  `HsyncMetricsInfo` — in `tdns/v2/mptypes.go`
- Carried in `AgentResponse` (grep for the exact
  field names during implementation).

**CLI callers** (post to `/agent` with the HSYNC
command names):
- tdns: `tdns/v2/cli/hsync_cmds.go`,
  `tdns/v2/cli/hsync_debug_cmds.go` — ~3-5 commands
  that send HSYNC commands. These are **already
  legacy-flagged by filename** — they belong to the
  tdns CLI but operate on MP state.
- tdns-mp: `tdns-mp/v2/cli/agent_cmds.go`,
  `tdns-mp/v2/cli/agent_router_cmds.go` — the
  production MP CLI callers.

Exact CLI caller inventory must be done during
implementation (grep each HSYNC command string).

### Design decisions

- **New endpoint**: `/agent/hsync` accepts the same
  request body shape as `/agent` (an `AgentPost` with
  `Command`, `Zone`, `AgentID`, etc.). Commands live
  in the same 6-item switch in a new handler.
- **New handler**: `APIagentHsync(kdb *tdns.KeyDB)
  func(w, r)`. Minimal parameters — it only needs
  KeyDB and access to `AgentRegistry` via
  `conf.InternalMp.AgentRegistry`.
- **Response types stay in tdns for now**:
  `HsyncPeerInfo`, `HsyncSyncOpInfo`, etc. stay in
  `tdns/v2/mptypes.go`. tdns-mp imports them. Moving
  them to tdns-mp is a second-order cleanup; don't
  conflate with this task.
- **Helper functions stay in tdns for now**:
  `PeerRecordToInfo` and friends stay in
  `tdns/v2/db_hsync.go`. Same reasoning.
- **Do not touch tdns's `apihandler_agent.go`
  structure**: Just delete the 6 cases. Leave the
  other 35 cases intact. The surrounding switch stays.
- **Remove tdns-mp's duplicate cases**: Since
  tdns-mp's `APIagent` currently also has these 6
  cases, delete them from there too — the new
  `/agent/hsync` endpoint is the one true source.
- **Route registration**: Register `/agent/hsync`
  only in `SetupMPAgentRoutes` (not signer/combiner —
  HSYNC state is agent-scoped).
- **CLI helper**: Add
  `SendAgentHsyncCommand(api, data)` in tdns-mp's
  CLI package (new file or existing support file).
  Hardcodes `/agent/hsync`. Returns the existing
  `AgentResponse` type (imported from tdns).

### Steps

1. **Inventory phase** (before editing anything):
   - grep both repos for each of the 6 HSYNC command
     strings to produce an exact caller list
   - Verify tdns-mp's `apihandler_agent.go` HSYNC
     case implementations match tdns's line-for-line
     (modulo the qualification differences). Report
     any drift before proceeding.
   - Confirm `AgentPost` and `AgentResponse` field
     sets used by the HSYNC commands (Zone, AgentID,
     HsyncPeers, HsyncSyncOps, etc.) — list them
     explicitly before the migration.
2. **tdns-mp**: Create
   `tdns-mp/v2/apihandler_agent_hsync.go` with:
   ```go
   func (conf *Config) APIagentHsync(kdb *tdns.KeyDB)
       func(w http.ResponseWriter, r *http.Request) {
       return func(w, r) {
           // decode AgentPost
           // switch on Command, handle 6 HSYNC cases
           // port verbatim from tdns-mp's existing
           // APIagent (which already has the right
           // conf.InternalMp.* paths)
       }
   }
   ```
   Port the 6 case bodies from tdns-mp's existing
   `APIagent` — they already have the correct config
   paths and qualifications.
3. **tdns-mp**: Register the new route in
   `SetupMPAgentRoutes`
   (`tdns-mp/v2/apihandler_agent_routes.go`):
   ```go
   sr.HandleFunc("/agent/hsync",
       conf.APIagentHsync(kdb)).Methods("POST")
   ```
4. **tdns-mp**: Delete the 6 HSYNC cases from
   `tdns-mp/v2/apihandler_agent.go`'s `APIagent`
   switch. Add a default "unknown command" fallthrough
   if any of them had special handling in the default
   branch (they don't, but verify).
5. **tdns-mp**: Add `SendAgentHsyncCommand(api
   *tdns.ApiClient, data tdns.AgentPost)
   (tdns.AgentResponse, error)` helper in the
   tdns-mp CLI package. Model on
   `SendAgentCommand` — same shape, different path.
6. **tdns-mp**: Update all tdns-mp CLI commands
   that send HSYNC commands to use the new helper
   and new endpoint path. Files to touch (exact
   list from inventory step):
   - `tdns-mp/v2/cli/agent_cmds.go`
   - `tdns-mp/v2/cli/agent_router_cmds.go`
   - (any others found in inventory)
7. **tdns**: Delete the 6 HSYNC cases from
   `APIagent` in `tdns/v2/apihandler_agent.go`.
8. **tdns**: Delete the tdns-side CLI commands that
   send HSYNC commands, in
   `tdns/v2/cli/hsync_cmds.go` and
   `tdns/v2/cli/hsync_debug_cmds.go`. These are
   tdns-cli commands for MP state — they have no
   business existing on tdns-cli once the endpoint
   moves. Remove their registrations from their
   parent cobra commands.
9. **tdns**: Verify that nothing else in non-test
   tdns code still references the 6 HSYNC command
   strings (grep). If the cases are gone but
   something still sends them, that's a bug.
10. Build both repos.
11. Test: run `mpcli agent hsync peer-status`,
    `mpcli agent hsync sync-ops`, etc. (exact CLI
    command names per inventory) against a running
    mpagent, verify output.

### Notes

- **Scope discipline**: This task migrates ONLY the
  6 HSYNC commands. It does not touch peer-*,
  gossip-*, parentsync-*, router-*, add-rr/del-rr,
  hsync-locate, hsync-agentstatus, discover,
  refresh-keys, etc. Those are future tasks.
- **tdns-mp handler duplication**: After this task,
  the 6 HSYNC cases exist in tdns-mp's
  `apihandler_agent_hsync.go` but are gone from
  tdns-mp's `apihandler_agent.go`. This is correct.
  tdns-mp's `apihandler_agent.go` will continue to
  shrink as more command groups migrate.
- **`hsync-locate` and `hsync-agentstatus`**: These
  sound HSYNC-named but are AgentRegistry/discovery
  commands, not KeyDB-state commands. They stay in
  `/agent` for now and will migrate with a future
  "discovery" group.
- **`hsync-init-db`**: This is a debug command on
  `/agent/debug`, not on `/agent`. Out of scope for
  this task.
- **Why agent-only route registration**: HSYNC state
  (peers, sync ops, confirmations, transport events,
  metrics) lives in the agent's KeyDB. Signer and
  combiner do not run HSYNC peering and have nothing
  to report here. If a diagnostic use case emerges,
  they can register the same endpoint later.
- **Non-goal**: Removing `db_hsync.go` or its
  helpers from tdns. That's downstream cleanup,
  driven by the broader "can we delete these legacy
  symbols yet?" question after multiple command
  groups have migrated.

---

## Task M: Move /agent router commands to /router in tdns-mp

**Decoupling item**: 27 (continuation)
**Risk**: Medium — 5 commands, helper functions in
both repos, pre-existing CLI bug to fix
**Repos**: tdns (remove cases + legacy files),
tdns-mp (add endpoint + consolidate CLI)

### What to do

tdns and tdns-mp both have 5 router introspection
cases in `APIagent` (router-list, router-describe,
router-metrics, router-walk, router-reset). These
are transport-layer concerns: "show me the state of
this process's DNS message router." They are
role-agnostic by nature — any process that runs a
`TransportManager` has a router to introspect.
Today the CLI paths through `/agent` hardcoded,
which means `mpcli combiner router list` is broken
(posts to `/agent` on the combiner, which has no
`/agent` route).

Migrate them to a new top-level `/router` endpoint
registered on all MP roles (agent, combiner, signer;
auditor stub too). Consolidate the CLI into a single
`router_cmds.go` file using the existing
`runRouterXxx(role, ...)` shared-implementation
pattern, which cleanly fixes the combiner/signer bug
as a side effect. Introduce dedicated
`RouterPost`/`RouterResponse` types that live in
tdns-mp alongside the handler, so the code is
self-contained and ready for eventual extraction to
tdns-transport.

### Current state

- **Handler cases** (both repos, line numbers from
  tdns-mp):
  - `tdns-mp/v2/apihandler_agent.go:463-517` — 5
    cases in `APIagent` switch
  - `tdns/v2/apihandler_agent.go:464-518` — parallel
    copy in tdns
- **Helper functions**:
  - `tdns-mp/v2/apihandler_agent_router.go` —
    `handleRouterList`, `handleRouterDescribe`,
    `handleRouterMetrics`, `handleRouterWalk`,
    `handleRouterReset`. All take
    `*transport.DNSMessageRouter` (or
    `*transport.TransportManager` for metrics) and
    return `*AgentMgmtResponse`.
  - `tdns/v2/legacy_apihandler_agent_router.go` —
    parallel copy, already legacy-flagged.
    `handleRouterMetrics` has a different signature
    in tdns (`*DNSMessageRouter`) vs tdns-mp
    (`*TransportManager`). Drift that doesn't matter
    for migration since we only port the tdns-mp
    version.
- **CLI commands in tdns-mp**
  (`tdns-mp/v2/cli/agent_router_cmds.go`):
  - Already uses the `runRouterXxx(role, args)`
    shared-implementation pattern.
  - Defines three cobra trees: `agentRouterCmd` (5
    subs), `combinerRouterCmd` (5 subs),
    `signerRouterCmd` (1 sub: metrics only).
  - All three trees call into `runRouterList`,
    `runRouterDescribe`, `runRouterMetrics`,
    `runRouterWalk`, `runRouterReset` which
    currently hardcode `POST /agent`
    (`agent_router_cmds.go:124`). **This is the
    pre-existing bug**: the `parent` argument
    selects the API client but the path is always
    `/agent`, so the combiner/signer variants 404.
- **CLI commands in tdns**
  (`tdns/v2/cli/legacy_agent_router_cmds.go`):
  - Parallel `legacy_*`-prefixed copy. Registers
    `agentRouterCmd` into both `AgentCmd` AND
    `CombinerCmd`
    (`legacy_agent_router_cmds.go:345-346`).
    Shadows mpcli's versions via the same
    duplicate-registration pattern we hit in Task K.
- **Response types**: currently reuse
  `tdns.AgentMgmtResponse`, with router data stuffed
  into `.Data interface{}` (generic field). The
  `Data` field carries a `map[string]interface{}`
  built by the helpers.
- **Route registration**: `/agent` is registered in
  `tdns-mp/v2/apihandler_agent_routes.go:15`. No
  `/router` route exists anywhere today.

### Design decisions

- **New request/response types in tdns-mp**:
  `RouterPost` and `RouterResponse` live in a new
  file `tdns-mp/v2/api_router_structs.go`.
  Per-group types (not a shared `CommsPost`).
  Fields:
  - `RouterPost{Command string, Detailed bool}` —
    `Detailed` is the `router-metrics --detailed`
    flag (currently stuffed into
    `AgentMgmtPost.Data["detailed"]`).
  - `RouterResponse{Time time.Time, Error bool,
    ErrorMsg string, Msg string, Identity AgentId,
    Data interface{}}` — `Data` stays as
    `interface{}` because the 5 commands return very
    different structures (list of handler names vs
    metrics map vs walk tree); typing each one
    individually isn't worth it when the CLI formats
    them anyway.
- **Handler is role-agnostic**: `APIrouter(tm
  *tdns.TransportManager) http.HandlerFunc` takes
  only the TransportManager. No `conf` reference.
  No role check. No knowledge of what role it's
  running in. This is the key property for future
  extraction to tdns-transport.
- **Helper functions move into the new handler
  file**: `handleRouterList`, `handleRouterDescribe`,
  `handleRouterMetrics`, `handleRouterWalk`,
  `handleRouterReset` become unexported helpers
  inside `tdns-mp/v2/apihandler_router.go`. The
  existing `tdns-mp/v2/apihandler_agent_router.go`
  file is deleted (its contents moved).
- **Route registration on all four role setups**:
  `SetupMPAgentRoutes`, `SetupMPCombinerRoutes`,
  `SetupMPSignerRoutes`, `SetupMPAuditorRoutes` each
  gain a `sr.HandleFunc("/router",
  conf.APIrouter(tm)).Methods("POST")` line. The
  `tm` reference resolves to
  `conf.InternalMp.TransportManager` which exists
  on all four roles. The auditor file is currently
  empty — this adds the first real line to it.
- **CLI file rename**:
  `tdns-mp/v2/cli/agent_router_cmds.go` →
  `tdns-mp/v2/cli/router_cmds.go`. The file already
  uses the right pattern (`runRouterXxx(role,
  args)`); the migration is mostly (a) fix the
  hardcoded `/agent` path to `/router`, (b) switch
  to `SendRouterCommand(role, req)` helper, (c)
  change request type from `tdns.AgentMgmtPost` to
  `tdnsmp.RouterPost`.
- **CLI shells stay per-role**: cobra doesn't allow
  one command instance to be added to two parents.
  `agentRouterListCmd`, `combinerRouterListCmd`,
  `signerRouterListCmd` all exist as separate
  variables, all with `Run: func(...) {
  runRouterList("agent", args) }` etc. The `Run`
  closure is the only difference. The shared
  `runRouterList(role string, args []string)`
  function does all the work.
- **Signer gets all 5 router commands**, not just
  `metrics`. Per the "generic transport infra"
  directive. The current asymmetry (signer has only
  metrics) is artificial. Adding list/describe/walk/
  reset to signer is a CLI-only change; the server
  side handler answers all 5 commands on any role.
- **CLI helper**: `SendRouterCommand(role string,
  req tdnsmp.RouterPost) (*tdnsmp.RouterResponse,
  error)` in `router_cmds.go`. Hardcodes `/router`.
  Selects API client via `role` parameter. Returns
  the tdns-mp type.
- **The CLI bug gets fixed as a natural
  consequence**: before the migration, `mpcli
  combiner router list` posts to `/agent` (404).
  After, it posts to `/router` (handled). Same for
  signer.
- **Delete tdns's legacy files entirely**:
  `tdns/v2/cli/legacy_agent_router_cmds.go` and
  `tdns/v2/legacy_apihandler_agent_router.go` get
  deleted. They contain only router commands/
  handlers, all of which are being deleted in this
  task. If either file has unrelated content I
  missed, trim instead of delete.

### Steps

1. **tdns-mp**: Create
   `tdns-mp/v2/api_router_structs.go` with
   `RouterPost` and `RouterResponse` types.
2. **tdns-mp**: Create
   `tdns-mp/v2/apihandler_router.go` with
   `APIrouter(tm *tdns.TransportManager) func(w,
   r)` handler. Port the 5 case bodies from
   tdns-mp's existing `APIagent` switch, adapted
   to use `RouterPost`/`RouterResponse` instead of
   `AgentMgmtPost`/`AgentMgmtResponse`. Move the
   unexported `handleRouterList`,
   `handleRouterDescribe`, `handleRouterMetrics`,
   `handleRouterWalk`, `handleRouterReset` helpers
   into this same file (ported from
   `apihandler_agent_router.go`). Change their
   return type from `*AgentMgmtResponse` to
   `*RouterResponse`.
3. **tdns-mp**: Delete
   `tdns-mp/v2/apihandler_agent_router.go`
   (contents moved to `apihandler_router.go`).
4. **tdns-mp**: Register `/router` route in all
   four route setup files:
   - `apihandler_agent_routes.go` — add
     `sr.HandleFunc("/router",
     conf.APIrouter(conf.InternalMp.TransportManager
     )).Methods("POST")`
   - `apihandler_combiner_routes.go` — same line
   - `apihandler_signer_routes.go` — same line
   - `apihandler_auditor_routes.go` — same line
     (first real route in this file)
5. **tdns-mp**: Delete the 5 router cases from
   `apihandler_agent.go` `APIagent` switch
   (`router-list`, `router-describe`,
   `router-metrics`, `router-walk`, `router-reset`).
6. **tdns-mp**: Rename
   `tdns-mp/v2/cli/agent_router_cmds.go` to
   `tdns-mp/v2/cli/router_cmds.go`. Inside:
   - Add `SendRouterCommand(role string, req
     tdnsmp.RouterPost) (*tdnsmp.RouterResponse,
     error)` helper at the top. Hardcodes `/router`,
     selects API client via role, returns tdnsmp
     types.
   - Rewrite `runRouterList`/`runRouterDescribe`/
     `runRouterMetrics`/`runRouterWalk`/
     `runRouterReset` to call `SendRouterCommand`
     instead of the inline `api.RequestNG("POST",
     "/agent", ...)` pattern. Request type changes
     from `tdns.AgentMgmtPost` to
     `tdnsmp.RouterPost`. Response field access is
     straightforward `resp.Data` / `resp.Msg` /
     `resp.Error` — same shape as before.
   - Add the missing signer shells:
     `signerRouterListCmd`,
     `signerRouterDescribeCmd`,
     `signerRouterWalkCmd`, `signerRouterResetCmd`.
     Register them on `SignerCmd` →
     `signerRouterCmd` in `init()`.
7. **tdns**: Delete the 5 router cases from
   `tdns/v2/apihandler_agent.go` `APIagent` switch.
8. **tdns**: Delete
   `tdns/v2/legacy_apihandler_agent_router.go`
   entirely (only contains the 5 helper functions,
   all now dead).
9. **tdns**: Delete
   `tdns/v2/cli/legacy_agent_router_cmds.go`
   entirely (only contains router cobra commands,
   all now dead). Verify the file has no other
   content first — if it does, trim in place.
10. Run `gofmt -w` on all touched `.go` files.
11. **tdns**: Build with `cd tdns/cmdv2 &&
    GOROOT=/opt/local/lib/go make`. Fix any errors
    (expect: unused imports in
    `tdns/v2/apihandler_agent.go` if
    `handleRouter*` helpers were the only thing
    keeping an import alive).
12. **tdns-mp**: Build with `cd tdns-mp/cmd &&
    GOROOT=/opt/local/lib/go make`. Fix any errors.
13. Grep both repos for `"router-list"`,
    `"router-describe"`, `"router-metrics"`,
    `"router-walk"`, `"router-reset"`. Should only
    match in `tdns-mp/v2/apihandler_router.go`
    (handler cases) and
    `tdns-mp/v2/cli/router_cmds.go` (CLI request
    construction).
14. Commit: one commit per repo (tdns deletions
    first, then tdns-mp additions + deletions).

### Notes

- **The CLI bug fix for combiner/signer is a silent
  net win**: today `mpcli combiner router list` is
  broken; after the migration it works. Worth
  mentioning in the commit message.
- **`handleRouterMetrics` signature change**:
  tdns-mp's version takes
  `*transport.TransportManager` because it reaches
  into `tm.Router` and per-peer stats. This
  signature is preserved in the port; no behavior
  change.
- **Auditor route file becomes non-empty**: this is
  the first real route added to
  `apihandler_auditor_routes.go`. Fine — the file
  is a placeholder that's been waiting for content.
- **Scope discipline**: does not touch `peer-*`,
  `gossip-*`, or `imr-*` commands. Those are Tasks
  N, O, and future respectively.

---

## Task N: Move /agent peer commands to /peer in tdns-mp

**Decoupling item**: 27 (continuation)
**Risk**: Medium-High — 3 commands, two pre-existing
dead/broken endpoints to clean up, interacts with
`/auth/peer` deletion
**Repos**: tdns (remove cases + legacy files +
auth_peer), tdns-mp (add endpoint + consolidate CLI
+ delete `/signer/peer`)

### What to do

tdns and tdns-mp both have 3 peer cases in
`APIagent`: `peer-ping`, `peer-apiping`,
`peer-reset`. Peer ping/apiping are "contact this
peer and verify liveness"; peer-reset is "flush IMR
cache for this peer and restart discovery." All
three are transport-layer concerns. Ping/apiping
work on any role with a TransportManager and peer
registry. Peer-reset is conceptually agent-only
because it depends on IMR-based dynamic discovery,
which signer/combiner/auditor don't do.

Migrate to a new top-level `/peer` endpoint
registered on all MP roles. CLI gets consolidated
into `peer_cmds.go` using the `runXxx(role, args)`
pattern. For `peer-reset` on non-agent roles, the
CLI prints "{role} uses static peer configuration;
peer reset is not applicable" and returns without
making the RPC call. The handler itself stays
role-ignorant: it uses whatever IMR/AgentRegistry
it's given and reports an honest error if something
is nil.

Also clean up two pre-existing dead/broken
endpoints:

- `/signer/peer` in tdns-mp
  (`apihandler_signer_routes.go:29`) — zero CLI
  callers, dead code from earlier design iteration.
- `/auth/peer` in tdns — drives `tdns-cli auth peer
  list/ping/status`. Not MP code, but the CLI
  commands do MP things and per the confirmed
  directive should be deleted as part of the MP
  cleanup.

### Current state

- **Handler cases** (both repos, line numbers from
  tdns-mp):
  - `tdns-mp/v2/apihandler_agent.go:225-245` —
    `peer-ping`, `peer-apiping` (both delegate to
    `doPeerPing(conf, peerID, useAPI)`)
  - `tdns-mp/v2/apihandler_agent.go:814-864` —
    `peer-reset` (inline ~50 lines, uses
    `conf.InternalMp.AgentRegistry` and
    `tdns.Globals.ImrEngine`)
  - `tdns/v2/apihandler_agent.go:224-245 and
    812-864` — parallel copies
- **Helper functions**:
  - `tdns-mp/v2/apihandler_agent.go:30-166` —
    `doPeerPing` (~90 lines) and `lookupStaticPeer`
    (~45 lines). Both move to the new peer handler
    file.
  - `tdns/v2/apihandler_agent.go:29-165` — parallel
    copies in tdns, get deleted.
- **CLI commands**:
  - tdns-mp: `peer-ping`/`peer-apiping` in
    `agent_cmds.go:162-200` (`agentPeerPingCmd`,
    inline logic, no `runPeerPing` helper).
    `peer-reset` in `agent_imr_cmds.go:160-184`
    (`agentPeerResetCmd`, inline logic). Both
    inline — need to refactor into `runXxx(role,
    args)` pattern as part of this task.
  - tdns: parallel copies in
    `legacy_agent_cmds.go:162-200` and
    `legacy_agent_imr_cmds.go:160-184`. Get deleted.
- **Dead/broken endpoints to delete**:
  - `/signer/peer` in
    `tdns-mp/v2/apihandler_signer_routes.go:29 +
    51-111`. `APIsingerPeer` handler (~60 lines),
    `SignerPeerPost` struct, `SignerPeerResponse`
    struct. **Zero CLI callers confirmed** via grep
    in prior inventory.
  - `/auth/peer` in tdns. Need to locate the handler
    file (`apihandler_auth.go` or similar) and the
    `AuthPeerPost`/`AuthPeerResponse` types. CLI
    driver in `tdns/v2/cli/auth_peer_cmds.go`.
    **Commands to delete from CLI**: `tdns-cli auth
    peer list`, `tdns-cli auth peer ping`,
    `tdns-cli auth peer status`.
- **Response types**: today the peer commands return
  `AgentMgmtResponse` with domain data stuffed into
  `.Msg` (text) and `.Error`/`.ErrorMsg`. No
  structured data — ping is just "ok/fail + text
  message." Simple.
- **Pre-existing legacy shadowing**:
  `legacy_agent_cmds.go` registers `agentPeerPingCmd`
  against `AgentCmd`, shadowing mpcli's version
  (same Task K/L pattern).

### Design decisions

- **New request/response types in tdns-mp**:
  `PeerPost` and `PeerResponse` in new file
  `tdns-mp/v2/api_peer_structs.go`. Fields:
  - `PeerPost{Command string, PeerID AgentId}` —
    commands are `peer-ping`, `peer-apiping`,
    `peer-reset`. The command name carries the
    API-vs-DNS distinction; no separate `UseAPI`
    flag needed.
  - `PeerResponse{Time time.Time, Error bool,
    ErrorMsg string, Msg string, Identity AgentId}`
    — no structured payload. Ping returns text
    only. Peer-reset returns text only. Keep it
    simple.
- **Handler is role-agnostic**: `APIpeer(tm
  *tdns.TransportManager, ar *AgentRegistry, imr
  *tdns.Imr) http.HandlerFunc` takes the three
  dependencies it needs. No `conf` reference.
  Peer-reset on a role without IMR returns a clean
  "no IMR configured" error — honest reporting of
  state, not a role check. The CLI is where the
  "not applicable" gating happens.
- **`doPeerPing` and `lookupStaticPeer` move into
  the new peer handler file** as unexported
  helpers. Keep them in the same file as `APIpeer`
  to reinforce locality-for-future-extraction.
- **Route registration on all four role setups**:
  same pattern as Task M. `sr.HandleFunc("/peer",
  conf.APIpeer(conf.InternalMp.TransportManager,
  conf.InternalMp.AgentRegistry,
  tdns.Globals.ImrEngine)).Methods("POST")`. Note
  the `tdns.Globals.ImrEngine` reference — this is
  the pre-existing coupling that should eventually
  move into a per-role config, but for this task I
  keep it as-is to avoid scope expansion.
- **CLI consolidation into `peer_cmds.go`**: new
  file `tdns-mp/v2/cli/peer_cmds.go` contains:
  - `SendPeerCommand(role string, req
    tdnsmp.PeerPost) (*tdnsmp.PeerResponse, error)`
    helper.
  - `runPeerPing(role, peerID string)`,
    `runPeerApiPing(role, peerID string)`,
    `runPeerReset(role, peerID string)` worker
    functions.
  - Three role prefixes × 3 commands = 9 cobra
    shells total: `agentPeerPingCmd`,
    `combinerPeerPingCmd`, `signerPeerPingCmd`,
    `agentPeerApiPingCmd`, ... `signerPeerResetCmd`.
  - Each shell's `Run:` is a one-liner:
    `runPeerPing("agent", peerID)` etc.
  - `runPeerReset` checks `role` at entry and prints
    "{role} uses static peer configuration; peer
    reset is not applicable" for any role other
    than `"agent"`, then returns without calling
    `SendPeerCommand`. This is the CLI-side role
    gating per the Q2 decision.
  - Registration into `init()`: add each shell to
    its respective role's peer parent
    (`AgentPeerCmd`, `CombinerPeerCmd`,
    `SignerPeerCmd`). The `AgentPeerCmd` parent
    exists today (`agent_cmds.go:139`);
    `CombinerPeerCmd` and `SignerPeerCmd` need to
    be created.
- **Combiner/signer peer parents**: need to create
  `CombinerPeerCmd` and `SignerPeerCmd` cobra
  parents (empty `Use: "peer"`) if they don't
  exist. Check `agent_cmds.go` /
  `combiner_*_cmds.go` / `signer_*_cmds.go` for
  existing `CombinerPeerCmd` / `SignerPeerCmd`
  symbols.
- **Delete `/signer/peer` entirely**: delete
  `sr.HandleFunc("/signer/peer", ...)` line, delete
  `APIsingerPeer` function, delete `SignerPeerPost`
  / `SignerPeerResponse` structs. All in
  `tdns-mp/v2/apihandler_signer_routes.go`. Zero
  CLI callers confirmed.
- **Delete `/auth/peer` from tdns**: locate the
  handler, the route registration, the
  `AuthPeerPost` / `AuthPeerResponse` types, and
  the CLI driver `tdns/v2/cli/auth_peer_cmds.go`.
  Delete all of them. This is a larger deletion
  because `/auth/peer` is a separate non-MP
  endpoint with its own types and handler. Need to
  check during implementation whether any other
  code imports `AuthPeerPost`.
- **`tdns-auth` binary loses `auth peer
  list`/`ping`/`status`**: per directive. Users on
  the `tdns-auth` binary lose these commands
  entirely. Acceptable because the MP binaries (via
  `mpcli signer peer ...`) cover the MP use case,
  and non-MP auth has no peer coordination to do.

### Steps

1. **tdns-mp**: Create
   `tdns-mp/v2/api_peer_structs.go` with `PeerPost`
   and `PeerResponse` types.
2. **tdns-mp**: Create
   `tdns-mp/v2/apihandler_peer.go` with `APIpeer(tm
   *tdns.TransportManager, ar *AgentRegistry, imr
   *tdns.Imr) func(w, r)` handler. Port the 3 case
   bodies from tdns-mp's existing `APIagent`
   switch. Move `doPeerPing` and `lookupStaticPeer`
   helpers into this file (from
   `apihandler_agent.go`). Adapt all to use
   `PeerPost`/`PeerResponse` instead of
   `AgentMgmtPost`/`AgentMgmtResponse`.
3. **tdns-mp**: Register `/peer` route in all four
   route setup files (agent, combiner, signer,
   auditor).
4. **tdns-mp**: Delete the 3 peer cases from
   `apihandler_agent.go` `APIagent` switch.
5. **tdns-mp**: Delete `doPeerPing` and
   `lookupStaticPeer` from `apihandler_agent.go`
   (now in `apihandler_peer.go`).
6. **tdns-mp**: Delete `/signer/peer` dead code: the
   `sr.HandleFunc("/signer/peer", ...)` line from
   `apihandler_signer_routes.go:29`, the
   `APIsingerPeer` function, the `SignerPeerPost`
   struct, the `SignerPeerResponse` struct.
7. **tdns-mp**: Create
   `tdns-mp/v2/cli/peer_cmds.go` with:
   - `SendPeerCommand(role string, req
     tdnsmp.PeerPost) (*tdnsmp.PeerResponse,
     error)` helper.
   - `runPeerPing`, `runPeerApiPing`, `runPeerReset`
     worker functions. `runPeerReset` includes the
     CLI-side role guard (early return for
     non-agent roles).
   - 9 cobra shells (3 commands × 3 roles).
   - `init()` registering all 9 shells into their
     respective role peer parents. Create
     `CombinerPeerCmd` and `SignerPeerCmd` if they
     don't exist.
8. **tdns-mp**: Delete the old inline
   `agentPeerPingCmd` from `agent_cmds.go` and its
   `init()` registration. Also remove the
   now-unused `peerPingID`, `peerPingDns`,
   `peerPingApi` globals and their flag
   registrations (they move into `peer_cmds.go`).
9. **tdns-mp**: Delete the old inline
   `agentPeerResetCmd` from `agent_imr_cmds.go` and
   its `init()` registration. Remove the
   `peerResetID` global and its flag (moves to
   `peer_cmds.go`).
10. **tdns**: Delete the 3 peer cases from
    `tdns/v2/apihandler_agent.go` `APIagent` switch.
11. **tdns**: Delete `doPeerPing` and
    `lookupStaticPeer` from
    `tdns/v2/apihandler_agent.go`.
12. **tdns**: Delete `/auth/peer` entirely: locate
    the handler file (grep for `APIauthPeer` or
    `/auth/peer`), delete the route registration,
    delete the handler, delete
    `AuthPeerPost`/`AuthPeerResponse` types. Verify
    nothing else in tdns or tdns-mp imports these
    types before deletion.
13. **tdns**: Delete `tdns/v2/cli/auth_peer_cmds.go`
    entirely. Delete any registration into
    `AuthCmd` or similar that references it.
14. **tdns**: Delete the legacy shells:
    `agentPeerPingCmd` / `agentPeerResetCmd` from
    `legacy_agent_cmds.go` and
    `legacy_agent_imr_cmds.go`. Trim init()
    registrations. Files stay (partial trim).
15. Run `gofmt -w` on all touched `.go` files.
16. **tdns**: Build. Fix any errors.
17. **tdns-mp**: Build. Fix any errors.
18. Grep both repos for `"peer-ping"`,
    `"peer-apiping"`, `"peer-reset"`. Should only
    match in `tdns-mp/v2/apihandler_peer.go`
    (cases) and `tdns-mp/v2/cli/peer_cmds.go`
    (request construction). Also verify
    `AuthPeerPost` / `AuthPeerResponse` /
    `/auth/peer` / `/signer/peer` have zero
    matches.
19. Commit: one commit per repo.

### Notes

- **Scope creep risk**: Task N is the largest of the
  three because it cleans up `/signer/peer` AND
  `/auth/peer` AND migrates 3 commands. If
  `/auth/peer` turns out to have unexpected
  couplings (other handlers importing
  `AuthPeerPost`, for example), scope-discipline
  it: mark `/auth/peer` for deletion with a TODO
  comment but don't delete in this task. The MP
  migration is the primary goal; `/auth/peer`
  cleanup is bonus.
- **CLI-side role guard on `peer-reset`**: this is
  the first case where the CLI refuses to make an
  RPC call based on role. Worth getting the pattern
  right because gossip will reuse it. The message
  format is: `"peer reset is not applicable to
  {role} (static peer configuration)"`. CLI prints
  to stderr and exits 0 (not an error, just a
  no-op).
- **`tdns.Globals.ImrEngine` coupling**: the new
  handler still references this global for
  peer-reset. Pre-existing coupling. Moving it into
  a per-role config is a separate cleanup. Not in
  scope for this task.
- **`peer-list` / `peer-status` / `peer-zones`
  commands**: these exist in mpcli
  (`agent_cmds.go`) but are NOT in the 3-command
  migration scope. They drive different server
  endpoints (not
  `peer-ping`/`peer-apiping`/`peer-reset`). Out of
  scope for Task N; they can migrate in a later
  task if needed.

---

## Task O: Move /agent gossip commands to /gossip in tdns-mp

**Decoupling item**: 27 (continuation)
**Risk**: Low — 2 commands, self-contained, no
parallel helpers, no pre-existing dead endpoints
**Repos**: tdns (remove cases + legacy file),
tdns-mp (add endpoint + consolidate CLI)

### What to do

tdns and tdns-mp both have 2 gossip cases in
`APIagent`: `gossip-group-list` and
`gossip-group-state`. Gossip is the inter-provider
state-dissemination protocol used by agents (and,
in future, auditors) to discover peer operational
state dynamically. Signer and combiner don't
participate — they use static peer configuration.

Migrate to a new top-level `/gossip` endpoint
registered on all MP roles. CLI gets consolidated
into `gossip_cmds.go`. For both gossip commands on
non-agent roles, the CLI prints "{role} does not
participate in gossip (static peer configuration)"
and returns without making the RPC call. The
handler itself is role-agnostic: it iterates
whatever `ProviderGroupManager` state exists and
returns it honestly. On a role where no provider
groups exist, the response is an empty list — not
an error.

### Current state

- **Handler cases** (both repos, line numbers from
  tdns-mp):
  - `tdns-mp/v2/apihandler_agent.go:866-958` —
    `gossip-group-state` (~95 lines, uses
    `ar.GossipStateTable`,
    `ar.ProviderGroupManager`,
    `conf.InternalMp.LeaderElectionManager`)
  - `tdns-mp/v2/apihandler_agent.go:960-995` —
    `gossip-group-list` (~35 lines, uses
    `ar.ProviderGroupManager.GetGroups()`)
  - `tdns/v2/apihandler_agent.go:864-1030` —
    parallel copies
- **CLI commands**:
  - tdns-mp: `tdns-mp/v2/cli/agent_gossip_cmds.go`
    — `agentGossipGroupListCmd` (uses
    `SendAgentMgmtCmd`), `agentGossipGroupStateCmd`
    (uses `SendAgentMgmtCmd`). Inline logic, not
    yet using `runXxx(role, args)` pattern.
  - tdns: `legacy_agent_gossip_cmds.go` — parallel
    copy, same structure. Gets deleted entirely.
- **Response data**: both commands stuff a
  `map[string]interface{}` into
  `AgentMgmtResponse.Data`. The CLI then
  type-asserts individual fields out of it. This is
  the generic-data-blob pattern. The new typed
  `GossipResponse` can either preserve the `Data
  interface{}` field (minimal change) or introduce
  structured fields (more work, more type safety).
- **Dependencies used by handler**:
  - `conf.InternalMp.AgentRegistry` →
    `.GossipStateTable`, `.ProviderGroupManager`
  - `conf.InternalMp.LeaderElectionManager`
  - Types: `GroupElectionState`, `ProviderGroup`,
    `MemberState`
- **No parallel helpers**: unlike router and peer,
  gossip doesn't have `handleGossipXxx` helper
  functions. The logic is all inline in the cases.
  Migration is just "move the inline bodies into
  the new handler."

### Design decisions

- **New request/response types in tdns-mp**:
  `GossipPost` and `GossipResponse` in new file
  `tdns-mp/v2/api_gossip_structs.go`. Fields:
  - `GossipPost{Command string, GroupName string}`
    — `GroupName` is the target for
    `gossip-group-state`.
  - `GossipResponse{Time time.Time, Error bool,
    ErrorMsg string, Msg string, Identity AgentId,
    Data interface{}}` — keep `Data` as
    `interface{}` for the same reason as router:
    the two commands return very different shapes
    (list of groups vs state matrix for one group),
    and the CLI formats them via type assertion
    anyway. Typing each one individually is work
    for minimal benefit.
- **Handler is role-agnostic**: `APIgossip(ar
  *AgentRegistry, lem *LeaderElectionManager)
  http.HandlerFunc`. Takes the two dependencies it
  needs. No role check. On a role where
  `ar.ProviderGroupManager` is nil, the handler
  returns `{"groups": []}` for list and an error
  for state (because state requires a specific
  group). This is honest reporting — the CLI is
  where the "not applicable" gating happens, so the
  server rarely gets hit for non-applicable roles
  in practice.
- **Route registration on all four role setups**:
  same pattern as M and N.
  `sr.HandleFunc("/gossip",
  conf.APIgossip(conf.InternalMp.AgentRegistry,
  conf.InternalMp.LeaderElectionManager)).Methods(
  "POST")`.
- **CLI consolidation into `gossip_cmds.go`**: new
  file `tdns-mp/v2/cli/gossip_cmds.go` contains:
  - `SendGossipCommand(role string, req
    tdnsmp.GossipPost) (*tdnsmp.GossipResponse,
    error)` helper.
  - `runGossipGroupList(role string)`,
    `runGossipGroupState(role, groupName string)`
    worker functions. Both include the role guard
    at entry (early return with "not applicable"
    message for non-agent roles).
  - Three role prefixes × 2 commands = 6 cobra
    shells.
  - Registration in `init()`: need
    `AgentGossipGroupCmd`, `CombinerGossipGroupCmd`,
    `SignerGossipGroupCmd` parent commands. Create
    them if they don't exist.
- **The role guard is stricter for gossip than for
  peer-reset**: gossip is not applicable to
  signer/combiner/auditor period. All commands in
  the group are gated. Peer-reset was mixed
  (ping/apiping work everywhere, only reset is
  gated). The gossip guard can be a single check
  at the top of each worker.
- **Delete tdns's legacy file entirely**:
  `tdns/v2/cli/legacy_agent_gossip_cmds.go`
  contains only the 2 gossip cobra commands. All
  deleted in this task, so delete the whole file.

### Steps

1. **tdns-mp**: Create
   `tdns-mp/v2/api_gossip_structs.go` with
   `GossipPost` and `GossipResponse` types.
2. **tdns-mp**: Create
   `tdns-mp/v2/apihandler_gossip.go` with
   `APIgossip(ar *AgentRegistry, lem
   *LeaderElectionManager) func(w, r)` handler.
   Port the 2 case bodies from tdns-mp's existing
   `APIagent` switch, adapted to use
   `GossipPost`/`GossipResponse`.
3. **tdns-mp**: Register `/gossip` route in all
   four route setup files.
4. **tdns-mp**: Delete the 2 gossip cases from
   `apihandler_agent.go` `APIagent` switch.
5. **tdns-mp**: Create
   `tdns-mp/v2/cli/gossip_cmds.go` with:
   - `SendGossipCommand(role string, req
     tdnsmp.GossipPost) (*tdnsmp.GossipResponse,
     error)` helper.
   - `runGossipGroupList(role string)` and
     `runGossipGroupState(role, groupName string)`
     workers, both with role guard at entry for
     non-agent roles.
   - 6 cobra shells (2 commands × 3 roles).
   - `init()` creating/using `AgentGossipCmd`/
     `CombinerGossipCmd`/`SignerGossipCmd` parents
     and registering the shells.
6. **tdns-mp**: Delete
   `tdns-mp/v2/cli/agent_gossip_cmds.go` entirely
   (all contents moved to `gossip_cmds.go`).
7. **tdns**: Delete the 2 gossip cases from
   `tdns/v2/apihandler_agent.go` `APIagent` switch.
8. **tdns**: Delete
   `tdns/v2/cli/legacy_agent_gossip_cmds.go`
   entirely.
9. Run `gofmt -w` on all touched `.go` files.
10. **tdns**: Build. Fix any errors.
11. **tdns-mp**: Build. Fix any errors.
12. Grep both repos for `"gossip-group-list"`,
    `"gossip-group-state"`. Should only match in
    `tdns-mp/v2/apihandler_gossip.go` and
    `tdns-mp/v2/cli/gossip_cmds.go`.
13. Commit: one commit per repo.

### Notes

- **Smallest of the three tasks**. 2 commands, no
  helpers to move, no dead endpoints to clean up,
  no parallel copies in auth CLI. Clean migration.
- **CLI role guard pattern established by Task N is
  reused here**. Same message format: `"{role}
  does not participate in gossip (static peer
  configuration)"`.
- **Gossip data deserialization in CLI**: the
  current `agent_gossip_cmds.go` does substantial
  work unmarshaling the `map[string]interface{}`
  response into a display format. That code moves
  verbatim into `runGossipGroupList` /
  `runGossipGroupState` in the new file. No
  changes to the unmarshal logic — just a file
  move and a wrapping function signature change.
- **Future auditor gossip**: per guidance, auditors
  may eventually participate in gossip. When that
  happens, the role guard in the CLI workers needs
  updating to allow `role == "auditor"` through to
  the server. For now, auditor is in the "not
  applicable" bucket alongside signer/combiner.

---

## Cross-cutting notes for Tasks M + N + O

### Recommended implementation order within M/N/O

1. **Task O (gossip)** — smallest and simplest.
   Establishes the CLI role-guard pattern in a
   low-risk context. 2 commands, clean migration.
2. **Task M (router)** — medium complexity. Has the
   pre-existing `/agent` hardcoding bug that gets
   fixed as a natural consequence. Existing
   `runRouterXxx` pattern means less refactoring. 5
   commands.
3. **Task N (peer)** — largest scope. Uses the
   role-guard pattern from O and the fixed CLI
   pattern from M. Also cleans up two pre-existing
   dead endpoints. 3 commands + cleanup.

### Shared patterns across all three

- **Handler package**: tdns-mp, in new dedicated
  files (`apihandler_router.go`,
  `apihandler_peer.go`, `apihandler_gossip.go`).
  Locality for future tdns-transport extraction.
- **Types**: per-group `XxxPost`/`XxxResponse`, in
  new `api_xxx_structs.go` files paired with
  handlers. 6 new types total. Use `interface{}`
  for payload `Data` in router and gossip (varied
  shapes); plain `Msg` text for peer.
- **Role agnosticism in handlers**: no `role`
  parameter, no `AppType` check, no knowledge of
  what's running the handler. Handlers take
  explicit dependencies (`*TransportManager`,
  `*AgentRegistry`, `*Imr`,
  `*LeaderElectionManager`) and report state
  honestly.
- **Route registration**: `/router`, `/peer`,
  `/gossip` all registered on agent, combiner,
  signer, auditor (4 files each, 3 files with real
  content, 1 stub that gets its first route line
  from Task M).
- **CLI file naming**: `router_cmds.go`,
  `peer_cmds.go`, `gossip_cmds.go` (no `agent_`
  prefix). Locality by topic, not role.
- **CLI structure**: thin cobra shells calling
  `runXxx(role, ...)` workers. Workers do all the
  real work. Role guards live in workers, at entry,
  before the RPC call. Non-applicable roles exit
  with a printed message, not an error, not an RPC
  round trip.
- **CLI registration**: one shell per (command,
  role) combination, registered into
  `AgentXxxCmd` / `CombinerXxxCmd` / `SignerXxxCmd`
  parent commands. Create parent commands if they
  don't exist. Do NOT try to add one shell
  instance to multiple parents (cobra disallows
  this).
- **Auditor CLI**: skipped for now. Server-side
  routes are registered on auditor; CLI trees are
  not added. `mpcli auditor ...` doesn't exist yet.
- **Legacy file cleanup**: fully-empty legacy files
  get deleted. Partially-trimmed files get left in
  place. Final sweep is a later task.
- **Commit cadence**: one task = one commit per
  repo. Two commits total per task (tdns deletions
  + tdns-mp additions and deletions).
- **Build verification**: both repos built locally
  after each task, per the post-Task-K rule.

### Open items deferred to implementation time

- Exact location of `/auth/peer` handler in tdns
  (grep during Task N).
- Whether `AuthPeerPost` is imported from anywhere
  other than `auth_peer_cmds.go` (verify during
  Task N).
- Whether `CombinerPeerCmd`, `SignerPeerCmd`,
  `CombinerGossipCmd`, `SignerGossipCmd`,
  `CombinerRouterCmd`, `SignerRouterCmd` exist
  today or need to be created (verify during each
  task).
- Whether any fully-empty legacy files result from
  M/N/O deletions (delete if so; otherwise leave).

### Related future work (not planned here)

- **`/keystore` on agent**: register
  `kdb.APIkeystore(conf.Config)` on
  `SetupMPAgentRoutes`. Separate task (Task P?).
  Driven by agent's need to sign its own
  autogenerated agent zone.
- **`/keystore` and `/truststore` on auditor**:
  consistency cleanup. Separate task.
- **`imr-*` commands migration to `/imr`
  endpoint**: 4 commands currently in `APIagent`.
  Parallel to M/N/O. Separate task.
- **tdns-transport extraction**: router/peer/gossip
  handlers eventually move out of tdns-mp into a
  shared transport package. Enabled by the current
  migration's file-locality and role-agnostic-
  handler decisions.
- **Final legacy file sweep**: once M/N/O plus
  future imr/keystore tasks land, the `legacy_*.go`
  files in `tdns/v2/cli/` and `tdns/v2/` may be
  empty enough to delete wholesale.

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
| 10 | **K** | Low | Move list-mp-zones to /zone/mplist in tdns-mp |
| 11 | **L** | Medium | Move /agent HSYNC commands to /agent/hsync in tdns-mp |
| 12 | **O** | Low | Move /agent gossip commands to /gossip in tdns-mp |
| 13 | **M** | Medium | Move /agent router commands to /router in tdns-mp |
| 14 | **N** | Medium-High | Move /agent peer commands to /peer in tdns-mp |

**Rationale**: Tasks A-B are pure tdns changes with zero risk
of breaking MP apps. Task H is schema reorganization and
must land before E (which references OutgoingSerials).
Task G merged into E. Tasks C-J all follow the "add first,
remove second" pattern and touch both repos. Tasks K-L are
the first two command-migration tasks: carving MP-specific
commands out of tdns's monolithic handlers so legacy tdns
code that supports them can eventually be deleted. Tasks
M-N-O continue the command-migration pattern but for
role-agnostic transport infrastructure (router, peer,
gossip), registered on all MP roles at top-level paths
(`/router`, `/peer`, `/gossip`) rather than under `/agent`.
Within M/N/O, O is done first (smallest, establishes the
CLI role-guard pattern), then M (fixes a pre-existing
combiner/signer CLI bug as a side effect), then N
(largest, also cleans up two dead peer endpoints).

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
- **Item 27** (/agent split): Partially planned as
  Task L (HSYNC commands only, first slice). Further
  slices — peer, gossip, parentsync, router,
  data-modification, discovery — follow the same
  pattern and will be planned as separate tasks
  after L lands and validates the approach.
- **Item 28** (/zone/mplist): Planned as Task K.
- **Item 29** (zd.AppData): Future work.
