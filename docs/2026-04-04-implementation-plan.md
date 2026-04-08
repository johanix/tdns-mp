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

**Rationale**: Tasks A-B are pure tdns changes with zero risk
of breaking MP apps. Task H is schema reorganization and
must land before E (which references OutgoingSerials).
Task G merged into E. Tasks C-J all follow the "add first,
remove second" pattern and touch both repos. Tasks K-L are
the first two command-migration tasks: carving MP-specific
commands out of tdns's monolithic handlers so legacy tdns
code that supports them can eventually be deleted.

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
