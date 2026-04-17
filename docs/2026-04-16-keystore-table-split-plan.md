# Keystore Table Split: Separate tdns and tdns-mp DNSSEC Key Tables

**Date**: 2026-04-16
**Companion**: `tdns/docs/2026-04-15-tdns-nonlegacy-to-legacy-dependency-analysis.md`
**Status**: Plan (not yet implemented)

---

## Problem

tdns and tdns-mp share a single `DnssecKeyStore` SQLite table for
DNSSEC key pair lifecycle management. tdns-mp extends the key state
machine with MP-specific states (`mpdist`, `mpremove`, `foreign`)
and MP-specific columns (`propagation_confirmed`,
`propagation_confirmed_at`). This creates a data-level safety
hazard: if tdns's keystore code encounters a key in `mpremove`
state — a state it doesn't understand — it may misinterpret it
and corrupt the key lifecycle.

The obvious fix — "tdns refuses to operate on MP zones" — is
circular: it drags MP awareness back into tdns precisely as we
work to remove it.

## Solution

Give each product its own keystore table in the same SQLite DB:

- **`DnssecKeyStore`** — owned by tdns. Simple state set:
  created, published, standby, active, retired, removed.
- **`MPDnssecKeyStore`** — owned by tdns-mp. Full MP state set:
  created, mpdist, mpremove, published, standby, active, retired,
  removed, foreign. Includes propagation tracking columns.

A process is either tdns-auth or tdns-mp-signer, never both, so
there is no runtime contention. The query responder serves DNSKEYs
from zone data, not from the keystore, so no shared read access
is needed.

This unblocks:

1. Wiring tdns's `KeyStateWorker` into `StartAuth`
2. Removing all MP awareness from tdns keystore code
3. Further `legacy_*.go` cleanup

---

## Phase 1: tdns-mp gets its own keystore table

tdns-mp already has `HsyncTables` in `db_schema_hsync.go` and
`InitHsyncTables()`. The new MP keystore table slots in naturally.

### Step 1.1 — Add `MPDnssecKeyStore` to HsyncTables

**File**: `tdns-mp/v2/db_schema_hsync.go`

Add to `HsyncTables` map:

```sql
CREATE TABLE IF NOT EXISTS 'MPDnssecKeyStore' (
   id                        INTEGER PRIMARY KEY,
   zonename                  TEXT,
   state                     TEXT,
   keyid                     INTEGER,
   flags                     INTEGER,
   algorithm                 TEXT,
   creator                   TEXT,
   privatekey                TEXT,
   keyrr                     TEXT,
   comment                   TEXT,
   propagation_confirmed     INTEGER DEFAULT 0,
   propagation_confirmed_at  TEXT DEFAULT '',
   published_at              TEXT DEFAULT '',
   retired_at                TEXT DEFAULT '',
   UNIQUE (zonename, keyid)
)
```

Same schema as current `DnssecKeyStore` — tdns-mp needs all
columns. `InitHsyncTables()` already iterates the map, so table
creation is automatic.

### Step 1.2 — Add MP-local state constants

**File**: `tdns-mp/v2/types.go`

Add local constants (currently imported from tdns):

```go
const (
   DnskeyStateMpdist   = "mpdist"
   DnskeyStateMpremove = "mpremove"
   DnskeyStateForeign  = "foreign"
)
```

These replace `tdns.DnskeyStateMpdist`, etc. throughout tdns-mp.

### Step 1.3 — Update signer_keydb.go to use MPDnssecKeyStore

**File**: `tdns-mp/v2/signer_keydb.go`

Replace all `DnssecKeyStore` table references with
`MPDnssecKeyStore` in SQL strings. Also replace
`tdns.DnskeyStateMpdist` etc. with the local constants from
Step 1.2. Functions affected:

- `GetDnssecKeysByState`
- `UpdateDnssecKeyState`
- `GenerateAndStageKey` (also see Step 1.4)
- `GetKeyInventory`
- `SetPropagationConfirmed`
- `TransitionMpdistToPublished`
- `TransitionMpremoveToRemoved`

### Step 1.4 — GenerateKeypair for MP table

`GenerateAndStageKey` in tdns-mp calls `hdb.GenerateKeypair()`,
which is a tdns method that INSERTs into `DnssecKeyStore`. After
the split, MP keys must go into `MPDnssecKeyStore`.

**Approach**: The current `GenerateKeypair` in
`tdns/v2/sig0_utils.go` (lines 104-322) has a clean internal
boundary:

- Lines 104-273: pure key material generation (crypto, PEM
  formatting). No DB access. Returns `*PrivateKeyCache`.
- Lines 275-322: DB INSERT into `Sig0KeyStore` or
  `DnssecKeyStore`.

Extract lines 104-273 into a standalone exported function:

```go
func GenerateKeyMaterial(owner string, rrtype uint16,
   alg uint8, keytype string) (*PrivateKeyCache, error)
```

Then:
- tdns's `GenerateKeypair` becomes: call `GenerateKeyMaterial`
  + INSERT into `DnssecKeyStore` (same behavior as today)
- tdns-mp adds `GenerateKeypairMP` on `*HsyncDB`: call
  `tdns.GenerateKeyMaterial` + INSERT into `MPDnssecKeyStore`

No crypto duplication, no row copying between tables.

**Files**:
- `tdns/v2/sig0_utils.go` — extract `GenerateKeyMaterial`
- `tdns-mp/v2/signer_keydb.go` — add `GenerateKeypairMP`

### Step 1.5 — Update mp_signer.go foreign key SQL

**File**: `tdns-mp/v2/mp_signer.go`

Replace `DnssecKeyStore` with `MPDnssecKeyStore` in all raw SQL:
- `fetchForeignSql` (SELECT foreign keys)
- `insertForeignSql` (INSERT OR IGNORE foreign keys)
- `deleteForeignSql` (DELETE stale foreign keys)
- `fetchZoneDnskeysSql` (SELECT for DNSKEY RRset publication)

Also replace `tdns.DnskeyStateForeign` with local constant.

### Step 1.6 — Update remaining tdns-mp references

Grep for `tdns.DnskeyStateMpdist`, `tdns.DnskeyStateMpremove`,
`tdns.DnskeyStateForeign` across all of tdns-mp/v2 and replace
with local constants. Files likely affected:

- `key_state_worker.go`
- `signer_msg_handler.go`
- `hsync_utils.go`
- `apihandler_agent.go`

### Step 1.7 — Build verification

```bash
cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make
```

tdns should still build unchanged at this point (MP table is
additive, no tdns changes yet).

---

## Phase 2: Clean MP awareness from tdns

### Step 2.1 — Remove MP state constants from structs.go

**File**: `tdns/v2/structs.go`

Remove `DnskeyStateMpdist`, `DnskeyStateMpremove`,
`DnskeyStateForeign` constants. Keep: created, published,
standby, active, retired, removed.

### Step 2.2 — Simplify DnssecKeyStore schema

**File**: `tdns/v2/db_schema.go`

Remove from table definition:
- `propagation_confirmed` column
- `propagation_confirmed_at` column

Update comment to list only: created, published, standby, active,
retired, removed.

Also update `dbMigrateSchema` in `db.go` if it adds these
columns.

### Step 2.3 — Remove MP functions from keystore.go

**File**: `tdns/v2/keystore.go`

Delete entirely (all now live in tdns-mp):
- `TransitionMpdistToPublished`
- `TransitionMpremoveToRemoved`
- `SetPropagationConfirmed`
- `GetDnssecKeyPropagation`
- `canPromoteMultiProvider`

Keep `DefaultDnskeyTTL` — it's a generic constant useful for
any signer logic, not MP-specific despite its only current
caller being MP-only.

### Step 2.4 — Simplify GenerateAndStageKey

**File**: `tdns/v2/keystore.go`

Remove `isMultiProvider` parameter. Always stage to `published`:

```go
func GenerateAndStageKey(kdb *KeyDB, zone, creator string,
   alg uint8, keytype string) (uint16, error) {
```

Update all call sites (key_state_worker.go, keystore.go "clear"
command).

### Step 2.5 — Simplify delete command in DnssecKeyMgmt

**File**: `tdns/v2/keystore.go`

Remove `OptMultiProvider` check. Always transition to `removed`:

```go
targetState := DnskeyStateRemoved
// (delete the zd/OptMultiProvider branch)
```

### Step 2.6 — Remove multiProviderGating from sign.go

**File**: `tdns/v2/sign.go`

Remove `multiProviderGating` variable and both
`canPromoteMultiProvider` checks. Published→active promotion
becomes unconditional (governed solely by the key_state_worker
pipeline: published→standby via time, then rollover
standby→active).

Remove `extractRemoteDNSKEYs` if it exists and is MP-only.

### Step 2.7 — Clean ops_dnskey.go

**File**: `tdns/v2/ops_dnskey.go`

Remove only `mpdist` and `foreign` from the SQL query. Do NOT
add `active` — active keys are provided separately via the
`dak` parameter from the signing path; including them here
would double-count them in the DNSKEY RRset. New query:

```sql
SELECT keyid, flags, algorithm, keyrr FROM DnssecKeyStore
WHERE zonename=? AND (state='published' OR state='standby'
   OR state='retired')
```

**Note**: Removing `foreign` here is safe because tdns-auth
never serves MP zones. The mpsigner has its own
`mpzd.PublishDnskeyRRs()` in `mp_signer.go` (line 256) that
shadows this function and has its own SQL query — that query
is updated to use `MPDnssecKeyStore` in Step 1.5.

### Step 2.8 — Clean key_state_worker.go

**File**: `tdns/v2/key_state_worker.go`

- Delete commented-out MP blocks (lines 212-217, 228-232,
  248-255)
- Remove `isMP` variable and parameter threading
- Remove mpdist pipeline check in `maintainStandbyKeysForType`:
  only check published count, not mpdist
- Update `GenerateAndStageKey` call to drop `isMP` arg
- Update function comment — no longer mentions MP

### Step 2.9 — Clean apihandler_funcs.go

**File**: `tdns/v2/apihandler_funcs.go`

Remove commented-out `pushKeystateInventoryToAllAgents`.

### Step 2.10 — Update comments

**File**: `tdns/v2/keystore.go`

Update `KeyInventoryItem.State` comment to remove "mpdist" and
"foreign".

### Step 2.11 — Build verification

```bash
cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make
cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make
```

---

## Phase 3: CLI and API split

The CLI (`tdns/v2/cli/keystore_cmds.go`) sends `KeystorePost`
requests to a server API endpoint (`POST /keystore`). The
mpsigner routes this to `kdb.APIkeystore(conf.Config)` — which
is tdns's handler, operating on `DnssecKeyStore`. After the
table split, the mpsigner CLI hits the wrong table.

### Step 3.1 — tdns-mp: Add MPDnssecKeyMgmt + APIkeystoreMP

**File**: new `tdns-mp/v2/apihandler_keystore.go`

Copy tdns's `DnssecKeyMgmt` as `MPDnssecKeyMgmt` — one
function, same structure. Do NOT split into per-subcommand
helpers; the shared transaction management and the CLI-side
boilerplate (parse args → build KeystorePost → send → handle
response) mean splitting would roughly double the code for no
maintainability gain.

Changes from the tdns original:

- All SQL: `DnssecKeyStore` → `MPDnssecKeyStore`
- **list**: keep `propagation_confirmed` columns
- **delete**: always `mpremove` (no OptMultiProvider check)
- **generate**: call `GenerateKeypairMP` instead of
  `GenerateKeypair`
- **clear**: call `GenerateKeypairMP` for regen
- **add/import**, **setstate**, **rollover**, **gen-ds**: table
  name change only

Add `(hdb *HsyncDB) APIkeystoreMP(conf *tdns.Config)` wrapper
that decodes `tdns.KeystorePost`, routes `"dnssec-mgmt"` to
`MPDnssecKeyMgmt`, and returns `tdns.KeystoreResponse`. Reuses
the same tdns API types — they're generic envelopes.

### Step 3.2 — tdns-mp: Route mpsigner /keystore to new handler

**File**: `tdns-mp/v2/apihandler_signer_routes.go` (line 32)

Change:
```go
sr.HandleFunc("/keystore",
   kdb.APIkeystoreMP(conf.Config)).Methods("POST")
```

Same for agent routes if the mpagent also needs keystore access
(`apihandler_agent_routes.go` line 24).

### Step 3.3 — tdns: Simplify CLI list output

**File**: `tdns/v2/cli/keystore_cmds.go`

Remove foreign-key sorting and `[foreign]` marker from the list
display (lines ~478-489). After the split, `DnssecKeyStore`
never contains foreign keys.

### Step 3.4 — tdns: Add state validation to setstate

**File**: `tdns/v2/keystore.go` (DnssecKeyMgmt "setstate" case)

Reject unknown states with a clear error. Maintain a set of
valid states (created, published, standby, active, retired,
removed) and check against it. This is future-proof — no
update needed when new states are added to tdns-mp.

**Note on shared types**: `KeystorePost` and `KeystoreResponse`
(`api_structs.go`) are generic structs with string/int fields.
tdns-mp's `APIkeystoreMP` can use the same tdns types as its
API contract — the CLI doesn't change, only the server-side
handler differs. No type duplication needed.

### Step 3.5 — Verify rollover works for non-MP zones

The rollover command (standby→active, active→retired) was
implemented for MP zones. Verify it works correctly for
tdns-auth's simple zones. If not, fix as part of this phase.
(Separate Linear issue if it turns out to be a larger problem.)

### Step 3.6 — Build verification

```bash
cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make
cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make
```

---

## Phase 4: Wire KeyStateWorker into StartAuth

### Step 4.1 — Register in StartAuth

**File**: `tdns/v2/main_initfuncs.go` (before `return nil` in
`StartAuth`)

```go
StartEngine(&Globals.App, "KeyStateWorker", func() error {
   return KeyStateWorker(ctx, conf)
})
```

### Step 4.2 — Remove "NOT YET WIRED" header comment

**File**: `tdns/v2/key_state_worker.go`

Replace the large block comment (lines 8-38) with a short
description of what the worker does and when it runs.

### Step 4.3 — Build verification

```bash
cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make
cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make
```

---

## Key Design Decisions

1. **Same DB file, different tables**: `DnssecKeyStore` for
   non-MP zones, `MPDnssecKeyStore` for MP zones. Both tables
   may be active in the same process (the mpsigner handles
   both zone types). The table boundary is per-zone-type,
   not per-binary. Non-MP zones use the full tdns code path
   regardless of which binary they run in.

2. **MP state constants move to tdns-mp**: `mpdist`, `mpremove`,
   `foreign` become local to `package tdnsmp`. tdns no longer
   exports them.

3. **GenerateKeypair split**: Extract `GenerateKeyMaterial`
   (pure crypto, no DB) from `GenerateKeypair`. Both products
   call it; each INSERTs into their own table. Mechanical cut
   at an existing boundary in the code (line 275).

4. **No migration of existing data**: No installed base, so no
   need to copy rows between tables. The initial migration
   function (`migrateMPDnssecKeysFromLegacy`) was a mistake —
   it copied non-MP zone keys into `MPDnssecKeyStore`. Remove
   it (Phase 5, Step 5.1).

## Deferred: EnsureActiveDnssecKeys auto-generation

`sign.go`'s `EnsureActiveDnssecKeys` auto-generates keys directly
into `active` state when no active keys exist. This bypasses the
KeyStateWorker pipeline (created→published→standby→active) and is
potentially dangerous: a zone may intentionally have no active
keys (e.g. a non-signing server in an MP setup, or a zone
mid-rollover). The current code already guards against some of
these cases, but the design conflates "ensure keys exist"
(KeyStateWorker's job) with "activate keys" (policy decision).

**Not in scope for this work** — the goal here is tdns/tdns-mp
separation, not improving the tdns signer. Track as a separate
Linear issue.

---

## Phase 5: Post-implementation corrections

**Added 2026-04-16 after reviewing the initial implementation.**

### Design clarification: MPDnssecKeyStore is for MP zones ONLY

The original plan implicitly assumed clean product boundaries:
"a process is either tdns-auth or tdns-mp-signer." But the
mpsigner handles **both** MP and non-MP zones. The initial
implementation routed all keystore operations to
`MPDnssecKeyStore` regardless of zone type, which is wrong.

**Corrected principle**: Non-MP zones must behave identically
regardless of which binary they run in. A non-MP zone in the
mpsigner uses `DnssecKeyStore`, `SignZone`, `DnssecKeyMgmt`,
`RolloverKey`, and the tdns `KeyStateWorker` — the full tdns
code path. The MP layer only activates for zones that are
actually MP.

**Why not "mpsigner owns all keys in MPDnssecKeyStore"?**
Two reasons:

1. **Improvements flow automatically.** The tdns signer is not
   polished; it will get bug fixes and improvements over time.
   If non-MP zones in the mpsigner use the regular tdns code
   path, they automatically benefit. Otherwise, every tdns
   signer fix requires asking "does this also need to change
   in the MP version?" — and over time the two diverge.

2. **No AppType gates in tdns.** We never want tdns code to
   ask "is this an MP binary?" A non-MP zone is a non-MP zone.
   If it's in `DnssecKeyStore` and uses the normal signing
   path, tdns code handles it correctly with zero awareness
   of the MP world.

### Step 5.1 — Remove or filter the migration

**File**: `tdns-mp/v2/db_schema_hsync.go`
(`migrateMPDnssecKeysFromLegacy`)

The current migration copies ALL keys from `DnssecKeyStore` to
`MPDnssecKeyStore`. This puts non-MP zone keys in the wrong
table.

**Option A** (preferred): Remove the migration entirely. There
is no installed base, so no data needs to be preserved across
the schema change.

**Option B**: Filter the migration to only copy keys for zones
that have `OptMultiProvider` set. This requires zone config
access at migration time, which may not be available during
`InitHsyncTables`. If config isn't loaded yet, Option A is
the only clean choice.

### Step 5.2 — Zone-type-aware API routing

**File**: `tdns-mp/v2/apihandler_keystore.go` (`APIkeystoreMP`)

Currently, `APIkeystoreMP` routes all `"dnssec-mgmt"` requests
to `MPDnssecKeyMgmt`. Change it to check the zone's
`OptMultiProvider` flag:

```go
case "dnssec-mgmt":
    zd, exists := tdns.Zones.Get(kp.Zone)
    if exists && zd.Options[tdns.OptMultiProvider] {
        resp, err = hdb.MPDnssecKeyMgmt(tx, kp)
    } else {
        resp, err = hdb.KeyDB.DnssecKeyMgmt(tx, kp)
    }
```

Note: `OptMultiProvider` lives in `zd.Options` (the regular
tdns zone options map), not in `MPOptions`. It's a zone config
flag parsed by tdns. `MPOptions` are runtime flags set by
tdns-mp after HSYNC analysis (`OptMultiSigner`,
`OptMPDisallowEdits`, etc.).

This is one gate at the API entry point — not gates scattered
throughout the code. Non-MP zones go through the regular tdns
handler, which operates on `DnssecKeyStore`.

**Note**: The `list` subcommand is a special case. In the
mpsigner, keys live in two tables. Default behavior: query
both tables and display results in two sections (non-MP keys
from `DnssecKeyStore`, then MP keys from `MPDnssecKeyStore`).
Add a `--mp-only` / `--non-mp-only` flag to list either
subset. If a zone argument is given, the routing check
determines which table to query (single section).

### Step 5.3 — Verify agent keystore routing

**File**: `tdns-mp/v2/apihandler_agent_routes.go`

The mpagent also routes `/keystore` to `APIkeystoreMP`. The
agent typically only has its auto-generated agent zone, which
is NOT an MP zone. After Step 5.2, the API routing check will
correctly dispatch to `DnssecKeyMgmt` for non-MP zones.

Verify that the agent's auto-zone keys stay in
`DnssecKeyStore` and are not duplicated into
`MPDnssecKeyStore`.

### Step 5.4 — Key state worker scope

The tdns-mp key state worker (`key_state_worker.go`) calls
`GetDnssecKeysByState(hdb, "", state)` which scans ALL keys
in `MPDnssecKeyStore`. After Step 5.1 removes the migration,
only MP zone keys are in `MPDnssecKeyStore`, so this is
correct — the MP worker only processes MP keys.

The tdns `KeyStateWorker` (started via `StartAuth` in Phase 4)
handles non-MP zones via `DnssecKeyStore`. Both workers run
in the mpsigner, each operating on its own table. No conflict.

**Mpsigner**: `StartAuth` starts the tdns worker;
`StartMPSigner` starts the MP worker. Both already run.

**Mpagent**: `StartMPAgent` does NOT call `StartAuth` — it has
its own startup sequence. But the agent DNSSEC-signs its
identity zone (a non-MP zone), so it needs the tdns
`KeyStateWorker` for key lifecycle management. Add:

```go
tdns.StartEngine(&tdns.Globals.App, "KeyStateWorker",
   func() error { return tdns.KeyStateWorker(ctx, conf.Config) })
```

to `StartMPAgent`. The agent does NOT need the MP
`KeyStateWorker` (it has no MP zones).

### Step 5.5 — Clean up any migrated data in dev DBs

Since the migration already ran on dev databases, existing
`MPDnssecKeyStore` tables may contain non-MP zone keys.
Manual DB cleanup — no migration code. Johan handles this
directly on the dev/test machines.

### Step 5.6 — Decouple StartMPSigner from tdns.StartAuth

**File**: `tdns-mp/v2/start_signer.go`

Replace the `conf.Config.StartAuth(ctx, apirouter)` call with
explicit `StartEngine` calls for only the engines the mpsigner
actually needs. This matches the pattern already established
by `StartMPAgent` and `StartMPCombiner`, which both manage
their own startup without calling tdns startup functions.

**Engines to start** (from current `StartAuth`):

- `APIdispatcher` — yes (API)
- `RefreshEngine` — yes (zone refresh)
- `Notifier` — yes (outbound NOTIFYs)
- `AuthQueryEngine` — yes (DNS queries)
- `ZoneUpdaterEngine` — yes (zone data updates)
- `UpdateHandler` — yes (DNS UPDATE processing)
- `NotifyHandler` — yes (inbound NOTIFYs)
- `DnsEngine` — yes (DNS listener)
- `ResignerEngine` — yes (re-signing)
- `KeyStateWorker` (tdns) — yes (non-MP zone key lifecycle)

**Engines to DROP**:

- `ValidatorEngine` — not needed by mpsigner
- `ImrEngine` — not needed by mpsigner
- `ScannerEngine` — not needed by mpsigner
- `DeferredUpdaterEngine` — superseded by OnFirstLoad callbacks
- `DelegationSyncher` — not needed by mpsigner
- `KeyBootstrapper` — not needed by mpsigner

**Why**: `StartAuth` is a grab bag that will change over time.
The `KeyStateWorker` addition (Phase 4) silently started
running in the mpsigner — we got lucky that it was correct.
The next addition might not be. Explicit startup means the
mpsigner's behavior only changes when someone intentionally
changes it.

### Step 5.7 — Build and smoke test

```bash
cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make
cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make
```

Verify:
- `mpcli signer keystore dnssec list` for an MP zone shows
  keys from `MPDnssecKeyStore`
- `mpcli signer keystore dnssec list` for a non-MP zone shows
  keys from `DnssecKeyStore`
- Agent auto-zone keys are in `DnssecKeyStore` only

---

## Risk Assessment and Scope Estimates

### Phase 1: tdns-mp gets its own keystore table

**Risk: LOW.** Additive changes only — new table, new constants,
SQL string replacements. tdns is untouched. All changes are within
tdns-mp where the MP keystore code already lives as local copies.

**Main risk**: Step 1.4 (GenerateKeyMaterial extraction) touches
tdns's `sig0_utils.go`, which is shared infrastructure. The
extraction is mechanical (cut at line 275), but any mistake in the
refactoring breaks key generation for both products. Mitigated by
build verification of both products.

**Estimated scope**:
- ~10 lines new (table schema, constants)
- ~30 SQL string replacements across signer_keydb.go, mp_signer.go
- ~15 `tdns.DnskeyState*` → local constant replacements across
  4-5 files
- ~40 lines for `GenerateKeyMaterial` extraction + `GenerateKeypairMP`
- **Total: ~50 lines new/modified in tdns-mp, ~20 in tdns**

### Phase 2: Clean MP awareness from tdns

**Risk: MEDIUM.** Removing code and simplifying branches. Each
deletion could expose a hidden dependency the grep-based analysis
missed. The `go build` step after each substep is the safety net.

**Main risks**:
- Removing `multiProviderGating` from `sign.go` changes signing
  behavior for any zone that has `OptMultiProvider` set. After the
  split this shouldn't happen in tdns-auth, but if a config file
  accidentally sets it, the signer would promote keys without
  propagation gating. Acceptable because tdns-auth should not be
  signing MP zones.
- Removing `extractRemoteDNSKEYs` from `sign.go` — verify it has
  no non-MP callers before deleting.
- Schema change (removing columns) means any existing DB file on
  a dev machine becomes incompatible. Not a problem (no installed
  base) but could surprise during local testing.

**Estimated scope**:
- ~120 lines deleted from keystore.go (5 functions + constant)
- ~30 lines simplified in key_state_worker.go
- ~20 lines simplified in sign.go
- ~10 lines in ops_dnskey.go, apihandler_funcs.go, structs.go,
  db_schema.go
- **Total: ~180 lines removed/simplified across ~8 files**

### Phase 3: CLI and API split

**Risk: MEDIUM-HIGH.** This is the most labor-intensive phase.
`APIkeystoreMP` is a near-copy of tdns's `DnssecKeyMgmt` (~290
lines) adapted for the MP table and MP states. The risk is
subtle behavioral differences between the two copies diverging
over time, and the rollover command potentially not working for
non-MP zones (unknown until tested).

**Main risks**:
- `DnssecKeyMgmt` is ~290 lines with 8 subcommands. Copying and
  adapting it is straightforward but tedious. Missing a table name
  or state reference in one subcommand would be a silent bug.
- The rollover logic may have implicit MP assumptions that only
  surface at runtime (not caught by `go build`).
- The mpagent route (line 24 in agent_routes.go) also points to
  the shared handler — needs the same fix, easy to overlook.

**Estimated scope**:
- ~300 lines new in tdns-mp (APIkeystoreMP handler)
- ~2 lines changed in route files
- ~15 lines simplified in tdns CLI (list output, setstate
  validation)
- **Total: ~320 lines new/modified, mostly in one new file**

### Phase 4: Wire KeyStateWorker into StartAuth

**Risk: LOW.** Two lines of code (StartEngine call) plus comment
cleanup. The worker is already written and tested via tdns-mp.
The only risk is config — if `Kasp` config is not present in
tdns-auth's config file, the worker uses safe defaults (1h
propagation delay, 1 standby ZSK, 1m check interval).

**Estimated scope**:
- ~2 lines new in main_initfuncs.go
- ~30 lines of comments replaced in key_state_worker.go
- **Total: ~32 lines changed**

### Phase 5: Post-implementation corrections

**Risk: MEDIUM.** Three distinct sub-tasks with different risk
profiles.

**Step 5.1 (remove migration)**: LOW risk. Deleting code that
shouldn't have existed. No functional change for fresh DBs.

**Step 5.2 (zone-type-aware API routing)**: MEDIUM risk. The
`if` at the API entry point is simple, but the `list`
subcommand (query both tables, merge, display in sections,
support `--mp-only`/`--non-mp-only` flags) adds CLI complexity.
Risk of showing stale or incomplete data if the zone-type
lookup fails (zone not yet loaded at query time).

**Step 5.4 (agent KeyStateWorker)**: LOW risk. Adding one
`StartEngine` call to `StartMPAgent`. The worker already
exists and handles non-MP zones correctly.

**Step 5.6 (decouple StartMPSigner from StartAuth)**: MEDIUM
risk. Replacing one function call with 10 explicit
`StartEngine` calls is mechanical, but getting the list wrong
means a missing engine at runtime — which may not be caught
by `go build`. Dropping 6 engines is a net simplification,
but each drop should be verified: confirm no transitive
dependency from the mpsigner's code paths into the dropped
engine. The `ImrEngine` drop is the one to double-check —
if any MP transport code uses IMR indirectly, removing it
breaks discovery.

**Estimated scope**:
- ~10 lines removed (migration function)
- ~15 lines changed in APIkeystoreMP (zone-type routing)
- ~30 lines for CLI list dual-table display + flags
- ~2 lines added to StartMPAgent (KeyStateWorker)
- ~25 lines in StartMPSigner (replace StartAuth call with
  explicit engine list)
- **Total: ~80 lines changed across ~4 files**

### Overall

| Phase | Risk | Lines changed | Files touched |
|-------|------|---------------|---------------|
| 1     | Low  | ~70           | ~8            |
| 2     | Med  | ~180 (mostly deletions) | ~8  |
| 3     | Med-High | ~320 (mostly new) | ~4    |
| 4     | Low  | ~32           | 2             |
| 5     | Med  | ~80           | ~4            |
| **Total** | | **~680** | **~18 unique files** |

Phase 3 is the largest and riskiest. Phase 2 has the most files
but is mostly mechanical deletion. Phases 1 and 4 are
straightforward. Phase 5 is moderate — the startup decoupling
(5.6) and CLI list changes (5.2) need the most care.

---

## Verification

After all phases:

```bash
# Both build cleanly
cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make
cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make

# No MP keystore references in tdns key_state_worker
grep -r 'mpdist\|mpremove\|foreign\|OptMultiProvider' \
   tdns/v2/key_state_worker.go
# → zero hits

# tdns-mp uses only MPDnssecKeyStore
grep -r 'DnssecKeyStore' \
   tdns-mp/v2/signer_keydb.go tdns-mp/v2/mp_signer.go
# → only MPDnssecKeyStore
```
