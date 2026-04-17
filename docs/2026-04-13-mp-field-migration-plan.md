# Migrate MP Field from tdns.ZoneData to tdns-mp MPZoneData

Date: 2026-04-13
Updated: 2026-04-14 (audit + accessor migration + signing
  migration + MPOptions + MPState rename)
Status: Design plan, not yet implemented
Related: Combiner persistence separation (completed),
  ongoing tdns->tdns-mp migration

## Goal

Move the MP state from `tdns.ZoneData.MP` to a new
`MP *MPState` field on `tdnsmp.MPZoneData`, with the
**`MPState` type defined in tdns-mp**. Additionally,
migrate zone signing orchestration (`SignZone`,
`ResignerEngine`) and MP-dynamic options to tdns-mp.
This breaks the dependency that forces MP state and
signing logic to be defined in tdns despite being
exclusively MP functionality.

## Design Principles

### Migrate, Don't Shadow

The tdns `legacy_*.go` files are dead code -- the tdns
MP implementation no longer works and the files exist
only to avoid compilation errors. We don't need to
maintain correctness of promoted methods. Instead:

- **Migrate** accessor methods to `*MPZoneData` receivers
  in tdns-mp. They become self-contained, operating on
  the local `mpzd.MP` field directly.
- **Leave** the originals in tdns for compilation.
  They become unreachable from tdns-mp via shadowing.
- **Convert** all free functions that take raw
  `*tdns.ZoneData` to `*MPZoneData` receivers, so they
  naturally use `mpzd.MP` instead of promoted accessors.

This eliminates the split-brain problem at the source:
there is no code path in tdns-mp that reaches the old
`tdns.ZoneData.MP` field.

### tdns becomes MP-agnostic

tdns should have no special code paths for multi-provider.
MP-dynamic options (set by HSYNC analysis) move to a
local `MPOptions` map on `*MPZoneData`. tdns core
infrastructure never sees them. MP signing orchestration
moves to tdns-mp. tdns keeps only the simple
single-signer signing path.

## Current State

```
tdns/v2/structs.go:
  type ZoneData struct {
      ...
      MP            *ZoneMPExtension
      RemoteDNSKEYs []dns.RR
      Options       map[ZoneOption]bool
  }

tdns-mp/v2/mpzonedata.go:
  type MPZoneData struct {
      *tdns.ZoneData       // embedded
      SyncQ chan SyncRequest
  }
```

All `.MP.` accesses in tdns-mp go through the promoted
field. The type `ZoneMPExtension` is defined in tdns.
`RemoteDNSKEYs` is a direct field on `ZoneData`.
MP-dynamic options (`OptInlineSigning`, `OptMultiSigner`,
`OptAllowEdits`, etc.) are set on `zd.Options` by HSYNC
analysis in tdns-mp but read by tdns code.

## Target State

```
tdns-mp/v2/mpzonedata.go:
  type MPZoneData struct {
      *tdns.ZoneData
      MP        *MPState
      MPOptions map[tdns.ZoneOption]bool
      SyncQ     chan SyncRequest
  }

tdns-mp/v2/mp_extension.go (new file):
  type MPState struct {
      CombinerData         *core.ConcurrentMap[...]
      UpstreamData         *core.ConcurrentMap[...]
      MPdata               *tdns.MPdata
      AgentContributions   map[string]map[...]
      PersistContributions func(...)
      LastKeyInventory     *tdns.KeyInventorySnapshot
      LocalDNSKEYs         []dns.RR
      RemoteDNSKEYs        []dns.RR    // moved from ZoneData
      KeystateOK           bool
      KeystateError        string
      KeystateTime         time.Time
      RefreshAnalysis      *tdns.ZoneRefreshAnalysis
  }

  // Migrated accessors
  func (mpzd *MPZoneData) GetKeystateOK() bool { ... }
  func (mpzd *MPZoneData) SetKeystateOK(ok bool) { ... }
  func (mpzd *MPZoneData) GetRemoteDNSKEYs() []dns.RR { ... }
  func (mpzd *MPZoneData) SetRemoteDNSKEYs(keys []dns.RR) { ... }
  // ... etc

  // Migrated signing
  func (mpzd *MPZoneData) SignZone(kdb *tdns.KeyDB, force bool) (int, error) { ... }
  func (mpzd *MPZoneData) SetupZoneSigning(resignq chan<- *MPZoneData) error { ... }
```

## Type Dependencies

All field types are importable from tdns-mp:

| Field | Type | Defined in |
|-------|------|------------|
| CombinerData | `*core.ConcurrentMap[string, tdns.OwnerData]` | core + tdns |
| UpstreamData | `*core.ConcurrentMap[string, tdns.OwnerData]` | core + tdns |
| MPdata | `*tdns.MPdata` | tdns |
| AgentContributions | `map[string]map[string]map[uint16]core.RRset` | core |
| PersistContributions | `func(...)` | built-in |
| LastKeyInventory | `*tdns.KeyInventorySnapshot` | tdns |
| LocalDNSKEYs | `[]dns.RR` | miekg/dns |
| RemoteDNSKEYs | `[]dns.RR` | miekg/dns |
| KeystateOK/Error/Time | `bool`/`string`/`time.Time` | built-in |
| RefreshAnalysis | `*tdns.ZoneRefreshAnalysis` | tdns |

No circular dependencies. Import direction tdns-mp->tdns
already exists.

## Verified Assumptions (2026-04-14 audit)

### RefreshEngine zone flip is safe

The RefreshEngine **does NOT replace the Zones map
entry** during refresh. It modifies individual fields
on the existing `*tdns.ZoneData` pointer (Owners,
OwnerIndex, IncomingSerial, Data, etc.) but **never
touches `zd.MP`** during the hard flip. The
`MPZoneData` wrapper in the `Zones` cache is long-lived
and survives all refreshes. Only 7 `Zones.Set` calls
exist in the entire tdns codebase, all in zone
creation/initialization code, none in refresh.

**This is the foundation of the migration.** The local
`mpzd.MP` field on the wrapper IS the persistent state.

### Legacy methods vs local functions

tdns defines methods on `*ZoneData` in `legacy_*.go`
files (e.g., `LocalDnskeysFromKeystate`,
`RequestAndWaitForKeyInventory`, `populateMPdata`,
`snapshotUpstreamData`). tdns-mp has **local free
functions** (or `*MPZoneData` methods) with the same
names. tdns-mp exclusively calls its own local versions
-- never the promoted methods. No name-collision
ambiguity.

### MP zones never have signing options in static config

MP zones are configured with only `multi-provider: true`
in YAML config. `OptInlineSigning` and `OptOnlineSigning`
are **never** set statically for MP zones. They are set
dynamically by HSYNC analysis at zone refresh time.

This means the tdns `parseconfig.go:698` signing callback
(which checks static options) is **never registered** for
MP zones. The tdns `ResignerEngine` never sees MP zones.
There is no conflict between tdns and tdns-mp signing.

### Inline-signing pre-signs the zone

For inline-signed MP zones (the MP signer model),
`SignZone()` calls `PublishDnskeyRRs()` which merges
`RemoteDNSKEYs` into the zone's DNSKEY RRset, then
signs the entire zone. After signing, the zone data
contains the correct DNSKEY RRset (local + remote)
with valid RRSIGs.

The query responder (`queryresponder.go:140`) checks
`len(rrset.RRSIGs) > 0` and short-circuits -- it
serves the pre-signed data as-is. Zone transfers
serve the same pre-signed data. **No on-the-fly
DNSKEY composition is needed for the inline-signing
use model.**

## MPOptions: Dynamic Options on *MPZoneData

### Problem

HSYNC analysis in tdns-mp sets options like
`OptInlineSigning`, `OptMultiSigner`, `OptAllowEdits`
on `zd.Options` (the `tdns.ZoneData.Options` map). This
leaks MP-derived state into tdns's data structures.
tdns should be MP-agnostic.

### Solution

Add `MPOptions map[tdns.ZoneOption]bool` to
`*MPZoneData`. MP-dynamic options live there. tdns-mp
code checks `mpzd.MPOptions[...]` instead of
`mpzd.Options[...]` for these options.

### Which options move

**Move to MPOptions** (dynamic, set by HSYNC analysis,
only read by tdns-mp code):

| Option | Set by | Read by |
|--------|--------|---------|
| `OptMultiSigner` | MPPreRefresh | MP SignZone (mode 4) |
| `OptAllowEdits` | populateMPdata, MPPreRefresh | combiner code |
| `OptMPDisallowEdits` | populateMPdata | combiner code |
| `OptMPNotListedErr` | populateMPdata | MP error reporting |

**Stay on zd.Options** (read by tdns core
infrastructure that tdns-mp doesn't override):

| Option | Why it stays |
|--------|-------------|
| `OptMultiProvider` | Static config. Read by tdns for zone setup routing. |
| `OptInlineSigning` | Read by `queryresponder.go:147` (on-the-fly signing gate), `dnsutils.go:224` (zone xfr SOA re-signing), `resigner.go:77` (resign skip guard). These are deep in tdns serving infrastructure. For inline-signed MP zones, the pre-signed RRSIGs mean the query responder short-circuits at line 140 anyway, but the guard must still pass for edge cases. |
| `OptOnlineSigning` | Same reads as OptInlineSigning. Only set statically for agent auto-zones (agent_setup.go:66). |
| `OptDelSyncChild` | Read by `delegation_sync.go`, `zone_utils.go`. Mixed static+dynamic. |
| `OptDelSyncParent` | Static config only. |

### Write site changes

HSYNC analysis in `populateMPdata()` and
`MPPreRefresh()` currently writes to `mpzd.Options[...]`
(promoted to `zd.Options`). After migration:
- `OptMultiSigner`, `OptAllowEdits`, `OptMPDisallowEdits`,
  `OptMPNotListedErr` -> write to `mpzd.MPOptions[...]`
- `OptInlineSigning` -> continues writing to
  `mpzd.Options[...]` (stays on zd.Options)

### The new_zd.Options complication

`populateMPdata()` currently runs on an ad-hoc wrapper
around `new_zd` in MPPreRefresh (line 1067). It writes
`OptMPDisallowEdits` and `OptAllowEdits` to
`new_zd.Options`. Then lines 1103-1115 read those
options from `new_zd.Options`.

After migration, `populateMPdata()` writes to
`newMpzd.MPOptions` (the temporary wrapper).
Wholesale-replace the persistent map with the
temporary one (just like MPdata is replaced):

```go
newMpzd.populateMPdata(mp)
mpzd.MP.MPdata = newMpzd.MP.MPdata
mpzd.MPOptions = newMpzd.MPOptions
```

This is safe because `MPOptions` only contains
MP-dynamic options rebuilt from scratch on every
refresh by `populateMPdata()` and `MPPreRefresh`.
There is no other state in the map to clobber. If
a new MP option is added to `populateMPdata()` in
the future, it automatically propagates -- no
per-key copy list to maintain.

Then lines 1103-1115 read from `mpzd.MPOptions`
instead of `new_zd.Options`. This works because the
persistent wrapper's MPOptions is the authoritative
source -- it doesn't need to survive the hard flip
on `zd.Options`, it lives on the wrapper.

### Read site changes

All reads of the moved options in tdns-mp change from
`mpzd.Options[Opt...]` to `mpzd.MPOptions[Opt...]`.

Sites verified for migration:
- `apihandler_agent.go:103` -- `zd` is `*MPZoneData`
  (declared at line 49). Change to `zd.MPOptions[...]`.
- `config.go:136` -- Category B callback, fixed to use
  `Zones.Get()`. Change to `mpzd.MPOptions[...]`.
- `hsync_utils.go:909` -- `mpzd` is `*MPZoneData`.
  Change to `mpzd.MPOptions[...]`.
- `hsync_utils.go:1103-1115` -- after MPPreRefresh
  conversion, reads `mpzd.MPOptions` (not
  `new_zd.Options`). See above.

Reads in tdns (all in `legacy_*.go` or `sign.go`) are
dead code -- they still read `zd.Options` which will
be `false` for the moved options. This is correct:
tdns signing (mode 1 only after migration) doesn't
need these options.

## Signing Migration

### What moves to tdns-mp

| Function | Current location | Why it moves |
|----------|-----------------|-------------|
| `SignZone()` | sign.go:353 | Modes 2-4 are MP-only. Needs `RemoteDNSKEYs` (on `mpzd.MP`), `OptMultiSigner` (on `mpzd.MPOptions`). |
| `extractRemoteDNSKEYs()` | sign.go:634 | Only called by SignZone mode 4. Uses `RemoteDNSKEYs` field. |
| `PublishDnskeyRRs()` remote merge | ops_dnskey.go:83-101 | Merges `RemoteDNSKEYs` into DNSKEY RRset. |
| `SetupZoneSigning()` | zone_utils.go:1062 | Must call MP `SignZone()` and feed MP `ResignerEngine`. |
| `ResignerEngine()` | resigner.go:14 | Must call MP `SignZone()` on `*MPZoneData`. |

### What stays in tdns

| Function | Why it stays |
|----------|-------------|
| `SignRRset()` | Pure cryptography: get keys, produce RRSIGs. No MP awareness. Called by query responder and zone transfer for on-the-fly signing. |
| `signRRsetForZone()` | Query responder wrapper around SignRRset. |
| `ensureActiveDnssecKeys()` | Key management. Used by both tdns and MP signing. |
| `PublishDnskeyRRs()` base | Local DNSKEY publication (without remote merge). |
| `SignZone()` | Simplified to mode 1 only (single signer, no MP branching). |
| `SetupZoneSigning()` | For non-MP zones. |
| `ResignerEngine()` | For non-MP zones. |

### MP SignZone implementation

```go
func (mpzd *MPZoneData) SignZone(
    kdb *tdns.KeyDB, force bool) (int, error) {

    zd := mpzd.ZoneData

    // Mode selection using MPOptions
    if mpzd.MPOptions[tdns.OptMultiSigner] {
        // Mode 4: extract remote DNSKEYs
        mpzd.extractRemoteDNSKEYs(kdb)
    } else {
        // Mode 2: single-signer MP, strip remote
        mpzd.SetRemoteDNSKEYs(nil)
    }

    // Ensure active keys (uses tdns infrastructure)
    dak, err := zd.ensureActiveDnssecKeys(kdb)

    // Publish DNSKEYs (local + remote merge)
    mpzd.PublishDnskeyRRs(dak)

    // Sign all RRsets (delegates to tdns SignRRset)
    for each rrset in zone {
        zd.SignRRset(&rrset, name, dak, force)
    }
}
```

Key points:
- Mode 3 (non-signer) gated by `weAreASigner()` check
  or by not enabling signing at all
- The iteration and actual signing delegate to tdns
  `SignRRset()` -- no crypto duplication
- `RemoteDNSKEYs` accessed via `mpzd.MP.RemoteDNSKEYs`
- `OptMultiSigner` checked via `mpzd.MPOptions`

### Role model: only signers need MP signing

- **Agent**: Has an auto-zone (identity zone, signed
  with `OptOnlineSigning`). This is a trivial
  single-signer zone. The tdns `ResignerEngine`
  handles it fine via `agent_setup.go:78`. **No MP
  signing needed. No changes to agent_setup.go.**
- **Combiner**: Never signs anything. No resigner
  involvement at all.
- **Signer** (`AppTypeMPSigner` / `AppTypeAuth`):
  Signs MP zones with inline-signing. Modes 2-4,
  `RemoteDNSKEYs`, `extractRemoteDNSKEYs`. **This
  is the only role that needs the MP signing path.**

### MP ResignerEngine (signer only)

~40 lines, trivial adaptation of tdns version:

```go
func MPResignerEngine(ctx context.Context,
    resignch chan *MPZoneData) {
    // ... same ticker logic ...
    for _, mpzd := range ZonesToKeepSigned {
        if !mpzd.Options[tdns.OptInlineSigning] {
            continue
        }
        mpzd.SignZone(mpzd.ZoneData.KeyDB, false)
    }
}
```

Channel is `chan *MPZoneData` (not `chan *ZoneData`).
Stores `*MPZoneData` pointers. Calls `mpzd.SignZone()`.

Both the tdns and MP ResignerEngines run, but they
serve different populations. The tdns one handles
non-MP zones (and the agent auto-zone). The MP one
handles MP signer zones. They don't interfere --
each has its own channel and its own zone map.

### MP SetupZoneSigning

```go
func (mpzd *MPZoneData) SetupZoneSigning(
    resignq chan<- *MPZoneData) error {
    // ... same guards as tdns version ...
    mpzd.SignZone(mpzd.ZoneData.KeyDB, false)
    resignq <- mpzd
    return nil
}
```

### Wiring (signer only)

tdns-mp `MainInit` registers signing callbacks that
point to the MP ResignerEngine. This is the existing
`main_init.go:98-105` callback, updated:

```go
zd.OnFirstLoad = append(zd.OnFirstLoad,
    func(zd *tdns.ZoneData) {
        if zd.Options[tdns.OptInlineSigning] {
            mpzd, ok := Zones.Get(zd.ZoneName)
            if !ok { return }
            mpzd.SetupZoneSigning(mpResignQ)
        }
    })
```

Note: `OptInlineSigning` stays on `zd.Options` (set
dynamically by HSYNC analysis), so the check works.
The `mpzd.SetupZoneSigning()` call sends the zone to
the MP ResignerEngine, not the tdns one.

The tdns `parseconfig.go:698` callback never fires
for MP zones (they don't have `OptInlineSigning` in
static config). The agent auto-zone goes to the tdns
resigner via `agent_setup.go:78` (unchanged). No tdns
changes needed.

### RemoteDNSKEYs migration

`RemoteDNSKEYs` moves from `tdns.ZoneData` field to
`mpzd.MP.RemoteDNSKEYs`:

- `Get/SetRemoteDNSKEYs` accessors migrate to
  `*MPZoneData` (same as KEYSTATE accessors)
- tdns `ZoneData.RemoteDNSKEYs` field stays for
  compilation (dead weight, can be removed when
  tdns signing is stripped of mode 2-4)
- All tdns-mp callers already have `*MPZoneData`

Callers of `SetRemoteDNSKEYs` in tdns-mp:
- `hsync_utils.go:282-352` (RequestAndWaitForKeyInventory)
  -- already being converted to `*MPZoneData` receiver

Callers of `GetRemoteDNSKEYs` in tdns-mp:
- `hsync_utils.go:95` (LocalDnskeysChanged) -- already
  has `*MPZoneData` available

### tdns SignZone simplification

After migration, tdns `SignZone()` is simplified to:

```go
func (zd *ZoneData) SignZone(
    kdb *KeyDB, force bool) (int, error) {
    // Mode 1 only: single signer, no MP
    dak, err := zd.ensureActiveDnssecKeys(kdb)
    err = zd.PublishDnskeyRRs(dak)
    // ... sign all RRsets ...
}
```

All multi-provider branching (modes 2-4),
`extractRemoteDNSKEYs`, `weAreASigner()` check,
`GetRemoteDNSKEYs` merge in `PublishDnskeyRRs` --
all removed. Clean single-signer path.

### Why DNSKEY queries work for multi-signer

For inline-signed MP zones (the MP use model):

1. MP `ResignerEngine` calls `mpzd.SignZone()` periodically
2. `mpzd.SignZone()` calls `mpzd.extractRemoteDNSKEYs()`
   -> stores on `mpzd.MP.RemoteDNSKEYs`
3. `mpzd.PublishDnskeyRRs()` merges local + remote into
   the zone's DNSKEY RRset (on `mpzd.ZoneData`)
4. `mpzd.SignZone()` signs everything including the
   merged DNSKEY RRset via `zd.SignRRset()`
5. Query responder serves pre-signed data -- RRSIGs
   already attached, short-circuits at line 140
6. Zone transfers serve the same pre-signed data

**No on-the-fly DNSKEY composition needed.** The zone
data is pre-signed with the correct merged RRset.

### Future: online-signing DNSKEY queries

If MP ever needs online-signing (on-the-fly) for
DNSKEY queries, the query responder would need to
compose local + remote DNSKEYs before signing. This
would require a composition hook (function pointer or
callback on `ZoneData`). Not needed for the
inline-signing use model. Can be added later without
changing the architecture.

## Accessor Inventory

### Methods on *tdns.ZoneData that access .MP
### (tdns/v2/mpmethods.go -- to be migrated)

| # | Method | Fields | R/W | tdns-mp calls |
|---|--------|--------|-----|---------------|
| 1 | `GetLastKeyInventory()` | `.MP.LastKeyInventory` | R | 4 |
| 2 | `SetLastKeyInventory(inv)` | `.MP.LastKeyInventory` | W | 2 |
| 3 | `GetKeystateOK()` | `.MP.KeystateOK` | R | 2 |
| 4 | `SetKeystateOK(ok)` | `.MP.KeystateOK` | W | 6 |
| 5 | `GetKeystateError()` | `.MP.KeystateError` | R | 6 |
| 6 | `SetKeystateError(err)` | `.MP.KeystateError` | W | 6 |
| 7 | `GetKeystateTime()` | `.MP.KeystateTime` | R | 1 |
| 8 | `SetKeystateTime(t)` | `.MP.KeystateTime` | W | 1 |
| 9 | `EnsureMP()` | `.MP` (init) | W | 13 |

### RemoteDNSKEYs accessors (tdns/v2/structs.go)

| # | Method | Fields | R/W | tdns-mp calls |
|---|--------|--------|-----|---------------|
| 10 | `GetRemoteDNSKEYs()` | `zd.RemoteDNSKEYs` | R | 1 |
| 11 | `SetRemoteDNSKEYs(keys)` | `zd.RemoteDNSKEYs` | W | 6 |

Total: 11 methods to migrate to `*MPZoneData`.
The tdns originals stay for compilation.

### Methods in legacy files (NOT called from tdns-mp)

| Method (tdns) | tdns-mp equivalent |
|---------------|--------------------|
| `LocalDnskeysFromKeystate()` | Free function -> receiver |
| `populateMPdata()` | `*MPZoneData` method |
| `snapshotUpstreamData()` | Free function -> receiver |
| `CombineWithLocalChanges()` | `*MPZoneData` method |
| `mergeWithUpstream(...)` | `*MPZoneData` method |

No migration needed -- local versions already shadow.

## Three Categories of Callers

(Reduced from five in audit version. The accessor
migration eliminates Categories D and E.)

### Category A: Methods on *MPZoneData (88 sites)

These access `mpzd.MP.{field}` inside receiver methods.
After adding the local `MP` field, Go automatically
resolves to it. **Zero code changes needed.**

| File | Count | Top methods |
|------|-------|-------------|
| combiner_utils.go | 61 | replaceCombinerDataByRRtypeLocked (16), AddCombinerData (14) |
| combiner_chunk.go | 14 | getEditPolicy (3), rrExistsInZone (3) |
| hsync_utils.go | 13 | populateMPdata (10), PostRefresh (3) |
| **Total** | **88** | 22 of 42 methods |

### Category B: OnFirstLoad callbacks (3 sites)

Callbacks have signature `func(zd *tdns.ZoneData)`.
Inside, `zd.MP` accesses the OLD tdns field. Must
look up `*MPZoneData` via `Zones.Get()`.

**config.go:113-144** (combiner contributions):
- Fix: `mpzd, _ := Zones.Get(zd.ZoneName)`, use
  `mpzd.MP` and `mpzd.RebuildCombinerData()`.

**config.go:147-149** (signal keys):
- Fix: `mpzd, _ := Zones.Get(zd.ZoneName)`,
  `mpzd.ApplyPendingSignalKeys(hdb)`.

**start_agent.go:151** (parentsync detection):
- Fix: `w, _ := Zones.Get(zd.ZoneName)`.

### Category C: Free functions to convert (5 functions)

Convert ALL to `*MPZoneData` receivers.

**1. LocalDnskeysFromKeystate** (hsync_utils.go:159)
- 7 direct `.MP` + 1 accessor + 3 `EnsureMP()`
- Migrated: `(mpzd *MPZoneData) LocalDnskeysFromKeystate()`

**2. RequestAndWaitForKeyInventory** (hsync_utils.go:275)
- 18 promoted accessor calls on raw `*tdns.ZoneData`
- Migrated: `(mpzd *MPZoneData) RequestAndWaitForKeyInventory(ctx, tm)`

**3. snapshotUpstreamData** (hsync_utils.go:972)
- 2 `.MP` + 1 `EnsureMP()`
- Migrated: `(mpzd *MPZoneData) snapshotUpstreamData()`

**4. LocalDnskeysChanged** (hsync_utils.go:85)
- Calls `zd.GetRemoteDNSKEYs()` (line 95)
- Must convert to receiver so it uses migrated
  accessor reading `mpzd.MP.RemoteDNSKEYs` (needed
  for Phase 2 when `zd.RemoteDNSKEYs` field goes away)
- Between Phase 1 and Phase 2, the promoted accessor
  still reads the old field consistently with tdns
  `SignZone`, so no split-brain. But conversion is
  required before Phase 2 can remove the field.
- Migrated: `(mpzd *MPZoneData) LocalDnskeysChanged(new_zd *tdns.ZoneData)`

**5. MPPreRefresh** (hsync_utils.go:1009)
- 15 `.MP` + 4 ad-hoc wrappers
- Migrated: `(mpzd *MPZoneData) MPPreRefresh(...)`
- See MPPreRefresh section for details

All callers already have `*MPZoneData` in scope.

## The MPPreRefresh Problem (simplified)

MPPreRefresh is called via `OnZonePreRefresh` callback.
After migration, the callback does `Zones.Get()` to
obtain `*MPZoneData` and calls
`mpzd.MPPreRefresh(new_zd, ...)`.

Persistent MP state (AgentContributions, CombinerData,
RefreshAnalysis) lives on `mpzd.MP` (the long-lived
wrapper). No copying between `zd.MP` and `new_zd.MP`
needed. Only `MPdata` (signing state from HSYNC) is
recomputed from `new_zd` via a temporary wrapper.

## Ad-hoc MPZoneData Wrappers (9 creation sites)

After migration: 2 permanent sites in `mpzonedata.go`
(with `EnsureMP()`), 1 temporary in MPPreRefresh
(with `EnsureMP()`), 0 ad-hoc wrappers elsewhere.
All 6 other sites eliminated by Steps 3-4.

## Implementation Steps

### Phase 1: MP field migration (atomic commit)

#### Step 1: Define new type + field + cache init

Create `tdns-mp/v2/mp_extension.go`:
- `MPState` struct (same fields as
  `tdns.ZoneMPExtension` + `RemoteDNSKEYs`)
- `EnsureMP()` on `*MPZoneData`

Add `MP *MPState` and
`MPOptions map[tdns.ZoneOption]bool` fields to
`MPZoneData` in `mpzonedata.go`.

Initialize in cache creation points:
- `mpzonedata.go:72` (`Get()`) -- `mpzd.EnsureMP()`
  + `mpzd.MPOptions = make(...)`
- `mpzonedata.go:147` (`getOrCreate()`) -- same

#### Step 2: Migrate accessors to *MPZoneData

In `mp_extension.go`, define all 11 accessor methods
on `*MPZoneData` (8 KEYSTATE + EnsureMP +
Get/SetRemoteDNSKEYs). These shadow promoted versions.

#### Step 3: Convert Category C free functions

Convert to `*MPZoneData` receivers in order:
1. `snapshotUpstreamData`
2. `LocalDnskeysFromKeystate`
3. `RequestAndWaitForKeyInventory`
4. `LocalDnskeysChanged`
5. `MPPreRefresh` (depends on 1-4)

Update all callers.

#### Step 4: Fix Category B callbacks

Update OnFirstLoad callbacks in `config.go` and
`start_agent.go` to use `Zones.Get()`.

#### Step 5: Migrate MPOptions writes

Change HSYNC analysis option writes:
- `mpzd.Options[OptMultiSigner]` ->
  `mpzd.MPOptions[OptMultiSigner]`
- Same for `OptAllowEdits`, `OptMPDisallowEdits`,
  `OptMPNotListedErr`
- `OptInlineSigning` stays on `mpzd.Options`

Change all reads of moved options in tdns-mp.

**Steps 1-5 MUST be a single atomic commit.**
Implement step-by-step (each step should compile),
build between steps, squash into one commit at the end.

### Phase 2: Signing migration (separate commit)

Can be done after Phase 1, or in the same commit
if confidence is high.

#### Step 6: Migrate SignZone to *MPZoneData

Create `tdns-mp/v2/mp_signer.go`:
- `(mpzd *MPZoneData) SignZone(kdb, force)`
  with modes 2-4
- `(mpzd *MPZoneData) extractRemoteDNSKEYs(kdb)`
- `(mpzd *MPZoneData) PublishDnskeyRRs(dak)`
  (with remote DNSKEY merge)

#### Step 7: Migrate ResignerEngine + SetupZoneSigning

Create `tdns-mp/v2/mp_resigner.go`:
- `MPResignerEngine(ctx, chan *MPZoneData)`
- `(mpzd *MPZoneData) SetupZoneSigning(resignq)`

Wire into `MainInit` (signer role only):
- Create MP-specific `resignQ chan *MPZoneData`
- Start `MPResignerEngine` goroutine
- Update `main_init.go` OnFirstLoad signing callback
  to call `mpzd.SetupZoneSigning(mpResignQ)`

Note: `agent_setup.go:73-78` is NOT changed. The
agent auto-zone is a plain single-signer zone. It
uses tdns `zd.SignZone()` and the tdns ResignerEngine.
Only the signer role needs the MP signing path.

#### Step 8: Simplify tdns SignZone

Remove from tdns `SignZone()`:
- Multi-provider branching (modes 2-4)
- `weAreASigner()` check
- `extractRemoteDNSKEYs()` call
- `GetRemoteDNSKEYs()` log

Remove from tdns `PublishDnskeyRRs()`:
- Remote DNSKEY merge (lines 83-101)

Optionally remove:
- `RemoteDNSKEYs` field from `ZoneData`
- `Get/SetRemoteDNSKEYs` from `structs.go`
- `extractRemoteDNSKEYs()` function
  (Only if no compilation issues. Otherwise leave
  as dead code.)

#### Step 9: Verify

- Build both repos
- Verification greps:
  - `grep -r '\.ZoneData\.MP' tdns-mp/v2/` -> zero
  - `grep -r 'mpzd\.ZoneData\.MP' tdns-mp/v2/` -> zero
    (catches fully-qualified access to old field)
  - `grep -rn 'EnsureMP()' tdns-mp/v2/` -> only on
    `*MPZoneData` or cache init
  - `grep -rn '&MPZoneData{' tdns-mp/v2/` -> only in
    cache and MPPreRefresh temporary wrapper
  - `grep -rn 'RemoteDNSKEYs' tdns-mp/v2/` -> only
    via `mpzd.MP.RemoteDNSKEYs` or migrated accessors
- Lab test: refresh, zone signing, combiner
  persistence, KEYSTATE flow, zone transfer,
  leader elections, resync

## Dependency Order

```
Phase 1 (MP field migration):

  Step 1 (type + field + cache init)  ─┐
  Step 2 (migrate accessors)           │
  Step 3 (convert free functions)      ├─ ATOMIC
  Step 4 (fix callbacks)               │  COMMIT
  Step 5 (migrate MPOptions writes)   ─┘

Phase 2 (signing migration):

  Step 6 (migrate SignZone)           ─┐
  Step 7 (migrate ResignerEngine)      ├─ COMMIT
  Step 8 (simplify tdns SignZone)     ─┘

  Step 9 (verify + test)
```

Phase 1 is the critical atomic change. Phase 2 can
follow immediately or be deferred -- the code is
correct after Phase 1 (signing still works via
promoted `zd.SignZone()` from tdns, just with the
old RemoteDNSKEYs field path).

**Phase 1/Phase 2 boundary note**: Between phases,
tdns `SignZone()` and `PublishDnskeyRRs()` read/write
`zd.RemoteDNSKEYs` (old field). The migrated
`mpzd.GetRemoteDNSKEYs()` reads `mpzd.MP.RemoteDNSKEYs`
(new field, empty). This is safe because no tdns-mp
code calls the migrated accessor between phases --
`LocalDnskeysChanged` passes `mpzd.ZoneData` (the
embedded pointer) and calls the promoted accessor,
which reads the same old field as `SignZone`. Phase 2
converts all callers to use the new field atomically.

## Why This Works (no split-brain)

After Phase 1, every `.MP` access in tdns-mp
resolves to the local `mpzd.MP` field:

| Access pattern | Resolution |
|----------------|------------|
| `mpzd.MP.Field` (direct) | Local field (shadowing) |
| `mpzd.GetKeystateOK()` | Migrated method -> local field |
| `mpzd.EnsureMP()` | Migrated method -> local field |
| `mpzd.LocalDnskeysFromKeystate()` | Converted receiver -> local field |
| `mpzd.RequestAndWaitForKeyInventory(...)` | Converted receiver -> local field |
| `mpzd.LocalDnskeysChanged(new_zd)` | Converted receiver -> migrated GetRemoteDNSKEYs |
| `mpzd.GetRemoteDNSKEYs()` | Migrated method -> local field (Phase 2) |
| `mpzd.MPOptions[Opt...]` | Local map (not on zd.Options) |

After Phase 2, signing also uses local state:

| Access pattern | Resolution |
|----------------|------------|
| `mpzd.SignZone(kdb, force)` | Local method -> mpzd.MP |
| `mpzd.extractRemoteDNSKEYs(kdb)` | Local method -> mpzd.MP.RemoteDNSKEYs |
| `mpzd.PublishDnskeyRRs(dak)` | Local method -> mpzd.MP.RemoteDNSKEYs |

There is **no code path** in tdns-mp that reaches
`tdns.ZoneData.MP` or `tdns.ZoneData.RemoteDNSKEYs`
after migration.

## Size Estimate

**Phase 1:**
- `mp_extension.go`: ~100 lines (struct + EnsureMP +
  11 accessor methods)
- `mpzonedata.go`: ~5 lines (fields + cache init)
- Category C conversions: ~50 lines in `hsync_utils.go`
- Category B callbacks: ~15 lines in `config.go` +
  `start_agent.go`
- MPOptions writes: ~20 lines in `hsync_utils.go`
- Refresh simplification: ~30 lines removed
- Caller updates: ~20 lines across 3 files
- Total: ~210 added, ~60 removed, ~90 modified

**Phase 2:**
- `mp_signer.go`: ~200 lines (SignZone + extract +
  PublishDnskeyRRs)
- `mp_resigner.go`: ~60 lines (ResignerEngine +
  SetupZoneSigning)
- Wiring: ~15 lines in `main_init.go`
- tdns simplification: ~80 lines removed from
  `sign.go`, `ops_dnskey.go`
- Total: ~280 added, ~80 removed, ~30 modified

**Combined: ~490 added, ~140 removed, ~120 modified.**

## Risks

**MEDIUM:**

1. **Phase 1 atomic commit is large.** ~350 lines of
   net change across 7-8 files. **Mitigation**:
   implement step-by-step (each compiles), build
   between steps, squash into one commit.

2. **Runtime nil panics if cache init missed.**
   Only 2 sites in `mpzonedata.go`. Grep verifies.

3. **Phase 2 SignZone duplication.** The MP version
   shares structure with the tdns version. Must not
   diverge. **Mitigation**: the signing loop delegates
   to `zd.SignRRset()` in tdns -- only the
   orchestration is duplicated.

4. **MPOptions initialization.** Must be initialized
   alongside `EnsureMP()` in cache creation. Missing
   it = nil map panic on first MPOptions write.

**LOW:**

5. **Locking.** Migrated accessors use `mpzd.mu`
   (promoted). Same lock as before.

6. **OnFirstLoad timing.** Verify `Zones.Get()` runs
   before `MainInit()`.

## Future Work

After this migration:
- `tdns.ZoneMPExtension` can be removed when legacy
  files are deleted
- `tdns.ZoneData.RemoteDNSKEYs` can be removed after
  Phase 2
- `tdns.MPdata` sub-struct can be migrated to tdns-mp
- New tdns-mp-only fields go on local
  `MPState` or `MPOptions`
- Online-signing DNSKEY composition hook can be added
  if MP ever needs it (not needed for inline-signing)
- The pattern generalizes: any tdns function operating
  on MP state migrates to `*MPZoneData` receiver
