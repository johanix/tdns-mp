# Migrate MP Field from tdns.ZoneData to tdns-mp MPZoneData

Date: 2026-04-13
Status: Design plan, not yet implemented
Related: Combiner persistence separation (completed),
  ongoing tdns→tdns-mp migration

## Goal

Move the `MP *ZoneMPExtension` field from `tdns.ZoneData`
to `tdnsmp.MPZoneData`, with a **new type defined in
tdns-mp**. This breaks the dependency that forces all MP
state to be defined in tdns despite being exclusively MP
functionality. The new type can be extended with
tdns-mp-only fields.

## Current State

```
tdns/v2/structs.go:
  type ZoneData struct {
      ...
      MP *ZoneMPExtension
  }

tdns-mp/v2/mpzonedata.go:
  type MPZoneData struct {
      *tdns.ZoneData       // embedded
      SyncQ chan SyncRequest
  }
```

All `.MP.` accesses in tdns-mp go through the promoted
field from the embedded `*tdns.ZoneData`. The type
`ZoneMPExtension` is defined in tdns, locking tdns-mp
out of adding fields.

## Target State

```
tdns-mp/v2/mpzonedata.go:
  type MPZoneData struct {
      *tdns.ZoneData
      MP    *ZoneMPExtension  // shadows promoted field
      SyncQ chan SyncRequest
  }

tdns-mp/v2/mp_extension.go (new file):
  type ZoneMPExtension struct {
      // Migrated from tdns — same fields, local type
      CombinerData         *core.ConcurrentMap[string, tdns.OwnerData]
      UpstreamData         *core.ConcurrentMap[string, tdns.OwnerData]
      MPdata               *tdns.MPdata
      AgentContributions   map[string]map[string]map[uint16]core.RRset
      PersistContributions func(string, string, map[string]map[uint16]core.RRset) error
      LastKeyInventory     *tdns.KeyInventorySnapshot
      LocalDNSKEYs         []dns.RR
      KeystateOK           bool
      KeystateError        string
      KeystateTime         time.Time
      RefreshAnalysis      *tdns.ZoneRefreshAnalysis
      // Future tdns-mp-only fields go here
  }
```

Go shadowing: `mpzd.MP` resolves to the local field,
not the promoted `tdns.ZoneData.MP`. All ~100 method
calls on `*MPZoneData` automatically use the new field
with zero code changes.

The tdns `ZoneData.MP` field stays (used by the simpler
tdns agent). The tdns `ZoneMPExtension` type stays (used
by legacy code). No tdns changes required.

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
| KeystateOK/Error/Time | `bool`/`string`/`time.Time` | built-in |
| RefreshAnalysis | `*tdns.ZoneRefreshAnalysis` | tdns |

No circular dependencies. Import direction tdns-mp→tdns
already exists. The `MPdata` sub-struct stays in tdns for
now (small, stable, used by tdns agent too). Can be
migrated later if needed.

## Three Categories of Callers

### Category A: Methods on *MPZoneData (~100 sites)

These access `mpzd.MP.{field}` inside receiver methods.
After adding the local `MP` field, Go automatically
resolves to it. **Zero code changes needed.**

Files: `combiner_utils.go`, `combiner_chunk.go`,
`combiner_msg_handler.go`, `apihandler_combiner.go`,
`apihandler_agent.go`, `hsync_utils.go` (PostRefresh),
`syncheddataengine.go`, `signer_msg_handler.go`,
`hsyncengine.go`, `key_state_worker.go`.

### Category B: OnFirstLoad callbacks (2 sites)

Callbacks have signature `func(zd *tdns.ZoneData)`.
Inside, `zd.MP` accesses the OLD tdns field, not the
new local field. Must look up `*MPZoneData` via
`Zones.Get()`.

**config.go:113-144** (combiner contributions):
- Accesses: `PersistContributions`, `AgentContributions`
- Fix: look up `mpzd, _ := Zones.Get(zd.ZoneName)`,
  use `mpzd.MP` for all accesses. Already does
  `zd.EnsureMP()` — replace with `mpzd.EnsureMP()`.

**config.go:147-149** (signal keys):
- Already creates `&MPZoneData{ZoneData: zd}` wrapper.
- Fix: look up real `mpzd` from `Zones.Get()` instead
  of ad-hoc wrapper (wrapper has nil local MP field).

Note: start_agent.go callbacks (lines 143, 172) and
agent_setup.go callbacks do NOT access .MP directly.

### Category C: Free functions with *tdns.ZoneData (3 sites)

These receive raw `*tdns.ZoneData` and access `.MP`.
Must be converted to either:
- Receiver methods on `*MPZoneData`, or
- Accept `*MPZoneData` parameter, or
- Do `Zones.Get()` lookup internally.

**1. LocalDnskeysFromKeystate** (hsync_utils.go:159)
- Signature: `func LocalDnskeysFromKeystate(zd *tdns.ZoneData) (bool, *tdns.DnskeyStatus, error)`
- 7 `.MP` accesses: reads `MPdata.ZoneSigned`,
  reads+writes `LocalDNSKEYs`, reads `LastKeyInventory`
  (via accessor)
- Fix: convert to `(mpzd *MPZoneData) LocalDnskeysFromKeystate()`.
  Callers pass `*MPZoneData` or look up via Zones.Get().
  The `GetLastKeyInventory()` accessor call stays (it's
  on `*tdns.ZoneData`) — but should be replaced with
  direct `mpzd.MP.LastKeyInventory` access.

**2. snapshotUpstreamData** (hsync_utils.go:972)
- Signature: `func snapshotUpstreamData(zd *tdns.ZoneData)`
- 2 `.MP` accesses: writes `UpstreamData`
- Fix: convert to `(mpzd *MPZoneData) snapshotUpstreamData()`.
  Called from MPPreRefresh (see below) — must be updated
  together.

**3. MPPreRefresh** (hsync_utils.go:1009)
- Signature: `func MPPreRefresh(zd, new_zd *tdns.ZoneData, tm *MPTransportBridge, msgQs *MsgQs, mp *tdns.MultiProviderConf)`
- 15 `.MP` accesses across both `zd` and `new_zd`
- This is the **hardest** function. See dedicated
  section below.

## The MPPreRefresh Problem

MPPreRefresh is called by the RefreshEngine (in tdns)
during zone refresh. It receives two raw `*tdns.ZoneData`
pointers:
- `zd`: the current (old) zone data
- `new_zd`: freshly parsed zone data (no MPZoneData wrapper)

### Current .MP accesses in MPPreRefresh

**On `zd` (old zone):**
| Line | Access | R/W |
|------|--------|-----|
| 1010 | `zd.EnsureMP()` | W |
| 1071 | `zd.MP.MPdata = new_zd.MP.MPdata` | W |
| 1117 | `zd.MP.AgentContributions` | R |
| 1118 | `new_zd.MP.AgentContribs = zd.MP.AgentContribs` | R |
| 1120 | `zd.MP.CombinerData` | R |
| 1121 | `new_zd.MP.CombinerData = zd.MP.CombinerData` | R |
| 1139 | `zd.MP.RefreshAnalysis = analysis` | W |

**On `new_zd` (new zone):**
| Line | Access | R/W |
|------|--------|-----|
| 1067 | `populateMPdata(mp)` via wrapper | W |
| 1071 | `new_zd.MP.MPdata` (copied to zd) | R |
| 1075 | `new_zd.MP.MPdata` nil check | R |
| 1078 | `new_zd.MP.MPdata.WeAreSigner` | R |
| 1079 | `new_zd.MP.MPdata.OtherSigners` | R |
| 1116 | `new_zd.EnsureMP()` | W |
| 1118 | `new_zd.MP.AgentContributions` (assigned) | W |
| 1121 | `new_zd.MP.CombinerData` (assigned) | W |

### The `new_zd` challenge

`new_zd` is created by RefreshEngine in tdns. There is
no `MPZoneData` wrapper for it. `Zones.Get()` returns
the OLD zone's wrapper, not the new one.

**Solution**: Convert MPPreRefresh to a receiver on
`*MPZoneData` (the old zone's wrapper). For `new_zd`,
create a temporary `MPZoneData` wrapper:

```go
func (mpzd *MPZoneData) MPPreRefresh(
    new_zd *tdns.ZoneData, tm *MPTransportBridge,
    msgQs *MsgQs, mp *tdns.MultiProviderConf) {

    // Wrap new_zd for local MP access
    newMpzd := &MPZoneData{ZoneData: new_zd}
    newMpzd.EnsureMP()

    // Now use mpzd.MP for old zone, newMpzd.MP for new
    newMpzd.populateMPdata(mp)
    mpzd.MP.MPdata = newMpzd.MP.MPdata  // persist across flip

    // State copy: old → new (combiner reapply)
    if mpzd.MP.AgentContributions != nil {
        newMpzd.MP.AgentContributions = mpzd.MP.AgentContributions
    }
    ...
}
```

The temporary wrapper's local MP field holds the new
zone's MP state during pre-refresh processing. After
the zone flip, the RefreshEngine replaces the old
`*tdns.ZoneData` with `new_zd`. At that point the
`Zones` map entry's `MPZoneData.ZoneData` pointer is
updated to `new_zd`, and the local `MPZoneData.MP`
field (which was on `mpzd`, the old wrapper) persists
— it's the same `MPZoneData` struct, only the embedded
ZoneData changed.

**Key insight**: the `MPZoneData` wrapper in `Zones`
is long-lived. The embedded `*tdns.ZoneData` gets
swapped on refresh, but the wrapper (and its local MP
field) survives. After migration, the local MP field
IS the persistent state — no more copying between
`zd.MP` and `new_zd.MP`.

This actually **simplifies** the refresh flow:
- Old flow: copy AgentContributions/CombinerData from
  old zd.MP → new_zd.MP before flip
- New flow: those fields live on `mpzd.MP` (the
  wrapper), not on the swappable ZoneData. No copying
  needed — they're already on the persistent wrapper.

The only thing that needs recomputing on refresh is
`MPdata` (signing state derived from HSYNC records in
the new zone data).

## KEYSTATE Accessor Methods

tdns defines 8 accessor methods on `*ZoneData`:
- `Get/SetLastKeyInventory`
- `Get/SetKeystateOK`
- `Get/SetKeystateError`
- `Get/SetKeystateTime`

These are thread-safe wrappers around `zd.MP` fields.
After migration, calls on `*MPZoneData` still resolve
to these (via promotion) — but they read/write the OLD
`tdns.ZoneData.MP` field, not the new local one.

**Fix**: Define shadow accessor methods on `*MPZoneData`
that use the local MP field:

```go
func (mpzd *MPZoneData) GetKeystateOK() bool {
    mpzd.mu.Lock()
    defer mpzd.mu.Unlock()
    if mpzd.MP == nil { return false }
    return mpzd.MP.KeystateOK
}
```

Or, since most callers in tdns-mp already have the
`*MPZoneData`, replace accessor calls with direct
field access where the lock is already held. The
accessors exist primarily for thread safety from
tdns code; tdns-mp code often already holds locks.

Callers in tdns-mp (all in hsync_utils.go and
apihandler_agent.go):
- `RequestAndWaitForKeyInventory`: 18 accessor calls
- `LocalDnskeysFromKeystate`: 1 accessor call
- `hsyncengine.go`: 1 SetLastKeyInventory
- `syncheddataengine.go`: 1 GetLastKeyInventory
- `apihandler_agent.go`: 7 accessor calls

## EnsureMP() Migration

13 call sites in tdns-mp. After migration, need a local
`EnsureMP()` on `*MPZoneData`:

```go
func (mpzd *MPZoneData) EnsureMP() {
    if mpzd.MP == nil {
        mpzd.MP = &ZoneMPExtension{}
    }
}
```

This shadows the promoted `tdns.ZoneData.EnsureMP()`.
Callers on `*MPZoneData` automatically use the new one.
Callers inside OnFirstLoad callbacks (which have raw
`*tdns.ZoneData`) must use `Zones.Get()` lookup first.

## Implementation Steps

### Step 1: Define new type + add field

Create `tdns-mp/v2/mp_extension.go`:
- Define `ZoneMPExtension` struct (same fields as
  `tdns.ZoneMPExtension`, local type)
- Define `EnsureMP()` on `*MPZoneData`

Add `MP *ZoneMPExtension` field to `MPZoneData` in
`mpzonedata.go`.

**Build**: should compile — the new field shadows the
promoted one. All ~100 Category A callers automatically
use the new field. But MP is nil everywhere → runtime
failures. Must complete Step 2 before testing.

### Step 2: Initialize local MP field

Update all `Zones.Set()` / zone registration paths to
initialize `mpzd.MP`. Find where `MPZoneData` structs
are created and ensure `EnsureMP()` is called.

Update `RegisterCombinerOnFirstLoad` and other init
paths that currently call `zd.EnsureMP()` on the
embedded ZoneData.

### Step 3: Convert Category C free functions

Convert to `*MPZoneData` receivers:
- `LocalDnskeysFromKeystate` → receiver
- `snapshotUpstreamData` → receiver
- `MPPreRefresh` → receiver (with temporary wrapper
  for `new_zd`)

Update callers accordingly.

### Step 4: Fix Category B callbacks

Update OnFirstLoad callbacks in `config.go` to use
`Zones.Get()` lookup instead of direct `zd.MP` access.

### Step 5: Shadow KEYSTATE accessors

Define `Get/SetLastKeyInventory`, `Get/SetKeystateOK`,
`Get/SetKeystateError`, `Get/SetKeystateTime` on
`*MPZoneData` using the local MP field.

### Step 6: Simplify refresh flow

With MP state on the persistent wrapper, simplify
MPPreRefresh:
- Remove AgentContributions/CombinerData copying
  (they live on the wrapper, not the swappable ZoneData)
- Only recompute MPdata from new zone's HSYNC records

### Step 7: Verify and clean up

- Build both repos
- Verify no code path still uses the promoted
  `tdns.ZoneData.MP` in tdns-mp
- Lab test refresh, combiner persistence, KEYSTATE flow

## Dependency Order

```
Step 1 (type + field)
  ↓
Step 2 (initialization) — runtime correctness
  ↓
Step 3 (free functions) — compile fixes
  ↓
Step 4 (callbacks) — callback correctness
  ↓
Step 5 (accessors) — thread safety
  ↓
Step 6 (simplify refresh) — cleanup, optional
  ↓
Step 7 (verify) — testing
```

Steps 1+2 must be done together (field without init
= nil panics). Steps 3-5 can be done in any order.
Step 6 is a follow-up optimization.

## Size Estimate

- New file `mp_extension.go`: ~40 lines (struct + EnsureMP)
- `mpzonedata.go`: +1 line (new field)
- Category C conversions: ~30 lines modified across
  `hsync_utils.go`
- Category B callbacks: ~15 lines modified in `config.go`
- KEYSTATE accessors: ~40 lines (8 methods)
- Refresh simplification: ~20 lines removed
- Initialization paths: ~10-20 lines modified

Total: ~150 lines added, ~40 removed, ~50 modified.
Medium-sized change across 5-6 files.

## Risks

**Medium:**

1. **Runtime nil panics if Step 2 (init) is incomplete.**
   Every path that creates or registers an MPZoneData
   must initialize the local MP field. Missing one →
   nil pointer dereference. Mitigated by grep for
   `MPZoneData{` and `Zones.Set`.

2. **KEYSTATE accessor divergence.** If Step 5 is
   incomplete, some code reads the old field (via
   promoted accessor) while other code writes the
   new field (via local accessor). Mitigated by doing
   Steps 1-5 atomically.

3. **MPPreRefresh complexity.** The temporary wrapper
   pattern for `new_zd` is non-obvious. Well-commented
   code mitigates this.

**Low:**

4. **OnFirstLoad callbacks using ad-hoc wrappers.**
   `&MPZoneData{ZoneData: zd}` creates a wrapper with
   nil local MP field. Must use `Zones.Get()` instead.
   Only 2 sites, easy to audit.

5. **tdns legacy code still uses old field.** By
   design — no risk, but the old field becomes dead
   weight in tdns-mp apps.

## Future Work

After this migration:
- `tdns.ZoneMPExtension` can be shrunk/removed as
  legacy code migrates
- `tdns.MPdata` sub-struct can be migrated to tdns-mp
  when ready
- New tdns-mp-only fields can be added to the local
  `ZoneMPExtension` (e.g. audit state, gossip state)
- The refresh flow simplification (Step 6) removes
  the last complex entanglement between tdns
  RefreshEngine and MP state
