# MPZoneData Experiment: Embedded ZoneData Wrapper

**Date**: 2026-04-12
**Status**: Experiment complete — all steps implemented
**Branch**: `mpzonedata-test-1` (both tdns and tdns-mp repos)

## Motivation

Today `tdns.ZoneData` has a `MP *ZoneMPExtension` field that
holds all multi-provider state. This is an MP-specific struct
defined in tdns — it can't move to tdns-mp without either
making the field `interface{}` or removing it entirely.

By creating `MPZoneData` in tdns-mp that embeds
`*tdns.ZoneData`, we get two immediate benefits:
1. tdns-mp code calls `Zones.Get()` (local) instead of
   `tdns.Zones.Get()` and receives `*MPZoneData` — a
   type tdns-mp owns
2. Migrating MP sub-commands from tdns to tdns-mp becomes
   near-zero-effort: `zd.MP.Something` works unchanged
   via embedding

And future cleanup opportunities (not part of this
experiment):
3. Move MP fields from `ZoneMPExtension` onto
   `MPZoneData` directly, eliminating `zd.MP` indirection
4. Convert 23 exported functions to methods on `*MPZoneData`
5. Eventually remove `ZoneMPExtension` from tdns

## Current State

### ZoneMPExtension (in tdns/v2/structs.go)

```go
type ZoneMPExtension struct {
    CombinerData         *core.ConcurrentMap[string, OwnerData]
    UpstreamData         *core.ConcurrentMap[string, OwnerData]
    MPdata               *MPdata
    AgentContributions   map[string]map[string]map[uint16]core.RRset
    PersistContributions func(string, string, map[string]map[uint16]core.RRset) error
    LastKeyInventory     *KeyInventorySnapshot
    LocalDNSKEYs         []dns.RR
    KeystateOK           bool
    KeystateError        string
    KeystateTime         time.Time
    RefreshAnalysis      *ZoneRefreshAnalysis
}
```

Accessed 129 times via `zd.MP.Something` across tdns-mp.

### Zones map

`tdns.Zones` is a `core.ConcurrentMap[string, *ZoneData]`
(global variable). tdns-mp accesses it 56 times using
5 methods:

| Method | Count | Purpose |
|--------|-------|---------|
| `Get` | 46 | Zone lookup by name |
| `Items` | 6 | Bulk retrieval (returns map) |
| `Keys` | 2 | List zone names |
| `IterBuffered` | 1 | Streaming iteration |
| `IterCb` | 1 | Callback iteration |

tdns-mp **never** calls `Set`, `Remove`, or any mutating
method on `tdns.Zones`. Zone creation/deletion happens
in tdns core.

## Design: MPZoneData (experiment phase)

```go
type MPZoneData struct {
    *tdns.ZoneData
}
```

That's it for the experiment. No new fields. The existing
`zd.MP.CombinerData` etc. continues to work unchanged via
the embedded `*tdns.ZoneData` — code that says
`mpzd.MP.CombinerData` is identical to today's
`zd.MP.CombinerData`.

All core `ZoneData` fields (`ZoneName`, `Options`,
`Logger`, `Lock`/`Unlock`, `GetOwner`, `GetRRset`, etc.)
are accessible via Go embedding. Methods on `*ZoneData`
(e.g. `zd.EnsureMP()`) work as `mpzd.EnsureMP()`.

### Future: field migration (not part of experiment)

Once the experiment proves the concept, a later phase
can move fields from `ZoneMPExtension` onto `MPZoneData`
directly:

```go
type MPZoneData struct {
    *tdns.ZoneData
    CombinerData         *core.ConcurrentMap[...]
    AgentContributions   map[string]map[...]
    // ... etc
}
```

This eliminates `zd.MP` indirection and nil guards, but
is a separate cleanup effort (~129 edits).

## Design: MPZones Accessor

The central problem: `tdns.Zones.Get()` returns
`*tdns.ZoneData`, but tdns-mp needs `*MPZoneData`.

### Lazy-caching accessor

```go
type MPZones struct {
    mu    sync.RWMutex
    cache map[string]*MPZoneData
}

var Zones = &MPZones{
    cache: make(map[string]*MPZoneData),
}
```

Each accessor method wraps the corresponding
`tdns.Zones` method, caching `*MPZoneData` on first
access:

### Get (46 call sites)

```go
func (mz *MPZones) Get(name string) (*MPZoneData, bool) {
    mz.mu.RLock()
    if mpzd, ok := mz.cache[name]; ok {
        mz.mu.RUnlock()
        return mpzd, true
    }
    mz.mu.RUnlock()

    zd, ok := tdns.Zones.Get(name)
    if !ok {
        return nil, false
    }

    mz.mu.Lock()
    defer mz.mu.Unlock()
    // Double-check after lock upgrade
    if mpzd, ok := mz.cache[name]; ok {
        return mpzd, true
    }
    mpzd := &MPZoneData{ZoneData: zd}
    mz.cache[name] = mpzd
    return mpzd, true
}
```

Returns a cached `*MPZoneData` or creates one on the fly
by wrapping the `*tdns.ZoneData`. Same `*MPZoneData`
always returned for a given zone (pointer stability).

### Items (6 call sites)

```go
func (mz *MPZones) Items() map[string]*MPZoneData {
    result := make(map[string]*MPZoneData)
    for name, zd := range tdns.Zones.Items() {
        result[name] = mz.getOrCreate(name, zd)
    }
    return result
}
```

Iterates `tdns.Zones.Items()` (authoritative source),
wraps each. The `getOrCreate` helper handles cache
lookup + creation atomically.

### Keys (2 call sites)

```go
func (mz *MPZones) Keys() []string {
    return tdns.Zones.Keys()
}
```

Pass-through — no wrapping needed, just zone names.

### IterBuffered (1 call site)

```go
func (mz *MPZones) IterBuffered() <-chan MPZoneTuple {
    ch := make(chan MPZoneTuple, 16)
    go func() {
        defer close(ch)
        for item := range tdns.Zones.IterBuffered() {
            mpzd := mz.getOrCreate(item.Key, item.Val)
            ch <- MPZoneTuple{Key: item.Key, Val: mpzd}
        }
    }()
    return ch
}

type MPZoneTuple struct {
    Key string
    Val *MPZoneData
}
```

Wraps the underlying channel, converting each tuple.

### IterCb (1 call site)

```go
func (mz *MPZones) IterCb(fn func(key string, v *MPZoneData)) {
    tdns.Zones.IterCb(func(key string, zd *tdns.ZoneData) {
        mpzd := mz.getOrCreate(key, zd)
        fn(key, mpzd)
    })
}
```

Wraps callback, converting the value.

### getOrCreate (internal helper)

```go
func (mz *MPZones) getOrCreate(
    name string, zd *tdns.ZoneData,
) *MPZoneData {
    mz.mu.RLock()
    if mpzd, ok := mz.cache[name]; ok {
        mz.mu.RUnlock()
        return mpzd
    }
    mz.mu.RUnlock()

    mz.mu.Lock()
    defer mz.mu.Unlock()
    if mpzd, ok := mz.cache[name]; ok {
        return mpzd
    }
    mpzd := &MPZoneData{ZoneData: zd}
    mz.cache[name] = mpzd
    return mpzd
}
```

### Invalidate (for zone deletion)

```go
func (mz *MPZones) Invalidate(name string) {
    mz.mu.Lock()
    defer mz.mu.Unlock()
    delete(mz.cache, name)
}
```

Called if a zone is removed from `tdns.Zones`. Not
strictly necessary (a stale cache entry just wraps a
`*ZoneData` that's no longer in the authoritative map),
but keeps the cache clean.

### Pre-populate (for OnFirstLoad)

```go
func (mz *MPZones) Set(name string, mpzd *MPZoneData) {
    mz.mu.Lock()
    defer mz.mu.Unlock()
    mz.cache[name] = mpzd
}
```

Called from `OnFirstLoad` callbacks to store a fully
initialized `*MPZoneData` with MP fields populated.
Subsequent `Get()` calls return this pre-populated
object instead of creating a bare one.

## MP Field Initialization (unchanged in experiment)

Today, MP fields are initialized via `EnsureMP()` +
lazy init. In the experiment, this is completely
unchanged — `mpzd.EnsureMP()` works via promotion,
and `mpzd.MP.CombinerData` etc. follows the same
patterns as today.

In a future cleanup phase, `OnFirstLoad` callbacks
would create `*MPZoneData` with MP fields populated
directly (no `EnsureMP` needed).

## Experiment Steps

### Step 1: Define types and accessor — DONE

Created `tdns-mp/v2/mpzonedata.go`:
- `MPZoneData` struct (embedding `*tdns.ZoneData` only)
- `MPZones` struct with `Get`, `Items`, `Keys`,
  `IterBuffered`, `IterCb`, `Set`, `Invalidate`
- `getOrCreate` internal helper (lazy cache population)
- `MPZoneTuple` for `IterBuffered` return type
- Package-level `var Zones = &MPZones{...}`

Commit: `a80827d` — "Add MPZoneData wrapper type and
MPZones lazy-caching accessor"

### Step 2: Convert Zones.Get call sites (46) — DONE

### Step 3: Convert Items/Keys/Iter call sites (10) — DONE

### Step 4: Update callbacks (2) — DONE (no change needed)

`TMConfig.GetZone` and `MPTransportBridge.getZone` kept
as `tdns.Zones.Get` / `tdns.Zones.Keys` — these bridge
to tdns-transport which expects `*tdns.ZoneData`.

Steps 2-4 committed together:

Commit: `afcb411` — "Migrate tdns.Zones.Get/Items/Keys/
Iter* to local Zones accessor"

20 files changed, 87 insertions, 88 deletions.

### Implementation notes

Where `*MPZoneData` is passed to functions that still
expect `*tdns.ZoneData`, extract `.ZoneData` at the
call site. Examples:
- `RebuildCombinerData(zd.ZoneData)`
- `combinerProcessOperations(req, zd.ZoneData, ...)`
- `conf.Config.Internal.ResignQ <- zd.ZoneData`
- `tdns.SyncRequest{ZoneData: zd.ZoneData, ...}`

`ForEachMPZone` signature changed from
`func(zd *tdns.ZoneData)` to `func(zd *MPZoneData)`.

One import removed: `hsync_hello.go` no longer imports
`tdns/v2` (the `Zones.Get` call was its only use).

### What is NOT changed in the experiment

- **No field migration**: `zd.MP.Something` stays as-is.
  `ZoneMPExtension` is untouched.
- **No function signature changes**: functions still take
  `*tdns.ZoneData` parameters. Only `Zones.Get()` call
  sites change. Functions receiving `mpzd` pass
  `mpzd.ZoneData` to functions expecting `*tdns.ZoneData`.
- **No EnsureMP removal**: `mpzd.EnsureMP()` works via
  promotion.
- **No method conversions**: the 23 exported functions
  stay as functions.
- **tdns repo unchanged**: zero modifications to tdns.

## Follow-up: Migrate zd.MP from tdns to tdns-mp

Once the experiment validates, this is the key
milestone. Today `zd.MP` is a `*ZoneMPExtension`
defined in tdns — it's a major blocker for completing
the tdns→tdns-mp migration. With `MPZoneData` in
place, we can move `ZoneMPExtension` (and `MPdata`)
to tdns-mp and replace `zd.MP` with `mpzd.MP` where
`MP` is a field on `MPZoneData` instead of on
`ZoneData`.

### What this achieves

- tdns no longer defines or references
  `ZoneMPExtension` or `MPdata`
- The `MP *ZoneMPExtension` field is removed from
  `tdns.ZoneData`
- `EnsureMP()` moves to tdns-mp (method on
  `*MPZoneData`)
- All MP state is owned by tdns-mp — the migration
  of MP-stuff from tdns to tdns-mp can complete

### Migration steps

1. Define `ZoneMPExtension` and `MPdata` locally in
   tdns-mp (copy from tdns)
2. Add `MP *ZoneMPExtension` field to `MPZoneData`
3. Migrate all `zd.MP` references in tdns-mp to
   `mpzd.MP` (where `mpzd` comes from `Zones.Get()`)
4. Migrate all `zd.MP` references in tdns to tdns-mp
   (these are in MP code that should have migrated
   anyway — the remaining legacy/wrapper functions)
5. Remove `MP` field, `ZoneMPExtension`, `MPdata`,
   and `EnsureMP()` from tdns
6. Function signatures: change `zd *tdns.ZoneData` →
   `mpzd *MPZoneData` where functions access `.MP`

This is a self-contained project. It does NOT require
breaking `ZoneMPExtension` into separate fields —
that is optional cleanup, done later if desired.

### Scale

| What | Count |
|------|-------|
| Types to copy to tdns-mp | 2 (`ZoneMPExtension`, `MPdata`) |
| `zd.MP` → `mpzd.MP` in tdns-mp | ~129 |
| `zd.MP` callers to migrate from tdns | TBD (depends on remaining legacy code) |
| Function signatures to update | ~70 |
| Fields/methods to remove from tdns | 3 (`MP`, `ZoneMPExtension`, `EnsureMP`) |

## Further future: break ZoneMPExtension apart

Once `ZoneMPExtension` lives in tdns-mp, it can
optionally be broken apart — fields moved directly
onto `MPZoneData`, eliminating the `.MP` indirection.
This is pure tdns-mp internal cleanup with no
cross-repo impact:

- `mpzd.MP.CombinerData` → `mpzd.CombinerData`
- `mpzd.MP.AgentContributions` → `mpzd.AgentContributions`
- Remove nil guards on `mpzd.MP`
- Remove `EnsureMP()` entirely

This is optional and low priority — the struct works
fine as-is. Only worth doing if the indirection
becomes annoying.

## Even further future: methods on MPZoneData

Convert the 23 exported functions that take
`mpzd *MPZoneData` as first parameter into proper
methods on `*MPZoneData`. Pure code quality
improvement, no functional change.

## Risks and Considerations

### Pointer identity

`MPZones.Get()` always returns the same `*MPZoneData`
for a given zone name (cached). All MP code sees the
same object. Mutations to `mpzd.CombinerData` etc. are
visible everywhere — same semantics as today with
`zd.MP`.

### Zone lifecycle

Zones are created in tdns core (`Zones.Set`). The MP
cache lazily wraps them. If a zone is deleted from
`tdns.Zones`, the cache retains a stale entry — call
`Zones.Invalidate(name)` to clean up. Deletion is rare
(catalog zone removal, API-driven), so this is low risk.

If tdns-mp needs to know about zone deletion, hook into
the existing zone removal path (e.g. via a callback
registered during init).

### Concurrency

`MPZones` uses its own mutex for the cache. The
underlying `*tdns.ZoneData` has its own locking
(`zd.Lock()`/`zd.Unlock()`). `MPZoneData` fields
that need concurrent access (e.g. `CombinerData`
which is itself a ConcurrentMap) are already safe.
Fields like `AgentContributions` are accessed under
zone lock today — same pattern continues.

### Functions that call back into tdns

Methods on `*tdns.ZoneData` (e.g. `zd.SignZone(...)`,
`zd.GetOwner(name)`) work via promotion — no extraction
needed.

For the experiment, functions still take
`*tdns.ZoneData` as parameter. At call sites where we
have `*MPZoneData`, pass `mpzd.ZoneData`. In a future
cleanup, function signatures change to `*MPZoneData`
and extraction is only needed for callbacks into tdns.

### Package-level Zones variable shadowing

tdns-mp defines `var Zones = &MPZones{...}` which
shadows the imported `tdns.Zones`. Code that needs
the raw `tdns.Zones` (e.g. passing `GetZone` callbacks
to transport) must use `tdns.Zones` explicitly. All
other code uses the unqualified `Zones`.

This is the intended behavior — the same name makes
the migration mechanical (remove `tdns.` prefix).

## Scale of Change

### Phase 1: Experiment — DONE (`mpzonedata-test-1`)

| What | Actual |
|------|--------|
| New files | 1 (`mpzonedata.go`, 146 lines) |
| `tdns.Zones.Get` → `Zones.Get` | 46 |
| `tdns.Zones.Items/Keys/Iter*` | 10 |
| `.ZoneData` extractions added | ~20 |
| Closure/callback signatures updated | 3 |
| Files modified | 20 |
| Insertions / deletions | 87 / 88 |
| tdns changes | 0 |

### Phase 2: Migrate zd.MP (separate project)

| What | Count |
|------|-------|
| Types to copy to tdns-mp | 2 |
| Function signatures accessing `.MP` | ~30-40 (subset of the 70 that actually touch `.MP`) |
| Callers of those functions | ~10-15 (pass `mpzd.ZoneData` → `mpzd`) |
| Remove from tdns | 3 |
| **Total edits** | **~50** |

Note: the 129 `zd.MP.Something` accesses are *inside*
functions. Once a function signature changes from
`zd *tdns.ZoneData` to `mpzd *MPZoneData`, all its
internal `.MP` accesses work without further edits.
Functions that don't access `.MP` keep their
`*tdns.ZoneData` parameter unchanged.

### Phase 3+: Optional cleanup (low priority)

| What | Count |
|------|-------|
| Break `ZoneMPExtension` apart | ~129 |
| Remove `EnsureMP()` | ~20 |
| Convert functions to methods | 23 |

All errors across all phases are compile-time. No
runtime behavior change in any phase.

## Verification

On the experiment branch:
```
cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make
```

tdns itself is unchanged (experiment is tdns-mp only).
`ZoneMPExtension` removal from tdns is a separate
future step.
