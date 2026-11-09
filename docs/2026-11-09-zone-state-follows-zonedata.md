# Zone state follows the ZoneData, not the zone name (tdns-mp #396)

2026-11-09. Refs #396.

## The defect

Suppose one config reload removes a zone and a later reload adds it back.
tdns builds a new `*tdns.ZoneData` for the re-added zone. tdns-mp kept the
following by zone name and never let any of it go:

- `MPZones` cached one wrapper per name. `Get` returned the cached
  wrapper without checking `tdns.Zones`, so every reader kept working on
  the removed ZoneData. That included the signer's role turn on the #211
  stack, which calls `StartSigning`.
- `refreshRegistered` and `onFirstLoadRegistered` were keyed by name and
  never cleared. The re-added zone therefore got none of tdns-mp's refresh
  callbacks and none of the combiner's first-load callbacks.
- Some first-load set-ups ran only in a role's start:
  - MainInit's MPdata and the signer's resigner registration;
  - the agent's parentsync detection and election.
- The key machine's take (`MPKeyLifecycleOwner.owned`) never released a
  zone, and the engine cached its driver by name, holding the policy of
  the ZoneData it was made from.

A restart cured all of this, because it rebuilds everything. tdns also
replaces a ZoneData under the same name on its dynamic and catalog paths,
so a list of removed zones from tdns would not cover every case.

## The rule

**A zone's tdns-mp state belongs to the ZoneData it was made for.** Once
tdns holds another ZoneData under that name, the old state is let go, and
the zone starts over as it does at a start.

### The wrapper (`mpzonedata.go`)

- A cached wrapper is valid only while it wraps the ZoneData that
  `tdns.Zones` holds. `Get`, `Items`, `IterBuffered` and `IterCb` rebuild
  a stale wrapper, with fresh MP state.
- `Get` of a zone tdns no longer holds returns false. Before, it returned
  the cached wrapper.
- `GetFor(zd)` returns the wrapper only while `zd` is the live ZoneData. A
  callback that runs on a removed zone, from a refresh still in flight, is
  handed the old ZoneData, finds no wrapper, and does nothing. Before, it
  reached the wrapper of the zone added back.
- `Prune` drops wrappers of zones tdns no longer holds. It runs after
  every reload.
- The cache files a wrapper under the lowercased name, as tdns files its
  zones (`core.CanonicalizeName`). A ZoneData then has one wrapper however
  its name is spelled, which the run-once hooks below rely on.
- `Set` had no caller and is gone.

### The per-zone hooks (`zone_hooks.go`)

`zoneOnce` records one ZoneData per zone name. A hook does its work when
the ZoneData is not yet the one recorded, then records it. So each hook
runs exactly once per ZoneData, whichever caller gets there first. After
every reload, `prune` forgets the ZoneData tdns no longer holds. The hooks
are:

| hook | what | roles |
|---|---|---|
| `registerRefreshCallbacks` | the Pre/PostRefresh closures | all |
| `firstLoadSetup` | MPdata; the signer's resigner registration | all |
| the agent's first-load hook | parentsync detection, election | agent |
| `RegisterCombinerOnFirstLoad` | contributions restored, first-load callbacks | combiner |

The hooks run at three points:

1. **A role's start.** It runs the hooks for the zones it starts with, as
   before. It then installs the hooks (`installZoneHooks`) as MPZones's
   `onNew`, so they run for every wrapper built from then on.
2. **A reload.** tdns calls the `OptMultiProvider` option handler inside
   `ParseZones`, after it has built a new zone's ZoneData and before it
   queues that zone's first load. The handler looks the zone up, so a
   re-added zone gets its hooks before its first load starts.
   - The combiner's contribution restore is left out of this path. It
     takes the keystore lock, and here tdns holds its config lock, which
     the keystore's update path also takes. The combiner's
     `PostParseZonesHook` restores the contributions instead, as before.
3. **The reload hook** (`PostParseZonesHook`) runs as before. For a
   ZoneData that already has the hooks it does nothing.

First-load callbacks are appended under the zone's lock, because tdns
drains `OnFirstLoad` under that lock and a zone added by a reload may
already be loading.

### The key machine (`mp_key_lifecycle_owner.go`, `mp_key_lifecycle_engine.go`)

- **Take.** `Take` records the ZoneData the zone was taken on.
  - `taken`, `Zones` and `runsKeys` count a take only for that ZoneData.
    `runsKeys(zd)` compares against the `zd` tdns asks about, so a refresh
    still running on the removed zone keeps its answer.
  - `ReleaseReplaced` runs at the top of `TakeConfiguredZones`. It
    releases a zone taken on a ZoneData tdns no longer holds, together
    with its driver.
  - The zone is taken again on the new ZoneData once that ZoneData is
    loaded with its policy bound, as at a start.
  - In between, a zone named in `key-lifecycle-zones` that has keys stays
    owned through #191, so tdns's own key machine does not take it.
- **Driver.** The engine records the ZoneData each cached driver was made
  on (`madeOn`). When the ZoneData no longer matches, it makes the driver
  again, restoring it from the keystore as at a start.
- A take made before the zone was loaded holds for any ZoneData. Only
  tests make such a take.

## What tdns-mp keeps by name on purpose

The following describes the zone, not its ZoneData. A restart keeps or
rebuilds it from the store in the same way, so a replacement keeps it too:

- the instructions (pruned when a zone leaves the config, design rule 3);
- the agent's repositories and registries;
- the owner's inventory snapshots (agent side);
- the keystore;
- the engine's log-once maps (`waiting`, `refused`, `idle`).

## Known limits

- **Pre/PostRefresh appends.** tdns ranges `OnZonePreRefresh` and
  `OnZonePostRefresh` without the zone's lock, so appending to them races
  with a refresh of the same ZoneData.
  - The reload path registers before tdns queues the zone's first load,
    so that race does not arise there.
  - The `onNew` path can register later, as `PostParseZonesHook` already
    did before this change.
- **Agent identity zone.** The agent's config-defined identity zone sets up
  its transport publication only at the start (`SetupAgent`). An identity
  zone that a reload removes and adds back is not handled here.
- **`MPZoneNames`.** The option handler appends to `MPZoneNames` on every
  parse, so a reload adds duplicates. Readers range over the slice while a
  reload appends to it. Both are unchanged here.
- **The #211 stack.** On the stack, the signer's role turn reads the wrapper
  through `Zones.Get`, so it acts on the live ZoneData once this change is
  merged forward. Its memory-only per-zone state, and the end-to-end test
  of a signer zone removed and added back, are built on the stack.

## Tests (`zone_replaced_test.go`)

- `TestMPZonesFollowTheLiveZoneData`: remove and re-add a zone with a live
  `MPZones`. `Get`, `GetFor`, `Items` and `IterCb` hand out the live
  ZoneData with fresh MP state.
- `TestZoneHooksRunOnceOnARecreatedZone`: the refresh hooks run exactly once
  on the re-created zone, also with 32 concurrent lookups and the reload
  hook after them. The removed zone's callback leaves the new wrapper alone.
- `TestFirstLoadSetupOncePerZoneData`: the signer's resigner registration
  runs once per ZoneData.
- `TestNothingKeepsTheRemovedZoneData`: after the removing reload, none of
  these points at the removed ZoneData:
  - the wrapper cache;
  - the hook marks;
  - the owner's take;
  - the engine's driver.
- `TestMPZonesOneWrapperPerZoneData`: names spelled in different cases
  share one wrapper.
- `TestKeyLifecycleTakeAndDriverFollowTheZoneData`:
  - the take is released and made again on the new ZoneData;
  - a cached driver is made again;
  - a zone removed and not added back is released and waits for its load.
