# Remove InternalMpConf from tdns

**Date**: 2026-04-12
**Status**: Steps 1-11 DONE. Step 12 is follow-up.
**Branch**: `mp-migration-final-push-1` (both repos)

## Goal

Delete `tdns.InternalMpConf` and its embedding in
`tdns.InternalConf`. After this work:

- tdns has zero knowledge of MP channels, registries,
  or transport
- tdns-mp owns all MP internal state via its own
  `InternalMpConf` (already exists)
- Dual-writes from tdns-mp into `conf.Config.Internal.*`
  MP fields are eliminated
- `SyncQ` moves from `tdns.ZoneData` to
  `tdns-mp.MPZoneData` (first real field on the wrapper)
- `MusicSyncQ` is deleted (OBE)
- Orphaned MP types in tdns become candidates for
  follow-up cleanup

---

## Step 1: delegation\_sync.go -- copy + lobotomize [DONE]

**tdns**: Removed `LeaderElectionManager` checks and
`notifyPeersParentSyncDone` calls from `DelegationSyncher`.
Deleted `notifyPeersParentSyncDone` function entirely.
Removed unused imports (`transport`, `core`, `time`).

**tdns-mp**: New `delegation_sync.go` with MP-enhanced
`DelegationSyncher` as method on `*HsyncDB` (takes
`*tdnsmp.Config`). Updated `start_agent.go` call site
to pass tdns-mp Config.

---

## Step 2: parentsync\_bootstrap.go -- copy + lobotomize [DONE]

**tdns**: Removed `LeaderElectionManager` variable and
both leader checks from `ParentSyncAfterKeyPublication`.

**tdns-mp**: New `parentsync_bootstrap.go` with thin
wrapper on `*Config` that checks `LeaderElectionManager`
before delegating to the base tdns version. Updated
call sites in `start_agent.go` and
`apihandler_agent.go` to use `conf.ParentSync...`
instead of `conf.Config.ParentSync...`.

---

## Step 3: apirouters.go -- delete dead code [DONE]

Deleted commented-out `DistributionCache` init block
(lines 75-85).

---

## Step 4: parseconfig.go -- delete MP KEY publication [DONE]

Deleted `if options[OptMultiProvider]` block (lines
750-789) that registered an `OnFirstLoad` callback
using `conf.Internal.MPTransport`. tdns-mp has its own
version in `start_agent.go:284-303`. Also removed
now-unused `core` import.

---

## Step 5: main\_initfuncs.go -- delete MP channel init [DONE]

Deleted: `SyncQ` creation, `MsgQs` creation,
`MPZoneNames = nil` reset, `MPZoneNames` log line.

---

## Step 6: config.go -- delete MPZoneNames reset [DONE]

Deleted `conf.Internal.MPZoneNames = nil` from
`ReloadZoneConfig`. tdns-mp adds its own reset
(`conf.InternalMp.MPZoneNames = nil`) before
`conf.Config.MainInit`.

---

## Step 7: refreshengine.go -- delete SyncQ/MusicSyncQ wiring [DONE]

Deleted `zd.SyncQ` and `zd.MusicSyncQ` assignments
at both sites (existing zone update + dynamic zone
creation).

---

## Step 8: Delete MusicSyncQ (OBE) [DONE]

**tdns**: Removed `MusicSyncQ` field from `ZoneData`
and `InternalDnsConf`. Removed legacy MusicSyncQ
branch from `legacy_hsync_utils.go`.

**tdns-mp**: Removed MusicSyncQ branch from
`hsync_utils.go`.

---

## Step 9: Move SyncQ from ZoneData to MPZoneData [DONE]

**tdns**: Removed `SyncQ chan SyncRequest` from
`ZoneData`. Fixed legacy/deadcode references.

**tdns-mp**:
- Added `SyncQ chan SyncRequest` to `MPZoneData`
  (first real field beyond the embedded pointer)
- Converted `MPPostRefresh` → `PostRefresh` receiver
  on `*MPZoneData`
- Updated caller in `config.go` to look up
  `*MPZoneData` via `Zones.Get()` inside closure
- Wired `SyncQ` via `MPZoneData` in `agent_setup.go`

---

## Step 10: Delete InternalMpConf from tdns [DONE]

1. Removed `InternalMpConf` embedding from
   `InternalConf`
2. Fixed 4 legacy/deadcode files to use nil local
   variables instead of deleted promoted fields:
   - `deadcode_apihandler_agent_distrib.go`
   - `legacy_apihandler_transaction.go`
   - `legacy_hsync_utils.go`
   - `legacy_hsyncengine.go`
   - `legacy_signer_msg_handler.go`
3. Deleted `InternalMpConf` struct definition
4. Removed now-unused `transport` import from
   `config.go`

---

## Step 11: tdns-mp -- eliminate dual-writes [DONE]

1. `MPZoneNames` callback writes directly to
   `conf.InternalMp.MPZoneNames` (was
   `conf.Config.Internal.MPZoneNames`)
2. `MPZoneNames` reads in `config.go` (3 sites) use
   `conf.InternalMp.MPZoneNames`
3. `SyncQ` created locally in agent init (was shared
   from tdns via `conf.Config.Internal.SyncQ`)
4. Deleted dual-writes for `CombinerState` (3 sites)
   and `TransportManager` (1 site)
5. Added `conf.InternalMp.MPZoneNames = nil` reset
   before `conf.Config.MainInit`

---

## Step 12: Cascade cleanup -- orphaned MP types [TODO]

With `InternalMpConf` deleted, these tdns types are
orphaned (only referenced by legacy\_/deadcode\_ files
or via type aliases in tdns-mp):

- `MsgQs` struct (config.go)
- `SyncRequest` / `SyncStatus` (mptypes.go)
- `AgentRegistry` (mptypes.go)
- `ZoneDataRepo` (mptypes.go)
- `CombinerState` (mptypes.go)
- `MPTransportBridge` (legacy\_hsync\_transport.go)
- `LeaderElectionManager` (legacy\_parentsync\_leader.go)
- `DistributionCache` (deadcode\_apihandler\_agent\_distrib.go)
- `ChunkPayloadStore` (mptypes.go)

Each needs a grep to confirm it is truly orphaned in
active tdns code before removal. Some types are still
referenced by live symbols defined in legacy files
(e.g. `lgEngine`, `lgSigner`, `pushKeystateInventory`).
Extracting those shared symbols into small live files
is a prerequisite to build-tagging or removing the
legacy files.

This is a separate follow-up task -- types are the
last thing to move.

---

## Commit History

**tdns** (8 commits on `mp-migration-final-push-1`):
1. Remove MP dependencies from delegation\_sync.go
2. Remove LeaderElectionManager from
   ParentSyncAfterKeyPublication
3. Remove MP dead code from apirouters.go and
   parseconfig.go
4. Remove MP channel init, MusicSyncQ, and SyncQ
   wiring from tdns
5. Move SyncQ from ZoneData to tdns-mp MPZoneData
6. Remove InternalMpConf embedding from InternalConf
7. Delete InternalMpConf struct definition

**tdns-mp** (5 commits on `mp-migration-final-push-1`):
1. Add MP-enhanced DelegationSyncher to tdns-mp
2. Add MP-enhanced ParentSyncAfterKeyPublication with
   leader gating
3. Remove legacy MusicSyncQ branch from hsync\_utils.go
4. Add SyncQ to MPZoneData, convert MPPostRefresh to
   receiver method
5. Eliminate dual-writes into tdns InternalMpConf

---

## Notes

- `MPPreRefresh` (config.go:47) is in the same
  situation as `MPPostRefresh` -- should also become a
  receiver on `*MPZoneData`. Not done yet but should be
  done when touching that code next.
- The `OnZonePostRefresh` / `OnZonePreRefresh` callback
  signatures are fixed by tdns (`func(*ZoneData)` and
  `func(*ZoneData, *ZoneData)`). tdns-mp bridges to
  `*MPZoneData` via `Zones.Get()` inside closures.
  tdns never sees `*MPZoneData`.
- `zd.MP` (`*ZoneMPExtension`) stays on `tdns.ZoneData`
  for now. It is accessed by tdns accessor methods in
  structs.go. Moving it is a much larger change.
- Legacy/deadcode files in tdns now use nil local
  variables where they previously accessed promoted
  InternalMpConf fields. This is a temporary measure
  until Step 12 extracts shared symbols and removes
  the legacy files.
