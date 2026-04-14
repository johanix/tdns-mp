# Combiner Persistence Branch: Rebase Assessment

**Date**: 2026-04-13
**Status**: **Rebase complete** (2026-04-13)
**Feature branch**: `combiner-persistence-sep-1` (both repos)
**Target branch**: `combiner-persistence-rebase-1` (both repos)
**Design doc**: `2026-03-31-combiner-persistence-separation.md`

## Branch Summary

6 commits implementing 5 steps + 1 doc update:

1. `RRStateIgnored` + `ConfirmIgnored` status
2. Separate combiner persistence from editing
   (editPolicy struct, per-RRtype gates)
3. Remove agent blanket block for non-signers
4. Empty REPLACE for stale data cleanup
5. CLI display of IGNORED state

~510 lines changed across 8 Go source files.
tdns side: trivial (2 lines across 2 legacy files).

## Divergence

The target branch is **52 commits ahead** of the merge
base. These 52 commits include the full MP migration
work: wrapper removal, HsyncDB migration, Zones
accessor, CLI endpoint moves, InternalMpConf removal,
SyncQ move to MPZoneData.

## Per-File Conflict Analysis

| File | Feature delta | Target delta | Risk |
|---|---|---|---|
| `combiner_chunk.go` | +162 (editPolicy, IGNORED) | ~70 (wrapper→direct) | Medium |
| `syncheddataengine.go` | +206 (RRState, skip removal) | ~18 (Zones, HsyncDB) | Medium |
| `combiner_utils.go` | +107 (edit policy) | ~20 (wrapper calls) | Low |
| `apihandler_agent.go` | +19 (per-RRtype policy) | -547 (CLI migrated out) | Low |
| `hsync_transport.go` | +10 (RMQ + callback) | 0 | None |
| `hsync_utils.go` | +8 (populateMPdata) | ~40 (PostRefresh, MusicSyncQ) | Low |
| `combiner_msg_handler.go` | +3 | ~26 | Low |
| `sde_types.go` | +7 (RRStateIgnored) | 0 | None |

### apihandler\_agent.go (downgraded from High to Low)

The feature branch adds per-RRtype policy checks
replacing the blanket `OptMPDisallowEdits` block.
The target branch removed ~547 lines (CLI commands
migrated to `apihandler_agent_distrib.go`,
`apihandler_agent_hsync.go`, etc.), but the zone
edit handling (`add-rr`, `del-rr` cases) stayed in
`apihandler_agent.go`. The `OptMPDisallowEdits`
check is at line ~101, right where the feature
branch targets it. Conflict should be minimal —
surrounding code was removed, not the edit path.

### Medium-risk files

`combiner_chunk.go` and `syncheddataengine.go` have
the most feature-branch logic. The target branch
changes in these files are mechanical: function
signature updates (`*HsyncDB` instead of
`*tdns.KeyDB`), `Zones.Get()` returning `*MPZoneData`
instead of `*tdns.ZoneData`. These are resolvable by
applying the same mechanical transforms to the
feature code.

### tdns-transport changes

The feature branch needs `ConfirmIgnored` added to
tdns-transport (4 files, ~11 lines). The transport
repo hasn't diverged significantly — these should
apply cleanly.

### tdns changes

Only 2 lines across 2 legacy files. Both files have
been further modified (nil local variables for deleted
InternalMpConf fields) but the feature changes are
in different functions. Low conflict risk.

## Recommendation: Rebase

**Rebase, not reimplement.** Reasons:

- The design is solid and carefully audited (17
  MPdata access sites checked, risk assessment done)
- The 5 implementation steps are clean and sequential
- The semantic changes (editPolicy, IGNORED flow,
  persistence/editing split) don't conflict with the
  migration work
- Most conflicts are mechanical: updated signatures,
  type changes, moved code locations
- Reimplementation would duplicate the design work
  and risk missing the careful edge-case analysis

## Rebase Strategy

1. Start with tdns-transport: apply `ConfirmIgnored`
   changes (should be clean).

2. Rebase tdns: 2-line change, resolve against the
   nil-local-variable fixes in legacy files.

3. Rebase tdns-mp commit-by-commit (6 commits):
   - Steps 1, 2: bulk of the work. Resolve signature
     changes mechanically (`*HsyncDB`, `Zones.Get`
     returns `*MPZoneData`, etc.).
   - Step 3: `apihandler_agent.go` — the `add-rr`/
     `del-rr` handler stayed in place (line ~101).
     Only surrounding CLI code was migrated out.
     Should resolve cleanly.
   - Steps 4, 5: should be straightforward.

4. Build-verify after each commit.

5. Lab-test per the verification plan in the design
   doc (caol-ila on echo, lagavulin on alpha, etc.).

## Estimated Effort

Mechanical rebase resolution: ~1 hour.
No high-risk files remain — `apihandler_agent.go`
edit path stayed in place, and the remaining
conflicts are signature/type updates.

## Outcome

Rebase completed 2026-04-13. All 5 steps applied
cleanly with build verification after each step.
No conflicts required manual resolution — all
changes were mechanical signature/type updates.

### Additional work during rebase

1. **MPZoneData receiver conversion**: ~20 standalone
   functions converted to receiver methods on
   `*MPZoneData`, aligned with ongoing migration.
   9 files, +375/-367 lines.

2. **CombineWithLocalChanges migration**: Moved from
   `tdns/v2/legacy_combiner_utils.go` to tdns-mp as
   receiver on `*MPZoneData`. Replaces
   `AllowedLocalRRtypes` whitelist with per-RRtype
   `editPolicy.canApply()`, fixing the unsigned-zone
   corner case where nsmgmt=owner NS records were
   applied but reported as IGNORED. Also migrated
   `mergeWithUpstream()`. +107 lines.

3. **Bug fix**: `start_agent.go` OnFirstLoad callback
   was using outer `mpzd` loop variable instead of
   callback `zd` parameter, reading stale zone data.

### Final commit log (tdns-mp)

```
c273c6c Step 1: RRStateIgnored + IGNORED confirmation
235b6a5 Step 2: editPolicy + persistence/editing split
1232752 Step 3: Remove agent blanket block
44c40ed Step 4: Empty REPLACE for stale data cleanup
471972f Step 5: CLI display of IGNORED state
6dc1faf Update rebase assessment doc
68b7dd3 Convert helpers to MPZoneData receivers
58924ee Migrate CombineWithLocalChanges to tdns-mp
```
