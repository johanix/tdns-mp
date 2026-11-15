# The multi-provider zones: once each, from the last parse (tdns-mp #401)

2026-11-09. Refs #401, #396.

## The defect

tdns calls the multi-provider option handler (`main_init.go`) for every
zone with the option, on every `ParseZones`, reloads included. The handler
appended the zone to `InternalMp.MPZoneNames`, and nothing reset that slice
after the start. That caused three problems:

- **Duplicates.** Each reload added every multi-provider zone once more, so
  every loop over the list ran once per copy:
  - the signer's start report and its hand-over check;
  - the refresh and first-load registrations;
  - on the #211 stack, the role ticker and the rollover mark.
- **Names that never left.**
  - A zone the config dropped stayed in the list.
  - So did a zone that lost the multi-provider option. The signer's rollout
    gate then counted such a zone as multi-provider. If the zone kept its
    DNSSEC policy and the operator took it out of `key-lifecycle-zones`, a
    reload made the signer stop itself over a correct config.
- **A data race.** The readers range over the slice from their own
  goroutines while a reload appends to it, with no lock.

## The change (`mp_zone_names.go`)

`mpZoneNameSet` replaces the field.

- **The handler collects.** `add` appends the zone's name to the names
  collected since the last publish, under a mutex.
- **`refresh` publishes.** It takes the published zones and the collected
  ones together, keeps each zone once by its folded name, and keeps a zone
  only while tdns holds it with the multi-provider option. The result
  becomes an immutable snapshot, stored in an atomic pointer, and the
  collected names are cleared.
- **Readers use `conf.mpZoneNames()`.** It returns the snapshot, which is
  never written to after it is published, so a reader ranges over it with
  no lock.

`refresh` checks the result against what tdns holds, so it is right
whenever it runs. It does not need to know where a parse began, which no
tdns hook says. It also cleans up after a parse that failed half-way: a name
collected then, which tdns does not hold with the option, is not kept. It
runs:

- after tdns's `MainInit`, so the start's readers have the zones, among them
  the agent's catch-up tracker and the hydration;
- at the top of `RegisterMPRefreshCallbacks`, which every role's reload hook
  runs, the signer's before its rollout gate;
- at the top of `RegisterCombinerOnFirstLoad`, which the combiner's reload
  hook runs first.

## Tests (`mp_zone_names_test.go`)

- `TestMPZoneNamesHoldEachZoneOnceOverReloads`: three parses of the same
  zones, one of them spelled in another case, leave each zone once.
- `TestMPZoneNamesFollowTheConfig`: a dropped zone leaves the set, so does
  one that lost the option, and an added zone joins.
- `TestMPZoneNamesAfterAParseThatFailed`: names left by a failed parse are
  not kept.
- `TestMPZoneNamesReadWhileAReloadPublishes`: readers range over the set
  while 500 parses publish. Run it with `-race`.
- `TestTheRolloutGatePassesAZoneThatLeftMultiProvider`: after the reload,
  the gate passes a zone the signer signs that left multi-provider and
  `key-lifecycle-zones`.

The tests that set the field now use `setForTest` and `includeForTest`
(`mp_zone_names_helpers_test.go`).

## On the #211 stack

`key_rollover_mark.go` and `signer_role.go` range over the old field. When
this change is merged forward, each needs the one-line change to
`conf.mpZoneNames()`.
