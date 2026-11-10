# Identity-zone parent sync back; a parent with no usable DSYNC is quiet

2026-11-09. Refs #391 #392.

## The ruling

Johan, 2026-11-09, replacing his ruling of 11-08:

- Parent sync is wanted wherever the parent announces, through DSYNC, a
  scheme the child can use. It stays on, identity zones included, whether
  or not the DNSSEC set-up needs it.
- A parent that publishes no usable DSYNC is the overwhelmingly common
  case. The child logs a warning and moves on: no ERROR, no flood.
- A test rig whose DNSSEC set-up depends on parent sync may complain
  loudly. That is the rig's check, not the daemon's.

## What #392 took out, and what comes back

#392 removed the identity zone's delegation sync in three commits. All
three are reverted here. Each was about identity-zone sync only, so
nothing in them is kept.

- **4338e22f.** The daemon-built identity zone is a parentsync child again
  when the `parentsync:` block names schemes and the imrengine is on.
  - Back with it: `startIdentityParentSync`, `publishIdentityCds` (the
    auditor's CDS), `AgentSig0KeyPrep`, `syncIdentityDelegation` with its
    pace, the start-up warnings, and their tests.
  - Why it matters: the identity zone's DS at its parent is what lets a peer
    validate the zone's TLSA, which the HTTPS transport's mTLS gate relies
    on. The rig's DNSSEC-chain suites (dnssec, dnssec-ctl, tlsa,
    dns-carrier) depend on it.
- **47286cf0.** The election and the syncher no longer pass a config-listed
  identity zone by.
- **558f2bdd.** `SetupAgent` no longer drops a config-listed identity zone's
  parentsync option, and no longer warns about it.
- **CodeRabbit's Minor on #398** (`agent_setup.go:458`) concerned that drop,
  so it is moot.

## A config-listed identity zone with the option keeps it

The start-up warning `configIdentityZoneNotSynced` came back with the
revert. It says that "parentsync does not apply" to a config-listed
identity zone. That is true only for a zone whose config does not give it
the parentsync option.

A zone with the option is synced, so the warning is now given only when the
option is absent. tdns doesn't start that sync: `SetupZoneSync` queues the
setup and the load-time compare only for an authoritative server's zone, or
for a multi-provider agent's multi-provider zone. The identity zone is
neither. So tdns-mp starts it:

- **On the agent**, the zone's first load elects (`electAtFirstLoad`). The
  elected leader sets up the SIG(0) key and asks for the sync
  (`onLeaderElected`).
- **On the auditor**, there is no election. The zone's first load starts the
  path the daemon-built zone takes (`startIdentityParentSync`): its CDS, then
  `syncIdentityDelegation`, which asks the parent only once it offers a
  usable scheme. `configIdentityZoneSyncedHere` decides this. It does not
  start the path where an election runs, since that would race the leader's
  SIG(0) key setup.

Tests:

- `TestAConfigListedIdentityZoneIsWarnedAbout` gains a case: no warning, and
  the option is still set after the set-up.
- `TestAConfigListedIdentityZoneWithTheOptionIsSynced`: the auditor's zone
  with the option asks for its sync after the first load. Without the option,
  or with an election, the first load starts nothing.

Rev. 2026-11-10: the first version of this note said tdns queues the setup
for such a zone. CodeRabbit's Major on #409 found that it does not, and the
auditor's first-load start was added.

## No usable DSYNC: one warning per zone (`parent_offer.go`)

Before anything is sent, the agent looks at what the parent offers
(`parentOfferOf`):

- **The plan.** It builds the sync plan tdns builds: `BuildParentSyncPlan`
  in the child role, which is one DSYNC discovery with the scheme gates.
- **The bootstrap target.** It checks whether the parent advertises the
  UPDATE target the SIG(0) bootstrap goes to. This uses the test
  `LookupDSYNCTarget` applies, whatever the configured schemes.
- **The cost.** The resolver answers the second discovery from its cache.

"Unusable" means the plan has no candidate after a discovery that
succeeded. That covers three cases:

- the parent publishes no DSYNC;
- it publishes none for a configured scheme;
- every advertised scheme fails its gate (an unsigned zone for NOTIFY, no
  credential for API, a target with no address).

A failed discovery (no resolver, a lookup error) is not this case. The sync
then goes on and meets the failure itself, as before.

### The notices (`parentNotices`)

The notices are kept per zone name, so a reload does not warn again.

| What | Level |
|---|---|
| The first time a zone's parent offers no usable scheme, or a new parent | WARN, naming the parent and what was found (the plan's summary) |
| Every later look that finds the same | DEBUG |
| A usable scheme after the warning | INFO, once; the note is cleared |
| The SIG(0) bootstrap, for a parent with no UPDATE target | its own note: WARN once, DEBUG after, INFO when it appears |

### Where the look is made

- **`syncDelegation`, both paths, just before `SyncZoneDelegation`.**
  - It returns `errNoUsableScheme`, and nothing is sent.
  - The SYNC-DELEGATION arm logs DEBUG and books no failure: no
    `leaderSyncFailed`, so no retry chain.
  - The EXPLICIT arm answers with `Msg` set and no error.
  - On the multi-provider path the leader's CSYNC is still made first: it
    is in the zone for a parent that scans for it, whether or not that
    parent publishes DSYNC.
- **The DELEGATION-SYNC-SETUP arm.** A parent with no UPDATE target gets the
  bootstrap's warning, and the setup ends there. Without this, tdns's
  `DelegationSyncSetup` logged ERROR twice per attempt (the sweep's class
  K3).
- **`syncIdentityDelegation`, before each ask.**
  - A parent that offers nothing is not asked anything. It is looked at
    again once per `identitySync.recheck` (an hour), at DEBUG.
  - The SIG(0) setup is queued only when the parent advertises the UPDATE
    target, or when nothing is known of the parent. A parent with other
    schemes and no UPDATE gets one warning, and the sync goes on through
    those schemes.
  - The fast attempts and the back-off still count only real asks.
- **`recheckParentOffers`, started with the syncher.**
  - Once an hour it looks at the zones the syncher noted.
  - Nothing new: DEBUG, and nothing is queued. A usable scheme: INFO, and
    the explicit sync (or setup) is queued.
  - A zone gone, or a multi-provider zone this agent no longer leads, is
    forgotten.
  - The identity zone's own loop does not put its zone on this list.
  - An hour is longer than the negative TTL of most DSYNC answers, so each
    look asks the parent anew. A parent change shows as a new parent at the
    next look; a reload brings a new ZoneData, which is looked at on its
    first sync.

### What stays an ERROR

A failure where a usable scheme exists stays an ERROR, as before: the
parent refuses the UPDATE, the API call fails, or the attempt times out.
These are logged as "error from SyncZoneDelegation", and the leader's
retry chain follows them.

### The race, and why it is left

The identity loop's look and the syncher's look are a moment apart. If a
parent drops its last scheme between the two, the syncher answers "nothing
sent" with no error. The loop logs that once as "delegation sent", and
finds the truth at its next look.

## tdns

The auditor's syncher is tdns's own. Before the re-pin, the auditor is
quiet anyway: its identity loop does not ask a parent that offers nothing,
and queues no setup without an UPDATE target.

The tdns PR makes the same case one WARN inside tdns:

- in `SyncZoneDelegation`;
- in the SIG(0) bootstrap behind `DelegationSyncSetup`;
- in the syncher's arms.

That covers tdns-auth children too. tdns-mp is re-pinned to it on top of
#351.

## Tests

| Test | What it shows |
|---|---|
| `TestIdentityZoneParentSync`, `TestTheIdentityZonesParentSyncStartsAfterItsCommit` (restored) | An identity zone with a `parentsync:` block gets the sync |
| `TestAConfigListedIdentityZoneIsWarnedAbout` (new case) | A config-listed identity zone keeps its option, with no warning |
| `TestAConfigListedIdentityZoneWithTheOptionIsSynced` | On the auditor, such a zone's first load asks for its sync; without the option, or where an election runs, nothing more is started |
| `TestAParentWithNoDsyncIsWarnedAboutOnce` | The real syncher, tdns's analysis and a resolver whose cache answers the DSYNC queries with no data. Five syncs of a multi-provider leader give one WARN naming the parent and what was found, four DEBUG lines, no ERROR, no failure chain, and nothing sent |
| `TestAUsableSchemeThatAppearsLaterIsPickedUp` | The same parent publishes NOTIFY targets. The next quiet look logs INFO, and the sync goes out as NOTIFY(CDS) |
| `TestARealFailureOnAUsableSchemeIsStillAnError` | A parent that offers UPDATE and fails it gives "error from SyncZoneDelegation" at ERROR, and no "offers nothing" notice |
| `TestASetupForAParentWithNoUpdateSchemeIsWarnedAboutOnce` | Three setups give one WARN, no ERROR, no bootstrap UPDATE and no SIG(0) key |
| `TestTheIdentitySyncWaitsQuietlyForAParentScheme` | No ask while the parent offers nothing: one WARN, DEBUG per look, INFO when a scheme appears, then the ask |
| `TestTheIdentitySetupWaitsForTheParentsUpdateScheme` | The setup is queued once with an UPDATE target and not at all without one (one WARN) |

The first and fourth syncher tests fail without the `delegation_sync.go`
change.
