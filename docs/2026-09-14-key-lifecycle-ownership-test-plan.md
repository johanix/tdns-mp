# Key lifecycle ownership: test plan

**Status:** proposal, under review
**Companion to:** `docs/2026-09-13-key-lifecycle-ownership-design.md` (the design; its §8 risks R1–R13 and §6 steps S1a–S6)
**Read at:** tdns `514db197`, tdns-mp `4da1d92`

## Revision history

| Rev | Date | Change |
|---|---|---|
| r1 | 2026-09-14 | First version. |

---

## 1. Principle

The design states its rules as tables and invariants. That is what makes it possible to write the tests before the code.

- **Tests are the acceptance criteria of each step.** A step's PR is done when its tests pass.
- **The tests come first.** A step's first commit adds its tests (skipped, or failing), and the last commit makes them pass.
- **Later steps don't delete earlier tests.** The one exception is the tests that keep today's code as the reference, which go in S4 together with that code.
- **Every test answers a risk** from the design's §8 (table in §6 below).
- **Every guard is itself tested.** For each guard, break the code once on purpose, and require a test to fail (§4.8).

---

## 2. What already exists, and what is missing

**tdns:**
- An in-memory keystore for tests: `newTestKeyDB` (`v2/sign_reconcile_test.go:93`). About a hundred test files open a test KeyDB.
- An injectable clock in the rollover engine: `RolloverEngineDeps.Now` (`v2/rollover_engine_deps.go:31`).
- Interop tests under `tests/`: `ixfr-interop`, `notify-semantics`, `xot-interop`, `zonemd`.

**tdns-mp:**
- An in-process transport harness: `v2/transport_harness_test.go`, `v2/transport_integ_test.go`.
- Wire goldens: `v2/testdata/golden-wire`, `v2/testdata/golden-api`.
- The key seam tests: `v2/signer_keyseam_test.go`.
- The scenario test design, whose KEY-GEN and KEY-ROLL rows are the key scenarios: `docs/2026-09-10-mp-scenario-test-rigs-design.md`.
- The policy matrix: `tests/mp-policy-matrix`.

**Missing:**
- **An injectable clock in tdns-mp.** None was found. The key state machine needs one before its tests can be deterministic (T3.0).
- **A fake parent, a validating check, a keystore write recorder, fixture databases.** §5 describes these shared tools.

---

## 3. The invariant checker (T1)

**What it is.** One function in tdns, `CheckKeyInvariants(kdb, zd) []KeyInvariantViolation`, used by every test layer. The same checks run behind a `keystore check` command in tdns and tdns-mp.

**The invariants:**

| # | Invariant | Violated by |
|---|---|---|
| I1 | `sign=1` implies `pub=1` | a key that signs but is not in the DNSKEY RRset |
| I2 | `sign=1` implies a private key | a foreign row, or a row with its key material missing, marked to sign |
| I3 | `ds` is set only on SEP keys | a ZSK with `ds=1` |
| I4 | at most one `sign=1` key per role and algorithm; the only exception is the two SEP keys of an algorithm rollover | two active ZSKs of the same algorithm |
| I5 | the served DNSKEY RRset equals the `pub=1` rows (for a multi-provider zone: plus what the owner merges) | a missing or extra DNSKEY |
| I6 | the keys that signed the zone's RRsets are the `sign=1` keys | an RRSIG by a key with `sign=0`, or a `sign=1` key that signed nothing it should |
| I7 | unless some SEP row has `ds` unset, the served CDS equals the CDS built from the `ds=1` rows | a CDS for a key without `ds`, or a missing one |
| I8 | no row has `pub` or `sign` unset after startup | a write that skipped the flags |
| I9 | in a zone tdns owns, the flags match the design's §3.4 table for the zone's DS model and the key's state (outside a transition in progress) | a flag written by the wrong rule |

**Where it runs:**
- **Unit tests,** after every keystore write.
- **Property tests,** after every event (§4.5).
- **Startup, in test builds.** During S1a the process refuses to start when I5 or I6 would change (design R1).
- **On the public testbed,** as a warning with a counter.
- **On demand,** through `keystore check`.

---

## 4. Tests per step

### 4.1 S1a (tdns): columns, one write function, `pub`/`sign` backfill

| Test | What it checks |
|---|---|
| T1a.1 table | Every tdns state × role (KSK, ZSK, the CSK fallback) gives the `pub` and `sign` of the design's §3.4 table. `ds` stays unset. |
| T1a.2 old against new | The signing set and the served DNSKEY set computed today's way are equal to the same sets computed from the columns. Today's way means the state queries: `state='active'`, plus the `ops_dnskey.go` served-state list. Those queries are kept in `_test.go` files as the reference. Coverage: every small keystore (zero to two keys per state and role), plus seeded random keystores. |
| T1a.3 migration fixtures | Fixture databases, generated once from today's code and committed under `testdata`, pass the migration with I1–I8 holding and T1a.2 equal. The fixtures (one zone per fixture):<br>• no automated rollover, with a standby KSK<br>• multi-DS mid-pipeline: ds-published and published<br>• an algorithm rollover in flight, its old head active<br>• a ZSK pipeline with standby and retired keys<br>• multi-provider rows: mpdist, foreign, mpremove<br>• a removed key |
| T1a.4 rollback and forward | On a migrated database, insert rows the way today's schema does (no flags), then reopen. The flags come back from state, and I8 holds. |
| T1a.5 single writer | A CI check fails on any SQL that inserts into `DnssecKeyStore` or updates its `state` outside `setKeyRowTx`/`insertKeyRowTx`. Test keystores also carry a trigger that aborts a state update leaving `pub` or `sign` unset. |
| T1a.6 listings | Goldens for the keystore `list` output with the `pub`, `sign` and `ds` columns. |

**Passes when:** all green, and the startup check (§3) is on in test builds.

### 4.2 S1b (tdns): `ds` written and read

| Test | What it checks |
|---|---|
| T1b.1 table | Every state × DS model (multi-DS, double-signature, none) gives the design's `ds`. That includes retired before and after the withdrawal, and the algorithm rollover's old head at `ds=0`. |
| T1b.2 old against new | Today's `DSIntentForZone`, kept in tests as the reference, against the `ds`-based answer, over every small keystore × model. The allowed differences are listed in the test: a published KSK outside multi-DS (tdns #635), and the algorithm rollover's old head. Any other difference fails. |
| T1b.3 one-time pass | The T1a.3 fixtures get `ds` per the table, and the logged difference list equals the allowed differences. |
| T1b.4 unset `ds` | With any SEP row's `ds` unset:<br>• DS intent is unknown<br>• the DS engine leaves the served CDS as it is<br>• the syncher sends no DS change |
| T1b.5 fake parent | For each model:<br>• none: no DS for a published KSK, DS once it is standby<br>• multi-DS: DS at ds-published<br>• algorithm rollover: the old head never gains a DS<br>• any model: a DS leaves the parent only after an explicit withdrawal |
| T1b.6 full rollovers | With the injectable clock, a full KSK rollover in each model completes, with I1–I9 holding after every tick. |

### 4.3 S2 (tdns): ownership

| Test | What it checks |
|---|---|
| T2.1 run everything on an owned zone | A test owner that owns the zone, and a recorder on keystore writes. The recorder must see zero writes when every lifecycle path in the design's §3.5 runs:<br>• every key state worker step<br>• every rollover tick, including the two walks at `ksk_rollover_automated.go:1474` and `:1703`<br>• promotion, minting and algorithm reconcile in `EnsureActiveDnssecKeys`<br>• bootstrap rollover-row registration<br>• first-load validation<br>Every refused API verb must return an error naming the tdns-mp command. This test lands before S2, failing, as the list of paths S2 must skip. |
| T2.2 not owned | The same paths, with no owner registered, behave as today. |
| T2.3 `Owns` false | A multi-provider zone the owner does not (yet) own keeps today's behaviour, hooks included. This is what the per-zone rollout relies on. |
| T2.4 new writers | A CI list of every caller of `UpdateDnssecKeyState*`, `PromoteDnssecKey` and `GenerateKeypair`. Each is either ownership-checked or on an explicit allow-list; a new, unlisted caller fails. |
| T2.5 DS-intent provider | For an owned zone, DS intent asks the owner; an unset answer is unknown. |
| T2.6 `setstate` | On an owned zone, `setstate` without flags is refused. With flags it goes through `setKeyRowTx`. |

### 4.4 S3 (tdns-mp): the state machine

- **T3.0 Clock.** An injectable clock for the key state machine, following `RolloverEngineDeps.Now`.
- **T3.1 Transition table.** The multi-provider key lifecycle written as data: state × event → next state, flags and guard. Its flag columns are the design's §3.4 table. A table test checks the implementation against it.
- **T3.2 Harness.** Two to four providers in one process:
  - the transport harness
  - the fake clock
  - one in-memory keystore per signer
  - per provider, a view of the zone that provider publishes
- **T3.3 Property tests.** Seeded random event sequences drive the harness. A failing seed becomes a regression test. Event types:
  - key generation
  - confirmations: success, pending, partial, rejected
  - propagation timer ticks
  - a signing provider joining or leaving (HSYNCPARAM signers)
  - a restart that reloads the keystore
  - message loss, duplication and reordering

  After every event, I1–I8 must hold for every provider, and so must these properties:

| # | Property |
|---|---|
| P1 | no key gets `sign=1` before every signing provider has confirmed applying its DNSKEY and the DNSKEY RRset has propagated |
| P2 | no KSK gets `ds=1` before it is standby |
| P3 | a foreign KSK has `ds=1` only if its provider signs the zone and its state there is standby or active, or retired before the withdrawal |
| P4 | no key is lost: every generated key is still in a live state or has reached removed |
| P5 | one `sign=1` key per role and algorithm per provider, except during an algorithm rollover |
| P6 | with fair message delivery, a started rollover completes within the bound its policy gives |
| P7 | with no other signing provider, mpdist moves to published at once |
| P8 | a rejected key stays in mpdist, is reported, and is never promoted |
| P9 | a "pending" confirmation never counts as applied (#57) |

- **T3.4 Scenarios, at unit-test speed,** following the KEY-GEN and KEY-ROLL rows:
  - standby generation with a policy count of 0, 1 and 2
  - ZSK rollover
  - KSK rollover with two and with three signing providers
  - a provider leaving mid-rollover
  - a restart mid-rollover
- **T3.5 Replacement commands.** API and CLI tests: policy bind and change, rollover now and cancel, retry and withdraw, listings with the columns. The mpcli tree golden is updated.
- **T3.6 Nothing the parent sees changes.** For an owned zone in S3, the served CDS and the agent's DS intent equal a snapshot taken before S3 (design §6).
- **T3.7 Mixed rollout.** Zones tdns-mp owns use no hooks; multi-provider zones it doesn't own yet still do.

### 4.5 S4 (tdns): deletion

- **T4.1 The gate, checked in the S4 PR:**
  - no caller of the hook registration is left in tdns-mp
  - T2.1 and T3.x are green on the tdns-mp commit S4 is tested against
- **T4.2 Names.** A CI check that tdns no longer contains the multi-provider state names or constants.
- **T4.3 Old reference removed.** The reference tests (T1a.2, T1b.2) are removed together with the code they call. The invariant checker, the table tests and the fixtures stay.

### 4.6 S5 (tdns-mp, and a tdns part): what the parent sees

| Test | What it checks |
|---|---|
| T5.1 goldens | The DNSKEY distribution payload carries, per key, the provider and its state or `ds`. The key inventory carries `Pub`, `Sign` and `DS`. |
| T5.2 mixed versions | An old payload without the fields gives foreign rows with `ds` unset, an unknown DS set and no parent update. Old and new decode each other in both directions, and an old receiver ignores the fields. |
| T5.3 arrow 1 | The signer publishes CDS from the `ds=1` rows. After a transfer from the combiner, `CollectDynamicRRs` restores the CDS and it is signed before the swap. The combiner no longer synthesizes CDS. |
| T5.4 arrow 2 | The inventory is pushed on every `pub`, `sign` or `ds` change, including a `ds` flip with no state change. The agent's DS-intent provider answers from the latest inventory. The leader's UPDATE or API carries exactly that DS set, and a non-leader sends nothing. |
| T5.5 cutover | One provider switches from combiner CDS to signer CDS in one release. The fake parent never sees a CDS deletion, or two different CDS sets. |
| T5.6 agent DS engine | For an owned zone, the agent's DS engine publishes no CDS. |
| T5.7 agent setup | Delegation-sync setup for `AppTypeMPAgent`: with parentsync=agent it runs once; with parentsync=owner it doesn't. Without explicit configuration, no KEY or UPDATE reaches the fake parent. |
| T5.8 leader change | Only the leader sends. A re-election hands over without a duplicate or a missing update. |

### 4.7 S6 (tdns): rollover pushes into the syncher

The T1b.5 fake-parent timelines and the T1b.6 full rollovers pass unchanged before and after the move. The move changes only who sends, not what the parent sees.

### 4.8 Tests for the tests

Each guard gets one deliberate break, applied in a test-only build or a throwaway branch, and the named test must fail:

| Break | Must fail |
|---|---|
| one writer skips the flags | T1a.5 trigger, T1a.2 |
| the algorithm-rollover old-head exclusion is dropped | T1b.2, T1b.5 |
| one ownership skip is removed | T2.1 |
| a pending confirmation promotes a key | P9 |
| the propagation wait is skipped | P1 |
| the combiner keeps synthesizing CDS after the cutover | T5.5 |

---

## 5. Shared test tools

- **Fake parent (tdns, usable from tdns-mp).** An in-process parent that:
  - serves DS
  - scans CDS on NOTIFY(CDS)
  - accepts UPDATE and the DSYNC API
  - records every change on a timeline

  Assertions:
  - no DS removed without an explicit withdrawal
  - no CDS deletion while any `ds` is unset
  - the DS set equals the expected set at each step
- **Validating check.** After every transition in the scenario tests, the zone is resolved through tdns's resolver in test mode, with the test's trust anchor, against every provider's served zone. A bogus answer fails the test. It catches R1, R4, R6 and R11 as a resolver would.
- **Keystore write recorder.** A trigger or KeyDB wrapper for test builds. It counts or refuses writes to `DnssecKeyStore`.
- **Fixture generator.** Writes the T1a.3 databases from today's code. It is run again only on purpose, and the committed fixtures are the reference.
- **Seeded property runner.** Records failing seeds as regression tests.

---

## 6. Risks and tests

| Risk (design §8) | Tests |
|---|---|
| R1 wrong `pub`/`sign` backfill or missed reader | T1, T1a.1, T1a.2, T1a.3, startup check |
| R2 older binary on a migrated database | T1a.4 |
| R3 a write outside the one function | T1a.5, T2.4, §4.8 |
| R4 wrong `ds` reaches the parent | T1b.1–T1b.6, fake parent |
| R5 a lifecycle path not skipped | T2.1, T2.4, §4.8 |
| R6 bugs in tdns-mp's state machine | T3.1–T3.4, P1–P9, validating check |
| R7 operators lose tools | T3.5, T2.1's error-message check |
| R8 hooks deleted too early | T4.1, T3.7 |
| R9 fleet cut | T5.2 |
| R10 agent setup code that never ran | T5.7 |
| R11 CDS source cutover | T5.3, T5.5, fake parent |
| R12 concurrent work in the same files | the full suite on every merge of main; T1b.6 and T1b.5 as the rollover regression set |
| R13 output changes | T1a.6, T5.1 |

---

## 7. What these tests cannot catch

- How real parents scan CDS and handle UPDATE, and their timing.
- DNSKEY and DS propagation through real resolvers on the Internet.
- How operators actually use the new commands.

For those, the first owned zone moves on the public testbed before any other zone. It runs with the invariant checker as a warning, and with the agent reporting which provider blocks the DS set.

---

## 8. Order of work

1. This plan is merged with the design.
2. The first S1a PR starts with T1 and the T1a tests, skipped, then turns them on as the implementation lands.
3. Each later step starts with its tests. T2.1 lands before S2 as the failing list of paths S2 must skip.
4. The fake parent, the write recorder and the fixture generator are built in the first step that needs them: S1a for the fixtures and the recorder, S1b for the fake parent.
5. T3.0 (the clock) and T3.2 (the harness) are the first commits of S3.
