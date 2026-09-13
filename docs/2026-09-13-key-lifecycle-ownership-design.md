# Key lifecycle ownership: tdns-mp runs the key state machine of multi-provider zones

**Status:** proposal, under review
**Repos:** tdns-mp (owner of the multi-provider state machine), tdns (keystore, signer, delegation sync, DS engine)
**Read at:** tdns `ff814c71`, tdns-mp `fb3b1bf`

## Revision history

| Rev | Date | Change |
|---|---|---|
| r1 | 2026-09-13 | First version. Problem statement, the decisions taken so far, the model, the parties that touch the parent, staging, open questions. |
| r2 | 2026-09-13 | Review. published and standby are different: published = in the DNSKEY RRset, not yet propagated; standby = propagated; no DS for a published key except under multi-DS. The `ds` column now depends on the DS model (§3.4), with a finding that tdns's DS rule counts published keys in every model. ds-published (multi-DS only) added; the policy may keep zero or more standby keys. Q6 rewritten. The protocol change (§5) and the propagation-gate bug (§1.1) agreed. |

---

## 1. Problem

The B-MP work (tdns #622, tdns-mp #50) moved multi-provider keys into tdns's keystore (`DnssecKeyStore`) and let tdns's signer sign multi-provider zones. Sharing storage and signing is right, and this design keeps it.

B-MP also left tdns's **key state machine** in charge of multi-provider zones: `KeyStateWorker`, the ZSK and KSK rollover engines, standby maintenance, promotion on the sign path, DS intent. tdns-mp bends that machine through five hooks (`KeyLifecycleHooks`, tdns `key_lifecycle_hooks.go:40-69`):

- `StagedState` returns mpdist
- `RetiredState` returns mpremove
- `MayPromote`
- `MayGenerate`
- `OnStateChange`

As a consequence, tdns code has learned states whose meaning only tdns-mp owns:

- **The constants** `DnskeyStateMpdist`, `DnskeyStateForeign` and `DnskeyStateMpremove` are defined in tdns (`structs.go:74-82`).
- **The served DNSKEY RRset** is a query that names mpdist and foreign (`ops_dnskey.go:21-32`).
- **DS intent** has special cases: mpdist gets no DS, foreign or mpremove makes the answer unknown, and a zone whose only DS-less key is mpdist is "unknown" too (`ds_intent.go:57`, `:114-166`).
- **The DS engine** has a multi-provider model that writes nothing and only relays a CDS someone else serves (`ds_engine.go:368-382`).

Each new tdns component that reads key state has to ask what to do about these states. The DS engine (tdns #624) is the forcing function. It must answer "which DS should the parent hold now?", and for a multi-provider zone that answer lives in tdns-mp.

### 1.1 The split is broken, not just untidy

**tdns's lifecycle does not treat multi-provider zones consistently:**
- Two KSK rollover walks lack the multi-provider skip that the main rollover tick has (`ksk_rollover_automated.go:1474`, `:1703` vs `:1949`).
- A retired KSK in a multi-provider zone whose policy rollover method is not `none` never leaves `retired`. `transitionRetiredToRemoved` leaves it to the rollover engine (`key_state_worker.go:202-206`), which skips the zone.
- Keystore API writes (`setstate`, `delete`, `add`, `rollover`, `policy-cleanup`, bulk import) bypass the hooks (`keystore.go:535`, `:628`, `:721`, `:1669`, `:1692`, `:845`). The hooks' own comment assumes only rollover paths are unreported.
- `EnsureActiveDnssecKeys` registers bootstrap rollover rows for multi-provider zones (`sign.go:610`).
- Delegation-sync setup is gated for multi-provider zones, but the `SYNC-DELEGATION` producer in the zone updater is not (`zone_utils.go:1954-1956` vs `zone_updater.go:451`).

**Multi-provider zones get no policy-driven key management.** Automated ZSK and KSK rollovers skip them (`zsk_rollover.go:502`, `ksk_rollover_automated.go:1949`). Key lifetimes are not honoured. Standby counts come from the global kasp settings, not the zone's policy (`key_state_worker.go:18-63`). A rollover happens only when an operator runs one.

**tdns-mp's own key protocol has gaps (code reading):**
- A key moves mpdist → published on *any* confirmation, including the immediate "pending" confirmation a relaying agent sends on receipt. The confirmation callback hands every status to the DNSKEY propagation tracker (tdns-mp `hsync_transport.go:393`), which marks the agent confirmed whatever the status (`:2089-2093`). A key can be promoted before any other provider's combiner has applied it. Agreed 2026-09-13 as a likely bug, to fix.
- With no remote agents, or after a "rejected", a key stays in mpdist forever (`syncheddataengine.go:222-229`; `signer_msg_handler.go:105-124`).

**The DS side for multi-provider zones barely exists (code reading):**
- **Only combiners write CDS.** Each combiner builds it with `SynthesizeCdsRRs` from the DNSKEY RRset it serves (tdns-mp `combiner_chunk.go:453-506`; tdns `ops_cds.go:22-58`).
- **That RRset lacks the provider's own keys.** A provider's DNSKEYs are never sent to its own combiner (`SkipCombiner`, tdns-mp `hsyncengine.go:90-99`).
- **It includes KSKs that should have no DS.** Every served SEP key goes in, mpdist and retired KSKs included.
- **It is rebuilt only when another provider's DNSKEY contribution changes** (`combiner_chunk.go:427-431`). A provider rolling its own KSK never updates its own CDS.
- **No process computes a DS set.** The leader agent's UPDATE carries no DS, because DS intent is always unknown on the agent: its keystore holds none of the zone's keys (tdns `delegation_utils.go:236-305`).
- **The syncher's `SYNC-DNSKEY-RRSET → PublishCdsRRs` path is dead:** nothing sends that command on the delegation-sync queue (tdns-mp `delegation_sync.go:160-180`).

---

## 2. Decisions taken

| # | Decision |
|---|---|
| D1 | For a multi-provider zone, the whole policy-driven key state machine is local to tdns-mp: ZSK and KSK, standby keys, rollovers, lifetimes. tdns shares the keystore and the signing and publishing functions. Sharing ZSK management but not KSK management would not be a clean cut. |
| D2 | `SignZone`/`ResignZone` keep finding their signing keys in the keystore themselves. What tdns no longer does for these zones is *manage* key states. |
| D3 | Keystore rows carry mechanism columns separate from the lifecycle state: **[include]** (in the DNSKEY RRset), **[sign]** (the key signs) and **[state]** (lifecycle state, opaque to the mechanism). The signer functions read only include and sign. Whichever state machine owns the zone reads [state] and writes the columns: tdns's `KeyStateWorker` for tdns zones, tdns-mp's for multi-provider zones. A foreign key is `[include][no sign][foreign]`. |
| D4 | The parent's DS set for a multi-provider zone is the DS of the KSKs of **all signing providers**. |

---

## 3. The model

### 3.1 Keystore row

Today's schema is at tdns `db_schema.go:72-88` (`state TEXT` at `:75`, `UNIQUE (zonename, keyid)`). The model adds three columns:

| Column | Meaning | Read by |
|---|---|---|
| `include` | the key is in the zone's DNSKEY RRset | DNSKEY publication |
| `sign` | the key signs; its role comes from the flags (SEP → DNSKEY RRset, otherwise zone data), as today (`signing_keys_snapshot.go:187-193`) | signing, resigning |
| `ds` | the key should have a DS at the parent; `NULL` means unknown | CDS publication, DS intent, delegation sync |
| `state` | the owner's lifecycle state; the mechanism never interprets it | the state machine that owns the zone |

`ds` is proposed in addition to D3. It removes the last place where tdns reasons about states it does not own (DS intent and the DS engine's per-model logic). It also carries a case today's states cannot express: the old head of a KSK algorithm rollover is active and signs, but must have no DS (`ksk_rollover_ds_push.go:159-167`). That key is `include=1, sign=1, ds=0`.

**Invariants, enforced by the one write function (§3.2):**
- `sign` implies `include`. No tdns transition signs with a key it does not publish: the KSK algorithm rollover mints the new key straight into active (`ksk_rollover_alg.go:177`), and `EnsureActiveDnssecKeys` republishes the DNSKEY RRset from the active set before signing (`sign.go:662`).
- `sign` implies a private key. Today a missing private key fails the zone's key load (`signing_keys_snapshot.go:176-179`). A foreign row has none and so can never sign.
- `ds` only on SEP keys.

**One boolean for `sign` is enough.** KSK, ZSK, the CSK fallback (`signing_keys_snapshot.go:211-214`) and the KSK algorithm rollover (two active SEP keys, both signing the DNSKEY RRset) are all expressed by `sign` plus the key flags. Nothing in tdns needs a KSK that also signs zone data next to a ZSK, or per-RRtype signers.

### 3.2 One write function

Every write of `state` must also set the flags, in the same statement. Today there are seven writers:

| Writer | Where |
|---|---|
| W1 `UpdateDnssecKeyState` / `…Tx` | `keystore.go:1491`, `:1529`, `:1537` |
| W2 `PromoteDnssecKey` | `keystore.go:1250` |
| W3 `GenerateKeypair` | `sig0_utils.go:262` |
| W4 `RolloverKey` raw SQL | `keystore.go:1669`, `:1692` |
| W5 keystore API `add`, `setstate`, `delete` | `keystore.go:535`, `:628`, `:721` |
| W6 bulk import | `keystore_bulk.go:426`, `:457` |
| W7 a migration | `db.go:160` |

They converge on:

```go
type KeyRowFlags struct {
    Include, Sign bool
    DS            sql.NullBool
}

// setKeyRowTx is the only UPDATE of DnssecKeyStore.state.
func setKeyRowTx(tx *Tx, zone string, keyid uint16, state string,
    f KeyRowFlags, expectOld string) (old string, err error)

// insertKeyRowTx is the only INSERT (GenerateKeypair, add, bulk import).
func insertKeyRowTx(tx *Tx, row KeyRow) error
```

- **tdns's own states** get their flags from one table keyed by DS model and state (§3.4), so tdns callers keep passing only a state; the zone's model is known where they run.
- **An owner** passes its state and the flags explicitly.
- **Post-commit effects** (snapshot republish, anything that replaces `OnStateChange`) stay in the wrapper that owns the transaction.
- **A CI grep gate**, like the existing `Data.Set` mutator gate, fails the build on any other `SET state` or `INSERT` on the table.

### 3.3 Readers

**Switch to the columns:**

| Reader | Today | With columns |
|---|---|---|
| Signing snapshot (`signing_keys_snapshot.go:143`), `GetDnssecKeys` (`keystore.go:1239`) | `state='active'` | `sign=1` |
| `EnsureActiveDnssecKeys`: the active-set reads (`sign.go:457`, `:562`, `:651`) | active | `sign=1` |
| DNSKEY RRset (`ops_dnskey.go:32` plus the active set at `:62-74`) and `CollectDynamicRRs` (`zone_utils.go:2029-2049`) | five named states plus active | `include=1`: one query for both readers |
| `DSIntentForZone` (`ds_intent.go:53-67`) | classifies states | `ds` on SEP keys; any `NULL` gives Known=false |
| DS engine and the rollover DS/CDS target (`ksk_rollover_ds_push.go:103-109`, `:159-167`, `:258`, `:691`; `ds_engine.go:384`, `:438`) | states plus the algorithm-rollover filter | `ds=1`, once the rollover engine writes `ds`, including the old-head exclusion |
| CDS synthesis (`ops_cds.go:28-45`) | SEP bit of the served DNSKEY set | `ds=1` rows. This also fixes the mpdist-in-CDS defect |
| `CountKskWithDSAtParent` (`ksk_rollover_pipeline.go:142`); `countDnskeyInZoneSEPKeys` (`ksk_rollover_automated.go:1807`); `config_reload_guardrail.go:140`; `zone_policy_apply.go:331`, `:623` | states used as "has DS", "published but not signing", "signs" | the matching column |
| Key inventory (`keystore.go:1351`, `KeyInventoryItem`) | state | adds `Include`, `Sign`, `DS` |
| API and CLI key listings | state | show the columns too; the rollover status label comes from include/ds |

**Stay on `state`:** the lifecycle readers, which exist only for zones tdns owns: `GetDnssecKeysByState` and its callers, pipeline counts, rollover phase logic, purge of `removed` rows.

### 3.4 Flags per state

The terms follow tdns's key state machine:
- **published:** the key is in the DNSKEY RRset, and that RRset has not yet propagated.
- **standby:** the DNSKEY RRset carrying the key has propagated fully. The policy may keep zero or more standby keys.
- **ds-published:** multi-DS only. The DS is placed at the parent before the DNSKEY is published. Only tdns's key state worker uses this state.

`ds` therefore depends on the zone's DS model as well as on the state:
- **Double-signature rollover, and zones without automated rollover:** a KSK gets no DS while it is published, only once it is standby.
- **Multi-DS:** the DS goes up first.

The state machine that owns the zone knows the model and sets `ds` at the transitions, so the readers of the column never need to know the model.

**tdns's own states:**

| state | include | sign | ds, multi-DS | ds, double-signature and none |
|---|---|---|---|---|
| created | 0 | 0 | 0 | 0 |
| ds-published | 0 | 0 | 1 | not used |
| published | 1 | 0 | 1 (placed at ds-published) | **0** |
| standby | 1 | 0 | 1 | 1 |
| active | 1 | 1 | 1 (0 for the old head of an algorithm rollover) | 1 |
| retired | 1 | 0 | 1 until the rollover withdraws it | 0 once its DS is withdrawn |
| removed | 0 | 0 | 0 | 0 |

A migration cannot know a zone's model, because it runs before policies load (`db.go:122-123`). Hence open question Q5.

**Finding for tdns zones (code reading).** `dsBelongsAtParent` counts a published KSK as having its DS in every model (`ds_intent.go:36-38`, `:55`). It follows the multi-DS order, created → ds-published → published → standby → active. DS intent mainly serves zones without automated rollover, and for those the DS engine then publishes a CDS for a key whose DNSKEY RRset has not propagated.

tdns has four definitions of "this key has a DS" today:
- `dsBelongsAtParent`
- the multi-DS rollover target: created through retired, minus the old head
- `CountKskWithDSAtParent`: ds-published through retired
- the rollover status label

The `ds` column replaces all four.

**tdns-mp's states for a multi-provider zone** (proposal; no multi-DS, see Q6):

| state | include | sign | ds (KSK) |
|---|---|---|---|
| created | 0 | 0 | 0 |
| mpdist | 1 | 0 | 0: in this provider's RRset, not yet confirmed by every provider |
| published | 1 | 0 | 0: confirmed by every provider, not yet propagated |
| standby | 1 | 0 | 1 |
| active | 1 | 1 | 1 |
| retired | 1 | 0 | 0 once its DS is withdrawn |
| mpremove | 0 | 0 | 0 |
| removed | 0 | 0 | 0 |
| foreign | 1 | 0 | 1 only for a KSK of a signing provider whose own state for that key is standby or active, or retired with its DS not yet withdrawn |

A ZSK has `ds=0` in every state.

### 3.5 Zone ownership

The columns say what the mechanism does with a key. They do not say who may change them. tdns needs a per-zone ownership marker, fixed before the zone's first refresh (the same ordering rule the hooks follow today). tdns-mp claims ownership of the zones it manages, for example from the `OptMultiProvider` option handler it already registers.

**For an owned zone, tdns skips every lifecycle path:**
- `KeyStateWorker`: published→standby (`key_state_worker.go:136`), retired→removed (`:188`), standby cap (`:424`), standby maintenance (`:288`).
- All KSK rollover walks (`ksk_rollover_automated.go:75`, `:1449`, `:1677`, `:2177`), the ZSK rollover (`zsk_rollover.go:494`), and the algorithm freeze and abort (`ksk_rollover_alg.go:250`, `:306`).
- In `EnsureActiveDnssecKeys`: promotion, minting and algorithm reconcile (`sign.go:308`, `:452-644`). A missing signing key for a role means "not released yet", as the publish path already handles (`zone_mutation.go:1040`).
- Bootstrap rollover-row registration (`sign.go:610`).
- Rollover-policy validation at first load (`ksk_rollover_validation.go:297`).
- The policy-change and reload guards (`ksk_rollover_alg.go:50`, `config_reload_guardrail.go:100`).

**For an owned zone, tdns refuses the API verbs that are lifecycle policy:**
- keystore `rollover` and `policy-cleanup` (`keystore.go:642`, `:809`)
- `clear` and forcing keys to the policy's roles (`:734`, `:897`)
- the rollover API: asap, cancel, reset, unstick (`apihandler_rollover.go`)
- policy set, change and reset (`apihandler_zone.go:646`, `:733`, `:941`)

**Mechanism paths keep working:**
- signing and resigning from `sign=1`
- DNSKEY publication from `include=1`
- CDS publication from `ds=1`
- stripping a departing key's RRSIGs, when the owner asks
- the delegation syncher, gated per §4
- policy binding for the fields that are mechanism (Q1)

**Removed once tdns-mp owns its zones:**
- the five hooks
- the multi-provider constants in `structs.go` (they move to tdns-mp)
- the state names in `ops_dnskey.go`
- the multi-provider cases in `ds_intent.go`
- `DSModelMultiProvider`: an owned zone's DS model is "the owner's `ds` column"

**tdns exports what an owner needs:** the resign trigger (`triggerResign`, `key_state_worker.go:470`, unexported today), the RRSIG strip of one key (`StripZoneRRSIGs`, `sign.go:849`), and the CDS publish-and-wait pair (`ds_engine.go:476`, `:496`) in place of `SynthesizeCdsRRs`.

---

## 4. Who decides the DS set, and who talks to the parent

The DS engine never talks to the parent. It writes CDS into the zone through the zone updater (`ds_engine.go:514-519`). Sending to the parent is a separate job. Today that job is done in four places:

| Party | What it does today | Where |
|---|---|---|
| tdns delegation syncher | UPDATE, NOTIFY(CDS) (after asking the DS engine) and API towards the parent | `delegation_sync.go:417-641`, `delegation_sync_api.go:24` |
| tdns KSK rollover engine, inside `KeyStateWorker` | its own scheme selection and its own UPDATE/NOTIFY/API pushes | `ksk_rollover_schemes.go:132`; `ksk_rollover_ds_push.go:336-441`; `ksk_rollover_ds_notify.go:33`; `ksk_rollover_ds_api.go:49` |
| DS engine | CDS content per DS model; no network I/O | `ds_engine.go` |
| tdns-mp | leader election; its own syncher, which calls tdns's `SyncZoneDelegation`; SIG(0) KEY bootstrap; combiner CDS synthesis | `parentsync_leader.go`, `delegation_sync.go:70-158`, `parentsync_bootstrap.go`, `combiner_chunk.go:453-506` |

**Proposed split** (the first three rows extend what the DS engine design already decided for tdns zones):

| Role | tdns zone | multi-provider zone |
|---|---|---|
| Decides the DS set | tdns's state machine writes `ds`: the rollover engine for multi-ds, the key state worker for `none` | tdns-mp's state machine writes `ds` on own KSKs and on foreign rows (D4) |
| Publishes CDS | DS engine, from `ds=1` rows | DS engine on the process holding the rows, from `ds=1` rows (Q3) |
| Sends to the parent | the one tdns delegation syncher. The rollover engine's pushes move into it (DS engine design, step 2) | the same syncher, on the node that may send |
| May send now | tdns: always, for its own zones | tdns-mp: parentsync=agent and the elected leader, through a gate on the syncher, not a second syncher (Q2) |

**Consequences for tdns-mp:**
- Its `DelegationSyncher` shrinks to the leader gate.
- The combiner stops synthesizing CDS.
- `notifyPeersParentSyncDone` stays if anything starts to act on it; nothing does today.

---

## 5. What tdns-mp's state machine takes over

1. **Standby keys per the zone's policy:** zero or more, and when to mint.
2. **Timers:** published → standby once the DNSKEY RRset has propagated, and the withdrawal margin before a key leaves the RRset.
3. **Rollover scheduling from the ZSK and KSK lifetimes,** for ZSK and KSK in multi-provider form.
4. **Real gates on the way in:**
   - mpdist → published only when every signing provider has applied the key. That replaces "any confirmation".
   - published → standby only when the DNSKEY RRset has propagated.
   - Only a standby KSK gets `ds=1`.
   - Only a standby key is promoted to `sign=1`.
5. **Withdrawal:** set `ds=0`, wait for the parent, set `sign=0`, keep `include=1` for the margin, ask tdns to strip the key's RRSIGs, set `include=0`.
6. **Foreign rows** that record the provider and the provider's state for the key, so `ds` can follow D4.
7. **The DS set for the zone** (D4), handed to the syncher on the node that may send.

**Protocol change.** Today DNSKEYs travel between providers as bare records: no provider identity and no state (`hsyncengine.go:62-73`). Foreign rows store neither (`signer_keydb.go:328`). Only a signer and its own agent exchange key states (the key inventory). D4 needs each provider's DNSKEYs to carry, per key, the provider and either its state or its `ds` intent. This is a change to what goes on the wire between providers; §7 Q9. Agreed 2026-09-13: it must be fixed.

**tdns-mp code that becomes the owner's answers:**

| Answer | Closest code today |
|---|---|
| include | `LocalDnskeysFromKeystate` (`hsync_utils.go:192-283`), `syncForeignDNSKEYs` (`signer_keydb.go:265-352`) |
| sign | `canPromoteMultiProviderMP` (`signer_keydb.go:199-216`), `countOwnKeysOfRole` (`:121-132`) |
| ds | none today. Ingredients: HSYNCPARAM signers (`hsync_utils.go:1072-1170`) and each signer's key inventory |
| may send now | `IsLeader` (`parentsync_leader.go:694-711`), the all-peers-operational rule (`start_agent.go:139-148`), parentsync=agent |

---

## 6. Staging

Each step builds, passes tests and leaves the system working.

| Step | Repo | Change | Behaviour |
|---|---|---|---|
| S1 | tdns | Columns, the one write function, backfill of include and sign from state; readers switch (§3.3). tdns-mp's states get their flags from a temporary table registered by tdns-mp, not named in tdns. | Unchanged, except CDS synthesis now follows `ds` |
| S2 | tdns | The per-zone ownership marker, the lifecycle skips and the API refusals (§3.5). No zone claims ownership yet. | Unchanged |
| S3 | tdns-mp | Its own policy-driven state machine, writing state and flags. It claims ownership of multi-provider zones and stops registering the hooks. | The key management of multi-provider zones moves to tdns-mp |
| S4 | tdns | Delete the hooks, the multi-provider constants and state names, the multi-provider DS intent cases and `DSModelMultiProvider`. | Unchanged |
| S5 | tdns-mp | Provider and state on DNSKEY distribution; foreign rows with provider and state; the DS set (D4); CDS from the rows; the leader gate on tdns's syncher. The combiner stops synthesizing CDS. | Multi-provider DS towards the parent works as D4 says |
| S6 | tdns | DS engine design step 2: the rollover engine's parent pushes move into the syncher. | Independent of S1–S5 |

S3 is the large step. It can land behind a per-zone switch, so one test zone moves to tdns-mp's machine before all multi-provider zones do.

---

## 7. Open questions

| # | Question | Recommendation |
|---|---|---|
| Q1 | Which DNSSEC policy fields does tdns still apply to an owned zone? | Signature validity, TTLs and the clamp's signature parameters are mechanism: tdns applies them. Algorithms, lifetimes, standby counts and the rollover method are the owner's. |
| Q2 | For a multi-provider zone, does tdns's syncher send DS on its own, or only when tdns-mp's gate allows? | Only through the gate: parentsync=agent and the elected leader. tdns-mp's syncher shrinks to that gate. |
| Q3 | Which process publishes a multi-provider zone's CDS? | The signer. It holds the rows: own keys and foreign rows. Today the combiner synthesizes CDS from a DNSKEY set that lacks the provider's own keys. |
| Q4 | Which keystore API verbs work on an owned zone? | The store verbs (add, generate with an explicit state and flags, delete, purge) work. The lifecycle verbs listed in §3.5 are refused. |
| Q5 | How is `ds` backfilled for existing rows? | Leave it `NULL` until the zone's owner writes it; readers treat `NULL` as unknown. For tdns zones, the first key state worker or rollover pass fills it in. |
| Q6 | Does the multi-DS scheme (DS placed before the DNSKEY, state ds-published) apply to multi-provider zones? | Not in this design. A multi-provider KSK gets its DS at standby, once every provider's DNSKEY RRset carrying it has propagated. Multi-DS across providers would first need the providers to agree on a shared DS pipeline. |
| Q7 | Who strips a departing key's RRSIGs? | The owner decides when; tdns exports the strip and the resign trigger. |
| Q8 | Is `OnStateChange` still needed? | No. tdns-mp makes its own transitions and knows when state changes. API writes to owned zones are limited to store verbs (Q4); if an inventory push is wanted after those, tdns-mp's API wrapper does it. |
| Q9 | How does the protocol change in §5 reach providers that run an older tdns-mp? | Add fields to the DNSKEY distribution payload; older receivers ignore unknown JSON fields. The `ds` column cannot follow D4 for a provider that does not send them yet. Such a provider's keys get `ds=NULL` and block the DS set, rather than being guessed. |
