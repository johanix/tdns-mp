# B-MP: tdns-mp on tdns's snapshot model — implementation plan

**Date:** 2026-09-11
**Status:** plan. Nothing here is implemented.
**Basis:** tdns `main` at `fe83b216` (#514 merged 2026-09-11 20:08 UTC) and
tdns-mp `fix/modern-repin` at `a8e1e50` (#43). The first two versions of this
plan were written against `d1eec102`, the pin of #43; anchors below are kept
where the code did not move and restated where #514 moved it. Line numbers
drift; re-locate by symbol.
**Reads with:** tdns `docs/2026-07-02-DONE-zone-mutation-snapshot-correctness.md`
(the model; its §9 defined B-MP and is corrected below), the re-pin trial
review of 2026-09-10 (§G) and the deployment log of 2026-09-11, both in the
project's `reviews/` directory.
**Amended the same evening:** §2.4 evaluates making tdns-signer the core of
tdns-mpsigner, as Johan asked after the first version, and the
recommendation for the key seam changed to it (§0, §4, §6 Q2 updated).
**Amended again, late the same day, for two events:** tdns merged #514
(publish signs the staged content before the swap, a signing zone is Ready
only on a signed apex SOA, `SetupZoneSigning` and `NotifyDownstreams` are
gone, `SignZone` takes a context), and an external review of this PR arrived
(`reviews/2026-09-11-tdns-mp-PR44-bmp-snapshot-plan-review.md`, checked
against `fe83b216`). §1.2, §1.4, §2.1–2.4, §3, §4, §5 and §6 are updated; §8
records what was taken from the review and where this plan differs from it.
**Re-reviewed at `4dfdcaf`** (`reviews/2026-09-11-tdns-mp-PR44-bmp-snapshot-plan-rereview.md`):
"this is the working plan"; its five leftovers are applied here (§8).
**Supersedes:** §9 of the 2026-07-02 doc. Its claim that `MPZoneData` gets the
staging receivers "for free" by embedding is wrong: they are unexported and do
not promote across packages. T-A below carries the dated amendment.

## 0. Summary

tdns-mp compiles and runs against tdns main (#43), but it still writes zone
data the way it did before tdns moved to an immutable published snapshot.
Every such write is now either lost or lands in the wrong place, and two
runtime workarounds in #43 paper over two reads that broke for the same
reason. This plan moves every tdns-mp write onto tdns's staging and publish
API, makes tdns's own signing loop serve multi-provider zones, and removes the
workarounds by fixing their causes in tdns.

Three small tdns PRs come first, then two tdns-mp PRs, then the test rigs:

| PR | what | size |
|---|---|---|
| T-A | export the analysis readers, a draft-aware staging API with a batched stage-and-publish, `CloneRRset`, `StopPublisher` | ¾ day |
| T-B | a first load runs its post-refresh callbacks once the zone is Ready (for a signer: once its SOA is signed) | ½ day |
| T-C or T-S | the key seam: a per-zone key source (§2.3) **or** MP keys in tdns's keystore with three states and lifecycle hooks, generation included (§2.4, recommended) | 1 day / 1½–2 days |
| M-1 | re-pin of the combiner, agent and auditor only; readers, combiner staging, gate, both workarounds deleted | 2 days + lab |
| M-2 or M-2S | the mpsigner's re-pin, and its first past #514: through the key source (M-2) or with the signer fork retired and its keys migrated (M-2S, recommended) | 1 day / 2–3 days + lab |
| R-1 | the multi-host rig gains data-path assertions | 1 day |
| R-2 | `mp-policy-matrix` gains signature validation and a DNSKEY roll | ½ day |

The decisions Johan is asked to make are in §6. The two that shape the code
are the first-load ordering (§2.2, recommended: defer the callbacks) and the
key seam (§2.3 and §2.4, recommended: retire tdns-mp's keystore fork and let
tdns's signer core carry multi-provider zones).

## 1. What is wrong on tdns main today

All four items are read from the code. Items 1 and 2 were seen in the lab and
are worked around in #43; items 3 and 4 have not been observed because the
multi-host rig asserts only communications. Item 4 goes further than the
trial's §G, and #514 made items 2 and 4 worse than the first version of this
plan said.

### 1.1 Pre-refresh reads of the incoming zone (worked around by `802f0c5`)

`FetchFromUpstream` and `FetchFromFile` hand the freshly transferred or parsed
zone to the `OnZonePreRefresh` callbacks as `new_zd`: `Data` populated,
`Ready` set true (`zone_utils.go:990`, `:639`), no snapshot. `GetOwner` passes
its `Ready` gate and reads `publishedSnapshot()`, which is nil, so it returns
`(nil, nil)`; `GetRRset` panics at a nil apex. Every read `MPPreRefresh` makes
of `new_zd` through the promoted methods — `HsyncChanged`,
`LocalDnskeysChanged`, `populateMPdata` and its helpers — saw an empty zone.

tdns has the same problem for its own delegation-sync analysis and solved it
with the unexported `ownerForAnalysis` / `rrsetForAnalysis`
(`zone_snapshot.go:388`, `:413`): published snapshot if there is one, else
`Data`. #43 copies that as a shadow of `GetOwner`/`GetRRset` on `MPZoneData`
(`mpzonedata.go`) plus `incomingRRset` (`hsync_utils.go:37`).

### 1.2 First-load ordering (worked around by `cd25d27`)

On a first load the sequence is: pre-refresh callbacks →
`applyRefreshReplacementLocked` publishes the snapshot but sets `Ready` only
`if !firstLoad` → post-refresh callbacks → `completeFirstZonePolicyAndLoad`
→ `InstallInitialSnapshot` → policy sync → `signOnceAfterPolicyBind` →
journal replay → `OnFirstLoad` (`refreshengine.go:384`, after #514).

Where `Ready` flips depends on the zone. After #514 a zone is Ready only on a
servable snapshot (`markReadyIfServableLocked`,
`snapshotContentIsServableLocked`): any snapshot for a zone that does not
sign its own content, one whose apex SOA carries an RRSIG for a zone that
does. A combiner's zones therefore become Ready at `InstallInitialSnapshot`.
A signer's do not: the first-load publish cannot sign because the policy is
not bound yet, `InstallInitialSnapshot` finds an unsigned SOA and leaves
`Ready` false, and the flip happens inside the publish that
`signOnceAfterPolicyBind` → `SignZone` makes, after the policy sync. The
first-load post-refresh callbacks run before all of that in both cases.

So the post-refresh callbacks of a first load run against a zone that HAS a
published snapshot and is NOT Ready. `GetOwner` refuses with
`ErrZoneNotReady`. tdns-mp's `PostRefresh` applies the HSYNC diff there;
`ApplyHsyncDiff` reads the participant set through the zone view
(`hsync_bridge.go:158`, `:171` → `GetOwner`), finds nothing, and with
`GateOnLocalPresence` returns having registered nobody. `RecomputeGroups`
skips non-Ready zones (`provider_groups.go:221`). Later refreshes carry no
HSYNC change, so nothing recomputes; peers waited for the 60 s reconcile and
provider groups were never built. #43 adds an `OnFirstLoad` callback on the
agent that calls `ReconcileZone` and `RecomputeGroups` (`start_agent.go:198`);
the auditor already had one (`start_auditor.go:111`).

The deferral of `Ready` on a first load is deliberate: `Ready` means "complete
content", and a to-be-signed zone must not serve or transfer before its first
`SignZone` (tdns `docs/2026-07-13-unsigned-publish-window.md`; #514 closed
that window, C1 in `docs/2026-09-05-signing-publish-notify-correctness.md`).
The defect is not the deferral, it is that one class of callback runs on the
wrong side of it.

### 1.3 Combiner writes after load go nowhere

`CombineWithLocalChanges` (`combiner_utils.go:112`), `InjectSignatureTXT`
(`:699`), `restoreUpstreamRRset` (`:753`) and `cleanupRemovedRRtype` (`:790`)
write `mpzd.Data`. After a load `Data` is neither the working set nor the
snapshot: `applyRefreshReplacementLocked` builds the working set from
`new_zd.Data` and publishes it; `publishSync` (what `BumpSerialOnly` is) seeds
the next working set from the published snapshot. Whatever these functions
wrote is not in either.

The paths that reach them, and where each publishes today:

| path | entry | publishes via |
|---|---|---|
| start-up combine after hydrating contributions | `config.go:173` (`OnFirstLoad`) | nothing |
| incoming update from an agent (add / delete / ops) | `combiner_chunk.go:1100`, `:1129`, `:1060` → `CombinerProcessUpdate` | `BumpSerialOnly` `combiner_chunk.go:1199` |
| CDS / CSYNC synthesis on delegation change | `combiner_chunk.go:482`, `:496` | `BumpSerialOnly` `:506` |
| `_signal` KEY into a provider zone | `combiner_chunk.go:725`, `:854` | `BumpSerialOnly` `:731` |
| KEY replace on key inventory | `combiner_chunk.go:592`, `:620`, `:622` | caller-dependent — verify |
| CLI-originated contribution | `apihandler_combiner.go:56` | verify |
| reapply from the database | `CombinerReapplyContributions` | `BumpSerialOnly` `combiner_utils.go:927` |
| purge by origin | `apihandler_combiner.go:441` → `PurgeContributionsForOrigin` | verify |
| pre-refresh combine on `new_zd` | `hsync_utils.go:1398` | the refresh publish consumes `new_zd.Data` — **this one works** |

Only the last row is served. On a cold start the first pre-refresh combine has
no contributions yet (they are hydrated in `OnFirstLoad`, `config.go:152`),
so a combiner serves the upstream zone unmodified until the next refresh.

Two side effects of the same model change. Publish NOTIFYs downstreams
itself, and after #514 it is the only thing that does (C2; `NotifyDownstreams`
no longer exists), so the explicit `go zd.NotifyDownstreams()` at
`apihandler_combiner.go:215` and `combiner_msg_handler.go:287` notified twice
on `d1eec102` and do not compile at the next re-pin (tdns-mp#46). And
`InjectSignatureTXT` appends onto `existing.RRs` obtained from a served owner,
which is the §1.4 aliasing the model forbids.

### 1.4 The signer signs the served snapshot in place, and publish re-signs the SOA with the wrong keys

`MPZoneData.SignZone` (`mp_signer.go:27`) is a copy of tdns's pre-snapshot
loop: it iterates `GetOwner` (the published snapshot), signs each RRset and
writes it back with `owner.RRtypes.Set` (`:142`) — into the live snapshot's
`RRTypeStore`, which `GetOwner` shares by pointer. Then `BumpSerial` (`:151`)
publishes. Readers see RRSIGs appear mid-serial; the delta diff compares
identical pointers, so the IXFR chain records nothing for the re-sign (§G).

Tracing one call on tdns main shows it is worse than that:

1. `EnsureActiveDnssecKeysMP` ends by calling tdns's `PublishDnskeyRRs(dak)`
   (`signer_keydb.go:630`), which stages a DNSKEY RRset into a working set
   that nothing publishes. The apex in that working set is now a fresh clone.
2. `zd.GenerateNsecChainWithDak(dak)` (`mp_signer.go:57`) stages NSECs into
   the same working set — without `zd.mu`, which tdns's callers hold.
3. `mpzd.PublishDnskeyRRs` (`:86`) writes the merged DNSKEY set, foreign keys
   included, into the **snapshot's** apex (`:356`), not the working-set clone.
4. The loop signs the snapshot's owners in place; for the apex that is again
   the snapshot's store, not the clone.
5. `BumpSerial` → `publishSync` → `publishWorkingSetLocked`: the working
   set's apex clone (step 1's DNSKEY set, unsigned RRsets) replaces the apex
   that steps 3 and 4 wrote. Before the swap, publish resolves its signing
   material through `resolveSigningMaterialLocked` →
   `zd.EnsureActiveDnssecKeys(zd.KeyDB, true)` (`zone_mutation.go:965` after
   #514). That is tdns's keystore, `DnssecKeyStore`, which holds no keys for
   an MP zone (they are in `MPDnssecKeyStore`), so with `zd.DnssecPolicy`
   bound it **generates a KSK and ZSK in the tdns keystore**, stages a DNSKEY
   RRset of those keys, and signs the whole staged scope with them
   (`signStagedScopeLocked`). Before #514 the same call re-signed only the
   SOA.

Expected served result after one `SignZone` on tdns main: a zone signed
throughout by tdns-minted keys that no agent knows and no other signer has
been told about, with a DNSKEY RRset of those keys and none of the MP or
foreign keys. Its apex SOA is signed, so it is Ready: it answers queries and
transfers out. Before #514 the apex stayed unsigned and the zone was bogus in
a way every validator would see; after #514 it validates against the wrong
keyset, which is worse. If key generation fails instead (an MP policy the
tdns generator refuses), the publish is refused and the zone stays not Ready.
The same path runs on every refresh of a signer zone with no MP code involved
at all: `applyRefreshReplacementLocked` stages a full sign and the refresh
publish resolves keys the same way. D0 (§5.3) is the assertion, and the
consequence for sequencing is in §4: no mpsigner re-pins onto a tdns with
#514 before the key seam has landed.

The trial's §G asked tdns to export a `dak`-taking staged `SignZone` and a
`PublishDnskeyRRs` that accepts foreign keys. Those two exports would fix
steps 1–4 and leave step 5 in place: the signing pass lives inside publish
and resolves keys on its own. The fix has to be a key seam: either tdns asks the zone for its keys
(§2.3) or the zone's keys live where tdns already looks (§2.4).

### 1.5 Mutator inventory at `b955faf`

tdns's gate (`utils/Makefile.common` `check-no-mutators`, pattern
`\.(RRtypes\.Set|Data\.Set)\(`) over `tdns-mp/v2` and `cmd`: 21 hits, none in
`cmd`. Re-verified; §G's classification holds.

| served zone — move to staging (§3.1) | MP-private — keep, mark (§3.4) |
|---|---|
| `mp_signer.go:142` (sign loop), `:356` (DNSKEY apex) | `agent_policy.go:34` (`AgentRepo.Data`, keyed by agent id) |
| `combiner_utils.go:163`, `:165`, `:170` (`CombineWithLocalChanges`) | `agent_policy.go:310`, `:337`, `:393`, `:423`, `:508` (agent repo owner records) |
| `combiner_utils.go:746`, `:747` (`InjectSignatureTXT`) | `syncheddataengine.go:52`, `:1412` (SDE node records) |
| `combiner_utils.go:762`, `:763` (`restoreUpstreamRRset`) | `hsync_utils.go:657` (SDE reconcile), `:1242` (`UpstreamData` snapshot) |
| `combiner_utils.go:807` (`cleanupRemovedRRtype`) | `combiner_utils.go:987` (`CombinerData` rebuild) |

The MP-private ones write `OwnerData` values that live in `AgentRepo`,
`ZoneDataRepo`, `CombinerData` and `UpstreamData` — maps tdns-mp owns, never
reachable from a published snapshot (`snapshotUpstreamData` copies the RR
slices; `RebuildCombinerData` builds fresh). They match the pattern because
they reuse tdns's `OwnerData` type and one of them names its field `Data`.

## 2. tdns side

Three PRs, each reviewable alone. T-A and T-B unblock M-1; the key seam
(T-C in §2.3, or T-S in §2.4, the recommended one) unblocks M-2.
Every tdns change here is app-neutral: tdns-auth's behaviour does not change
unless a caller opts in (a key source set, a callback registered). Anchors in
this section are post-#514.

### 2.1 T-A — analysis readers, draft-aware staging, `StopPublisher`

**Exports.** In `zone_snapshot.go`, `OwnerForAnalysis(qname)` and
`RRsetForAnalysis(qname, rrtype)`: rename the two existing functions and keep
the unexported names as one-line wrappers, or vice versa; the bodies do not
change. Contract, from the existing comment: the published snapshot wins
where it exists; `Data` otherwise; never a panic at a missing apex. This is
the reader for anything that runs on both a live zone and a draft.

**Staging.** In `zone_mutation.go`:

```go
// StageRRset replaces one RRset of one owner in the zone's next content.
// On a zone with a published snapshot it stages into the working set under
// zd.mu, cloning rs. On a draft -- a zone that holds content in Data and has
// published nothing, which is what the OnZonePreRefresh callbacks receive --
// it writes Data, which the refresh publish consumes. Either way the served
// snapshot is untouched until the next publish.
func (zd *ZoneData) StageRRset(name string, rs core.RRset)
func (zd *ZoneData) StageDelete(name string, rrtype uint16)
func (zd *ZoneData) StageOwnerDelete(name string)
```

Draft detection is `zd.publishedSnapshot() == nil`, the same test
`ownerForAnalysis` makes. The draft branch writes through `Data.Set` with a
cloned RRset (the fresh-alloc rule holds for drafts too: MP's RRsets alias
MP-private stores). The live branch is `zd.mu.Lock(); stageRRsetLocked(...)`.
`StageOwnerDelete` exists for `cleanupRemovedRRtype`: an owner whose last
RRtype goes must leave the working set, or it publishes as an empty owner
(compare `stageOwnerDeleteLocked` callers in `nsec_restitch.go`).

**One lock across a logical change (review A4).** The three calls above take
`zd.mu` per call and drop it. `CombineWithLocalChanges` stages several RRsets
and then publishes; a refresh of the same zone arriving between two of its
calls replaces the working set (`applyRefreshReplacementLocked`) and
publishes on its own, so the combiner's trailing publish then republishes
content the refresh already served, one serial later. The contributions
survive, because the pre-refresh combine re-applies `CombinerData`; "exactly
one serial per accepted edit" (D1) does not. So T-A also exports a batched
form:

```go
// Stager is what StageBatch hands its callback: staged writes, and reads of
// the zone's next content (current including pending), all under zd.mu.
type Stager interface {
    RRset(name string, rrtype uint16) *core.RRset   // next content; nil when absent
    SetRRset(name string, rs core.RRset)
    Delete(name string, rrtype uint16)
    DeleteOwner(name string)
}
// StageBatch runs fn with zd.mu held and publishes once if fn reports a
// change. On a draft it writes Data and publishes nothing. fn must not call
// anything that takes zd.mu.
func (zd *ZoneData) StageBatch(fn func(s Stager) (changed bool, err error)) (BumperResponse, error)
```

`RRset` reads the zone's next content. On a live zone the working set is
nil between publishes, so a literal read of it would return nothing for
every existing RRset and the combiner's merge would be wrong (re-review L2):
`RRset` first seeds the working set from the published snapshot
(`ensureWorkingSet`, exactly what `stagedOwner` does) and reads that, so a
pass sees the served RRsets and its own earlier writes. On a draft it reads
`Data`. The read-then-stage race two concurrent combines would otherwise
have through `RRsetForAnalysis` goes with it. The per-call `Stage*`
functions stay for one-record changes.

**`CloneRRset`.** Export `cloneRRset` (review C1): the one-line way to build
a new RRset from a served one before appending, which is what
`InjectSignatureTXT` must do.

**Publish.** `BumpSerialOnly()` already is `publishSync()`: one serial, one
snapshot, one delta, one NOTIFY. It stays the publish call for the per-call
form; `StageBatch` publishes through the same function. Optionally add
`Publish()` as a second name so MP code reads as what it does; not required
(§6, Q6).

**`StopPublisher()`.** Export `stopPublisher` for external test harnesses
(trial item F: tdns-mp's transport harness leaks one publisher goroutine per
seeded zone).

**Doc.** Append a dated amendment to §9 of the 2026-07-02 doc: receivers do
not promote; the exported surface is the above; B-MP is this plan.

**Tests.** `TestStageOnDraftWritesData` (Data populated, no snapshot: stage,
read back through `RRsetForAnalysis`, `InstallInitialSnapshot`, served);
`TestStageOnLiveZoneLeavesSnapshot` (the exported `StageRRset` obeys
`TestSnapshotImmutability`'s assertion); `TestAnalysisReadersPreferSnapshot`;
`TestStageBatchOneSerial` (a batch of three writes publishes once; a batch
reporting no change publishes nothing; a refresh started during the batch
publishes after it).

**Size and risk.** ~180 lines plus tests. No behaviour change for existing
callers.

### 2.2 T-B — a first load's post-refresh callbacks run once the zone is Ready

This is the part Johan asked to have sorted out cleanly. Three ways to do it
were weighed.

**O1 — defer the callbacks (recommended).** In `FetchFromUpstream` and
`FetchFromFile`, when `firstLoad`, record that post-refresh callbacks are
owed instead of running them (`zd.postRefreshOwed = true`, under the `zd.mu`
already held around `applyRefreshReplacementLocked`). Run them once the zone
is Ready, and only then: in `completeFirstZonePolicyAndLoad` and in its
retry twin `finishFirstLoadPolicy`, after `signOnceAfterPolicyBind` returns
nil and the journal replay has run, before the `OnFirstLoad` drain, guarded
by `zd.Ready`. The flag clears on that run and on no other path. Every later
refresh is unchanged.

- The callbacks then run at the moment the zone becomes Ready, which is the
  moment a non-first refresh's callbacks correspond to. The asymmetry is
  gone for every consumer, not patched in one.
- After the sign, not after `InstallInitialSnapshot`. The first version of
  this plan put the drain right after Install; the review (A6) is right that
  on post-#514 `main` a signer's zone is not Ready there (§1.2), so
  `GetOwner` would still refuse and `ApplyHsyncDiff` still register nobody.
  A combiner's zones are Ready at Install and would have worked by accident.
  After `signOnceAfterPolicyBind` covers both, and a failed sign leaves the
  flag owed for the ticker retry, which runs the same tail.
- tdns's own two post-refresh consumers are enqueue-only and idempotent:
  `ProxyDelegationPostRefresh` (`delsync_proxy.go:175`) enqueues PROXY-SYNC
  from an analysis computed pre-flip; `ChildSyncProxyPostRefresh`
  (`childsync_proxy.go:279`) reconciles in memory and enqueues. Running them
  a few milliseconds later, on the engine goroutine they already run on for
  a first load, changes nothing they depend on.
- ~40 lines. One test, run twice: register a post-refresh callback,
  first-load a zone from file, assert the callback saw `Ready == true` and
  `GetOwner` succeed; once on an unsigned zone, once on a signing zone with a
  bound policy, where the callback must run after the sign.
- After the replay, not before it (re-review L4). A later refresh reconciles
  the journal and then runs its post-refresh callbacks (`FetchFromFile`), so
  the first load keeps that order, and a change that only the journal holds
  is visible to the callbacks. `finishFirstLoadPolicy` has no replay, so
  there the drain follows the sign directly.
- T-B changes when the callbacks run, not what Ready means. #514's rule that
  a signing zone is Ready only on a signed apex SOA stays (review B3); that
  rule is also why O2 below is rejected.

**O2 — gate `GetOwner` on `HasPublishedData()` instead of `Ready`.** Smallest
diff, and it would make 1.2 disappear without reordering anything. Rejected:
`Ready` on `GetOwner` is what keeps a to-be-signed zone's unsigned first
snapshot from being read before `SignZone` (1.2, the 07-13 doc); the query
and transfer paths reach zone data through `GetOwner`/`GetOwnerNames`.
Relaxing it reopens the window the deferral closes.

**O3 — tdns-mp reads a not-Ready zone on purpose.** Make the hsync zone view
and `RecomputeGroups` read through `OwnerForAnalysis` and drop the `Ready`
gate in tdns-mp. No tdns change beyond T-A. Rejected as the primary fix: it
leaves tdns's first load running one class of callback before Ready for
every other consumer, and it has tdns-mp act on a zone tdns says is not
ready. Kept as the fallback if O1 turns up a consumer that needs the old
order.

After T-B, `cd25d27` is deleted whole and the auditor's `OnFirstLoad`
`RecomputeGroups` (`start_auditor.go:111`) becomes redundant; M-1 removes it
too, so there is one mechanism.

### 2.3 T-C — a per-zone key source

The signer needs tdns to sign with keys tdns's keystore does not hold, and
to publish a DNSKEY RRset tdns's keystore does not describe (pre-published
MP keys, foreign keys in multi-signer mode). Every place tdns resolves keys
must ask the same seam: `EnsureActiveDnssecKeys` (called by `SignZone`,
`ResignZone`, `SignRRset` with a nil `dak`, and after #514 by
`resolveSigningMaterialLocked` inside every signing publish),
`publishDnskeyRRsLocked` (the DNSKEY RRset at sign time) and
`CollectDynamicRRs` (the DNSKEY RRset at refresh time; the comment in
`ops_dnskey.go` explains why those two must agree).

**K2 — an interface on `ZoneData` (recommended).**

```go
// ZoneKeySource supplies the keys a zone signs with and the DNSKEY RRset it
// publishes. nil selects the keystore, which is what every zone has today.
type ZoneKeySource interface {
    // ActiveKeys returns the active KSKs and ZSKs, creating or promoting
    // keys as the source sees fit. Called with zd.mu held when locked is
    // true; it must not call back into any zd publish path.
    ActiveKeys(zd *ZoneData, locked bool) (*DnssecKeys, error)
    // DnskeyRRs returns every DNSKEY the zone publishes: the active set plus
    // whatever else the source wants served (pre-published, retired,
    // foreign). Order and duplicates are the caller's problem.
    DnskeyRRs(zd *ZoneData, active *DnssecKeys) ([]dns.RR, error)
}
func (zd *ZoneData) SetKeySource(ks ZoneKeySource)
```

Wiring, four sites:

- `EnsureActiveDnssecKeys`: after the option check, `if ks := zd.keySource;
  ks != nil { dak, err := ks.ActiveKeys(zd, zdLocked); store dak into
  zd.signingKeys as a built snapshot; return }`. Storing it keeps the
  lock-free hot path (`ActiveDnssecKeys()`, `sign.go:276`) consistent with
  what the source said, without a DB call on that path.
- `publishDnskeyRRsLocked` and `CollectDynamicRRs`: `if ks != nil {
  publishkeys, err = ks.DnskeyRRs(zd, dak) } else { today's keystore query }`.
- `reconcileActiveKeyAlgorithms`, promotion and generation are skipped when a
  source is set: the source owns its keys' lifecycle.

`SignZone(ctx, kdb, force)` keeps its signature; `kdb` is still needed for
the TTL clamp and `UpsertZoneSigningMaxTTL`, and `HsyncDB` embeds
`*tdns.KeyDB`, so tdns-mp passes `hdb.KeyDB`.

**Startup order (review A5).** The source must be set before the zone's
first refresh. `CollectDynamicRRs` runs before the pre-refresh callbacks
(`zone_utils.go:123`), so a source installed from `MPPreRefresh` is one
refresh late and the first publish mints. Install it from the
`multi-provider` zone-option handler, which fires during `ParseZones` once
the zone is registered and before its first refresh. The handler receives
the zone name and its options, not the zone (`ZoneOptionHandler`,
`option_handlers.go`), so it looks the zone up with `Zones.Get(zname)`. One
site, and the only one (re-review L1).

**K1 — install keys into the signing-keys snapshot, plus a DNSKEY hook.**
Export `InstallSigningKeys(dak)` (store a built `signingKeysSnapshot`) and a
`SetExtraDnskeyRRs(func() []dns.RR)` for the RRset composition. Smaller
diff. Rejected: two implicit seams instead of one explicit one, and the
snapshot is rebuilt from the tdns keystore by `refreshActiveDnssecKeys` and
`republishSigningKeys` on paths that are hard to prove an MP zone never
reaches (`reconcileActiveKeyAlgorithms` for one). K2 makes "a source is set"
a single test at every site.

**Not enough — §G's two exports alone.** See 1.4: they leave the SOA re-sign
inside publish resolving keys from the keystore.

**Tests.** `TestSignZoneWithKeySource`: a fake source with fixed keys and two
extra DNSKEYs; `SignZone`; assert the served DNSKEY RRset equals
`DnskeyRRs`, every RRSIG (SOA included, i.e. through the publish re-sign)
verifies against it, and `DnssecKeyStore` has no row for the zone.
`TestRefreshKeepsSourceDnskeys`: reload from file; `CollectDynamicRRs`
republishes the source's set.

**Size and risk.** ~150 lines plus tests. Touches the signing core; the
CodeRabbit hour matters here. Behaviour for a zone without a source is
identical, which the existing signing tests already pin.

### 2.4 The tdns-signer alternative: retire the signer fork instead of feeding it

Johan's question, after the first version of this plan: tdns now has
`tdns-signer`, snapshot-aware and compliant; can it be adapted, as in
extended, to be the internal core of `tdns-mpsigner`, so that the signer's
complexity is reused rather than re-implemented? Evaluated here against §2.3.

#### 2.4.1 What tdns-signer is

`cmdv2/signer/main.go` is tdns-auth built as a second binary: ~90 lines that
set `AppTypeAuth`, call `MainInit`, `SetupAPIRouter`, a SIGHUP watcher and
`StartAuth`. It adds nothing to `v2/`; a bump-on-the-wire signer is a
`type: secondary` zone with `inline-signing`, which tdns-auth has always
supported. Its only substance of its own is `algs.list`, from which
`tdns-genalgs` generates the algorithm registrations.

So "the core of tdns-signer" is `tdns/v2`, and `cmd/mpsigner/main.go` is
already the same skeleton: the same four calls, with `StartMPSigner` in place
of `StartAuth` (a hand-picked subset of the same engines plus the MP ones,
`start_signer.go:23`) and a hand-written algorithm `init()` in place of
genalgs. Go cannot import a `main` package, and tdns cannot import tdns-mp,
so "extend tdns-signer" can only mean one of two things: give `tdns/v2` the
hook points the MP signer needs so that tdns-mpsigner differs from
tdns-signer by nothing but its `multi-provider:` block, or move tdns-mp into
tdns, which is out of scope. The rest of this section is about the first.

#### 2.4.2 Where tdns-mpsigner forks the core today

Everything below is a copy of something in `tdns/v2`, taken when tdns-mp was
split out and not kept current. Sizes at `b955faf`.

| fork | lines | copied from | drift since the copy |
|---|---|---|---|
| `mp_signer.go` `SignZone`, `PublishDnskeyRRs` | 359 | pre-snapshot `sign.go` | everything in 1.4; no occluded-name, delegation, ZONEMD, TTL-clamp or canonical-NSEC handling |
| `mp_resigner.go` `MPResignerEngine`, `SetupZoneSigning` | 140 | `resigner.go` | still honours `service.resign: false`, which tdns removed because it silently let signatures expire; after #514 both the sign-then-enqueue contract and the `chan *MPZoneData` shape copy an API tdns no longer has (`registerForPeriodicResign`, `chan ResignRequest`) |
| `signer_keydb.go` + `MPDnssecKeyStore` (`db_schema_hsync.go:217`) + the cache in `hsyncdb.go` | ~790 | `keystore.go` | a parallel table with the same columns plus `propagation_confirmed(_at)`, three extra states (`mpdist`, `mpremove`, `foreign`), its own cache (the June `KeystoreDnskeyCache`, which tdns replaced with the per-zone signing-keys snapshot) |
| `key_state_worker.go` | 317 | `key_state_worker.go` | no RRSIG strip when a key is removed, no ZSK removal margin from the observed TTL, no `published_at` healing; plus the MP branches (standby keys staged as `mpdist`, retired keys parked as `mpremove`, inventory pushed to agents) |
| `apihandler_keystore.go` `MPDnssecKeyMgmt`, `RolloverKeyMP` | ~520 | `DnssecKeyMgmt`, `RolloverKey` | same commands (list, add, generate, setstate, rollover, delete, clear) over the other table |
| `cmd/mpsigner` algorithm registration (`main.go` init + three tag-gated files) | ~115 | genalgs | codepoints no longer match the registry (trial item E); a DNSKEY mpsigner emits at 200 is a different algorithm to every tdns binary |

About 2,200 lines. What is not a fork, and stays under either alternative:
the HSYNC-driven role (`MPPreRefresh` switching `inline-signing` and
multi-signer mode per zone), `extractRemoteDNSKEYs` (which DNSKEYs in the
incoming zone are another signer's), the KEYSTATE protocol with the agent
(`signer_msg_handler.go`: answer an inventory RFI; on a `propagated` signal
move `mpdist`→`published` and `mpremove`→`removed`; push the inventory when a
state changes), the propagation gate before a key may go active
(`canPromoteMultiProviderMP`, `signer_keydb.go:479`), and the transport
(`signer_transport.go`, `signer_peer.go`, `signer_chunk_handler.go`).

#### 2.4.3 What tdns already does for multi-provider zones

`multi-provider` is a tdns zone option (`OptMultiProvider`), and tdns's key
automation already treats it: `rolloverAutomatedForAllZones`,
`rolloverZsksForAllZones` and `promoteStandbyKskBootstrapAll` skip every
zone that carries it (`ksk_rollover_automated.go`, `zsk_rollover.go`). The
parent-facing machinery, which in a multi-provider setup belongs to the
agent and the combiner, therefore stays inert for MP zones without any new
gate. tdns's worker does not skip them in its generic transitions
(`published`→`standby`, `retired`→`removed`, standby maintenance): those are
exactly the three places where the MP fork's branches would have to go.

#### 2.4.4 The change list under this alternative

**tdns (T-S, replaces T-C).**

- *T-S1, three states.* `foreign` (a DNSKEY published but not generated
  here; no private half; never signs), `mpdist` (staged for pre-publication,
  served, awaiting peer confirmation) and `mpremove` (withdrawn from the
  RRset, awaiting peer confirmation of the removal). `FetchZoneDnskeysSql`
  (`ops_dnskey.go`, shared with `CollectDynamicRRs`) gains `mpdist` and
  `foreign`. `UpdateDnssecKeyStateTx` already passes unknown states through
  its `switch` default; nothing else in tdns names states by list. Zones
  that never use the three see no change.
- *T-S2, key lifecycle hooks.* One registration in the style of
  `RegisterZoneOptionHandler`:

  ```go
  type KeyLifecycleHooks struct {
      // The state a newly staged key starts in: "published" today, "mpdist"
      // for an MP zone. Keys in this state count as "in the pipeline" for
      // standby maintenance.
      StagedState  func(zd *ZoneData) string
      // The state a retired key moves to once its margin has passed:
      // "removed" today, "mpremove" for an MP zone.
      RetiredState func(zd *ZoneData) string
      // Whether a published key may become active now. MP: propagation
      // confirmed by the peers and the DNSKEY TTL elapsed.
      MayPromote   func(zd *ZoneData, keyid uint16) bool
      // Whether EnsureActiveDnssecKeys may mint a key of this role because
      // the active set is short. MP: only for a zone with no key of that
      // role in any state; a zone whose keys are all staged or gated waits.
      MayGenerate  func(zd *ZoneData, role string) bool
      // After every committed state change (the KEYSTATE inventory push).
      OnStateChange func(zone string, keyid uint16, from, to string)
  }
  func RegisterKeyLifecycleHooks(h KeyLifecycleHooks)
  ```

  Consulted at six sites, all in the keystore and the worker:
  `GenerateAndStageKey` (`keystore.go:1315`) for the staged state;
  `maintainStandbyKeys`, whose `OptMultiProvider` skip is lifted and whose
  "already in the pipeline" test becomes `published` ∪ `StagedState(zd)`;
  `transitionPublishedToStandby`, a global walk that reaches MP keys today
  and needs nothing beyond the `OnStateChange` it gets through
  `UpdateDnssecKeyState`, named here so nobody adds a skip;
  `transitionRetiredToRemoved` for the retired state;
  `EnsureActiveDnssecKeys` for `MayPromote` on its published branch and
  `MayGenerate` before either `GenerateKeypair`; and `UpdateDnssecKeyState`
  after its commit. Nil hooks mean today's behaviour. tdns-mp registers them
  in its `MainInit` before tdns's, like the zone-option handlers, so they are
  in place before any refresh.

  `MayGenerate` is the hook the first version of this plan lacked (review
  A1). Without it a zone whose keys were all `mpdist` would have tdns mint an
  active pair beside them on the first signing publish. Today's MP code mints
  in that same situation (`EnsureActiveDnssecKeysMP`, the `len(dak.KSKs) ==
  0` branch after its gate), so the hook does not preserve MP behaviour, it
  tightens it: the bootstrap mint is allowed only for a zone with no keys at
  all, and MP may refuse even that and generate on its own terms. When the
  hook allows it, the key is generated `active`, as today's MP bootstrap
  does; `StagedState` is not on this path, and T-S must not turn the
  bootstrap into an `mpdist` key by accident, because a zone with no active
  key cannot sign at all (re-review L5). Operator paths that also mint
  active keys (the keystore's clear-and-regenerate, the policy reset) stay
  unhooked: they are not the publish path.
  The alternative of keying these branches on `OptMultiProvider` inside tdns
  is smaller but puts the MP protocol's states into tdns; the hooks keep tdns
  ignorant of what `mpdist` means.
- *T-S3, nothing for the propagation columns.* They are MP protocol state;
  they go into an MP-owned side table in `HsyncDB`, keyed by zone and key
  id, so tdns's schema does not change.
- T-A and T-B stay as they are.

**tdns-mp (M-2S, replaces M-2).**

- Keys live in `DnssecKeyStore`, and tdns-mp has no signing code left. The
  first sign of a signer zone is tdns's own: `MPPreRefresh` switches
  `inline-signing` on before the first publish, the policy binds through the
  zone's `dnssecpolicy:`, and `signOnceAfterPolicyBind` signs and flips
  Ready. Every later refresh signs its staged scope in the refresh publish
  (C1). Renewal is tdns's `ResignerEngine`, which `StartMPSigner` already
  runs; tdns registers only zones whose config carries a signing option
  (`parseconfig.go:1496`) and MP enables it dynamically, so MP's
  `OnFirstLoad` sends `ResignRequest{Zd, ResignPeriodic}` on
  `conf.Internal.ResignQ` for each zone it switched on. A key-state change is
  tdns's worker's own `ResignKeyStateChanged`. Deleted whole: `mp_signer.go`
  (`MPZoneData.SignZone`, `PublishDnskeyRRs`) and `mp_resigner.go`
  (`MPResignerEngine`, `SetupZoneSigning`: copies of an API #514 removed).
  Deleted except `GetKeyInventory` and the three propagation functions
  (rewritten over the side table, ~100 lines): `signer_keydb.go`. Also
  deleted: `apihandler_keystore.go`, the MP key cache and the
  `MPDnssecKeyStore` schema. The MP `KeyStateWorker` becomes the hooks
  implementation (~80 lines); the KEYSTATE handler's transitions call tdns's
  `UpdateDnssecKeyState`.
- Foreign keys are found where they arrive. `extractRemoteDNSKEYs` moves
  from the signing loop into `MPPreRefresh`: it reads the incoming zone's
  DNSKEY RRset through `RRsetForAnalysis(new_zd, …)` and writes or deletes
  `foreign` rows through `kdb`; mode 2 keeps no rows, and whatever DNSKEYs the
  upstream carried are dropped by the publish, which rebuilds the RRset from
  the keystore. A refresh collects its dynamic RRs before the pre-refresh
  callbacks (`zone_utils.go:123`), so a foreign key found in this refresh is
  served from the next publish; when the set changed, MP sends
  `ResignRequest{ResignKeyStateChanged}` so that publish is now.
- `tdns-mpcli signer keystore …` becomes tdns's `keystore dnssec` subtree,
  which mpcli already mounts (#36); the signer's `/keystore` route points at
  tdns's handler. Foreign keys then show in the ordinary key listing.
- `cmd/mpsigner` adopts `algs.list` and genalgs like every tdns binary,
  which is the fix trial item E was waiting for.
- *Migration, one-shot and fail-closed.* `migrateHsyncSchema`
  (`db_schema_hsync.go:348`) copies `MPDnssecKeyStore` rows into
  `DnssecKeyStore` (its columns are a superset apart from the two
  propagation ones, which go to the side table), rewrites `keyrr` for the
  codepoint renumbering in the same pass and re-parses every rewritten
  record, compares row counts, renames the old table and keeps it until a
  second start finds nothing to do, and refuses to start on any mismatch. No
  row may arrive as `active` unless it left as `active`; a `foreign` row
  never has a private half. The fleet needs a flag day for the re-pin
  regardless (trial items C and E); this joins it rather than adding one.
- The agent needs nothing: the KEYSTATE inventory carries state names on
  the wire (`mp_wire_payloads.go:222`), and they do not change.

#### 2.4.5 Comparison

| | T-C key source (§2.3) | T-S keystore merge (this section) |
|---|---|---|
| tdns change | ~150 lines; an interface consulted in `EnsureActiveDnssecKeys`, `publishDnskeyRRsLocked`, `CollectDynamicRRs` and stored into the signing-keys snapshot | ~200 lines; two SQL predicates and a hooks struct consulted at six sites in the keystore and worker, the generation gate among them |
| where the tdns change sits | in the signing path | in the keystore and worker; the signing path is untouched |
| tdns-mp change | +150 (the source), −500 (`SignZone`, `PublishDnskeyRRs`, the resigner, which #514 forces out either way); ~1,700 lines of fork stay, each still drifting | +300 (hooks, inventory, foreign-key discovery in the pre-refresh, migration), −2,200 |
| sizing | 1 day tdns, 1 day tdns-mp | 1½–2 days tdns, 2–3 days tdns-mp (review B1) |
| what MP zones gain | tdns's signing loop and publish | the same, plus the signing-keys snapshot, RRSIG stripping on key removal, the ZSK removal margin, algorithm reconciliation, standby maintenance, the tdns CLI, genalgs |
| two key stores in one database | yes, permanently, with two workers over them (as today) | no |
| migration | none | one-shot, on the flag day the re-pin already needs |
| risk | low; nothing existing moves | tdns's generic transitions now run on MP keys, bounded to the six hook sites; the generation gate must be right or 1.4 moves into tdns (review A1); a migration that must be right once |
| fixes item E | no | yes |

#### 2.4.6 What it does not do

It does not make tdns-signer multi-provider aware, and it does not make the
two daemons one binary: tdns cannot depend on tdns-mp. tdns-mpsigner stays a
tdns-mp binary whose main is tdns-signer's plus the MP block; after M-2S the
list of things it does that tdns-signer does not is the list in the last
paragraph of 2.4.2, and nothing else. `AppTypeMPSigner` stays (tdns's
auth-only safety gates stand down for it today, as for any derived app;
tdns#558 is the path to changing that, and it is unrelated to this plan).
`StartMPSigner` keeps its explicit engine list; with the MP worker gone,
the tdns `KeyStateWorker` in that list is the only one.

#### 2.4.7 Recommendation

T-S over T-C. It reuses the part of the signer that is actually complex,
which was the point of the question; it changes tdns outside the signing
path rather than inside it; and it retires forks that are already wrong in
ways the lab has not yet noticed (a removed key's RRSIGs are never stripped;
`service.resign: false` still disables renewal on an mpsigner). The cost is
the migration and a larger tdns-mp diff, both of which coincide with a flag
day that is coming anyway.

The external review agreed with the destination and rejected T-S as first
specified, because its hook list did not reach key generation, standby
maintenance or the published→standby walk (A1–A3). Those are in T-S2 now,
which is the condition the review set for preferring T-S over T-C. T-C
remains the fallback if the flag day is pushed out: it is compatible with a
later T-S, but everything it adds is then deleted.

## 3. tdns-mp side

Two PRs. M-1 re-pins the combiner, the agent and the auditor to the tdns
commit that carries T-A and T-B and does everything except the signer. The
mpsigner does not re-pin until M-2, which needs the key seam: on a tdns with
#514 an mpsigner without it serves a Ready zone signed with minted keys
(§1.4). Splitting keeps each lab run answering one question.

### 3.1 M-1: served-zone sites, one publish per logical change

| site | today | becomes |
|---|---|---|
| `combiner_utils.go:163`, `:165` | `existingOwnerData.RRtypes.Set(rrtype, …)` | `s.SetRRset(ownerName, merged|newRRset)` inside one `StageBatch`; read the current RRset through `s.RRset` instead of `mpzd.Data.Get` |
| `:170` | `mpzd.Data.Set(ownerName, existingOwnerData)` | deleted; staging is per RRset |
| `:746`, `:747` (`InjectSignatureTXT`) | append onto the served TXT slice, `Data.Set` | build the new RRset with `CloneRRset` before appending, `s.SetRRset` |
| `:762`, `:763` (`restoreUpstreamRRset`) | `zoneOd.RRtypes.Set`, `Data.Set` | `s.SetRRset(owner, upstream rrset)` |
| `:807` (`cleanupRemovedRRtype`) | `od.RRtypes.Delete`, `Data.Set` | `s.Delete(owner, rrtype)`; `s.DeleteOwner(owner)` when it was the owner's last type |
| `config.go:173` (start-up combine) | no publish | one `StageBatch` whose callback runs the combine and the TXT injection; publishes when either changed anything |
| `hsync_utils.go:1398` (pre-refresh combine on `new_zd`) | writes `new_zd.Data` and works | the same `StageBatch`, which on a draft writes `Data` and publishes nothing (the refresh publish is the publish) |
| `apihandler_combiner.go:215`, `combiner_msg_handler.go:287` | `go zd.NotifyDownstreams()` after the bump | deleted; the function no longer exists after #514, and publish notifies (tdns-mp#46) |

The rule for every runtime path in the 1.3 table: one `StageBatch` per
logical change, its callback staging everything and returning whether
anything changed. The three rows marked "verify" in 1.3 get theirs if they
lack one. A bare `BumpSerialOnly` on an empty working set still bumps the
serial, so the guard inside the batch is not optional.

Under `StageBatch` a refresh cannot interleave: it waits for `zd.mu`. The
first version of this plan documented the interleaving instead of guarding
it; the review (A4) showed that a refresh arriving between two per-call
stages costs an extra serial, and that D1's exact count would flake in the
lab. Guarded now. The callback must not take `zd.mu` itself, so
`CombineWithLocalChanges` copies what it needs from `CombinerData` under
`mpzd`'s own lock first and stages outside it, as its `OnFirstLoad` caller
already arranges.

M-1 also carries the agent's and combiner's share of the #514 re-pin
(tdns-mp#46): `SignZone(ctx, …)` in `SetupAgentAutoZone`; `SetupZoneSigning`
replaced by a `ResignRequest{Zd, ResignPeriodic}` send **and**
`tdns.ResignerEngine` started in `StartMPAgent`, because today nothing in the
agent reads `ResignQ` and its auto zone is signed once and never renewed
(#46 item 2); and the two `NotifyDownstreams` deletions above.

### 3.2 M-1: readers and the two workarounds

- The pre-refresh analysis helpers read through `OwnerForAnalysis` /
  `RRsetForAnalysis`: `HsyncChanged`, `LocalDnskeysChanged`, `populateMPdata`,
  `matchHsyncIdentity`, `getHSYNCPARAM`, `isServer`/`isSigner`/`isAuditor`,
  `analyzeHsyncSigners` (12 call sites in `hsync_utils.go`). They run on
  drafts (`newMpzd` in `MPPreRefresh`) and on live zones; the reader is right
  for both.
- Delete `802f0c5`: the `GetOwner`/`GetRRset` shadow and `readsData` in
  `mpzonedata.go`, and `incomingRRset`.
- Delete `cd25d27`: the agent's `OnFirstLoad` reconcile-and-recompute
  (`start_agent.go:189–209`). Delete the auditor's `OnFirstLoad`
  `RecomputeGroups` (`start_auditor.go:111–114`) for the same reason.
- The zone view (`hsync_bridge.go`), `RecomputeGroups` and the auditor keep
  `GetOwner`: they read served zones and, after T-B, run when the zone is
  Ready.

### 3.3 M-2: the signer (T-C variant; see §2.4.4 for M-2S)

Either way this is the mpsigner's first re-pin past #514, and either way
`SetupZoneSigning` and `MPResignerEngine` go in it (review A7, tdns-mp#46):
the API they copy no longer exists. Under the recommended T-S the step is
M-2S, listed in §2.4.4: no signing code left in tdns-mp, the keystore fork,
the MP key-state worker and the MP keystore API deleted, the one-shot key
migration. What follows is the step if the key source (T-C) is chosen
instead.

- `mpKeySource{hdb *HsyncDB}` implements `tdns.ZoneKeySource`. `ActiveKeys`
  is `EnsureActiveDnssecKeysMP` minus its final `zd.PublishDnskeyRRs(dak)`
  (`signer_keydb.go:630`; that call is step 1 of 1.4 and goes). `DnskeyRRs`
  is the body of `MPZoneData.PublishDnskeyRRs` (`mp_signer.go:283–349`)
  minus the apex `Set`: active keys, the `MPDnssecKeyStore` rows
  (mpdist/published/standby/retired/foreign), the `RemoteDNSKEYs` merge,
  deduplicated. `SetKeySource` is called once, from the `multi-provider`
  zone-option handler (§2.3), which looks the zone up by name.
- `MPZoneData.SignZone` and `PublishDnskeyRRs` are deleted; tdns signs the
  zone on first load, on every refresh and on renewal exactly as under M-2S
  (§2.4.4, first bullet), asking the source for keys. `extractRemoteDNSKEYs`
  moves into `MPPreRefresh` as under M-2S, keeping `RemoteDNSKEYs` on
  `MPZoneData` for the source's `DnskeyRRs` instead of writing rows.
- `SetupZoneSigning` and `MPResignerEngine` are deleted (Q4, required):
  MP's `OnFirstLoad` sends `ResignRequest{Zd, ResignPeriodic}`, tdns's
  `ResignerEngine` renews. The MP key-state worker stays and sends
  `ResignRequest{Zd, ResignKeyStateChanged}` on a change, with a bounded
  wait instead of today's drop-when-full: after #514 a dropped key-state
  trigger is not repaired by the periodic pass, which renews by age (#46
  item 3).
- Invalidate: every MP key-state change that today calls
  `mpDnskeyCacheDelete` (`signer_keydb.go`) is where the source's answer
  changes; nothing else to do, since tdns asks the source on every sign and
  stores the answer in the signing-keys snapshot (T-C).

Known and unchanged by this plan: a non-signer mpsigner still bumps a zone's
serial it cannot re-sign (`mp-policy-matrix` README, "Known reds"); trial
items C (config keys) and E (codepoints).

### 3.4 The gate

`utils/Makefile.common` gets tdns's target, scoped to `v2` and `cmd`,
excluding `_test.go` and lines carrying the marker `mp-private:`; the root
`Makefile` gets `check: check-no-mutators` and `test` depends on it. There is
no CI in tdns-mp; `make check` before every commit is the discipline, as it
is in tdns.

Each of the 11 MP-private sites keeps its `Set` and gains a trailing
comment naming what it writes, for example
`nod.RRtypes.Set(rrtype, cur) // mp-private: SDE node record, not zone data`.
Per-site rather than a per-file allowlist: the claim sits next to the write,
and a new `Set` in the same file is not covered by accident.

### 3.5 Re-pin

Each of M-1 and M-2 re-pins every `go.mod` (`v2`, five `cmd/*`) to the tdns
commit carrying its prerequisites, by the trial's script (`sed` on every
go.mod + `go mod tidy`; the `replace (...)` block form needs a second pass).
tdns main moves daily; a re-pin that lands a week after its tdns PR pays for
a week of drift. M-1 should merge within days of T-A and T-B; the
2026-07-21 drift recipe is the fallback if it does not. The next re-pin is
onto a tdns with #514: tdns-mp#46 lists its six compile-level edits and the
three that need more than a signature fix; the agent's and combiner's share
is in M-1 (§3.1), the signer's in M-2 (§3.3).

## 4. Order and sizing

| step | depends on | estimate | gate |
|---|---|---|---|
| T-A readers + staging + `StageBatch` + `CloneRRset` + `StopPublisher` | — | ¾ day | tdns tests, `make check` |
| T-B first-load post-refresh deferral, at the Ready flip | — | ½ day | tdns tests, on a signing and an unsigned zone |
| T-C key source, or T-S states + hooks incl. the generation gate (§2.4) | — | 1 day / 1½–2 days | tdns tests incl. signature verification; under T-S also worker tests with hooks set and a "no mint while staged keys exist" test |
| M-1 combiner, agent, auditor: re-pin past #514 (#46's share), readers, combiner `StageBatch`, gate, workarounds out | T-A, T-B merged | 2 days | `make check`, `make test-race`, the multi-host rig's communications checks all green after a cold start and a warm restart, D1 (§5.3). **No mpsigner in this re-pin.** |
| M-2 (key source) or M-2S (fork retired, keys migrated): the mpsigner's re-pin | key seam merged, M-1 merged | 1 day / 2–3 days | lab D0–D4; under M-2S also the migration test |
| R-1 the multi-host rig's data-path assertions | — (written against M-1/M-2 expectations) | 1 day | runs green on M-2 |
| R-2 `mp-policy-matrix` F/G scenarios | the rig's own tdns pin moved to a main with #616 and IMR forwarding, both merged | ½ day | runs green on M-2 |

T-A, T-B and the key-seam PR are independent of each other and can be three
PRs in the same week; CodeRabbit's one review per hour in johanix/tdns sets
the pace. Total about eight working days plus two lab afternoons with T-C,
nine to ten with T-S. Slices over a big bang: each tdns PR is reviewable in
one sitting, and each tdns-mp PR has one lab question to answer. The one
hard ordering rule: the mpsigner does not re-pin onto a tdns with #514 until
the key seam is merged.

## 5. Tests

### 5.1 tdns (in the T-* PRs)

Listed under each PR in §2. All run with `-race`; the existing snapshot tests
(`zone_snapshot_test.go`) are the model.

### 5.2 tdns-mp per-writer tests (the §5 per-writer test of the 07-02 doc, MP variant)

In package `tdnsmp`, so only exported tdns API: a zone from `ReadZoneData` +
`InstallInitialSnapshot` (the transport harness already does this; add
`StopPublisher` to its cleanup) and a temporary `KeyDB` for the `HsyncDB`.

- **Combiner (M-1).** Seed `AgentContributions` for two agents;
  `RebuildCombinerData`; run the combine as the one `StageBatch` it becomes
  after M-1. Inside the callback, `s.RRset` shows the served NS RRset before
  `s.SetRRset` and the merged one after it, and the served zone is still
  the old one. After the batch: the merged NS is served, the serial advanced
  by exactly one, one NOTIFY was queued. A second identical batch reports no
  change and publishes nothing. Then `InjectSignatureTXT` twice, two batches
  (one TXT, one bump); `RemoveCombinerDataNG` of the last contribution for a
  type → the type is gone and, when it was the owner's only type, the owner
  too; `restoreUpstreamRRset` for NS restores the upstream set. Same
  sequence on a draft (a zone with `Data` and no snapshot) → the batch
  writes `Data` and publishes nothing, `RRsetForAnalysis` sees the result,
  `InstallInitialSnapshot` serves it. (The two-step stage-then-bump the
  first versions described would pin an API M-1 deletes; re-review L3.)
- **Signer, mode 2.** MP policy; `SignZone(ctx, …)` and then a refresh
  from file (the publish-path sign); assert after each: DNSKEY RRset is
  exactly the MP active keys; every RRset including SOA and NSEC has RRSIGs
  that verify against it; delegations are not signed; serial advanced once.
  Under T-C: `DnssecKeyStore` has no row for the zone. Under T-S: every row
  for the zone in `DnssecKeyStore` was written by the test or the migration
  and none by the generation fallback (`creator` column), also when the
  zone's keys are all `mpdist` at the time of the sign. A second sign
  without `force`: serial unchanged or plus one, DNSKEY set identical.
- **Signer, mode 4.** Two foreign DNSKEYs in the incoming apex before the
  refresh; after it the served DNSKEY set is local ∪ foreign, local RRSIGs
  verify, no RRSIG is by a foreign key, and the store holds the foreign keys
  as `foreign` (T-S: in `DnssecKeyStore`, with no private half).
- **Combiner versus refresh (M-1).** Start a `StageBatch` whose callback
  blocks; trigger a refresh of the same zone; release the callback; assert
  one serial for the combine, the refresh's publish after it, and the
  contributions served by both.
- **Bare bump (M-1).** No production path calls `BumpSerialOnly` without a
  preceding stage: a test that greps the tree is crude but adequate, given
  that `StageBatch` is the only publish the combiner uses after M-1.
- **Analysis readers are not the serve path (T-A).** `GetOwner` still
  refuses a not-Ready zone that `OwnerForAnalysis` reads, and neither reader
  appears in `queryresponder.go` or the transfer path.
- **Key migration (M-2S only).** A database with `MPDnssecKeyStore` rows
  in every state, including `foreign` and a `propagation_confirmed` key,
  and a `keyrr` at an old codepoint; after `InitHsyncTables` the rows are in
  `DnssecKeyStore` with the same states, the propagation flags are in the
  side table, the codepoint is rewritten, the old table is renamed, and a
  second start changes nothing.
- **First load (M-1).** A zone with pre-refresh and post-refresh callbacks
  registered; first load from file; the post-refresh callback observes
  `Ready` and a readable HSYNC3 RRset. (The tdns test in T-B covers the
  mechanism on both zone kinds; this one covers `PostRefresh` →
  `ApplyHsyncDiff` registering a peer.)

### 5.3 The lab data path (R-1, the multi-host rig)

The multi-host rig that tested #43 lives outside this repository and asserts
communications only: discovery, gossip, elections. R-1 adds a data-path
group that runs once the rig has converged. Cells, in the matrix's naming
(§5.4): one with a single signer (mode 2), one with three signers (mode 4),
one with `parentsync=agent` so that delegation change also flows. Every
assertion is one `PASS`/`FAIL` line, the convention both rigs share. `T` is
the rig's operation timeout.

- **D0 — served zones validate, before any mutation.** For each cell and each
  signer: AXFR the zone from the signer's `tdns-mpsigner`; every RRSIG in it
  verifies against the DNSKEY RRset in the same transfer (`dnssec-verify` or
  `ldns-verify-zone`, whichever the driving host has); the DNSKEY
  RRset contains no key the signer's `tdns-mpcli signer` key listing does not
  show as its own or as foreign; the SOA's RRSIG is by a key in the set. For
  each downstream provider: its served DNSKEY RRset and RRSIGs equal its
  upstream signer's (the loopback rig's static assertion A, on real hosts).
  This is the assertion 1.4 predicts fails on any mpsigner without the key
  seam; on a tdns with #514 it fails as a Ready zone that validates against
  minted keys, not as an unsigned apex.
- **D1 — NS add and delete by an agent** (`nsmgmt=agent` cells, each
  provider in turn): `tdns-mpcli <provider>-agent zone addrr` of an NS under
  the provider's suffix; within `T` the combiner of every provider serves it,
  every signer serves it signed (RRSIG verifies, NSEC bitmap at the apex
  unchanged, the chain still validates), every downstream serves it; the
  combiner's serial advanced by exactly one per accepted edit (one publish
  per logical change — read the serial before and after); an IXFR from the
  signer at the previous serial returns a delta, not a full zone; `delrr`
  reverses all of it. Also the start-up combine: restart one combiner (the
  rig's warm restart covers only agents and the auditor today) and assert the
  previously added NS is served straight after the restart, not after the
  next refresh.
- **D2 — DNSKEY roll by a signer** (the single-signer cell): roll the ZSK with the signer's
  rollover verb (`RolloverKeyMP` behind `tdns-mpcli signer`); within `T` the
  new DNSKEY is served, RRSIGs verify against the new set, the old key is
  gone after the retire step; the agent's `SYNC-DNSKEY-RRSET` propagated the
  change: every other provider's combiner serves the new DNSKEY.
- **D3 — multi-signer merge** (the three-signer cell): each signer serves a DNSKEY RRset
  equal to the union of the three signers' keys; each signer's RRSIGs verify
  against its own keys within that set; a D2 roll on one signer appears in
  the other two signers' served DNSKEY RRsets within `T`.
- **D4 — no publish refusals.** Every daemon log is free of
  `serial mirror drift`, `refusing to publish` and
  `refusing to swap in an apex-less snapshot`.

Ordering: M-1 must keep every communications check green after a cold start
and a warm restart, and pass D1 (the combiner). The mpsigner is not part of M-1, so D0 is out of M-1's scope
rather than red: the rig runs it against the June-pinned signer and reports
it for information. M-2's gate is D0–D4 green.

### 5.4 The loopback rig (R-2, `tests/mp-policy-matrix`)

The matrix already has NS add/delete (C), the foreign-NS negative (D) and
the DNSKEY API gate (E). Add **F. signatures validate** (D0's check per cell
and signer, from AXFR on the signer's port) and **G. DNSKEY roll** (D2 and
D3 on `p2s2a`/`p3s2a`). Both things its README waited for are on `main` now:
tdns#616 (tdns-auth answers JWK) and IMR forwarding (#433, #445, #464). The
rig pins its own tdns and `setup.sh` refuses any other commit, so R-2 starts
by moving that pin to the tdns M-1 re-pins to. Until R-2 lands the lab rig
is the data-path gate.

## 6. Open questions for Johan

Each with the recommendation the plan is written to.

1. **First-load ordering: O1, O2 or O3 (§2.2)?** Recommend O1, deferring a
   first load's post-refresh callbacks to the Ready flip, which after #514
   is the sign in `signOnceAfterPolicyBind` for a signer and
   `InstallInitialSnapshot` for everything else. It is the only option that
   removes the asymmetry for every consumer. O3 is the fallback.
2. **Key seam: T-S keystore merge (§2.4), K2 key source or K1 snapshot
   install (§2.3)?** Recommend T-S with the generation gate and the two
   worker sites designed into T-S2 (§2.4.4), which is the condition the
   review set for it: it reuses the signer core instead of feeding a fork
   of it, and its migration lands on the flag day the re-pin needs anyway.
   K2 is the fallback if that flag day is deferred; K1 is rejected either
   way.
3. **Under T-S: lifecycle hooks (T-S2) or `OptMultiProvider` branches inside
   tdns?** Recommend the hooks. They keep tdns ignorant of what the MP
   states mean, at the cost of one registration call. (Under K2 the
   question is instead whether tdns stores the source's keys into the
   signing-keys snapshot; recommend yes, tdns owns that snapshot.)
4. **Retire `MPResignerEngine` in favour of tdns's `ResignerEngine`?**
   Required in M-2 or M-2S, not later (review A7, tdns-mp#46): the API it
   copies, `SetupZoneSigning` and a `ResignQ` of zones, no longer exists
   after #514, so the re-pin cannot keep it.
5. **Draft semantics: keep `new_zd.Data` as the draft that `StageRRset`
   writes, or have tdns's refresh build its working set from `new_zd`'s own
   working set?** Recommend the former. It is what the refresh publish
   consumes today, `ownerForAnalysis` already defines the draft test, and it
   costs no tdns refresh-path change.
6. **Add `Publish()` as a name for `BumpSerialOnly()`?** Cosmetic; recommend
   yes, in T-A, so the MP call sites read as what they do. `BumpSerialOnly`
   stays.
7. **Where do the lab data-path assertions live: extend the multi-host rig
   or a sibling?** Recommend extending: same topology, same cells, and the
   rig's scope statement gets a dated amendment.
8. **Gate marker: per-site `mp-private:` comments (recommended) or a
   per-file allowlist?** Per-site, for the reason in §3.4.
9. **May the mpsigner re-pin before the key seam lands?** No, withdrawn
   (review, tdns-mp#46 item 4): on a tdns with #514 an mpsigner without the
   seam serves a Ready zone signed with minted keys, which is worse than
   the pre-#514 unsigned apex the first version accepted as "D0 red". The
   combiner, agent and auditor re-pin in M-1 as planned; the signer waits
   for M-2.
10. **Under T-S: fold the key migration, the codepoint renumbering (trial
    item E) and the config-key migration (item C) into one flag day?**
    Recommend yes: one migration tool, one fleet cycle, one rollback point.
    Each of the three rewrites the same deployments. Under T-C, no: item E
    stays its own mpsigner fix.
11. **Batched staging as a `StageBatch` closure (recommended) or as
    exported `*Locked` staging functions plus a locked publish?** The
    closure: it cannot be misused by calling the locking wrapper while the
    lock is held, and its `Stager` gives the read-your-own-writes view that
    the per-call form lacks.

## 7. Out of scope, deliberately

tdns-transport (nothing there touches zone data); the config-key migration
(trial item C) and, under T-C only, the mpsigner codepoint renumbering
(item E; under T-S it is part of M-2S); JWK
(tdns#616, merged); the IMR lame-delegation backoff (tdns#617, merged); the
80 s cold start (its own handover, tdns-mp#45); the non-signer serial bump
the matrix README records; a non-Ready zone's readability for anything but
the callbacks above.

## 8. The external review, and where this plan differs from it

`reviews/2026-09-11-tdns-mp-PR44-bmp-snapshot-plan-review.md` reviewed the
second version of this document against tdns `fe83b216`. Its verdict: adopt
the publication design (T-A, O1, M-1); do not take T-S as then specified;
rewrite for #514 before implementing. Every finding, and what this version
does with it:

| finding | disposition |
|---|---|
| A1 `EnsureActiveDnssecKeys` mints when the active set is short; T-S did not hook it | Taken: `MayGenerate` in T-S2 (§2.4.4). One correction: MP's own `EnsureActiveDnssecKeysMP` mints in the same situation today, so the gap was in the specification, not a regression T-S would have introduced; the hook tightens MP's behaviour. |
| A2 `maintainStandbyKeys` skips MP zones and does not count `mpdist` | Taken: skip lifted, pipeline = `published` ∪ `StagedState` (§2.4.4). |
| A3 `transitionPublishedToStandby` is a global walk | Taken: named as a hook site; it needs only `OnStateChange` (§2.4.4). |
| A4 a refresh between per-call stages and the publish | Taken: `StageBatch` holds `zd.mu` across a logical change (§2.1, §3.1). One correction: the interleaving costs an extra serial; "a second sign" would need the combiner's zone to sign its own content, which it does not. |
| A5 the key source must exist before the first refresh | Taken: installed from the zone-option handler (§2.3, §3.3); the T-S analogue is hook registration before `MainInit`. |
| A6 O1's landing site is the Ready flip, not `InstallInitialSnapshot` | Taken (§2.2). The first version was written against `d1eec102`, where Install was the flip; #514 moved it for signing zones. |
| A7 M-2 named APIs #514 removed | Taken: §3.3 and §2.4.4 rewritten for `SignZone(ctx, …)`, `ResignRequest`, `registerForPeriodicResign`; `MPResignerEngine` goes in M-2 either way (Q4). |
| B1 T-S was undersized | Taken (§2.4.5, §4). |
| B2 one flag day only under T-S | Taken (Q10). |
| B3 T-B must not reopen the unsigned-serve window | Taken, stated in §2.2. |
| C1 export `CloneRRset` | Taken (§2.1). |
| "IMR forwarding is still the remaining matrix gate" | Not so: #433, #445 and #464 are on `main`. The rig's gate is its own tdns pin (§5.4). |
| "T-C until T-S is completed" | The review offered two ways to close: recommend T-C, or keep T-S and design A1–A3 into it. This version takes the second (Q2); Johan's stated preference for reusing the signer core is the reason. |

The re-review at `4dfdcaf` closed A1–A7, B1–B3, C1, Q4 and Q9, agreed with
both corrections above, and prefers T-S as now specified. Its leftovers:

| finding | disposition |
|---|---|
| L1 the key source's install site named a handler that does not receive the zone; §3.3 named two sites | Taken: one site, the `multi-provider` zone-option handler looking the zone up by name (§2.3, §3.3). |
| L2 `Stager.RRset` on a live zone must seed the working set first | Taken (§2.1). |
| L3 the combiner test still pinned stage-then-bump | Taken: rewritten around `StageBatch` (§5.2). |
| L4 drain after the journal replay, to match a later refresh's order | Taken (§2.2). |
| L5 say that a permitted bootstrap mint is `active`, not `StagedState` | Taken (§2.4.4). |

## 9. Decisions (2026-09-11)

Johan's answers to §6, recorded the same evening. The sections above are
not rewritten; where an answer changes a detail, the change is stated here
and governs.

| Q | decision | consequence |
|---|---|---|
| 1 | O1 | as §2.2: the drain lands on the Ready flip, after the journal replay |
| 2 | T-S | T-C is not built; §2.3 stays as the record of the alternative and the fallback |
| 3 | hooks; and keep tdns-mp references and code in tdns to a minimum | T-S1's states get tdns-generic names: `foreign` stays; `mpdist` becomes `staged` (served, promotion owner-controlled) and `mpremove` becomes `withdrawn` (out of the RRset, deletion owner-controlled). tdns-mp's constants take those values, the migration maps the old names, and the KEYSTATE inventory carries the new ones, which the flag day (Q10) covers. Nothing in tdns names tdns-mp, the KEYSTATE protocol or the agent; the hooks are the only seam, and tdns's own behaviour with nil hooks is unchanged |
| 4 | no decision needed | `MPResignerEngine` is retired in M-2S, as §3.3 says |
| 5 | `new_zd.Data` stays the draft that staging writes | as §2.1 |
| 6 | yes | `Publish()` is added in T-A beside `BumpSerialOnly()` |
| 7 | extend the multi-host rig | as §5.3 |
| 8 | per-site `mp-private:` markers | as §3.4 |
| 9 | already withdrawn | no mpsigner re-pin before the key seam |
| 10 | yes | one flag day: the key migration, the codepoint renumbering (trial item E) and the config-key migration (item C) |
| 11 | `StageBatch` | as §2.1 |

The order stands as §4: T-A, T-B and T-S in tdns; then M-1 for the
combiner, agent and auditor; then M-2S for the signer; then R-1 and R-2.

**Correction to Q3, the same evening.** The consequence written above
over-read "minimise" as "never". The states keep the names §2.4.4 gives
them: `mpdist`, `mpremove` and `foreign`. What T-S1 puts into tdns is two of
those names in one SQL predicate (`FetchZoneDnskeysSql`, shared with
`CollectDynamicRRs`) and the hook struct; tdns still attaches no meaning to
them beyond "served" and "not served", and everything that decides
transitions stays behind the hooks in tdns-mp. That is the minimum, and it
spares the flag day a state rename. The generic names are withdrawn.
