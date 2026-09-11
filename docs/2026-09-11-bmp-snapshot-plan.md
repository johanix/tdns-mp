# B-MP: tdns-mp on tdns's snapshot model — implementation plan

**Date:** 2026-09-11
**Status:** plan. Nothing here is implemented.
**Basis:** tdns `main` at `d1eec102` (the pin of #43; `02581d04` on top is a
dependency bump only) and tdns-mp `fix/modern-repin` at `b955faf` (#43; the
four commits it gained afterwards, up to `a8e1e50`, touch none of the files
cited here).
Line numbers are anchors at those commits and drift; re-locate by symbol.
**Reads with:** tdns `docs/2026-07-02-DONE-zone-mutation-snapshot-correctness.md`
(the model; its §9 defined B-MP and is corrected below), the re-pin trial
review of 2026-09-10 (§G) and the lab-run log of 2026-09-11, both in the
project's `reviews/` directory.
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
| T-A | export the analysis readers, a draft-aware staging API, `StopPublisher` | ½ day |
| T-B | a first load runs its post-refresh callbacks once the zone is Ready | ½ day |
| T-C | a per-zone key source, so publish and `SignZone` sign with the zone's keys | 1 day |
| M-1 | re-pin; readers, combiner staging, gate, both workarounds deleted | 1½ days + lab |
| M-2 | re-pin; the signer uses tdns's `SignZone` through the key source; MP loop deleted | 1 day + lab |
| R-1 | `mp-comms` gains data-path assertions | 1 day |
| R-2 | `mp-policy-matrix` gains signature validation and a DNSKEY roll | ½ day |

The decisions Johan is asked to make are in §6. The two that shape the code
are the first-load ordering (§2.2, recommended: defer the callbacks) and the
key seam (§2.3, recommended: an interface on `ZoneData`).

## 1. What is wrong on tdns main today

All four items are read from the code. Items 1 and 2 were seen in the lab and
are worked around in #43; items 3 and 4 have not been observed because the
`mp-comms` rig asserts only communications. Item 4 goes further than the
trial's §G.

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
`if !firstLoad` (`zone_mutation.go:732`) → post-refresh callbacks →
`completeFirstZonePolicyAndLoad` → `InstallInitialSnapshot` sets `Ready`
(`zone_mutation.go:808`) → policy sync → journal replay → `OnFirstLoad`.

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
`SignZone` (tdns `docs/2026-07-13-unsigned-publish-window.md`). The defect is
not the deferral, it is that one class of callback runs on the wrong side of
it.

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

Two side effects of the same model change: `publishLocked` NOTIFYs
downstreams itself (`zone_mutation.go`, end of `publishWorkingSetLocked`), so
the explicit `go zd.NotifyDownstreams()` at `apihandler_combiner.go:215` and
`combiner_msg_handler.go:287` now notifies twice; and `InjectSignatureTXT`
appends onto `existing.RRs` obtained from a served owner, which is the §1.4
aliasing the model forbids.

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
5. `BumpSerial` → `publishSync` → `publishLocked`: the working set's apex
   clone (step 1's DNSKEY set, unsigned RRsets) replaces the apex that step
   3 and 4 wrote. `resignWorkingSetSOAIfSigned` then calls
   `zd.EnsureActiveDnssecKeys(zd.KeyDB, true)` (`zone_mutation.go`, the
   publish path) — tdns's keystore, `DnssecKeyStore`, which holds no keys for
   an MP zone (they are in `MPDnssecKeyStore`) — and with `zd.DnssecPolicy`
   bound it **generates a KSK and ZSK in the tdns keystore**, stages a DNSKEY
   RRset of those keys, and signs the SOA with them.

Expected served result after one `SignZone` on tdns main: apex RRsets unsigned
or stale-signed, DNSKEY RRset made of tdns-minted keys (no MP keys, no
foreign keys), SOA signed by a tdns-minted ZSK, every other RRset signed by
MP keys that are not in the DNSKEY set. That is a bogus zone from the first
sign. If key generation fails instead (an MP policy the tdns generator
refuses), the SOA is not re-signed and the DNSKEY set is the MP active keys
only — also wrong, less loudly. Which of the two happens is the first thing
the lab data-path run (§5.3, D0) must establish; neither is acceptable.

The trial's §G asked tdns to export a `dak`-taking staged `SignZone` and a
`PublishDnskeyRRs` that accepts foreign keys. Those two exports would fix
steps 1–4 and leave step 5 in place: the SOA re-sign lives inside publish and
resolves keys on its own. The fix has to be a per-zone key seam (§2.3).

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

Three PRs, each reviewable alone. T-A and T-B unblock M-1; T-C unblocks M-2.
Every tdns change here is app-neutral: tdns-auth's behaviour does not change
unless a caller opts in (a key source set, a callback registered).

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

**Publish.** `BumpSerialOnly()` already is `publishSync()`: one serial, one
snapshot, one delta, one NOTIFY. It stays the publish call. Optionally add
`Publish()` as a second name for the same thing so MP code reads as what it
does; not required (§6, Q6).

**`StopPublisher()`.** Export `stopPublisher` for external test harnesses
(trial item F: tdns-mp's transport harness leaks one publisher goroutine per
seeded zone).

**Doc.** Append a dated amendment to §9 of the 2026-07-02 doc: receivers do
not promote; the exported surface is the above; B-MP is this plan.

**Tests.** `TestStageOnDraftWritesData` (Data populated, no snapshot: stage,
read back through `RRsetForAnalysis`, `InstallInitialSnapshot`, served);
`TestStageOnLiveZoneLeavesSnapshot` (the exported `StageRRset` obeys
`TestSnapshotImmutability`'s assertion); `TestAnalysisReadersPreferSnapshot`.

**Size and risk.** ~120 lines plus tests. No behaviour change for existing
callers.

### 2.2 T-B — a first load's post-refresh callbacks run once the zone is Ready

This is the part Johan asked to have sorted out cleanly. Three ways to do it
were weighed.

**O1 — defer the callbacks (recommended).** In `FetchFromUpstream` and
`FetchFromFile`, when `firstLoad`, record that post-refresh callbacks are
owed instead of running them (`zd.postRefreshOwed = true`, under the `zd.mu`
already held around `applyRefreshReplacementLocked`). In
`completeFirstZonePolicyAndLoad`, immediately after `InstallInitialSnapshot`
and before the policy sync, run them once and clear the flag
(`runOwedPostRefresh`). Every later refresh is unchanged.

- The callbacks then run at the moment the zone becomes Ready, which is the
  moment a non-first refresh's callbacks correspond to. The asymmetry is
  gone for every consumer, not patched in one.
- Before the policy sync, so a sync failure (which returns early and retries
  `OnFirstLoad` on the ticker) cannot lose them; a retry finds the flag
  clear. The other `InstallInitialSnapshot` caller (`zone_utils.go:2341`)
  runs the same drain; the flag makes it a no-op where nothing was deferred.
- tdns's own two post-refresh consumers are enqueue-only and idempotent:
  `ProxyDelegationPostRefresh` (`delsync_proxy.go:175`) enqueues PROXY-SYNC
  from an analysis computed pre-flip; `ChildSyncProxyPostRefresh`
  (`childsync_proxy.go:279`) reconciles in memory and enqueues. Running them
  a few milliseconds later, on the engine goroutine they already run on for
  a first load, changes nothing they depend on.
- ~40 lines. One test: register a post-refresh callback, first-load a zone
  from file, assert the callback saw `Ready == true` and `GetOwner` succeed.

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
`ResignZone`, `SignRRset` with a nil `dak`, and `resignWorkingSetSOAIfSigned`
inside publish), `publishDnskeyRRsLocked` (the DNSKEY RRset at sign time) and
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

`SignZone(kdb, force)` keeps its signature; `kdb` is still needed for the TTL
clamp and `UpsertZoneSigningMaxTTL`, and `HsyncDB` embeds `*tdns.KeyDB`, so
tdns-mp passes `hdb.KeyDB`.

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

## 3. tdns-mp side

Two PRs. M-1 re-pins to the tdns commit that carries T-A and T-B and does
everything except the signer; M-2 re-pins to the commit that carries T-C and
does the signer. Splitting keeps each lab run answering one question.

### 3.1 M-1: served-zone sites, one publish per logical change

| site | today | becomes |
|---|---|---|
| `combiner_utils.go:163`, `:165` | `existingOwnerData.RRtypes.Set(rrtype, …)` | `mpzd.StageRRset(ownerName, merged|newRRset)`; read the current RRset through `RRsetForAnalysis` (draft or live) instead of `mpzd.Data.Get` |
| `:170` | `mpzd.Data.Set(ownerName, existingOwnerData)` | deleted; staging is per RRset |
| `:746`, `:747` (`InjectSignatureTXT`) | append onto the served TXT slice, `Data.Set` | build the new RRset from a copy (`cloneRRset` is unexported: `append([]dns.RR(nil), existing.RRs...)`), `StageRRset` |
| `:762`, `:763` (`restoreUpstreamRRset`) | `zoneOd.RRtypes.Set`, `Data.Set` | `StageRRset(owner, upstream rrset)` |
| `:807` (`cleanupRemovedRRtype`) | `od.RRtypes.Delete`, `Data.Set` | `StageDelete(owner, rrtype)`; `StageOwnerDelete(owner)` when it was the owner's last type |
| `config.go:173` (start-up combine) | no publish | `BumpSerialOnly()` after `CombineWithLocalChanges` and `InjectSignatureTXT` when either changed anything |
| `hsync_utils.go:1398` (pre-refresh combine on `new_zd`) | writes `new_zd.Data` and works | same code, now through `StageRRset`'s draft branch; no publish (the refresh publish is the publish) |
| `apihandler_combiner.go:215`, `combiner_msg_handler.go:287` | `go zd.NotifyDownstreams()` after the bump | deleted; publish notifies |

The rule for every runtime path in the 1.3 table: stage all of a logical
change, then exactly one `BumpSerialOnly()`, guarded by "something changed".
The three rows marked "verify" in 1.3 get their publish call if they lack
one. `publishSync` on an empty working set still bumps the serial, so the
guard is not optional.

Between the stages and the publish, a refresh on the same zone replaces the
working set (`applyRefreshReplacementLocked`). The contributions are not
lost: the pre-refresh combine re-applies them into `new_zd`. Documented, not
guarded against.

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

### 3.3 M-2: the signer

- `mpKeySource{hdb *HsyncDB}` implements `tdns.ZoneKeySource`. `ActiveKeys`
  is `EnsureActiveDnssecKeysMP` minus its final `zd.PublishDnskeyRRs(dak)`
  (`signer_keydb.go:630`; that call is step 1 of 1.4 and goes). `DnskeyRRs`
  is the body of `MPZoneData.PublishDnskeyRRs` (`mp_signer.go:283–349`)
  minus the apex `Set`: active keys, the `MPDnssecKeyStore` rows
  (mpdist/published/standby/retired/foreign), the `RemoteDNSKEYs` merge,
  deduplicated. `SetKeySource` is called where a zone becomes a signer zone
  (`MPPreRefresh`, where inline-signing is switched on) and at startup for
  zones already so.
- `MPZoneData.SignZone` becomes: mode selection as today
  (`extractRemoteDNSKEYs` for mode 4, `SetRemoteDNSKEYs(nil)` for mode 2),
  then `return mpzd.ZoneData.SignZone(hdb.KeyDB, force)`. Lines 48–158 of
  `mp_signer.go` — `EnsureActiveDnssecKeysMP`'s call, the NSEC call, the
  owner loop, `BumpSerial` — are deleted; so is `MPZoneData.PublishDnskeyRRs`.
  tdns's loop already does what the MP loop did and more (occluded names,
  delegation handling, ZONEMD, the TTL clamp, canonical NSEC order).
- `SetupZoneSigning` and `MPResignerEngine` keep their shape and call the
  new `SignZone`. Retiring the MP resigner for tdns's is a later cleanup
  (§6, Q4).
- `extractRemoteDNSKEYs` keeps reading the live apex through `GetOwner`: it
  runs post-Ready (from `OnFirstLoad` and the resigner). A foreign key the
  upstream signer withdraws disappears on the next refresh-then-resign.
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
2026-07-21 drift recipe is the fallback if it does not.

## 4. Order and sizing

| step | depends on | estimate | gate |
|---|---|---|---|
| T-A readers + staging + `StopPublisher` | — | ½ day | tdns tests, `make check` |
| T-B first-load post-refresh deferral | — | ½ day | tdns tests |
| T-C key source | — | 1 day | tdns tests incl. signature verification |
| M-1 re-pin, readers, combiner, gate, workarounds out | T-A, T-B merged | 1½ days | `make check`, `make test-race`, lab D0–D1 (§5.3) 71/0 comms unchanged |
| M-2 re-pin, signer through the key source | T-C merged, M-1 merged | 1 day | lab D0–D3 |
| R-1 `mp-comms` data-path verbs and assertions | — (written against M-1/M-2 expectations) | 1 day | runs green on M-2 |
| R-2 `mp-policy-matrix` F/G scenarios | tdns#616 (JWK) and the IMR forwarding the README asks for | ½ day | runs green on M-2 |

T-A, T-B and T-C are independent of each other and can be three PRs in the
same week; CodeRabbit's one review per hour in johanix/tdns sets the pace.
Total about seven working days plus two lab afternoons. Slices over a big
bang: each tdns PR is reviewable in one sitting, and each tdns-mp PR has one
lab question to answer.

## 5. Tests

### 5.1 tdns (in the T-* PRs)

Listed under each PR in §2. All run with `-race`; the existing snapshot tests
(`zone_snapshot_test.go`) are the model.

### 5.2 tdns-mp per-writer tests (the §5 per-writer test of the 07-02 doc, MP variant)

In package `tdnsmp`, so only exported tdns API: a zone from `ReadZoneData` +
`InstallInitialSnapshot` (the transport harness already does this; add
`StopPublisher` to its cleanup) and a temporary `KeyDB` for the `HsyncDB`.

- **Combiner (M-1).** Seed `AgentContributions` for two agents;
  `RebuildCombinerData`; `CombineWithLocalChanges`; assert the served NS
  RRset is unchanged and the serial unchanged (staged, not published);
  `BumpSerialOnly`; assert the merged NS is served and the serial advanced
  by exactly one. Then `InjectSignatureTXT` twice (one TXT, one bump);
  `RemoveCombinerDataNG` of the last contribution for a type → the type is
  gone and, when it was the owner's only type, the owner too;
  `restoreUpstreamRRset` for NS restores the upstream set. Same sequence on a
  draft (a zone with `Data` and no snapshot) → `RRsetForAnalysis` sees the
  result, `InstallInitialSnapshot` serves it.
- **Signer, mode 2 (M-2).** MP policy, `mpKeySource` over the temp store;
  `SignZone`; assert: DNSKEY RRset is exactly the MP active keys; every RRset
  including SOA and NSEC has RRSIGs that verify against it; delegations are
  not signed; serial advanced once; `DnssecKeyStore` has no row for the zone.
  A second `SignZone` without `force`: serial unchanged or plus one, DNSKEY
  set identical.
- **Signer, mode 4 (M-2).** Two foreign DNSKEYs in the apex before signing;
  after `SignZone` the served DNSKEY set is local ∪ foreign, local RRSIGs
  verify, and `MPDnssecKeyStore` holds the foreign keys as `foreign`.
- **First load (M-1).** A zone with pre-refresh and post-refresh callbacks
  registered; first load from file; the post-refresh callback observes
  `Ready` and a readable HSYNC3 RRset. (The tdns test in T-B covers the
  mechanism; this one covers `PostRefresh` → `ApplyHsyncDiff` registering a
  peer.)

### 5.3 The lab data path (R-1, labstuff `mp-comms`)

`mp-comms` (labstuff#492) asserts communications only; its README says data
mutations are out of scope. R-1 adds a `data` verb group that runs after
`converge` and is part of `all`. Cells: `p3s1a` (one signer, mode 2),
`p3s3a` (three signers, mode 4), `p3s1e` (`parentsync=agent`, so delegation
change also flows). Every assertion is one `PASS`/`FAIL` line, the rig's
convention. `T` is the rig's operation timeout.

- **D0 — served zones validate, before any mutation.** For each cell and each
  signer: AXFR the zone from the signer's `tdns-mpsigner`; every RRSIG in it
  verifies against the DNSKEY RRset in the same transfer (`dnssec-verify` or
  `ldns-verify-zone`, whichever the master has; `lib.sh` picks); the DNSKEY
  RRset contains no key the signer's `tdns-mpcli signer` key listing does not
  show as its own or as foreign; the SOA's RRSIG is by a key in the set. For
  each downstream provider: its served DNSKEY RRset and RRSIGs equal its
  upstream signer's (the loopback rig's static assertion A, on real hosts).
  This is the assertion 1.4 predicts fails on #43.
- **D1 — NS add and delete by an agent** (`nsmgmt=agent` cells, each
  provider in turn): `tdns-mpcli <provider>-agent zone addrr` of an NS under
  the provider's suffix; within `T` the combiner of every provider serves it,
  every signer serves it signed (RRSIG verifies, NSEC bitmap at the apex
  unchanged, the chain still validates), every downstream serves it; the
  combiner's serial advanced by exactly one per accepted edit (one publish
  per logical change — read the serial before and after); an IXFR from the
  signer at the previous serial returns a delta, not a full zone; `delrr`
  reverses all of it. Also the start-up combine: restart one combiner
  (`warm` restarts only agents and the auditor today; add `restart-combiner`)
  and assert the previously added NS is served straight after the restart,
  not after the next refresh.
- **D2 — DNSKEY roll by a signer** (`p3s1a`): roll the ZSK with the signer's
  rollover verb (`RolloverKeyMP` behind `tdns-mpcli signer`); within `T` the
  new DNSKEY is served, RRSIGs verify against the new set, the old key is
  gone after the retire step; the agent's `SYNC-DNSKEY-RRSET` propagated the
  change: every other provider's combiner serves the new DNSKEY.
- **D3 — multi-signer merge** (`p3s3a`): each signer serves a DNSKEY RRset
  equal to the union of the three signers' keys; each signer's RRSIGs verify
  against its own keys within that set; a D2 roll on one signer appears in
  the other two signers' served DNSKEY RRsets within `T`.
- **D4 — no publish refusals.** Every daemon log is free of
  `serial mirror drift`, `refusing to publish` and
  `refusing to swap in an apex-less snapshot`.

Ordering: M-1 must keep comms at 71/0 cold and warm and pass D1 (the
combiner) while D0's signature checks are expected red until M-2; the rig
reports them, the M-1 gate excludes them by name. M-2's gate is D0–D4 green.

### 5.4 The loopback rig (R-2, `tests/mp-policy-matrix`)

The matrix already has NS add/delete (C), the foreign-NS negative (D) and
the DNSKEY API gate (E). Add **F. signatures validate** (D0's check per cell
and signer, from AXFR on the signer's port) and **G. DNSKEY roll** (D2 and
D3 on `p2s2a`/`p3s2a`). It cannot converge until tdns#616 (tdns-auth answers
JWK) is merged and the pinned tdns has IMR forwarding; the rig's README
records both. Until then the lab rig is the data-path gate.

## 6. Open questions for Johan

Each with the recommendation the plan is written to.

1. **First-load ordering: O1, O2 or O3 (§2.2)?** Recommend O1, deferring a
   first load's post-refresh callbacks to the Ready flip. It is the only
   option that removes the asymmetry for every consumer. O3 is the fallback.
2. **Key seam: K2 interface or K1 snapshot install (§2.3)?** Recommend K2.
   One explicit seam that every key-resolving site tests the same way; a
   fake source makes the tdns test self-contained.
3. **Does T-C's `EnsureActiveDnssecKeys` store the source's keys into the
   signing-keys snapshot, or does the source push them?** Recommend the
   former: tdns owns that snapshot and already refreshes it on every sign;
   a second writer from another package is the G3 design's own warning.
4. **Retire `MPResignerEngine` in favour of tdns's `ResignerEngine` in M-2,
   or later?** Recommend later, as its own small PR once M-2 has run in the
   lab: M-2 should change what signs, not what schedules signing.
5. **Draft semantics: keep `new_zd.Data` as the draft that `StageRRset`
   writes, or have tdns's refresh build its working set from `new_zd`'s own
   working set?** Recommend the former. It is what the refresh publish
   consumes today, `ownerForAnalysis` already defines the draft test, and it
   costs no tdns refresh-path change.
6. **Add `Publish()` as a name for `BumpSerialOnly()`?** Cosmetic; recommend
   yes, in T-A, so the MP call sites read as what they do. `BumpSerialOnly`
   stays.
7. **Where do the lab data-path assertions live: extend `mp-comms` or a
   sibling rig?** Recommend extending: same topology, same cells, and the
   README's scope statement gets a dated amendment.
8. **Gate marker: per-site `mp-private:` comments (recommended) or a
   per-file allowlist?** Per-site, for the reason in §3.4.
9. **M-1 before T-C lands means the lab signer stays wrong for a few days
   (1.4).** Acceptable? The fleet runs the June pin; only the lab sees main.
   Recommend yes, with D0 red and named in M-1's PR.

## 7. Out of scope, deliberately

tdns-transport (nothing there touches zone data); the mpsigner codepoint
renumbering and the config-key migration (trial items E and C); JWK
(tdns#616); the IMR lame-delegation backoff (`fix/imr-servfail-backoff`);
the 80 s cold start (its own handover); the non-signer serial bump the
matrix README records; a non-Ready zone's readability for anything but the
callbacks above.
