# Peer-discovery-engine-extraction fallout: two bugs

Date: 2026-05-28
Status: IMPLEMENTED on branch (both bugs), builds clean + hsync unit
tests pass; pending testbed verification (redeploy + restart `cpt`).
Branch: `peer-discovery-engine-extraction` (tdns-mp), with the
transport piece in tdns-transport branch
`transport-refactor-semi-easy-bites`.

Two distinct bugs surfaced while testing this branch on the
distributed testbed (a single NS edit to `espresso.mp.axfr.net` on
agent `cpt` that never converged). They have independent tactical
fixes (below). Bug 2 is the live blocker; Bug 1 is a correctness bug
exposed by the same investigation.

## Underlying root cause: three registries

Both bugs are symptoms of one architectural problem: tdns-mp keeps
**three separate registries** that hold overlapping peer information
and are updated by different code paths:

1. **tdnsmp `AgentRegistry`** — `Agent` (`agent.Zones`, `DnsDetails`/
   `ApiDetails` with addresses/state). What `peer list` displays.
2. **hsync `Registry`** — `hsync.Peer` (`peer.Zones`, per-mechanism
   details). Owned by the shared HsyncEngine.
3. **transport `PeerRegistry`** — `transport.Peer` (`OperationalAddr`/
   `DiscoveryAddr`, per-mechanism state). What the send path reads.

The bridges between them are partial and asymmetric, so the three
drift apart:
- **Bug 1** is a zone-membership divergence (`agent.Zones` / group
  membership vs HSYNC3/HSYNCPARAM reality).
- **Bug 2** is an address divergence (`AgentRegistry` has the combiner
  address, the transport `PeerRegistry` does not).

The strategic cure is to **consolidate the three registries into one**
— a major goal of the transport redesign
(`2026-04-15-transport-interface-redesign.md`). The fixes below are
tactical stopgaps (route a read through the authoritative source; make
a bridge copy the missing field) until that consolidation lands. Both
should be revisited / subsumed when the single registry exists.

---

# Bug 1: zone membership derived from HSYNC3 instead of HSYNCPARAM

## Summary

A peer that has an HSYNC3 record in a zone but **no role in that
zone's HSYNCPARAM** is wrongly treated as a participating member of
the zone. Membership is derived from the raw HSYNC3 identity set; it
must instead derive from HSYNCPARAM roles. Behavioral, not cosmetic:
the bogus member enters the provider group, gossip state matrix, beat
targets, and the distribution recipient set.

## Data model (authoritative)

- **HSYNC3** is *only* an identity↔label declaration: `Label` →
  `Identity` FQDN, plus `State` (ON/OFF). No role, no responsibility.
  A customer may publish an HSYNC3 record for any identity — by
  mistake, in preparation for a future role, or as an experiment.
- **HSYNCPARAM** is the **sole authority** for roles and membership.
  It is SVCB-like: an open-ended set of key/value params. Today the
  membership-conferring keys are `servers=`, `signers=`, `auditors=`
  (label lists). Other keys (`nsmgmt=`, `parentsync=`, `suffix=`) are
  policy, not membership. New membership-conferring keys may be added,
  so the fix must make the set of such keys easy to extend.

**Participant set of a zone** = union of identities named by the
membership-conferring HSYNCPARAM keys, each label resolved via the
zone's **ON** HSYNC3 label→identity map. Voting = `servers ∪ signers`;
auditors are non-voting members. An ON HSYNC3 identity with no
HSYNCPARAM role is **known** (mapping usable) but **not a member**.

## Evidence (espresso.mp.axfr.net, AXFR from auditor `skrubb`)

```
HSYNC3:     hare, fox, cpt, auden(=auditor.mp), skrubb   (all State ON)
HSYNCPARAM: servers="cpt,fox,hare" signers="fox,hare" auditors="skrubb"
```

`auden` (= `auditor.mp.axfr.net.`) has an ON HSYNC3 record but no
HSYNCPARAM role. Observed: it appears in `auditor peer zones` under
espresso/hoola, in espresso's gossip matrix as OPERATIONAL, and it
entered the NS edit's `ExpectedRecipients` (the SDE `Pending:` set).
`mplist` (HSYNCPARAM-derived) correctly shows auditor `skrubb` only.

## Root cause: membership taken from the HSYNC3 identity set

| Site | Current source | Correct source |
|---|---|---|
| `hsync/hsync3_diff.go` `IdentitiesFromRRset` (feeds `ReconcileZone` `expected` + `ApplyHsyncDiff`) | every HSYNC3 identity; does **not** filter `State==OFF` | HSYNCPARAM-role identities, labels resolved via ON HSYNC3 |
| `provider_groups.go` `RecomputeGroups` — `Members` and the **group key** | raw HSYNC3 `identities` | participant set (HSYNCPARAM roles) |
| `provider_groups.go` `RecomputeGroups` — `votingMembers` | **already correct** (HSYNCPARAM signers/servers via label→identity) | — |
| `agent_utils.go` `GetZoneAgentData` (feeds `GetDistributionRecipients` → `ExpectedRecipients`) | iterates every HSYNC3 record's identity; no role check | participant set (HSYNCPARAM roles) |

The correct pattern already exists: `votingMembers` above,
`analyzeHsyncSigners`, `providerBeatMeta` (which filters `State==0`).
The defect is that the participant/group membership paths never
adopted it.

## Fix

1. One canonical helper — `ZoneParticipants(zd)` (name TBD): build the
   label→identity map from **ON-only** HSYNC3 records; collect labels
   from the membership-conferring HSYNCPARAM keys via a single
   **extensible** list (today `GetServers`, `GetSigners`,
   `GetAuditors` in `tdns/v2/core/rr_hsyncparam.go`); resolve labels →
   identities. Expose voting vs non-voting (voting = servers ∪
   signers).
2. Route `RecomputeGroups` `Members` **and the group key**, and
   `GetZoneAgentData`, through the participant set.
3. Route `ReconcileZone`'s `expected` set through it, so the periodic
   reconcile actively prunes non-members (`RemovePeerFromZone`). This
   repairs already-running nodes within one reconcile interval.
4. `ApplyHsyncDiff` / the membership trigger: an HSYNC3 change alone
   must not add/remove a *member*; membership follows HSYNCPARAM.
5. Fix the `State==OFF` inconsistency: `IdentitiesFromRRset` and any
   label→identity construction must ignore OFF records.

---

# Bug 2: config infra peers get an addressless transport peer (Bite H regression)

## Summary

On this branch, every agent→combiner send fails with "all transports
failed … no address available", so an agent's edits never reach the
combiner. This is the live blocker (the espresso NS edit retried 200+
times over 3.5h; the combiner has zero contributions). It is a
regression introduced by **Bite H** of the transport refactor.

## Root cause

Two `Agent → transport.Peer` helpers in `hsync_transport.go`:

- `SyncPeerFromAgent` (1452) sets the peer's discovery address from
  `agent.DnsDetails.Addrs[0]`+`Port` (1466).
- `GetOrCreatePeer` (1440, "Bite H") only does
  `PeerRegistry.GetOrCreate(identity)` — **no address sync**. Split
  out of `SyncPeerFromAgent` to skip a "redundant" per-send *state*
  refresh; it also (unintentionally) dropped the *address* copy.

The hot send paths — `SendBeatWithFallback` (1632), the distribution
send, and `sendRfiToCombiner` (2298) — use bare `GetOrCreatePeer`.

- **Discovered peers** (agents/auditors) get their address via the DNS
  discovery flow (`agent_discovery.go` `SetDiscoveryAddress`), so they
  are unaffected.
- **Config-only infra peers** (combiner, signer) are never discovered;
  their address lives only on the `AgentRegistry` Agent (set by
  `combiner_peer.go` / `signer_peer.go` init). The only way it reaches
  the transport peer is a path that explicitly addresses it.

## Evidence (mptest92, agent started 12:27:29 this run)

- `12:27:29 combiner_peer.go:80 registered combiner as virtual peer address=41.76.135.54:8055`
- `12:27:29 hsync_infra_beat.go:86 infra beat failed peer=combiner … no address available` — and every ~10 min since.
- `12:27:29 signer_peer.go:83 registered signer as virtual peer address=41.76.135.54:8053`
- `12:27:29 hsync_infra_beat.go:86 infra beat failed peer=signer … no address available` — **once**.
- `12:27:29 hsync_transport.go:2277 RFI … KEYSTATE … signer … status=SUCCESS` — repeating every cycle.

The signer's KEYSTATE RFI path (`sendRfiToSigner`, which calls
`SetDiscoveryAddress` at 2255) succeeds at the same instant its
infra-beat fails, and persistently addresses the signer's transport
peer — so agent→signer works. The combiner has **no** recurring
address-setting path (agents fetch nothing from a combiner), so its
transport peer is only ever touched by addressless `GetOrCreatePeer`
and stays unreachable. Same defect, signer masked, combiner exposed.

## Fix

1. **Primary:** make `GetOrCreatePeer` set the discovery address from
   the agent's `DnsDetails` when the peer currently has none (mirror
   `SyncPeerFromAgent:1466`). Repairs all config-infra-peer send paths
   at once; preserves Bite H's skip of the redundant *state* refresh.
2. **Optional belt-and-braces:** seed the transport `PeerRegistry`
   peer with the configured address at init in `combiner_peer.go` /
   `signer_peer.go` (they currently write only the `AgentRegistry`).

## Verification

After fix + redeploy + restart: `agent peer ping --id combiner` works,
agent→combiner infra beats are acknowledged, and the queued espresso
edit drains to the combiner (contribution appears).

---

## What was implemented

- **Bug 2:** `GetOrCreatePeer` sets the discovery address from the
  agent's `DnsDetails` when the transport peer has none.
- **Bug 1:** new `zoneParticipants(apex)` + `apexHSYNCPARAM` helpers in
  `provider_groups.go`; `ZoneView.Participants() []PeerID` added to the
  hsync interface and implemented by `mpZoneView`; routed through
  `RecomputeGroups` (Members + group key + voting), `GetZoneAgentData`,
  `ReconcileZone` (`expected`), and `ApplyHsyncDiff` (add-gate, with a
  safe fallback to the periodic reconcile when the zone view is
  unavailable). OFF HSYNC3 records are excluded from label resolution.

## Notes / related

- **Dead parallel reconcile:** `AgentRegistry.ReconcileHsync` /
  `reconcileZone` / `reconcileAllZones` in `hsync_reconcile.go` use the
  buggy raw-HSYNC3 approach (`hsync3IdentitiesFromRRset`) and write the
  `AgentRegistry` directly. **They have no caller** (superseded by the
  hsync subpackage engine's reconcile), so they were left untouched —
  but if revived they must use `zoneParticipants`, or they re-introduce
  Bug 1. Candidate for deletion (another instance of the three-registry
  duplication).
- The `AgentRegistry` (`agent.Zones`) ↔ hsync `Registry`
  (`peer.Zones`) bridge has only an `OnPeerStored` hook (no removal);
  verify Bug 1's reconcile prunes propagate to `agent.Zones` (the
  source `listPeerSharedZones` reads). Add an `OnPeerRemoved`/zone hook
  if not.
- Stale comment in `start_auditor.go` claims the auditor "does NOT run
  HsyncEngine"; it does (via `NewAuditorEngine`). Correct in passing.

## Implementation / PR

Bugs 1 and 2 are independent (HSYNCPARAM membership vs infra-peer
address). Suggest separate commits/PRs. Bug 2 first — it is the live
blocker and unsticks the testbed.
