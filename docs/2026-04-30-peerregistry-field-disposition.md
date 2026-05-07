# PeerRegistry Field Disposition Map

Date: 2026-04-30
Status: AUDIT — pre-work for Phase 1 step 6 of the
        transport interface redesign (legacy single-state field
        deletion).

Companion to:
[2026-04-15-transport-interface-redesign.md](./2026-04-15-transport-interface-redesign.md)
[2026-04-25-transport-refactor-early-bites.md](./2026-04-25-transport-refactor-early-bites.md)
[2026-04-30-transport-refactor-semi-easy-bites.md](./2026-04-30-transport-refactor-semi-easy-bites.md)
(Bite A)

## Purpose

After Bites 1 + 7 (per-mechanism state on `Peer.Mechanisms` plus the
`PopulateFromAgent` helper), the original single-state fields on
`Peer` are duplicates: every receipt site dual-writes them. Phase 1
step 6 of the parent plan deletes the duplicates.

This document maps every field's read sites and the replacement
expression for each, so the eventual deletion bite is a mechanical
pass with no in-flight surprises. Closes parent-plan open item **L**.

## Method

For each in-scope field on the `Peer` struct
([tdns-transport/v2/transport/peer.go](../../tdns-transport/v2/transport/peer.go)
lines 55–101), grep both codebases for read sites (write sites are
deleted alongside, so they're listed in summary form only):

- `tdns-transport/v2/transport/`
- `tdns-mp/v2/`

Excluded from "read" sites:
- The struct declarations themselves
- The `MechanismState` struct
- Test files (`*_test.go`)
- Doc files (`*.md`)
- Field-name collisions on unrelated types (`Agent.State`,
  `PeerRecord.State`, `HsyncPeerInfo.State`, `KeyInventoryEntry.State`,
  `BeatRequest.State`, `RRTracked.State`, etc.)

A "read" means: appears on the right-hand side of an assignment, in
a condition, as a function argument, in a return value, in a struct
literal value, or in a log/format string.

## Scope

In scope (14 fields):

- `State PeerState`
- `StateReason string`
- `StateChanged time.Time`
- `DiscoveryAddr *Address`
- `OperationalAddr *Address`
- `APIEndpoint string`
- `LastHelloSent time.Time`
- `LastHelloReceived time.Time`
- `LastBeatSent time.Time`
- `LastBeatReceived time.Time`
- `BeatSequence uint64`
- `ConsecutiveFails int`
- `Stats MessageStats`
- `PreferredTransport string`

Out of scope (different concerns, kept on `Peer` for the foreseeable
future): `ID`, `DisplayName`, `LongTermPubKey`, `KeyType`,
`TLSARecord`, `Capabilities`, `SharedZones`, `ZoneRelation` (scope
fields are addressed in parent plan §A4; identity/crypto fields stay).

---

## Field 1: `State PeerState`

**Replacement:** `peer.EffectiveState()` (returns aggregate
`PeerState` across mechanisms).

**Read sites:**

| Site | Note | Replacement | Concerns |
|---|---|---|---|
| [tdns-transport/v2/transport/peer.go:240](../../tdns-transport/v2/transport/peer.go#L240) | `return p.State` (legacy fallback inside `EffectiveState`) | n/a — IS the fallback | keep until field deleted; then return zero-value |
| [tdns-transport/v2/transport/peer.go:516](../../tdns-transport/v2/transport/peer.go#L516) | `GetState()` returns `p.State` | rewire to `p.EffectiveState()` | trivial |
| [tdns-transport/v2/transport/peer.go:603](../../tdns-transport/v2/transport/peer.go#L603) | `IsHealthy`: `p.State == Operational \|\| p.State == Degraded` | `s := p.EffectiveState(); s == Operational \|\| s == Degraded` | minor semantic shift: aggregate-health, not legacy-field-health |
| [tdns-mp/v2/db_hsync.go:535](../../tdns-mp/v2/db_hsync.go#L535) | `peerStateToString(peer.State)` (PeerRecord build) | `peerStateToString(peer.EffectiveState())` | persisted state should reflect aggregate |
| [tdns-mp/v2/apihandler_router.go:216](../../tdns-mp/v2/apihandler_router.go#L216) | `"state": string(peer.State)` (debug metrics map) | `peer.EffectiveState().String()` | observability only |

**Summary:** 5 read sites — 3 trivial, 1 in-method fallback,
1 (`IsHealthy`) with a minor semantic shift to confirm.

---

## Field 2: `StateReason string`

**Replacement:** none needed — field is **write-only** outside
its declaring file. If a downstream consumer eventually wants the
reason, add `EffectiveStateReason() string`.

**Read sites:** none.

**Summary:** 0 read sites of `transport.Peer.StateReason`. The hits
in `tdns-mp/v2/db_hsync.go` and `cli/hsync_cmds.go` are on
`PeerRecord` / `HsyncPeerInfo`, not `transport.Peer`. Deletion is
one-swing safe.

---

## Field 3: `StateChanged time.Time`

**Replacement:** none needed — write-only outside the declaring
file.

**Read sites:** none.

**Summary:** 0 read sites. Deletion one-swing safe.

---

## Field 4: `DiscoveryAddr *Address`

**Replacement:** `peer.CurrentAddress()` (already encapsulates
discovery+operational precedence) for normal use, OR
`peer.Mechanisms["DNS"].Address` for direct per-mechanism reads
that deliberately bypass operational-address overrides.

**Read sites:**

| Site | Note | Replacement | Concerns |
|---|---|---|---|
| [tdns-transport/v2/transport/peer.go:528](../../tdns-transport/v2/transport/peer.go#L528) | `return p.DiscoveryAddr` (fallback in `CurrentAddress`) | n/a — IS the encapsulation | mechanism-aware: assumes single DNS address |
| [tdns-mp/v2/db_hsync.go:541](../../tdns-mp/v2/db_hsync.go#L541) | `if addr := peer.DiscoveryAddr; addr != nil` (PeerRecord build) | `peer.Mechanisms["DNS"].Address` | bypasses CurrentAddress on purpose; record needs raw discovery |

**Summary:** 2 read sites — 1 internal to `CurrentAddress`, 1 in
`db_hsync.go` deliberately bypasses CurrentAddress to persist the
discovery address separately. The db_hsync code currently
disambiguates API vs DNS via `PreferredTransport`; after migration
it should iterate `peer.Mechanisms["API"]` and `peer.Mechanisms["DNS"]`
directly. Flag: SEMANTIC — db_hsync row-build code restructures.

---

## Field 5: `OperationalAddr *Address`

**Replacement:** `peer.CurrentAddress()` (preferred). Direct reads
need a per-mechanism replacement that doesn't yet exist —
`MechanismState` has only one `Address` field.

**Read sites:**

| Site | Note | Replacement | Concerns |
|---|---|---|---|
| [tdns-transport/v2/transport/peer.go:525](../../tdns-transport/v2/transport/peer.go#L525) | `if p.OperationalAddr != nil` (in `CurrentAddress`) | n/a — IS the encapsulation | trivial |
| [tdns-transport/v2/transport/peer.go:526](../../tdns-transport/v2/transport/peer.go#L526) | `return p.OperationalAddr` (in `CurrentAddress`) | n/a — IS the encapsulation | trivial |
| [tdns-mp/v2/db_hsync.go:554](../../tdns-mp/v2/db_hsync.go#L554) | `if addr := peer.OperationalAddr; addr != nil` (PeerRecord build) | not yet expressible per-mechanism | **PRECURSOR** |

**Summary:** 3 read sites; 2 inside the encapsulation. The
db_hsync.go:554 read persists the post-Relocate address separately
from the discovery address. **Precursor decision needed:** either
(a) add `MechanismState.OperationalAddress` (two addresses per
mechanism), or (b) accept that `CurrentAddress` is the only address
and stop persisting them separately.

---

## Field 6: `APIEndpoint string`

**Replacement:** `peer.Mechanisms["API"].Address` exists, but its
type is `*Address` (host/port/transport) while `APIEndpoint` is a
URL string. **Precursor needed:** add `(p *Peer) APIURL() string`
that returns the URL for the API mechanism (or `""`).

**Read sites:**

| Site | Note | Replacement | Concerns |
|---|---|---|---|
| [tdns-transport/v2/transport/peer.go:196](../../tdns-transport/v2/transport/peer.go#L196) | `return p.APIEndpoint != ""` in `HasMechanism("API")` | check `p.Mechanisms["API"]` presence | encapsulated; deletes alongside |
| [tdns-transport/v2/transport/manager.go:205](../../tdns-transport/v2/transport/manager.go#L205) | `tm.APITransport != nil && peer.APIEndpoint != ""` (SelectTransport, "API" branch) | `peer.HasMechanism("API")` | trivial |
| [tdns-transport/v2/transport/manager.go:211](../../tdns-transport/v2/transport/manager.go#L211) | `tm.APITransport != nil && peer.APIEndpoint != ""` (SelectTransport, default branch) | `peer.HasMechanism("API")` | trivial |
| [tdns-transport/v2/transport/api.go:75](../../tdns-transport/v2/transport/api.go#L75) | `if peer.APIEndpoint == ""` in `apiURL` (error guard) | `peer.APIURL() == ""` | **PRECURSOR**: needs URL helper |
| [tdns-transport/v2/transport/api.go:84](../../tdns-transport/v2/transport/api.go#L84) | `return peer.APIEndpoint + path, nil` (URL construction) | `peer.APIURL() + path` | **PRECURSOR** |
| [tdns-mp/v2/hsync_transport.go:1362](../../tdns-mp/v2/hsync_transport.go#L1362) | `tm.APITransport != nil && peer.APIEndpoint != ""` (SelectTransport in MPTransportBridge) | `peer.HasMechanism("API")` | trivial; duplicate of manager.go |
| [tdns-mp/v2/hsync_transport.go:1368](../../tdns-mp/v2/hsync_transport.go#L1368) | same, default branch | `peer.HasMechanism("API")` | trivial |
| [tdns-mp/v2/hsync_transport.go:1579](../../tdns-mp/v2/hsync_transport.go#L1579) | same, in SendPing | `peer.HasMechanism("API")` | trivial |
| [tdns-mp/v2/apihandler_agent_distrib.go:378](../../tdns-mp/v2/apihandler_agent_distrib.go#L378) | `if peer.APIEndpoint != ""` (debug map presence test) | `peer.HasMechanism("API")` | trivial |
| [tdns-mp/v2/apihandler_agent_distrib.go:379](../../tdns-mp/v2/apihandler_agent_distrib.go#L379) | `discoveryInfo["api_uri"] = peer.APIEndpoint` (string value) | `peer.APIURL()` | **PRECURSOR** |
| [tdns-mp/v2/apihandler_peer.go:179](../../tdns-mp/v2/apihandler_peer.go#L179) | `if peer.APIEndpoint == ""` (apiping guard) | `peer.HasMechanism("API")` | trivial |
| [tdns-mp/v2/apihandler_peer.go:184](../../tdns-mp/v2/apihandler_peer.go#L184) | `url := strings.TrimSuffix(peer.APIEndpoint, "/") + "/ping"` | `peer.APIURL()` + trim | **PRECURSOR** |
| [tdns-mp/v2/db_hsync.go:533](../../tdns-mp/v2/db_hsync.go#L533) | `APIEndpoint: peer.APIEndpoint` (PeerRecord field) | `peer.APIURL()` | **PRECURSOR** |

**Summary:** 13 read sites. 8 are presence-only (trivial after
`HasMechanism`). 5 require the URL string itself and need the
`APIURL()` helper as a precursor. The Address-vs-URL type mismatch
makes `peer.Mechanisms["API"].Address.String()` a fragile direct
replacement — the helper isolates the encoding.

---

## Field 7: `LastHelloSent time.Time`

**Replacement:** `peer.Mechanisms[mech].LastHelloSent` (no
non-test reads exist).

**Read sites:** none.

**Summary:** 0 read sites. Field is dead at the Peer level. Only
write site is in the dual-write plumbing. One-swing safe.

---

## Field 8: `LastHelloReceived time.Time`

**Replacement:** `peer.Mechanisms[mech].LastHelloRecv`.

**Read sites:**

| Site | Note | Replacement | Concerns |
|---|---|---|---|
| [tdns-mp/v2/hsync_transport.go:600](../../tdns-mp/v2/hsync_transport.go#L600) | `peer.SetMechanismLastHelloRecv("DNS", peer.LastHelloReceived)` (dual-write fan-out) | n/a — dual-write plumbing | deletes with field |

**Summary:** 1 "read" — only forwarding the just-written value into
the per-mechanism setter. Disappears alongside the dual-write.

---

## Field 9: `LastBeatSent time.Time`

**Replacement:** `peer.Mechanisms[mech].LastBeatSent`.

**Read sites:** none.

**Summary:** 0 read sites. Only write is in `RecordBeatSent`
([peer.go:580](../../tdns-transport/v2/transport/peer.go#L580)).
**PRECURSOR:** `RecordBeatSent` has no `mech` parameter; either
extend the signature or replace it with `RecordBeatSentOn(mech)`.
See "Beat trio" group below.

---

## Field 10: `LastBeatReceived time.Time`

**Replacement:** `peer.Mechanisms[mech].LastBeatRecv` via
`SetMechanismLastBeatRecv`.

**Read sites:**

| Site | Note | Replacement | Concerns |
|---|---|---|---|
| [tdns-mp/v2/hsync_transport.go:686](../../tdns-mp/v2/hsync_transport.go#L686) | `peer.SetMechanismLastBeatRecv("DNS", peer.LastBeatReceived)` (dual-write fan-out) | n/a | deletes with field |
| [tdns-mp/v2/hsync_transport.go:770](../../tdns-mp/v2/hsync_transport.go#L770) | same, ping handler | n/a | deletes with field |
| [tdns-mp/v2/signer_msg_handler.go:60](../../tdns-mp/v2/signer_msg_handler.go#L60) | same, signer | n/a | deletes with field |
| [tdns-mp/v2/combiner_msg_handler.go:75](../../tdns-mp/v2/combiner_msg_handler.go#L75) | same, combiner | n/a | deletes with field |

**Summary:** 4 reads, all dual-write plumbing. One-swing safe.

---

## Field 11: `BeatSequence uint64`

**Replacement:** `peer.Mechanisms[mech].BeatSequence`.

**Read sites:** none.

**Summary:** 0 read sites. Only write is `p.BeatSequence++` in
`RecordBeatSent`. Same precursor as Field 9 — see "Beat trio".

---

## Field 12: `ConsecutiveFails int`

**Replacement:** `peer.Mechanisms[mech].ConsecutiveFails`.

**Read sites:** none.

**Summary:** 0 read sites. Writes only (`RecordBeatReceived` resets
to 0, `RecordFailure` increments). Same precursor — see "Beat trio".

---

## Field 13: `Stats MessageStats`

**Replacement:** `peer.Mechanisms[mech].Stats` for mechanism-aware
sites; **precursor needed** for sites that want aggregate counts:
add `(p *Peer) AggregateStats() MessageStatsSnapshot` summing all
mechanisms.

**Read sites:**

| Site | Note | Replacement | Concerns |
|---|---|---|---|
| [tdns-transport/v2/transport/stats_middleware.go:50](../../tdns-transport/v2/transport/stats_middleware.go#L50) | `peer.Stats.RecordMessageReceived(msgType)` | per-mechanism via ctx | **PRECURSOR**: middleware needs mech tag from ctx |
| [tdns-transport/v2/transport/stats_middleware.go:52](../../tdns-transport/v2/transport/stats_middleware.go#L52) | `peer.Stats.GetStats()` (debug log of totals) | `peer.AggregateStats()` | needs aggregate accessor |
| [tdns-transport/v2/transport/dns.go:900](../../tdns-transport/v2/transport/dns.go#L900) | `peer.Stats.RecordMessageSent("confirm")` | `peer.Mechanisms["DNS"].Stats.RecordMessageSent("confirm")` | trivial — context is DNS transport |
| [tdns-transport/v2/transport/dns.go:961](../../tdns-transport/v2/transport/dns.go#L961) | `peer.Stats.RecordMessageSent("status-update")` | same | trivial |
| [tdns-transport/v2/transport/dns.go:1063](../../tdns-transport/v2/transport/dns.go#L1063) | `peer.Stats.RecordMessageSent(opType)` | same | trivial |
| [tdns-mp/v2/apihandler_router.go:197](../../tdns-mp/v2/apihandler_router.go#L197) | `peer.Stats.GetDetailedStats()` (router metrics — aggregate) | `peer.AggregateStats()` | needs aggregate |
| [tdns-mp/v2/apihandler_signer_routes.go:84](../../tdns-mp/v2/apihandler_signer_routes.go#L84) | same (signer peer list) | `peer.AggregateStats()` | needs aggregate |
| [tdns-mp/v2/apihandler_agent_distrib.go:498](../../tdns-mp/v2/apihandler_agent_distrib.go#L498) | per-API-transport peer info | `peer.Mechanisms["API"].Stats.GetDetailedStats()` | mechanism-aware, trivial |
| [tdns-mp/v2/apihandler_agent_distrib.go:555](../../tdns-mp/v2/apihandler_agent_distrib.go#L555) | per-DNS-transport peer info | `peer.Mechanisms["DNS"].Stats.GetDetailedStats()` | mechanism-aware, trivial |
| [tdns-mp/v2/apihandler_agent_distrib.go:607](../../tdns-mp/v2/apihandler_agent_distrib.go#L607) | config-only / authorized-peer fallback | `peer.AggregateStats()` | needs aggregate |
| [tdns-mp/v2/apihandler_agent_distrib.go:645](../../tdns-mp/v2/apihandler_agent_distrib.go#L645) | registry-fallthrough peer info (both transports unknown) | `peer.AggregateStats()` | needs aggregate |

**Summary:** 11 read sites. 5 are mechanism-aware-able (DNS
transport file, plus distrib branches that already know which
transport is being shown). 6 want aggregate counts. **Precursors:**
1. `(p *Peer) AggregateStats() MessageStatsSnapshot`
2. Verify `stats_middleware` has the mechanism name in `ctx` so it
   can route writes to the right mech (likely already there as
   `ctx.TransportType` or similar — confirm before deleting)

---

## Field 14: `PreferredTransport string`

**Replacement:** `peer.PreferredMechanism()` (already exists;
returns "API" / "DNS" / "").

**Read sites:**

| Site | Note | Replacement | Concerns |
|---|---|---|---|
| [tdns-transport/v2/transport/manager.go:199](../../tdns-transport/v2/transport/manager.go#L199) | `switch peer.PreferredTransport` (SelectTransport) | `switch peer.PreferredMechanism()` | semantic shift: PreferredMechanism is availability-derived, PreferredTransport was set imperatively |
| [tdns-mp/v2/hsync_transport.go:485](../../tdns-mp/v2/hsync_transport.go#L485) | log field `"preferredTransport": peer.PreferredTransport` | `peer.PreferredMechanism()` | trivial |
| [tdns-mp/v2/hsync_transport.go:1356](../../tdns-mp/v2/hsync_transport.go#L1356) | `switch peer.PreferredTransport` (MPTransportBridge.SelectTransport) | `switch peer.PreferredMechanism()` | same semantic concern as manager.go:199 |
| [tdns-mp/v2/apihandler_agent_distrib.go:387](../../tdns-mp/v2/apihandler_agent_distrib.go#L387) | `discoveryInfo["preferred_transport"] = peer.PreferredTransport` (debug map) | `peer.PreferredMechanism()` | trivial |
| [tdns-mp/v2/db_hsync.go:534](../../tdns-mp/v2/db_hsync.go#L534) | `PreferredTransport: peer.PreferredTransport` (PeerRecord field) | `peer.PreferredMechanism()` | trivial — confirm db schema accepts "" |
| [tdns-mp/v2/db_hsync.go:542](../../tdns-mp/v2/db_hsync.go#L542) | `if peer.PreferredTransport == "API" \|\| peer.PreferredTransport == "api"` (PeerRecord build branch) | `peer.PreferredMechanism() == "API"` | "api" lower-case branch likely dead |

**Summary:** 6 read sites. 4 trivial. 2 inside `SelectTransport`
switch with a **semantic shift**: `PreferredMechanism()` is computed
from current availability, while `PreferredTransport` was set once
at discovery. After migration, a peer whose API endpoint disappears
would automatically fall back to DNS — likely the desired behavior,
but flag for confirmation.

---

## Deletion Phase Ordering

### Group A — One-swing-safe, no precursor

These can be deleted in a single commit with no helper additions:

1. **StateReason** (Field 2) — 0 reads
2. **StateChanged** (Field 3) — 0 reads
3. **LastHelloSent** (Field 7) — 0 reads
4. **LastHelloReceived** (Field 8) — only dual-write plumbing
5. **LastBeatReceived** (Field 10) — only dual-write plumbing

Estimated diff: ~25 lines.

### Group B — Trivial precursor (helpers already exist)

6. **State** (Field 1) — confirm `IsHealthy` semantic shift, then
   replace with `EffectiveState()`. Helper exists.
7. **PreferredTransport** (Field 14) — replace with
   `PreferredMechanism()`. Helper exists. Confirm semantic
   (availability-derived vs sticky) is acceptable.
8. **DiscoveryAddr** (Field 4) — db_hsync.go:541 needs a small
   refactor to iterate `Mechanisms` instead of single field.

### Group C — Real precursor needed

9. **APIEndpoint** (Field 6) — **add `(p *Peer) APIURL() string`**
   before deletion. Five read sites need the URL string. Without the
   helper every caller has to know that "API" mechanism's `Address`
   carries a URL while "DNS" mechanism's `Address` is host/port —
   fragile.
10. **OperationalAddr** (Field 5) — db_hsync.go:554 persists
    post-Relocate address separately from discovery. **Decision
    required:** (a) add `MechanismState.OperationalAddress`, or
    (b) accept that `CurrentAddress` is the only address and stop
    persisting them separately.
11. **Beat trio** — `LastBeatSent` (Field 9), `BeatSequence`
    (Field 11), `ConsecutiveFails` (Field 12) all move together
    because they're written by `RecordBeatSent` /
    `RecordBeatReceived` / `RecordFailure`. Need mech-aware variants
    (`RecordBeatSentOn(mech string)`, etc.) before the legacy
    fields can go. Treat as a single deletion unit.
12. **Stats** (Field 13) — **add `(p *Peer) AggregateStats()
    MessageStatsSnapshot`** before deletion. 6 of 11 read sites
    need aggregates. Also confirm `stats_middleware` has the
    mechanism name in `ctx` to route per-mech writes.

### Recommended execution order

1. **Group A** (one PR): delete the 5 zero/trivial fields. Smallest,
   most rewarding diff.
2. **APIURL helper + APIEndpoint deletion** (one PR): touches 13
   sites at once, isolated by the helper.
3. **AggregateStats helper + Stats deletion** (one PR): mechanical
   after the helper lands.
4. **Beat trio refactor** (one PR): mech-aware
   `RecordBeatSent`/`RecordBeatReceived`/`RecordFailure` plus the
   three field deletions together.
5. **State + PreferredTransport** (one PR): semantic-shift
   confirmations baked into the commit message.
6. **DiscoveryAddr / OperationalAddr** (last PR): the
   address-persistence question is the messiest — settle the
   `OperationalAddress` design before touching the db_hsync code.

### Cross-cutting concern

The mechanism-name plumbing in
[tdns-transport/v2/transport/stats_middleware.go](../../tdns-transport/v2/transport/stats_middleware.go)
needs an audit before Group C #4 (Stats) — verify the middleware
actually knows whether it's processing API or DNS traffic. If not,
that's an additional precursor. (Likely already there; just
verify.)
