# A3d dead-code triage — review before deletion

Date: 2026-06-03. Branch: `transport-redesign-v1-A`.
Companion to `2026-06-01-a3d-field-ownership.md`.

## Why this doc

The A3d field slices kept stalling because `AgentDetails` is riddled with
dead code that masks the live migration surface. Rather than wholesale-delete
(which would erase the record of features we started and never finished), this
triages the dead set into:

- **(A) Superseded / residue** — a live replacement does the same job, or the
  code has zero references. Safe to delete; deletion is INVARIANT and
  compiler-proven (if it still builds, nothing live referenced it).
- **(B) Abandoned-feature candidates** — written by live code but **read by
  nothing**; no live equivalent. These are *lost intent*. **Do NOT delete
  without operator review** — decide per item: **finish / keep / drop**.

Scope is bounded: the dead set found during the A3d audits (the `AgentDetails`
surface + the MP liveness/discovery functions it implicated) plus what falls
out when those go. Not a whole-repo hunt.

Evidence convention: "read by bridge only" = the only readers are the
`hsync_bridge_sync.go` converters, which copy the field between `AgentDetails`
and `hsync.PeerDetails` but feed no consumer; those converters are themselves
slated for teardown (A5).

---

## (A) Superseded / residue — safe to delete

| Item | Evidence | Replaced by / status | Verdict |
|---|---|---|---|
| MP `CheckState` (`hsync_beat.go:57`) | **0 callers** | NG `checkPeerState` (`hsync/beat.go:104`, live) does the same DEGRADED/INTERRUPTED liveness | delete |
| `FetchSVCB` (`agent_utils.go`) | 0 callers (only the deleted legacy `LocateAgent` used it) | `Imr.LookupServiceAddresses` (NG discovery, `agent_discovery_common.go`) | delete |
| `AgentDetails.Host` | **0 references** (writes were in the deleted `LocateAgent`) | residue | delete |
| `AgentDetails.Endpoint` | **0 references** | residue (already flagged "delete, 0 uses" in field-ownership §4) | delete |
| `AgentDetails.BeatInterval` | written by live `HeartbeatHandler` (`hsync_beat.go:21/25`) but **read only by the dead `CheckState`** + bridge | NG keeps its own `hsync.PeerDetails.BeatInterval` (live, read by `checkPeerState`) | delete (with CheckState) |

Removing `CheckState` may orphan helpers used only by it — the compiler will
surface those at deletion time; they extend this (A) set.

---

## (B) Abandoned-feature candidates — REVIEW, do not delete blind

All of these were **recognized by the operator** (2026-06-03) as features
started and not finished. They form one half-built capability:
**per-peer diagnostics** (why a peer is failing / when last seen / beat counts),
written on the live hello/beat paths but **never wired to any display, JSON, or
logic consumer** — on *either* the MP side (`AgentDetails`) or the NG side
(`hsync.PeerDetails`). The `HsyncPeerInfo` debug DTO (`agent_structs.go:460`,
fields `LastContactAt`/`BeatsReceived`/`FailedContacts`/…) that would have
surfaced it is never instantiated.

| Field (MP `AgentDetails`) | Written by (live) | Read by | NG mirror (`hsync.PeerDetails`) | Apparent intent |
|---|---|---|---|---|
| `LatestError` | hello/beat fail+reset paths (`hsync_transport.go`, `hsync_infra_beat.go`, `apihandler_peer.go`) | **bridge only** | written by `hsync/beat.go`,`hsync/discovery.go`; **no consumer** | surface *why* a peer is failing (the gap we hand-patched in the "no transport available" debugging) |
| `LatestErrorTime` | same paths | **bridge only** | written; no consumer | timestamp for the above |
| `LastContactTime` | hello/beat receipt (`hsync_transport.go`) | **bridge only** | (not mirrored) | "last seen / staleness" display |
| `ReceivedBeats` | beat receipt (`hsync_transport.go:1700/1730`, `hsync_beat.go:20/24`) | **bridge only** | `hsync/transport_peer.go:99`; no consumer | beat-count metric (note `SentBeats` *is* read, for sequencing) |

Related, same feature, flag for review:
- `HsyncPeerInfo` DTO (`agent_structs.go:460`) — never instantiated; the
  intended display surface for the above.
- `hsync.PeerDetails.{LatestError,LatestErrorTime,LastContactTime,ReceivedBeats}`
  — the NG-side halves; share the verdict of their MP counterparts.

### Decision (operator to fill)

| Item | finish / keep / drop | notes |
|---|---|---|
| `LatestError` + `LatestErrorTime` (peer error surfacing) | | |
| `LastContactTime` (last-seen) | | |
| `ReceivedBeats` (beat metric) | | |
| `HsyncPeerInfo` DTO | | |

- **drop** → I remove the field(s) + their writes + bridge refs (+ NG mirror),
  one reviewed commit.
- **finish** → wire a reader (e.g. expose in `peer list -v` / a JSON field) so
  the data the live paths already collect becomes visible — turns dead writes
  into a working feature.
- **keep** → leave as-is, note as a tracked loose end.

---

## After this triage

Deleting the (A) set shrinks `AgentDetails` to its live fields — `State`,
`Addrs`/`Port`, `BaseUri`, the crypto group (`KeyRR`/`TlsaRR`/`UriRR`/`JWKData`/
`KeyAlgorithm`), `HelloTime`, `LatestSBeat`/`LatestRBeat`, `DiscoveryFailures`,
`SentBeats` — making the remaining A3d migration finite and clear:
- crypto group → `agentMeta` (A3d.3);
- `State` + address + `HelloTime`/`LatestSBeat`/`LatestRBeat` +
  `DiscoveryFailures` → `transport.Peer` (the spine cluster).

`(B)` outcomes feed the same shrink (drop) or become a small finish-it task.
