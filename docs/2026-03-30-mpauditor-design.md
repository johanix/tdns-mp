# TDNS MP Auditor Design

Date: 2026-03-30
Last updated: 2026-04-27
Status: DESIGN — revised for `mpauditor-2` reboot

## Revision history

- **2026-04-27 (c)**: Added Size Estimate section
  (per-phase LOC estimate, anchored to actual file sizes
  on the abandoned `mpauditor-1` branch).
- **2026-04-27 (b)**: Split the original `mpauditor-1`
  "associate zones with peers" work into two distinct
  pieces. `RecomputeGroups()` is needed for the auditor
  to interpret incoming gossip (name groups, attribute
  zones, fire mutual-OPERATIONAL transitions) and is
  pure-zone-data — promoted into Phase A as a single
  callback. `auditorAssociateZonePeers` (the registry-
  poking part) remains deferred — it is only needed for
  outbound BEAT advertisement of zones to as-yet-unseen
  peers.
- **2026-04-27 (a)**: Reboot revision. Original
  `mpauditor-1` branch abandoned mid-flight during repo
  split; design re-targeted to a fresh `mpauditor-2`
  branch off current tdns-mp main. Phase 1 (tdns-side
  protocol support) is already merged on tdns main, with
  one shape change from the original design —
  `HSYNCPARAM_AUDITORS` is plural (list of labels), not
  singular. Phase 2 stub (`SetupMPAuditorRoutes`) also
  already merged on tdns-mp main. Phasing renumbered to
  reflect what is already done; transport-boundary test
  harness added as Phase 0; web dashboard kept in scope.

## Overview

The auditor is a read-only observer that participates in
the multi-provider HSYNC protocol but never contributes
zone data. It maintains a complete "current state"
representation of each zone by receiving all SYNC
operations, BEATs (gossip), and confirmations — enabling
reporting, dashboards, and compliance auditing.

## Protocol Integration

### HSYNC3 Presence

The auditor appears in the zone's HSYNC3 RRset like any
other provider:

```
example.com. 3600 IN HSYNC3 ON auditor audit.example.com. .
```

- **State**: ON (participates in protocol)
- **Label**: short identifier (e.g. "auditor")
- **Identity**: FQDN for discovery (e.g. "audit.example.com.")
- **Upstream**: "." (no upstream — the auditor doesn't
  replicate from anyone in the provider chain)

Being in HSYNC3 means:
- Other agents discover the auditor via DNS
- The auditor appears in provider groups
- The auditor receives BEATs (gossip protocol)
- The auditor is included in peer lists

### HSYNCPARAM Declaration

SvcParam `auditors=` declares which HSYNC3 labels are
auditors. The value is a comma-separated list of labels;
a zone may have multiple auditors:

```
example.com. 3600 IN HSYNCPARAM signers="alpha,echo" \
                                auditors="auditor1,auditor2"
```

This enables:
- Agents to identify auditors and include them as
  mandatory SYNC recipients
- The combiner to recognize auditor contributions as
  invalid (defense-in-depth)
- Policy engines to verify auditor participation

### HSYNCPARAM Implementation (merged)

Already on tdns main:

```go
HSYNCPARAM_AUDITORS HSYNCPARAMKey = 7 // "auditors"
```

Type: `HSYNCPARAMAuditors{ Auditors []string }` in
`tdns/v2/core/rr_hsyncparam.go`. Accessors needed by
mpauditor (`GetAuditors() []string`,
`IsAuditorLabel(label) bool`) are not yet present and
must be added in tdns-mp helpers — the tdns repo is
under active development by other agents and must not
be touched from this work stream.

Note on shape change vs original design: the original
spec said singular `auditor=` (one label per zone). The
merged implementation is plural (list of labels). All
mpauditor logic must therefore handle a *set* of auditor
labels, not a single label.

## Behavioral Rules

### Rule 1: Mandatory SYNC Recipient

When an agent sends a SYNC (zone data update) to other
agents, the auditor MUST be included as a recipient.
This is enforced by the sending agent:

- `EnqueueForZoneAgents` already enqueues for all agents
  discovered via HSYNC3. The auditor is in HSYNC3, so it
  receives SYNCs automatically.
- No code change needed for sending — the auditor is
  just another peer.

### Rule 2: Mandatory Gossip Participant

The auditor participates in BEAT/gossip like any agent:
- Receives BEATs with gossip state from peers
- Sends BEATs with its own gossip state
- Included in provider group computation
- Participates in mutual OPERATIONAL detection

No special handling needed — gossip treats all HSYNC3
members equally.

### Rule 3: Read-Only (No Contributions)

The auditor MUST NOT contribute zone data:

**(a) Auditor self-enforcement:**
The auditor binary (tdns-mpauditor) simply never sends
SYNC operations with zone data. It has no SDE, no
combiner data, no local edits. It only sends:
- BEATs (heartbeat + gossip)
- HELLOs (peer introduction)
- PINGs (connectivity test)
- Empty SYNCs (in response to RFI SYNC, see rule 5)

**(b) Peer enforcement (defense-in-depth):**
When a receiving agent gets a SYNC from a sender, it
checks if the sender's label is in the declared auditor
set. If so, reject any non-empty data:

```go
if isAuditor(senderLabel, zd) { // senderLabel ∈ HSYNCPARAM_AUDITORS
    if len(syncReq.Records) > 0 ||
       len(syncReq.Operations) > 0 {
        return reject("auditor may not contribute data")
    }
}
```

**(c) Combiner enforcement (defense-in-depth):**
Same check in `combinerProcessOperations`: if the
sender's label is in the auditor set, reject all
non-empty operations.

### Rule 4: Leader Election Exclusion

The auditor MUST NOT participate in leader elections.
It should not become leader (leaders perform delegation
sync, key publication, etc. — all write operations).

Implementation: when computing election candidates,
exclude peers whose label is in the HSYNCPARAM auditor
set.

### Rule 5: RFI SYNC Response

When another agent sends RFI SYNC to request the
auditor's zone data, the auditor responds with an
empty SYNC. This satisfies the protocol expectation
(every RFI gets a response) without contributing data.

The agent's resync flow sends RFI SYNC to all peers.
The auditor responds with:

```go
SyncResponse{
    Status:  "ok",
    Records: map[string][]string{}, // empty
    Message: "auditor: no data to contribute",
}
```

## Application Architecture

The auditor is implemented entirely in tdns-mp. The agent
extraction is complete — all MP machinery (MPTransportBridge,
AgentRegistry, MsgQs, gossip, provider groups, etc.) is
local to tdns-mp. The only changes to tdns are the
HSYNCPARAM extension (new SvcParam key) and AppType.

### Binary: tdns-mpauditor

Lives in `tdns-mp/cmd/mpauditor/`. Uses `AppTypeMPAuditor`.

Startup follows the same pattern as mpagent:
1. `conf.MainInit()` → `tdns.MainInit()` for DNS infra,
   then `initMPAuditor()` for MP components
2. `conf.StartMPAuditor()` for engines

The `initMPAuditor` function in `main_init.go` is modeled
on `initMPAgent` but omits:
- SDE initialization (no sync state tracking)
- HsyncEngine (no outbound sync)
- Leader election wiring

It keeps:
- MPTransportBridge (for CHUNK transport)
- AgentRegistry (peer tracking, heartbeat monitoring)
- MsgQs (async message routing)
- Crypto (CHUNK payload decryption)
- Router (incoming message dispatch)
- Gossip (state exchange via BEATs)
- Provider group computation

### What the Auditor Runs

**From tdns (DNS infrastructure):**
- RefreshEngine (zone transfers from upstream)
- DnsEngine (serve zone data, handle NOTIFYs)
- NotifyHandler (process incoming NOTIFYs)
- APIdispatcher (management API)

**From tdns-mp (MP engines):**
- IncomingMessageRouter (CHUNK → router → handlers)
- AuditorMsgHandler (consumes MsgQs: Beat, Hello, Ping,
  Msg/Sync — stores state, logs events, never sends data)
- Gossip engine (state exchange via BEATs)
- Provider group computation (group membership)

**NOT run:**
- SynchedDataEngine (no tracking/confirmation state)
- HsyncEngine (no outbound sync operations)
- CombinerMsgHandler (not a combiner)
- SignerMsgHandler / KeyStateWorker (not a signer)
- Leader election (excluded by rule 4)

### Relationship to Existing Code

The auditor reuses most of the agent's transport and
discovery machinery from tdns-mp:
- `hsync_transport.go` — MPTransportBridge (as-is)
- `agent_authorization.go` — peer authorization (as-is)
- `agent_discovery.go` — peer discovery (as-is)
- `gossip.go` / `gossip_types.go` — gossip protocol (as-is)
- `provider_groups.go` — group computation (as-is)
- `hsync_beat.go` — beat processing (as-is)
- `hsync_hello.go` — hello processing (as-is)

New auditor-specific files:
- `auditor_msg_handler.go` — simplified message consumer
  (receives SYNCs/UPDATEs but doesn't send data)
- `auditor_state.go` — AuditZoneState, AuditProviderState
- `auditor_eventlog.go` — persistent event log (SQLite)
- `auditor_observations.go` — anomaly detection
- `apihandler_auditor.go` — `/audit/*` API endpoints
- `start_auditor.go` — StartMPAuditor

### State Maintained by Auditor

For each zone, the auditor maintains:

```go
type AuditZoneState struct {
    Zone          string
    Providers     map[string]*AuditProviderState
    LastRefresh   time.Time
    ZoneSerial    uint32
    Observations  []AuditObservation
}

type AuditProviderState struct {
    Identity       string
    Label          string
    IsSigner       bool
    LastBeat       time.Time
    LastSync       time.Time
    GossipState    string // from gossip protocol
    Contributions  map[string]map[uint16]int // owner→rrtype→count
    KeyInventory   []KeySummary // DNSKEYs seen
}

type AuditObservation struct {
    Time     time.Time
    Severity string // info, warning, error
    Zone     string
    Provider string
    Message  string
}
```

### Persistent Event Log

The auditor keeps a persistent, per-zone changelog of
all zone data modifications with timestamps and
originator. Stored in the auditor's SQLite database.

```go
type AuditEvent struct {
    ID         int64     // auto-increment
    Time       time.Time // when the change was received
    Zone       string    // zone name
    Originator string    // agent identity that sent the change
    DeliveredBy string   // transport sender (may differ if forwarded)
    EventType  string    // "sync", "update", "resync", "confirm"
    Summary    string    // human-readable summary of change
    RRsAdded   int       // count of RRs added
    RRsRemoved int       // count of RRs removed
    RRtypes    string    // comma-separated list of affected RRtypes
    Details    string    // JSON: full operation details (optional)
}
```

**Database schema:**

```sql
CREATE TABLE IF NOT EXISTS AuditEventLog (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    time        TEXT NOT NULL,        -- RFC3339
    zone        TEXT NOT NULL,
    originator  TEXT NOT NULL,
    delivered_by TEXT DEFAULT '',
    event_type  TEXT NOT NULL,
    summary     TEXT NOT NULL,
    rrs_added   INTEGER DEFAULT 0,
    rrs_removed INTEGER DEFAULT 0,
    rrtypes     TEXT DEFAULT '',
    details     TEXT DEFAULT ''       -- JSON
);
CREATE INDEX IF NOT EXISTS idx_audit_zone_time
    ON AuditEventLog(zone, time);
CREATE INDEX IF NOT EXISTS idx_audit_time
    ON AuditEventLog(time);
```

**When events are logged:**
- Every inbound SYNC/UPDATE with non-empty data
- Every confirmation received (ACCEPTED/REJECTED)
- Every resync (RFI SYNC received or sent)
- DNSKEY changes (new keys, removed keys)
- Provider state changes detected via gossip

**Event log management:**

The event log supports:
- **Retention cap**: configurable max age. Events older
  than the cap are automatically pruned. Config:
  ```yaml
  audit:
     event_log:
        retention: 168h   # 1 week
        prune_interval: 1h
  ```
- **Manual purge**: CLI command to drop events:
  ```
  mpcli auditor eventlog clear --zone whisky.dnslab.
  mpcli auditor eventlog clear --older-than 24h
  mpcli auditor eventlog clear --all
  ```
- **Query by zone and time range**:
  ```
  mpcli auditor eventlog list --zone whisky.dnslab.
  mpcli auditor eventlog list --zone whisky.dnslab. \
      --since 2026-03-30T00:00:00Z
  mpcli auditor eventlog list --last 100
  ```

**API endpoints:**

All auditor management goes through a single endpoint with a
command-dispatched JSON body. The path mirrors the auditor's role
name (matching `/agent`, `/combiner`, `/signer` for those roles)
rather than describing the action — i.e. `/auditor`, not `/audit`:

- `POST /api/v1/auditor` with JSON body:
  ```json
  {"command": "eventlog-list", "zone": "whisky.dnslab.",
   "since": "2026-03-30T00:00:00Z", "limit": 100}
  {"command": "eventlog-clear", "zone": "whisky.dnslab."}
  {"command": "eventlog-clear", "older_than": "168h"}
  {"command": "eventlog-clear", "all": true}
  ```

### Reporting Capabilities

The auditor exposes state via its management API. All commands go
through the single `POST /api/v1/auditor` endpoint:

- `command: "zones"` — list all audited zones with summary
- `command: "zone"` — detailed state for one zone
- `command: "observations"` — recent observations/anomalies
- `command: "eventlog-list"` — event log queries
- `command: "eventlog-clear"` — event log management

Wire-format DTOs (`AuditZoneSummary`, `AuditProviderSummary`,
`AuditEvent`, `AuditObservation`) are plain value types,
snapshotted from the runtime state types under their RWMutex.
Runtime types (`AuditZoneState`, `AuditProviderState`) are never
exposed directly over the API.

Observations the auditor can detect (Phase B and B' implemented;
others are future work):

- ✓ Unauthorized DNSKEY contribution (non-signer sent keys) — B
- ✓ Provider went silent (no BEAT for >N seconds) — B'
- ✓ Missing provider (listed in HSYNC3 but never seen) — B'
- SYNC data inconsistency (provider A and B disagree)
- Serial drift (zone serial mismatch between providers)
- NS inconsistency (different providers advertise
  different NS sets)

## Implementation Plan

Reboot on a fresh `mpauditor-2` branch off current
tdns-mp main. Cherry-pick the auditor-specific files from
the abandoned `mpauditor-1` branch rather than rebasing —
the original is 130+ commits stale and carries repo-split-
era merge artifacts that would collide on rebase. The
auditor-specific files (`auditor_*.go`,
`apihandler_auditor.go`, `cli/auditor_cmds.go`,
`cmd/mpauditor/`) are nearly self-contained and port
cleanly.

**Constraint**: the tdns repository is under active
development by other agents and must NOT be modified from
this work stream. Any tdns-side gap is worked around in
tdns-mp helpers, or queued for a separate coordination
step.

### Status of the originally-listed phases

| Original phase                  | Status on current main         |
|---------------------------------|--------------------------------|
| Phase 1 — Protocol support (tdns) | **Done** (with shape change) |
| Phase 2 — Auditor binary (tdns-mp) | **Stub only** (routes file)  |
| Phase 3 — Event log and state    | **Not started**                |
| Phase 4 — Reporting and CLI      | **Not started**                |
| Phase 5 — Enforcement            | **Not started**                |

What's already merged on tdns main:
- `HSYNCPARAM_AUDITORS` (key 7, plural — see HSYNCPARAM
  Implementation section)
- `HSYNCPARAMAuditors` type with pack/unpack/parse
- `AppTypeMPAuditor` + AppType guards in `enums.go`,
  `main_initfuncs.go`, `parseconfig.go`

What's already merged on tdns-mp main:
- `apihandler_auditor_routes.go` — stub
  `SetupMPAuditorRoutes` registering only the shared
  transport-layer endpoints (gossip/router/peer); no
  auditor-specific endpoints yet.
- `cmd/mpauditor/` directory exists but contains only a
  stale prebuilt binary (no source).

Gaps from the original Phase 1 design that mpauditor-2
must work around (without touching tdns):
- The `GetAuditors()` / `IsAuditorLabel(label)` accessors
  on `HSYNCPARAMAuditors` are not present in tdns. Provide
  equivalent helpers in tdns-mp (e.g. in a new
  `auditor_helpers.go`) that walk the HSYNCPARAM RRset
  directly.

### Phase 0: Transport boundary test harness

Land the harness from
`2026-04-23-transport-boundary-test-harness.md` first.
The harness is shared infrastructure — it gates the
upcoming transport interface redesign
(`2026-04-15-transport-interface-redesign.md`) and serves
as the regression net for mpauditor work.

For mpauditor purposes, the seven scenarios cover all the
boundary behaviors the auditor depends on (CHUNK → Msg,
Confirmation paths, Hello, discovery). No auditor-specific
scenarios are needed at this stage; auditor-specific tests
live above the boundary in MP land.

Done criteria: all seven scenarios pass via `go test` in
tdns-mp/v2, wired into the same CI gate the redesign will
use.

### Phase A: Auditor binary skeleton (tdns-mp)

1. Add `case "auditor"` to MainInit role switch.
2. Create `initMPAuditor` in `main_init.go` (modeled on
   `initMPAgent`: transport, crypto, chunk handler, peers,
   router, gossip — minus SDE and leader election).
3. Create `start_auditor.go` — `StartMPAuditor` (modeled
   on `StartMPAgent`: DNS engines + incoming message
   router + auditor msg handler — minus HsyncEngine/SDE).
4. Create `auditor_msg_handler.go` — simplified consumer
   that receives all message types, logs events, updates
   state, but never sends zone data.
5. Create `auditor_helpers.go` with `GetAuditors(zd)` and
   `IsAuditorLabel(zd, label)` reading the HSYNCPARAM
   RRset (substitute for the missing tdns accessors).
6. Wire `ar.ProviderGroupManager.RecomputeGroups()` into
   the auditor's zone-load path (see "Provider group
   recomputation" below).
7. Populate `cmd/mpauditor/` with main.go, Makefile,
   sample config.
8. Add "auditor" to `mpcli` shared_cmds.go.

#### Provider group recomputation

The agent triggers `RecomputeGroups()` from the
HSYNC-UPDATE flow inside `HsyncEngine`, which the
auditor does not run. Without a replacement call, the
auditor's `ProviderGroupManager` stays empty: incoming
gossip merges into `GossipStateTable.States[hash]` (the
merge is keyed on `GroupHash` and does not consult the
registry), but `GetGroup(hash)` returns nil — so the
dashboard cannot name groups, list members, or attribute
zones, and `CheckGroupState` cannot fire mutual-
OPERATIONAL transitions.

`RecomputeGroups` reads HSYNC3 RRsets from each loaded
zone and is a pure function of zone data — it does not
need `SharedZones`, `LocateAgent`, or any registry
poking. The auditor needs exactly one call after each
zone load (and a re-run on HSYNC3 change). Suggested
home: a small auditor-only branch in `MPPostRefresh`
that calls `ar.ProviderGroupManager.RecomputeGroups()`
and nothing else, or an `OnFirstLoad` callback
registered in `initMPAuditor` plus a re-run on HSYNC
change.

This is **distinct from** the deferred
`auditorAssociateZonePeers` work. That function calls
`LocateAgent`/`AddZoneToAgent` to populate
`SharedZones` so outbound BEATs advertise zones — needed
for the auditor to participate in gossip *as a sender*
of meaningful state about zones it hasn't yet seen
inbound traffic for. The Phase A `RecomputeGroups` call
is sufficient for the auditor's *observer* role
(receiving and interpreting gossip) regardless of
`SharedZones`.

### Phase B: Event log and audit state — DONE

8. Create `AuditEventLog` DB schema + CRUD functions. ✓
9. Log events from `AuditorMsgHandler` on every inbound
   SYNC/UPDATE/confirm/resync. ✓
10. Implement automatic retention pruning (background
    goroutine, configurable interval + max age). ✓
11. Implement `AuditZoneState` tracking (in-memory). ✓
12. Implement observation detection (per-message: unauthorized
    DNSKEY contribution from non-signers). ✓

### Phase B': Periodic detectors — DONE

12a. provider-silent detector (no BEAT within
     `audit.silence_threshold`, default 90s). ✓
12b. missing-provider detector (HSYNC3 identity never seen). ✓
     Both run from `StartAuditDetectors` on a configurable
     interval (`audit.detector_interval`, default 30s); state
     transitions emit one observation each, not one per tick.

### Phase C: Reporting — JSON API + CLI — DONE

13. Single `POST /api/v1/auditor` endpoint with command
    dispatch (`zones`, `zone`, `observations`, `eventlog-list`,
    `eventlog-clear`). Wire format uses snapshot DTOs
    (`AuditZoneSummary`, `AuditProviderSummary`); runtime
    state types are never exposed. ✓
14. mpcli auditor subcommands: ✓
    - `auditor eventlog list`
    - `auditor eventlog clear`
    - `auditor zones`
    - `auditor observations`

### Phase D: Web dashboard — DONE

The web dashboard runs on its own HTTPS listener under
`/web/*`, separate from the JSON API. It uses htmx + Pico
CSS templates ported from `mpauditor-1`.

15. Cherry-picked 9 templates + 3 static assets (htmx,
    pico, auditor.css) from `mpauditor-1`. ✓
16. Adapter functions (`buildDashboardData`,
    `buildZoneDetailData`, `buildEventLogData`,
    `buildProvidersData`, `buildObservationsData`,
    `buildGossipData`) in `auditor_web.go` snapshot state
    into a single `WebData` struct of DTOs. Templates only
    see DTOs (`AuditZoneSummary`, `AuditProviderSummary`,
    `GossipMatrixDTO`, etc.) — never runtime types. When
    the transport redesign moves/renames structs, only the
    adapter changes. ✓
17. `/web/*` routes registered with bcrypt auth + signed
    session cookies + sliding idle timeout (default 30m).
    `/web/login` (GET form, POST verify), `/web/logout`,
    `/web/status` (unauthenticated healthcheck), data
    pages and HTMX fragments behind `requireAuth`. ✓

**Auth**: multi-user, bcrypt-hashed passwords in YAML,
in-memory sessions with HMAC-signed cookies (`HttpOnly` +
`Secure` + `SameSite=Strict`). CSRF defended by
`SameSite=Strict` plus the dashboard being entirely
read-only (the only POST is `/web/login`).
`audit.web.auth.mode="none"` is permitted only when all
bind addresses are loopback — non-loopback no-auth refuses
to start.

**Gossip view (extension to mpauditor-1)**: per-group
N×N member×peer state matrix at `/web/gossip` and via
`{"command": "gossip"}` on `/api/v1/auditor`. Snapshotted
under both `ProviderGroupManager.mu` and
`GossipStateTable.mu`.

Done criteria: dashboard renders zone list, per-zone
provider state, providers, gossip matrix, recent events,
and observations. ✓

### Phase E: Enforcement

18. Add auditor rejection in agent SYNC processing.
19. Add auditor rejection in combiner processing.
20. Exclude auditor from leader elections.
21. Implement empty SYNC response for RFI.

### Deferred until after transport interface redesign

The following item is deferred until after the transport
redesign lands (`2026-04-15-transport-interface-redesign.md`)
to avoid rework when transport-layer types move/rename:

- `auditorAssociateZonePeers` in `MPPostRefresh`. Calls
  `LocateAgent`/`AddZoneToAgent` to populate
  `SharedZones` for HSYNC3-listed peers, so outbound
  BEATs advertise zones to peers the auditor has not yet
  received traffic from. The most invasive bit on shared
  MP code on the original branch (introduces a role-
  global check inside the cross-role `MPPostRefresh` hot
  path and reaches directly into `tm.agentRegistry`).
  Without it, the auditor still receives and interprets
  inbound gossip correctly (Phase A's `RecomputeGroups`
  call is sufficient for that). What is lost: the
  auditor's outbound BEATs do not advertise zone
  membership for peers it has not yet seen inbound
  traffic for, and the dashboard's "providers I haven't
  heard from yet" view is lossy until this lands. Add
  back as a clean callback once the transport redesign
  has decoupled `agentRegistry` access from role globals.

Note on the web dashboard: even though it renders structs
the redesign relocates, the rendering goes through the
Phase D adapter — so the post-redesign change is local to
`apihandler_auditor.go`, not the templates.

## Complexity Assessment

**Lower than agent** because:
- No SDE (no tracking/confirmation state machine)
- No outbound sync (read-only)
- No combiner interaction (doesn't contribute)
- No leader election participation
- Message handler is simplified (consume + store, never
  send data)

**Heavily reuses agent infrastructure** from tdns-mp:
- MPTransportBridge, AgentRegistry, MsgQs — as-is
- Gossip, provider groups — as-is
- Beat/Hello processing — as-is
- Crypto, chunk handler, router — as-is

**New work:**
- HSYNCPARAM auditor SvcParam (small, in tdns)
- initMPAuditor + StartMPAuditor (modeled on agent)
- AuditorMsgHandler (simplified agent handler)
- Audit state tracking (new data model)
- Persistent event log (new SQLite table + CRUD)
- Reporting API (new endpoints)
- CLI commands (new)
- Enforcement checks (small additions to existing code)

## Risk

Low-medium. The auditor is additive — it doesn't change
existing behavior. The enforcement rules (reject auditor
contributions) are defense-in-depth; the primary
enforcement is that the auditor binary simply doesn't
send data.

The protocol integration (HSYNC3 + HSYNCPARAM) is
straightforward — the auditor is just another provider
with special policy.

## Size Estimate

Per-phase line-of-code estimate. Numbers in **ref**
columns are the actual sizes of the corresponding files
on the abandoned `mpauditor-1` branch (sampled
2026-04-27); they are an upper bound for cherry-pick
scope. **est** is the realistic delta to land each phase
on `mpauditor-2` after porting + rework.

| Phase | Component                              | ref | est | Notes |
|-------|----------------------------------------|-----|-----|-------|
| 0     | Transport boundary test harness        | —   | 1500–2500 | Per the harness doc: env builder + 7 scenarios. Test code, not production. Most of this serves the transport redesign too — not properly chargeable to mpauditor alone. |
| A     | `auditor_msg_handler.go`               | 200 | ~220 | Simplified agent msg consumer. |
| A     | `start_auditor.go`                      | 162 | ~180 | Modeled on `start_agent.go` (411 LOC) minus HsyncEngine/SDE/leader-election wiring. |
| A     | `initMPAuditor` (in `main_init.go`)    | —   | ~120 | New case branch; smaller than `initMPAgent` for the same reason as start. |
| A     | `auditor_helpers.go` (`GetAuditors` etc.) | 89 | ~100 | Local substitute for missing tdns accessors + label-set predicates. |
| A     | `RecomputeGroups()` wiring             | —   | ~30 | Single-call hook in `MPPostRefresh` or `OnFirstLoad`. |
| A     | `cmd/mpauditor/` (main + Makefile + sample yaml) | 70 | ~100 | main.go is small; Makefile + sample mostly cherry-pickable. |
| A     | `mpcli` "auditor" wiring               | —   | ~80 | New shared_cmds entry + role gating. |
| A     | **subtotal**                           |     | **~830** | |
| B     | `auditor_state.go`                     | 151 | ~170 | `AuditZoneState`, `AuditProviderState`, `AuditObservation`. |
| B     | `auditor_eventlog.go`                  | 184 | ~200 | Schema, CRUD, retention pruner. |
| B     | Observation detection                  | —   | ~150 | Not present as a separate file on the branch — folded into msg handler / state. Estimate based on rules listed in design (silent provider, serial drift, NS inconsistency, etc.). |
| B     | Eventlog logging hooks in handler      | —   | ~80 | Edits to `auditor_msg_handler.go` to call `InsertAuditEvent` on each event class. |
| B     | **subtotal**                           |     | **~600** | |
| C     | `apihandler_auditor.go` (real)         | 197 | ~220 | Replaces the existing 17-LOC stub. `/audit/zones`, `/audit/zone`, `/audit/providers`, `/audit/observations`, `/audit/eventlog`. |
| C     | `cli/auditor_cmds.go`                  | 399 | ~430 | `eventlog list/clear`, `zones`, `observations`. |
| C     | API request/response struct types      | —   | ~80 | New `api_audit_*_structs.go`. |
| C     | **subtotal**                           |     | **~730** | |
| D     | `auditor_web.go` (handler + adapter)   | 396 | ~440 | Includes the new transport-struct adapter layer (~50 LOC delta vs. branch). |
| D     | `auditor_web_templates/*.html` (10 files) | 376 | ~376 | Cherry-pick verbatim if shape allows; otherwise minor. |
| D     | `auditor_web_static/*` (htmx, pico, css) | — | 0 | Vendored libraries + ~50-LOC `auditor.css`. Not counted as new LOC. |
| D     | **subtotal**                           |     | **~820** | |
| E     | Auditor SYNC rejection in agent path   | —   | ~30 | `isAuditor(senderLabel, zd)` check + reject. |
| E     | Auditor SYNC rejection in combiner path | —  | ~30 | Same shape, different file. |
| E     | Leader election exclusion              | —   | ~20 | Filter on candidate computation. |
| E     | Empty SYNC response for RFI            | —   | ~30 | One handler branch. |
| E     | **subtotal**                           |     | **~110** | |
|       | **Total production code (Phases A–E)** |     | **~3100** | |
|       | **Plus harness (Phase 0, shared)**     |     | ~1500–2500 | |

Excluded from totals: vendored static assets (htmx, pico
CSS), prebuilt binaries, generated `go.sum`.

Excluded from initial scope (deferred):
`auditorAssociateZonePeers` (~50 LOC plus its hook in
`MPPostRefresh`).

The estimate's largest soft spot is observation
detection (Phase B), which exists only sketchily on the
branch — the ~150 LOC figure is for the rules listed in
this doc, not a measured port. If the rule set grows,
that figure grows linearly.
