# TDNS MP Auditor Design

Date: 2026-03-30
Status: DESIGN

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

New SvcParam `auditor=` declares which HSYNC3 label is
the auditor:

```
example.com. 3600 IN HSYNCPARAM signers="alpha,echo" \
                                auditor="auditor"
```

The value is a single HSYNC3 label. A zone may have at
most one auditor (like it has at most one set of signers).

This enables:
- Agents to identify the auditor and include it as a
  mandatory SYNC recipient
- The combiner to recognize auditor contributions as
  invalid (defense-in-depth)
- Policy engines to verify auditor participation

### HSYNCPARAM Implementation

Add new SvcParam key to existing enum:

```go
HSYNCPARAM_AUDITOR HSYNCPARAMKey = 7 // "label"
```

Type: `HSYNCPARAMAuditor` (string, single label).
Accessors: `GetAuditor() string`, `IsAuditorLabel(label) bool`.

Note: the existing `HSYNCPARAM_AUDIT` (key 2) is a boolean
"audit=yes/no" flag. The new `HSYNCPARAM_AUDITOR` (key 7)
names the specific auditor provider. These are distinct:
`audit=yes` enables audit mode, `auditor=label` identifies
who performs it.

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
checks if the sender is the declared auditor. If so,
reject any non-empty data:

```go
if isAuditor(senderLabel, zd) {
    if len(syncReq.Records) > 0 ||
       len(syncReq.Operations) > 0 {
        return reject("auditor may not contribute data")
    }
}
```

**(c) Combiner enforcement (defense-in-depth):**
Same check in `combinerProcessOperations`: if sender
is the auditor label, reject all non-empty operations.

### Rule 4: Leader Election Exclusion

The auditor MUST NOT participate in leader elections.
It should not become leader (leaders perform delegation
sync, key publication, etc. — all write operations).

Implementation: when computing election candidates,
exclude peers whose label matches the HSYNCPARAM
auditor label.

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

- `POST /audit/eventlog` with JSON body:
  ```json
  {"command": "list", "zone": "whisky.dnslab.",
   "since": "2026-03-30T00:00:00Z", "limit": 100}
  {"command": "clear", "zone": "whisky.dnslab."}
  {"command": "clear", "older_than": "168h"}
  {"command": "clear", "all": true}
  ```

### Reporting Capabilities

**JSON API** (for CLI and programmatic access):

- `POST /audit/zones` — list all audited zones with summary
- `POST /audit/zone` — detailed state for one zone
- `POST /audit/providers` — all providers across all zones
- `POST /audit/observations` — recent observations/anomalies
- `POST /audit/eventlog` — event log queries and management

**Observations** the auditor can detect:
- Provider went silent (no BEAT for >N seconds)
- SYNC data inconsistency (provider A and B disagree)
- Unauthorized DNSKEY contribution (non-signer sent keys)
- Missing provider (listed in HSYNC3 but never seen)
- Serial drift (zone serial mismatch between providers)
- NS inconsistency (different providers advertise
  different NS sets)

### Web Interface

The auditor provides a built-in web interface for
inspecting current state. Read-only — no mutations
from the browser.

**Technology: Go templates + HTMX**

Server-rendered HTML using Go's `html/template` package.
HTMX (~14KB) for dynamic partial-page updates without a
JavaScript framework. Pico CSS (~10KB) for clean default
styling. All assets embedded in the binary via `//go:embed`.

No Node.js, no npm, no build toolchain. The web interface
is compiled into the auditor binary.

**Pages:**

- `/web/` — dashboard overview: all zones, provider
  health summary, recent observations
- `/web/zone/{zone}` — zone detail: providers, current
  contributions (per-agent, per-RRtype), DNSKEY inventory,
  NS sets, gossip state
- `/web/eventlog` — event log browser with zone filter,
  time range, auto-refresh
- `/web/providers` — all providers across zones, last
  beat time, gossip state, operational status
- `/web/observations` — anomaly feed with severity,
  time, provider, zone

**Dynamic updates via HTMX:**

Pages use HTMX attributes for live updates without full
page reloads:

```html
<!-- Auto-refresh zone status every 10 seconds -->
<div hx-get="/web/fragment/zone-status?zone=whisky.dnslab."
     hx-trigger="every 10s"
     hx-swap="innerHTML">
  ... current status ...
</div>

<!-- Click to expand provider detail -->
<tr hx-get="/web/fragment/provider-detail?zone=whisky.dnslab.&provider=agent.alpha.dnslab."
    hx-target="#detail-panel"
    hx-swap="innerHTML">
  <td>agent.alpha.dnslab.</td>
  <td>OPERATIONAL</td>
  <td>2s ago</td>
</tr>
```

The server renders HTML fragments for HTMX requests
(detected via `HX-Request` header) and full pages for
normal requests.

**File structure in tdns-mp:**

```
v2/auditor_web.go              — HTTP handlers, template
                                 rendering, fragment handlers
v2/auditor_web_templates/      — Go HTML templates (embedded)
   layout.html                 — base layout (nav, head, CSS)
   dashboard.html              — overview page
   zone_detail.html            — per-zone detail
   eventlog.html               — event log browser
   providers.html              — provider list
   observations.html           — anomaly feed
   fragments/                  — HTMX partial templates
      zone_status.html
      provider_detail.html
      eventlog_rows.html
      observation_list.html
v2/auditor_web_static/         — static assets (embedded)
   htmx.min.js                 — HTMX library (~14KB)
   pico.min.css                — Pico CSS (~10KB)
   auditor.css                 — custom styles
```

**Configuration:**

```yaml
audit:
   web:
      enabled: true
      addresses: [ 127.0.0.1:8099 ]
      # No authentication — read-only, bind to localhost.
      # For remote access, put behind a reverse proxy with
      # auth (e.g. nginx + basic auth or OAuth).
```

**Separate listener:** The web interface runs on its own
HTTP listener, distinct from the management API (which
uses apikey authentication). The web interface has no
authentication by default (read-only, localhost only).
For production, deploy behind a reverse proxy with auth.

## Implementation Plan

All implementation in tdns-mp except Phase 1 items 1-4
which touch tdns (RR types and AppType).

### Phase 1: Protocol Support (tdns)

1. Add `HSYNCPARAM_AUDITOR` SvcParam (key 7) to
   tdns/v2/core/rr_hsyncparam.go
2. Add `GetAuditor()` and `IsAuditorLabel()` accessors
3. Add `AppTypeMPAuditor` to tdns/v2/enums.go
4. Add AppType guards in tdns (same pattern as
   MPSigner/MPCombiner/MPAgent)

### Phase 2: Auditor Binary (tdns-mp)

5. Add `case "auditor"` to MainInit role switch
6. Create `initMPAuditor` in main_init.go (modeled on
   initMPAgent: transport, crypto, chunk handler, peers,
   router, gossip — minus SDE and leader election)
7. Create `start_auditor.go` — StartMPAuditor (modeled
   on StartMPAgent: DNS engines + incoming message router
   + auditor msg handler — minus HsyncEngine/SDE)
8. Create `auditor_msg_handler.go` — simplified consumer
   that receives all message types, logs events, updates
   state, but never sends zone data
9. Create `cmd/mpauditor/` (main.go, Makefile, go.mod,
   sample config)
10. Add "auditor" to mpcli shared_cmds.go

### Phase 3: Event Log and State

10. Create AuditEventLog DB schema + CRUD functions
11. Log events from AuditorMsgHandler on every inbound
    SYNC/UPDATE/confirm/resync
12. Implement automatic retention pruning (background
    goroutine, configurable interval + max age)
13. Implement `AuditZoneState` tracking (in-memory)
14. Implement observation detection

### Phase 4: Reporting and CLI

15. Add `/audit/*` JSON API endpoints (zones, providers,
    observations, eventlog)
16. Add auditor CLI commands to mpcli:
    - `auditor eventlog list`
    - `auditor eventlog clear`
    - `auditor zones`
    - `auditor observations`

### Phase 5: Web Interface

17. Create `auditor_web.go` — HTTP handlers, template
    rendering, `//go:embed` for templates and static
18. Create template files (layout, dashboard, zone detail,
    eventlog, providers, observations)
19. Create HTMX fragment handlers for partial updates
20. Embed HTMX and Pico CSS in static assets
21. Add web listener config and startup wiring

### Phase 6: Enforcement

22. Add auditor rejection in agent SYNC processing
23. Add auditor rejection in combiner processing
24. Exclude auditor from leader elections
25. Implement empty SYNC response for RFI

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
