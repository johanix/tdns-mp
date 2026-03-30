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

### Binary: tdns-mpauditor

Lives in `tdns-mp/cmd/mpauditor/`. Uses `AppTypeMPAuditor`.

Startup:
1. `tdns.MainInit()` — DNS infrastructure (zones, KeyDB,
   refresh)
2. `initMPAuditor()` — transport, crypto, chunk handler,
   peer registration (same as agent, minus SDE/combiner)
3. `StartMPAuditor()` — DNS engines, incoming message
   router, auditor message handler

### What the Auditor Runs

**From tdns (DNS infrastructure):**
- RefreshEngine (zone transfers from upstream)
- DnsEngine (serve zone data, handle NOTIFYs)
- NotifyHandler (process incoming NOTIFYs)
- APIdispatcher (management API)

**From tdns-mp (MP engines):**
- IncomingMessageRouter (CHUNK → router → handlers)
- AuditorMsgHandler (consumes MsgQs: Beat, Hello, Ping,
  Msg/Sync — stores state, never sends data)

**NOT run:**
- SynchedDataEngine (no tracking/confirmation state)
- HsyncEngine (no outbound sync operations)
- CombinerMsgHandler (not a combiner)
- SignerMsgHandler / KeyStateWorker (not a signer)
- Leader election (excluded by rule 4)

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

### Reporting Capabilities

The auditor exposes state via its management API:

- `GET /audit/zones` — list all audited zones with summary
- `GET /audit/zone/{zone}` — detailed state for one zone
- `GET /audit/providers` — all providers across all zones
- `GET /audit/observations` — recent observations/anomalies
- `GET /audit/dashboard` — HTML dashboard (optional)

Observations the auditor can detect:
- Provider went silent (no BEAT for >N seconds)
- SYNC data inconsistency (provider A and B disagree)
- Unauthorized DNSKEY contribution (non-signer sent keys)
- Missing provider (listed in HSYNC3 but never seen)
- Serial drift (zone serial mismatch between providers)
- NS inconsistency (different providers advertise
  different NS sets)

## Implementation Plan

### Phase 1: Protocol Support

1. Add `HSYNCPARAM_AUDITOR` SvcParam (key 7) to
   core/rr_hsyncparam.go
2. Add `GetAuditor()` and `IsAuditorLabel()` accessors
3. Add `AppTypeMPAuditor` to enums.go
4. Add AppType guards in tdns (same pattern as
   MPSigner/MPCombiner)

### Phase 2: Auditor Binary

5. Create `tdns-mp/v2/start_auditor.go`
6. Create `tdns-mp/v2/auditor_msg_handler.go`
7. Add `initMPAuditor` to MainInit
8. Create `tdns-mp/cmd/mpauditor/`
9. Add auditor CLI commands to mpcli

### Phase 3: State and Reporting

10. Implement `AuditZoneState` tracking
11. Implement observation detection
12. Add `/audit/*` API endpoints
13. Add auditor CLI commands to mpcli

### Phase 4: Enforcement

14. Add auditor rejection in agent SYNC processing
15. Add auditor rejection in combiner processing
16. Exclude auditor from leader elections
17. Implement empty SYNC response for RFI

## Complexity Assessment

**Lower than agent** because:
- No SDE (no tracking/confirmation state machine)
- No outbound sync (read-only)
- No combiner interaction (doesn't contribute)
- No leader election participation
- Message handler is simplified (consume + store, never
  send data)

**Similar to combiner** in terms of:
- Transport setup (CHUNK handler, router, peers)
- Incoming message processing (Beat, Hello, Ping, Sync)
- Persistence (audit state, observations)

**New work:**
- HSYNCPARAM auditor SvcParam (small, well-defined)
- Audit state tracking (new data model)
- Reporting API (new endpoints)
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
