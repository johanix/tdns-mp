# Combiner Persistence/Editing Separation + IGNORED Status

Date: 2026-03-31
Status: Design plan, not yet implemented
Related: tdns/docs/2026-03-26-architectural-improvements.md
  (items 1 and 3, plus additional changes identified during
  design discussion)

## Problem

Multi-provider DNS zones may have providers that are not
signers. Currently, non-signing providers are completely
blocked from contributing (`OptMPDisallowEdits` +
`MPdata = nil`). This means:

1. Non-signers can't contribute NS or KEY records (wrong —
   any provider should be able to contribute NS when
   nsmgmt=agent)
2. Non-signer combiners have incomplete contribution views
   (only the signing combiner knows about all contributions)
3. Stale data can't be cleaned up via empty REPLACE
4. Agent-to-agent sync is broken for non-signing providers
   (remote updates not forwarded to local combiner)

## Design Principle

**All combiners persist all contributions from authorized
agents. Each combiner applies only what its role permits.**

A non-signing provider's combiner stores the same data as
the signing provider's combiner. The difference is only in
what gets applied to the live zone.

## New Confirmation Status: IGNORED

IGNORED = persisted but not applied. Same effect as ACCEPTED
for the agent (stop retrying, data is safe), but transparent
to operators about what actually happened.

IGNORED is a definitive answer. The agent's reliable message
queue stops retrying, and the per-RR tracking counts it as
"confirmed" in the all-recipients-confirmed check.

**State transition rule:** If ANY recipient reports ACCEPTED
(at least one combiner applied it), the RR transitions to
Accepted. Only if ALL recipients report IGNORED (no combiner
applied it) does the RR transition to Ignored.

## Per-RRtype Edit Policy

Whether a combiner applies a contribution depends on four
gates derived from the zone's HSYNCPARAM and the combiner's
own role:

  (a) is the zone signed?
  (b) are we a signer?
  (c) nsmgmt=agent?
  (d) parentsync=agent?

Each RRtype uses a different combination:

| RRtype | Apply when                                    |
|--------|-----------------------------------------------|
| NS     | nsmgmt=agent AND (unsigned OR we are signer)  |
| DNSKEY | signed AND we are a signer                    |
| CDS    | signed AND we are signer AND parentsync=agent |
| CSYNC  | signed AND we are signer AND parentsync=agent |
| KEY    | parentsync=agent AND (unsigned OR we are signer) |

This is the **edit policy** — it governs what gets applied
to the live zone. The **persistence policy** is simply:
accept all contributions from authorized agents.

Notes:
- NS and KEY can be applied by any combiner for unsigned
  zones (no signing needed), gated only by nsmgmt/
  parentsync respectively.
- DNSKEY is only meaningful for signed zones.
- CDS, CSYNC and KEY are delegation sync records — only
  meaningful when parentsync=agent.
- The existing agent-side NSmgmt check
  (agent_policy.go:92-128) blocks local NS edits when
  nsmgmt != AGENT. The combiner needs the same checks
  at edit time (not receipt time).

## Examples

### caol-ila.whisky.dnslab

Providers: alpha, echo. Signer: alpha.
NSmgmt: agent. ParentSync: owner.

| Contribution       | combiner.alpha | combiner.echo |
|--------------------|----------------|---------------|
| NS from echo       | APPLIED        | IGNORED       |
| NS from alpha      | APPLIED        | IGNORED       |
| DNSKEY from alpha  | APPLIED        | IGNORED       |
| KEY from echo      | IGNORED        | IGNORED       |

NS is APPLIED by combiner.alpha (signer, nsmgmt=agent).
KEY is IGNORED everywhere because parentsync=owner —
the zone owner handles parent sync, no SIG(0) key needed.

### lagavulin.whisky.dnslab

Providers: alpha, echo. Signer: echo.
NSmgmt: owner. ParentSync: agent.

| Contribution       | combiner.alpha | combiner.echo |
|--------------------|----------------|---------------|
| NS from alpha      | IGNORED        | IGNORED (!)   |
| DNSKEY from echo   | IGNORED        | APPLIED       |
| KEY (shared)       | IGNORED        | APPLIED       |

NS is IGNORED everywhere because nsmgmt=owner. KEY is
APPLIED by combiner.echo (signer, parentsync=agent).

### whisky.dnslab (multi-signer)

Providers: alpha, echo, delta, whisky.
Signers: alpha, echo. NSmgmt: agent. ParentSync: agent.

| Contribution       | combiner.alpha | combiner.echo |
|--------------------|----------------|---------------|
| NS from delta      | APPLIED        | APPLIED       |
| DNSKEY from alpha  | APPLIED        | APPLIED       |
| DNSKEY from echo   | APPLIED        | APPLIED       |
| CDS from alpha     | APPLIED        | APPLIED       |
| KEY (shared)       | APPLIED        | APPLIED       |

Both alpha and echo are signers — both combiners apply
everything (all four gates satisfied).

### ardbeg.whisky.dnslab (unsigned, no signers)

Providers: alpha, delta. NSmgmt: agent.
ParentSync: owner.

| Contribution       | combiner.alpha | combiner.delta |
|--------------------|----------------|----------------|
| NS from alpha      | APPLIED        | APPLIED        |
| NS from delta      | APPLIED        | APPLIED        |

Unsigned, nsmgmt=agent — all combiners apply NS.
No DNSKEY (unsigned). No KEY (parentsync=owner).

## Confirmation Flow After Changes

Example: agent.alpha sends NS update for caol-ila.

alpha's expected recipients: [combiner.alpha, agent.echo]

```
agent.alpha ──→ combiner.alpha ──→ SUCCESS (applied)
     │
     └──────→ agent.echo
                  │
                  └──→ combiner.echo ──→ IGNORED (persisted)
                  │         │
                  │         └── echo relays IGNORED back
                  │              to alpha (via
                  │              PendingRemoteConfirms)
                  └──→ echo also stores in local SDE
```

alpha receives:
- SUCCESS from combiner.alpha (direct)
- IGNORED from agent.echo (relayed from combiner.echo)

Both are definitive → all recipients confirmed →
Pending → Accepted.

**Contrast with current code:** echo currently fabricates an
immediate "ok" without consulting combiner.echo at all.
After changes, combiner.echo is involved (persists the data)
and the relayed IGNORED replaces the fabricated "ok".

**State transition rule:** If ANY recipient reports ACCEPTED
(at least one combiner applied it), RR → RRStateAccepted.
Only if ALL recipients report IGNORED (no combiner applied)
does RR → RRStateIgnored. This matters because the
originating agent wants to know: did anyone actually apply
my data?

**Example of all-IGNORED:** alpha contributes NS for
lagavulin (nsmgmt=owner). combiner.alpha returns IGNORED
(not a signer). combiner.echo returns IGNORED (is signer,
but nsmgmt=owner so NS not applied). Alpha's RR transitions
to RRStateIgnored — nobody applied it. This is correct:
the zone owner manages NS for lagavulin, not providers.

## Implementation Steps

### Step 1: Add ConfirmIgnored + RRStateIgnored

New IGNORED status in transport and agent tracking.

**tdns-transport/v2/transport/transport.go:**
- Add `ConfirmIgnored` to `ConfirmStatus` enum
  (after ConfirmPending)
- Add `"IGNORED"` case to `String()` method
- Add `IgnoredRecords []string` to `ConfirmRequest` struct

**tdns-transport/v2/transport/handler.go:**
- Add `"IGNORED"` case to `parseConfirmStatus()`

**tdns-transport/v2/transport/dns.go:**
- Add `IgnoredCount`/`IgnoredRecords` to
  `DnsConfirmPayload`
- Populate in `DNSTransport.Confirm()`

**tdns-transport/v2/transport/handlers.go:**
- Forward `IgnoredRecords` through
  `OnConfirmationReceived` callback

**syncheddataengine.go:**
- Add `RRStateIgnored` to `RRState` enum + `String()`
- Add `IgnoredRecords []string` to `ConfirmationDetail`
- In `ProcessConfirmation`: build `ignoredSet`, transition
  Pending → RRStateIgnored when all recipients report
  "ignored"
- IGNORED counts as "confirmed" in
  `allRecipientsConfirmed` check — it is a definitive
  answer. If some recipients report ACCEPTED and others
  IGNORED, the RR transitions to Accepted (at least one
  combiner applied it). Only if ALL recipients report
  IGNORED does it go to RRStateIgnored.

**hsync_transport.go:**
- `OnConfirmationReceived`: add `ignored []string` param,
  forward to `ConfirmationDetail.IgnoredRecords`
- RMQ definitive-answer check: add `ConfirmIgnored`
  (stop retrying, same as SUCCESS)

### Step 2: Separate Combiner Persistence from Editing

The keystone change: receipt path always persists, edit path
applies role-based policy.

**hsync_utils.go — `populateMPdata()` (line 833):**
- Remove `zd.MP.MPdata = nil` and `return` for non-signers
- Keep `OptMPDisallowEdits = true` and
  `OptAllowEdits = false`
- Fall through to populate MPdata with
  `WeAreSigner: false`
- This affects ALL apps (agent, combiner, signer) —
  intended

**legacy_combiner_chunk.go — `checkMPauthorization()`:**
- Simplify: with MPdata no longer nil for non-signers,
  guard-4 case never reaches the `MPdata == nil` branch
- Function becomes: check OptMultiProvider + MPdata != nil

**legacy_combiner_chunk.go — `CombinerProcessUpdate()`
(line 278):**
- After `checkMPauthorization` passes, compute an edit
  policy struct from MPdata + HSYNCPARAM:
  ```go
  type editPolicy struct {
      ZoneSigned  bool
      WeAreSigner bool
      NSmgmt      uint8 // from HSYNCPARAM
      ParentSync  uint8 // from HSYNCPARAM
  }

  func (p *editPolicy) canApply(rrtype uint16) bool {
      switch rrtype {
      case dns.TypeNS:
          return p.NSmgmt == HsyncNSmgmtAGENT &&
              (!p.ZoneSigned || p.WeAreSigner)
      case dns.TypeDNSKEY:
          return p.ZoneSigned && p.WeAreSigner
      case dns.TypeCDS, dns.TypeCSYNC:
          return p.ZoneSigned && p.WeAreSigner &&
              p.ParentSync == HsyncParentSyncAgent
      case dns.TypeKEY:
          return p.ParentSync == HsyncParentSyncAgent &&
              (!p.ZoneSigned || p.WeAreSigner)
      }
      return false
  }
  ```
- Pass policy to `combinerProcessOperations`

**legacy_combiner_chunk.go —
`combinerProcessOperations()` (line 884):**
- Add `policy *editPolicy` parameter
- For each operation, check `policy.canApply(rrtype)`:
  - If editable: persist + apply (existing flow)
  - If not editable: persist only, add to
    `resp.IgnoredRecords`, skip `CombineWithLocalChanges`
- When ALL operations were ignored:
  `resp.Status = "ignored"`
- When SOME were applied and some ignored:
  `resp.Status = "partial"` with both AppliedRecords
  and IgnoredRecords populated
- Skip SOA serial bump when nothing was applied

**legacy_combiner_utils.go —
`CombineWithLocalChanges()` (line 56):**
- Build an `editPolicy` from MPdata + HSYNCPARAM (same
  struct as above).
- If `ZoneSigned && !WeAreSigner`: early return
  `false, nil` (nothing editable for non-signers on
  signed zones). Covers all callers.
- Otherwise: inside the existing RRtype loop
  (line 100-107), replace the `AllowedLocalRRtypes`
  check with `policy.canApply(rrtype)`. This applies
  the full four-gate policy per RRtype.
- For unsigned zones the policy naturally allows NS
  (if nsmgmt=agent) and KEY (if parentsync=agent),
  and blocks DNSKEY (requires signed zone).

**legacy_combiner_utils.go —
`ReplaceCombinerDataByRRtype()` (line 636):**
- The `CombineWithLocalChanges` call at line 733 is now
  self-guarding (returns false for non-signers). No
  parameter changes needed.
- `InjectSignatureTXT` at line 745 similarly becomes a
  no-op for non-signer combiners (no zone changes to
  sign).

**legacy_combiner_msg_handler.go —
`combinerSendConfirmation()`:**
- Add `"ignored"` → `ConfirmIgnored` mapping
- Include `resp.IgnoredRecords` in `ConfirmRequest`

**legacy_combiner_chunk.go — `CombinerSyncResponse`:**
- Add `IgnoredRecords []string` field

### Step 3: Remove Agent Blanket Block

Non-signing agents participate in sync, contribute NS/KEY,
forward all data to their combiner.

**apihandler_agent.go (line 272):**
- Replace blanket `OptMPDisallowEdits` block with
  per-RRtype policy using the same four gates:
  - Block DNSKEY: non-signers must not contribute
  - Block CDS, CSYNC: non-signers or parentsync!=agent
  - Block NS: nsmgmt!=agent
  - Block KEY: parentsync!=agent
- Note: the existing NSmgmt check in EvaluateUpdate
  (agent_policy.go:92-128) already blocks NS when
  nsmgmt != AGENT for local updates. The apihandler
  check is a first-line defense; EvaluateUpdate is the
  authoritative gate. Both should use the same policy.

**syncheddataengine.go — local updates (line 434):**
- Remove `OptMPDisallowEdits` → `skipCombiner` override
- Non-signers forward to combiner (gets IGNORED back)

**syncheddataengine.go — remote updates (line 537):**
- Remove entire `remoteSkipCombiner` block (lines 537-589)
- Always forward to local combiner for persistence
- Combiner returns IGNORED, agent handles it (Step 1)
- Originating agent gets relayed IGNORED from non-signer
  combiner + SUCCESS from signer combiner

### Step 4: Empty REPLACE for Stale Data Cleanup

On resync push, send empty REPLACE for RRtypes with no
data, so the combiner cleans up stale contributions.

**syncheddataengine.go — resync push (line 869):**
- After building Operations from local data, compute
  `sentRRtypes` set
- For each RRtype in `AllowedLocalRRtypes` not in
  `sentRRtypes` (skip DNSKEY — goes via signer):
  - Append empty REPLACE operation (`Records: []string{}`)
- Create ZoneUpdate even when no local data exists
  (still need empty REPLACEs for cleanup)

**Combiner side:** No changes — `ReplaceCombinerDataByRRtype`
already handles empty sets correctly (deletes the agent's
contribution for that owner+rrtype).

### Step 5: CLI Display

**cli/agent_edits_cmds.go:**
- Add display block for "ignored" state (parallel to
  "rejected" block)
- Show: "Combiner persisted but did not apply"
- Show which combiner(s) ignored

## Dependency Order

```
Step 1 (IGNORED status)
  ↓
Step 2 (persistence/editing split) — uses IGNORED
  ↓
Step 3 (remove agent block) — needs combiner to handle
  ↓
Step 4 (empty REPLACE) — needs agent forwarding to work
  ↓
Step 5 (CLI) — needs RRStateIgnored
```

## Key Files Modified

| File                              | Steps | Changes                       |
|-----------------------------------|-------|-------------------------------|
| tdns-transport/.../transport.go   | 1     | ConfirmIgnored, IgnoredRecords|
| tdns-transport/.../handler.go     | 1     | parseConfirmStatus            |
| tdns-transport/.../dns.go         | 1     | DnsConfirmPayload             |
| tdns-transport/.../handlers.go    | 1     | Forward IgnoredRecords        |
| hsync_utils.go                    | 2     | populateMPdata no-wipe        |
| legacy_combiner_chunk.go          | 2     | checkMPauth, processOps       |
| legacy_combiner_utils.go          | 2     | CombineWithLocalChanges guard |
| legacy_combiner_msg_handler.go    | 2     | Map "ignored" status          |
| syncheddataengine.go              | 1,3,4 | RRStateIgnored, skip, REPLACE |
| hsync_transport.go                | 1     | RMQ + callback                |
| apihandler_agent.go               | 3     | Per-RRtype policy             |
| cli/agent_edits_cmds.go           | 5     | Display IGNORED               |

## Verification

1. **Build**: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
   (covers both tdns and tdns-transport)
2. **Lab test — caol-ila on echo** (non-signer provider):
   - `tdns-cliv2 agent zone addrr --zone
     caol-ila.whisky.dnslab. --rr
     "caol-ila.whisky.dnslab. IN NS ns6.echo.dnslab"`
   - Should succeed (was: "modifications not allowed")
   - `agent zone edits list --zone caol-ila.whisky.dnslab.`
     should show IGNORED from combiner.echo, APPLIED from
     combiner.alpha
3. **Lab test — resync on echo**:
   - `agent peer resync --push
     --zone caol-ila.whisky.dnslab.`
   - combiner.echo should persist all contributions,
     apply none
4. **Lab test — empty REPLACE**:
   - Remove echo's NS contribution, resync push
   - combiner.alpha should clean up stale echo NS data
5. **Lab test — lagavulin on alpha** (nsmgmt=owner):
   - `tdns-cliv2 agent zone addrr --zone
     lagavulin.whisky.dnslab. --rr
     "lagavulin.whisky.dnslab. IN NS ns1.alpha.dnslab"`
   - Should be blocked by agent-side NSmgmt check
     (nsmgmt=owner, NS not delegated to agents)
   - Even if it reached combiners: both would IGNORE NS
6. **Lab test — ardbeg** (unsigned zone, no signers):
   - Both combiners should APPLY contributions (no IGNORED)
   - Unchanged behavior from today
