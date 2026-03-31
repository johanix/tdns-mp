# Multi-Provider Regression Test Plan

Date: 2026-03-30

## Purpose

Verify that the tdns-mp versions of mpagent, mpcombiner, and
mpsigner are functionally equivalent to (or better than) the
tdns versions of agent, combiner, and signer. This is the gate
for removing MP code from tdns.

## Lab Setup

### Topology

Two providers (Alpha, Bravo), each with:
- 1 agent (mpagent)
- 1 combiner (mpcombiner)
- 1 signer (mpsigner)

One parent zone server running tdns-auth with:
- `OptDelSyncParent` enabled
- DSYNC SVCB published for bootstrap discovery

### Zone Matrix

| Zone | Signed | Signers | Purpose |
|------|--------|---------|---------|
| `signed-both.example.` | Yes | Alpha + Bravo | Multi-signer: both sign |
| `signed-one.example.` | Yes | Alpha only | One signer, Bravo pass-through |
| `unsigned.example.` | No | (none) | Unsigned multi-provider |

All three zones have HSYNC3 + HSYNCPARAM records listing both
Alpha and Bravo as providers. The `signers=` field in HSYNCPARAM
controls which providers sign.

### Baseline

Before each test section, establish the baseline:
- All agents discovered and OPERATIONAL (gossip converged)
- All zones loaded and refreshing normally
- Combiner contributions hydrated from persistent storage
- Leader elected for zones with `OptDelSyncChild`

---

## 1. Agent Discovery and Peer Communication

### 1.1 Initial Discovery

- [ ] Start Alpha agent. Verify it enters NEEDED state for Bravo.
- [ ] Start Bravo agent. Verify mutual discovery via IMR + HSYNC3.
- [ ] Verify HELLO exchange succeeds (both transports if
      configured).
- [ ] Verify JWK exchange and crypto verification. *HOW?*
- [ ] Verify both agents reach INTRODUCED then OPERATIONAL.

### 1.2 Heartbeat and Health

- [ ] Verify periodic BEATs at configured interval. *HOW?*
- [ ] Verify beat health tracking:
  - Stop Bravo agent. Verify Alpha marks Bravo as DEGRADED after
    2x beat interval, INTERRUPTED after 10x.
  - Restart Bravo. Verify Alpha marks Bravo OPERATIONAL again.
- [ ] Verify infra beats to combiner and signer peers. *HOW?*
- [ ] Verify beat errors are recorded in peer state
      (`LatestError`, `LatestErrorTime`). *HOW?*

### 1.3 Gossip Convergence

- [ ] Verify gossip state exchanged on BEATs. *HOW?*
- [ ] Verify provider group computed from HSYNC3 data. *HOW?*
- [ ] Verify `OnGroupOperational` fires when all members see all
      others as OPERATIONAL. *HOW?*
- [ ] Verify `OnGroupDegraded` fires when a member goes down. *HOW?*

---

## 2. Zone Synchronization -- NS Records

### 2.1 Add NS (Signing Provider)

- [ ] On Alpha (signer): add NS record via CLI
      `agent zone addrr --zone signed-both.example. --rr "..."`.
- [ ] Verify NS appears in Alpha's SDE as PENDING.
- [ ] Verify UPDATE sent to Alpha's combiner.
- [ ] Verify combiner merges NS into zone data.
- [ ] Verify SYNC sent to Bravo agent.
- [ ] Verify Bravo confirms (ACCEPTED).
- [ ] Verify Alpha SDE marks NS as ACCEPTED.

### 2.2 Add NS (Non-Signing Provider)

- [ ] On Bravo (non-signer for `signed-one.example.`): attempt to
      add NS via CLI.
- [ ] Verify combiner REJECTS the edit (non-signer gate).
- [ ] Verify agent receives REJECT confirmation.
- [ ] Verify NS does NOT appear in zone data.

### 2.3 Add NS (Unsigned Zone)

- [ ] On Alpha: add NS to `unsigned.example.` via CLI.
- [ ] Verify NS flows through combiner to Bravo.
- [ ] Verify no DNSKEY distribution triggered (unsigned zone
      suppression).
- [ ] Verify NS appears in both agents' zone data.

### 2.4 Remove NS (Signing Provider)

- [ ] On Alpha: remove NS record via CLI
      `agent zone delrr --zone signed-both.example. --rr "..."`.
- [ ] Verify ClassNONE deletion propagates to combiner.
- [ ] Verify combiner removes NS from contributions.
- [ ] Verify SYNC to Bravo with delete operation.
- [ ] Verify Bravo confirms removal.

### 2.5 Remove NS (Unsigned Zone)

- [ ] On Alpha: remove NS from `unsigned.example.`.
- [ ] Verify deletion flows through combiner to Bravo.
- [ ] Verify no DNSKEY-related side effects.

---

## 3. Zone Synchronization -- DNSKEY Records

### 3.1 New DNSKEY Publication (Multi-Signer Zone)

- [ ] Alpha signer generates new ZSK:
      `keystore dnssec generate --zone signed-both.example.`.
- [ ] Verify key enters `mpdist` state (not `published`).
- [ ] Verify KEYSTATE inventory sent to Alpha agent.
- [ ] Verify agent extracts DNSKEY from inventory.
- [ ] Verify agent SYNCs DNSKEY (replace operation) to Bravo.
- [ ] Verify Bravo agent processes replace, sends to Bravo combiner.
- [ ] Verify Bravo combiner merges DNSKEY.
- [ ] Verify Bravo signer receives merged DNSKEY in zone transfer.
- [ ] Verify Bravo agent sends "propagated" KEYSTATE signal back.
- [ ] Verify Alpha signer transitions key: mpdist → published.

### 3.2 New DNSKEY Publication (Single-Signer Zone)

- [ ] Alpha signer generates new ZSK for `signed-one.example.`.
- [ ] Verify key enters `mpdist` state.
- [ ] Verify agent SYNCs DNSKEY to Bravo.
- [ ] Verify Bravo (non-signer) accepts DNSKEY via combiner.
- [ ] Verify Bravo agent sends "propagated" signal.
- [ ] Verify Alpha signer transitions mpdist → published.

### 3.3 DNSKEY Suppression (Unsigned Zone)

- [ ] Verify signer does NOT send KEYSTATE inventory for
      `unsigned.example.`.
- [ ] Verify agent does not request DNSKEY data for unsigned zone.
- [ ] Verify no SYNC-DNSKEY-RRSET messages for unsigned zone.

### 3.4 DNSKEY Replace Idempotency

- [ ] Trigger resync (`agent peer resync --zone signed-both.example. --push`).
- [ ] Verify DNSKEY replace operation is idempotent (no state
      changes if data matches).
- [ ] Verify combiner reports no-op for unchanged DNSKEY set.

---

## 4. DNSKEY Rollover

### 4.1 ZSK Rollover (Multi-Signer Zone)

- [ ] Alpha: `keystore dnssec rollover --zone signed-both.example.
      --keytype zsk`.
- [ ] Verify old active ZSK → retired.
- [ ] Verify standby ZSK -> active.
- [ ] Verify retired key enters `mpremove` state.
- [ ] Verify agent SYNCs updated DNSKEY RRset (replace) to Bravo.
- [ ] Verify Bravo receives new DNSKEY set, old key removed.
- [ ] Verify Bravo sends "propagated" signal for retired key.
- [ ] Verify Alpha signer transitions retired key:
      mpremove -> removed.
- [ ] Verify KeyStateWorker generates new standby ZSK to maintain
      pipeline.

### 4.2 KSK Rollover (Multi-Signer Zone)

- [ ] Alpha: `keystore dnssec rollover --zone signed-both.example.
      --keytype ksk`.
- [ ] Same verification as ZSK rollover, plus:
- [ ] Verify combiner detects KSK change (flag 257).
- [ ] Verify CDS record published in zone.
- [ ] Verify STATUS-UPDATE(ksk-changed) sent to agent.
- [ ] Verify parent sync triggered (see Section 7).

### 4.3 Automatic Standby Key Maintenance

- [ ] Verify KeyStateWorker detects standby count below configured
      threshold.
- [ ] Verify new standby key generated automatically.
- [ ] Verify mpdist → published transition happens after agent
      propagation.

---

## 5. Combiner Operations

### 5.1 Contribution Persistence

- [ ] Add data via Alpha agent.
- [ ] Verify combiner stores in `CombinerContributions` table.
- [ ] Restart mpcombiner.
- [ ] Verify contributions hydrated from persistent storage.
- [ ] Verify `RebuildCombinerData` restores zone data correctly.

### 5.2 Signal KEY Publication

- [ ] Leader agent publishes SIG(0) KEY with PublishInstruction.
- [ ] Verify combiner stores in `CombinerPublishInstructions`.
- [ ] Verify KEY published at zone apex.
- [ ] Verify `_signal` KEY published at each in-bailiwick NS.
- [ ] Add a new NS record. Verify combiner auto-publishes
      `_signal` KEY at new NS name.
- [ ] Remove an NS record. Verify combiner removes corresponding
      `_signal` KEY.

### 5.3 Non-Signer Rejection

- [ ] From non-signer Bravo, attempt to send edit to combiner for
      `signed-one.example.`.
- [ ] Verify combiner returns REJECT confirmation.
- [ ] Verify `mp-disallow-edits` option is set on zone.

### 5.4 Signature TXT Injection

- [ ] Verify combiner injects signature TXT record when configured.
- [ ] Verify TXT is re-injected after zone data rebuild.

---

## 6. Resync Operations

### 6.1 Pull Resync

- [ ] `agent peer resync --zone signed-both.example. --pull`.
- [ ] Verify agent requests RFI SYNC from Bravo. *HOW?*
- [ ] Verify received data applied to SDE. *HOW?*
- [ ] Verify agent requests RFI EDITS from combiner. *HOW?*
- [ ] Verify combiner contributions applied.

### 6.2 Push Resync

- [ ] `agent peer resync --zone signed-both.example. --push`.
- [ ] Verify agent sends local non-DNSKEY data to combiner.
- [ ] Verify agent sends local data to remote agents.
- [ ] Verify remote data attributed to correct source.

### 6.3 Full Resync

- [ ] `agent peer resync --zone signed-both.example. --full`.
- [ ] Verify pull-then-push ordering.
- [ ] Verify no data loss or duplication.

---

## 7. Parent Sync -- DNS UPDATE Method

### 7.1 NS Change Triggers Parent Sync

- [ ] Add NS record on Alpha for `signed-both.example.`.
- [ ] Verify combiner detects NS change.
- [ ] Verify CSYNC record published in zone (if signed).
- [ ] Verify STATUS-UPDATE(ns-changed) sent to Alpha agent.
- [ ] Verify leader agent enqueues EXPLICIT-SYNC-DELEGATION.
- [ ] Verify DelegationSyncher queries parent for current NS set.
- [ ] Verify delta computed (new NS not in parent).
- [ ] Verify DNS UPDATE sent to parent with NS + glue A/AAAA.
- [ ] Verify parent accepts UPDATE and serves new NS.

### 7.2 NS Removal Triggers Parent Sync

- [ ] Remove NS record from zone.
- [ ] Verify combiner detects removal.
- [ ] Verify delegation delta computed (old NS still in parent).
- [ ] Verify DNS UPDATE sent to parent removing NS + glue.

### 7.3 KSK Change Triggers DS Update

- [ ] Roll KSK on Alpha signer.
- [ ] Verify combiner detects KSK change (flag 257).
- [ ] Verify CDS record published.
- [ ] Verify STATUS-UPDATE(ksk-changed) sent to agent.
- [ ] Verify leader computes DS delta against parent.
- [ ] Verify DNS UPDATE sent to parent with new DS.
- [ ] Verify old DS removed after propagation delay.

### 7.4 Glue Record Handling

- [ ] Add in-bailiwick NS (e.g., `ns3.signed-both.example.`).
- [ ] Verify A/AAAA glue included in parent UPDATE.
- [ ] Add out-of-bailiwick NS (e.g., `ns.external.net.`).
- [ ] Verify NO glue sent for out-of-bailiwick NS.

### 7.5 Non-Leader Ignores Parent Sync

- [ ] On Bravo (non-leader): verify STATUS-UPDATE received and
      logged but no DNS UPDATE sent to parent.

### 7.6 Leader Re-election After Failure

- [ ] Kill leader agent.
- [ ] Verify remaining agent detects leadership loss.
- [ ] Verify new election triggered.
- [ ] Verify new leader can perform parent sync.

---

## 8. Parent Sync — NOTIFY(CSYNC/CDS) Method

### 8.1 CSYNC NOTIFY to Parent

- [ ] Trigger NS change that produces CSYNC record.
- [ ] Verify agent sends NOTIFY(CSYNC) to parent.
- [ ] Verify parent scans child CSYNC record.
- [ ] Verify parent queries all child NS for SOA consistency.
- [ ] Verify parent applies NS/glue changes per CSYNC bitmap.

### 8.2 CDS NOTIFY to Parent

- [ ] Trigger KSK rollover that produces CDS record.
- [ ] Verify agent sends NOTIFY(CDS) to parent.
- [ ] Verify parent processes CDS and updates DS.

### 8.3 Combined CSYNC + CDS

- [ ] Trigger simultaneous NS + KSK change (or rapid sequence).
- [ ] Verify both NOTIFY(CSYNC) and NOTIFY(CDS) sent.
- [ ] Verify parent processes both independently.

---

## 9. SIG(0) Key Lifecycle

### 9.1 Leader Election and Key Generation

- [ ] Start two agents with no pre-existing SIG(0) keys.
- [ ] Verify leader election completes.
- [ ] Verify leader checks local keystore (no key).
- [ ] Verify leader asks peers via RFI CONFIG(sig0key).
- [ ] Verify no peer has key → leader generates new keypair.
- [ ] Verify KEY published to combiner (via PublishInstruction).

### 9.2 Key Import from Peer

- [ ] Start agent C (new peer) for same zone.
- [ ] Verify C wins or loses election.
- [ ] If C is leader: verify C asks existing peers for SIG(0) key.
- [ ] Verify peer responds with key material.
- [ ] Verify C imports key via `importSig0KeyFromPeer`.
- [ ] Verify C publishes same KEY to its combiner.

### 9.3 DSYNC Bootstrap

- [ ] After KEY publication, verify leader queries parent via
      KeyState EDNS(0).
- [ ] If parent returns KeyStateUnknown: verify bootstrap UPDATE
      sent.
- [ ] Verify polling with backoff (5s → 10s → 20s → 40s).
- [ ] Verify parent transitions to KeyStateTrusted.
- [ ] Verify post-bootstrap delegation verification triggered.

---

## 10. Config Reload

### 10.1 SIGHUP Reload

- [ ] Add new MP zone to config file.
- [ ] Send SIGHUP to mpagent.
- [ ] Verify new zone loaded with `FirstZoneLoad` callbacks.
- [ ] Verify tdns-mp PreRefresh/PostRefresh closures registered
      (via `PostParseZonesHook`).
- [ ] Verify existing zones unaffected.

### 10.2 CLI Reload

- [ ] Add new MP zone to config file.
- [ ] `mpcli agent config reload-zones`.
- [ ] Same verification as 10.1.

### 10.3 Combiner Reload

- [ ] Add new MP zone to mpcombiner config.
- [ ] SIGHUP to mpcombiner.
- [ ] Verify `RegisterCombinerOnFirstLoad` attaches
      PersistContributions callback.
- [ ] Verify new zone gets contribution hydration on first load.

### 10.4 Zone Removal

- [ ] Remove MP zone from config.
- [ ] Reload.
- [ ] Verify zone removed from zone list.
- [ ] Verify no orphaned state in agent registry.

---

## 11. Startup and Recovery

### 11.1 Cold Start Hydration

- [ ] Start mpcombiner with pre-existing contribution data in DB.
- [ ] Verify `LoadAllContributions` loads snapshot.
- [ ] Verify each MP zone hydrates `AgentContributions`.
- [ ] Verify `RebuildCombinerData` restores zone data.

### 11.2 Agent SDE Hydration

- [ ] Start mpagent after combiner has contributions.
- [ ] Verify agent sends RFI EDITS to combiner for each MP zone.
- [ ] Verify combiner responds with contributions.
- [ ] Verify `applyEditsToSDE` populates SDE.
- [ ] Verify agent sends RFI KEYSTATE to signer.
- [ ] Verify signer responds with key inventory.
- [ ] Verify `LocalDnskeysFromKeystate` populates local DNSKEYs.

### 11.3 Reliable Message Queue Recovery

- [ ] Send SYNC while remote agent is down.
- [ ] Verify RMQ stores message for retry.
- [ ] Start remote agent.
- [ ] Verify RMQ delivers message with exponential backoff.
- [ ] Verify confirmation received and RMQ entry cleared.

---

## 12. CLI Commands

### 12.1 Agent Commands

- [ ] `mpcli agent peer list` — shows all peers with state.
- [ ] `mpcli agent peer ping --id <peer>` — successful ping.
- [ ] `mpcli agent peer zones` — lists shared zones per peer.
- [ ] `mpcli agent zone list` — lists configured zones.
- [ ] `mpcli agent zone mplist` — lists MP zones with HSYNCPARAM.
- [ ] `mpcli agent gossip group list` — lists provider groups.
- [ ] `mpcli agent gossip group state --group <name>` — shows
      gossip state matrix.
- [ ] `mpcli agent imr show --id <agent>` — shows IMR cache.
- [ ] `mpcli agent router list` — shows registered handlers.
- [ ] `mpcli debug agent queue-status` — shows RMQ state.
- [ ] `mpcli debug agent sync-state --zone <zone>` — shows SDE.

### 12.2 Combiner Commands

- [ ] `mpcli combiner list-data --zone <zone>` — shows merged data.
- [ ] `mpcli combiner show-combiner-data --zone <zone>` — shows
      per-agent contributions.
- [ ] `mpcli combiner zone edits list --zone <zone>` — shows
      pending/approved edits.

### 12.3 Signer Commands

- [ ] `mpcli signer keystore dnssec list --zone <zone>` — lists
      keys with states.

---

## 13. Regression Comparison

For each test above, run the same scenario against both:
- **tdns binaries**: agent + combiner + signer (AppTypeAgent)
- **tdns-mp binaries**: mpagent + mpcombiner + mpsigner

Compare:
- [ ] Same zone data served after convergence.
- [ ] Same DNSKEY RRset in both providers.
- [ ] Same NS RRset in parent.
- [ ] Same DS RRset in parent.
- [ ] No error log messages that don't appear in tdns version.
- [ ] Equivalent or better timing (no added latency).

---

## Test Execution Notes

- Building happens on the NetBSD build server.
- Testing happens on NetBSD VMs in the training lab.
- Do not inspect local (dev machine) binaries or configs.
- Each test should start from a clean state unless testing
  recovery.
- Log output should be captured for both success and failure.
- Use `--verbose` flags where available for detailed output.
