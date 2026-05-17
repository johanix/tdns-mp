# Model for Synchronization of DNS Data

This document describes how DNS data is synchronized across
the multi-provider system: where it lives, who owns it, how
it is tracked, and where the policy gates are.

The model is shaped by a small number of decisions:

1. The **combiner is the center of persistence** for a
   provider. Everything that should survive a restart lives
   there.
2. The **agent SDE is a runtime cache**. It is large, it is
   queryable, but it is not the source of truth for
   anything.
3. **Every piece of data is attributed to its originator**
   and tracked per-originator throughout its lifecycle.
4. **Intake is permissive; the gates are in the combiner.**
   Agents accept what peers send them so the network stays
   consistent and aware. Each combiner decides what to
   actually apply to its served zone, based on policy
   derived from HSYNCPARAM.

The rest of this document expands those points and shows
the CLI commands for inspecting the resulting state.

## 1. The Combiner: Center of Persistence

The combiner owns the `CombinerContributions` table. This
table stores, per zone, per originator, per RR type, the
records that originator has contributed:

```
zone           origin                  rrtype  records
─────────────────────────────────────────────────────────
example.com.   agent.alpha.example.    DNSKEY  [DNSKEY1, DNSKEY2]
example.com.   agent.bravo.example.    DNSKEY  [DNSKEY3]
example.com.   agent.charlie.example.  DNSKEY  [DNSKEY4]
example.com.   agent.alpha.example.    NS      [ns1.alpha, ns1.bravo, ns1.charlie]
example.com.   agent.alpha.example.    CDS     [CDS1, CDS2, CDS3, CDS4]
```

On every change, the combiner rebuilds the served zone
from two sources:

1. The customer zone received via inbound AXFR from the
   zone owner — used for everything *outside* the
   coordinated RRsets.
2. `CombinerContributions` — used for the coordinated
   RRsets (DNSKEY, NS, CDS, CSYNC, plus per-provider
   edits where authorized).

Because contributions are persisted, the served zone is
deterministic across combiner restarts. Nothing about
"what is published right now" lives only in memory.

The combiner also persists a separate `PublishedNS` view
(used to diff NS changes and resync `_signal` KEY records
in provider zones) and an audit trail of
`CombinerPublishInstructions`. Together these mean the
combiner can answer "what should be in the served zone
and why?" without needing to ask the agent.

## 2. The Agent SDE: Runtime Cache

The agent maintains the **Synched Data Engine (SDE)**:
a per-zone, in-memory map of everything the agent has
learned, indexed by source agent and RR type.

```
zone           source                  rrtype  RRs + per-RR tracking state
──────────────────────────────────────────────────────────────────────────
example.com.   agent.alpha.example.    DNSKEY  [DNSKEY1@accepted, DNSKEY2@accepted]
example.com.   agent.bravo.example.    DNSKEY  [DNSKEY3@accepted]
example.com.   agent.charlie.example.  DNSKEY  [DNSKEY4@pending(bravo)]
example.com.   agent.alpha.example.    NS      [ns1.alpha@accepted, ns1.bravo@accepted, ns1.charlie@accepted]
```

The SDE is **not authoritative for anything**. If it is
lost (e.g. agent restart), it is rebuilt by asking the
authoritative sources:

- **RFI EDITS** to the local combiner — restores everything
  the local provider has contributed.
- **RFI KEYSTATE** to the local signer — restores the local
  signer's DNSKEYs.
- **RFI SYNC** to each peer agent — restores data those
  peers contributed.

After hydration, the SDE reflects the union of all
authoritative state in the system. It is what the CLI
queries when you ask "what does this agent currently know?".

### 2.1 Inspecting the SDE

`agent zone edits list` shows the SDE summary across all
zones:

```
$ tdns-mpcli agent zone edits list

Synchronized Data from Peer Agents
===================================

Zone: example.com.
────────────────────────────────────────
  Source: agent.alpha.example.
    DNSKEY (2 records):
      keytag=12345  KSK (257)  alg=ED25519  key=YWJj...XYZ  [accepted 2026-05-17T09:14:22Z]
      keytag=23456  ZSK (256)  alg=ED25519  key=ZGVm...PQR  [accepted 2026-05-17T09:14:22Z]
    NS (3 records):
      example.com.  3600  IN  NS  ns1.alpha.example.
      example.com.  3600  IN  NS  ns1.bravo.example.
      example.com.  3600  IN  NS  ns1.charlie.example.

  Source: agent.bravo.example.
    DNSKEY (1 records):
      keytag=34567  ZSK (256)  alg=ED25519  key=aGlq...STU  [accepted 2026-05-17T09:14:25Z]

  Source: agent.charlie.example.
    DNSKEY (1 records):
      keytag=45678  ZSK (256)  alg=ED25519  key=bm9w...VWX  [pending 2026-05-17T09:14:31Z]
```

`agent zone edits list --zone example.com.` shows
per-RR tracking detail including outbound queue state:

```
$ tdns-mpcli agent zone edits list --zone example.com.

SDE Status for Zone: example.com. at 2026-05-17 09:16:02
════════════════════════════════════════

Source: agent.charlie.example.

Type   | State    | RR / Details
DNSKEY | PENDING  | example.com. 3600 IN DNSKEY 256 3 15 bm9w...VWX
       |          | KeyId: 45678  State: published  Updated: 2026-05-17 09:14:31
       |          | Pending: agent.bravo.example.

Outbound Queue (zone example.com.):
DistID            | Recipient            | Type  | State    | Attempts | Age
d8f2a91c00b14e3a  | agent.bravo.example. | SYNC  | pending  | 2        | 47s
```

Three useful things in that output:

- **State** reflects the *per-RR* status. PENDING means at
  least one recipient has not yet confirmed; ACCEPTED means
  all recipients confirmed; REJECTED means at least one
  recipient's combiner rejected the record on policy
  grounds.
- **Pending** lists the specific peers still owing a
  confirmation. This is how you tell a single-peer outage
  apart from a system-wide problem.
- The **Outbound Queue** is the reliable message queue —
  what the agent is still trying to deliver. Old entries
  with high attempt counts mean an agent that cannot be
  reached.

## 3. Origin Tracking

Every piece of data carries the identity of its
originator. The originator is preserved end-to-end:

- **Local edits** (`agent zone addrr/delrr`) are attributed
  to the local agent identity.
- **Peer SYNCs** are attributed to the sending agent's
  identity.
- **DNSKEYs from a signer** are attributed to the
  originating signer via KEYSTATE flow, even after they
  propagate agent → agent across the network.

Origin attribution matters for three reasons:

1. **Policy decisions**. The combiner uses origin to decide
   whether a contribution is authorized — only contributions
   from a recognized signer may add DNSKEYs; only the local
   provider may add per-provider edits; etc.
2. **Targeted purge**. When a provider leaves the group,
   you can purge everything attributed to that provider in
   one operation (see `combiner zone edits purge` below).
3. **Audit and diagnostics**. When the served zone contains
   a record you did not expect, origin attribution tells
   you who put it there.

## 4. Permissive Intake, Gated Application

The model is deliberately asymmetric:

- **Agents accept** valid data from any authorized peer
  into their SDE, even if the local provider will not act
  on it.
- **Combiners gate** what actually enters the served
  zone, based on policy derived from HSYNCPARAM.

This means the SDE on every agent in a group should
converge toward the same content (modulo propagation
delay). The combiners produce different served zones
because they apply different policies — but they all see
the same input.

For the rationale and corner cases of this asymmetry —
why ACCEPTED is not the same as "I applied it", why
non-signing providers still accept DNSKEYs, what happens
when an agent tries to add records it is not authorized
to add — see [Change Tracking Semantics](mp-change-tracking-semantics.md).

## 5. The Dynamic MP Options

When a zone is loaded, the agent runs `populateMPdata`
which evaluates the zone's HSYNC3 + HSYNCPARAM records
against the local provider's identity and produces a set
of zone options. These options drive the per-zone
behavior of the combiner and signer.

| Option                | Set when                                                    | Effect                                                                 |
|-----------------------|-------------------------------------------------------------|------------------------------------------------------------------------|
| `OptMultiProvider`    | Zone has HSYNC3 + HSYNCPARAM records                        | This zone participates in multi-provider coordination.                 |
| `OptAllowEdits`       | We are listed in HSYNC3 AND (we sign OR zone is unsigned)   | Combiner *applies* contributions from the local agent to served zone.  |
| `OptMPDisallowEdits`  | Zone is signed AND we are not in HSYNCPARAM `signers=`      | Combiner *persists* contributions but does not apply them.             |
| `OptMPNotListedError` | Our identity does not match any HSYNC3 record               | Zone is rejected outright — we are not a participant.                  |
| `OptMultiSigner`      | We are a signer AND at least one other provider also signs  | Enables RFC 8901 multi-signer DNSKEY coordination via KEYSTATE.        |
| `OptInlineSigning`    | We are a signer for this zone                               | Signer signs combiner output before publishing.                        |

A few things worth highlighting:

- `OptAllowEdits` and `OptMPDisallowEdits` are mutually
  exclusive but both are tracked. The combination encodes
  a third state: "we are a participant who reads but does
  not modify". A non-signing provider in a signed zone
  falls into that state — it gets the data via zone
  transfer from a signer, and its combiner persists what
  the local agent contributes (e.g. local NS knowledge)
  but never applies it.
- `OptMultiSigner` is what enables DNSKEY-exchange logic
  in KEYSTATE. A zone with a single signer skips it.
- `OptMPNotListedError` is intentional: a provider that
  finds itself not listed in HSYNC3 for a zone it has been
  asked to serve will refuse the zone rather than silently
  serve stale data. This catches configuration drift.

Options derived this way are visible in the agent's zone
list (`agent zone list` shows them in the trailing
brackets column).

## 6. Inspecting Combiner State

The combiner has its own view of the same world.
`combiner zone edits` covers the per-RR lifecycle on the
combiner side.

### 6.1 Current contributions (the served-zone source data)

```
$ tdns-mpcli combiner zone edits list --zone example.com.

Current Contributions for Zone: example.com.
═══════════════════════════════════════

Type    | Origin                   | Record
DNSKEY  | agent.alpha.example.     | example.com. 3600 IN DNSKEY 256 3 15 YWJj...XYZ
DNSKEY  | agent.alpha.example.     | example.com. 3600 IN DNSKEY 257 3 15 ZGVm...PQR
DNSKEY  | agent.bravo.example.     | example.com. 3600 IN DNSKEY 256 3 15 aGlq...STU
DNSKEY  | agent.charlie.example.   | example.com. 3600 IN DNSKEY 256 3 15 bm9w...VWX
NS      | agent.alpha.example.     | example.com. 3600 IN NS ns1.alpha.example.
NS      | agent.alpha.example.     | example.com. 3600 IN NS ns1.bravo.example.
NS      | agent.alpha.example.     | example.com. 3600 IN NS ns1.charlie.example.
CDS     | agent.alpha.example.     | example.com. 3600 IN CDS 12345 15 2 abcdef...
```

This is what the combiner is currently applying — its
half of the rebuild input.

### 6.2 Pending / approved / rejected edits

By default the combiner auto-approves contributions that
pass policy. The `--pending` / `--approved` / `--rejected`
flags surface the edit lifecycle when you need to
investigate or run a manual-approval workflow:

```
$ tdns-mpcli combiner zone edits list --zone example.com. --rejected

Rejected Edits for Zone: example.com.
═══════════════════════════════════════

  #42  From: agent.charlie.example.  Received: 2026-05-17T09:14:31Z  Rejected: 2026-05-17T09:14:31Z
      Reason: provider not in HSYNCPARAM signers list — DNSKEY contributions not authorized
      example.com. 3600 IN DNSKEY 256 3 15 bm9w...VWX
```

Rejections are the combiner enforcing policy. The agent
sees the same edit as REJECTED in its SDE
(propagated back via the confirmation message), with the
combiner-provided reason.

`approve` and `reject` are manual overrides for the
pending state — useful for testing and for the (rare)
case where the combiner is configured to require manual
approval rather than auto-applying authorized
contributions.

### 6.3 Purging by origin

When a provider is removed from a zone, you can purge
everything they contributed in a single command:

```
$ tdns-mpcli combiner zone edits purge --zone example.com. --origin agent.charlie.example.
```

This removes every record attributed to charlie from
`CombinerContributions` and rebuilds the served zone
without those contributions. The local agent's SDE will
eventually catch up via the normal sync flow.

### 6.4 Re-applying contributions

`combiner zone edits reapply --zone example.com.`
reloads the persisted contributions from the database
and re-runs the rebuild. This is the recovery operation
for "the in-memory served zone has drifted from what the
database says it should be" — for example after a manual
intervention you want to undo.

### 6.5 Clearing tables

`combiner zone edits clear` empties one or more of the
edit tables (`--pending`, `--approved`, `--rejected`,
`--current`). The `--current` flag clears the
authoritative contributions table itself — use with care;
the combiner will fall back to whatever the unsigned
inbound zone contains until contributions are
re-received.

## 7. What This Looks Like End-to-End

A change to a coordinated RRset (e.g. agent alpha adds an
NS record) flows like this:

1. Operator runs `agent zone addrr --zone example.com.
   --rr "example.com. 3600 IN NS ns2.alpha.example."` on
   alpha.
2. The local agent inserts the RR into its SDE, attributed
   to itself, state PENDING.
3. The local agent sends UPDATE to its combiner.
   Combiner persists the contribution to
   `CombinerContributions` (origin = agent.alpha.example.),
   rebuilds the served zone, and confirms ACCEPTED.
4. The local agent sends SYNC to agents bravo and
   charlie via DNS CHUNK.
5. Each remote agent inserts the RR into its SDE,
   attributed to alpha, sends UPDATE to its own combiner,
   and returns a confirmation to alpha. Each remote
   combiner persists the contribution (origin =
   agent.alpha.example. — origin is preserved across the
   network) and rebuilds.
6. Once all peers have confirmed, the alpha agent
   transitions the RR from PENDING to ACCEPTED in its SDE.

If a remote combiner rejects (e.g. policy violation), the
remote agent returns REJECTED with a reason; the alpha
agent records that REJECTED state in its SDE per-peer, and
the operator sees it in `agent zone edits list --zone
example.com.`. The record may be ACCEPTED at some peers
and REJECTED at others; the per-peer detail is preserved.

## 8. See Also

- [Architecture](multi-provider-architecture.md) — the
  bigger picture of roles and data flow.
- [Change Tracking Semantics](mp-change-tracking-semantics.md)
  — corner cases and the rationale for permissive intake.
- [Operation and Debugging](operation-and-debugging.md) —
  the full operational CLI surface.
- [Making Data Changes](data-changes.md) — adding, removing
  and rolling records in a live zone.
