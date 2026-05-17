# Making Data Changes

This document covers the things you actually *do* to a
running multi-provider zone: add or remove records, roll
DNSSEC keys, and verify the changes propagated. It builds
on:

- [Synchronization Model](synchronization-model.md) — how
  changes flow through the SDE and combiner.
- [Operation and Debugging](operation-and-debugging.md) —
  the inspection commands used here to verify.

Running example: `example.com.` with alpha (signer +
server), bravo and charlie (server only). Throughout this
doc, `agent.alpha.example.` is the local provider unless
noted otherwise.

## 1. Adding and Removing Records

Most coordinated changes go through the agent's
`addrr` / `delrr` commands:

```
tdns-mpcli agent zone addrr --zone <zone> --rr "<record>"
tdns-mpcli agent zone delrr --zone <zone> --rr "<record>"
```

The `--rr` argument is a full DNS record in zone-file
syntax: owner, TTL, class, type, RDATA. The CLI parses
it locally before submitting, so a syntactically broken
record fails fast. Supported RR types: NS, DNSKEY, CDS,
CSYNC, KEY.

### 1.1 Adding an NS record

```sh
tdns-mpcli agent zone addrr --zone example.com. \
    --rr "example.com. 3600 IN NS ns2.alpha.example."
```

What happens, in order:

1. CLI parses and normalizes the RR, POSTs to the local
   agent's `/agent` API.
2. Agent inserts the RR into its SDE, attributed to
   `agent.alpha.example.`, state PENDING.
3. Agent sends UPDATE to local combiner.
4. Agent sends SYNC to `agent.bravo.example.` and
   `agent.charlie.example.` over DNS CHUNK.
5. Each recipient confirms back. As confirmations arrive
   the SDE state transitions PENDING → ACCEPTED.

The CLI returns as soon as step 1 succeeds. Steps 2-5
happen asynchronously. Verify with:

```sh
tdns-mpcli agent zone edits list --zone example.com.
```

The new NS will appear under `Source:
agent.alpha.example.` with its current state. Watch it
go from PENDING to ACCEPTED as confirmations come in.

### 1.2 Removing a record

```sh
tdns-mpcli agent zone delrr --zone example.com. \
    --rr "example.com. 3600 IN NS ns2.alpha.example."
```

The record string must match what is currently in the
SDE. The agent issues a ClassNONE deletion on the
combiner side, distributed to peers the same way as
additions.

### 1.3 What records you can add or remove

For the coordinated RRsets (NS, DNSKEY, CDS, CSYNC) the
combiner is the gate — it decides whether your
contribution is policy-authorized for this zone. For
per-provider edits (other RR types) the combiner checks
the HSYNCPARAM-derived options:

- On the *signing* provider (alpha): `OptAllowEdits` is
  true, so contributions are applied.
- On *non-signing* providers (bravo, charlie):
  `OptMPDisallowEdits` is true. The agent will reject
  the local `addrr` call before it gets anywhere near
  the SDE, with a message explaining that a non-signer
  cannot edit a signed zone (it would have no way to
  produce valid RRSIGs over the change).

See [Change Tracking Semantics](mp-change-tracking-semantics.md)
for the full rationale.

### 1.4 What you should *not* use addrr / delrr for

- **DNSKEYs.** The signer owns DNSKEYs and exposes them
  to the agent via KEYSTATE. Use the signer's rollover
  commands (next section), not `addrr DNSKEY`.
- **RRSIGs.** The signer produces these from DNSKEYs +
  zone content. They are not editable.
- **SOA.** The signer manages the serial. Use `bump`
  (section 4) if you want to force a re-serve.
- **Records in zones you do not have `OptAllowEdits`
  for.** Even per-provider edits require authorization.

## 2. DNSSEC Key Rollover

Key rollover is signer-initiated. The agent's job is to
propagate the resulting DNSKEY set to peer agents (so
their combiners can include the union of DNSKEYs in
their served zones) and to track when every peer has
confirmed.

> **Note on automation.** Fully automatic DNSSEC key
> rollover is already implemented in the upstream tdns
> codebase (used by standalone tdns-auth deployments).
> It has not yet been imported into the tdns-mp stack —
> the multi-signer coordination layer (KEYSTATE-driven
> propagation, gating on peer confirmation before each
> key state transition) needs to be wired up first. The
> code exists; the integration is pending. Until that is
> done, all MP rollovers are operator-driven via the
> commands below.

### 2.1 Manual rollover

```sh
tdns-mpcli signer keystore dnssec rollover -z example.com. --keytype ZSK
tdns-mpcli signer keystore dnssec rollover -z example.com. --keytype KSK
```

This performs a manual key state advance: standby →
active, active → retired. The new active key starts
signing immediately; the retired key stops signing but
stays published until the operator removes it.

Before rolling, you typically generate the standby key:

```sh
tdns-mpcli signer keystore dnssec generate -z example.com. \
    --keytype ZSK --state published --algorithm ED25519
```

Then verify the keystore state before and after the
rollover with:

```sh
tdns-mpcli signer keystore dnssec list -z example.com.
```

### 2.2 Watching the rollover propagate

The interesting thing about a multi-provider rollover is
*propagation* — the new DNSKEY has to reach every
provider before the old key can be retired. From the
local agent's view:

```sh
tdns-mpcli agent zone edits list --zone example.com.
```

DNSKEY entries appear under `Source: signer.alpha.example.`
(attribution is preserved through the signer-agent
KEYSTATE handoff and the agent-agent SYNC). You will see
the new key go PENDING → ACCEPTED on each peer as their
combiners confirm receipt.

The signer's KEYSTATE logic will not proceed to the next
phase of the rollover (e.g. activating a new ZSK, or
retiring an old one) until every peer has confirmed.
This is how RFC 8901 multi-signer correctness is
enforced: if bravo is offline, alpha's rollover stalls
rather than de-syncing the DNSKEY set.

If a rollover is stuck, the SDE view shows you exactly
which peers have not confirmed. From there it is the
same triage as any other peer problem — see
[Operation and Debugging §6](operation-and-debugging.md#6-putting-it-together-a-triage-checklist).

## 3. Inspecting State

The `agent zone edits` and `combiner zone edits`
commands are the **primary inspection tools** for
*every* kind of change — NS, DNSKEY, CDS, CSYNC and any
per-provider edits. They show the same per-RR tracking
state and origin attribution regardless of what RR type
or what operation produced the change. Reach for them
first whenever you want to know "what does the system
think about this zone right now?".

Three views to keep straight:

### 3.1 What the agent has learned (SDE)

```sh
# All zones, summary
tdns-mpcli agent zone edits list

# One zone, per-RR detail + outbound queue
tdns-mpcli agent zone edits list --zone example.com.
```

This is the *runtime* picture: what data the agent has
in memory, attributed to each source, and what
transitions are in flight. Use it to answer questions
like:

- Did my `addrr NS` reach every peer? (look for PENDING
  vs ACCEPTED per recipient)
- Has the new DNSKEY from the local signer propagated to
  bravo and charlie? (DNSKEY entries under
  `Source: signer.alpha.example.`)
- Are CDS records consistent across providers?

Detail in
[Synchronization Model §2.1](synchronization-model.md#21-inspecting-the-sde).

### 3.2 What the combiner has persisted

```sh
# Current contributions feeding the served zone
tdns-mpcli combiner zone edits list --zone example.com.

# Edit lifecycle
tdns-mpcli combiner zone edits list --zone example.com. --pending
tdns-mpcli combiner zone edits list --zone example.com. --approved
tdns-mpcli combiner zone edits list --zone example.com. --rejected
```

This is the *persistent* picture: what the combiner will
serve after the next rebuild. Same scope as the SDE view
— every RR type, every origin, every change. If the SDE
and the combiner disagree, the combiner wins for "what
is actually published."

`--rejected` is especially useful: any time an `addrr`
goes through the SDE but never lands in the served
zone, the rejection reason is recorded here.

### 3.3 What the world sees

```sh
# Combiner output (unsigned)
dog @127.0.0.1:8055 example.com. NS
dog @127.0.0.1:8055 example.com. HSYNC3

# Signer output (signed)
dog @127.0.0.1:8053 +dnssec example.com. NS
dog @127.0.0.1:8053 +dnssec example.com. DNSKEY
```

Always end a verification pass here — confirm that what
you intended is actually in the DNS responses you can
see, not just what the management commands report.

`dog` is used throughout this guide rather than `dig`:
it understands the same query syntax but also decodes
the private RR types (HSYNC3, HSYNCPARAM, JWK, CHUNK)
that tdns-mp uses. `dig` would emit those as opaque
`TYPE65285`-style blobs.

## 4. Bumping the Zone

Force a serial bump and re-NOTIFY without changing zone
content:

```sh
# On the combiner — re-serve the merged zone to the signer
tdns-mpcli combiner zone bump -z example.com.

# On the signer — re-sign + re-serve to downstream secondaries
tdns-mpcli signer zone bump -z example.com.

# On the zone owner's tdns-auth — re-send to all combiners
tdns-cli auth zone bump -z example.com.
```

`auth zone bump` (on the zone owner) is what you want
after changing HSYNC3 / HSYNCPARAM; it propagates the
new zone to every combiner. The other two are for
forcing a refresh of an already-loaded zone within one
provider, usually for debugging.

## 5. Recovery and Re-Sync

When the SDE has drifted from the truth — for example
after a long network partition, or after a bug — the
agent has commands to rebuild it:

```sh
# Pull: ask every peer to re-send their data for this zone
tdns-mpcli agent peer resync -z example.com. --pull

# Push: re-send our local data to combiner and peers
tdns-mpcli agent peer resync -z example.com. --push

# Both (default if no flag given)
tdns-mpcli agent peer resync -z example.com.
```

Pull happens first, then push — this way the local agent
has the complete current picture before broadcasting.

On the combiner side, the equivalent recovery is:

```sh
# Re-apply persisted contributions to in-memory zone
tdns-mpcli combiner zone edits reapply -z example.com.

# Purge everything attributed to one origin (e.g. departed
# provider). Be sure before doing this.
tdns-mpcli combiner zone edits purge -z example.com. \
    --origin agent.bravo.example.
```

`reapply` is safe and usually the right first move when
the served zone has drifted from the contributions table.
`purge` is destructive and needs care; see
[Synchronization Model §6.3](synchronization-model.md#63-purging-by-origin).

## 6. End-to-End Walkthrough: Add an NS Record

Putting it together. Operator at provider alpha decides
example.com. should pick up a new alpha-side
nameserver:

```sh
# 1. Add the record on alpha
tdns-mpcli agent zone addrr --zone example.com. \
    --rr "example.com. 3600 IN NS ns2.alpha.example."

# 2. Verify the SDE on alpha shows it PENDING then ACCEPTED
tdns-mpcli agent zone edits list --zone example.com.

# 3. Verify it landed on a remote combiner (run on bravo)
tdns-mpcli combiner zone edits list --zone example.com.

# 4. Verify alpha's signed output contains it
dog @127.0.0.1:8053 +dnssec example.com. NS

# 5. Verify bravo's served zone contains it (after AXFR
#    propagation from alpha's signer to bravo's auth)
dog @<bravo-public-addr> example.com. NS
```

If step 2 stays PENDING for one peer: that peer's
transport is broken — investigate per the triage
checklist. If step 3 shows the record at bravo's
combiner but step 5 does not, the zone has not yet
been re-transferred from alpha's signer to bravo's
auth servers — wait or trigger a bump.

## See Also

- [Synchronization Model](synchronization-model.md) —
  the per-RR tracking states and the
  `agent / combiner zone edits` commands in detail.
- [Operation and Debugging](operation-and-debugging.md)
  — peer and gossip inspection used in the
  walkthroughs above.
- [Change Tracking Semantics](mp-change-tracking-semantics.md)
  — what REJECTED means, and why non-signers cannot
  add records to a signed zone.
