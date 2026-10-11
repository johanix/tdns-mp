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

A signer handles the keys of a multi-provider zone in
one of two ways:

- **The signer's key machine runs them.** The signer
  generates new keys and rolls them. Before it moves a
  key on, it waits for the other signing providers and,
  for a KSK, for the parent. This is switched on per
  zone (2.1) and described in sections 2.2 to 2.6.
- **The key machine does not run them.** This is the
  case for every zone that has not been switched on.
  The operator rolls the keys with the keystore
  commands (2.7).

To see which zones the key machine runs on this signer:

```sh
tdns-mpcli signer key zones
```

### 2.1 Switching the key machine on for a zone

Add the zone to `key-lifecycle-zones` in the
`multi-provider:` section of the signer's config
(`tdns-mpsigner.yaml`) and restart the signer:

```yaml
multi-provider:
   role:   signer
   # identity, keys and agents as before
   key-lifecycle-zones:
      - example.com.
   # Optional: how long a key may wait for the peers'
   # confirmations before it is sent again. Default 10m.
   key-lifecycle-resend: 10m
```

`tdns-mpcli configure` does not write these two keys.

The signer takes a listed zone once the zone is loaded
and its DNSSEC policy is bound; until then it tries
again every 30 seconds. The keys the zone already has
are kept, and the machine runs them from then on. Two
kinds of zone are left out, each with an error in the
signer's log:

- a zone without the `multi-provider` option;
- a zone this provider does not sign (its label is not
  in the HSYNCPARAM `signers=` list).

The setting belongs to this signer and covers this
provider's keys for the zone. There is no setting that
switches the machine on for all zones at once.

A signer with at least one zone listed also starts its
own resolver. The key machine uses it to ask which DS
records the parent serves for the zone. Leave it on:
with `imrengine.active: false` the machine cannot ask
the parent, and a KSK roll does not complete.

### 2.2 What starts a roll

On a zone the key machine runs, the KSK or the ZSK is
rolled for one of two reasons.

**Age.** The zone's DNSSEC policy gives each role a
lifetime (`ksk.lifetime` and `zsk.lifetime`; see
[Initial Provider Configuration §4.3](initial-provider-configuration.md#43-signer-configuration)).
When the active key of a role has been active for that
long, the machine rolls it. The lifetimes the machine
applies are shown by:

```sh
tdns-mpcli signer key policy -z example.com.
```

A role whose lifetime is shown there as `forever` is
never rolled because of its age.

**A request.**

```sh
tdns-mpcli signer key rollover -z example.com. --role ZSK
tdns-mpcli signer key rollover -z example.com. --role KSK
```

`--role` defaults to KSK. The machine acts on the
request at its next tick (it ticks every 30 seconds)
and promotes the next standby key of that role, on the
conditions in 2.3. If there is no standby key yet the
request waits for one, and if no key of the role is on
its way at all the machine first generates one. A
request that has not been carried out yet can be taken
back:

```sh
tdns-mpcli signer key rollover cancel -z example.com. --role KSK
```

The machine keeps standby keys ready, as many per role
as `standby-zsk-count` and `standby-ksk-count` under
`dnssec.kasp` say (1 and 0 when not set). So a ZSK roll
normally finds a standby key waiting, and a KSK roll
normally starts by generating one.

### 2.3 What the machine waits for

`signer key status` (2.4) shows the state of every key.
A new key is `created` and sent out on the same tick.
After that it goes through the states below, in order.
The machine moves a key on only when the condition is
met, so each condition is also a place where a roll can
stall.

1. **`mpdist`.** The key is in this provider's DNSKEY
   RRset and has been sent to the other providers
   through the agents. It stays here until every other
   signing provider has confirmed that it applied the
   key. With no other signing provider (the running
   example, where only alpha signs) there is nobody to
   wait for.
2. **`published`.** The key waits for
   `kasp.propagation-delay` plus the TTL of the DNSKEY
   RRset.
3. **`standby`.** The key is ready to take over. For a
   KSK, its DS is now part of the zone's DS set. The
   signer publishes that set as CDS, and for a zone
   that syncs with its parent through its agents the
   elected leader agent sends the change to the parent
   (see
   [Multi-Provider Advanced Topics §1](multi-provider-advanced.md#1-parent-synchronization)).
   The key stays here until a roll starts (2.2). A ZSK
   is then promoted at the next tick. A KSK is promoted
   only once the signer has seen the parent serve the
   key's DS for as long as the TTL of the DS RRset. If
   the parent serves no DS at all for the zone, there
   is nothing to wait for. If the parent cannot be
   asked, the key waits.
4. **`active`.** The key signs. The key it replaces
   becomes `retired` in the same step.
5. **`retired`.** The key no longer signs but stays in
   the DNSKEY RRset. A retired KSK's DS is taken out of
   the zone's DS set at once, and the key waits until
   the parent no longer serves it. When
   `kasp.propagation-delay` has passed since the key
   retired (and, for a KSK, its DS is gone from the
   parent), the signer removes the key's signatures
   from the zone and takes the key out of the DNSKEY
   RRset.
6. **`mpremove`.** The removal has been sent to the
   other providers. When every other signing provider
   has confirmed it, the key is `removed`.

The waits in steps 1 and 6 are how RFC 8901
multi-signer correctness is enforced: if a peer does
not answer, the roll stalls rather than de-syncing the
DNSKEY set.

### 2.4 Watching a roll

```sh
tdns-mpcli signer key status -z example.com.
```

This prints:

- The DNSSEC policy bound to the zone, and the other
  signing providers.
- One row per key: its `State`, three columns that say
  what the key does now (`Pub`: it is in the DNSKEY
  RRset; `Sign`: it signs; `DS`: its DS belongs at the
  parent, `-` when that is not decided), and the times
  it was published, became active and retired. The
  other providers' keys are listed too, in state
  `foreign`.
- `Distributions in flight`: every key, or removal of a
  key, that still waits for confirmations, with the
  providers expected, applied, pending and rejected,
  and the reason for a rejection.
- `Rollover requested`: the roles with a request that
  has not been carried out yet.

The agent sends the signer one answer for all peers
together, so this view does not say which peer is
missing. The agent's own view does:

```sh
tdns-mpcli agent zone edits list --zone example.com.
```

The provider's own DNSKEYs are listed there with their
tracking state. A key that is still PENDING names the
peers that have not confirmed yet.

### 2.5 When a roll stalls

Find the key in `signer key status` and go by what it
shows.

- **A key stays in `mpdist` or `mpremove`.** A peer has
  not answered. The agent reports to the signer only
  when every other agent of the zone has answered,
  those of providers that do not sign included, so one
  unreachable peer holds the key.
  `agent zone edits list` shows which one. From there
  it is the same triage as any other peer problem — see
  [Operation and Debugging §6](operation-and-debugging.md#6-putting-it-together-a-triage-checklist).
- **A key is listed as rejected.** A peer refused the
  key, or a signing provider does not take this
  provider for a signer of the zone. The key stays
  where it is: the machine undoes nothing by itself,
  and it never promotes a rejected key. See the two
  commands below.
- **A standby KSK is not promoted.** The parent does
  not serve the key's DS yet, has served it for less
  than the DS TTL, or could not be asked. Check what
  the parent serves, that parent synchronization works
  for the zone, and that the signer's resolver is on.
- **A retired KSK does not go away.** The parent still
  serves its DS, or could not be asked.
- **Another provider's KSK has `-` in the `DS`
  column.** That provider has not said whether the
  key's DS belongs at the parent. Until it does, the
  zone's DS set is unknown, and no CDS and no DS change
  reaches the parent.

For a rejected key, fix the cause and send the key
again, or give the key up:

```sh
tdns-mpcli signer key retry -z example.com. --keyid 56789
tdns-mpcli signer key withdraw -z example.com. --keyid 56789
```

`retry` forgets the rejection and sends the key (or its
removal) to the providers that sign the zone now.
`withdraw` works on a key in `mpdist`, `published` or
`standby`: the key leaves the DNSKEY RRset and its
removal is sent to the peers. An active key is not
withdrawn; it is rolled.

The signer logs a warning,
`key lifecycle: needs the operator`, with the zone, the
key and the reason, when a key is rejected, and when a
key has waited for the parent, or for another
provider's word about a DS, for three times
`kasp.propagation-delay`.

### 2.6 What the key machine does not do

- **Zones that are not listed.** The machine runs only
  the zones in `key-lifecycle-zones` (2.1).
- **Algorithm rollover.** The machine does not roll a
  zone to another algorithm.
  `signer key policy --set NAME` binds another DNSSEC
  policy to the zone, and its lifetimes apply from the
  next tick, but a policy with another algorithm,
  another mode or another DS model is refused. The
  binding is not written to the config file, so change
  the zone's `dnssecpolicy:` there as well.
- **Sending to the parent.** The machine only asks the
  parent what it serves. A DS reaches the parent as
  step 3 of 2.3 says. If it never does, the KSK stays
  in `standby`.
- **Per-zone standby counts and waits.** They come from
  `dnssec.kasp` and are the same for every zone on the
  signer.
- **Remembering a request over a restart.** A rollover
  request that has not been carried out is lost when
  the signer restarts. Ask again.

### 2.7 Manual rollover

On a zone the key machine does not run, nothing rolls
the keys by itself: the automatic rollover that
tdns-auth has for its own zones leaves multi-provider
zones alone. The operator rolls them:

```sh
tdns-mpcli signer keystore dnssec rollover -z example.com. --keytype ZSK
tdns-mpcli signer keystore dnssec rollover -z example.com. --keytype KSK
```

This performs a manual key state advance: standby →
active, active → retired. The zone is re-signed with
the new active key; the retired key stops signing but
stays published. The signer takes a retired ZSK out of
the DNSKEY RRset by itself when its margin has passed.

The command acts at once. It does not wait for the
peers and does not look at the parent, so check both
before a roll: that every peer has the new key
(`agent zone edits list`, see 2.4) and, for the KSK of
a zone that has DS records at the parent, that the
parent already serves the new key's DS.

The roll needs a key of that type in state `standby`.
Verify the keystore state before and after the
rollover with:

```sh
tdns-mpcli signer keystore dnssec list -z example.com.
```

The signer keeps standby ZSKs ready on such a zone too
(`standby-zsk-count`). A key it generates for that is
first held in `mpdist`, until the agent reports that
the peers have confirmed it. If there is no standby
key, generate a key:

```sh
tdns-mpcli signer keystore dnssec generate -z example.com. \
    --keytype ZSK --state published --algorithm ED25519
```

The new key starts as `published`; `list` shows when it
has become a standby key.

On a zone the key machine runs,
`keystore dnssec rollover` is refused, with an error
that points to `signer key rollover`, and
`keystore dnssec generate` is refused too.

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
