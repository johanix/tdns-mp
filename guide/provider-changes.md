# Changing the Set of Providers

This document covers the three changes a zone owner makes
to the providers of a running multi-provider zone: adding
a provider, removing one, and changing a provider's role.
It builds on:

- [Customer Zone Setup](customer-zone-setup.md) — the
  HSYNC3 and HSYNCPARAM records the owner edits.
- [Making Data Changes](data-changes.md) — the `addrr` /
  `delrr` and resync commands used here.
- [Multi-Provider Advanced Topics](multi-provider-advanced.md)
  — leader election and parent delegation sync.

Running example: `example.com.` with alpha (signer +
server) and bravo (server only). Charlie is the provider
that is added, removed or changed.

**This page describes the required order.** tdns-mp does
not take every step by itself yet. Where it does not, the
step says what an operator does by hand today, and names
the issue that tracks it.

One rule stands above the rest: an operation may stall,
but the zone must never go bogus or lame.

Every edit of HSYNC3 or HSYNCPARAM raises HSYNCPARAM's
`serial=`, and every agent judges it before it acts on it:
see section 6 for the owner's rules and what is refused.

## 1. The Ordering Rule

**Adds start at the edge and end at the parent. Deletes
start at the parent and end at the edge.**

The edge is the provider's own servers. The parent is the
delegation: the NS RRset that sends resolvers to a
provider, and the DS RRset that makes them trust its keys.

- A provider that is added must serve the zone correctly
  before anything points at it. Its keys must be
  published by every signer before its signatures are
  served. Its NS record and its DS reach the parent last.
- A provider that is removed loses what points at it
  first. It keeps answering correctly until nothing in
  any cache can still send a resolver to it.

## 2. Who Is a Member

- Every provider with an HSYNC3 record is a member of the
  zone's group: discovery and comms run with it.
- A member with no role in HSYNCPARAM is in transition,
  on its way in or on its way out. It does not vote in
  the leader election and cannot be leader.

Both changes below pass through that state: an HSYNC3
record and no role.

**Today:** the group is built from the roles, so a
provider with no role is left out of it
([issue 158](https://github.com/johanix/tdns-mp/issues/158)).

## 3. Adding a Provider

### 3.1 The owner adds the HSYNC3 record

```
example.com.   HSYNC3   ON  charlie  agent.charlie.example.  alpha
```

HSYNCPARAM is left as it is. Charlie has no role yet. The
last field names charlie's upstream, for a provider that
will not sign.

### 3.2 Discovery, comms and catching up

The other agents discover charlie's agent and comms
start. Charlie's agent asks the others for the current
state of the zone: what each has contributed, and the
DNSKEYs with their key states.

**Today:** charlie's agent does not ask while charlie has
no role: the others would refuse the request
([issue 158](https://github.com/johanix/tdns-mp/issues/158)).
It asks by itself once charlie has its role (step 3.4),
and each answer carries the DNSKEYs with their key states.
To ask again by hand:

```sh
tdns-mpcli agent peer resync -z example.com. --pull
```

`tdns-mpcli agent parentsync status` shows, per voting
member, whether its answer is complete.

### 3.3 Charlie serves the zone correctly

Before the owner lists it, charlie answers for the zone
with correct data: not at all until it has the zone, and
signed if the zone is signed. Answering before it is
listed is not an error. It is the gate for adding any
nameserver.

Check it from outside, at charlie's public nameserver:

```sh
dog @ns.charlie.example. example.com. SOA +dnssec
```

**Today:** a provider that is about to sign can answer
with an unsigned copy of a signed zone before it is listed
([issue 137](https://github.com/johanix/tdns-mp/issues/137)).
Do not go on until its copy validates.

### 3.4 The owner gives charlie its role

As a server:

```
example.com.   HSYNCPARAM   servers="alpha,bravo,charlie" signers="alpha" ...
```

As a signer and server, in this order:

1. `signers="alpha,charlie"` first, or `signers=` and
   `servers=` in one edit. Never `servers=` first: that
   lists a provider that cannot yet sign what it serves.
2. Charlie makes its keys. Every signer publishes them,
   and the leader adds charlie's DS at the parent.
3. The owner waits for the caches: the TTL of the DNSKEY
   RRset and of the DS RRset.
4. `servers="alpha,bravo,charlie"`, if it was not in the
   first edit.

**Today:** a provider named in `signers=` while its
signer is running does not sign until the signer is
restarted
([issue 146](https://github.com/johanix/tdns-mp/issues/146)).

### 3.5 Charlie's NS records

Which NS records a provider adds is its operator's
decision. With `nsmgmt="agent"` charlie's operator adds
them through the agent:

```sh
tdns-mpcli agent zone addrr --zone example.com. \
    --rr "example.com. 3600 IN NS ns.charlie.example."
```

No NS record of a provider goes into the NS RRset until
the provider serves a correctly signed zone. With
`parentsync="agent"` the leader then carries the new NS
RRset to the parent: the add ends there.

## 4. Removing a Provider

A planned removal, with the leaving provider's
cooperation.

### 4.1 The owner takes charlie's roles away

Charlie leaves `servers=` and `signers=`. Its HSYNC3
record stays.

### 4.2 Charlie's NS records leave the zone

With `nsmgmt="agent"` the NS records charlie contributed
are removed at this moment, not when its HSYNC3 record
goes: by then it is too late. With the NS RRset managed
by the owner, the owner removes them in the same edit.

**Today:** contributed NS records stay until an operator
purges them at every remaining provider
([issue 159](https://github.com/johanix/tdns-mp/issues/159)):

```sh
tdns-mpcli combiner zone edits purge -z example.com. \
    --origin agent.charlie.example.
```

### 4.3 Charlie keeps answering

Charlie answers correctly, and keeps signing if it signs,
for the NS RRset's TTL plus a safety period of its own.
It notes any query that still arrives.

**Today:** a provider taken out of `signers=` goes on
signing for as long as its HSYNC3 record stays
([issue 147](https://github.com/johanix/tdns-mp/issues/147)).
Its combiner applies what it is sent, and the other
providers treat it as a signer. It starts nothing of its
own: no keys, no rollover. Section 4.6 gives the order
of the owner's edits.

Charlie takes no key distribution from the others, so
while it leaves, **no signer of the zone rolls a key**.
Every signer's key machine pauses, an emergency rollover
included, and `tdns-mpcli signer key status` says
"key rollovers paused: agent.charlie.example. is leaving
the signing set". The rollovers resume when the owner
removes charlie's HSYNC3 record. To end the pause early,
finish the leave.

### 4.4 For a signer: NS first, DS second

1. The NS wait of 4.3 passes.
2. The leader removes charlie's DS at the parent. It
   needs nothing from charlie for that: when it is safe
   is a matter of time and TTL only.
3. The DS RRset's TTL passes.
4. The other signers drop charlie's DNSKEYs.

Charlie's DS has to outlive its NS because every signer
signs its DNSKEY RRset with its own KSK.

**Today:** while charlie's HSYNC3 record stays, the other
signers keep its DNSKEYs and its DS stays in the zone's
DS set. Both go at once when the owner removes the
record (4.6). The steps above, each at its own time, are
not built yet
([issue 138](https://github.com/johanix/tdns-mp/issues/138),
[issue 211](https://github.com/johanix/tdns-mp/pull/211)).

### 4.5 "Safe to remove"

When the waits are over, charlie's `zone mplist` shows
the zone as safe to remove. Charlie's operator, not the
software, then takes the zone out of service.

**Today:** nothing says so
([issue 137](https://github.com/johanix/tdns-mp/issues/137)).
Count the waits by hand.

### 4.6 The owner removes the HSYNC3 record

Last, after every cache has expired.

**Today**, the owner's order for a signer:

1. Take charlie out of `signers=` and `servers=`. Under
   `nsmgmt=owner`, drop charlie's NS records from the
   owner's NS RRset in the same edit.
2. Wait until the parent no longer lists charlie's NS
   records. Then wait the NS TTL, then the DS TTL.
3. Only then remove charlie's HSYNC3 record.

Removing the record ends everything at once. Charlie's DS
leaves the DS set, and the leader removes it at the
parent. The other signers drop charlie's DNSKEYs.
Charlie's combiner refuses its own agent's operations,
and charlie is no longer a provider of the zone. Its
operator then takes the zone out of service (4.5).

For a few seconds the parent may still hold charlie's DS
after the other signers have dropped its keys. The other
DS records keep the chain. That holds when the remaining
signers use charlie's algorithm. A validator that guards
against algorithm downgrade can fail on a DS of an
algorithm no DNSKEY has.

## 5. Changing a Provider's Role

The role is the zone owner's decision, made in
`signers=`.

### 5.1 A server becomes a signer too: allowed

- It starts above the serial it was serving.
- It needs no restart.
- It does not serve its own signatures until its DS is at
  the parent and the earlier DS and DNSKEY RRsets have
  left caches. Until then it goes on serving the copy of
  its upstream signer. It is already in the NS RRset, so
  this wait is its own to keep.

**Today:** the agents refuse the edit until a signer role
can be carried out (section 6). It needs a restart of its
signer
([issue 146](https://github.com/johanix/tdns-mp/issues/146)),
and it serves its own signatures before its DS is at the
parent
([issue 160](https://github.com/johanix/tdns-mp/issues/160)).

### 5.2 A signer becomes a server only: not allowed

A provider that has signed a zone has a serial of its
own, and it can be above the serial of its new upstream.
It would then never take the upstream's copy.

If the owner makes that edit, the provider keeps signing
and its operator is told. To get there, the owner removes
the provider completely (section 4) and adds it back as a
server (section 3).

**Today:** every agent refuses the edit
(`signer-to-server`, section 6) and shows it, but does
not enforce the refusal yet. The provider keeps signing
for as long as its HSYNC3 record stays, as a leaving
signer does (4.3,
[issue 147](https://github.com/johanix/tdns-mp/issues/147)).

## 6. The Owner's Edits

Every agent of the zone keeps the owner's instructions by
their serial, and judges each edit against the serial it
acts by. The owner:

- **Raises `serial=` at every edit** of HSYNC3 or
  HSYNCPARAM, never by 2^31 or more at once. An edit at
  the same serial is an owner error: the agents hold the
  zone until a copy with a higher serial arrives, and
  putting the old contents back at the same serial does
  not end it. A zone without `serial=` is at serial 0,
  and its first change is an owner error.
- **Keeps the order** of records and roles: the HSYNC3
  record first and a role later, each its own edit; the
  roles away first and the record later.
- **Waits for "done"** before the next edit. An edit made
  earlier waits at the agents.
- **Does not revoke a leaving provider's access** to the
  zone before "done".
- **Upgrades every agent of the zone** before an edit. A
  mix of versions only stalls.

Every agent refuses, with the same reason:

| The edit                                                                 | Refused as                |
|--------------------------------------------------------------------------|---------------------------|
| Removes, or turns OFF, the HSYNC3 record of a provider with a role       | `record-with-role-removed`|
| Gives a role to a label with no HSYNC3 record, or removes its record      | `role-without-record`     |
| Changes the identity under a label with a role                           | `identity-changed`        |
| Moves a signer to `servers=` only (5.2)                                  | `signer-to-server`        |
| Empties `signers=`                                                       | `signers-emptied`         |
| Leaves an upstream that is not in `signers=`, or has no HSYNC3 record    | `upstream-dangling`       |
| Takes out of `signers=` the upstream of a server that stays: move the server's upstream first, as its own edit | `upstream-signer-removed` |

On this build the agents also refuse every edit whose
steps tdns-mp does not carry out yet (`step-missing`,
`not-built`): a role taken away (section 4), a server role
(3.4), a move into `signers=` (3.4, 5.1), and a change of
an upstream, of `nsmgmt`, `parentsync`, `pubkey` or
`pubcds`. So:

- a removal is refused. The owner keeps the provider's NS
  records in its own NS RRset and at the parent;
- a change of `parentsync` is refused. The owner does not
  write to the parent.

A change of `auditors=` or `suffix`, and an HSYNC3 record
added or removed for a provider with no role, are agreed.

The refusal shows in `tdns-mpcli agent parentsync status`
(`instructions: 42 refused: ...`), in `zone mplist` and in
the auditor's configuration errors, and once in each
agent's log.

**Today:** the refusal is shown, not enforced. Until the
agents agree on a serial before they act on it, they act
by the zone's own copy, refused or not
([issue 211](https://github.com/johanix/tdns-mp/issues/211)).

## 7. Open Points

- Whether `servers=` before `signers=` is refused for a
  provider that is to sign. The owner's later intent
  cannot be known from the first edit.
- Who removes a leaving provider's NS records: every
  remaining provider when it sees the `servers=` change,
  or the leaving provider's own agent.

## 8. See Also

- [Customer Zone Setup](customer-zone-setup.md) — the
  records, and how the owner's edits reach the combiners.
- [Making Data Changes](data-changes.md) — NS edits, key
  rollover, resync and purge.
- [The Auditor](auditor.md) — watching a change from the
  zone owner's side.
