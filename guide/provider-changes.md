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

The owner edits the HSYNCPARAM and raises its serial; the
leader carries out the rest, one step at a time, and
needs nothing from charlie: it may be stopped. Follow it
in `tdns-mpcli agent parentsync status`. The other edits
the owner makes meanwhile wait until it is done.

Do not revoke charlie's access to the zone before "done":
it goes on serving and signing as before until its steps
take it out.

### 4.1 The owner takes charlie's roles away

Charlie leaves `servers=`, `signers=` or both, in one
edit. Its HSYNC3 record stays: removing the record of a
provider with a role is refused. With `nsmgmt="owner"`,
the same edit also drops charlie's NS records from the
owner's NS RRset (4.2).

Every agent agrees on the serial and the leader thaws it.
Charlie stays a member, with no role, until its removal
is done. The leader's first step keeps charlie's
nameserver names with the removal, on every agent, so that
any leader can go on: those charlie tells in its beats,
and those the parent's NS RRset holds that no other
provider tells or contributes. The roll of the zone's
SIG(0) key starts here, because charlie holds the private
key. If the roll fails, the removal goes on, and the roll
is tried again on its own schedule.

### 4.2 Charlie's NS records leave the zone

With `nsmgmt="agent"` the leader withdraws the NS records
charlie contributed, at every member. With
`nsmgmt="owner"` nobody withdraws anything: the owner's
edit did. Then the leader syncs with the parent and
watches it:

```
reconciling 41->42: removing agent.charlie.example., step 2 (its NS), waiting until the parent no longer names ns1.charlie.example.
```

An NS RRset of the owner's that still names charlie's
names holds this step, safely, and the status says so.

### 4.3 Charlie keeps answering

Charlie answers correctly, and keeps signing if it signs,
through the larger of the parent's and the zone's NS TTL,
plus the propagation delay, counted from when the parent
no longer names its names:

```
reconciling 41->42: removing agent.charlie.example., step 2 (its NS), waiting for the NS TTL until 2026-10-20 15:00 UTC
```

Then charlie leaves the providers whose confirmations a
key's distribution expects, and a rollover paused on it
resumes. A provider that only serves is done here. A
signer that serves nothing has no NS step: it leaves those
confirmations at the first step.

### 4.4 For a signer: NS first, DS second

1. The NS wait of 4.3 passes.
2. The leader takes charlie out of the providers whose
   KSKs have a DS. Its CDS records are withdrawn, and the
   leader syncs and watches the parent until it no longer
   serves charlie's DS.
3. The parent's DS TTL, as last served, and the DNSKEY TTL
   pass.
4. Charlie's DNSKEYs are withdrawn, it leaves the providers
   that publish keys and sign, and its own agent tells its
   signer so: it stops signing.

Steps 2 and 4 wait for an emergency rollover at another
provider; nothing else does. Charlie's DS has to outlive
its NS because every signer signs its DNSKEY RRset with
its own KSK.

### 4.5 "Safe to remove"

When the last step is done, charlie's
`tdns-mpcli agent parentsync status` ends in
`safe to remove`. Charlie's operator, not the software,
then takes the zone out of service.

If charlie's agent was running and stopped answering, or
was stopped, it is excused after
`multi-provider.transitions.leaving-timeout`, with a log
line, and the removal goes on without it.

### 4.6 The owner removes the HSYNC3 record

Last, after every cache has expired: a transition of its
own, with nothing to carry out. Comms with charlie end
after the hold time.

When a transition is done, each agent drops from its own
data, and from its own combiner, every contribution the
active instructions do not entitle its origin to: NS
needs `nsmgmt="agent"` and the origin in `servers=`;
DNSKEY and CDS the origin in `signers=`; KEY and CSYNC
are the leader's. No purge by hand is needed after a
removal.

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
`not-built`): a server role (3.4), a move into `signers=`
(3.4, 5.1), and a change of
`parentsync`. So a change of
`parentsync` is refused: the owner does not write to the
parent. A role taken away is carried out (section 4).

A change of `auditors=` or `suffix`, and an HSYNC3 record
added or removed for a provider with no role, are agreed.

A change of `nsmgmt` is agreed too, and takes effect at the
leader's step for it, not when the owner's edit arrives:

- To the owner: every combiner stops applying the agents' NS
  records and serves the owner's NS RRset, every agent drops
  the NS records from its data, and the combiners drop what
  they stored. Have the NS RRset the zone is to have in place
  before the edit.
- To the agents: nothing that was stored comes back. Each
  provider's operator adds its NS records again (3.5).

Under `nsmgmt="owner"` the owner's NS RRset may name a
provider's nameservers only once that provider's role is
done. Every agent warns about one that does, by the names
each provider sets in `multi-provider.local.nameservers`: in
`tdns-mpcli agent parentsync status`, and once an hour in its
log. A provider with no names configured is not checked.

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
