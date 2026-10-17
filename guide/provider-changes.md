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

**One provider at a time.** Change the set of providers
one provider at a time, and let each edit settle before
the next. At every step at least one provider that serves
or signs the zone before the edit must still do so after
it.

Do not exchange the whole set in one edit: the only
provider replaced by another, or two providers replaced by
a third. The providers agree on a change through the ones
that are part of the zone both before and after it. An
edit that leaves none gives them nobody to agree through,
and for a while the old providers and the new ones can
both update the parent.

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
([issue 158](https://github.com/johanix/tdns-mp/issues/158)),
and an agent with no role may elect itself leader of a
zone when it sees no peers
([issue 172](https://github.com/johanix/tdns-mp/issues/172)).

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

**Today:** nothing sends that request. Run it by hand on
charlie once it is a member:

```sh
tdns-mpcli agent peer resync -z example.com. --pull
```

Its answer carries the DNSKEYs and not their key states
([issue 157](https://github.com/johanix/tdns-mp/issues/157)).
While charlie has no role the others refuse the request
([issue 158](https://github.com/johanix/tdns-mp/issues/158)),
so today it only works after step 3.4.

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

The edit of 4.1 withdraws nothing by itself. It starts
the removal, which the leader of the zone's group runs.
Charlie is never that leader, and the leader needs
nothing from charlie to do it. With `parentsync="agent"`
and a parent that takes UPDATE, the removal's first step
is a roll of the zone's SIG(0) key, since charlie holds
its private key. With `nsmgmt="agent"` the leader removes
the NS records charlie contributed as a step of the
removal, not when charlie's HSYNC3 record goes: by then
it is too late. With the NS RRset managed by the owner,
the owner removes them. Whether the zone's NS RRset or
the parent's delegation changes first is open
(section 6).

**Today:** nothing rolls the zone's SIG(0) key for a
multi-provider zone. The agent's
`zone dsync roll-sig0-key` runs the single-provider roll:
it hands the new key to no other member, and it has not
been tried on a multi-provider zone. So a provider that
leaves and holds the zone's private key keeps it, and
with it a key the parent may still trust. Today that is
a provider that led the zone when the key was made, or
one the key was handed to through the upstream relation.
Contributed NS
records stay until an operator purges them at every
remaining provider
([issue 159](https://github.com/johanix/tdns-mp/issues/159)):

```sh
tdns-mpcli combiner zone edits purge -z example.com. \
    --origin agent.charlie.example.
```

### 4.3 Charlie keeps answering

Charlie answers correctly for the NS RRset's TTL plus a
safety period of its own, and notes any query that still
arrives. A signer goes on signing until the leader
removes its DNSKEYs (4.4, 4.5).

**Today:** a provider taken out of `signers=` stops
signing at its next zone refresh and serves an unsigned
copy
([issue 147](https://github.com/johanix/tdns-mp/issues/147)).
Removing a signing provider is not safe until that is
fixed.

### 4.4 For a signer: NS first, DS second

1. The NS wait of 4.3 passes.
2. The leader removes charlie's DS at the parent. It
   needs nothing from charlie for that: when it is safe
   is a matter of time and TTL only.
3. The DS RRset's TTL passes.
4. The leader removes charlie's DNSKEYs. Until then
   every other signer keeps them in its key set.

Charlie's DS has to outlive its NS because every signer
signs its DNSKEY RRset with its own KSK.

**Today:** the remaining signers drop charlie's keys with
the owner's edit, and nothing removes its DS in this
order
([issue 138](https://github.com/johanix/tdns-mp/issues/138)).

### 4.5 "Safe to remove"

When the waits are over, charlie's `zone mplist` shows
the zone as safe to remove. For a signer, the leader's
removal of its DNSKEYs (4.4) is where charlie stops
signing and serving the zone. For a server only, charlie's
operator, not the software, then takes the zone out of
service.

**Today:** nothing says so
([issue 137](https://github.com/johanix/tdns-mp/issues/137)).
Count the waits by hand.

### 4.6 The owner removes the HSYNC3 record

Last, after every cache has expired.

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

**Today:** it needs a restart of its signer
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

**Today:** the provider stops signing
([issue 147](https://github.com/johanix/tdns-mp/issues/147)).

## 6. Open Points

- Whether `servers=` before `signers=` is refused for a
  provider that is to sign. The owner's later intent
  cannot be known from the first edit.
- Whether the zone's NS RRset or the parent's delegation
  changes first when a provider leaves.

## 7. See Also

- [Customer Zone Setup](customer-zone-setup.md) — the
  records, and how the owner's edits reach the combiners.
- [Making Data Changes](data-changes.md) — NS edits, key
  rollover, resync and purge.
- [The Auditor](auditor.md) — watching a change from the
  zone owner's side.
