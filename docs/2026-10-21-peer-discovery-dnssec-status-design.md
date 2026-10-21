# Peer discovery and DNSSEC: what an operator sees

Status: implemented in tdns #947, tdns-transport #37 and tdns-mp #263 (for
#260). The plan beside this document,
`2026-10-21-peer-discovery-dnssec-status-plan.md`, has the code changes and
their state.

## The problem

An agent discovers a peer from the peer's identity zone: the URI records
for its API and DNS endpoints, the SVCB records with their addresses, the
TLSA record that its certificate is checked against, and the JWK (or KEY)
with its long-term key. Every one of these is security-sensitive: what the
zone says is what the agent then trusts.

With `imrengine.require-dnssec-validation: true` (the default), an answer the
resolver could not validate is refused. With it set to `false`, the answer is
used anyway.

Both cases used to be invisible:

- A refused answer read as a missing one. The peer stayed NEEDED, and the
  default log said "no contact endpoints found (no API or DNS URI records)"
  although the records were served and signed. Only a debug log showed the
  refusal.
- With validation off, nothing said so. A node that takes discovery data
  nobody could validate is exposed, and a setting turned off to get past a
  broken chain is easily forgotten.

Discovery also kept what it found for as long as the peer was known. A peer
could stay OPERATIONAL on data whose TTL and signatures had run out long
ago, and whose chain might have broken since.

## Rules

### The verdict is about the chain

Every RRset discovery reads gets a verdict: **secure** (validated),
**insecure** (not validated: unsigned, no trust anchor above it, or not
judged) or **bogus** (signed, and the signatures fail). A denial gets one
too: the verdict on its proof.

The verdict describes the peer's chain, not what the local setting did with
it. The state of the peer says that:

| chain    | validation required          | validation off     |
|----------|------------------------------|--------------------|
| secure   | used                         | used               |
| insecure | refused: the peer is NEEDED  | used, and marked   |
| bogus    | refused: the peer is NEEDED  | used, and marked   |

A peer's verdict is the worst over every RRset discovery read for it, the
refused ones included. For a mechanism (API, DNS) it is the worst over that
mechanism's RRsets.

### A denial that is not validated proves nothing

With validation required, a denial that was not validated is refused as an
answer would be. It is not read as "the records do not exist": a forged
denial of the API's URI would otherwise pass as "this peer has no API".

### Why discovery failed

When discovery gives nothing to use, the peer keeps the reason: the
RRset, and what went wrong with it:

- **not validated**: refused, as validation is required;
- **no records**: the name or the records do not exist, or none is usable;
- **unreachable**: no server for the name answered;
- **query failed**: the lookup failed in another way.

The reason that tells most wins: a refusal for want of validation over an
unreachable zone over another failure over missing records. The reason is
also what the default-level log says, for example
`URI at _https._tcp.agent.example.: answer insecure, DNSSEC validation
required`.

### Data expires

Data that validated when it was looked up is used until it expires from the
resolver's cache. An entry lives no longer than its smallest TTL, and an
entry held secure no longer than its signatures. Then the peer is looked up
again, and the new answers decide:

- validated: the peer goes on as it was;
- refused for want of validation: the mechanism the data was for is not
  used any more, whatever it held before. It goes back to NEEDED and needs
  discovery again. When no mechanism is left in use, the peer is NEEDED;
- the lookup cannot run (the zone is unreachable): that says nothing about
  the data. The peer keeps what it has and is asked for again, at most once
  a minute.

The TLSA set is read through the cache before every use already, so its
verdict follows the set in use.

### What the operator sees

The daemon keeps a peer's state plain, and gives the verdict beside it. The
CLI adds a mark to the state:

- `(-)`: the chain is insecure;
- `(!)`: the chain is bogus.

So `NEEDED(-)` is a peer refused because its chain is not validated, and
`OPERATIONAL(-)` a peer in use on data nobody validated.

`peer list` marks each mechanism's state, and has a Discovery column with
the reason when any peer has one. `peer list -v` shows the verdict, the
reason and when the data expires.

`gossip state` marks each cell with the verdict as the reporter sees it.
Each member's gossip row carries its verdicts for its peers, and whether its
own validation is off.

After either view, when a state is marked or validation is off on a node in
it, the CLI prints:

- a warning naming where validation is off, for example
  `WARNING: DNSSEC validation is OFF on agent-a: peers are discovered on DNS
  data that is not validated`;
- the legend of the marks.

Wherever validation is off, it is also said where the operator looks
without asking:

- `daemon status` starts with
  `DNSSEC validation: OFF (imrengine.require-dnssec-validation: false)`;
- the daemon logs a warning at start and then every hour.

## Not covered

- The auditor's web view of the gossip matrix shows the states without
  marks.
- A URI that disappears, with a validated denial, does not take a mechanism
  out of use. Only a refusal for want of validation, or a withdrawn TLSA,
  does.
