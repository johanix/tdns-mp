# TDNS-MP

TDNS-MP is the multi-provider DNSSEC coordination layer
built on top of [TDNS](../tdns/). It implements the
agent-to-agent, agent-to-combiner and agent-to-signer
protocols needed to operate a single zone across two or
more independent DNS providers (RFC 8901 multi-signer and
the more general multi-provider case).

This repository contains only the multi-provider-specific
binaries and code. The underlying DNS engine, authoritative
nameserver, recursive resolver, query tool, keystore and
delegation-sync machinery all live in the
[tdns repository](../tdns/) and must be present as a sibling
checkout in order to build.

## Applications

| Binary           | Role                                                       |
|------------------|------------------------------------------------------------|
| tdns-mpagent     | Per-provider coordination agent                            |
| tdns-mpcombiner  | Zone combiner (merges per-provider contributions)          |
| tdns-mpsigner    | DNSSEC signer for multi-provider zones                     |
| tdns-mpauditor   | Optional read-only observer participating in gossip        |
| tdns-mpcli       | Management CLI for the four services above                 |

The `dog` query tool from tdns is the recommended way to
inspect HSYNC3, HSYNCPARAM, JWK, CHUNK and the other
experimental record types used by tdns-mp.

## Multi-Provider Specific Features

- **HSYNC3 + HSYNCPARAM** — per-provider identity records
  and zone-wide multi-provider policy in the customer zone
  apex.
- **Combiner persistence** — per-provider contributions are
  persisted with full origin attribution and survive
  restarts. Served zone is deterministically rebuilt from
  inbound zone + contributions.
- **Synched Data Engine (SDE)** — per-zone runtime cache on
  every agent of all state learned from peers, the local
  signer and the local combiner. Hydrated on startup via
  RFI EDITS / KEYSTATE / SYNC.
- **KEYSTATE-driven DNSKEY coordination** — multi-signer
  rollovers gate on per-peer confirmation so the DNSKEY
  union stays consistent.
- **JOSE/CHUNK transport** — agent-to-agent and
  agent-to-combiner messages are JWS(JWE(JWT)) payloads
  carried in the experimental CHUNK DNS record type.
- **Provider groups and gossip protocol** — agents discover
  each other from HSYNC3 records and maintain an N×N state
  matrix per provider group, exchanged on every BEAT.
- **Per-group leader election** — three-phase election
  (CALL/VOTE/CONFIRM) to designate a single agent for
  parent-facing operations.
- **Auditor role** — optional fourth-party read-only
  observer that joins gossip and receives SYNCs without
  contributing anything.

## Documentation

Start with the [tdns-mp Guide](guide/README.md). The
guide is organised as a reading order:

1. [Applications](guide/applications.md) — overview of
   the five mp binaries.
2. [Architecture](guide/multi-provider-architecture.md)
   — problem statement, roles, intra- and inter-provider
   data flow.
3. [Synchronization Model](guide/synchronization-model.md)
   — combiner persistence, SDE, origin tracking, dynamic
   HSYNCPARAM options, `agent / combiner zone edits` CLI.
4. [Quickstart](guide/quickstart.md) — bring up a
   per-provider stack via `tdns-mpcli configure`.
5. [Bringup](guide/bringup.md) — the ordered runbook
   from fresh deployment to verified working
   multi-provider network, with verification gates and
   expected CLI output at each phase.
6. [Customer Zone Setup](guide/customer-zone-setup.md) —
   the zone-owner side of phase 2 (HSYNC3 + HSYNCPARAM,
   NOTIFY/AXFR, forcing a refresh).
7. [Operation and Debugging](guide/operation-and-debugging.md)
   — day-2 CLI for peer/gossip/zone/distrib/transaction
   inspection.
8. [Making Data Changes](guide/data-changes.md) —
   `agent zone addrr/delrr`, DNSSEC key rollover,
   inspection at three layers, recovery and resync.
9. [The Auditor](guide/auditor.md) — adding the optional
   passive observer.

Reference material:

- [Change Tracking Semantics](guide/mp-change-tracking-semantics.md)
  — design decisions for change tracking, confirmation
  and routing.
- [Multi-Provider Advanced Topics](guide/multi-provider-advanced.md)
  — parent delegation sync (DSYNC), provider zones,
  `_signal` KEY publication, gossip details, leader
  election protocol.
- [Initial Provider Configuration](guide/initial-provider-configuration.md)
  — long-form manual configuration for when
  `tdns-mpcli configure` is not appropriate.

Per-binary reference cards:
[tdns-mpagent](guide/app-mpagent.md) ·
[tdns-mpcombiner](guide/app-mpcombiner.md) ·
[tdns-mpsigner](guide/app-mpsigner.md) ·
[tdns-mpcli](guide/app-mpcli.md)

For the underlying DNS engine, authoritative nameserver,
delegation sync, transport signaling and experimental RR
types, see the [TDNS Guide](../tdns/guide/README.md).

## Building

The code is split across three repositories that must be
cloned next to each other (the build uses `go.mod`
`replace` directives that reference sibling directories).

```sh
git clone https://github.com/johanix/tdns.git
git clone https://github.com/johanix/tdns-transport.git
git clone https://github.com/johanix/tdns-mp.git

cd tdns-mp/cmd
make
sudo make install
```

Requires Go 1.22+. Installs:

```
/usr/local/bin/tdns-mpcli
/usr/local/libexec/tdns-mpagent
/usr/local/libexec/tdns-mpcombiner
/usr/local/libexec/tdns-mpsigner
/usr/local/libexec/tdns-mpauditor
```
