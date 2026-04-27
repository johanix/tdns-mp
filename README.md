# TDNS-MP

TDNS-MP is the multi-provider DNSSEC coordination layer
built on top of [TDNS](../tdns/). It implements the
agent-to-agent, agent-to-combiner, and agent-to-signer
protocols needed to operate a single zone across two or
more independent DNS providers (RFC 8901 multi-signer and
the more general multi-provider case).

This repository contains only the multi-provider-specific
binaries and code. The underlying DNS engine, authoritative
nameserver, recursive resolver, query tool, keystore, and
delegation-sync machinery all live in the
[tdns repository](../tdns/) and must be present as a sibling
checkout in order to build.

## Applications

| Binary           | Role                                              |
|------------------|---------------------------------------------------|
| tdns-mpagent     | Per-provider coordination agent                   |
| tdns-mpcombiner  | Zone combiner (merges per-provider contributions) |
| tdns-mpsigner    | DNSSEC signer for multi-provider zones            |
| tdns-mpcli       | Management CLI for the three services above      |

The `dog` query tool from tdns can be used to inspect
HSYNC3, HSYNCPARAM, and other experimental record types
used by tdns-mp.

## Multi-Provider Specific Features

- **Provider groups and gossip protocol** -- agents discover
  each other from HSYNC3 records and maintain an NxN state
  matrix per provider group, exchanged on every BEAT.
- **Leader election** -- per-group three-phase election
  (CALL/VOTE/CONFIRM) to designate a single agent for
  parent-facing operations.
- **Combiner** -- merges contributions from all providers
  with a single zone owner's input zone, applying policy
  (signing authorization, protected namespaces) and
  publishing the result via outbound zone transfer to the
  signer.
- **JOSE/CHUNK transport** -- agent-to-agent and
  agent-to-combiner messages are JWS(JWE(JWT)) payloads
  carried in the experimental CHUNK DNS record type.
- **HSYNC3 + HSYNCPARAM** -- per-provider identity records
  and zone-wide multi-provider policy.
- **KEYSTATE bootstrap and signaling** -- DNSKEY publication
  is driven by KEYSTATE EDNS(0) handshakes between signer
  and agent.
- **Synched Data Engine (SDE)** -- per-zone runtime cache of
  combined provider state, hydrated from the combiner on
  startup via RFI EDITS.

## Documentation

See the [tdns-mp Guide](guide/README.md):

- [tdns-mp Applications](guide/applications.md) -- overview
  of the four mp binaries with links to per-app docs.
- [Multi-Provider QuickStart](guide/multi-provider-quickstart.md)
  -- single-host setup with agent, combiner, and signer
  serving one example zone.
- [Multi-Provider Advanced Topics](guide/multi-provider-advanced.md)
  -- parent synchronization, provider zones,
  provider-to-provider sync, gossip, leader elections.
- [MP Change Tracking Semantics](guide/mp-change-tracking-semantics.md)
  -- design decisions for change tracking, confirmation,
  and routing across agents, combiners, and signers.

For the underlying DNS engine, authoritative nameserver,
delegation sync, transport signaling, and experimental RR
types, see the [TDNS Guide](../tdns/guide/README.md).

## Building

The code is split across three repositories that must be
cloned next to each other (the build uses `go.mod` `replace`
directives that reference sibling directories).

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
```
