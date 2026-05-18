# tdns-mp Applications

tdns-mp provides five binaries for operating a
multi-provider DNSSEC setup. They share the underlying
tdns DNS engine, keystore, truststore and database
layer, but each plays a distinct role in the
multi-provider data flow.

| Application      | Binary           | Role                                                       |
|------------------|------------------|------------------------------------------------------------|
| tdns-mpagent     | tdns-mpagent     | Per-provider coordination agent                            |
| tdns-mpcombiner  | tdns-mpcombiner  | Zone combiner (center of persistence for served zone)      |
| tdns-mpsigner    | tdns-mpsigner    | DNSSEC signer for multi-provider zones                     |
| tdns-mpauditor   | tdns-mpauditor   | Optional read-only observer that participates in gossip    |
| tdns-mpcli       | tdns-mpcli       | Management CLI for the four services above                 |

The standalone tdns applications — tdns-auth, tdns-imr,
tdns-cli, tdns-agent, dog — are documented in the
[tdns Applications](../../tdns/guide/applications.md)
overview. The `dog` query tool is the recommended way to
inspect HSYNC3, HSYNCPARAM, JWK and CHUNK records (dig
cannot decode the RDATA).

## tdns-mpagent — Multi-Provider Agent

A per-provider coordination service. Watches HSYNC3
records in customer zones to discover peer agents at
other providers, runs the BEAT/gossip protocol with
them, participates in per-group leader elections, and
forwards zone updates between the local
combiner/signer and remote agents over the JOSE-secured
CHUNK transport.

[Reference](app-mpagent.md) ·
[Architecture §2.3](multi-provider-architecture.md#23-agent)

## tdns-mpcombiner — Zone Combiner

Receives the customer zone via inbound zone transfer
from the zone owner, applies contributions received
from the local agent (replacing the apex NS, DNSKEY,
CDS and CSYNC RRsets and adding any per-provider edits
authorized by HSYNCPARAM), and publishes the combined
zone via outbound zone transfer to the signer.
Contributions are persisted, attributed to their
originator, and survive restarts.

[Reference](app-mpcombiner.md) ·
[Architecture §2.1](multi-provider-architecture.md#21-combiner) ·
[Synchronization Model §1](synchronization-model.md#1-the-combiner-center-of-persistence)

## tdns-mpsigner — Multi-Provider Signer

A DNSSEC signer that consumes the combined zone from
the combiner, signs it with locally managed keys, and
serves the signed zone authoritatively to the world.
Coordinates DNSKEY publication state with the local
agent via the KEYSTATE EDNS(0) option so multi-signer
key rollovers are consistent across all providers in
the group.

[Reference](app-mpsigner.md) ·
[Architecture §2.2](multi-provider-architecture.md#22-signer) ·
[Key rollover →](data-changes.md#2-dnssec-key-rollover)

## tdns-mpauditor — Read-Only Observer

An optional fourth role. Participates in the multi-provider
network like any other party — DNS identity, HSYNC3
presence, BEAT/gossip, SYNC reception — but contributes
no zone data of its own. Used for compliance auditing,
detecting divergence between providers and surfacing
observations that no single provider would otherwise
see.

[Full guide](auditor.md)

## tdns-mpcli — Management CLI

A CLI tool to interact with all MP services via their
REST APIs. Sub-commands are organized by role (`agent`,
`combiner`, `signer`, `auditor`) and cover zone
management, peer and gossip inspection, group/election
state, combiner contribution audit, signer key state
and the DNS UPDATE, keystore and truststore operations
inherited from tdns-cli.

`tdns-mpcli configure` generates coordinated YAML
configs for all four daemons — see
[Quickstart](quickstart.md).

[Reference](app-mpcli.md)
