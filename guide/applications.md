# tdns-mp Applications

tdns-mp provides four binaries for operating a multi-provider
DNSSEC setup. They share the underlying tdns DNS engine,
keystore, truststore, and database layer, but each plays a
distinct role in the multi-provider data flow.

| Application      | Binary           | Role                                       |
|------------------|------------------|--------------------------------------------|
| tdns-mpagent     | tdns-mpagent     | Per-provider coordination agent            |
| tdns-mpcombiner  | tdns-mpcombiner  | Zone combiner                              |
| tdns-mpsigner    | tdns-mpsigner    | DNSSEC signer for multi-provider zones     |
| tdns-mpcli       | tdns-mpcli       | Management CLI for the three services above |

The standalone tdns applications -- tdns-auth, tdns-imr,
tdns-cli, tdns-agent, dog -- are documented in the
[tdns Applications](../../tdns/guide/applications.md)
overview. The `dog` query tool is the recommended way to
inspect HSYNC3, HSYNCPARAM, JWK, and CHUNK records.

## tdns-mpagent -- Multi-Provider Agent

A per-provider coordination service. Watches HSYNC3 records
in customer zones to discover peer agents at other
providers, runs the BEAT/gossip protocol with them,
participates in per-group leader elections, and forwards
zone updates between the local combiner/signer and remote
agents over the JOSE-secured CHUNK transport.

[Full documentation](app-mpagent.md)

## tdns-mpcombiner -- Zone Combiner

Receives the customer zone via inbound zone transfer from
the zone owner, applies contributions received from the
local agent (replacing the apex NS, DNSKEY, CDS, and CSYNC
RRsets and adding any per-provider edits authorized by
HSYNCPARAM), and publishes the combined zone via outbound
zone transfer to the signer.

[Full documentation](app-mpcombiner.md)

## tdns-mpsigner -- Multi-Provider Signer

A DNSSEC signer that consumes the combined zone from the
combiner, signs it with locally managed keys, and serves
the signed zone authoritatively. Coordinates with the agent
via KEYSTATE EDNS(0) signaling so that DNSKEY publication
across providers is consistent.

[Full documentation](app-mpsigner.md)

## tdns-mpcli -- Management CLI

A CLI tool to interact with all three mp services via their
REST APIs. Sub-commands cover agent zone management, peer
and gossip inspection, group/election state, combiner
contribution audit, signer key state, and the DNS UPDATE,
keystore, and truststore operations inherited from
tdns-cli.

[Full documentation](app-mpcli.md)
