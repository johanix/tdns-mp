# tdns-mp Guide

tdns-mp is the multi-provider DNSSEC coordination layer
built on top of [tdns](../../tdns/). It implements the
agent-to-agent, agent-to-combiner, and agent-to-signer
protocols needed to operate a single zone across two or
more independent DNS providers (RFC 8901 multi-signer and
the more general multi-provider case).

This guide assumes familiarity with the basic tdns
applications, configuration, and DNSSEC. For those, see the
[tdns Guide](../../tdns/guide/README.md).

## Documents

- [tdns-mp Applications](applications.md)
  -- Overview of the four mp binaries (tdns-mpagent,
  tdns-mpcombiner, tdns-mpsigner, tdns-mpcli) with links
  to per-app documentation.

- [Multi-Provider QuickStart](multi-provider-quickstart.md)
  -- Get a single-host multi-provider setup running with
  agent, combiner, and signer serving an example zone.

- [Multi-Provider Advanced Topics](multi-provider-advanced.md)
  -- Parent synchronization, provider zones,
  provider-to-provider sync, gossip protocol, leader
  elections.

- [MP Change Tracking Semantics](mp-change-tracking-semantics.md)
  -- Design decisions for how multi-provider changes are
  tracked, confirmed, and routed. Corner cases for
  non-signing providers.

- Future Work (coming soon)
  -- IXFR support, API transport for agent-agent comms,
  TSIG authentication, HPKE encryption.

## Related Documentation

- [tdns Guide](../../tdns/guide/README.md) -- the underlying
  DNS engine, authoritative nameserver, recursive resolver,
  delegation sync, transport signaling, and experimental
  record type definitions.
- [tdns Special Features](../../tdns/guide/special-features.md)
  -- definitions of the record types (HSYNC3, HSYNCPARAM,
  JWK, CHUNK) that tdns-mp builds on.
