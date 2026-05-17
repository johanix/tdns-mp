# tdns-mp Guide

tdns-mp is the multi-provider DNSSEC coordination layer
built on top of [tdns](../../tdns/). It implements the
agent-to-agent, agent-to-combiner and agent-to-signer
protocols needed to operate a single zone across two or
more independent DNS providers (RFC 8901 multi-signer and
the more general multi-provider case).

This guide assumes familiarity with the basic tdns
applications, configuration and DNSSEC. For those, see
the [tdns Guide](../../tdns/guide/README.md).

## Read in This Order

1. **[Applications](applications.md)** — overview of the
   four mp binaries and what each does.
2. **[Architecture](multi-provider-architecture.md)** —
   the problem multi-provider DNSSEC solves, the three
   roles, and how data flows inside and between
   providers. Read this before going further.
3. **[Synchronization Model](synchronization-model.md)**
   — the combiner as center of persistence, the agent
   SDE as runtime cache, origin tracking, the dynamic
   MP options derived from HSYNCPARAM, and the
   `agent / combiner zone edits` CLI commands.
4. **[Quickstart](quickstart.md)** — bring a working
   per-provider stack up via `tdns-mpcli configure`.
5. **[Customer Zone Setup](customer-zone-setup.md)** —
   onboard an actual zone: HSYNC3 + HSYNCPARAM,
   NOTIFY/AXFR to combiners, forcing a refresh.
6. **[Operation and Debugging](operation-and-debugging.md)**
   — the day-2 CLI: peer state, gossip matrix, zone
   inspection, transactions and queues, end-to-end
   triage.
7. **[Making Data Changes](data-changes.md)** —
   add-rr/remove-rr, DNSSEC key rollover, inspection
   at three layers (SDE / combiner / DNS), recovery
   and resync.
8. **[The Auditor](auditor.md)** — adding a passive
   read-only observer to the multi-provider network.

## Reference

- [Change Tracking Semantics](mp-change-tracking-semantics.md)
  — design decisions and corner cases for how
  multi-provider changes are tracked, confirmed and
  routed.
- [Multi-Provider Advanced Topics](multi-provider-advanced.md)
  — parent delegation sync (DSYNC), provider zones,
  `_signal` KEY publication, gossip protocol details,
  leader elections.
- [Initial Provider Configuration](initial-provider-configuration.md)
  — long-form manual configuration of agent, combiner
  and signer for cases where `tdns-mpcli configure`
  is not appropriate.

## Per-Binary Reference

- [tdns-mpagent](app-mpagent.md)
- [tdns-mpcombiner](app-mpcombiner.md)
- [tdns-mpsigner](app-mpsigner.md)
- [tdns-mpcli](app-mpcli.md)

## Related Documentation

- [tdns Guide](../../tdns/guide/README.md) — the
  underlying DNS engine, authoritative nameserver,
  recursive resolver, delegation sync, transport
  signaling and experimental record type definitions.
- [tdns Special Features](../../tdns/guide/special-features.md)
  — definitions of the record types (HSYNC3,
  HSYNCPARAM, JWK, CHUNK) that tdns-mp builds on.
