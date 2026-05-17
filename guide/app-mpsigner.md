# tdns-mpsigner

**tdns-mpsigner** is the DNSSEC signer used in a
multi-provider deployment. It is a specialization of the
standard tdns authoritative server (`tdns-auth`) with
`multi-provider.role: signer` and the
multi-provider-specific KEYSTATE coordination with the
local agent.

This page is the per-binary reference. The substantive
material is in the topical guides:

- The signer's role in the data flow →
  [Architecture §2.2](multi-provider-architecture.md#22-signer).
- Source-of-truth for DNSKEYs, KEYSTATE handoff to the
  agent, multi-signer DNSKEY coordination →
  [Synchronization Model](synchronization-model.md).
- Key rollover (manual and automated), inspection of
  rollover state →
  [Making Data Changes §2](data-changes.md#2-dnssec-key-rollover).
- Configuration →
  [Quickstart](quickstart.md) (preferred) and
  [Initial Provider Configuration](initial-provider-configuration.md)
  (manual).

## Design Constraints

1. **The signer is the source of truth for local
   DNSKEYs.** The agent does not derive DNSKEYs from
   zone transfer data; it learns them from the signer
   via KEYSTATE EDNS(0) signaling. This is what makes
   multi-signer rollovers (RFC 8901) correct: the
   signer decides when a new key is published, when an
   old key is retired, and the agent network propagates
   that decision to peer providers in lock-step.

2. **The signer is a regular tdns-auth instance.** All
   standard tdns-auth features apply — online signing,
   dynamic zones, catalog zones, delegation-sync-parent
   for parent-zone roles. The multi-provider role just
   adds the KEYSTATE coordination and the
   combiner-as-primary zone-transfer plumbing.

3. **Configuration shares the tdns-auth YAML schema.**
   With an additional `multi-provider:` section
   declaring role `signer` and the local agent's
   identity + JOSE public key. See
   [Initial Provider Configuration](initial-provider-configuration.md)
   for the full layout.

## See Also

- [Architecture](multi-provider-architecture.md)
- [Synchronization Model](synchronization-model.md)
- [Making Data Changes](data-changes.md) — `signer
  keystore rollover` and `signer keystore
  auto-rollover` commands with examples.
- [Operation and Debugging](operation-and-debugging.md)
- [tdns-auth documentation](../../tdns/guide/) — the
  underlying authoritative server.
