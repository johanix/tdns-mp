# tdns-mpcombiner

**tdns-mpcombiner** is the per-provider zone combiner. It
receives the customer zone via inbound zone transfer from
the zone owner, merges in contributions from the local
agent, and publishes the merged zone via outbound zone
transfer to the local signer.

This page is the per-binary reference. The substantive
material is in the topical guides:

- The combiner's role and what it persists →
  [Architecture §2.1](multi-provider-architecture.md#21-combiner).
- The `CombinerContributions` table, origin attribution,
  the dynamic MP options that gate application →
  [Synchronization Model §1, §3, §5](synchronization-model.md).
- Inspection commands (`combiner zone list`, `mplist`,
  `edits list / approve / reject / clear / reapply /
  purge`) →
  [Synchronization Model §6](synchronization-model.md#6-inspecting-combiner-state)
  and [Operation and Debugging](operation-and-debugging.md).
- Configuration →
  [Quickstart](quickstart.md) (preferred) and
  [Initial Provider Configuration](initial-provider-configuration.md)
  (manual).

## Design Constraints

1. **Configuration errors are fatal.** Same rationale as
   the agent — a partially configured combiner has no
   value.

2. **The combiner is the center of persistence.**
   Contributions from the local agent are stored in the
   `CombinerContributions` table, attributed to their
   origin, and survive restarts. The served (merged)
   zone is deterministically rebuilt from the inbound
   customer zone + contributions on every change.

3. **RRset replacement semantics.** For the coordinated
   apex RRsets:

   - **DNSKEY, CDS, CSYNC** — if there are contributions,
     they replace the inbound RRset entirely. With no
     contributions, the inbound RRset is dropped
     (CDS/CSYNC) or retained as-is (DNSKEY pass-through,
     but the signer typically owns this).
   - **NS** — if there are contributions, they replace
     the inbound RRset. Otherwise the inbound NS RRset
     is left intact.

4. **Per-zone policy comes from HSYNCPARAM.** Whether
   the combiner *applies* contributions or only
   *persists* them is determined by the dynamic MP
   options (`OptAllowEdits`, `OptMPDisallowEdits`)
   derived from the zone's HSYNCPARAM record and the
   combiner's own identity. See
   [Synchronization Model §5](synchronization-model.md#5-the-dynamic-mp-options).

## See Also

- [Architecture](multi-provider-architecture.md)
- [Synchronization Model](synchronization-model.md)
- [Operation and Debugging](operation-and-debugging.md)
- [Customer Zone Setup](customer-zone-setup.md) — how
  the inbound zone reaches the combiner.
