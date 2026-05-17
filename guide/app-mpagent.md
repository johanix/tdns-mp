# tdns-mpagent

**tdns-mpagent** is the per-provider coordination service
in a multi-provider deployment. It does not serve the
customer zone to end users; it coordinates with the local
combiner, the local signer and remote peer agents so the
customer zone stays consistent across all providers.

This page is the per-binary reference. The substantive
material is in the topical guides:

- The agent's role in the bigger picture →
  [Architecture §2.3](multi-provider-architecture.md#23-agent).
- How agents discover each other and exchange data →
  [Architecture §4](multi-provider-architecture.md#4-data-flow-between-providers)
  and [Customer Zone Setup](customer-zone-setup.md).
- The Synched Data Engine (SDE), per-RR tracking,
  contributions →
  [Synchronization Model](synchronization-model.md).
- Adding the agent to a deployment →
  [Quickstart](quickstart.md).
- All `agent` CLI commands →
  [Operation and Debugging](operation-and-debugging.md)
  and [Making Data Changes](data-changes.md).

## Design Constraints

1. **Configuration errors are fatal.** A partially
   misconfigured agent has no value — it would coordinate
   the wrong thing or fail intermittently. The agent
   exits at startup rather than running degraded.

2. **The agent does not serve the customer zone.** Its
   DNS listener (default `:8054`) carries CHUNK / SYNC /
   BEAT traffic to peer agents and serves the agent's
   own auto-zone (the discovery records under the
   agent's identity FQDN). It is not an authoritative
   server for any customer zone.

3. **The agent does not modify zones directly.** All
   modifications to the served customer zone go through
   the combiner. The agent submits contributions; the
   combiner persists and applies them.

4. **The agent is the source of truth for nothing
   persistent.** The SDE is a runtime cache,
   reconstructed on startup from RFI EDITS (combiner),
   RFI KEYSTATE (signer) and RFI SYNC (peers). The
   authoritative state lives in the combiner database
   and the signer's keystore.

## See Also

- [Architecture](multi-provider-architecture.md) — what
  the agent is for and how it fits in.
- [Synchronization Model](synchronization-model.md) —
  the SDE and per-RR tracking states.
- [Operation and Debugging](operation-and-debugging.md)
  — CLI for inspecting agent state and peer transports.
- [Making Data Changes](data-changes.md) — CLI for
  causing changes that flow through the agent.
- [tdns-agent](../../tdns/guide/) — the upstream
  single-zone tdns-agent that mpagent is built on
  (for use cases like parent delegation sync that are
  shared between standalone and multi-provider use).
