# tdns-mpcli

**tdns-mpcli** is the management CLI for tdns-mp. It is a
superset of the upstream
[tdns-cli](../../tdns/guide/): all the standard
sub-commands (zone, ddns, update, keystore, truststore,
notify, dsync) work the same way. tdns-mpcli adds the
multi-provider sub-commands documented across this
guide.

This page is the per-binary reference. For *what to do
with* the CLI, see the topical guides.

## Configuration

mpcli is configured with a single YAML file that lists
every MP daemon it can talk to:

```yaml
apiservers:
   - name:    tdns-agent
     baseurl: https://127.0.0.1:7054/api/v1
     ...
   - name:    tdns-combiner
     baseurl: https://127.0.0.1:7055/api/v1
     ...
   - name:    tdns-signer
     baseurl: https://127.0.0.1:7053/api/v1
     ...
   - name:    tdns-auditor    # if present
     baseurl: https://127.0.0.1:7056/api/v1
     ...
```

`tdns-mpcli configure` generates this automatically; see
[Quickstart](quickstart.md).

## Command Tree

Top-level structure: one sub-command per role, plus a
small set of role-agnostic commands.

```
tdns-mpcli
├── configure               -- interactive bootstrap (see Quickstart)
├── ping                    -- ping any one role (--role agent|signer|...)
├── version
├── agent     {...}         -- agent-targeted commands
├── signer    {...}         -- signer-targeted commands
├── combiner  {...}         -- combiner-targeted commands
└── auditor   {...}         -- auditor-targeted commands (if running)
```

The four role sub-trees share several common shapes:

- **`{role} ping`** — health/liveness against this
  daemon's API.
- **`{role} peer ping / apiping / reset`** — exercise
  per-peer transports. `reset` is only meaningful on
  agent/auditor.
- **`{role} gossip group list / state`** — gossip
  matrix; only meaningful on agent/auditor.
- **`{role} zone list / mplist`** — what zones the
  daemon is handling.

Role-specific commands include:

- **`agent local zonedata add-rr / remove-rr`** —
  contribute DNS records into a zone.
- **`agent zone edits list`** — inspect the SDE.
- **`agent peer resync`** — push/pull resync against
  peers and combiner.
- **`combiner zone edits list / approve / reject /
  clear / reapply / purge`** — combiner contribution
  inspection and lifecycle.
- **`combiner transaction errors / details`** —
  NOTIFY/SYNC failure inspection.
- **`signer keystore rollover / auto-rollover`** —
  DNSSEC key rollover.
- **`signer zone bump`** / **`combiner zone bump`** /
  **`auth zone bump`** — force a SOA bump and
  re-NOTIFY at each layer.
- **`auditor zones / eventlog / observations`** —
  auditor-specific introspection.

For per-command syntax, flags and example output, see
the topical guides:

- [Operation and Debugging](operation-and-debugging.md)
  — peer, gossip, zone, distrib, transaction commands.
- [Synchronization Model](synchronization-model.md) —
  agent/combiner edits commands.
- [Making Data Changes](data-changes.md) — add-rr,
  remove-rr, keystore rollover, bump, resync.
- [The Auditor](auditor.md) — all auditor sub-commands.

Or use `-h` at any level to see what is currently
registered.

## See Also

- [Quickstart](quickstart.md) — generate the mpcli
  config automatically via `configure`.
- [tdns-cli](../../tdns/guide/) — the upstream CLI;
  mpcli inherits its sub-command set.
