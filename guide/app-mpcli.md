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

The file is found via `--config`, else the environment
variable `TDNS_MPCLI_CONFIG`, else
`/etc/tdns/tdns-mpcli.yaml`. A session working against a
non-default config (a test rig, a second fleet) sets the
variable once instead of repeating `--config`.

### Several instances of one daemon

A host, or a test rig, can run more than one agent,
combiner, signer or auditor. Each extra instance is one
more `apiservers` entry carrying a `role:`; the entry's
`name` becomes a top-level command word offering the
same command set as the built-in word for that role:

```yaml
apiservers:
   - name:    tdns-agent            # the built-in "agent" word
     baseurl: https://127.0.0.1:7054/api/v1
     ...
   - name:        p2-agent          # "tdns-mpcli p2-agent ..."
     role:        agent
     baseurl:     https://127.0.0.1:7254/api/v1
     apikey:      ...
     authmethod:  X-API-Key
     config_file: /etc/tdns/p2/tdns-mpagent.yaml   # for "config check", "keys"
     command:     /usr/local/libexec/tdns-mpagent  # for "daemon start"
   - name:        p2-signer
     role:        signer
     ...
```

```
tdns-mpcli agent    zone mplist          # the built-in agent
tdns-mpcli p2-agent zone mplist          # the p2 instance
tdns-mpcli p2-signer keystore dnssec list -z example.com.
```

Rules: `role:` is one of `agent`, `combiner`, `signer`,
`auditor`; the name must not be one of those four, nor
`version`, `configure`, `help` or `completion`, nor an
earlier entry's name — a collision is reported on stderr
and that entry is ignored, nothing else changes. Entries
without `role:` behave exactly as before, so an existing
config needs no change.

Every command under an instance word targets that
instance: the target is read off the command tree, never
from a fixed name, so `p2-agent zone edits list` cannot
quietly drive the built-in agent. The instance tree is
built by the same code as the built-in tree, so the two
cannot offer different commands. Four commands exist on
the built-in `signer` word only, because they are not
API clients of an mp daemon: `signer auth`, `signer
report`, `signer keys`, `signer jwt`.

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
- **`{role} gossip state --zone <zone>`** — gossip
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
- **`signer keystore dnssec generate / rollover / list`** —
  DNSSEC key lifecycle. (`keystore dnssec policy`,
  `ds-push`, `query-parent` and `auto-rollover` are
  tdns-auth's KSK-rollover automation; the mp signer does
  not serve those endpoints, so tdns-mpcli does not offer
  them.)
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
