# tdns-mpcli

**tdns-mpcli** is the management CLI for tdns-mp. It is a
superset of [tdns-cli](../../tdns/guide/app-tdns-cli.md):
all the standard tdns-cli sub-commands (zone, ddns, update,
keystore, truststore, notify, dsync) work the same way and
target the same REST API endpoints. tdns-mpcli adds
multi-provider-specific sub-commands.

## Configuration

tdns-mpcli is configured to talk to all three mp services in
a single YAML file, typically `/etc/tdns/tdns-mpcli.yaml`:

```yaml
apiservers:
   - name:    tdns-agent
     baseurl: https://127.0.0.1:8074/api/v1
     ...
   - name:    tdns-combiner
     baseurl: https://127.0.0.1:8075/api/v1
     ...
   - name:    tdns-signer
     baseurl: https://127.0.0.1:8073/api/v1
     ...
```

See [Multi-Provider QuickStart](multi-provider-quickstart.md)
section 4.5 for a complete example.

## Multi-Provider Sub-Commands

The following command groups exist in addition to the
tdns-cli base set:

- **`tdns-mpcli agent zone`** -- list zones the agent is
  serving, query zone status, list HSYNC3/HSYNCPARAM data,
  trigger resync (pull/push) against combiner and peer
  agents, add/remove individual records (`addrr`/`delrr`).

- **`tdns-mpcli agent peer`** -- list discovered peer
  agents, inspect their state, force discovery
  (`peer reset`).

- **`tdns-mpcli agent gossip`** -- list provider groups,
  show the gossip state matrix, show election state for a
  group.

- **`tdns-mpcli agent debug`** -- send debug RFI requests
  (KEYSTATE, EDITS, SYNC) for diagnosing data flow.

- **`tdns-mpcli imr`** -- query, flush, reset, and inspect
  the agent's embedded IMR cache (used to discover peers
  via DNS).

- **`tdns-mpcli combiner`** -- inspect combiner state,
  list contributions, audit rejected edits, query
  per-record state.

- **`tdns-mpcli keys generate --jose`** -- generate JOSE
  keypairs for the agent, combiner, and signer. JOSE keys
  secure the CHUNK transport between the three roles.

The exact set of sub-commands evolves; use `-h` at any
level to see what is currently available.

## See Also

- [tdns-cli](../../tdns/guide/app-tdns-cli.md) for the
  shared sub-commands.
- [Multi-Provider QuickStart](multi-provider-quickstart.md)
  for examples of common operations.
