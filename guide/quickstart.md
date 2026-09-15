# Quickstart

This guide brings up a complete tdns-mp deployment for a
single provider — combiner, signer and agent on one host,
optionally with an auditor — using `tdns-mpcli configure`
to generate the configuration files. The generated stack
carries an example zone, `mptest.example.`, from the
combiner through the signer to the agent, so you can see
data move before any real customer zone exists. The
generated values (short signature lifetimes, a 5-minute
key propagation delay) suit a testbed.

If you need to write the configuration files by hand (for
example to fit existing configuration management, or to
use a non-standard port layout), see
[Initial Provider Configuration](initial-provider-configuration.md)
instead.

## 1. Prerequisites

You need:

1. A host with the tdns-mp binaries installed:
   - `/usr/local/libexec/tdns-mpagent`
   - `/usr/local/libexec/tdns-mpcombiner`
   - `/usr/local/libexec/tdns-mpsigner`
   - `/usr/local/libexec/tdns-mpauditor` (optional)
   - `/usr/local/bin/tdns-mpcli`
   - `openssl` on the PATH (for the TLS certificates)
2. A public IP address from which to serve DNS and accept
   peer connections.
3. A DNS identity per role under a zone you control —
   e.g. `agent.alpha.example.`,
   `signer.alpha.example.`,
   `combiner.alpha.example.`. The agent identity is
   published in customer zones' HSYNC3 records so peers
   can find you.

For other providers (or an auditor) to discover the
agent, the agent's identity zone (`agent.alpha.example.`
in the example) must be delegated in the public DNS to
nameservers that hold the agent's auto-generated URI,
SVCB and JWK records. The agent publishes those records
itself; secondaries elsewhere pick up the zone from the
agent's DNS listener (`<public-ip>:8054`). A single stack
runs without the delegation.

Optionally:

4. An auditor identity (e.g. `auditor.alpha.example.`)
   if you want to run a tdns-mpauditor in parallel. The
   `configure` command will ask.

## 2. Generate Configuration

```sh
sudo tdns-mpcli configure
```

The interview asks for:

- **Keys directory** (default `/etc/tdns/keys`).
- **Certs directory** (default `/etc/tdns/certs`).
- **Public IP** — advertised to peers, in the TLS certs
  and in the example zone.
- **Internal IP** — the bind address of the management
  APIs and the address the roles dial each other on.
  Use `127.0.0.1` for single-host; on AWS / multi-host
  use the local interface address.
- **Agent identity**, **signer identity**, **combiner
  identity** — the FQDNs from the prerequisites.
- **Auditor?** — yes/no; if yes, auditor identity.
- **Agent identity zone NS records** and **NOTIFY
  targets** for the secondaries that will hold it. Both
  optional; leave blank if not needed.

It then shows the port layout:

| Role            | DNS      | Mgmt API | Sync API |
|-----------------|----------|----------|----------|
| tdns-mpsigner   | 8053, 53 | 7053     | —        |
| tdns-mpcombiner | 8055     | 7055     | —        |
| tdns-mpagent    | 8054     | 7054     | 9054     |
| tdns-mpauditor  | 8056     | 7056     | 9056     |

and, once you confirm:

1. Generates any missing JOSE keypairs (one per role,
   used to secure the CHUNK transport).
2. Generates any missing TLS certs and keys (one per
   role, used by the management API).
3. Generates API keys.
4. Writes YAML configs under `/etc/tdns/`:
   `tdns-mpagent.yaml`, `tdns-mpcombiner.yaml`,
   `tdns-mpsigner.yaml`, `tdns-mpcli.yaml` and, with an
   auditor, `tdns-mpauditor.yaml`.
5. Writes the example zone file
   `/etc/tdns/zones/mptest.example.zone` if it does not
   exist. Its HSYNC3 records name your agent (and
   auditor); its HSYNCPARAM makes this provider the only
   server and signer. The provider label is derived from
   the agent identity: `alpha` for
   `agent.alpha.example.`.
6. Pings any already-running daemons before overwriting
   their config, so you do not get blindsided by a
   restart-on-edit.

Re-runs are safe: existing values become the prompt
defaults, existing key material and the example zone
file are left alone, and you are asked before any live
server's config is replaced.

## 3. Start the Daemons

```sh
sudo /usr/local/libexec/tdns-mpcombiner --config /etc/tdns/tdns-mpcombiner.yaml &
sudo /usr/local/libexec/tdns-mpsigner   --config /etc/tdns/tdns-mpsigner.yaml &
sudo /usr/local/libexec/tdns-mpagent    --config /etc/tdns/tdns-mpagent.yaml &
sudo /usr/local/libexec/tdns-mpauditor  --config /etc/tdns/tdns-mpauditor.yaml &   # if configured
```

The signer binds port 53, which needs root. In
production these would be unit files or rc.d scripts.
Order does not matter: each service retries until its
peers are reachable.

## 4. Verify

The management APIs respond:

```
$ tdns-mpcli combiner ping
TLS pong from tdns-mpcombiner @ <hostname>: pings: 1, pongs: 1, uptime: 0m16s, ...
```

and the same for `signer`, `agent` and `auditor`.

Every role has loaded the example zone and read its
HSYNCPARAM:

```
$ tdns-mpcli agent zone mplist
Zone             Servers  Signers  Auditors  NSmgmt  ParentSync  Suffix  Options
mptest.example.  alpha    alpha    auditor   owner   owner               [multi-provider on-conflict-db-wins]
```

`tdns-mpcli signer zone mplist` additionally shows
`inline-signing`. The agent serves the zone as the signer
signed it (the combiner holds serial 1, the signer
publishes serial 2):

```
$ dig @127.0.0.1 -p 8054 +dnssec +norec mptest.example. SOA
mptest.example.  300  IN  SOA    ns1.mptest.example. hostmaster.mptest.example. 2 3600 600 604800 300
mptest.example.  300  IN  RRSIG  SOA 15 2 300 ...
```

The agent talks to its combiner and signer over the DNS
transport:

```
$ tdns-mpcli agent peer list
Found 3 peer(s) with working keys
Identity                 Type      Transport  Address                Crypto  State
combiner.alpha.example.  combiner  DNS        dns://127.0.0.1:8055/  JOSE    OPERATIONAL
signer.alpha.example.    signer    DNS        dns://127.0.0.1:8053/  JOSE    OPERATIONAL
auditor.alpha.example.   agent     DNS        -                      JOSE    NEEDED
```

The auditor stays NEEDED until the agent and auditor can
look up each other's identity zones through the public
DNS (see the prerequisites).

At this point you have a working provider stack carrying
one zone. To change the example zone, edit the zone file,
bump its SOA serial and run
`tdns-mpcli combiner zone reload -z mptest.example.`.

## 5. What Next

- **Onboard a zone.** Once the other providers in your
  group have their stacks running, the zone owner adds
  the customer zone with HSYNC3 + HSYNCPARAM records and
  starts sending NOTIFY to the combiners. See
  [Customer Zone Setup](customer-zone-setup.md), and
  [Bringup §2](bringup.md#phase-2--add-a-customer-zone)
  for the zone entries on this provider's side — the
  generated configs already contain the template they
  use.
- **Watch it run.** Once a zone is loaded, the agents
  discover each other, run gossip and elect a leader.
  See [Operation and Debugging](operation-and-debugging.md).
- **Make changes.** Adding/removing records, key
  rollovers and inspecting state across the network is
  covered in [Making Data Changes](data-changes.md).
- **Add an auditor.** See [The Auditor](auditor.md).

## See Also

- [Architecture](multi-provider-architecture.md) — read
  this if you have not yet, before going much further.
- [Synchronization Model](synchronization-model.md) —
  how data actually moves through the system.
- [Initial Provider Configuration](initial-provider-configuration.md)
  — when you need to write configs by hand instead of
  using `configure`.
