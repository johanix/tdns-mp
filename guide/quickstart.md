# Quickstart

This guide brings up a complete tdns-mp deployment for a
single provider — combiner, signer and agent on one host
— using `tdns-mpcli configure` to generate the
configuration files.

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
   - `/usr/local/bin/tdns-mpcli`
   - `/usr/local/bin/dog`
2. A public IP address from which to serve DNS and accept
   peer connections.
3. A DNS identity per role under a zone you control —
   e.g. `agent.alpha.example.`,
   `signer.alpha.example.`,
   `combiner.alpha.example.`. These are FQDNs published
   in the customer zone's HSYNC3 record so peers can find
   you.

That zone (`alpha.example.` in the example) needs to be
delegated in the public DNS to nameservers that will hold
the agent's auto-generated URI, SVCB and JWK records.
The agent publishes those records itself; you need
secondaries elsewhere that pick up the zone from the
agent's DNS listener (typically `<public-ip>:8054`).

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
- **Public IP** — advertised in TLS certs, mpcli base
  URLs and the agent's published address.
- **Internal IP** — the bind address and inter-role dial
  target. Use `127.0.0.1` for single-host; on AWS / multi-host
  use the local interface address.
- **Agent identity**, **signer identity**, **combiner
  identity** — the FQDNs from the prerequisites.
- **Auditor?** — yes/no; if yes, auditor identity.
- **Agent auto-zone NS records** and **NOTIFY targets**
  for downstream secondaries that will hold the agent
  zone. Both optional; leave blank if not needed.

The command then:

1. Generates any missing JOSE keypairs (one per role,
   used to secure the CHUNK transport).
2. Generates any missing TLS certs and keys (one per
   role, used by the management API).
3. Generates API keys.
4. Renders YAML configs under `/etc/tdns/`:
   - `tdns-mpagent.yaml`
   - `tdns-mpcombiner.yaml`
   - `tdns-mpsigner.yaml`
   - `tdns-mpcli.yaml`
   - and matching `mp{agent,combiner,signer}-zones.yaml`
     include files.
5. Pings any already-running daemons before overwriting
   their config, so you do not get blindsided by a
   restart-on-edit.

Re-runs are safe: existing values become the prompt
defaults, existing key material is left alone, and you
are asked before any live server's config is replaced.

## 3. Start the Daemons

```sh
sudo tdns-mpcombiner --config /etc/tdns/tdns-mpcombiner.yaml &
sudo tdns-mpsigner   --config /etc/tdns/tdns-mpsigner.yaml &
sudo tdns-mpagent    --config /etc/tdns/tdns-mpagent.yaml &
```

In production these would be unit files or rc.d scripts.
Order does not matter: each service retries until its
peers are reachable.

## 4. Verify

Three quick checks:

```sh
# All three management APIs respond
tdns-mpcli agent ping
tdns-mpcli combiner ping
tdns-mpcli signer ping

# Agent has loaded its auto-zone
tdns-mpcli agent zone list

# Agent zone is being served on the configured DNS port
dog @127.0.0.1:8054 agent.alpha.example. SOA
```

At this point you have a working provider stack. Nothing
is coordinating with any other provider yet — there is no
customer zone loaded.

## 5. What Next

- **Onboard a zone.** Once the other providers in your
  group have their stacks running, the zone owner adds
  the customer zone with HSYNC3 + HSYNCPARAM records and
  starts sending NOTIFY to the combiners. See
  [Customer Zone Setup](customer-zone-setup.md).
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
