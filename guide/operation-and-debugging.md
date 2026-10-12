# Operation and Debugging

This document is the day-2 reference: the CLI commands you
live in once a multi-provider deployment is running. It
assumes the example.com setup from
[Customer Zone Setup](customer-zone-setup.md) — alpha
signs and serves, bravo and charlie serve only.

The commands fall into five groups:

1. **Health & liveness** — is each daemon up and reachable?
2. **Peer state** — what other parties has this agent
   discovered, and what is their transport state?
3. **Gossip & groups** — what does the per-zone provider
   group think of itself?
4. **Zone state** — what is loaded, with which MP options?
5. **Transactions & queues** — what is in flight, what
   has failed?

For commands that *change* state, see
[Making Data Changes](data-changes.md). For inspecting
the SDE and combiner contributions specifically, see
[Synchronization Model](synchronization-model.md).

## 1. Health and Liveness

The simplest checks. Each MP role exposes a `ping`
command on its management API:

```sh
tdns-mpcli agent ping
tdns-mpcli combiner ping
tdns-mpcli signer ping
```

A healthy response is a one-line "pong" with the daemon's
identity and uptime. Failure here means the daemon is
down, the API is wedged, or the CLI is pointed at the
wrong base URL — check `/etc/tdns/tdns-mpcli.yaml`.

`ping` only validates the local management API.
**`peer ping`** (next section) is what proves peers can
actually talk to each other.

## 2. Peer State

The agent maintains two parallel transports to every peer:

- **DNS transport** — JOSE-protected CHUNK records sent
  over TCP NOTIFY. The primary path for SYNC and BEAT.
- **API transport** — HTTPS to the peer's management
  port. Used as a fallback and for some RFI exchanges.

Each transport has its own state, and either can be
broken independently.

### 2.1 List peers

```
$ tdns-mpcli agent peer list

IDENTITY                  TRANSPORT  STATE         LAST SEEN
agent.bravo.example.      dns        OPERATIONAL   3s ago
agent.bravo.example.      api        OPERATIONAL   12s ago
agent.charlie.example.    dns        OPERATIONAL   2s ago
agent.charlie.example.    api        OPERATIONAL   12s ago
combiner.alpha.example.   api        OPERATIONAL   5s ago
signer.alpha.example.     api        OPERATIONAL   8s ago
```

The state progression is `UNKNOWN → NEEDED → KNOWN →
OPERATIONAL`. Anything stuck below OPERATIONAL is a
discovery or authentication problem — usually a missing
or mismatched JWK record, or a peer that hasn't reached
back yet.

`-v` adds full per-peer detail: published address, JWK
KeyID, last successful round-trip, error counters.

### 2.2 Ping a specific peer

```sh
tdns-mpcli agent peer ping    --id agent.bravo.example.
tdns-mpcli agent peer apiping --id agent.bravo.example.
```

`ping` exercises the DNS/CHUNK path; `apiping` exercises
the HTTPS/API path. If `ping` works but `apiping` fails
(or vice versa) you have a *transport-specific* problem
— often a firewall rule that allows TCP/53 but not the
management port, or a TLS cert that is invalid for the
API path.

### 2.3 Reset a stuck peer

```sh
tdns-mpcli agent peer reset --id agent.bravo.example.
```

This drops everything the agent knows about
`agent.bravo.example.`, flushes the IMR cache entries
for its discovery names, and restarts the
`UNKNOWN → NEEDED → ...` cycle. Use it when:

- A peer is stuck below OPERATIONAL after you have
  fixed the underlying problem (DNS record updated, JWK
  rotated, etc.).
- The agent is caching a stale resolution for the
  peer's identity.

`peer reset` is an agent/auditor command only. Signer
and combiner use static peer configuration and respond
with "not applicable".

### 2.4 Which peers share which zones

```sh
tdns-mpcli agent peer zones
tdns-mpcli agent peer zone --zone example.com.
```

`peer zones` shows the list of shared zones per peer.
`peer zone --zone example.com.` inverts it: which peers
share this specific zone. Useful when you suspect a
zone is configured at some providers but not at others.

## 3. Gossip and Groups

A **provider group** is the set of identities that share
the same set of HSYNC3 records in some zone. Every zone
belongs to exactly one group; groups are recomputed
when HSYNC3 records change.

Gossip runs over the group: each member periodically
exchanges its view of every other member's state. The
group as a whole is OPERATIONAL only when every cell of
the N×N matrix shows OPERATIONAL.

### 3.1 List groups

```
$ tdns-mpcli agent gossip state --zone customer.mptest.

GROUP        MEMBERS                                                            ZONES
-----        -------                                                            -----
g_3a8f1c     agent.alpha.example., agent.bravo.example., agent.charlie.example. example.com. (+2 more)
```

`GROUP` is the short hash. Members are the agents that
share this exact set of HSYNC3 identities across all
zones in the group. ZONES shows up to a few sample zones
plus a count of any others.

### 3.2 The gossip matrix

```
$ tdns-mpcli agent gossip state --zone customer.mptest.

Group: g_3a8f1c (hash: 3a8f1c2b0e9d4f...)
Leader: agent.alpha.example. (term 4, expires in 47m12s)

REPORTER / PEER     agent.alpha    agent.bravo    agent.charlie   AGE
agent.alpha         —              OPERATIONAL    OPERATIONAL     2s    (30s beats)
agent.bravo         OPERATIONAL    —              OPERATIONAL     5s    (30s beats)
agent.charlie       OPERATIONAL    OPERATIONAL    —               3s    (30s beats)
```

Read it row-by-row: row `agent.bravo` shows bravo's view
of every other member. The diagonal is `—` (no one
reports on themselves). AGE is how stale that row is —
how long since the reporter last beat into us.

A healthy group shows OPERATIONAL in every off-diagonal
cell with low AGE values. Common failure patterns:

- **One peer's row is missing or very stale**: that peer
  is not beating to us. Local-side problem (firewall,
  process down) or the peer has lost track of us. Try
  `peer ping --id <them>` from us, and `peer ping --id
  <us>` from them.
- **One column is full of NEEDED or UNKNOWN**: that peer
  is unreachable from the rest of the group. The
  remaining members agree on it. Usually a downed
  daemon or a routing problem at that peer's site.
- **Asymmetric — alpha sees bravo OPERATIONAL but bravo
  sees alpha NEEDED**: one direction of the transport
  works, the other does not. Often firewall.

`Leader: ... expires in ...` shows the current leader
election state. `no election held` means the group has
not yet reached OPERATIONAL across the board; `expired`
or `invalidated` means an election is needed and the
lexicographically smallest member should start one.

## 4. Zone State

### 4.1 What zones are loaded

```
$ tdns-mpcli agent zone list

ZONE                       TYPE       STORE   FROZEN  DIRTY  OPTIONS
agent.alpha.example.       primary    MapZone false   false  [allow-updates automatic-zone online-signing]
example.com.               secondary  MapZone false   false  [multi-provider delegation-sync-child]
mp-internal.example.       secondary  MapZone false   false  [multi-provider]
```

The `OPTIONS` column shows the effective zone flags
including the dynamic MP options derived from HSYNCPARAM.
See [Synchronization Model §5](synchronization-model.md#5-the-dynamic-mp-options)
for what each flag means.

### 4.2 Multi-provider zone detail

```
$ tdns-mpcli combiner zone mplist

ZONE          ROLE        SIGNERS         SERVERS                NSMGMT  EDITS
example.com.  provider    alpha           alpha,bravo,charlie    agent   ALLOW
```

`mplist` is the most useful one-shot health check for a
zone: it shows the role this combiner has for the zone,
the HSYNCPARAM signers/servers/nsmgmt, and whether the
combiner is currently applying contributions (`ALLOW`)
or only persisting them (`DISALLOW`). The same command
exists under `agent zone mplist` and `signer zone mplist`.

For per-zone HSYNC3/HSYNCPARAM RDATA, use `dog`:

```sh
dog @127.0.0.1:8055 example.com. HSYNC3
dog @127.0.0.1:8055 example.com. HSYNCPARAM
```

### 4.3 SDE and contribution inspection

The detail commands for the agent's SDE and the
combiner's contributions are documented in
[Synchronization Model](synchronization-model.md):

- `agent zone edits list` — SDE summary across zones.
- `agent zone edits list --zone <zone>` — per-RR
  tracking detail + outbound queue for one zone.
- `combiner zone edits list --zone <zone>` — current
  contributions making up the served zone.
- `combiner zone edits list --zone <zone> --pending /
  --approved / --rejected` — edit lifecycle tables.

These are the bread-and-butter commands when something
is wrong with what is being published.

### 4.4 The SOA serial a signer serves

Which serial a signer serves for a multi-provider zone
depends on who signs the zone:

- **A zone this provider signs** (its label is in
  `signers=`) has a serial of the signer's own. It starts
  at the combiner's serial and moves on by itself at
  every publish, so it is normally ahead of the
  combiner's.
- **A zone this provider only serves**, signed by another
  provider, is relayed as it was received: the upstream
  signer's SOA, with its serial and its RRSIG. The two
  signers answer with the same SOA:

  ```sh
  dog @<upstream-signer> +dnssec example.com. SOA
  dog @<this-signer>     +dnssec example.com. SOA
  ```

  Nothing at this provider changes such a zone. A
  `signer zone bump` of it is refused, and a server-wide
  `outbound-soa-serial` setting does not apply to it.
  A zone that no provider signs is relayed the same way,
  from the provider's own combiner.

**When the role changes.** A provider that starts to
sign a zone it relayed goes on from one past the serial
it was serving, also when its signer is restarted in
between; the servers downstream of the signer keep
transferring. A provider that stops signing a zone and
relays it instead drops to the upstream signer's serial,
which is normally lower than its own count. The servers
downstream of it then hold the higher serial and need a
forced retransfer, as after an upgrade (below).

**Upgrading a signer that relays zones.** Earlier
versions counted a serial of their own for a relayed
zone as well, so a signer's copy could be a few serials
ahead of its upstream's, or behind it, and its SOA then
failed validation. A signer with this fix takes the
upstream's serial at its first load. Where the old
version was ahead, that serial is lower than the one it
served, and the signer's log does not say so. The
servers that transfer the zone from this signer (the
provider's public nameservers, and its agent if it is
not restarted after the signer) still hold the higher
serial. They do not transfer a lower one, and go on
serving their old copy until the upstream signer's
serial has passed the one they hold. So after the
upgrade, force a retransfer of each relayed zone on each
of them: with
`tdns-mpcli agent zone reload -z <zone> --force` for the
agent, and with the server's own command for a
nameserver that is not tdns. Then compare the SOA at the
upstream signer, at this signer and at each of those
servers.

A signer logs `secondary SOA serial steps BACKWARDS to
mirror upstream` when the serial of a zone drops while it
runs. The same remedy applies. The command the message
names is tdns-auth's; for a tdns-mp daemon it is the
`zone reload ... --force` above.

## 5. Transactions and Queues

The outbound message queue is where in-flight peer
messages live until they are confirmed.

### 5.1 List distributions

```
$ tdns-mpcli agent distrib list

DISTID            ZONE          RECIPIENT                TYPE  STATE      AGE
d8f2a91c00b14e3a  example.com.  agent.bravo.example.     SYNC  pending    47s
d8f2a91c00b14e3a  example.com.  agent.charlie.example.   SYNC  confirmed  46s
e1cd472f1a5b9c30  example.com.  combiner.alpha.example.  UPDATE confirmed 49s
```

Each distribution has one row per recipient. State
progression: `pending → sent → confirmed` (success) or
`pending → sent → failed` after the reliable message
queue gives up retrying.

`agent zone edits list --zone example.com.` shows the
same outbound queue filtered to one zone alongside the
SDE state — usually more useful when debugging a
specific zone.

### 5.2 Purge completed distributions

```sh
tdns-mpcli agent distrib purge          # only confirmed/failed
tdns-mpcli agent distrib purge --force  # everything, even pending
```

`--force` is destructive — pending messages disappear,
the recipient never hears about the change. Use only
when you know the distribution is irrelevant (e.g. the
zone has been removed).

### 5.3 Combiner transaction errors

The combiner keeps a per-zone log of NOTIFY processing
errors:

```sh
tdns-mpcli combiner transaction errors             # last 30 minutes
tdns-mpcli combiner transaction errors --last 24h  # custom window
tdns-mpcli combiner transaction details --id <distrib-id>
```

`errors` summarises recent failures; `details` drills
into a specific distribution by ID. These are most
useful when an agent reports REJECTED back to a sender
— `details` shows exactly which records failed and why.

## 6. Putting It Together: a Triage Checklist

When something is wrong, walk down the stack:

1. **`agent ping`** / **`combiner ping`** / **`signer ping`** —
   are the local daemons up?
2. **`agent peer list`** — are we talking to everyone we
   should?
3. For each peer not OPERATIONAL: **`agent peer ping
   --id <them>`** and **`agent peer apiping --id <them>`**
   to isolate transport vs API.
4. **`agent gossip state --zone <zone>`** — does the
   matrix agree the group is healthy?
5. **`combiner zone mplist`** — is the zone loaded with
   the expected MP options on every combiner?
6. **`agent zone edits list --zone <zone>`** — are
   contributions PENDING (recipient down), REJECTED
   (combiner policy), or all ACCEPTED?
7. **`combiner transaction errors`** + **`combiner zone
   edits list --zone <zone> --rejected`** — for the
   detailed reason behind any REJECTED entries.

Most issues are visible at step 2 or 4. Steps 5–7 are
for "the network is healthy but the zone is wrong."

## See Also

- [Architecture](multi-provider-architecture.md)
- [Synchronization Model](synchronization-model.md) —
  edits CLI in depth.
- [Making Data Changes](data-changes.md) — the
  commands that *cause* the activity inspected here.
- [Change Tracking Semantics](mp-change-tracking-semantics.md)
  — why REJECTED is sometimes ACCEPTED and other
  corner cases.
