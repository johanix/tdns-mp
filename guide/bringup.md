# Bringup

This document is the ordered runbook for standing up a
multi-provider deployment from nothing. Each step has a
**verification gate** — a small set of commands with
expected output — that confirms the step worked before
you move to the next.

Use it the first time you bring up a deployment. After
that, the topical guides ([Operation and
Debugging](operation-and-debugging.md), [Making Data
Changes](data-changes.md)) are the right reference.

The four phases:

1. **One provider stands alone.** Generate configs,
   start the daemons, verify the three local roles can
   talk to each other.
2. **Add a customer zone.** Configure the zone on
   combiner, signer and agent. Verify each role has
   loaded it and parsed the HSYNCPARAM.
3. **Verify multi-provider communication.** Once the
   zone is loaded and other providers exist, verify
   every pair of parties can reach each other and the
   gossip matrix converges to OPERATIONAL.
4. **Exercise the change paths.** Make a small NS edit
   and a small DNSSEC rollover and verify the changes
   propagate.

Each phase assumes the previous one passed. If a
verification gate fails, fix it before going on —
problems compound.

---

## Phase 1 — One Provider Stands Alone

Goal: combiner, signer and agent are running on this
host, with TLS, JOSE keys and API keys generated, and
the three roles can talk to each other.

### 1.1 Generate the configs

```sh
sudo tdns-mpcli configure
```

Answer the interview prompts (keys dir, certs dir,
public IP, internal IP, identities for each role). On
re-runs the existing values become defaults.

The command writes `/etc/tdns/{tdns-mpcombiner,
tdns-mpsigner, tdns-mpagent, tdns-mpcli}.yaml` plus the
matching zone include files, generates JOSE keypairs
and TLS certs that are missing, and assigns API keys.

### 1.2 Start the daemons

```sh
sudo tdns-mpcombiner --config /etc/tdns/tdns-mpcombiner.yaml &
sudo tdns-mpsigner   --config /etc/tdns/tdns-mpsigner.yaml &
sudo tdns-mpagent    --config /etc/tdns/tdns-mpagent.yaml &
```

Order does not matter; each daemon retries until its
peers are reachable.

### 1.3 Verification gate

Each daemon responds to a management `ping`:

```
$ tdns-mpcli combiner ping
pong: combiner.alpha.example. (uptime 12s)

$ tdns-mpcli signer ping
pong: signer.alpha.example. (uptime 11s)

$ tdns-mpcli agent ping
pong: agent.alpha.example. (uptime 10s)
```

Then verify that the three roles have *discovered* each
other. The combiner and signer are configured with the
local agent's identity + JOSE pubkey, and vice versa —
so they should show each other in their peer lists
immediately:

```
$ tdns-mpcli combiner peer list
IDENTITY                  TRANSPORT  STATE         LAST SEEN
agent.alpha.example.      api        OPERATIONAL   3s ago

$ tdns-mpcli signer peer list
IDENTITY                  TRANSPORT  STATE         LAST SEEN
agent.alpha.example.      api        OPERATIONAL   4s ago

$ tdns-mpcli agent peer list
IDENTITY                  TRANSPORT  STATE         LAST SEEN
combiner.alpha.example.   api        OPERATIONAL   5s ago
signer.alpha.example.     api        OPERATIONAL   5s ago
```

Finally, exercise the encrypted transport in both
directions:

```
$ tdns-mpcli combiner peer ping --id agent.alpha.example.
pong from agent.alpha.example. (rtt 4ms)

$ tdns-mpcli agent peer ping --id combiner.alpha.example.
pong from combiner.alpha.example. (rtt 3ms)

$ tdns-mpcli signer peer ping --id agent.alpha.example.
pong from agent.alpha.example. (rtt 4ms)

$ tdns-mpcli agent peer ping --id signer.alpha.example.
pong from signer.alpha.example. (rtt 3ms)
```

**Pass condition.** Each `peer list` shows the expected
peers as OPERATIONAL on the `api` transport. Each
`peer ping` returns a pong in both directions.

If a peer is stuck in NEEDED or UNKNOWN:

- Check the JOSE pubkey file paths in each config —
  they must reference the *other* role's pubkey.
- Check the API key in each config — mpcli needs to
  know the right one to call each daemon.
- See [Operation and Debugging §2.3](operation-and-debugging.md#23-reset-a-stuck-peer)
  for `peer reset`.

Repeat phase 1 for every provider in your deployment
before continuing to phase 2.

---

## Phase 2 — Add a Customer Zone

Goal: a customer zone is loaded on combiner, signer and
agent at this provider, with HSYNC3 / HSYNCPARAM
parsed and the dynamic MP options derived.

This phase assumes the zone owner has set up the
customer zone with HSYNC3 + HSYNCPARAM records and is
NOTIFYing every provider's combiner — see
[Customer Zone Setup](customer-zone-setup.md) for the
zone-owner side.

### 2.1 Add a zone directive to each role

The customer zone needs a zone entry in each of
combiner, signer and agent. Using `example.com.` as
the example:

**Combiner** (`/etc/tdns/mpcombiner-zones.yaml`):

```yaml
zones:
   - name:      example.com.
     type:      secondary
     primary:   ZONE-OWNER-ADDR:53
     options:   [ multi-provider ]
```

The `primary` is the zone owner's auth server. Always
include `multi-provider` in the options.

**Signer** (`/etc/tdns/mpsigner-zones.yaml`):

```yaml
zones:
   - name:      example.com.
     type:      secondary
     primary:   COMBINER-ADDR:8055
     options:   [ multi-provider ]
```

The signer's primary is the local combiner.

**Agent** (`/etc/tdns/mpagent-zones.yaml`):

```yaml
zones:
   - name:      example.com.
     type:      secondary
     primary:   COMBINER-ADDR:8055
     options:   [ multi-provider ]
```

The agent also reads the zone (from the combiner), so
it can parse HSYNC3 / HSYNCPARAM and discover peer
agents.

Reload each daemon after editing (`SIGHUP`, or restart).

### 2.2 Verify the zone loaded

`zone list` shows what each role is currently serving:

```
$ tdns-mpcli combiner zone list
ZONE                       TYPE       STORE   FROZEN  DIRTY  OPTIONS
example.com.               secondary  MapZone false   false  [multi-provider]

$ tdns-mpcli signer zone list
ZONE                       TYPE       STORE   FROZEN  DIRTY  OPTIONS
example.com.               secondary  MapZone false   false  [multi-provider online-signing]

$ tdns-mpcli agent zone list
ZONE                       TYPE       STORE   FROZEN  DIRTY  OPTIONS
agent.alpha.example.       primary    MapZone false   false  [allow-updates automatic-zone online-signing]
example.com.               secondary  MapZone false   false  [multi-provider]
```

### 2.3 Verification gate

`zone mplist` is the per-role MP-specific view. It
shows the HSYNCPARAM-derived roles for this zone and
the effective MP options. This is the most informative
single command for "did the multi-provider setup
land?":

```
$ tdns-mpcli combiner zone mplist
ZONE          ROLE        SIGNERS         SERVERS                NSMGMT  EDITS
example.com.  provider    alpha           alpha,bravo,charlie    agent   ALLOW

$ tdns-mpcli signer zone mplist
ZONE          ROLE        SIGNERS         SERVERS                NSMGMT  EDITS
example.com.  signer      alpha           alpha,bravo,charlie    agent   ALLOW

$ tdns-mpcli agent zone mplist
ZONE          ROLE        SIGNERS         SERVERS                NSMGMT  EDITS
example.com.  provider    alpha           alpha,bravo,charlie    agent   ALLOW
```

The `EDITS` column reflects the dynamic option:

- `ALLOW` — this provider is in HSYNCPARAM and may
  contribute (signer or unsigned zone). `OptAllowEdits`
  is set.
- `DISALLOW` — this provider is listed in HSYNCPARAM
  but not as a signer of a signed zone.
  `OptMPDisallowEdits` is set; contributions are
  persisted but not applied. (Expected for bravo and
  charlie in this example.)
- `NOT-LISTED` — our identity does not appear in HSYNC3
  at all. The zone is refused. This is a configuration
  mismatch — investigate before continuing.

**Pass condition.** Every role shows the zone in `zone
list` and `zone mplist` returns sensible HSYNCPARAM
data with `EDITS` in the expected state. The signer
will additionally show `online-signing` in the zone
options once it has signed at least once.

If the zone never appears: the zone owner is not
NOTIFYing this combiner, or the combiner is not
allowed to AXFR from the zone owner. See
[Customer Zone Setup §3](customer-zone-setup.md#3-notify-and-zone-transfer-to-the-combiners).

If `mplist` shows the wrong roles or `NOT-LISTED`: the
HSYNC3 / HSYNCPARAM records in the customer zone do
not match this provider's identity. Inspect with:

```
$ dog @<combiner-addr>:8055 example.com. HSYNC3
$ dog @<combiner-addr>:8055 example.com. HSYNCPARAM
```

---

## Phase 3 — Verify Multi-Provider Communication

Goal: every party in the provider group can reach every
other party, and the gossip matrix converges to
OPERATIONAL across the board.

This phase only makes sense once at least two providers
(or one provider plus an auditor) have completed
phases 1–2. With a single provider in HSYNC3 there is
nothing to coordinate.

### 3.1 Verify pairwise peer discovery

From the local agent's perspective, every remote
participant should appear in `peer list` once HSYNC3
discovery has run:

```
$ tdns-mpcli agent peer list
IDENTITY                   TRANSPORT  STATE         LAST SEEN
agent.bravo.example.       dns        OPERATIONAL   3s ago
agent.bravo.example.       api        OPERATIONAL   12s ago
agent.charlie.example.     dns        OPERATIONAL   2s ago
agent.charlie.example.     api        OPERATIONAL   12s ago
combiner.alpha.example.    api        OPERATIONAL   5s ago
signer.alpha.example.      api        OPERATIONAL   8s ago
```

Note that remote agents show *two* rows each — one per
transport (DNS/CHUNK and API). Both should be
OPERATIONAL.

Exercise both directions with both transports:

```
$ tdns-mpcli agent peer ping    --id agent.bravo.example.
pong from agent.bravo.example. via DNS CHUNK (rtt 18ms)

$ tdns-mpcli agent peer apiping --id agent.bravo.example.
pong from agent.bravo.example. via API (rtt 9ms)
```

If `ping` works but `apiping` doesn't (or vice versa),
the problem is transport-specific — usually a firewall
allowing TCP/53 but not the management port, or a TLS
cert mismatch on the API path.

### 3.2 List the provider groups

The agent computes provider groups automatically from
HSYNC3 RRsets: every distinct set of identities is one
group. List them:

```
$ tdns-mpcli agent gossip group list

GROUP        MEMBERS                                                              ZONES
-----        -------                                                              -----
g_3a8f1c     agent.alpha.example., agent.bravo.example., agent.charlie.example.   example.com. (+0 more)
```

Each row is one group. Members are the identities that
share this exact HSYNC3 set; ZONES are the customer
zones that produced the group.

If you expect more than one group (different customer
zones with different provider sets) and only see one,
the zones probably share members. That is fine.

### 3.3 Verification gate — the gossip matrix

`gossip group state` shows the N×N matrix for one
group: each row is one reporter's view of every other
member's state.

```
$ tdns-mpcli agent gossip group state --group g_3a8f1c

Group: g_3a8f1c (hash: 3a8f1c2b0e9d4f...)
Leader: agent.alpha.example. (term 4, expires in 47m12s)

REPORTER / PEER     agent.alpha    agent.bravo    agent.charlie   AGE
agent.alpha         —              OPERATIONAL    OPERATIONAL     2s    (30s beats)
agent.bravo         OPERATIONAL    —              OPERATIONAL     5s    (30s beats)
agent.charlie       OPERATIONAL    OPERATIONAL    —               3s    (30s beats)
```

**Pass condition.** Every off-diagonal cell is
OPERATIONAL, all AGE values are low (single-digit
seconds for typical BEAT intervals), and `Leader:`
shows an active election with a non-expired lease.

Common failure shapes:

- **One peer's row missing or very stale**: that peer
  is not beating into us. Either they cannot reach us
  (firewall toward our DNS/CHUNK port) or their daemon
  is down.
- **One column full of NEEDED / UNKNOWN**: that peer is
  unreachable from the rest of the group. The remaining
  members agree — probably a downed daemon at that
  peer's site.
- **Asymmetric — alpha sees bravo OPERATIONAL, bravo
  sees alpha NEEDED**: one direction of the transport
  works, the other does not. Usually firewall.
- **Leader: no election held**: the matrix has not yet
  reached all-OPERATIONAL across the board. Once it
  does, the lexicographically smallest member starts an
  election within seconds. If it stays "no election
  held" with a healthy matrix, restart the smallest
  member.

For the full triage flow see
[Operation and Debugging §6](operation-and-debugging.md#6-putting-it-together-a-triage-checklist).

---

## Phase 4 — Exercise the Change Paths

Goal: confirm end-to-end that a contribution actually
propagates to every provider and lands in their served
zones.

This is the smoke test that proves the whole machinery
works. Pick a change you can easily undo.

### 4.1 Add and remove an NS record

```
$ tdns-mpcli agent zone addrr --zone example.com. \
      --rr "example.com. 3600 IN NS ns2.alpha.example."
Successfully added NS record to zone example.com.
  Record: example.com. 3600 IN NS ns2.alpha.example.
```

Verify it propagated to every peer:

```
$ tdns-mpcli agent zone edits list --zone example.com.

SDE Status for Zone: example.com. at 2026-05-17 09:16:02
════════════════════════════════════════

Source: agent.alpha.example.

Type   | State    | RR / Details
NS     | ACCEPTED | example.com. 3600 IN NS ns1.alpha.example.
       |          | Updated: 2026-05-17 09:14:10
NS     | ACCEPTED | example.com. 3600 IN NS ns1.bravo.example.
       |          | Updated: 2026-05-17 09:14:10
NS     | ACCEPTED | example.com. 3600 IN NS ns1.charlie.example.
       |          | Updated: 2026-05-17 09:14:10
NS     | ACCEPTED | example.com. 3600 IN NS ns2.alpha.example.
       |          | Updated: 2026-05-17 09:16:00
```

The new NS appears with state ACCEPTED on every line —
meaning every remote agent's combiner confirmed it. If
state is PENDING with a `Pending:` line listing some
peers, those peers have not confirmed yet — wait a
moment and re-run.

Confirm it landed in the actual signed zone:

```
$ dog @127.0.0.1:8053 +dnssec example.com. NS
example.com. 3600 IN NS ns1.alpha.example.
example.com. 3600 IN NS ns1.bravo.example.
example.com. 3600 IN NS ns1.charlie.example.
example.com. 3600 IN NS ns2.alpha.example.
example.com. 3600 IN RRSIG NS 15 2 3600 ...
```

Then remove it again (clean up after the smoke test):

```
$ tdns-mpcli agent zone delrr --zone example.com. \
      --rr "example.com. 3600 IN NS ns2.alpha.example."
```

Re-run the `dog` query and confirm `ns2.alpha.example.`
is gone.

### 4.2 Trigger a DNSSEC key rollover

Generate a standby ZSK, then roll active→retired and
standby→active:

```
$ tdns-mpcli signer keystore dnssec generate -z example.com. \
      --keytype ZSK --state published --algorithm ED25519
Generated DNSKEY: keytag 56789  ZSK  ED25519  state=published

$ tdns-mpcli signer keystore dnssec rollover -z example.com. --keytype ZSK
Rollover complete: keytag 23456 (ZSK) active→retired, keytag 56789 (ZSK) published→active
```

Watch the propagation through the SDE:

```
$ tdns-mpcli agent zone edits list --zone example.com.
...
Source: signer.alpha.example.

Type    | State    | RR / Details
DNSKEY  | ACCEPTED | example.com. 3600 IN DNSKEY 256 3 15 ...
        |          | KeyId: 23456  State: retired  Updated: 2026-05-17 09:18:14
DNSKEY  | ACCEPTED | example.com. 3600 IN DNSKEY 257 3 15 ...
        |          | KeyId: 12345  State: active  Updated: 2026-05-17 09:14:22
DNSKEY  | ACCEPTED | example.com. 3600 IN DNSKEY 256 3 15 ...
        |          | KeyId: 56789  State: active  Updated: 2026-05-17 09:18:14
```

All three DNSKEYs ACCEPTED at every peer means the new
ZSK has reached every combiner in the group. The signer
will not advance to retiring the old key from the
published set until all peers have confirmed — that
is what the ACCEPTED state encodes.

Confirm the served zone has all three DNSKEYs:

```
$ dog @127.0.0.1:8053 +dnssec example.com. DNSKEY
example.com. 3600 IN DNSKEY 256 3 15 ... ; KeyTag: 23456 (retired ZSK)
example.com. 3600 IN DNSKEY 257 3 15 ... ; KeyTag: 12345 (active KSK)
example.com. 3600 IN DNSKEY 256 3 15 ... ; KeyTag: 56789 (active ZSK)
example.com. 3600 IN RRSIG DNSKEY ...
```

**Pass condition.** Both smoke tests show the change
ACCEPTED at every peer in the SDE and visible in the
signed zone served by the signer.

If any step fails: drop into the topical guides.
[Synchronization Model §7](synchronization-model.md#7-what-this-looks-like-end-to-end)
walks through the same flow with more detail on each
hop; [Making Data Changes](data-changes.md) covers all
the inspection levers; [Operation and Debugging
§6](operation-and-debugging.md#6-putting-it-together-a-triage-checklist)
is the triage flowchart.

---

## What Next

With all four phases green, the deployment is
production-ready in the operational sense. From here:

- Day-to-day inspection lives in [Operation and
  Debugging](operation-and-debugging.md).
- Day-to-day changes (more zones, more peers, key
  rollovers) follow the patterns in [Making Data
  Changes](data-changes.md).
- For an extra independent observer of the network,
  see [The Auditor](auditor.md).

## See Also

- [Quickstart](quickstart.md) — produces the configs
  this runbook starts from.
- [Customer Zone Setup](customer-zone-setup.md) — the
  zone-owner side of phase 2.
- [Operation and Debugging](operation-and-debugging.md)
  — full CLI reference for everything used in the
  verification gates.
- [Synchronization Model](synchronization-model.md) —
  what is happening under the hood at each gate.
