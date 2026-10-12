# The Auditor

`tdns-mpauditor` is the multi-provider system's read-only
observer. It joins the network the same way a regular
provider does — it has a DNS identity, an HSYNC3 entry
in each zone it audits, it participates in BEAT/gossip,
and it receives SYNC messages — but it never contributes
any zone data of its own. It exists to *see* what is
happening across the network.

The auditor's value is independence. A combiner sees its
own provider's view; an agent sees its provider's
contributions and what peers have sent it. The auditor
sees what *every* participant claims, what *every* SYNC
carries, and what *every* confirmation reports —
without being part of the production path. This makes it
the natural place to detect divergence, missed
confirmations, suspicious key activity, or providers
silently dropping data.

## 1. Where the Auditor Fits

For the example.com setup (alpha signing+serving, bravo
and charlie serving only), adding an auditor makes the
gossip matrix 4×4:

```mermaid
flowchart LR
    AA[agent.alpha]
    AB[agent.bravo]
    AC[agent.charlie]
    AD[audit.example.]

    AA <-- "BEAT + gossip" --> AB
    AA <-- "BEAT + gossip" --> AC
    AA <-- "BEAT + gossip" --> AD
    AB <-- "BEAT + gossip" --> AC
    AB <-- "BEAT + gossip" --> AD
    AC <-- "BEAT + gossip" --> AD

    AA -- "SYNC" --> AD
    AB -- "SYNC" --> AD
    AC -- "SYNC" --> AD
```

The auditor receives SYNCs from every agent (so it sees
every change passing through the network) and
participates in gossip (so it sees every BEAT and the
liveness view each agent reports). It sends no SYNCs and
contributes nothing to any combiner.

## 2. Adding the Auditor to a Zone

Two changes to the customer zone:

```
; Add an HSYNC3 record for the auditor
example.com.   HSYNC3       ON  auditor  audit.example.  .

; List the auditor in HSYNCPARAM auditors=
example.com.   HSYNCPARAM   servers="alpha,bravo,charlie" signers="alpha" auditors="auditor" nsmgmt="agent" parentsync="agent"
```

Then bump the zone so every combiner picks up the change:

```sh
tdns-cli auth zone bump -z example.com.
```

The `auditors=` key in HSYNCPARAM is what tells the
agents that this HSYNC3 entry refers to an auditor (not
a signer or server) — agents include auditors as
mandatory SYNC recipients while not expecting them to
contribute back.

The audit identity (`audit.example.`) follows the same
DNS-discovery model as any agent identity: URI, SVCB and
JWK records published under that name. If the auditor
was generated via `tdns-mpcli configure`, those records
are already being served by the auditor's auto-zone.

## 3. Configuring an Auditor

The simplest path is `tdns-mpcli configure`: when asked
"Also generate a tdns-mpauditor config?" answer yes,
provide an auditor identity, and the same interview
produces a `/etc/tdns/tdns-mpauditor.yaml` config plus
JOSE keypair and TLS cert. The generated example zone
`mptest.example.` then lists the auditor in its HSYNC3
and HSYNCPARAM records, and the auditor observes it.

Start it like the other daemons:

```sh
sudo tdns-mpauditor --config /etc/tdns/tdns-mpauditor.yaml &
```

The auditor listens for DNS (its identity zone, observed
zones and MP signaling) on port `8056` and serves its
management API over HTTPS on `7056`; the mpcli config
gets a `tdns-mpauditor` entry pointing at it.

## 4. CLI Surface

All auditor commands hang off `tdns-mpcli auditor` and
target the auditor's management API.

### 4.1 Zones being audited

```
$ tdns-mpcli auditor zones

Zone: example.com.  (4 providers, serial 2026051704)
  Provider                          Signer  Last BEAT     Last SYNC     Gossip
  agent.alpha.example.              true    3s            17s           OPERATIONAL
  agent.bravo.example.              false   5s            17s           OPERATIONAL
  agent.charlie.example.            false   2s            17s           OPERATIONAL
  audit.example.                    false   0s            -             OPERATIONAL
```

`zones` is the most useful one-shot health view from the
auditor's perspective: per zone, every party the auditor
knows about, who is a signer, when each was last heard
from (BEAT), when each last sent a SYNC, and the gossip
state.

`Last SYNC = -` for the auditor's own row is expected
(it never sends SYNC). `Last SYNC = -` for any other
row means the auditor has never received a SYNC from
that provider for that zone — probably a configuration
mismatch in HSYNCPARAM.

### 4.2 Audit event log

The auditor records every protocol-level event:
incoming BEAT, incoming SYNC, gossip state change,
confirmation, key state transition.

```sh
# Most recent 50 events
tdns-mpcli auditor eventlog list

# Filter by zone
tdns-mpcli auditor eventlog list -z example.com.

# Events since a specific time
tdns-mpcli auditor eventlog list --since 2026-05-17T08:00:00Z

# Larger window
tdns-mpcli auditor eventlog list --last 500
```

Output is one line per event with its ID, timestamp,
type, zone, originator and a one-line summary.

Each event also records what its message carried: per
operation its kind and RR type and the records, a
DNSKEY by key tag with the DS verdict and state its
sender gave it, the distribution ID, and for a
confirmation what was applied, removed or rejected.
The text is the message's standard printable form, the
same wherever the message is shown. A sync's one-line
summary is its operations, e.g. `replace DNSKEY (3
records)`.

A provider resends its whole DNSKEY set, so the details
of a sync also show what changed since the same
sender's previous one for the zone:
`DS no, standby (was: published)`; a key that is new
says `(new)`, and one the sender no longer sends is
listed as such. The auditor remembers this from its
start: the first sync from each sender after a start
shows no changes.

```sh
# The details below each event
tdns-mpcli auditor eventlog list --details

# One event in full, by the ID from the list
tdns-mpcli auditor eventlog show 1742
```

Events logged before the details were recorded have
none.

Clearing the log:

```sh
tdns-mpcli auditor eventlog clear -z example.com.        # one zone
tdns-mpcli auditor eventlog clear --older-than 30d       # rotate
tdns-mpcli auditor eventlog clear --all                  # wipe
```

At least one of `--zone`, `--older-than` or `--all` is
required.

### 4.3 Observations

Observations are anomalies the auditor has *inferred* —
not raw events. There are four today:

- a provider that has stopped beating, and its return;
- a provider declared in HSYNC3 that the auditor has
  never heard from;
- a DNSKEY, CDS or CDNSKEY sent by a provider that is
  not a signer of the zone;
- a distribution that has waited longer than
  `audit.pending_threshold` (default 2 minutes) for a
  member's confirmation. The observation names the
  distribution, its originator and the member. A second
  one follows when the member has answered. See 4.6.

```sh
tdns-mpcli auditor observations
tdns-mpcli auditor observations -z example.com.
```

Output groups observations by severity (INFO, WARN,
ERROR), zone and provider.

Observations are where the auditor earns its keep — they
turn the raw event stream into actionable signal. The
exact detectors are evolving; for now treat any WARN or
ERROR as something to triage.

### 4.4 Peer and gossip commands

The auditor reuses the same `peer` and `gossip`
subtrees as agents:

```sh
tdns-mpcli auditor peer list
tdns-mpcli auditor peer ping --id agent.alpha.example.
tdns-mpcli auditor peer reset --id agent.alpha.example.

tdns-mpcli auditor gossip state --zone customer.mptest.
```

Behaviour matches the agent equivalents documented in
[Operation and Debugging](operation-and-debugging.md).
In particular `gossip state --zone` is the way to see
the matrix *from the auditor's vantage point* — useful
when the auditor disagrees with what the agents think
about each other.

### 4.5 Zone listings

```sh
tdns-mpcli auditor zone list
tdns-mpcli auditor zone mplist
```

Same shape as `combiner zone mplist`, but from the
auditor's view. The auditor should show every zone that
includes it in HSYNCPARAM `auditors=`.

### 4.6 Distributions and their confirmations

Every agent sends its final confirmation of a
distribution to the originator and, as a copy, to each
auditor of the zone. The auditor gets the distribution
itself as well, so for each one it knows which voting
members have answered and which it still waits for.

```
$ tdns-mpcli auditor confirmations -z example.com.
Zone: example.com.
  Distribution  Originator                      Age       State      Carries
  69812b15      agent.alpha.example.            3m12s     pending    add NS (1 record)
      agent.bravo.example.            confirmed  SUCCESS at 09:30:00
      agent.charlie.example.          pending    no confirmation seen for 3m10s
```

Here alpha's NS change is blocked on charlie: bravo has
confirmed, charlie has not. A member that refused is
listed as `rejected` with the reason it gave.

A distribution is `pending` while a member's
confirmation is missing, `completed` when all have
confirmed and `rejected` when all have answered and one
refused. `--pending` lists the pending ones only.
Without `-z` every audited zone is listed.

What the view cannot tell:

- An agent on older software sends no copies. A member
  that has sent the auditor none since the auditor
  started is therefore listed as `unknown`, not
  `pending`, and no observation is raised for it. A
  distribution that misses only such members'
  confirmations is `unknown` too. A member counts from
  its first copy, for any zone.
- A copy is sent once. If it is lost, the member stays
  `pending` here although the originator has its
  confirmation.
- A distribution sent to one member only (a resync on
  request) does not reach the auditor. Its confirmation
  does, and it is listed as `unseen`: who else was to
  confirm it is not known.
- The state is kept in memory. After a restart the
  auditor follows the distributions sent from then on.

A distribution stays listed for an hour after its last
confirmation, and for a day while one is missing.

## 5. What the Auditor Does Not Do

- **No contributions.** The auditor never sends UPDATE
  to any combiner. If you ever see auditor identity as
  an Origin in `combiner zone edits list`, that is a
  bug.
- **No served zone for customers.** It serves only its
  own auto-zone (for peers to discover it).
- **No participation in leader election votes.**
  Auditors are not eligible to be leader.

These properties are what make the auditor safe to
deploy: it cannot, by design, break the production data
plane.

## 6. Web Interface (Under Development)

A web dashboard for the auditor is in development. It
will surface the same data exposed by `auditor zones`,
`auditor observations` and `auditor eventlog` plus
historical timelines and per-zone state diffs. It is
**not ready for use yet** — for now, the CLI is the
only supported interface.

## 7. See Also

- [Architecture](multi-provider-architecture.md) — where
  the auditor fits in the data flow.
- [Customer Zone Setup](customer-zone-setup.md) —
  HSYNC3 and HSYNCPARAM fundamentals.
- [Operation and Debugging](operation-and-debugging.md)
  — the shared `peer` and `gossip` commands.
- [Synchronization Model](synchronization-model.md) —
  the SYNC messages the auditor observes.
