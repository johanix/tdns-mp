# Multi-Provider Advanced Topics

This document covers topics beyond the basic quickstart setup:
how providers synchronize zone data between themselves, how
delegation information is kept in sync with the parent zone,
and how provider-controlled zones are managed.

## Contents

1. **Parent Synchronization** -- Automatically updating the
   delegation information (NS, DS, glue) in the parent zone
   of a customer zone.

2. **Provider Zones** -- Combiner management of zones
   controlled by the provider, where contents need to be
   managed in sync with customer zones (e.g., _signal KEY
   records for SIG(0) trust bootstrap).

3. **Provider-to-Provider Synchronization** -- The data flow
   from signer to local agent to remote agents to remote
   combiners. Double confirmations with per-record details.

4. **Agent-to-Agent Coordination** -- The gossip protocol,
   provider group computation, leader election, and group
   state management.


## 1. Parent Synchronization

When a child zone's delegation data changes (NS records, glue
addresses, or DS records), the parent zone must be updated.
TDNS automates this via two mechanisms, both driven by the
DSYNC RRset published in the parent zone.

### 1.1 The DSYNC RRset

The parent zone publishes a DSYNC RRset at `_dsync.<parent>.`
that advertises which synchronization schemes it supports and
where to send updates. The format is:

```
_dsync.parent. IN DSYNC <type> <scheme> <port> <target>
```

Where:
- **type** is the RR type being synchronized (CDS, CSYNC,
  CDNSKEY, or ANY)
- **scheme** is NOTIFY, UPDATE, SCANNER, or API
- **port** is the TCP/UDP port of the target
- **target** is the FQDN of the receiving server

Example:

```
_dsync.example.com. IN DSYNC CDS   NOTIFY 5354 notifications.example.com.
_dsync.example.com. IN DSYNC CSYNC NOTIFY 5354 notifications.example.com.
_dsync.example.com. IN DSYNC ANY   UPDATE 5354 updates.example.com.
```

This tells child zone operators: "to synchronize CDS or CSYNC,
send a generalized NOTIFY to notifications.example.com:5354.
To synchronize any record type, send a SIG(0)-signed UPDATE
to updates.example.com:5354."

### 1.2 The UPDATE Scheme (Child Side)

The UPDATE scheme is the more capable mechanism. The child
agent constructs a DNS UPDATE message, signs it with a SIG(0)
key, and sends it directly to the parent's UPDATE receiver.

**Flow:**

1. The agent detects a change to delegation data (NS, glue,
   or DS) in the customer zone.
2. The agent looks up the parent's DSYNC RRset via its IMR
   to find the UPDATE target address and port.
3. The agent constructs a DNS UPDATE message containing the
   adds and removes needed to bring the parent's delegation
   in sync.
4. The agent signs the UPDATE with its active SIG(0) key.
5. The agent sends the signed UPDATE to the parent's UPDATE
   receiver.

**SIG(0) Key Bootstrap:**

Before the parent will accept signed UPDATEs, it must trust
the child's SIG(0) key. The agents run the bootstrap for a
zone that has the `parentsync` zone option and whose
HSYNCPARAM record says `parentsync="agent"`. The flow is:

1. The elected leader agent generates a SIG(0) keypair (or
   uses an existing one) and sends a Publish instruction to
   the combiner.
2. The combiner publishes the KEY record at the zone apex
   and at `_signal` names under each NS target in provider
   zones (see section 3).
3. The agent sends a KeyState EDNS(0) inquiry to the
   parent. If the parent already trusts the key, the agent
   goes on to step 6.
4. If the parent does not know the key, the agent selects
   a bootstrap method: the strongest method that is both
   in the parent's SVCB bootstrap advertisement and in its
   own `parentsync.update.bootstrap.methods`. It then sends
   a self-signed UPDATE containing the KEY RR to the
   parent's UPDATE receiver. When the method is `manual`,
   no UPDATE is sent and an operator at the parent has to
   act.
5. The parent verifies the key under the delegation policy
   bound to the parent zone: it looks for the KEY where the
   policy's `mechanisms` point (`at-apex`, `at-ns`) and,
   with `require-dnssec`, accepts it only if it is
   DNSSEC-validated there (see section 2.4).
6. The agent polls the parent's KeyState until the key is
   trusted, then compares the delegation data with the
   parent and syncs any difference.

**Agent configuration** (in tdns-mpagent.yaml):

```yaml
parentsync:
   schemes:     [ notify, update ]
   update:
      keygen:
         algorithm:  ED25519

# How long an elected leader holds the role; 60m is the
# default.
# delegationsync:
#    leader-election-ttl: 60m
```

`parentsync.schemes` lists the schemes the agent uses
towards the parent, in order of preference (section 1.4).
`parentsync.update.keygen.algorithm` is the algorithm of the
SIG(0) keys that sign the UPDATEs. `tdns-mpcli configure`
writes this `parentsync:` block.

The other `parentsync:` keys (`update.bootstrap.methods`,
`update.allow-insecure`, `api`) are described in
[tdns-agent configuration](../../tdns/guide/config-tdns-agent.md).
How the bootstrap method is negotiated is in
[tdns special features §1.5](../../tdns/guide/special-features.md#15-child-pushing-changes).

### 1.3 The NOTIFY Scheme (Child Side)

The NOTIFY scheme is simpler but requires the parent to run a
scanner. The child publishes CDS and/or CSYNC records at the
zone apex, then sends a generalized NOTIFY to the parent's
NOTIFY receiver. The parent's scanner picks up the NOTIFY,
queries the child for the published records, verifies them,
and applies the changes.

**Flow:**

1. The agent detects a change to delegation data.
2. The agent publishes a CSYNC record (for NS/glue changes)
   or a CDS record (for DS changes) at the zone apex.
3. The agent sends a NOTIFY with the appropriate QTYPE
   (CSYNC or CDS) to the parent's NOTIFY receiver address
   (from the DSYNC RRset).
4. The parent's scanner queries the child for the published
   records, authenticates them under the parent zone's
   delegation policy (section 2.3), and applies the changes
   to the parent zone.

### 1.4 Scheme Selection

The agent considers its configured schemes
(`parentsync.schemes`: `notify`, `update`, `api`) in the
order listed, and uses those the parent advertises in its
DSYNC RRset. An empty list means nothing is sent. UPDATE is
immediate and needs no scanner on the parent side; list it
first to prefer it.


## 2. Parent-Side Configuration

### 2.1 Automatic DSYNC Publication

When tdns-auth is the primary for a parent zone with the
`childsync` zone option, it publishes DSYNC RRsets based on
the top-level `childsync:` block:

```yaml
childsync:
   schemes: [ notify, update ]
   notify:
      types:      [ CDS, CSYNC ]
      port:       5354
      target:     notifications.{ZONENAME}
      addresses:  [ 198.51.100.1 ]
   update:
      types:      [ ANY ]
      port:       5354
      target:     updates.{ZONENAME}
      addresses:  [ 198.51.100.1 ]
      keygen:
         algorithm: ED25519
```

The `{ZONENAME}` template is expanded at runtime to the actual
zone name. The server creates DSYNC RRs at `_dsync.<zone>.`
and publishes A/AAAA glue records for the target names.
Each `port` must be one that the `listeners:` block listens
on.

For the UPDATE target the server also publishes an SVCB
record advertising the SIG(0) bootstrap methods, derived
from the zone's delegation policy (section 2.4). It keeps a
SIG(0) key of its own, of `keygen.algorithm`, to sign
KeyState responses. The `api` scheme, for children that
cannot sign DNS messages, is described in
[tdns special features §1.7](../../tdns/guide/special-features.md#17-the-dsync-api-scheme-https-for-children-that-cannot-sign).

### 2.2 UPDATE Receiver

tdns-auth acts as the UPDATE receiver. A tdns-agent that is
a secondary of the parent zone can do the same with the
`childsync-proxy` zone option; see
[Agent fronting a parent zone](../../tdns/guide/childsync-proxy.md).
When the receiver gets a SIG(0)-signed UPDATE for a child
delegation:

1. It validates the SIG(0) signature against its truststore.
2. It checks the update against the zone's
   `updatepolicy.child` (which names and RR types a child
   may change).
3. It writes the delegation data via a delegation backend.

**Delegation backends** say where the delegation state is
kept (`store: sqlite | direct | external-db`) and how it
reaches the parent zone (`writer: none | zonefile | ddns`).
The one-word `type:` names are shorthand for a pair:

- **direct** -- Modifies the in-memory zone directly and
  rewrites its zone file. Used when the receiving server
  is the primary and owns the zone's data.
- **db** -- Stores delegation data in a SQLite database
  without touching the served zone. The change is served
  once something rebuilds the zone.
- **zonefile** -- Stores in the database and generates
  per-child zone file fragments in `directory`. Supports
  an optional `notify-command` (e.g., `rndc reload`) to
  trigger the actual primary to reload.
- **upstream** -- Stores in the database and sends the
  change to the parent zone's primary as a TSIG-signed
  DNS UPDATE.
- **external-db** -- Stores delegation data in a shared
  MariaDB database for a provisioning system to read.

`db` and `direct` are predefined and need no entry. Other
backends are declared in `delegationbackends:`:

```yaml
delegationbackends:
   - name:       files-example
     type:       zonefile
     directory:  /var/lib/tdns/delegations/example.com
```

The store/writer axes are described in
[Agent fronting a parent zone](../../tdns/guide/childsync-proxy.md).

Zones reference backends by name:

```yaml
zones:
   - name:              example.com.
     type:              primary
     zonefile:          /etc/tdns/zones/example.com.zone
     options:
        - childsync
        - allow-child-updates
        - on-conflict-zonefile-wins
     delegationbackend: files-example
     delegationpolicy:  default
     updatepolicy:
        child:
           type:     selfsub
           rrtypes:  [ NS, A, AAAA, DS, KEY ]
```

`allow-child-updates` needs a `delegationbackend:` and an
`updatepolicy.child` type other than `none`. A primary whose
backend is not `direct` must also set
`on-conflict-zonefile-wins`: the default,
`on-conflict-db-wins`, contradicts a zone file generated
elsewhere, and the zone is refused at startup.
`delegationpolicy:` names an entry in `childsync.policies:`
(section 2.4).

### 2.3 NOTIFY Receiver

tdns-auth (or a tdns-agent with `childsync-proxy`) also acts
as the NOTIFY receiver for generalized NOTIFY messages. When
it receives a NOTIFY(CDS) or NOTIFY(CSYNC) for a type the
zone advertises, it triggers the scanner to query the child
zone and process the published records.

What the scanner accepts is decided by the zone's delegation
policy (section 2.4). With `require-dnssec: true`, the
records copied from the child must be DNSSEC-validated. See
[tdns special features §1.3](../../tdns/guide/special-features.md#13-parent-the-generalized-notify-scanner).

### 2.4 Key Trust Management

When a child sends a self-signed UPDATE containing its SIG(0)
KEY, the parent must verify the key before trusting it. How
it verifies is set by the delegation policy bound to the
parent zone. Policies are named under `childsync.policies:`,
and a zone selects one with `delegationpolicy:`:

```yaml
childsync:
   policies:
      default:
         bootstrap:
            mechanisms:      [ at-apex, at-ns ]
            require-dnssec:  true
            manual:          false
            allow-unvalidated-upload: false
            retry:
               max-attempts: 5
               interval:     10s
```

- `mechanisms` -- where the parent looks for the child's
  KEY: `at-apex` at the child apex, `at-ns` at
  `_sig0key.<child>._signal.<ns>` for the child's
  nameservers. An empty list means no automatic
  verification.
- `require-dnssec` -- the KEY found must be
  DNSSEC-validated. When false, finding the KEY where
  `mechanisms` point is enough.
- `manual` -- a new key needs an operator to trust it:
  KeyState answers and rejected UPDATEs tell the child
  that manual bootstrap is required, and the parent
  advertises `manual`.
- `allow-unvalidated-upload` -- whether a child may upload
  its KEY in an UPDATE signed by that not-yet-trusted key.
- `retry` -- how many lookups the parent makes
  (`max-attempts`) and the delay between them
  (`interval`).

The values shown are the built-in `default` policy, used
when the config defines no policy by that name. A zone that
omits `delegationpolicy:` binds `default`; a name that does
not resolve quarantines the zone.

The parent advertises its policy in the bootstrap SVCB
record at the UPDATE target: `at-apex`/`at-ns` when
`require-dnssec` is true, `unsigned` when it is false and
`mechanisms` is not empty, and `manual` when that flag is
set. The child selects its method from that advertisement
(section 1.2). See
[tdns special features §1.2](../../tdns/guide/special-features.md#12-parent-the-update-receiver).


## 3. Provider Zones

In a multi-provider setup, each provider typically controls
one or more zones of their own (e.g., `alpha.example.net.`).
These "provider zones" may need to contain records that are
managed in sync with customer zone state -- most notably,
`_signal` KEY records used for SIG(0) key bootstrap.

### 3.1 _signal KEY Records

When a child zone's agent publishes its SIG(0) key, the
combiner places the KEY not only at the customer zone apex
but also at special `_signal` owner names under each NS
target that falls within a provider zone:

```
_sig0key.child.example.com._signal.ns1.alpha.example.net.  KEY  ...
```

This allows the parent to discover the child's SIG(0) key
by looking at the NS targets -- each provider's nameserver
advertises the key under a well-known `_signal` name.

### 3.2 Combiner Provider Zone Management

The combiner is configured with a list of provider zones it
manages:

```yaml
multi-provider:
   provider-zones:
      - zone:            alpha.example.net.
        allowed-rrtypes: [ KEY ]
```

When the agent sends a Publish instruction with
`locations: ["at-ns"]`, the combiner:

1. Determines which NS targets belong to the local provider.
2. Computes the `_signal` owner name for each.
3. Publishes the KEY RRs at those names in the provider zone.
4. Bumps the provider zone serial.

When NS records change (providers added or removed), the
combiner resyncs: it diffs the current NS set against the
stored set and adds/removes `_signal` KEYs accordingly.


## 4. Provider-to-Provider Synchronization

When one provider's agent makes a change (e.g., adds an NS
record), that change must propagate to all other providers'
combiners so the zone is consistent everywhere.

### 4.1 Data Flow

```
Local Signer
     |  signs zone
     v
Local Agent
     |  SYNC message (DNS CHUNK)
     v
Remote Agent(s)
     |  forwards to its combiner
     v
Remote Combiner(s)
     |  applies changes, re-serves zone
     v
Remote Signer(s)
     |  re-signs
     v
Remote Auth Servers
```

### 4.2 SYNC Messages

The local agent sends zone updates to remote agents via SYNC
messages carried in DNS NOTIFY with CHUNK EDNS(0) payloads
over TCP. Each SYNC message contains:

- The zone name
- A list of RRset operations (add/remove) with full RR data
- The sender's identity and a message ID

### 4.3 Double Confirmation

TDNS uses a two-phase confirmation system:

**Phase 1 -- Immediate ACK:** The remote agent acknowledges
receipt of the SYNC message. This confirms the data was
received but not yet applied.

**Phase 2 -- Confirmation with Details:** After the remote
combiner processes the update, it sends a confirmation back
with per-record status:

- **ACCEPTED** -- Record was applied successfully
- **REJECTED** -- Record was rejected by policy
- **DUPLICATE** -- Record already existed (no-op)

The local agent tracks confirmation state per record and per
remote agent. The ReliableMessageQueue retries unconfirmed
messages with exponential backoff until all remote agents
have confirmed.


## 5. Agent-to-Agent Coordination

### 5.1 The Gossip Protocol

Agents maintain an NxN state matrix for each provider group.
Each agent reports its view of every other agent's state
(UNKNOWN, NEEDED, KNOWN, OPERATIONAL). This matrix is
exchanged via gossip piggy-backed on the regular BEAT
heartbeat messages.

On every BEAT round-trip:
- The outgoing BEAT carries the sender's gossip state.
- The BEAT response carries the responder's gossip state
  back via CHUNK EDNS(0) on the same TCP connection.

Gossip merge uses latest-timestamp-wins: if a received entry
has a newer timestamp than the local entry, it replaces it.

When all cells in the matrix show OPERATIONAL, the group
fires the OnGroupOperational callback. When any cell drops
below OPERATIONAL, OnGroupDegraded fires and the group
leader is invalidated.

### 5.2 Provider Groups

Provider groups are computed deterministically from the
HSYNC3 records in the zone. All zones that share the same
set of provider identities form a group, identified by a
truncated SHA-256 hash of the sorted identity set.

Groups are recomputed whenever HSYNC3 data changes (e.g.,
a provider is added or removed from a zone).

### 5.3 Leader Election

Each provider group elects a leader via a three-phase
protocol: CALL, VOTE, CONFIRM. Elections are broadcast via
dedicated election messages (not piggybacked on BEAT).

Key properties:
- Only the lexicographically smallest group member initiates
  an election when OnGroupOperational fires. This prevents
  concurrent overlapping elections.
- Election results propagate to non-participating agents via
  the gossip protocol.
- The leader has a TTL, `delegationsync.leader-election-ttl`
  (default 60m). Re-election is triggered automatically
  before expiry.
- If the group degrades (a member becomes unreachable), the
  leader is invalidated immediately.

The leader is responsible for parent-facing operations
(delegation sync, key publication) on behalf of the entire
provider group.
