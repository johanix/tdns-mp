# Customer Zone Setup

This document covers what the *zone owner* must do to put a
zone under multi-provider coordination. The providers' own
configuration (combiner, signer, agent) is covered in
[Quickstart](quickstart.md) and assumed to be in place.

The running example throughout this guide:

- **example.com.** — the customer zone.
- **alpha** — provider that signs *and* serves the zone.
- **bravo** — provider that only serves.
- **charlie** — provider that only serves.

The same example is used in
[Operation and Debugging](operation-and-debugging.md),
[Making Data Changes](data-changes.md), and
[The Auditor](auditor.md) (where a fourth party joins).

## 1. What the Zone Owner Provides

The zone owner runs an authoritative DNS server that holds
the *unsigned* customer zone — the records they want to
publish, before any multi-provider coordination or DNSSEC
processing. This is typically the same operator's existing
hidden-primary or BIND/Knot setup.

Their responsibilities are:

1. **Publish the customer zone** with HSYNC3 and HSYNCPARAM
   records that name the providers (next section).
2. **Allow zone transfer** to each provider's combiner.
3. **Send NOTIFY** to each provider's combiner on the
   combiner's published address:port whenever the zone
   changes.

Everything downstream of the combiner (merging
contributions, signing, serving to resolvers) is the
providers' job.

## 2. HSYNC3 and HSYNCPARAM

Two private RR types in the apex of the customer zone tell
the multi-provider system who the providers are and what
role each plays.

### 2.1 HSYNC3 — provider identity

There is one HSYNC3 record per participating party. The
RDATA fields are:

| Field    | Meaning                                                          |
|----------|------------------------------------------------------------------|
| State    | `ON` (active) or `OFF` (configured but suspended).               |
| Label    | Short tag for this provider. Used in HSYNCPARAM to refer to it.  |
| Identity | FQDN at which the agent for this provider publishes itself.      |
| Upstream | Label of an upstream provider, or `.` if none.                   |

For example.com. with three providers:

```
example.com.   HSYNC3   ON  alpha    agent.alpha.example.    .
example.com.   HSYNC3   ON  bravo    agent.bravo.example.    .
example.com.   HSYNC3   ON  charlie  agent.charlie.example.  .
```

The **Identity** is the FQDN where peers will look up the
URI, SVCB and JWK records for that agent — see
[Architecture §5](multi-provider-architecture.md#5-identity-and-discovery).
Each provider operator gives the zone owner this FQDN as
part of onboarding.

The **Label** is the short name used everywhere else
(HSYNCPARAM lists, CLI output, log messages). Keep it
short and meaningful.

`OFF` is useful when temporarily removing a provider:
keep the HSYNC3 record so peers still know about the
provider, but block coordination. Removing the HSYNC3
record entirely takes the provider out of the group, at
which point the other providers' combiners should be
purged of contributions attributed to it (see
[Synchronization Model §6.3](synchronization-model.md#63-purging-by-origin)).

### 2.2 HSYNCPARAM — roles

A single HSYNCPARAM record per zone carries zone-wide
multi-provider policy as key=value pairs. Multiple
HSYNCPARAM records in the same zone is an error.

The keys that matter here:

| Key          | Meaning                                                            |
|--------------|--------------------------------------------------------------------|
| `servers=`   | Comma-separated labels of providers that serve the zone.           |
| `signers=`   | Labels of providers that sign the zone.                            |
| `nsmgmt=`    | Who manages the NS RRset: `agent` (coordinated) or a single label. |
| `parentsync=`| Who is responsible for parent-side delegation sync.                |
| `auditors=`  | Labels of auditor parties (see [The Auditor](auditor.md)).         |

For example.com. with alpha signing+serving and
bravo/charlie serving only:

```
example.com.   HSYNCPARAM   servers="alpha,bravo,charlie" signers="alpha" nsmgmt="agent" parentsync="agent"
```

This says:

- All three providers serve the zone (their NS records
  will all appear in the apex NS RRset).
- Only alpha signs the zone. Bravo and charlie receive
  the signed zone via zone transfer from alpha's signer.
- The agents collectively manage the NS RRset
  (`nsmgmt="agent"`).
- The agents collectively manage parent delegation sync.

The HSYNCPARAM record is what triggers the dynamic
options derived in `populateMPdata` — see
[Synchronization Model §5](synchronization-model.md#5-the-dynamic-mp-options)
for the full table. For this example.com setup:

| Provider | `OptAllowEdits` | `OptMPDisallowEdits` | `OptInlineSigning` | `OptMultiSigner` |
|----------|-----------------|----------------------|--------------------|------------------|
| alpha    | true            | false                | true               | false            |
| bravo    | false           | true                 | false              | false            |
| charlie  | false           | true                 | false              | false            |

Bravo and charlie are *participants* (they get the SDE,
they receive SYNCs, they participate in gossip and leader
election) but their combiners do not apply local edits to
the served zone, because they cannot produce valid RRSIGs
over them. They get the signed zone via zone transfer
from alpha's signer.

To add a second signer (true RFC 8901 multi-signer
setup), change `signers="alpha"` to e.g.
`signers="alpha,bravo"`. That flips `OptMultiSigner` to
true everywhere and enables the KEYSTATE DNSKEY exchange
between alpha and bravo.

### 2.3 A complete example.com. zone file

All names below are written as fully-qualified FQDNs
with trailing dots — no `$ORIGIN`, no `@`, no short
names. This is more verbose but unambiguous; it is also
the form the CLI emits and accepts everywhere.

```
example.com.   3600  IN  SOA   ns1.alpha.example. hostmaster.example.com. (
                                  2026051701  ; serial
                                  3600        ; refresh
                                  900         ; retry
                                  604800      ; expire
                                  300         ; minimum
                                  )

; Apex NS — every serving provider has at least one NS here.
example.com.   3600  IN  NS   ns1.alpha.example.
example.com.   3600  IN  NS   ns1.bravo.example.
example.com.   3600  IN  NS   ns1.charlie.example.

; Multi-provider coordination records
example.com.   3600  IN  HSYNC3      ON  alpha    agent.alpha.example.    .
example.com.   3600  IN  HSYNC3      ON  bravo    agent.bravo.example.    .
example.com.   3600  IN  HSYNC3      ON  charlie  agent.charlie.example.  .
example.com.   3600  IN  HSYNCPARAM  servers="alpha,bravo,charlie" signers="alpha" nsmgmt="agent" parentsync="agent"

; Actual zone content
www.example.com.    3600  IN  A     192.0.2.10
www.example.com.    3600  IN  AAAA  2001:db8::10
mail.example.com.   3600  IN  A     192.0.2.20
example.com.        3600  IN  MX    10 mail.example.com.
```

The combiner will treat the apex NS, DNSKEY, CDS and
CSYNC RRsets as multi-provider-coordinated (controlled
by contributions from the agents). Everything else in
the zone passes through unchanged.

### 2.4 Inspecting HSYNC3/HSYNCPARAM records

`dig` cannot display the RDATA for private RR types like
HSYNC3 and HSYNCPARAM. Use `dog` instead:

```sh
dog @ns1.example-owner. example.com. HSYNC3
dog @ns1.example-owner. example.com. HSYNCPARAM
```

## 3. NOTIFY and Zone Transfer to the Combiners

Each combiner publishes a DNS listener on a known
address:port (typically `<provider-public-addr>:8055` in
the example configs, or `:53` in production). The zone
owner's authoritative server must:

1. **Allow AXFR/IXFR** from each combiner's source
   address.
2. **Send NOTIFY** to each combiner's address:port on
   every change to the zone.

For the example.com. setup, the zone owner's BIND
configuration would include something like:

```
zone "example.com" {
    type primary;
    file "example.com.zone";

    allow-transfer {
        198.51.100.10;     // alpha combiner
        198.51.100.20;     // bravo combiner
        198.51.100.30;     // charlie combiner
    };

    also-notify {
        198.51.100.10 port 8055;
        198.51.100.20 port 8055;
        198.51.100.30 port 8055;
    };
};
```

The exact address:port for each combiner is part of the
information the providers give the zone owner during
onboarding.

If the zone owner's primary is itself tdns-auth, the
equivalent configuration uses the `notify` and
`allow-transfer` zone options.

## 4. Forcing a Refresh

After changing HSYNC3, HSYNCPARAM, or anything else in
the customer zone, you want every combiner to pull a
fresh copy without waiting for the SOA refresh interval.
Bump the serial and re-send NOTIFY:

```sh
tdns-cli auth zone bump -z example.com.
```

This increments the SOA serial (and the optional epoch
field, if the zone uses one) and sends NOTIFY to all
configured `also-notify` targets. Each combiner will see
the new serial, request an AXFR/IXFR, reload the zone,
and re-evaluate HSYNC3/HSYNCPARAM (which may change
options for that zone).

This is the right command after:

- Adding or removing an HSYNC3 record (a provider joining
  or leaving).
- Changing HSYNCPARAM (e.g. promoting a provider from
  server-only to signer).
- Any other change you want propagated immediately.

The `bump` command works on whichever auth server holds
the customer zone — usually the zone owner's own
tdns-auth instance, but the same command exists on the
combiner (`tdns-mpcli combiner zone bump`) for the rare
case where you want to force a re-serve from the
combiner without going back to the zone owner.

## 5. Verifying the Zone Reached Every Combiner

After `auth zone bump`, check each combiner for the new
zone:

```sh
# At each combiner: list zones it is currently serving
tdns-mpcli combiner zone list

# Or show only the multi-provider zones with HSYNCPARAM detail
tdns-mpcli combiner zone mplist

# Confirm the new serial arrived
dig @<combiner-addr> -p 8055 example.com. SOA
```

`combiner zone mplist` is the most useful of these —
it shows the per-zone HSYNCPARAM roles, the derived
`OptAllowEdits` / `OptMPDisallowEdits` flags, and the
combiner's view of what each provider should contribute.

Once the zone is loaded on every combiner, the agents
discover each other via the HSYNC3 records, run hello +
beat, populate the gossip matrix and (after the group
reaches OPERATIONAL) hold a leader election. Watch this
unfold with the commands in
[Operation and Debugging](operation-and-debugging.md).

## 6. See Also

- [Architecture](multi-provider-architecture.md) — what
  each role does with the zone once it arrives.
- [Synchronization Model](synchronization-model.md) —
  how contributions and edits flow between agents and
  combiners.
- [Operation and Debugging](operation-and-debugging.md)
  — the day-2 CLI for watching the system run.
- [Making Data Changes](data-changes.md) — adding,
  removing and rolling records in a live zone.
- [The Auditor](auditor.md) — adding a fourth, passive
  party.
