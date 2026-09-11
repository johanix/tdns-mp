# mp-policy-matrix — the multi-provider policy matrix as a rig

Who may change the NS and DNSKEY RRsets of a customer zone, and where a
change ends up, across every combination of **1–3 providers × 1–2 signers ×
`nsmgmt=owner|agent`**. One deployment of three providers (agent + combiner
+ signer each), one auditor and one zone-owner server carries every cell of
the matrix at once: **one cell is one customer zone**, named after its
parameters (`p3s2a.rig.test.` = 3 providers, 2 signers, nsmgmt=agent).
Design and rationale: `docs/2026-09-10-mp-scenario-test-rigs-design.md`.

Everything runs on loopback under `/var/tmp/mp-policy-matrix`; no lab, no
public DNS, no key material in the repo.

## Running

```
sh setup.sh                  # seed $RIG: binaries, configs, zones, keys, certs
sh run.sh redirect --do      # ONCE per boot, needs sudo: 127.0.0.1:53 -> world server
sh run.sh start
sh run.sh converge           # every cell OPERATIONAL from every reporter (~1-2 min)
sh run.sh watch              # meanwhile, in another window: the gossip matrices, refreshed
sh run.sh verify             # one PASS/FAIL per assertion; non-zero exit on failure
sh run.sh stop               # removes the redirect too; or: clean (stop + remove $RIG)
```

`sh run.sh scenario static|ns|foreign|dnskey` runs one group.
`CELLS="p2s1a.rig.test. p3s2o.rig.test." sh setup.sh` seeds a subset.

Requirements: `python3`, `openssl`, `dig`, `nc`; the five mp binaries built
in `cmd/` of this checkout (`MP=` points elsewhere); `tdns-auth` built from
the tdns commit this checkout **pins** (`TDNS=`, default `../tdns.pinned`;
`setup.sh` refuses any other commit — the HSYNCPARAM wire keys changed in
tdns after the pin, and a world server from tdns tip would pack `servers=`
where the daemons unpack `nsmgmt=`).

### Why the redirect

The daemons discover each other through their embedded resolvers, which
reach the rig's names via a stub for `rig.test.` — and the pinned tdns dials
stubs, like root servers, on port 53 only. So `127.0.0.1:53` must reach the
world server, which runs unprivileged on 5300. `run.sh redirect` prints (or
with `--do` runs) the one-line packet redirect for macOS (`pfctl`, in the
rig's own anchor `com.apple/mp-policy-matrix` — the stock `/etc/pf.conf`
evaluates only `com.apple/*` anchors, so a rule loaded into any other
anchor is silently ignored) or Linux (`iptables`). It is the rig's
single privileged step; nothing runs as root. Without it everything starts
and every zone flows, but the agents never find each other (`status` says
so). A tdns with IMR forwarding — post-pin — removes the need.

The rig owns the redirect so it is not forgotten: `redirect --do` records
what it installed in `$RIG/.redirect` (on macOS also whether pf was
already enabled), **`stop` and `clean` remove it again** (one more sudo
prompt; `KEEP_REDIRECT=1 sh run.sh stop` keeps it for the next `start`),
`status` shows whether it is in place, `unredirect` removes it by hand, and
a reboot clears it regardless. The undo is `sudo pfctl -a com.apple/mp-policy-matrix
-F all` (Linux: the two rules with `-D`), and `unredirect` checks
afterwards that 127.0.0.1:53 no longer answers.

## What is where

| Piece | Port(s) | Role |
|---|---|---|
| world (`tdns-auth`) | 5300 DNS, 5301 API | zone owner for every cell; primary for `rig.test.`; secondary for the identity zones the agents auto-create |
| pN combiner / signer / agent | 8N55 / 8N53 / 8N54 DNS, 7N5x API | provider N. **What a provider serves is what its signer answers on 8N53**, as the testbed's signers answer on 53 |
| auditor | 8456 DNS, 7456 API | observer, identity `auditor.rig.test.`, in every cell's HSYNC3 and `auditors=` |

`tdns-mpcli --config $RIG/tdns-mpcli.yaml p2-agent zone mplist` — every
daemon is an instance word (`p1-agent` … `p3-signer`, `aud`); the built-in
words address p1 and the auditor. `export TDNS_MPCLI_CONFIG=$RIG/tdns-mpcli.yaml`
saves the `--config`.

## The cells

`cells.tsv` is the single source: `gen.py` derives the zone files, every
daemon's zone list, which signer a downstream provider pulls the signed
zone from (the `upstreams` column, which is also the HSYNC3 upstream the
zone declares — the two cannot disagree), and the expectations `verify.sh`
checks. Adding a cell is one line.

| zone | P | S | nsmgmt | providers | signers | pulls from |
|---|---|---|---|---|---|---|
| p1s1a / p1s1o | 1 | 1 | agent / owner | p1 | p1 | — |
| p2s1a / p2s1o | 2 | 1 | agent / owner | p1,p2 | p1 | p2←p1 |
| p2s2a / p2s2o | 2 | 2 | agent / owner | p1,p2 | p1,p2 | — |
| p3s1a / p3s1o | 3 | 1 | agent / owner | p1,p2,p3 | p1 | p2←p1, p3←p1 |
| p3s2a / p3s2o | 3 | 2 | agent / owner | p1,p2,p3 | p1,p2 | p3←p2 |
| p2s0a / p2s0o | 2 | 0 | agent / owner | p1,p2 | — | — (unsigned controls) |

## What verify asserts

- **A. static** — per cell and provider: `agent zone mplist` reports the
  servers/signers/nsmgmt of `cells.tsv` and no ERROR; the provider serves
  the zone; the NS RRset and the ordinary content are the owner's; signers
  serve a DNSKEY RRset and RRSIGs, a downstream provider serves exactly its
  upstream's DNSKEY RRset and RRSIGs, an unsigned cell has no DNSKEY; in a
  two-signer cell both signers serve the same DNSKEY RRset.
- **B. gossip** — every multi-provider cell OPERATIONAL from every provider
  and from the auditor.
- **C. NS add/delete** — `nsmgmt=agent`: each provider adds an NS under its
  own suffix, it is served by every provider of the cell (signers through
  their combiner, downstreams through the transfer), the SDE lists it, then
  the delete takes it away everywhere. `nsmgmt=owner`: the API refuses,
  naming nsmgmt, and the served NS RRset stays the owner's.
- **D. foreign NS** — deleting an NS another provider published is refused
  ("not owned by this agent"); adding an NS under another provider's suffix
  has no gate in the code today (design doc §10 F2): the rig asserts no
  provider serves it and stays red until a suffix rule exists.
- **E. DNSKEY gate** — a non-signer's `addrr DNSKEY` is refused at the API.

## Known reds and gaps

- D's foreign-NS add is expected red (see above).
- **A downstream provider serves the SOA without its RRSIG.** A
  tdns-mpsigner that is not a signer for a zone still bumps that zone's
  SOA serial (`v2/mp_signer.go`, "failed to bump SOA serial" is its error
  path) and cannot re-sign it, so the relayed copy carries every RRSIG
  the upstream signer made except the SOA's. The static assertion
  "downstream of pN serves pN's RRSIG over SOA" is red for every
  downstream provider until that is fixed in the daemon. Found on the
  rig's first run.
- Key rollover scenarios (design §4.3) are not in this rig yet.
- Propagation to a downstream provider is NOTIFY-driven only from the
  signing provider's signer (the rig configures those NOTIFYs); a change
  still takes one combiner→signer→agent hop per provider, so `OP_TIMEOUT`
  (default 120 s) is what the NS scenarios wait.
- Signature validity in the rig is 6 h everywhere: the daemon's floor is
  2 × (served TTL + propagation delay); the signer publishes DNSKEYs with
  a 1 h TTL and the auto-created identity zones carry a 1 h TTL (24 h
  before tdns's `mp-pin-2026-06` fix, which tdns-mp pins). A policy below
  the floor makes the daemon SERVFAIL the zone, not warn.
- Two log lines to ignore: the world server reports `bind: address already
  in use` for its API port once at start (tdns-auth starts its API
  dispatcher twice on the same address; the first wins), and every daemon
  logs a NOTIFY `connection refused` for peers that start after it.
