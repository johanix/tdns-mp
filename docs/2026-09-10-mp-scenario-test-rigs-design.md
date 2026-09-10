# Multi-provider scenario test rigs — matrix and rig design

Date: 2026-09-10
Status: DESIGN. No rig code exists yet; §9 is the build order.
Scope: the policy behaviour of a running provider group — who may
change the NS and DNSKEY RRsets of a customer zone, and where a change
ends up — across the permutations of provider count, signer count and
`nsmgmt=`. Parent-side delegation sync, SIG(0) bootstrap and config
reload are out of scope here (they are §7–§11 of
`2026-03-30-mp-regression-test-plan.md`, which stays the checklist for
those).

Related: `2026-03-30-mp-regression-test-plan.md` (the hand-run
checklist this mechanises for NS/DNSKEY), `guide/synchronization-model.md`
§5 (the dynamic options), `guide/mp-change-tracking-semantics.md`
(ACCEPTED vs REJECTED vs not-forwarded), and the rig conventions in
the tdns repo's `tests/README.md`, which these rigs follow.

## 1. Why rigs, and where they live

Every scenario below has so far been exercised by hand on the testbed.
That is good confirmation and very slow, and it is redone per change.
A rig is a committed harness — configs, zones, a `setup.sh` that seeds
a work tree, a `run.sh` that starts everything and prints one PASS/FAIL
per assertion — so that a milestone can be checked in minutes, by
anyone, unattended.

The rigs go in **`tdns-mp/tests/<rigname>/`**, mirroring `tdns/tests/`.
tdns-mp is public, so the rigs are fully self-contained: private test
names (`rig.test.`), loopback addresses, no lab hosts, no key material
(`setup.sh` mints it).

Conventions inherited from `tdns/tests/README.md`:

- fixed work root `/var/tmp/<rigname>/`; committed configs name
  absolute paths under it;
- no key material in the repo; per-issuance values are `@PLACEHOLDER@`
  substituted at seed time;
- `run.sh verify` prints one PASS/FAIL per assertion, exits non-zero on
  any failure;
- **negative cases are part of the rig** — a rig that only shows things
  working cannot tell whether the gate is switched on;
- binary paths overridable by environment.

Two lessons paid for on the first lab rig (2026-08-31) are rules here:
`start` refuses to run while any rig port is held or any prior rig
daemon is alive (a stale daemon once made 24 cases report *its*
behaviour), and "process up but no listener" is a verdict of its own,
never folded into a timeout.

## 2. What is under test — the gates as implemented

The matrix only makes sense against what the code actually enforces.
Verified in the v1-C branch on 2026-09-10 (file:function):

| Gate | Where | Decides | Inputs |
|---|---|---|---|
| `canSubmit` | agent, `combiner_chunk.go` (called from the `add-rr`/`del-rr` API) | may this agent put an RRtype into the network at all | NS: `nsmgmt=agent`; DNSKEY: we are a signer; KEY: `parentsync=agent`; CDS/CSYNC: signer ∧ `parentsync=agent` |
| local-delete ownership | agent, `agent_policy.go` `ValidateUpdate` case "local" | a ClassNONE delete must name an RR this agent itself contributed | agent's own repo for the zone; `--force` bypasses it |
| `canApply` | combiner, `combiner_chunk.go` | does *this* combiner publish the contribution in its served zone | zone signed?, we sign?, `nsmgmt`, `parentsync`. A non-signing combiner on a signed zone applies nothing; contributions are persisted ("ignored"), not rejected |
| `checkDNSKEYPolicy` | combiner, only when it would apply | is the DNSKEY sender's HSYNC3 label in `signers=` | HSYNC3 (identity→label), HSYNCPARAM `signers=` |
| `checkNSNamespacePolicy` | combiner, every NS op, every sender | NS target under any configured `protected-namespaces` suffix is rejected | combiner config only — **sender-agnostic** (see §10) |
| `OptMPDisallowEdits` | agent | a non-signer on a signed zone stores peer data in its SDE and answers ACCEPTED, but does not forward to its combiner | derived from HSYNCPARAM at zone load |
| KEYSTATE gating | signer, `key_state_worker.go` | new key `mpdist`→`published` only after every peer confirmed; retired key `retired`→`mpremove`→`removed` likewise | agent "propagated" signals |
| HSYNC3 `upstream` | agent, `hsyncengine.go` CONFIG RFI | a downstream provider learns its upstream's outgoing-XFR config (`xfr_srcs`/`xfr_auth`) and hands its own incoming-XFR config back | HSYNC3 upstream label, `multi-provider.xfr` blocks |

Two things the matrix must NOT assume, because the code does not do
them: HSYNCPARAM `suffix=` is decoded and displayed (auditor `mplist`)
but enforced nowhere; and there is no "this NS belongs to provider X"
notion anywhere — attribution is per *origin agent*, not per NS name.
§10 says what the rig does about that.

## 3. Parameters and the cell matrix

Three parameters, from the request:

- **P** providers: 1, 2, 3.
- **S** signers: 1 or 2 (S ≤ P). Every non-signing provider pulls the
  signed zone from a signing provider: its HSYNC3 `upstream` names a
  signer, and its serving nameserver is a secondary of that signer.
- **nsmgmt**: `owner` or `agent`.

That is 10 cells. Two unsigned controls (S=0) are added because the
DNSKEY rules have an explicit "unsigned zone" branch (`canApply` refuses
DNSKEY outright) that should be seen to fire. `parentsync=owner` in
every cell; parent sync is a later axis (§9, phase 4).

**One cell is one customer zone.** All cells run at once in a single
deployment of three providers plus one auditor; the cell decides which
providers list the zone and with which roles. This is how the testbed
already works (espresso, espressino, macchiato … differ only in their
HSYNC3/HSYNCPARAM), so the rig exercises the real code path for
"one agent, many zones with different policies".

Labels are `p1`, `p2`, `p3` (identities `agent.pN.rig.test.`), auditor
label `aud` (`auditor.rig.test.`). `p1` always signs. In S=2 cells `p2`
also signs. Non-signers pull from `p1`, except in the P=3/S=2 cells
where `p3` pulls from `p2`, so that "downstream of the *second* signer"
is exercised too.

| Zone | P | S | nsmgmt | HSYNC3 rows (label, upstream) | HSYNCPARAM |
|---|---|---|---|---|---|
| `p1s1a.rig.test.` | 1 | 1 | agent | p1 . | `servers="p1" signers="p1" nsmgmt="agent" parentsync="owner" auditors="aud"` |
| `p1s1o.rig.test.` | 1 | 1 | owner | p1 . | same, `nsmgmt="owner"` |
| `p2s1a.rig.test.` | 2 | 1 | agent | p1 . ; p2 p1 | `servers="p1,p2" signers="p1" …agent` |
| `p2s1o.rig.test.` | 2 | 1 | owner | p1 . ; p2 p1 | `servers="p1,p2" signers="p1" …owner` |
| `p2s2a.rig.test.` | 2 | 2 | agent | p1 . ; p2 . | `servers="p1,p2" signers="p1,p2" …agent` |
| `p2s2o.rig.test.` | 2 | 2 | owner | p1 . ; p2 . | `servers="p1,p2" signers="p1,p2" …owner` |
| `p3s1a.rig.test.` | 3 | 1 | agent | p1 . ; p2 p1 ; p3 p1 | `servers="p1,p2,p3" signers="p1" …agent` |
| `p3s1o.rig.test.` | 3 | 1 | owner | p1 . ; p2 p1 ; p3 p1 | `servers="p1,p2,p3" signers="p1" …owner` |
| `p3s2a.rig.test.` | 3 | 2 | agent | p1 . ; p2 . ; p3 p2 | `servers="p1,p2,p3" signers="p1,p2" …agent` |
| `p3s2o.rig.test.` | 3 | 2 | owner | p1 . ; p2 . ; p3 p2 | `servers="p1,p2,p3" signers="p1,p2" …owner` |
| `p2s0a.rig.test.` | 2 | 0 | agent | p1 . ; p2 . | `servers="p1,p2" nsmgmt="agent" …` (control) |
| `p2s0o.rig.test.` | 2 | 0 | owner | p1 . ; p2 . | `servers="p1,p2" nsmgmt="owner" …` (control) |

Every zone also carries one HSYNC3 row for the auditor
(`aud auditor.rig.test. .`), apex NS records for each serving
provider's nameserver, and a few ordinary records so that "the rest of
the zone passes through unchanged" is asserted too.

Derived per (zone, provider), and asserted as a static invariant before
any operation runs. The observation point is `tdns-mpcli agent zone
mplist` on each provider: one row per zone with Servers, Signers,
Auditors, NSmgmt, ParentSync, Suffix and the derived Options, i.e. the
daemon's own decoding of HSYNC3/HSYNCPARAM and what it concluded from
it. The served zones show the effect:

| Provider role in the cell | `OptAllowEdits` | `OptMPDisallowEdits` | `OptInlineSigning` | `OptMultiSigner` | serves |
|---|---|---|---|---|---|
| signer, S=1 | true | false | true | false | own signed output |
| signer, S=2 | true | false | true | true | own signed output; DNSKEY RRset is the union |
| non-signer, S≥1 | false | true | false | false | upstream signer's zone, verbatim (same RRSIGs) |
| provider, S=0 | true | false | false | false | own combiner output, unsigned |

The testbed already covers five of these cells with its live zones
(P3/S2/agent, P3/S1/agent, P2/S2/agent, P2/S2/owner, P3/S2/owner, the
last two with `nsmgmt=owner`), which is what phase 4's fleet mode will
run the same assertions against. Its `mplist` output also shows two
zones in ERROR (owner unreachable / undeclared) — the rig's converge
step treats an ERROR row as a failed invariant, not as background.

## 4. Operations and expected outcomes

The scenario per cell is a fixed script of operations. Each row names
the operation, who runs it, what must happen, and where the rig looks.
"All providers" means every provider listed for the zone; "served"
means the DNS answer from each provider's public-facing nameserver.

### 4.1 NS operations (nsmgmt = agent)

| Op | Actor | Expected | Observed at |
|---|---|---|---|
| NS-ADD-OWN | each agent | API accepts. SDE at every peer gets the RR attributed to the actor; origin SDE goes PENDING→ACCEPTED for every peer. Every *signing* combiner applies it. Served NS RRset at every provider grows by exactly this RR (signers via their combiner; downstream providers via XFR from upstream). Auditor's view lists it. | `agent zone edits list` (origin + peers), `combiner zone edits list` (signers), `dig NS` at every provider, `auditor zones` |
| NS-DEL-OWN | same agent | Reverse of the above; served RRsets return to the pre-op set. | same |
| NS-ADD-FOREIGN | agent pN adds an NS whose target is inside another provider's namespace | Must not end up in any served NS RRset. (Where the gate lives today is a finding, §10: the API accepts it; a combiner rejects only if configured. The rig asserts the *served* outcome and reports the gate that fired.) | `dig NS` everywhere, `combiner zone edits list --rejected`, origin SDE state REJECTED |
| NS-DEL-FOREIGN | agent pN deletes an NS another agent contributed | API refuses ("RR not owned by this agent"); nothing changes anywhere. | CLI exit status + message, `dig NS` everywhere |
| NS-DEL-SHARED | two agents contribute the same NS RR; one deletes | Only that origin's contribution goes; served RRset still contains the RR (the other origin still contributes it). Guards against "delete removes the last copy". | `combiner zone edits list` per origin, `dig NS` |
| NS-ADD-NONAPEX | agent adds an NS with an owner below the apex | API refuses (apex-only rule). | CLI |

### 4.2 NS operations (nsmgmt = owner)

| Op | Actor | Expected | Observed at |
|---|---|---|---|
| NS-ADD-OWN / NS-DEL-OWN / NS-ADD-FOREIGN | each agent | API refuses with the nsmgmt message; **served NS RRset at every provider is byte-identical to the owner's**, before and after. | CLI, `dig NS` everywhere vs the owner server |
| NS-OWNER-CHANGE | zone owner edits its NS RRset and bumps the serial | Every provider's served NS RRset follows the owner (through combiner → signer → downstream). Confirms the owner path is what publishes NS in this mode. | `dig NS` everywhere after refresh |

### 4.3 DNSKEY operations

| Op | Actor | Expected | Observed at |
|---|---|---|---|
| KEY-GEN | a signer generates a standby ZSK (`signer keystore dnssec generate`) | Key appears as `mpdist`; KEYSTATE goes to the local agent; the DNSKEY reaches every peer SDE attributed to the signer's agent; every other *signing* combiner has it as a contribution and its served DNSKEY RRset contains it; downstream providers serve it via XFR; the key then transitions `mpdist`→`published` and only then. In S=1 cells the transition still requires the non-signing peers' confirmation. | `signer keystore dnssec list`, `agent zone edits list`, `combiner zone edits list`, `dig +dnssec DNSKEY` everywhere |
| KEY-ROLL-ZSK | same signer, `rollover --keytype ZSK` | Standby→active, active→retired; new signatures validate at every provider against the union DNSKEY RRset; after the rig's short propagation delay the retired key goes `mpremove` and, once every peer confirmed, `removed`; it disappears from every served DNSKEY RRset. | as above, plus `dig +dnssec` RRSIG key tags |
| KEY-ROLL-KSK | same signer, `--keytype KSK` | As ZSK, plus the combiner detects a KSK change (a CDS would be published if `parentsync=agent`; here it must **not** be, `parentsync=owner`). | `dig CDS` everywhere must be empty |
| KEY-ADD-NONSIGNER | a non-signing agent runs `addrr` with a DNSKEY | API refuses (`canSubmit`). Nothing propagates. | CLI, `dig DNSKEY` everywhere unchanged |
| KEY-ADD-UNSIGNED | any agent in a S=0 zone adds a DNSKEY | API refuses (no signers → not a signer). Control for the unsigned branch. | CLI |
| KEY-CONVERGE-S2 | both signers in an S=2 cell generate keys | Each signer's served DNSKEY RRset is the union of both keystores; each signer's RRSIGs are made with its own keys only; both sets validate. | `dig +dnssec DNSKEY` at both signers, key tags |

### 4.4 Policy flips (dynamic; phase 4)

The static matrix says what each policy does. These say what happens
when the owner changes policy under live contributions — the cases
most likely to leave stale data behind.

| Op | Change by the owner | Expected |
|---|---|---|
| FLIP-NSMGMT | `nsmgmt=agent` → `owner` on a zone with agent-contributed NS | On the next zone load every combiner stops applying NS contributions (persisted, not applied); served NS RRset reverts to the owner's. Flip back: contributions are applied again without re-submission. |
| FLIP-SIGNERS | remove p2 from `signers=` in an S=2 cell | p2's DNSKEY contributions are no longer applied by p1's combiner; p1's served DNSKEY RRset shrinks to its own keys; p2 becomes a non-signer (options flip) and stops signing; p2 now needs an upstream (a second edit adds it). |
| FLIP-ADD-PROVIDER | add p3 to a P=2 cell | Discovery, hello, gossip OPERATIONAL, SDE hydration by pull-resync; p3 serves the zone within one refresh. |

## 5. Rig architecture

Single host, one deployment, every cell at once. Nothing outside
`/var/tmp/mp-policy-matrix/` is read or written; no public DNS; no
port below 1024.

### 5.1 Processes

| Process | Role | DNS | API | Notes |
|---|---|---|---|---|
| `tdns-auth` "world" | zone owner for all 12 cells **and** the stand-in for the public DNS: primary for `rig.test.`, secondary for the four identity zones | 127.0.0.1:5300 | 5301 | the only server every IMR is pointed at |
| p1 combiner / signer / agent | provider 1 (always a signer) | 8155 / 8153 / 8154 | 7155 / 7153 / 7154 | |
| p2 combiner / signer / agent | provider 2 | 8255 / 8253 / 8254 | 7255 / 7253 / 7254 | signer signs S=2 cells, relays otherwise |
| p3 combiner / signer / agent | provider 3 | 8355 / 8353 / 8354 | 7355 / 7353 / 7354 | never a signer in this matrix |
| auditor | observer, identity `auditor.rig.test.` | 8456 | 7456 | listed in every cell's HSYNC3 + `auditors=` |

Eleven processes (nine provider daemons, the auditor, the world server). Each daemon is addressed by an instance name — `p1-agent` …
`p3-signer`, `aud` — from ONE `tdns-mpcli.yaml`, once tdns-mpcli has
the multi-instance trees tdns-ncli already has
(`2026-09-10-mpcli-multi-instance-assessment.md`); until then `lib.sh`
wraps `tdns-mpcli --config $RIG/<provider>/tdns-mpcli.yaml` behind the
same names, so nothing in this document changes when the wrapper goes.

### 5.2 Identity discovery without public DNS

The agents discover each other through their embedded IMR: URI at
`_dns._tcp.<identity>`, SVCB and JWK at `dns.<identity>`, served from
the identity zone the agent auto-creates and signs on start. On the
testbed those zones are delegated in public DNS and slaved by public
secondaries. The rig reproduces that shape on loopback:

- each agent lists `local.nameservers: [ world.rig.test. ]` and
  `local.notify: [ 127.0.0.1:5300 ]`, so the auto zone's NS points at
  the world server and the world server is NOTIFYed on every change;
- the world server is configured as secondary for
  `agent.p{1,2,3}.rig.test.` and `auditor.rig.test.` with
  `primary: 127.0.0.1:<agent dns port>`, and `rig.test.` delegates each
  of them to `world.rig.test.`;
- every IMR (agents, auditor) is configured with
  `imrengine.forward: [{ zone: rig.test., upstreams: [{ addr: 127.0.0.1, port: 5300, transport: do53 }] }]`
  and `imrengine.require-dnssec-validation: false` (hyphens; the key is
  a pointer bool defaulting to true, read in `imrengine.go`). In the
  transport that flag gates only the TLSA lookup of the API mechanism;
  the DNS-mechanism lookups (URI, SVCB, JWK) do not check the
  validation state at all, so with `supported_mechanisms: [ dns ]` the
  rig would work even without it. It is set anyway so the rig does not
  depend on that asymmetry.

The forward path exists so that a port can be given (root hints and
stubs cannot carry one, which would force port 53), and it stamps
forwarded answers Insecure, which the relaxed validation setting
accepts. This is a deliberate reduction: what the rig tests is MP
policy, not discovery security. A **validated-discovery variant** is
phase 4 work: fake root + trust anchor, DS records for the auto zones
inserted after first start. Until then the rig README says so.

### 5.3 Zone data flow per provider

```
world:5300 ──AXFR/NOTIFY──▶ combiner:8x55 ──▶ signer:8x53 ──▶ agent:8x54 (KEYSTATE, NOTIFY)
                                  ▲                │
                     UPDATE/RFI ──┘                └──XFR──▶ downstream provider's signer (relay)
```

Signing providers: combiner pulls the owner zone, merges contributions,
signer signs. Non-signing providers: the signer is configured as a
secondary of its **upstream provider's signer** for that zone (the
HSYNC3 upstream), with `dnssecpolicy` unset so it relays. The rig
writes those `primary:` lines from the cell table, so a mismatch
between the HSYNC3 upstream and the transfer topology is impossible by
construction. Phase 4 adds the case where the downstream instead
learns the XFR source over the CONFIG RFI.

### 5.4 Binaries

- `tdns-mpagent`, `tdns-mpcombiner`, `tdns-mpsigner`, `tdns-mpauditor`,
  `tdns-mpcli` from the tdns-mp checkout under test (`MP=` env).
- `tdns-auth` and `tdns-cli` **built from the tdns commit tdns-mp
  pins** (`TDNS=` env, default a checkout at that commit). This is not
  a nicety: HSYNCPARAM key numbers changed on the wire in tdns on
  2026-09-03 (§10, F1). A world server built from tdns tip would pack
  `servers=` where the pinned mp daemons unpack `nsmgmt=`. `dog` is
  not needed: the daemons' own decoding is what `agent zone mplist`
  prints, and that is what the rig reads.

`setup.sh` prints both versions and refuses to seed if the tdns commit
differs from the one in `cmd/*/go.mod`.

### 5.5 Timing knobs (rig values, not defaults)

| Knob | Default | Rig | Why |
|---|---|---|---|
| `syncengine.intervals.beatinterval` | 30 | 10 | convergence in ~1 min |
| `helloretry`, `discoveryretry` | 15 | 5 | |
| `kasp.propagation_delay` | 1h | 60s | `published`→`standby`, `retired`→`mpremove` inside a test run |
| `kasp.check_interval` | 1m | 10s | |
| zone SOA refresh | zone file | 30s | downstream relays follow within a minute; NOTIFY does most of it |
| `service.maxrefresh` | 1800 | 30 | clamps refresh |

## 6. Files

```
tests/mp-policy-matrix/
  README.md                     what it is, how to run, the cell table, known reds
  setup.sh                      seed $RIG: keys, certs, configs, zones
  run.sh                        start | stop | status | converge | verify | scenario <name> | clean
  lib.sh                        assertion primitives, wait_until, port/pid preflight
  cells.tsv                     the matrix (zone, P, S, nsmgmt, roles, upstreams) — single source
  zones/                        rig.test. and one owner zone per cell, generated from cells.tsv by gen-zones.sh
  world/tdns-auth.yaml
  p1/ p2/ p3/                   tdns-mpagent.yaml tdns-mpcombiner.yaml tdns-mpsigner.yaml tdns-mpcli.yaml
  auditor/tdns-mpauditor.yaml tdns-mpcli.yaml
  gen-zones.sh                  cells.tsv → zones/*.zone and the per-provider zone lists
```

`cells.tsv` is the single source of truth: zone files, each daemon's
`zones:` list, each non-signer's `primary:` line and the verify
expectations are all derived from it. Adding a cell is one line.

Committed configs use `@APIKEY_P1_AGENT@`-style placeholders for API
keys (minted at seed time, 32 random bytes) and absolute paths under
`$RIG` for JOSE keys, TLS certs and databases. JOSE keys come from
`tdns-mpcli keys generate --jose`, TLS certs from `tdns-cli cert ca` +
`cert leaf` (as the XoT rig does) with the identity as CN — the agent
checks the CN against its identity when the API transport is on; the
rig runs DNS transport only (`supported_mechanisms: [ dns ]`, as the
testbed), so the API cert is only for the management API.

`run.sh scenario <name>` runs one scenario from §4 against every cell
it applies to; `verify` runs converge, the static invariants, then all
scenarios in dependency order (NS before DNSKEY, flips last), and
prints the PASS/FAIL tally. A `--cell <zone>` filter limits the run.

## 7. Assertion primitives

All in `lib.sh`, all producing exactly one `PASS`/`FAIL` line with the
cell and the observation, never a bare timeout:

- `served_rrset <provider> <zone> <type>` — normalised RRset from the
  provider's serving port (`dig +norec`, lower-cased, sorted, TTL
  stripped); `assert_served_eq`, `assert_served_has`,
  `assert_served_lacks`, `assert_served_same_everywhere`.
- `validates <provider> <zone> <type>` — `dig +dnssec` and check that
  every RRSIG key tag is present in the served DNSKEY RRset (a
  self-consistency check, enough to catch "signed with a key nobody
  publishes"); phase 4 upgrades this to real validation through a
  rig `tdns-imr` with the fake-root trust anchor.
- `sde_state <provider> <zone> <rr>` → PENDING/ACCEPTED/REJECTED per
  peer, parsed from `agent zone edits list`.
- `combiner_has <provider> <zone> <origin> <rr>` and
  `combiner_rejected <provider> <zone> <rr>` (with the reason) from
  `combiner zone edits list [--rejected]`.
- `keystate <provider> <zone> <keyid>` from `signer keystore dnssec list`.
- `mplist_row <provider> <zone>` — the Servers/Signers/Auditors/NSmgmt/
  ParentSync/Suffix/Options columns of `agent zone mplist`, compared
  field by field against the cell's row in `cells.tsv`; an ERROR row
  is a FAIL with the row printed.
- `gossip_operational <zone>` — every listed provider's matrix cell
  OPERATIONAL from every reporter, from `agent gossip state`.
- `wait_until <secs> <cmd>` — polls every 2 s; on expiry prints the
  last observation, not just "timeout".

The CLI output is text tables today. Parsing them is the fragile part
of this design; a `--json` flag on `agent zone edits list`,
`combiner zone edits list`, `signer keystore dnssec list` and
`agent gossip state` is a small change and the first thing to add once
phase 0 is green, after which `lib.sh` reads JSON.

## 8. Preflight, convergence, teardown

`start`: refuse if any of the 25 rig ports is held (`lsof`), or any
process matches `--config $RIG/`; then start world, wait for the SOA
of every owner zone on :5300, start combiners, signers, agents,
auditor in that order (each waits for its API to answer `ping`).

`converge`: wait until every cell's gossip matrix is OPERATIONAL,
every provider's `agent zones` shows the expected options for every
cell, and every provider serves every cell at the owner's serial or
higher. Budget: 180 s on a laptop; the observed order on the testbed
is discovery ≈ 10 s, hello ≈ 15 s, first beat ≤ 1 interval.

`stop`: `tdns-mpcli <role> stop` per daemon, then kill anything left
that matches the rig path. `clean`: `stop` + `rm -rf $RIG`.

## 9. Build order

| Phase | Deliverable | Green means |
|---|---|---|
| 0 | skeleton: `cells.tsv` with `p2s1a` only, world + p1 + p2 + auditor, `start/stop/status/converge`, NS-ADD-OWN/NS-DEL-OWN on one cell | discovery over the forward path works on loopback; a change made at p1 is served by p2 via the relay |
| 1 | the full `cells.tsv`, `gen-zones.sh`, static invariants (§3 options table, served zones, gossip) for all 12 cells | one deployment carries all cells; every provider's role per cell is what HSYNCPARAM says |
| 2 | §4.1 and §4.2 for every cell | the NS policy matrix, with its negative cases |
| 3 | §4.3 for every signed cell, rig timing knobs | DNSKEY propagation and the KEYSTATE gating end to end |
| 4 | §4.4 flips; CONFIG-RFI upstream variant; validated discovery (fake root + DS); `parentsync=agent` axis; `--json` in the CLI; a "fleet mode" where `lib.sh` endpoints point at the testbed instead of loopback (endpoints only, no lab names in the repo) | |

Phase 0 is the risky one (loopback discovery). Everything after it is
mostly table-driven.

## 10. Findings made while designing, and expected reds

The rig encodes the intended behaviour. Where the code today differs,
the rig will be red on purpose; these are the places, with the
decision each needs.

**F1 — HSYNCPARAM wire keys changed in tdns on 2026-09-03**
(`3be08497`, "fix the HSYNCPARAM key numbers to match the draft").
Pinned core (`v0.0.0-20260611…`): 0 nsmgmt, 1 parentsync, 2 servers,
3 signers, 4 pubkey, 5 pubcds, 6 suffix, 7 auditors. tdns tip: 0
servers, 1 signers, 2 auditors, 3 nsmgmt, 4 parentsync, 5 suffix, 6
pubkey, 7 pubcds. The testbed's owner server and every mp daemon
agree today (both old), and `agent zone mplist` on every provider
shows the intended values. The re-pin (F0, separate project) is
therefore a **flag day for every customer zone**: the owner's
tdns-auth and all providers' daemons must cross together, or
`servers=` is read as `nsmgmt=`. The rig pins its tdns build to the mp
pin for exactly this reason, and the F0 plan needs a step for it. The
check that catches a mismatch is already in the rig: `mplist_row` on
every provider against `cells.tsv`.

**F2 — `suffix=` is not enforced.** HSYNCPARAM `suffix=` ("label under
which providers may add NS+glue") is parsed and shown by the auditor
and used by nothing. The only NS-target rule is the combiner's
`protected-namespaces`, which is sender-agnostic: a combiner listing
its own suffix would reject its **own** agent's NS under that suffix,
so on the testbed nobody configures it (cpt has none). Consequently
NS-ADD-FOREIGN in §4.1 has no gate today: the intruding NS is applied
by the intruder's own combiner and appears in its served zone, while
the other providers may (if configured) reject it — a cross-provider
NS divergence. Decision needed on the rule the combiner should
enforce: (a) NS target must be under `<label>.<suffix>.<zone>` for the
sender's own HSYNC3 label, or (b) NS target must be under a namespace
the sender's provider declares (identity parent), or (c) leave it to
`protected-namespaces` but make it sender-aware. The rig's NS naming is
a parameter (`NS_PATTERN` in `cells.tsv`, default `ns<N>.<label>.rig.test.`,
which is what the testbed does) so it can assert whichever is chosen.

**F3 — two combiner-side gates are unreachable from the CLI.** The
`nsmgmt=owner` `canApply(NS)` refusal and the `checkDNSKEYPolicy`
signer check both sit behind agent-side `canSubmit`, which refuses
first (and `--force` does not bypass it). The rig covers them through
the owner path (§4.2 NS-OWNER-CHANGE) and the flips (§4.4), which
exercise "contribution exists, policy no longer allows it". Direct
coverage needs a rogue sender — a small `tests/tools/mp-rogue` that
signs and sends one SYNC/UPDATE with a real JOSE key — listed for
phase 4, not assumed.

**F4 — the live testbed would fail cell `p3s2a` today.** From here,
fox serves `espresso.mp.axfr.net` with a DNSKEY RRset and RRSIGs; hare
answers the DNSKEY query with an empty, authoritative answer (its
signer is not signing the zone — consistent with the "unknown
algorithm: 0" in its log noted on 2026-09-09); cpt relays an unsigned
copy on its signer port. That is exactly the invariant of §3's last
table, and it is red on the fleet now. Not a rig problem; recorded
because it is the first thing the rig would have said.

**F5 — CLI output is text only.** No `--json` on the mplist, edit,
keystore or gossip listings. Phase 0 parses text; the `--json` flag is
the first follow-up (§7).

## 11. Relation to the 2026-03-30 regression test plan

That plan is a hand checklist across 13 sections. This rig mechanises
its §2 (NS sync), §3 (DNSKEY sync), §4 (rollover) and §5.3 (non-signer
rejection) for every cell of the matrix rather than for the two-provider
Alpha/Bravo lab, and adds the negative cases and the policy flips the
checklist lacks. §1 (discovery/beat/gossip) becomes the rig's
`converge`. §6 (resync), §7–§9 (parent sync, SIG(0)), §10–§11 (reload,
recovery) and §13 (tdns-vs-mp comparison, now moot) are not covered
here.

## 12. Open decisions (non-blocking; defaults stated)

1. NS naming rule for "own suffix" — F2 above. Default until decided:
   provider-domain pattern, no combiner-side enforcement expected, the
   FOREIGN case asserts only the served outcome and prints which gate
   fired.
2. Unsigned controls (S=0): keep the two cells (default) or drop them.
3. Where phase 4's "fleet mode" endpoints live: an untracked
   `fleet.env` under `$RIG` (default), never in the repo.
