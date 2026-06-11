# Peer state & discovery truth — diagnosis and complete fix proposal

Date: 2026-06-11
Status: PROPOSAL (diagnosis testbed-confirmed; fix not yet implemented).
Context: surfaced while verifying Gate-1 (Spine-1a) on the testbed.
A peer (`agent.fox`) displayed OPERATIONAL with an address in
`peer list` and `gossip state`, while every send to it failed with
`no address available` / `all transports failed`.

## TL;DR

Four linked bugs. The first three are the **same disease**: a partial
or wrong "success" signal is recorded as full success and **never
retracted** when the underlying fact stops being true. The fourth
(discovery probing transports the local agent doesn't support)
pollutes the very signal the others need.

1. **OPERATIONAL set by the wrong trigger.** Per the long-standing
   definition, OPERATIONAL means *"I sent a BEAT and got a working
   response"* — an OUTBOUND round-trip. But on `transport.Peer`
   (the store the redesign's readers now use), OPERATIONAL is set by
   **inbound** message receipt (beat/hello/ping *received*). Inbound
   receipt proves the *other* direction (they can reach me), not
   that I can reach them.
2. **Demotion lives in a store nobody operational reads.** The only
   DEGRADED/INTERRUPTED demotion is the NG beat-age scanner writing
   `hsync.PeerDetails` (`hsync/beat.go:133-135`). The correct
   OUTBOUND promotion writes only `AgentDetails`
   (`SendBeatWithFallback`, `hsync_transport.go:1725`). Neither
   touches `transport.Peer`. So the canonical store has promotion
   (wrong trigger) but no demotion at all.
3. **Partial discovery registered as success; address never
   cleared.** Discovery does two lookups at two names: the URI at
   `<identity>` and the IP/SVCB at `dns.<identity>`. When the IP
   lookup fails (NXDOMAIN), `result.Partial` is set but **ignored**
   (`agent_discovery.go:384`: warn-and-continue). Registration then
   writes `BaseUri` + state KNOWN + ContactInfo "complete" but
   **skips the transport address** (no resolved IP,
   `agent_discovery.go:229`). `BaseUri` is never cleared
   (`mergeAgentDetails` is fill-if-empty). Net: `peer list` shows a
   URL string that the send path has no IP for.
4. **Discovery probes transports the local agent doesn't support.**
   `DiscoverAgent` (`agent_discovery.go:148-149`) calls BOTH
   `DiscoverAgentAPI` and `DiscoverAgentDNS` unconditionally, ignoring
   the local `supported_mechanisms` config. On a DNS-only fleet
   (today: API transport is unimplemented, every agent/auditor is
   `supported_mechanisms: [ dns ]`) the API leg ALWAYS fails — there
   are no `_https._tcp.<id> URI` records to find — which (a) spams
   `IterativeDNSQuery failed ... _https._tcp.<id> URI` for every peer,
   and (b) sets `result.Partial = true` on EVERY discovery. So the
   `Partial` flag bug #3 wants to act on is permanently true for a
   spurious reason, and cannot be used as-is. The agreed rule is:
   **an agent only discovers connectivity for transports it itself
   supports.** Discovery violates it.

Spine-1a did not *cause* these — it **exposed** them by redirecting
the state/gossip readers from `AgentDetails` (fed by the correct
outbound signal) to `transport.Peer` (fed by the wrong inbound one).

## The state machine, as it should be (the definition)

OPERATIONAL is reached only by a successful outbound BEAT round-trip.
Everything before a working response is one of:
NEEDED → KNOWN → INTRODUCED → OPERATIONAL, with DEGRADED / INTERRUPTED
as the decay states once a peer that WAS operational stops responding
to our beats, and ERROR for an outbound attempt that failed outright.

Crucially this is a statement about the OUTBOUND direction only ("can
I reach them"). "They can reach me" (inbound beats arriving) is the
*other* axis and must not drive this state.

## The four stores (why nothing agrees)

| Store | OPERATIONAL set by | Demoted by | Read by (post-Spine-1a) |
|---|---|---|---|
| `AgentDetails` | outbound beat success (CORRECT) — `hsync_transport.go:1725` | nothing (failure only logs `LatestError`) | `peer list` only (until Spine-1b) |
| `transport.Peer` | inbound receipt (WRONG) — `hsync_transport.go:707-709`, `:810-812`, combiner/signer msg handlers | nothing | gossip matrix + `EffectiveState` + send-gating |
| `hsync.PeerDetails` (NG) | — | beat-age scanner (`hsync/beat.go:133-135`) — the only demotion in the system | NG `checkPeerState` (Stage D) |
| `AgentDetails.State` (display) | (= AgentDetails above) | — | `peer list` State column |

The complete, correct state machine (send beat → on success promote,
on age/failure demote) exists **only in the NG Engine tick**
(`hsync/beat.go:42-55`: `sendBeatToPeer` then `checkPeerState`) and
writes **only `hsync.PeerDetails`** — a store the canonical readers
do not consult. `transport.Peer` has half a machine (wrong promotion,
no demotion).

## Evidence (testbed, 2026-06-11)

- `agent.fox` shows `dns://dns.agent.fox.mp.axfr.net.:8054/` +
  OPERATIONAL in `peer list`; `gossip state` shows it OPERATIONAL in
  every cell; `peer ping --id agent.fox` → "all transports failed";
  logs spam `no address available` on every confirm.
- Root: `dns.agent.fox.mp.axfr.net` returns NXDOMAIN (a stale NS in
  fox's delegation), so the IP/SVCB lookup fails while the URI lookup
  (at `agent.fox.mp.axfr.net`, served correctly) succeeds.
- Fleet is heterogeneous across the relevant boundary: fox =
  `main 9fe8202` (2026-05-17, pre-redesign), hare =
  `peer-discovery-engine-extraction 5c41aa4` (2026-05-28, pre-Spine-1a),
  cpt = `transport-redesign-v1-A` tip. Only cpt reads state from
  `transport.Peer`, which is why only cpt's view exposes the bug.

## The complete fix

Single principle, applied in three places: **`transport.Peer` is the
one store, and its connection state is driven exclusively by the
outbound BEAT round-trip — promote on response, decay on
age/failure — and never asserted from inbound receipt or from a
discovery that did not yield a usable address.**

### Fix A — OPERATIONAL only on outbound beat success

- Move the OPERATIONAL promotion to the outbound beat path. On a
  successful `DNSTransport.Beat`/`APITransport.Beat` round-trip
  (`SendBeatWithFallback`, `hsync_transport.go:1683/1711`), set
  `transport.Peer` `Mechanisms[m].State = OPERATIONAL` (today it
  writes only `AgentDetails`).
- Remove the inbound-receipt OPERATIONAL writes on `transport.Peer`:
  `hsync_transport.go:707-709, 810-812, 869, 893`;
  `combiner_msg_handler.go:72-88`; `signer_msg_handler.go:57-73`.
  Inbound receipt may update *liveness evidence* for the inbound
  axis (LastBeatRecv) and may promote NEEDED→KNOWN (we now know they
  exist), but must NOT assert OPERATIONAL.
- Decide the inbound-axis representation (see "Open question 1"):
  either a separate inbound-liveness field on `transport.Peer`, or
  accept that the matrix's inbound axis is the *peer's own* gossiped
  self-view (which it already is — see Fix D).

### Fix B — outbound failure/age demotes on `transport.Peer`

- On outbound beat failure or `Ack=false` (`hsync_transport.go:1685,
  1713`), demote `transport.Peer` `Mechanisms[m]`: → ERROR on a hard
  send failure (no address / transport error), and let the age-based
  rule produce DEGRADED/INTERRUPTED.
- Bring the beat-age decay (today `hsync/beat.go:133-135` on
  `hsync.PeerDetails`) onto `transport.Peer`, driven by
  `LastBeatSent`/`LastBeatRecv` already tracked there
  (`SetMechanismLastBeatRecv` exists; add LastBeatSent on the send
  path). This is the Stage-D "transport-owned liveness" work pulled
  forward because the bug forces it. Thresholds unchanged
  (2×/10× interval).
- This makes `EffectiveState()` honest: a peer we cannot beat decays
  out of OPERATIONAL within 2× its interval, instead of being held
  OPERATIONAL forever by inbound beats.

### Fix C — discovery must not register success without an address

> Depends on **Fix E**: until the spurious API-leg `Partial` is gone,
> `result.Partial` cannot be used as a failure signal (it is always
> true on a DNS-only fleet). Either gate on the specific condition
> (a *supported* mechanism resolved a URI but no address) rather than
> the blanket `Partial` flag, or land E first.

- Treat a partial discovery that lacks a usable transport address as
  NOT operational-eligible. Concretely: when `DNSAddresses` is empty
  (IP/SVCB lookup failed) for a supported mechanism, do not set
  ContactInfo "complete" for DNS (`agent_discovery.go:325`) and do
  not advance state to KNOWN on that mechanism; keep it NEEDED so the
  retrier keeps trying.
- Stop displaying a URL we cannot use: either clear
  `DnsDetails.BaseUri` when a re-discovery yields no address, or
  (better, end-state) make `peer list` read the transport address
  (`transport.Peer.CurrentAddress()`) — this is the Spine-2 address
  display redirect, also pulled forward by the bug.
- Keep retrying the failing leg: a partial result must leave the
  peer in a state the discovery retrier will revisit (NEEDED), not a
  terminal-looking KNOWN/"complete".
- Consider surfacing `Partial`/NXDOMAIN reachability faults so the
  operator sees "fox: address unresolved (dns.<id> NXDOMAIN)"
  instead of a misleading OPERATIONAL.

### Fix D — the gossip matrix asymmetry (the original symptom)

The matrix exists to show both directions (reporter → peer). With
A+B+C, each reporter's row becomes its *measured outbound* state per
peer (OPERATIONAL only if it can beat them), so:
- `cpt → fox` correctly shows ERROR/DEGRADED (cpt cannot reach fox).
- `fox → cpt` shows whatever fox reports about cpt (fox's own
  outbound view, gossiped) — the other axis, naturally.

No separate matrix change is needed if A+B+C land: the cells already
come from each reporter's `effectiveAgentState`, which becomes
truthful once the underlying state is. (If we want cpt's row to also
reflect "fox can reach me," that is a deliberate addition — Open
question 1 — not required to fix the lie.)

### Fix E — discovery only probes locally-supported transports

- In `DiscoverAgent` (`agent_discovery.go:148-149`), gate the two
  legs on the local `supported_mechanisms`: call `DiscoverAgentAPI`
  only if API is supported, `DiscoverAgentDNS` only if DNS is. The
  gate already exists as `tm.isTransportSupported(name)`
  (`hsync_bridge.go:100`, used by the beat send path); discovery
  just doesn't consult it. Note `DiscoverAgent` is a method on `Imr`
  and has no direct view of `supported_mechanisms` — thread the
  supported set in (a param, or a small predicate) rather than
  reaching for a global.
- Effect: a DNS-only agent stops emitting `_https._tcp.<id> URI`
  lookups entirely (kills the log spam) and stops setting the
  spurious `Partial`, so `Partial` becomes a meaningful signal again
  (true only when a *supported* transport's records are incomplete) —
  which is what Fix C needs.
- Land E first (or together with C): it is small, removes noise, and
  unblocks C's use of `Partial`.

## Relationship to the redesign plan

- This is **not** a Gate-1 failure of Spine-1a's *redirect*. The
  redirect is mechanically correct; it exposed a pre-existing
  state-machine that was always wrong but hidden behind the
  AgentDetails store. Gate-1's INVARIANT assumed the two stores
  agreed; they do not, because they implement different (and both
  incomplete) machines.
- Fix B is **Stage D** ("transport-owned liveness") and Fix C's
  display redirect is **Spine-2**, both pulled earlier because the
  bug makes the canonical store unusable until they land. This is a
  re-sequencing, not new scope — the target design already calls for
  transport.Peer to own liveness and address.
- Recommend sequencing: **E → C → A → B** as a focused "make
  transport.Peer's connection state truthful" change BEFORE
  continuing the A3d slice sequence (E first to clean the signal and
  kill noise; C to stop registering address-less peers; A/B to fix
  the state machine). Every remaining A3d slice stacks on
  `transport.Peer` being the trustworthy single source. Then re-run
  Gate-1 against a homogeneous (all-tip) fleet.

## Open questions

1. **Inbound axis representation.** Do we add an explicit
   inbound-liveness field on `transport.Peer` (so a single node can
   display "they reach me / I reach them" without gossip), or rely
   on the gossip matrix's cross-rows for the inbound direction? The
   matrix already carries it; a local field is a convenience, not a
   correctness need.
2. **Homogeneous re-test.** fox (25 days old) and hare (14 days old)
   predate the readers under test. Before declaring Gate-1, upgrade
   the fleet to the tip so all nodes use the same state machine —
   otherwise we are comparing new readers against old writers.

   **Test-fleet plan (decided 2026-06-11):**
   - **cpt stays the observer** on `transport-redesign-v1-A` tip —
     it is where the fixes land and where they are verified. The
     bugs live on the *observing* agent's discovery + state path, so
     the observer's version is what matters; fox's version does not
     change cpt's logic.
   - **Upgrade fox to the tip.** fox's value to the test is its
     broken `dns.agent.fox` NS (the trigger), not its old software.
     Upgrading gives fox `agent zone bump`, turning it into a
     *controllable* trigger: (1) first use `zone bump` to FIX the
     stale NS and establish a clean all-healthy baseline; (2) then
     deliberately re-break it to reproduce the failure on demand and
     verify each fix (E→C→A→B), including the RECOVERY direction
     (NS restored → cpt heals fox back to OPERATIONAL), which the
     current accidental break cannot test.
   - **Heterogeneity is tested deliberately, not via fox.** Interop
     coverage wants a pinned, known-version, *otherwise-healthy*
     node — not an accidentally-broken one. hare
     (`peer-discovery-engine-extraction`, 14 days, healthy) already
     provides one old-but-working node; add a purpose-pinned node if
     more interop signal is wanted later.
3. **Fox's NXDOMAIN itself** is an operational data problem (stale
   `dns.agent.fox` NS in the delegation) — fixable with the new
   `agent zone bump` once it deploys. Independent of the code fix,
   but it is the trigger that exposed all three bugs and a useful
   permanent test case.
