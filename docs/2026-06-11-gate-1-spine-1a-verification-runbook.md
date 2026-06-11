# Gate-1 — Spine-1a testbed verification runbook

Date: 2026-06-11
Status: EXECUTABLE procedure for the operator. Closes Gate-1 in
`2026-06-11-transport-redesign-consolidated-plan-v3.md`.

## What Spine-1a changed (the thing under test)

Commit `95c3cf6` ("A3d Spine-1a: route canonical State readers to
transport.Peer"). The operational-gating and gossip-state readers
now read the canonical `transport.Peer` store instead of
`AgentDetails`:

- `agent.EffectiveState()`        → `ar.effectiveAgentState(id)`
  (`agent_view.go:121`) — transport `EffectiveState()` +
  the MP LEGACY overlay.
- `agent.IsAnyTransportOperational()` → `ar.isAgentOperational(id)`
  (`agent_view.go:110`) — transport `EffectiveState() ==
  OPERATIONAL`, no LEGACY overlay.

~15 callers redirected (auditor_engine, gossip, hsyncengine ×9,
parentsync_leader ×3, start_agent ×2).

### What did NOT change (so it is INVARIANT by construction)

`peer list`'s State column still reads `AgentDetails.State`
(`apihandler_agent_distrib.go:358,420`) — the display redirect is
Spine-1b, not 1a. So the `peer list` State column is INVARIANT
**trivially** (it reads the exact same store as before). It is in
the probe set only as a cross-check that AgentDetails itself did not
drift.

### Why it should be INVARIANT on this fleet

`transport.Peer` is dual-written by the same handlers that write
`AgentDetails.State`, so `transport.Peer.EffectiveState()` tracks
the old `Agent.EffectiveState()`. On a **single-mechanism (DNS-only)
fleet** the two are byte-identical: `transport.EffectiveState()`
returns the best state across {API, DNS}, but with only "DNS"
present it returns that mechanism's state directly
(`tdns-transport peer.go:222`).

### The one latent difference (must stay dormant)

`transport.Peer.EffectiveState()` reconciles a MIXED API+DNS state
by min-value across mechanisms; the old per-mechanism Agent logic
did not. This differs ONLY for a peer that has BOTH mechanisms in
different states — which cannot occur on a DNS-only fleet. If the
testbed fleet is single-mechanism, any observed delta is a real
regression, not this latent difference. (Reconciled deliberately at
Stage D.)

## Deploy points

| Role | Commit | Note |
|---|---|---|
| Baseline (BEFORE) | `b15ba7b` | doc commit immediately preceding Spine-1a; last pre-1a runtime state |
| Tip (AFTER) | `af33c9a` | current `transport-redesign-v1-A` tip |

Everything between baseline and tip that touches runtime is Spine-1a
alone: the only post-1a `.go` change is `apihandler_keystore.go`
(the `list-algorithms` handler), which has zero relationship to
agent state / gossip / peer-list. So this is a clean 2-point
experiment isolating Spine-1a.

> Pre-req: confirm the fleet is DNS-only (no peer has an active API
> mechanism). If any peer is multi-mechanism, STOP — the INVARIANT
> assumption does not hold and the latent difference above is in
> play; that is a Stage-D conversation, not Gate-1.

## Procedure

For each of the N agents in the testbed, on a quiet fleet (no
in-flight rollovers / membership changes), capture the probe set,
then redeploy and recapture. Compare with `diff`.

### 1. Capture BASELINE (deploy `b15ba7b`)

Per agent, save to a per-host file:

```
tdns-mpcli <role> peer list            > base.<host>.peerlist
tdns-mpcli <role> gossip state -z ZONE > base.<host>.gossip   # each MP zone
tdns-mpcli <role> peer zones           > base.<host>.peerzones
```

Also exercise the operational-gated paths and record that they
behave (these have no stable text snapshot, so record outcome, not
bytes):

- trigger one **election cycle** in a provider group → the elected
  leader is the same identity as before.
- issue one **RFI** (`tdns-mpcli <role> ... rfi ...` as you normally
  do) to a peer → it is gated/sent exactly as before (operational
  peers reachable, non-operational refused).

### 2. Capture AFTER (deploy tip `af33c9a`)

Same commands, into `after.<host>.*`. Same quiet-fleet conditions,
same zones, same peers.

### 3. Compare — the pass/fail gate

```
diff base.<host>.gossip    after.<host>.gossip      # MUST be empty
diff base.<host>.peerlist  after.<host>.peerlist    # MUST be empty (State col esp.)
diff base.<host>.peerzones after.<host>.peerzones   # MUST be empty
```

INVARIANT pass criteria:

1. **`gossip state` matrix** — the per-peer State column is
   byte-identical. This is the PRIMARY gate: it is the column that
   now flows through `effectiveAgentState`. (Note: ignore volatile
   non-state fields if the matrix prints timestamps/sequence
   numbers — compare the State cells, or filter timestamps before
   diffing.)
2. **`peer list` State column** — byte-identical (trivially; reads
   AgentDetails). A diff here means AgentDetails drifted — unexpected
   and worth investigating even though it is not the 1a path.
3. **election** — same leader per group; no group flips
   OPERATIONAL↔DEGRADED across the deploy.
4. **RFI / send-gating** — same peers reachable; LEGACY peers (zero
   participations but established) still count operational for
   sending, exactly as before (`isAgentOperational` has no LEGACY
   overlay — that is intended).
5. **DEGRADED / INTERRUPTED** — displayed by NEITHER side, before
   and after (NG-only today; Stage D makes them visible). If either
   appears in `gossip state`/`peer list` now, that is a regression.

### 4. Spot-check the LEGACY overlay specifically

The one piece of NEW logic (vs. a pure store-swap) is the LEGACY
overlay in `effectiveAgentState` (`agent_view.go:130-133`): an
OPERATIONAL/INTRODUCED peer with zero participations shows LEGACY.
If the fleet has a LEGACY peer (a configured peer not in any shared
zone), confirm it still reads `LEGACY` in `gossip state` after the
deploy — same as before. This exercises the overlay path that the
commit reintroduced MP-side.

## Outcome

- **All five INVARIANT criteria hold** → Gate-1 PASS. Record the
  pass (date + commit pair) in the v3 plan's baseline table; A3d-S1b
  unblocks.
- **Any State-column diff, leader flip, or DEGRADED/INTERRUPTED
  surfacing** → Gate-1 FAIL → halts Stage A and reopens the A3d.0
  enum-mapping design, per the v3 plan. Capture the diff and the
  specific peer/zone; the likely suspects are (a) a handler that
  writes `AgentDetails.State` but not `transport.Peer` (dual-write
  gap) or (b) the LEGACY-overlay transition boundary.
