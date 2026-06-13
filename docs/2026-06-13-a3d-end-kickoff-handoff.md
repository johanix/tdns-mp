# A3d-END kickoff / handoff note

Date: 2026-06-13
Author: prior session (context handoff)
Status: ORIENTATION for the next agent picking up A3d-END. NOT a
new design — the binding spec is the v3 plan's "A3d-END" section
(`2026-06-11-transport-redesign-consolidated-plan-v3.md` lines ~448-509)
plus the addendum §3 type-merge design. This note saves you the
code-map rediscovery and flags the traps, with line numbers verified
2026-06-13 at tip tdns-mp `d8b1af6`, tdns-transport `892e5de`.

## Where we are (read these first, in order)

1. `2026-06-11-transport-redesign-consolidated-plan-v3.md` — AUTHORITATIVE.
   Read: "Verified baseline" table, A3d-S2/S3/S4 (DONE), **A3d-END**,
   "Gate-1" section (records the truth-model bugs + last night's three
   fixes), "Cross-stage rules" (lock order — BINDING).
2. `2026-06-01-a3d-field-ownership.md` §1-5 — the binding A3d design
   (acceptance test, target types, lock order). §3 = the type-merge END.1
   targets.
3. MEMORY.md index line for the one-paragraph current state.

S1b, S2, S3, S4 are DONE and **testbed-confirmed 2026-06-13**. Build:
`cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make` (5 bins). Tests from
`tdns-mp/v2`: `GOROOT=/opt/local/lib/go go test ./... -count=1 -race`.
Testbed: `ssh -A root@mptest92.axfr.net -p 5101`, agent log
`/var/log/tdns/tdns-mpagent.log`, fleet zone `espresso.mp.axfr.net`
(agents cpt/fox/hare + auditor.skrubb; combiner/signer = cpt infra).

## The ONE big idea END.0 must deliver

`transport.Peer` becomes the SOLE per-peer State store. Today there are
still THREE state stores (the redesign's whole point is to collapse them):
- (1) `transport.Peer.Mechanisms[m].State` — per-mechanism, decayed. CANONICAL target.
- (2) `transport.Peer.State` — top-level; `EffectiveState()` falls back to it.
- (3) `agent.{Dns,Api}Details.State` (AgentState enum) — the MP sidecar END.0 RETIRES.

**Read side is already done** (S1b): display + gossip already read
`transport.Peer` via `effectiveAgentState`→`peer.EffectiveState()`
(`agent_view.go:122`) and `transportToAgentState` (`agent_view.go:~76`).
**END.0 closes the WRITE side**: stop writing store (3); make the
beat/hello send gates and state transitions read/write store (1)/(2).

### *** ROOT CAUSE of last night's 3 bugs — fix it properly HERE ***

All three testbed bugs (KNOWN/NEEDED `44f06bd`, ERROR-clobber `0bb1d5d`,
+ the convergence-window gossip-vs-peerlist diff) share ONE root:
`EffectiveState()` falls back to top-level `peer.State` (store 2), and
various paths write `peer.State` UNCONDITIONALLY (KNOWN at discovery,
ERROR on discovery-fail). The tactical fixes guard those writes. **The
real fix is END.0: make `peer.State` DERIVED from the per-mechanism
states, not independently written.** When you do END.0, revisit:
- `OnPeerDiscovered` (`hsync_transport.go:~446`) — the guarded KNOWN write.
- `OnDiscoveryFailed` (`hsync_transport.go:~505`) — the guarded ERROR write.
- `RegisterDiscoveredAgent` (`agent_discovery.go:~178` removed; KNOWN now
  set in the apiUsable/dnsUsable blocks).
If `peer.State` becomes a derived read (best-of-mechanisms + a discovery
phase marker), these unconditional-write hazards disappear structurally
and the guards can be simplified/removed. THIS is the prize of END.0
beyond just "retire store 3."

## END.0 code census (verified 2026-06-13, tip d8b1af6)

48 functional `{Dns,Api}Details.State` sites + 9 `LastState`, across:

| File | State refs | What they are |
|---|---|---|
| `hsync_transport.go` | 19 | **THE CORE** — send gates + transitions (see below) |
| `agent_discovery.go` | 6 | discovery → KNOWN writes (store 3); pair with store-1 writes |
| `apihandler_agent_distrib.go` | 2 | display reads (peer list) — already mostly transport; verify |
| `apihandler_peer.go` | 2 | `peer reset` → NEEDED writes |
| `parentsync_leader.go` | 2 | **election readiness reads** — must read transport state |
| `hsync_infra_beat.go` | 2 | infra-beat readiness gate |
| `agent_utils.go` | 1 | `RecomputeSharedZonesAndSyncState` LEGACY/OP flip (`:67-74`) — RETIRE per END.0 |
| `hsync/discovery.go` | 6 | **hsync.PeerDetails.State — DIFFERENT STORE, Stage D, DO NOT TOUCH** |
| `hsync/types.go` | 4 | hsync.PeerDetails struct — Stage D, DO NOT TOUCH |
| `hsync/hello.go` | 4 | hsync stub — pass-2 M4 says do NOT wire inbound hello to it |

### The load-bearing send gates in hsync_transport.go (verified lines)
- `SendHelloWithFallback` (`:1491`): API gate reads `ApiDetails.State == AgentStateKnown` (`:1508`); writes INTRODUCED (`:1523-1524`); DNS gate `:1536`; writes `:1551-1552`. Return readiness reads `:1572/:1575`.
- `SendBeatWithFallback` (`:1600`): API send-gate reads the 5-state OR (`:1629`); writes OPERATIONAL (`:1643`); DNS `:1668`/`:1684`. Fix A already moved the OPERATIONAL writes onto `transport.Peer` via `peer.SetMechanismState(...,Operational)` + `SetMechanismLastBeatSent` — confirm those stay and the AgentDetails twin write is what you delete.
- Inbound hello state writes: `:667-668`, `:690`.

These gates currently READ store (3). END.0 makes them read store (1)
via a decayed/raw mechanism-state accessor. `transport.Peer` already
has: `MechanismRawState(name)` (non-decayed, added S4),
`MechanismEffectiveState(name)` (decayed), `SetMechanismState`,
`GetState`, `SetState`. You likely need a small helper to map the
"is this mechanism in {OPERATIONAL,INTRODUCED,LEGACY,DEGRADED,
INTERRUPTED}" send-gate predicate onto mechanism state.

## TRAPS (each of these cost the prior sessions real time)

1. **Two same-named State stores.** `AgentDetails.State` (this package,
   END.0) vs `hsync.PeerDetails.State` (hsync subpackage, Stage D).
   The `hsync/*` files in the census are the WRONG store. Do NOT touch
   them in END.0. `hsync/beat.go:checkPeerState` decay stays until D.
2. **AgentState enum ≠ transport.PeerState enum.** AgentState has LEGACY
   (no transport equivalent — it's the MP overlay, `effectiveAgentState`
   applies it) and lacks DISCOVERING. Use `transportToAgentState` /
   the existing mapping; don't invent a new one (the old
   `agentStateToTransportState[Fn]` were deleted in S4 on purpose —
   the read direction `transportToAgentState` is the survivor).
3. **AgentDetails is also the WIRE DTO** (S3 item 4 deferral).
   `GetZoneAgentData` (`agent_utils.go:~294`) serializes the live `Agent`
   (incl. `*AgentDetails`) to the CLI `peer status` line
   (`cli/hsync_cmds.go:558-560`), which reads `SentBeats/LatestSBeat/
   LatestRBeat` client-side (no transport.Peer there). **END.0 must feed
   that DTO from transport.Peer** before END.1/A5 can delete the fields,
   else the CLI heartbeat line breaks. Pairs with the State DTO question.
4. **Lock order is BINDING** (cross-stage rule): `AgentRegistry.mu` →
   peer mutex → `transport.PeerRegistry` → `transport.Peer`. NEVER hold a
   registry/peer mutex across a transport call. Single-writer per peer
   field. `-race` every sub-step. END.1 collapses `Agent.Mu` →
   `hsync.Peer.Mu` (ONE mutex) — until then mind the two.
5. **Don't wire inbound hello to `hsync/hello.go`** (pass-2 M4) — it's a
   stub; END.3 routes inbound hello via `routeHelloMessage`.

## Sub-step order (each = own commit, green + -race + INVARIANT)

- **END.0** State functional-merge (above) + the DTO-from-transport feed.
  **Load-bearing — its own commit + testbed checkpoint before END.1.**
  This is where the `peer.State`-derived fix for last night's bug root lands.
- **END.1** type-merge (addendum §3): `Agent` embeds `*hsync.Peer`;
  dedupe Identity/PeerID→`hsync.Peer.ID`; `Agent.Mu`→`hsync.Peer.Mu`;
  `Zones`→`hsync.Peer.Zones`; `DeferredTasks`→`hsync.Peer.Deferred`.
- **END.2** delete the dual map (`AgentRegistry.S`/`mu` shadowing
  `hsync.Registry.S`, `agent_structs.go:~206-214`).
- **END.3** collapse inbound pipeline (one writer per msg type;
  `routeBeatMessage` + `HeartbeatHandler` + engine converge).
- **END.4** delete `hsync.Registry.RemoteAgents` (`hsync/registry.go:17`).
- **END.5** `staticcheck U1000` dead-code sweep.

**After END.0: deploy + testbed-confirm** (the post-embed checkpoint).
Operator wants to be in the loop between sub-steps — do NOT run END.0→
END.5 unattended.

## Verification recipe (use every sub-step)
1. `cd tdns-mp/cmd && GOROOT=/opt/local/lib/go make` (5 bins) +
   transport standalone build + `cmd/transport-exercise` build.
2. `go test ./... -count=1 -race` from tdns-mp/v2 (boundary + hsync).
3. Operator deploys; runtime probes `gossip state -z espresso.mp.axfr.net`
   + `peer list` must stay byte-comparable on a healthy fleet (INVARIANT),
   matrix fully OPERATIONAL after convergence.

## Workflow rules that bit prior sessions (from MEMORY.md)
- Never touch `tdns/tdns/` (v1) or `tdns/obe/`,`tdns/music/` (frozen).
- `gofmt -w <file>` after every .go edit; never hand-fix indentation.
- Build before commit. `-race` on every A-step.
- A recommendation is NOT approval — wait for the operator's decision
  before commit/push on a posed choice.
- Commit+push to the feature branch is fine; no amend, no Co-Authored-By,
  never push to main / merge alone.
- Use `git -C <repo>` (project dir is not a git repo).
- Don't remove U1000-unused code without asking (END.5 is the exception,
  and it's a reviewed commit).
