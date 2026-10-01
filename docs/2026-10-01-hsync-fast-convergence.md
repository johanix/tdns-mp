# Faster convergence of the hsync engine: adaptive beat rounds

**Status:** implemented on branch `feat/hsync-fast-convergence` (four commits, before this document). Not yet run on the testbed; §6 says how to judge it there. The design text is not rewritten after review (dated amendments at the end).

## 1. Where the time went

An agent's link to a peer goes NEEDED → KNOWN (discovery) → INTRODUCING (a hello in either direction) → OPERATIONAL (its own outbound beat round trip). The gossip matrix then needs every member's own row to show every other member OPERATIONAL before the group reaches mutual OPERATIONAL, which is what starts the group's election.

The links were already fast: discovery runs at zone load, the first hello leaves when the identity zone is published, and fast beats follow it. The matrix was not:

- An agent wrote its own row only in `BeforeHeartbeats`, on the engine's beat ticker, and `time.NewTicker` fires first one full interval after the start. Fast beats after a hello carried gossip, but no row had been written yet.
- So a group reached mutual OPERATIONAL at least one beat interval (30 s by default) after the start, however fast the links came up. On a three-agent test rig with a 10 s beat interval, every link was INTRODUCING within 3 s of the start and the group reached mutual OPERATIONAL after 12–14 s.
- A link's second direction could wait a whole interval for its first beat: when an agent discovered a peer after the peer's hello had arrived, its mechanism was already INTRODUCING, `attemptDiscovery` started no hello retrier, and only the ticker beat the peer.
- An accepted hello was followed by the first beat at the retrier's next attempt slot, `hello_fast_interval` (2 s) later, or `helloretry` (15 s) in the slow phase.
- In a two-member group the initiator finalized the election 5 s after its peer, on every start: the peer's CONFIRM, sent the moment it held both votes, was handled before the peer's VOTE, and the initiator's own confirm then completed the set where nothing checked for it, so the confirm timer finalized.

A cold start is a different matter: there the time goes to the DNS layer (published identities, cached denials and validation verdicts), and no engine timer changes it.

## 2. Beat rounds: fast while there is news, steady once there is none

The fixed ticker gives way to a `beatSchedule` (`hsync/beat_schedule.go`), after Trickle (RFC 6206):

- Rounds start at `BeatIntervalMin` (default 2 s) after the start, and each round that finds the engine's view of its peers as the previous one left it doubles the gap, up to `BeatInterval`: 2, 4, 8, 16, 30 s.
- A change starts the fast pace over. A round sees one in `peersView`: every peer that is not infrastructure with its mechanism states, decayed (so a decay counts), and the provider groups. Between rounds, the engine kicks itself (`kickBeats`) after a hello it sent changed the peer, on every inbound hello, and after a beat that changed the peer. A kick brings the next round to one fast interval after the last one at the earliest.
- The pace resets on changes, not on states: a peer that stays down does not hold the engine at 2 s; it backs off like everything else.
- The gap never exceeds `BeatInterval`. Liveness decay keys on that interval (DEGRADED after 2×, INTERRUPTED after 10× without a successful outbound beat), and so does the interval peers are told; neither changes.
- A round is what it was: `BeforeHeartbeats` (the host refreshes its gossip rows and checks the groups), then a beat to every peer past the hello.

A round costs one beat per peer. The fast phase after a change is about five rounds instead of one, so about four extra beats per peer per episode of change; the steady state is the same as before.

`BeatIntervalMin` is the new key `multi-provider.syncengine.intervals.beat_fast_interval`, in seconds. Zero or absent means the default; a value at or above `beatinterval` gives the fixed pace, first round included, as before.

## 3. The first gossip row waits for good news

The old first-round delay also did something useful: after a restart, an agent's links were usually up again by its first round, so its peers never saw its half-built row (KNOWN cells), and the group never lost mutual OPERATIONAL. With the first round 2 s after the start, that row would show, and each restart would degrade the group, invalidate its leader (`InvalidateGroupLeader`) and re-elect a moment later.

So until one beat interval after the engine starts, an agent writes the first row of each group only once every other member is OPERATIONAL from here (`GossipStateTable.HoldFirstLocalRows`, `refreshLocalRow`). Good news goes out at once; news of a member that is not up yet goes out no sooner than before. A row written once is refreshed every round. The hold counts the rows this process wrote, not rows in the table: after a restart, an agent hears its own old row in its peers' gossip. The agent and the auditor start the hold where they start the engine.

## 4. The smaller fixes

- **Hello → beat:** the hello retrier checks the peer's state right after each hello it sends and goes to the fast beats at once (`hsync/hello.go`).
- **Election:** `determineAndConfirmGroup` and `determineAndConfirm` finalize after broadcasting their confirm when the set is complete, and arm the confirm timer only when it is not. Finalization is once per term: `finalizeGroupElection` and `finalizeElection` return unless the election is still active in that term. Before, the last confirm and the confirm timer could each finalize the same term and run `onLeaderElected` twice.

## 5. What was considered and not done

- **A shorter steady beat interval.** It shortens the wait without removing it, multiplies steady-state traffic by the same factor, and makes the decay thresholds that key on it quicker to fire.
- **An exponential hello backoff.** The retrier is already fast then slow, and once a hello in either direction is accepted both sides are INTRODUCING and the hello is off the critical path.
- **Gossip relaying.** A group is a full mesh; every row reaches every member from its owner in one hop.
- **Answering a message from a sender whose key is missing with an error instead of dropping it** (tdns-transport). The sender would learn of it at once instead of after its 5 s send timeout, but its three fast hello attempts would then be spent within 4 s instead of 14 s, which is often shorter than the receiver's discovery of the sender takes. Not clearly a gain.

## 6. Judging it on the testbed

On the multi-provider test rig, warm start, against a build with `beat_fast_interval` set to `beatinterval` (the old behaviour):

1. Engine start to "group reached mutual OPERATIONAL" on every agent: expected a few seconds, against about one beat interval before.
2. Election: the initiator's "group leader elected" in the same second as its peer's.
3. Restart one agent: no "group lost mutual OPERATIONAL" on its peers.
4. Steady state: rounds one beat interval apart once nothing changes (the debug log of `RefreshLocalStates`), and no peer DEGRADED that was not before.

## Amendments

None yet.
