# One lost beat must not degrade a group

**Status:** implemented in tdns-mp PR #124 (branch `fix/123-beat-retry`), for issue #123, with Amendment 1 after its review. Run on the testbed 2026-10-11 (Amendment 2). Amendment 3, for issue #128, is implemented and not yet run on the testbed. The design text is not rewritten after review (dated amendments at the end).

## 1. What was wrong

Restarting one agent made every member of its provider groups lose mutual OPERATIONAL a few seconds after the agent was back, which invalidated the group's leader and ran a new election. On a three-agent test rig with a 10 s beat interval:

| Time | Event |
|---|---|
| T | one agent is stopped and started; the other two are left alone |
| T + 4 s, T + 5 s | each peer's regular beat to it fails ("connection refused"); their last successful beats were 10 s earlier |
| T + 5 s | the agent is up and logs "group reached mutual OPERATIONAL"; each peer processes its hello and sends no beat back |
| T + 14 s | each peer's next round: "group lost mutual OPERATIONAL" on all three; the same round's beat to the restarted agent succeeds |
| T + 16 s, T + 17 s | "group reached mutual OPERATIONAL" on all, new elections, a different leader in one group |

The causes:

- A mechanism reads DEGRADED when its last successful outbound beat is more than two beat intervals old.
- The rounds beat each peer once per interval. After a single failed beat, the next round comes two intervals after the last success.
- A round refreshes the gossip rows before it sends its beats. That round's refresh therefore read the threshold by milliseconds and wrote DEGRADED, moments before its own beat cleared it.
- Nothing beat the peer in between. A failed beat was not sent again before the next round, and the returning agent's hello found the peer's mechanism still OPERATIONAL from before the restart, so it moved nothing and brought no round forward.

`docs/2026-10-01-hsync-fast-convergence.md` expected, in its §6, no loss on the peers when one agent restarts. That holds only when no peer's beat falls inside the restart. A beat lost for any other reason has the same effect.

## 2. A failed beat is retried to that peer

A beat that fails is sent again to that peer alone (`beatRetrier` in `v2/hsync/beat_retry.go`): after the fast interval, then at doubling gaps, until one succeeds or the gap reaches the beat interval, where the rounds take over. With the defaults the gaps are 2, 4, 8 and 16 s, so the retries come 2, 6, 14 and 30 s after the failure.

- The retries are to one peer and do not touch the pace of the rounds.
- Only the first failure after a success starts them. A peer that stays down gets one episode and then the rounds' beats only, until a beat to it has succeeded again.
- A success from anywhere ends them: the retrier's own beat, or a round's.
- With the fixed pace (`beat_fast_interval` at or above `beatinterval`) there is no fast interval to retry at, and a failed beat waits for the next round as before.

In the case above, the beat that failed at T + 4 s is sent again at T + 6 s, to an agent that has been up for a second, and the peer's reading never leaves OPERATIONAL. A peer that is really down still reads DEGRADED two intervals after its last success: the retries fail too.

## 3. A peer that introduces itself again gets one beat back

A hello from a peer whose mechanism is already introduced means the peer restarted, or never got our accept. `routeHelloMessage` then has the engine beat that peer once, at once (`Engine.BeatPeer`).

It is one beat to one peer, not a kick of the rounds. A peer that repeats its hello every `helloretry` costs one beat for each, and the rounds keep their pace, which is what Amendment 1 of the convergence design is about. A hello that moves the mechanism to INTRODUCING still kicks the rounds, as before.

Either change alone covers the restart above. The retry also covers a beat lost with no restart. The beat back covers a restart of any length up to the peers' next round: the returning agent's hello is answered with a beat whenever it comes, where a retry has to fall after the agent is up.

## 4. The hello retrier's own beats

The beats the hello retrier sends after an accepted hello (`fastBeatAttempts`) have their own loop, three attempts 5 s apart, and start no beat retrier beside it.

## 5. On the testbed

1. Restart one agent, the others untouched: no "group lost mutual OPERATIONAL" on any agent, and no new election, when the agent is back within one beat interval of the beat that failed. An agent away longer than that has been unreachable for two intervals when its peers' next round comes, and reads DEGRADED.
2. On the peers: "beat failed" for the restarted agent, then a beat to it acknowledged within seconds, before their next round: a retry, or the beat back in the second its hello is processed.
3. Stop one agent and leave it down: its peers log "group lost mutual OPERATIONAL" two beat intervals after their last successful beat, as before.

## 6. Left out

- **The threshold.** Two intervals without a successful beat still reads DEGRADED. It lives in tdns-transport and defines what DEGRADED means.
- **The order within a round.** The rows are still refreshed before the round's beats. Refreshing after them would make every row one round older when it is gossiped.
- **What a brief loss does to the leader.** One loss of mutual OPERATIONAL still invalidates the group's leader at once.

## Amendments

### Amendment 1 (2026-10-11): after the review of PR #124

**One beat back at a time.** §3 gave every hello from an already-introduced peer a beat of its own. A peer whose hellos come faster than a beat returns, a beat that can wait ten seconds on a peer that does not answer, would have had several on their way at once. `BeatPeer` now does nothing while a beat it started to that peer has not returned.

**A retrier that ends picks up a new failure.** A beat could fail in the moment between a retrier's success and its exit. `noteBeatFailed` then saw a retrier still on the books and started none, though the failure opened a new outage, which then had no retries until a beat succeeded again. The retrier's exit (`endBeatRetrier`) now starts the retries when its own outage is over and the peer is failing again. A retrier that ran out of retries starts none, as before.

### Amendment 2 (2026-10-11): on the testbed

Run on a three-agent test rig with a 10 s beat interval, on top of the branch of PR #121. The build was this branch before the two changes of Amendment 1. Read against §5:

**Restarts.** Five restarts of a single agent, its peers left alone: four of a member that did not lead the group, and one of the group's leader inside its term. No agent logged "group lost mutual OPERATIONAL", and no restart cost the group its leader. Each time the restarted agent was back in mutual OPERATIONAL five seconds after the restart. Lease renewals that fell inside one restart's window ran as at any other time.

**The peers' beats.** In three of the restarts a peer's beat fell inside the restart and failed. A beat to the restarted agent was acknowledged one or two seconds after the failure, before that peer's next round.

**The beat back can come too early.** In one of those three the peer processed the returning agent's hello a second after its beat had failed, and beat the agent back at once. The agent was not yet taking beats and refused it. The retry of the failed beat, a second later, was acknowledged. §3 says that either change alone covers a restart: here the beat back alone would have left the peer waiting for its next round.

**An agent left down.** One agent was stopped and left down for a minute. Its peers logged "group lost mutual OPERATIONAL" 13 s after the stop, two beat intervals after their last acknowledged beat to it, as before.

### Amendment 3 (2026-10-12): a refused beat back is sent again

Amendment 2 saw a returning agent refuse the beat back, and the retry of the failed beat cover for it. That retry is not always there. A beat's retries come at doubling gaps, so the last stretch before the next round has none: with a 10 s beat interval they come 2 and 6 s after the failure and the round at 10 s; with the default 30 s, at 2, 6 and 14 s. A peer that is back in that stretch is covered by the beat back alone, and when it refuses that beat, the round reads it as DEGRADED (issue #128).

**A beat back that fails is sent again after the fast interval**, twice at most (`beatBackRetries`). The first retry covers the refusal that was seen, which lasted a second. The second is for a peer that needs longer than one fast interval. A peer that refuses three beats in a row is left to the rounds.

- One beat back per peer at a time, as before. While it waits to be sent again, further hellos from the peer start no second one.
- The beat back does not retry beside the beat retrier. A failed beat back that is the first failure since a success starts the retrier, whose first retry comes after the fast interval, and sends nothing more itself. With an outage already on the books it starts no retrier, and sends its own retries. A beat that succeeds in between, a round's or the retrier's, ends them.
- With the fixed pace there is no fast interval and no retry, as for a failed beat (§2).

Why a returning agent refuses a beat right after its own hello is not established. Closing that window would make the beat back dependable by itself.
