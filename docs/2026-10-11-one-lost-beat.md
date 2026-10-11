# One lost beat must not degrade a group

**Status:** implemented on branch `fix/123-beat-retry`, for issue #123. Not yet run on the testbed; §5 says what to look for there. The design text is not rewritten after review (dated amendments at the end).

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

None yet.
