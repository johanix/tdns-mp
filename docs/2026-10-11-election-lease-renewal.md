# Leader lease renewal: one election, not a burst

**Status:** implemented on branch `fix/120-election-renewal`, for issue #120. Not yet run on the testbed; §5 says what to look for there. The design text is not rewritten after review (dated amendments at the end).

## 1. What was wrong

A group's leader holds a lease of `leader-election-ttl` (60 min by default), renewed at 90% of it. At every renewal the group ran one election that failed and then two or three that succeeded, all within about six seconds:

| Time | Each member |
|---|---|
| T | "group leader TTL expiring", starts its own election for term N |
| T + 5 s | "group election aborted: not all members voted" (one vote of three) |
| T + 6 s | the first member's retry: term N+1, the others join, a leader is elected |
| T + 6 s | the second member's retry: term N+2, joined, elected |
| T + 6 s | the third member's retry: term N+3, joined, elected |

Each term draws new random votes, so the leader could change from one term to the next, and `onLeaderElected` ran for each term's winner: members that led for milliseconds started their leader duties (the SIG(0) key request, the delegation sync).

The causes, in `v2/parentsync_leader.go`:

- `finalizeGroupElection` armed the renewal timer on every member, leader or not, at the same delay. All members finalize in the same instant, so the timers fired together.
- `StartGroupElection` always increments the term, whether or not an election is running or a newer term has just been elected.
- `handleGroupCall` ignores a CALL for a term the member is already active in, so members that start the same term at the same time never join each other.
- The retry timers (after a vote timeout, a confirm timeout, or no consensus) called `StartGroupElection` unconditionally, so a retry ran even when another member's retry had already produced a leader.

A two-member group used to renew in one term, by accident: its initiator finalized 5 s after its peer, so its timer was behind and was re-armed by the peer's renewal before it fired. PR #117 removed that 5 s wait, and two-member groups then collided like larger ones.

## 2. Rule 1: a timer acts only on the term it was armed for

The renewal timer and the three retry timers remember the term at arming. When one fires and the election's term has moved on, or an election is running, it starts nothing: another member got there first. `startGroupElection(..., armed)` holds the check under the election's lock; `StartGroupElection`, for the first election and the API, passes no term and starts as before.

With this rule alone a collision still costs the 5 s abort, but only the first retry elects: the others find the term moved on.

## 3. Rule 2: the leader renews first

The leader renews at 90% of the lease. Every other member arms a fallback one step later for each member before it, in the order of their identities (`renewalDelay`). A step is the lease's last tenth divided by the number of members plus two, at most 10 s, so that the last fallback still fires while there is a leader. With the default lease and three members: the leader at 54:00, the others at 54:10 and 54:20.

The fallback is for a leader with no timer or a lost renewal. A leader that restarts inside its term learns from gossip that it leads, and arms no renewal timer; the next member in line then renews. In the normal case the leader's renewal reaches every member long before its fallback, which rule 1 then turns into nothing.

A group that has lost mutual OPERATIONAL has no renewal to run: `InvalidateGroupLeader` stops the timer, and the election starts over when the group is operational again.

## 4. The per-zone election

The per-zone election (zones that no provider group covers) gets both rules. It does not know its members by identity, so every member that is not the leader waits one step: the leader renews first, and a fallback that finds the term renewed starts nothing. Its no-consensus retry acts only on its term.

## 5. On the testbed

At a lease renewal, on every agent of a group:

1. One "group leader TTL expiring, triggering re-election" line, on the leader only.
2. No "group election aborted" line.
3. One "group leader elected" line, for one new term.
4. The term grows by one per renewal.

A short `leader-election-ttl` on the agents shows several renewals in one run.

## 6. Left out

- **New votes at every renewal.** A renewal still draws random votes, so the leader can change every 54 minutes though the old one is alive. Whether a living leader should keep the lead is a separate decision.
- **A tie-break for two CALLs of the same term.** Two fallbacks firing together, or a restart at the wrong moment, can still collide and cost the 5 s abort; rule 1 then gives one elected term.

## 7. Also fixed

`handleGroupCall` read the vote map for its log line after releasing the election's lock, while a vote could be written: a data race, found by the test that runs several managers through a real election.

## Amendments

None yet.
