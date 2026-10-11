# Leader lease renewal: one election, not a burst

**Status:** implemented in tdns-mp PR #121 (branch `fix/120-election-renewal`), for issue #120. Run on the testbed 2026-10-11 (Amendment 1) and reviewed (Amendment 2). Amendments 3 and 4, for issues #125 and #129, are implemented in PR #126 and were run on the testbed (Amendment 5), and so was the change of Amendment 6 (Amendment 7). The design text is not rewritten after review (dated amendments at the end).

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

### Amendment 1 (2026-10-11): on the testbed

Run on a three-agent test rig with a 5-minute `leader-election-ttl`: the leader renews 4 min 30 s into the lease, and the fallbacks follow 6 s apart. There were two runs, the first with this branch alone and the second with PR #124 (issue #123) on top.

**Renewals.** Two in each run, read on every agent against §5:

- one "group leader TTL expiring, triggering re-election" line per renewal, on the member that led;
- no "group election aborted" line;
- one "group leader elected" line per agent, for the same new term on all three;
- the term up by one per renewal.

The leader changed at the renewals, which §6 leaves as it is.

**The fallback.** In the second run the leader was restarted 36 s into its term. Back up, it showed itself as the leader of the same term, and it logged no renewal of its own. Six seconds after its renewal time the next member in line logged the "TTL expiring" line, once. The election that member called gave the next term on all three agents in the same second, with no abort.

In the first run the same restart cost the group its mutual OPERATIONAL (issue #123), and with it the leader. The group elected anew when it was back, so there was no lease left for a fallback to renew.

### Amendment 2 (2026-10-11): after the review of PR #121

The review asked for no change. It noted that the per-zone renewal was tested at its guard only, not through its timers.

**The per-zone renewal through its timers.** `v2/parentsync_leader_zone_renewal_test.go` runs a zone's managers, two and three of them, through a renewal: one call, and it is the leader's. With the leader's timer gone in a zone of two, the other member calls, once. With every member at the leader's delay the first of these fails, three runs in four: both members call.

**Two more log lines.** As in §7 for the group, the per-zone `handleCall` and `handleConfirm` read the election's term for a debug line after releasing its lock. The new test found it under `-race`, and the values are now taken under the lock.

**Not changed: a member that has only ever joined.** A per-zone member counts the votes and the confirms against the number of peers it gave its own last call. One that joins a call before it has called an election itself counts against none: it can settle on the first confirm it receives without confirming itself, and the caller then waits out the confirm timeout. Every member calls the zone's election once its peers are operational, so this is a matter of the moments after a start. It is older than this branch and is left for a change of its own.

### Amendment 3 (2026-10-11): a vote that overtakes the call (issue #125)

The test that runs several managers through an election showed one more way an election waits out the 5 s timeout, older than the renewal collision and not removed by §2 or §3. In a group of three or more, another member's VOTE can reach a member before the initiator's CALL does: the two come from different senders, and nothing orders them. `handleGroupVote` dropped a vote for a term the member had not joined; the member then joined on the CALL with one vote short, never held every vote, and confirmed nothing.

A member now keeps a vote for a term newer than the one it is in (`keepEarlyVote`), the newest such term only and one vote per sender, and counts it when it joins that term on the CALL (`takeEarlyVotes`). A member that starts a term of its own forgets what it kept for it. The per-zone election does the same.

A CONFIRM needs no such care: a member confirms only once it holds every vote, the late member's among them, and that member votes when it joins.

This is implemented in PR #126 (branch `fix/125-early-votes`).

### Amendment 4 (2026-10-11): a member that joins counts against the zone's peers (issue #129)

Amendment 2 named this and left it. The review of the early-vote change showed it on that change's new path: a per-zone member that had never called an election, joining with one vote kept from before the CALL, held two votes against a count of no peers, and the join settled the election.

The per-zone `handleCall` now sets the count from the zone's configured peers when it joins, as a call of one's own does, and as the group's join does from its member list. A member that joins waits for every vote and every confirm, whether or not it has called before.

The per-zone renewal tests no longer give their members the count by hand. This is implemented in PR #126 with Amendment 3.

### Amendment 5 (2026-10-11): Amendments 3 and 4 on the testbed

Run on the three-agent test rig of Amendment 1, with a 5-minute `leader-election-ttl`, at the head of PR #126: main with PR #121 and PR #124, plus Amendments 3 and 4. The readings are those of Amendment 1:

- **First elections.** Both groups, one of two members and one of three, elected in term 1 at their first election, in the same second on every agent.
- **Renewals.** Two, read against §5: one "TTL expiring" line per renewal, on the member that led, no "group election aborted", the same new term on every agent, and one term per renewal.
- **The fallback.** The leader was restarted inside its term. The group held, and the next member in line renewed once, a step after the leader's time.
- **Restarts and a stop.** Four restarts of a member that did not lead: no "group lost mutual OPERATIONAL" on any agent. Left down, it was given up 12 s after the stop.
- **Over the whole run**, in every agent's log: no "group election aborted" line, no "not all members voted", and the same nine elected terms of the three-member group on every agent.

What the run does not show: the line of Amendment 3, "group vote for a term not joined yet, kept for its CALL", did not appear. A run cannot put a VOTE ahead of its CALL, so the kept vote rests on its in-process tests. So does the per-zone election of Amendments 3 and 4: every zone on the rig has a provider group and uses the group election.

### Amendment 6 (2026-10-11): the vote timeout of a join, after the review of PR #126

A join that already held every vote armed the vote timeout, released the election's lock, broadcast its vote, and then stopped whatever timer the election had by then. A term the member itself had started during the broadcast had put its own timeout there, and lost it. That election, if its votes never came, was never aborted, and rule 1 then kept every renewal timer from starting another while it stood.

On main only a two-member group joins with every vote. With the kept votes of Amendment 3 a larger group can as well, which is how the review came to it. `handleGroupCall` now arms the timeout only when votes are missing, and decides that under the lock, as the per-zone `handleCall` of Amendment 3 already did.

The testbed run of Amendment 5 was made before this change. It alters what a two-member group does at every join: no timeout is armed where one was armed and stopped. The in-process renewal tests of a two-member group run through that join.

### Amendment 7 (2026-10-11): Amendment 6 on the testbed

A second run on the same rig, at the head of PR #126 with the change of Amendment 6, read for what that change touches, the joins of a two-member group:

- **First elections.** Both groups elected in term 1 at their first election, in the same second on every member.
- **Renewals of both groups**, two each, read against §5: no "group election aborted", one "TTL expiring" line per renewal, on the member that led, the same new term on every member, and one term per renewal. In the two-member group the same member led both times and renewed both times.
- **Over the whole run**, in every agent's log: no "group election aborted", no "not all members voted", and the same elected terms on every member of each group.

The leader's restart inside its term, the restarts of the other members and the stop were not run again: nothing in them changed after Amendment 5.
