# The election as gossip and the status command tell it

**Status:** implemented on branch `fix/154-gossip-election-status`, for issue #154. Not run on the testbed. The design text is not rewritten after review (dated amendments at the end).

## 1. What was wrong

`gossip zone-state` could report "election invalidated (group degraded, last term N)" for a group whose election was healthy, until the next renewal. The election itself was not affected.

On a test fleet a two-provider group elected its leader at term 1. One provider's status showed the leader, the other's "election invalidated (group degraded, last term 1)". The second provider's log had the leader elected at term 1 and never invalidated, and it joined the renewal 54 minutes later.

Two things combined:

- **The `/gossip` handler had no election manager.** The routes are set up before the role is started, and the manager is created at that start. The handler was given `conf.InternalMp.LeaderElectionManager` at registration, which was nil then, and kept it. It answered from the election record in the gossip table.
- **The gossip table could hold a wrong record for a term, and kept it.** A member sent its live election state whenever the term was above zero. Inside an election the term is already the new one and the leader is not decided: empty in a first election, the leader of the term before, with that term's expiry, in a renewal. The receiver stored the first record of a term and replaced it only for a higher term. The decided record that followed was of the same term, and was dropped.

A term without a leader is what the status command prints as "election invalidated".

## 2. The handler asks the manager of the moment

`APIgossip` takes the config and reads the agent registry and the election manager when a request comes in, as the agent's other handlers do.

## 3. Only a decided term is told

A member tells its peers of a term only once it is decided (`GroupElectionForGossip`): no election is running, there is a leader, and the leader was elected in that term. The election keeps the term its leader was elected in (`leaderTerm`) to know the last of these: after an aborted renewal the term has moved on and the leader is still the one of the term before.

So a member says nothing of its own in these cases, and passes on what it last heard from a peer, as it did before when it had no state of its own:

| State | Told before | Told now |
|---|---|---|
| first election running | term 1, no leader | nothing |
| renewal running, or aborted | the new term, the old leader and expiry | nothing of the new term |
| leader invalidated | the term, no leader | nothing |
| decided | the term and its leader | the same |

## 4. A record without a leader is not stored

`MergeGossip` ignores an election record without a leader. A peer on an older build still sends them.

With §3 and §4 the first record a member stores for a term is that term's result, so `onElectionUpdate` fires for it. Before, an agent that restarted while an election was running could store the undecided record first, and then did not learn that term's leader from gossip.

## 5. Left out

- **A wrong record with a leader, from a peer on an older build.** In a renewal such a peer sends the new term with the old leader. A receiver cannot tell that from a result, and stores it for the term. It ends when every member runs this change.
- **The status of a zone that no provider group covers.** `gossip zone-state` answers for a zone's group. A single-provider zone has none, and the command has no answer for it, with or without the manager.
- **What the status command says while an election runs.** With the manager it shows the live state, which for the length of an election is the new term with the old leader, or "invalidated" in a first election.

## 6. Tests

`v2/gossip_election_status_test.go`:

- a record without a leader is not stored, and the result of the same term that follows it is, and is passed on once;
- a member tells nothing inside a first election, the term and leader once decided, nothing of the new term inside a renewal or after its abort, and nothing with its leader invalidated;
- the handler, registered before the election manager exists, reports the election the manager holds.

Each fails without its part of the change.

## Amendments

None yet.
