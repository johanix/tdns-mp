# Membership and catch-up: implementation plan

**Status:** PLAN, 2026-10-12. No step is started. Section 5 holds the status of each step.

This is the plan for the design in `2026-10-12-membership-and-catch-up-design.md` ("the design" below). The design describes membership and catch-up as they are meant to stand. This document holds what is dated: the difference from today's code, where each rule of the design lands in the code, the steps, and the questions that are open.

For issues #158, #157, #172, #149 and #137 (item 2). It sits on PR #163 (issues #143, #130) and PR #162 (issues #84, #128, #145), which are not on main yet.

Code read: tdns-mp main `90ca02c`, the two PRs as they stand on the branch `test/e2e-fix-round-2026-10-12`, and tdns `81ce1fda` and tdns-transport `b15bedb7` as `v2/go.mod` pins them. Nothing was built or run for this document: every statement about the code is a reading of it.

## 1. What exists, and what is new

Most of the machinery of the design exists.

**Exists, and is used as it is:** discovery, hello, beat and gossip; provider groups; the election protocol and the lease; a participant that does not vote (the auditor); the request for a zone's state and its answer (RFI SYNC and `resync-targeted`, today behind the operator's `resync --pull`); key states on a DNSKEY operation; the rule that a zone's DS set is unknown until every signing provider has spoken.

**Promised by the guide, and not done by the code:** `guide/synchronization-model.md` (section 2) and the README say that an agent rebuilds its state after a restart from three sources: its combiner (RFI EDITS), its signer (RFI KEYSTATE) and each peer agent (RFI SYNC). The code asks the first two and never the third (2.5). Asking the peers at a start is therefore a repair of the existing design, not an addition to it.

**In open pull requests this plan sits on:** the sender check of the group election (PR #163), the recovery of hello and beat (PR #162), the helpers for a zone's voting members (PR #169).

**New:**

1. Membership follows the HSYNC3 records, not the roles (design 1 and 2).
2. What a sender may do is checked per message, not by admission alone, and a message counts as sent by the sender the transport established (design 3).
3. The answer to a request for state is complete: every type, the key states, always sent, and marked. A leader waits for it (design 5.4 to 5.6).
4. The request is also sent when an agent joins a zone or gets its first role, and after a long outage (design 5.1).
5. The election's edges: no election without a vote, and a leader when the voting members become one (design 4).
6. An agent whose provider has no role refuses its operator's edits (design 6).

No message type is added. Two fields are: the marker on the answer, and a reason word on the request.

## 2. What is wrong today

On a test fleet, a provider with an HSYNC3 record and no role in HSYNCPARAM:

- was in nobody's gossip;
- reported no leader when the zone had an auditor, and elected itself when it had none;
- had its request for state refused by the other agents ("NOTIFY returned rcode REFUSED");
- never got the other signers' DNSKEYs until it had a role and its operator asked by hand;
- had its operator's NS edit accepted by its own agent.

With every missing step taken by hand, in the required order, adding a provider produced no bogus and no lame sample. Separately, a leader that does not sign its zone was restarted and then logged "delegation data in parent is in sync with child, no action needed" with no DS at the parent. One zone waited 30 minutes for its DS, one never got it.

### 2.1 Membership is derived from the roles

`zoneParticipants` (`v2/provider_groups.go`) returns the identities that hold a role: `servers=` and `signers=` (voting) and `auditors=` (not voting), each label resolved through the zone's HSYNC3 records in state ON. A record without a role is left out on purpose, and so is a record in state OFF. A zone with HSYNC3 and no HSYNCPARAM takes every ON identity (the legacy fallback).

Every question "who is in this zone" goes through it: `ParticipantsForZone`, `participantFQDNSetForApex`, `sharedParticipantZones` and `RecomputeGroups` in the same file, `GetZoneAgentData` and `GetAgentsForZone` (`v2/agent_utils.go`), `mpZoneView.Participants` (`v2/hsync_bridge.go`), and through that the hsync engine's `ApplyHsyncDiff` and `ReconcileZone` (`v2/hsync/`). So one set answers three questions: who is talked to, who votes, and who gets a distribution and is waited for. Only the vote is kept apart, as the `voting` subset.

`RecomputeGroups` keys a provider group on the participant list and skips a zone with fewer than two. When zones with the same participants disagree about who votes, the group's voting members are the union, with a warning.

A role given later to a record that is already there is a change of HSYNCPARAM alone. `ApplyHsyncDiff` then gets no HSYNC3 add: nothing marks the peer as needed and `reattachHsyncMemberAdds` does not run. The periodic `ReconcileZone` (60 s by default) finds the peer.

### 2.2 Admission

The transport asks `IsPeerAuthorized` (`v2/agent_authorization.go`) twice for a message: before any crypto, with no zone (`isInHSYNCAnyZone`: known at all), and after parsing, with the message's zone (`isInHSYNC`). Both want the sender and the local agent to be participants of the same zone. A sender that fails gets rcode REFUSED.

For most messages that is the only check of who sent them. `MsgHandler` (`v2/hsyncengine.go`) checks that the zone exists and has an HSYNC3 RRset, not the sender's standing in it. The handlers behind it rest on the admission: a SYNC's operations are stored and passed to the combiner, an election message was counted (until PR #163), and `CONFIG sig0key` hands the zone's SIG(0) private key to a requester that the HSYNC3 `upstream` fields relate to the answering agent.

Two tests assert the refusal: the `RoleLessRejected` case of `v2/transport_integ_test.go`, which calls itself a security regression test, and `TestApplyHsyncDiff_roleLessAddExcluded` in `v2/hsync/` (but see 2.9).

### 2.3 What a provider with a record and no role gets

| | Today | Where |
|---|---|---|
| Discovery by the others | None | `ApplyHsyncDiff` skips "HSYNC3 record without a HSYNCPARAM role"; `ReconcileZone` expects participants only |
| Its own discovery of the others | Runs: the gate on local presence (`localInHsync3`) reads the raw RRset. Its hellos are refused | `v2/hsync/hsync3_diff.go`, `isInHSYNC` |
| Gossip | None, either way: it is in no group | `BuildGossipForPeer` (`v2/gossip.go`) wants both agents in the group |
| Distributions | None | `GetZoneAgentData` leaves it out of `Agents`; `getAllAgentsForZone`, `GetDistributionRecipients` and `EnqueueForZoneAgents` read that |
| Its requests (RFI) | Refused at admission | `isInHSYNC` |
| A leader to report | None, or itself (2.4) | |
| Its operator's edits | Accepted by its own agent (2.8) | `v2/apihandler_agent.go` |

### 2.4 The election's counts, and the self-election

A group's election is started by the voting member with the lowest identity when the group reaches mutual OPERATIONAL (`wireAgentGossipCallbacks`, `v2/hsync_bridge.go`). `CheckGroupState` computes that over `pg.Members`, auditors included, so an auditor that is down holds an election back and invalidates a leader. `startGroupElection` (`v2/parentsync_leader.go`) expects the voting members minus one.

A zone that no group covers uses the per-zone election. Its count comes from `SetConfiguredPeersFunc` (`v2/start_agent.go:142`): the zone's participants minus one, with no look at whether the local agent is one of them.

With zero expected peers `startElection` makes the local agent leader at once ("single agent, self-elected as leader", `v2/parentsync_leader.go:969`) and runs `onLeaderElected`. `startGroupElection` has the same branch (`:106`). Neither checks that the local agent has a role. Four callers can get there: the first-load callback (`v2/start_agent.go:207`), the hook for an HSYNC3 add (`reattachHsyncMemberAdds`, `v2/agent_utils.go:380`), the lease renewal (`scheduleReelection`), and the operator's `parentsync-election` (`v2/apihandler_agent.go:594`).

What issue #172 and the fleet saw, as the code gives it: a zone with one provider has one participant. That provider's agent counts 1 - 1 = 0 and leads, correctly. An agent that has the zone in its config and no role in it, with or without a record of its own, also counts 1 - 1 = 0, and leads too. With an auditor in the zone the count is 1: the agent with no role defers an election that never starts for it, and reports no leader.

A zone that the owner reduces to one provider gets no leader (#149): an election starts when a group becomes operational or when an HSYNC3 record is added. Here the group goes away, and nothing starts the per-zone election until the agent's next start.

PR #163 makes `HandleGroupMessage` drop a CALL, VOTE or CONFIRM whose sender is not one of the group's voting members. The per-zone `HandleMessage` is unchanged by it.

### 2.5 What an agent asks at its start

At its start `SynchedDataEngine` (`v2/syncheddataengine.go`) hydrates each zone from the agent's own provider: the contributions its combiner holds (RFI EDITS) and, when its provider signs, the key inventory of its signer. `reattachHsyncMemberAdds` asks an upstream or a downstream for the zone transfer set-up (RFI CONFIG) once that peer is OPERATIONAL.

No peer is asked about the zone's state, although the guide says each one is (RFI SYNC, `guide/synchronization-model.md` section 2). Two things live only at the peers: what each signing provider says about its keys (2.7), and any change that was sent while the agent was down and has left its sender's queue. The confirmed queue keeps a message for 24 hours, in memory: a sender that restarts loses what it had queued.

### 2.6 What the answer to a resync contains

`tdns-mpcli agent peer resync --pull` sends RFI SYNC to every agent of the zone that is OPERATIONAL, once each (`CommandHandler`, `v2/hsyncengine.go`). The receiver runs `resync-targeted` (`v2/syncheddataengine.go:807`): one SYNC to the asker alone, through the confirmed queue, with a `replace` for each RRtype of the answering agent's own records. It has four gaps:

- no key states on the DNSKEY operation;
- no operation for an RRtype the agent holds no record of, so the asker keeps what it had;
- no message at all from an agent that holds nothing, so "nothing" and "lost" look the same;
- nothing that ties the answer to the request, or says that it is everything.

### 2.7 Where the key states live, and when they are sent

A signing provider's agent attaches the key states (`core.RROperation.KeyStates`) in one place: `SyncRequestHandler` (`v2/hsyncengine.go:70`), when its signer's key inventory differs from what it last distributed. The receiver keeps them, and the DNSKEY records, in two maps in memory (`foreignKeyStates` and `foreignDnskeys` on `MPTransportBridge`, written by `NoteForeignKeyStates`, `v2/hsync_transport.go`).

A leader whose own signer does not own the zone computes the zone's DS set from those maps (`computedDSIntent`, `v2/mp_s5_computed_ds.go`). The set is unknown while any provider in `signers=` "has not said what it holds its keys as". After the leader's restart the maps are empty and nobody is asked. tdns then leaves the parent's DS alone, which is right, and reports the delegation as in sync when NS and glue match (`AnalyseZoneDelegation` returns with `NewDSKnown` false). The agent's syncher logs "in sync" and ends its retry chain (`v2/delegation_sync.go:147`). The sync is asked for again when the computed set changes, at an election, on the combiner's hint, or when the zone's NS or glue change. None of those follows from the restart.

The sending agent's own restart sends nothing either, as far as the code reads. The start-up hydration stores the keys as already distributed and clears the remembered key states so that the next inventory carries them (`v2/syncheddataengine.go:127`). The first zone load does ask the signer for its inventory, but at that point the zone's multi-provider data is still the stub of `v2/main_init.go`, which reads as "not signed", and `LocalDnskeysFromKeystate` returns no result. The states go out with the next inventory the signer sends by itself, which follows a key event.

`logSilentAgents` lists every agent of the zone that has sent no key states: the auditor, and also every server that does not sign. Neither holds a key.

### 2.8 The agent's own operator

`add-rr` and `del-rr` check `getEditPolicy().canSubmit` (`v2/apihandler_agent.go:115`): `nsmgmt`, `parentsync`, and whether the provider signs. `EvaluateUpdate` checks `nsmgmt` for an NS record. Neither checks that the provider has a role. The edit is stored and sent to the provider's combiner and to the zone's agents.

### 2.9 Where the code differs from the issues' descriptions, or adds to them

- **The exclusion is not complete on the way out.** A peer with which comms are up and no participant zone is left reads as LEGACY (`effectiveAgentState`), and `IsPeerAuthorized` admits a LEGACY peer before it looks at the zone. `handleAppSync` then refuses its SYNC; `handleAppRfi` has no such gate. So a provider that loses its last role in the zones it shares with the receiver keeps the RFI verbs, for any zone the receiver has: SYNC, AUDIT, CONFIG, and the election messages, which were counted before PR #163. The fleet showed the way in. The way out was not run.
- **`TestApplyHsyncDiff_roleLessAddExcluded` does not test a record without a role.** Its excluded record is in state OFF, in a zone with no HSYNCPARAM. `RoleLessRejected` is the test of the rule.
- **The combiner has no role check either.** Where a combiner declines such an edit it is on other grounds: it does not apply a contribution to a signed zone when its provider is not a signer (`canApply`, `v2/combiner_chunk.go`), and stores it. In an unsigned zone the same edit from a provider with no role would be applied.
- **Why the unlisted agent of #172 was in the election at all.** `PostRefresh` turns the parentsync option on for any zone whose HSYNCPARAM says `parentsync=agent` (`v2/hsync_utils.go:1546`), without the check of the local identity that the first-load callback makes, and a first load's `PostRefresh` runs before that callback.

Found on the way, as read, none of them filed:

- On an agent, the originator that a SYNC, an RFI or a beat names in its payload is not compared with the sender the transport established (`routeSyncMessage`, `routeBeatMessage`, `v2/hsync_transport.go`). The checks of the sender in `MsgHandler` and in the election read the named one, PR #163's check among them: any admitted peer can name a voting member.
- An agent that does not vote and learns a leader from gossip arms the lease's fallback renewal (`ApplyGossipElection` calls `scheduleGroupReelection` with no look at the local agent). Today that is an agent listed under `auditors=` only. With members that have no role it is the normal case.
- A group that no zone is left in keeps its election state and its timers. Nothing retires it: `RecomputeGroups` drops the group and the election manager is not told.
- A lone voting member's self-election does not take a new term. `GroupElectionForGossip` tells nothing of term 0, and a renewed lease of the same term is not news to a peer, so an observer of a one-voter group never learns its leader.

## 3. The design in the code

Where each rule of the design lands. The design's sections are named as "design N".

### 3.1 Membership (design 1 and 2)

| Function | Today | Change |
|---|---|---|
| `zoneParticipants` (`v2/provider_groups.go`) | Role holders, and the voting subset | Returns three sets: members (every ON record), voting members, auditors. The legacy fallback is unchanged |
| `ParticipantsForZone`, `participantFQDNSetForApex`, `sharedParticipantZones` | Role holders | Members. The callers that mean a role get `VotingMembersForZone`, `AuditorsForZone` and `isVotingMember`. Those exist today only on the draft PR #169 (issue #152); step 1 brings them if that has not merged |
| `RecomputeGroups` | Key and hash from the participants | Key and hash from the members (design 4.1). It tells the election manager which groups are gone |
| `isInHSYNC`, `isInHSYNCAnyZone` (`v2/agent_authorization.go`) | Both must hold a role | Both must be members. What a member may do is checked per message (3.2) |
| LEGACY (`effectiveAgentState`, `isKnownLegacy`) | No shared participant zone | No shared member zone. A peer whose roles are gone and whose record stays is a member, not LEGACY |
| `mpZoneView.Participants` (`v2/hsync_bridge.go`), `ApplyHsyncDiff`, `ReconcileZone` | An add with no role is skipped | A member is registered and discovered. An OFF record is skipped as today |
| `GetZoneAgentData`, `GetAgentsForZone` (`v2/agent_utils.go`) | `Agents` are the role holders | `Agents` are the members, each with its standing. Callers choose: recipients take members, the election and the SIG(0) key take voting members |
| `reattachHsyncMemberAdds` | CONFIG requests for a role holder; an election kick | CONFIG requests for a member; the catch-up request for the zone (design 5.1). The kick goes (3.3) |
| `SetConfiguredPeersFunc`, `SetOperationalPeersFunc` (`v2/start_agent.go`) | Participants minus one; OPERATIONAL agents of the zone | Voting members other than this agent; the OPERATIONAL ones among them |
| `PostRefresh` (`v2/hsync_utils.go`) | Turns parentsync on for the zone, whoever is listed in it | Only for a zone in which this agent is a member |
| `beatZones` (`v2/hsync_transport.go`), and the zones a hello names (`sendHelloToPeer`, `v2/hsync/hello.go`) | Shared participant zones, in no order | Shared member zones, those in which both hold a role first (section 4) |
| `logSilentAgents` | Every agent of the zone | The providers in `signers=` |
| `populateMPdata`, guard 3 | A zone without a record of this provider is not a multi-provider zone for it | Unchanged |

### 3.2 Senders (design 3)

The sender the transport established: `routeSyncMessage` and `routeBeatMessage` (`v2/hsync_transport.go`) drop a payload that names another originator, with the names compared as FQDNs. As read, an agent forwards nothing to another agent.

What the exclusion protected, and how each protection survives:

| Protection today, by admission alone | After the change |
|---|---|
| A SYNC from an identity with no role is never stored, passed to a combiner or applied | `handleAppSync` (`v2/mp_verb_handlers.go`) refuses a SYNC whose sender is not a voting member of the zone, with the reason, as it refuses a LEGACY sender today. `CombinerProcessUpdate` refuses an operation whose named origin is not one, as a second line: there the origin and the deliverer differ by design. An auditor is covered by the same rule; nothing refuses its operations today |
| Its election messages are not counted | PR #163 for the group path. The same check in `HandleMessage` for the per-zone path. Election messages are sent to voting members and auditors only |
| The zone's SIG(0) private key is not handed to it | `CONFIG sig0key` (`MsgHandler`) wants a requester that is a voting member, in addition to today's check |
| It cannot inflate the election's count | The counts are taken from the voting members (3.3) |
| It gets no gossip, so it learns nothing of the group and cannot speak into it | It is a member of its zone's group and gets that group's gossip. From a member that does not vote a receiver takes that member's own row and the term number of an election record, never who leads (`MergeGossip`, keyed on the beat's sender as the transport established it) |
| No distribution waits for it | It is a recipient, and waited for (question 2) |
| Only an identity the zone owner names can make an agent run discovery | Unchanged. The owner names it with one record instead of two edits |

This also closes the way out of 2.9: no handler rests on admission alone any more.

Tests: `RoleLessRejected` becomes a test that the hello of a member with no role is accepted and that its SYNC, its election message and its request for the SIG(0) key are refused. `TestApplyHsyncDiff_roleLessAddExcluded` splits in two: an OFF record is excluded; an ON record without a role is registered and reported to `OnHsyncMembersAdded`.

### 3.3 Elections (design 4)

- **The hash** (design 4.1). `ComputeGroupHash` over the identities, a member with no role with a marker after its name. For a zone in which every member has a role the list and the hash are today's: nothing changes for a zone until its owner adds a record without a role, or takes a provider's roles away.
- **The lead checked per zone** (design 4.1). `IsLeader` also checks that the leader is a voting member of the zone that is asked about.
- **The counts** (design 4.2). The two peer functions of 3.1. `startGroupElection` already expects the voting members minus one.
- **The gate** (design 4.3). The three callers of `CheckGroupState` pass `pg.VotingMembers` for the gate.
- **Start** (design 4.4). `startElection` and `startGroupElection` return when the local agent is not a voting member, which covers the four callers of 2.4. `ApplyGossipElection` arms no renewal timer on an agent that does not vote.
- **Vote.** PR #163's check of the sender, the same check in the per-zone `HandleMessage`, and the existing check of the local agent.
- **Win.** `determineWinner` sees votes of voting members only. `finalizeGroupElection` and `finalizeElection` take a winner only if it is one.
- **One check for every change** (design 4.5). `PostRefresh` calls one function for every change of HSYNC3 or HSYNCPARAM, and at the first load, in place of the first-load callback's logic and the kick in `reattachHsyncMemberAdds`. It keeps today's condition that the zone syncs with its parent through its agents.
- **A term for a self-election** (design 4.6). A self-election takes a term one above the highest the agent holds or has heard of for the group, so that `GroupElectionForGossip` tells it.
- **What a member with no role reports** (design 4.7). `ApplyGossipElection` takes the decided term that `GroupElectionForGossip` of a voting member tells. `agent parentsync status` and `gossip zone-state` show it.
- **Retiring** (design 4.8). When `RecomputeGroups` drops a group, the election manager stops that group's timers and forgets it.

On PR #163: its check compares the sender with `pg.VotingMembers`. This plan keeps the check and makes the list exact for every group that has a member with no role. It adds the same check to the per-zone path, and uses the PR's `isAmong` for the local agent in the two start functions. The sender that the check reads has to be the one the transport established (3.2): today it is the one the payload names.

### 3.4 Catch-up (design 5)

- **When** (design 5.1). The edge exists: a mechanism that turns OPERATIONAL in `SendBeatWithFallback`, where `NotifyPeerOperational` is called today. That edge compares the raw mechanism state, which an outage need not move, so the `outage` case compares the effective state. PR #162 is what makes the edge arrive after a refused hello, a refused beat back or a wrong key. The `join` request is sent from `reattachHsyncMemberAdds`.
- **The request** (design 5.3). RFI SYNC as today, with two additions that an older receiver ignores: the reason word in `RfiSubtype`, and the request's distribution ID as the request's name.
- **The answer** (design 5.4). `resync-targeted` stays the answer, sent with `EnqueueForSpecificAgent`. The types are those of `AllowedLocalRRtypes`. The key states are read from the signer's latest inventory by the code that `LocalDnskeysFromKeystate` uses, without touching what that function remembers. The marker is a new field on `DnsSyncPayload`, tdns-mp's own type, with its golden wire file.
- **At the asker.** The operations go through `EvaluateUpdate` and `ProcessUpdate` as any remote update. The order guard holds (`noteReplaceOrigin`). `NoteForeignKeyStates` takes a complete answer from a provider in `signers=` as that provider having spoken, also when it lists no key: the wire cannot say "spoken, no keys" today, because an empty list of key states is not encoded.
- **The tracker** (design 5.5). New, in memory, per zone and peer.
- **What waits** (design 5.6). `computedDSIntent` is unchanged. `noteComputedDSSet` asks for the sync when the set turns from unknown to known. `requestDelegationSync` asks for nothing while the zone is not caught up, and the syncher's two sync commands (`v2/delegation_sync.go`) send nothing. The syncher's "in sync" line becomes "DS set unknown, waiting for" when the analysis has no DS set to compare for a zone that names a signer.
- **Pacing** (design 5.8). Eight requests in flight to one peer, as `DiscoverySemLimit` does for discovery. An answer that changes nothing is confirmed on the existing short path for an update whose result is already there.

### 3.5 The agent's own operator (design 6)

- `add-rr`, `del-rr` and `update-local-zonedata` (`v2/apihandler_agent.go`) refuse, and so does the `local` case of `EvaluateUpdate`, so that no other path gets past. This is item 2 of #137.
- `parentsync-election` and `parentsync-bootstrap` refuse.
- `resync --push` sends nothing to peers and says why.
- `zone mplist` gets the member list with each member's standing. `agent parentsync status` gets the learned leader and term, "does not vote", and the tracker's state per voting member.

## 4. Mixed versions

"New" is an agent with the design, "old" one without.

**A zone in which every member has a role works in a mixed group.** Members, hash and admission are the same on old and new agents, with or without an auditor. Three things differ:

- A new agent asks an old one for state. The old one answers in the old way: its own records, no key states, no marker, and nothing at all when it holds nothing. A peer that has acknowledged three requests a minute apart and sent no marked answer is taken as old: answered, without key states. That is logged once, and it is asked again once an hour. A new leader with an old signer then syncs NS as today and leaves DS alone until that signer's next key event, as today.
- An old agent never asks. A new agent answers `resync --pull` from an old one with the new answer. The old receiver ignores the marker and applies the operations, the empty ones included. The key states it gets are an improvement.
- The election's gate is the voting members on new agents and every participant on old ones. With an auditor down, a new agent that is the lowest voting member calls an election, and an old voting member joins a CALL from a voting member, so the group elects. When the lowest voting member is old, nobody calls until the auditor is back, as today.

**A zone with a member that has no role stalls in a mixed group. It is not harmed.**

- Old agents refuse the member with no role and leave it out of the group. New agents include it, and compute another hash. For that zone the two sides are in different groups and agree on no leader. The new side never completes an election for it, since an old voting member does not know its group. So at most the old side's leader acts, and the zone's sync with the parent may stall until every voting member is new.
- A new agent's beat names the zones it shares with the peer, and an old receiver authorizes it on the first one. So zones in which both hold a role come first, in no fixed order among themselves, and the zone a hello names is chosen the same way. An old peer then sees what it sees today.
- A new member with no role whose hello an old peer refuses is looked up again by PR #162's recovery, once a minute. That is bounded, and ends with the upgrade.

**An old agent as the member with no role is today's behaviour,** #172 included: it can elect itself and talk to the parent, and no peer can stop that. New voting members drop its election messages and refuse its SYNCs.

So two rules for operators:

1. An agent gets step 1 (section 5) before it is configured with a zone in which its provider has no role.
2. Every agent of a zone runs the whole design before the owner starts a provider change in it.

## 5. The steps

Each step is one pull request. Steps 1 to 6 are safe to merge alone and change nothing for a zone in steady state except what the step names.

| Step | What | Issues | Status |
|---|---|---|---|
| 1 | No election without a role | #172 | Not started |
| 2 | An agent with no role refuses its operator's edits | #137 item 2 | Not started |
| 3 | The complete answer | #157 | Not started |
| 4 | Asking by itself, and what waits | #157 | Not started |
| 5 | A rule for the sender in every handler | | Not started |
| 6 | The election by its voting members | #149 | Not started |
| 7 | The switch: every HSYNC3 provider is a member | #158 | Not started |

**Step 1. No election without a role (#172).**
- Changes: `startElection` and `startGroupElection` return unless the local agent is a voting member. The two counts are taken from the voting members. `PostRefresh` turns parentsync on only where the agent is a member. No renewal timer on an agent that does not vote. PR #163's sender check in `HandleMessage`.
- Unit: an agent with no role and zero expected peers starts nothing, from each of the four callers. An agent that is not listed gets no parentsync option. An observer arms no timer.
- Harness: two election managers, one zone with one provider, the other agent configured and not listed: one leader.
- Fleet: the case of #172. One "self-elected" line in the whole fleet. `agent parentsync status` on the unlisted agent shows no leader of its own.
- Needs PR #163 for `isAmong`. Brings `isVotingMember` unless PR #169 has merged.

**Step 2. An agent with no role refuses its operator's edits (#137 item 2); signers only in `logSilentAgents`.**
- Unit: the three commands and `EvaluateUpdate` refuse with the text of design 6, and nothing reaches the update queue. The warning names no auditor and no server that does not sign.
- Fleet: `addrr` on a provider with a record and no role is refused; its combiner holds nothing new.

**Step 3. The complete answer (#157, the answering side).**
- Changes: `resync-targeted` as in design 5.4. The marker on `DnsSyncPayload`, and its golden wire file. `NoteForeignKeyStates` takes a complete answer as having spoken.
- Unit: the answer of a signer with keys, of a signer without an inventory ("not complete"), of a server that holds nothing (five empty operations, complete). `computedDSIntent` is known after a complete answer from every provider in `signers=`. An answer in the old form is still applied.
- Harness: the two-agent transport test: RFI SYNC and its answer over the real path.
- Fleet: restart a leader that does not sign, then run `resync --pull` by hand: the DS set becomes known, a sync is asked for, the DS is at the parent. The "Today" note of section 3.2 of the guide loses its sentence about key states.

**Step 4. Asking by itself, and what waits (#157, the restart).**
- Changes: the tracker of design 5.5. The requests of design 5.1 for `start`, `peer-start`, `outage` and `manual`. The retries. The held sync and the "DS set unknown" report of design 5.6. The status lines.
- Unit: the tracker's states, the retry schedule, the one-minute rule, the peer taken as old. The syncher's messages for known, unknown and held.
- Harness: three agents, one restarted: it asks two, is asked back by two, and ends caught up.
- Fleet: every agent restarted within ten seconds, on a zone whose leader does not sign: the DS is at the parent with no owner edit and no command. The leader alone restarted: the same. One signer's agent stopped: the leader reports what it waits for, and syncs when the agent is back.

**Step 5. A rule for the sender in every handler.**
- Changes: 3.2: the sender is the one the transport established; SYNC, at the agent and at the combiner; `CONFIG sig0key`; gossip. Election messages go to voting members and auditors.
- For a zone in steady state nothing changes: admission already keeps these senders out. What closes is the LEGACY way out of 2.9 and the named originator.
- Unit: each rule, with the sender admitted and holding no role. A SYNC and a vote that name a voting member and come from another sender are dropped.
- Fleet: no difference in a run without a provider change. That is the test.

**Step 6. The election by its voting members (#149).**
- Changes: 3.3, without what step 1 took: the gate, the one check for every change, a term for a self-election, retiring a group, the lead checked per zone.
- Unit: a group of one voting member and one observer: the voter leads at a term above zero and the observer learns it. A group that is dropped leaves no timer. A leader whose role is gone is no leader. An auditor that is down does not hold the election back (question 3).
- Harness: several managers through a real election, as the existing renewal tests do.
- Fleet: two providers reduced to one, with no auditor: a leader with no restart. A lease renewal with the auditor stopped.

**Step 7. The switch: every HSYNC3 provider is a member (#158).**
- Changes: 3.1. The hash of design 4.1. The `join` and `role` requests. The displays of design 6. The order of the beat's zones. `guide/provider-changes.md` loses the "Today" notes of its sections 2 and 3.2.
- Unit: the two replaced tests of 3.2. Members, voting members and auditors for each kind of zone. The hash is today's for a zone in which every member has a role.
- Harness: the hello of a member with no role is accepted; it gets gossip and an answer to its request for state.
- Fleet: an add with the owner's two edits apart. After the first edit the newcomer is in every agent's gossip, reports the group's leader, has caught up with every voting member, and has its `addrr` refused. The other agents hold one election, without it. After the second edit there is one election, with it. No sample is bogus or lame at any point. Then the removal's first edit: the provider stops voting at once, and stops leading if it led.
- Not safe alone: it needs steps 1, 5 and 6, and step 4 on every agent for the newcomer to catch up by itself.

## 6. Open questions for the project owner

The design is written with the recommended answer to each, and marks the places that depend on one. A decision is written into the design, and the question leaves this list.

1. **How the asker knows that an answer is complete.**
   (a) One message that is complete by construction, with a marker that names the request. (b) Several messages and an end marker. (c) A count or a digest announced first.
   Recommended: (a). A `replace` per type is already a whole set, the answer for one zone is small, and (b) needs an ordered delivery that the transport does not have.

2. **Does a member with no role receive every distribution, and does a distribution wait for its confirmation?**
   (a) It receives nothing until it has a role, and catches up then. (b) It receives, and is not waited for. (c) It receives and is waited for, like any member. (d) It is waited for only on its way out, which needs to know what the zone said before the owner's edit.
   Recommended: (c). On its way out a provider still serves, and a new key of another signer must be at every server that still answers before it is used. So (a) and (b) can make answers bogus, and (c) stalls instead: a key roll waits for a member whose agent is down, until it is up or the owner removes its record. The wait is what the removal design will need. It does not by itself make a removal safe (issues #147, #138).

3. **Does an auditor that is down still hold an election back?**
   Today it does, because the gate is every participant. (a) The gate is the voting members. (b) The voting members and the auditors.
   Recommended: (a), by the rule that takes the member with no role out of the gate: who cannot vote cannot block the vote.

4. **Is one election for each step of an add or a removal acceptable?**
   (a) Yes: the group is the member list, as decided, and a zone changes group at each step. (b) Key the election on the voting members alone, so that a record without a role disturbs nothing.
   Recommended: (a). With (b) the group that gossips and the group that elects are two different things, and a member with no role would have to be shown the election of a group that may hold zones it is not a member of.

5. **Does a peer ask a restarted agent back?**
   (a) Yes, once, on a `start` request. (b) No.
   Recommended: (a). It is the only thing that finds a change the restarted agent made and lost from its queue.

6. **May a member with no role get the zone transfer set-up from its upstream (RFI CONFIG)?**
   (a) Yes. (b) Not until it has a role.
   Recommended: (a). Section 3.3 of the guide needs it: the newcomer serves the zone before it is listed, and the HSYNC3 record names its upstream.

7. **What a provider contributed while it had a role, after its roles are gone.**
   (a) It stands until the removal procedure takes it away, and the provider cannot change it: not its NS records, and not its DNSKEYs or what it says about them. (b) It may still update its own DNSKEYs and key states until it is gone.
   Recommended: (a) here, with the removal design to say how a leader that restarts in the middle of a removal learns a departing signer's keys: by asking it, or from what was kept.

8. **Does the whole sync with the parent wait for catch-up, or only the DS?**
   (a) The whole sync. (b) Only the DS; NS and glue go as today.
   Recommended: (a). A leader that missed a change would send its older view of the NS RRset, and the wait adds no stall that the loss of the leader would not cause anyway.

## 7. After this plan

A provider that is named in `signers=` while it runs does not sign until its signer is restarted (#146), and the key machine's `SignersChanged` has no caller (#136). Both need what the design gives a newcomer before it has a role: comms with every member, and the other signers' DNSKEYs with what they say about them. With that in place, calling `SignersChanged` from the refresh when `signers=` changes, and binding the signing policy at that moment, is the next step. It is not part of this plan.

What else the design leaves out is listed in its section 7.
