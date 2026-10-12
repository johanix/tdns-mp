# Membership and catch-up: implementation plan

**Status:** PLAN, 2026-10-12. No step is started. Section 5 holds the status of each step.

This is the plan for the design in `2026-10-12-membership-and-catch-up-design.md` ("the design" below). The design describes membership and catch-up as they are meant to stand. This document holds what is dated: the difference from today's code, where each rule of the design lands in the code, the steps, and the decisions the design rests on.

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
5. A group is defined by its members together with what each one is, so that all its zones agree on who votes. The election's edges: no election without a vote, a leader when the voting members become one, and a leader that takes up a zone which arrives in its group (design 4).
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

Found on the way, as read. Two are filed since, the others are covered by the steps of this plan:

- On an agent, the originator that a SYNC, an RFI or a beat names in its payload is not compared with the sender the transport established (`routeSyncMessage`, `routeBeatMessage`, `v2/hsync_transport.go`). The checks of the sender in `MsgHandler` and in the election read the named one, PR #163's check among them: any admitted peer can name a voting member.
- An agent that does not vote and learns a leader from gossip arms the lease's fallback renewal (`ApplyGossipElection` calls `scheduleGroupReelection` with no look at the local agent). Today that is an agent listed under `auditors=` only. With members that have no role it is the normal case.
- A group that no zone is left in keeps its election state and its timers. Nothing retires it: `RecomputeGroups` drops the group and the election manager is not told (issue #182).
- A zone that moves into a group which has a leader is not taken up by that leader. The work a leader owes a zone is started by `onLeaderElected`, which the election manager calls at election events only, and `RecomputeGroups` tells the election manager nothing. On a test fleet a zone moved to another group when its owner removed a provider, the NS change of that edit was skipped by the new group's leader ("not the delegation sync leader, skipping DDNS"), and it reached the parent 49 minutes later, at the lease renewal. This is issue #179, and a change for the arrival is being made apart from this plan.
- A lone voting member's self-election does not take a new term. `GroupElectionForGossip` tells nothing of term 0, and a renewed lease of the same term is not news to a peer, so an observer of a one-voter group never learns its leader.

## 3. The design in the code

Where each rule of the design lands. The design's sections are named as "design N".

### 3.1 Membership (design 1 and 2)

| Function | Today | Change |
|---|---|---|
| `zoneParticipants` (`v2/provider_groups.go`) | Role holders, and the voting subset | Returns three sets: members (every ON record), voting members, auditors. The legacy fallback is unchanged |
| `ParticipantsForZone`, `participantFQDNSetForApex`, `sharedParticipantZones` | Role holders | Members. The callers that mean a role get `VotingMembersForZone`, `AuditorsForZone` and `isVotingMember`. Those exist today only on the draft PR #169 (issue #152); step 1 brings them if that has not merged |
| `RecomputeGroups` | Key and hash from the participants; voting members are the union across the group's zones | Key and hash from the members with what each one is: voting member, auditor, no role (design 4.1). No union, and its warning goes. It tells the election manager which groups are gone, and which zones arrived in which group |
| `isInHSYNC`, `isInHSYNCAnyZone` (`v2/agent_authorization.go`) | Both must hold a role | Both must be members. What a member may do is checked per message (3.2) |
| LEGACY (`effectiveAgentState`, `isKnownLegacy`) | No shared participant zone | No shared member zone. A peer whose roles are gone and whose record stays is a member, not LEGACY |
| `mpZoneView.Participants` (`v2/hsync_bridge.go`), `ApplyHsyncDiff`, `ReconcileZone` | An add with no role is skipped | A member is registered and discovered. An OFF record is skipped as today |
| `GetZoneAgentData`, `GetAgentsForZone` (`v2/agent_utils.go`) | `Agents` are the role holders | `Agents` are the members, each with its standing. Callers choose: recipients take members, the election and the SIG(0) key take voting members |
| `reattachHsyncMemberAdds` | CONFIG requests for a role holder; an election kick | CONFIG requests for a member; the catch-up request for the zone (design 5.1). The kick goes (3.3) |
| `SetConfiguredPeersFunc`, `SetOperationalPeersFunc` (`v2/start_agent.go`) | Participants minus one; OPERATIONAL agents of the zone | Voting members other than this agent; the OPERATIONAL ones among them |
| `PostRefresh` (`v2/hsync_utils.go`) | Turns parentsync on for the zone, whoever is listed in it | Only for a zone in which this agent is a member |
| `beatZones` (`v2/hsync_transport.go`), and the zones a hello names (`sendHelloToPeer`, `v2/hsync/hello.go`) | Shared participant zones | Shared member zones |
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
| No distribution waits for it | It is a recipient, and waited for |
| Only an identity the zone owner names can make an agent run discovery | Unchanged. The owner names it with one record instead of two edits |

This also closes the way out of 2.9: no handler rests on admission alone any more.

Tests: `RoleLessRejected` becomes a test that the hello of a member with no role is accepted and that its SYNC, its election message and its request for the SIG(0) key are refused. `TestApplyHsyncDiff_roleLessAddExcluded` splits in two: an OFF record is excluded; an ON record without a role is registered and reported to `OnHsyncMembersAdded`.

### 3.3 Elections (design 4)

- **The group's key** (design 4.1). `RecomputeGroups` keys a group on the zone's members with what each one is, and `ComputeGroupHash` takes the same. The union of voting members across a group's zones goes: all zones of a group agree on who votes.
- **A zone that arrives** (design 4.1, issue #179). `RecomputeGroups` reports which zones arrived in which group. An agent that leads the group runs for the zone what `onLeaderElected` runs, once per arrival. An agent that led the group the zone left drops what it holds for the zone. A zone that arrives in a new group gets it from that group's election.
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
- **The request** (design 5.3). RFI SYNC as today, with two additions: the reason word in `RfiSubtype`, and the request's distribution ID as the request's name.
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

## 4. Agents in step

tdns-mp does not support agents that are out of step with each other: all agents of a zone must be in sync protocol-wise. So this plan has no code for a peer that runs an earlier build:

- no detection of a peer that answers a request for state without the marker;
- no order among the zones a beat or a hello names;
- no fallback for a group in which some agents count members and others count role holders.

An agent that is out of step shows as a stall, not as harm. Its answer has no marker, so it does not count as complete and is asked for again (design 5.7). A zone with a member that has no role is in different groups on the two sides, and the sides agree on no leader for it.

Two rules for operators follow:

1. Every step of section 5 goes to all agents of a zone together.
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
- Unit: the answer of a signer with keys, of a signer without an inventory ("not complete"), of a server that holds nothing (five empty operations, complete). `computedDSIntent` is known after a complete answer from every provider in `signers=`. An answer without the marker is applied and does not count as complete.
- Harness: the two-agent transport test: RFI SYNC and its answer over the real path.
- Fleet: restart a leader that does not sign, then run `resync --pull` by hand: the DS set becomes known, a sync is asked for, the DS is at the parent. The "Today" note of section 3.2 of the guide loses its sentence about key states.

**Step 4. Asking by itself, and what waits (#157, the restart).**
- Changes: the tracker of design 5.5. The requests of design 5.1 for `start`, `peer-start`, `outage` and `manual`. The retries. The held sync and the "DS set unknown" report of design 5.6. The status lines.
- Unit: the tracker's states, the retry schedule, the one-minute rule. The syncher's messages for known, unknown and held.
- Harness: three agents, one restarted: it asks two, is asked back by two, and ends caught up.
- Fleet: every agent restarted within ten seconds, on a zone whose leader does not sign: the DS is at the parent with no owner edit and no command. The leader alone restarted: the same. One signer's agent stopped: the leader reports what it waits for, and syncs when the agent is back.

**Step 5. A rule for the sender in every handler.**
- Changes: 3.2: the sender is the one the transport established; SYNC, at the agent and at the combiner; `CONFIG sig0key`; gossip. Election messages go to voting members and auditors.
- For a zone in steady state nothing changes: admission already keeps these senders out. What closes is the LEGACY way out of 2.9 and the named originator.
- Unit: each rule, with the sender admitted and holding no role. A SYNC and a vote that name a voting member and come from another sender are dropped.
- Fleet: no difference in a run without a provider change. That is the test.

**Step 6. The election by its voting members (#149).**
- Changes: 3.3, without what step 1 took: the gate, the one check for every change, a term for a self-election, retiring a group, a zone's arrival in a group.
- Unit: a group of one voting member and one observer: the voter leads at a term above zero and the observer learns it. A group that is dropped leaves no timer. A zone that arrives in a group with a leader is taken up by it, and no election is held. An auditor that is down does not hold the election back.
- Harness: several managers through a real election, as the existing renewal tests do.
- Fleet: two providers reduced to one, with no auditor: a leader with no restart. A lease renewal with the auditor stopped. A zone whose owner removes a provider that leads the zone's group: the NS change is at the parent without waiting for a lease renewal.

**Step 7. The switch: every HSYNC3 provider is a member (#158).**
- Changes: 3.1. The group's key of design 4.1. The `join` and `role` requests. The displays of design 6. `guide/provider-changes.md` loses the "Today" notes of its sections 2 and 3.2.
- Unit: the two replaced tests of 3.2. Members, voting members and auditors for each kind of zone. Two zones with the same providers and another make-up are in two groups.
- Harness: the hello of a member with no role is accepted; it gets gossip and an answer to its request for state.
- Fleet: an add with the owner's two edits apart. After the first edit the newcomer is in every agent's gossip, reports the group's leader, has caught up with every voting member, and has its `addrr` refused. The zone is in the group that has the newcomer as a member with no role, and that group's leader has taken it up; a new group has elected, among its voting members. After the second edit the zone is in the group in which the newcomer votes. No sample is bogus or lame at any point. Then the removal's first edit: the zone moves to a group that the leaving provider cannot lead, at once.
- Not safe alone: it needs steps 1, 5 and 6, and step 4 on every agent for the newcomer to catch up by itself.
- For a leaving signer the last fleet test needs more than this plan. Today a signer that is taken out of `signers=` stops signing and drops to its combiner's serial, and its own agent refuses the lower serial: it stays on the old copy of the zone and does not see the owner's edit. The other agents refuse what it sends, so the zone stalls and is not harmed. That belongs to the removal (#147).

## 6. Decisions

Decided by the project owner on 2026-10-12. The design is written with them.

1. **How the asker knows that an answer is complete.** One message that is complete by construction, with a marker that names the request. A `replace` per type is a whole set, and the answer for one zone is small.
2. **A member with no role receives every distribution, and the distribution waits for its confirmation,** like any member. A provider on its way out still serves, and a new key of another signer must be at every server that still answers before it is used: the roll waits instead of answers going bogus. And being able to keep up with the other providers is a condition for serving the zone: if a provider cannot, that has to show before the zone owner gives it a role, not after.
3. **An auditor that is down does not hold an election back.** The gate is the voting members. A SYNC is another matter: where a zone has an auditor, the auditor is a required participant, and the SYNC is not complete without its confirmation.
4. **A group is the set of providers with roles together with the set of providers without a role** (and the auditors), which is not the same as the set of providers. A provider with no role in a zone cannot lead it. Elections are per group. A zone that joins or leaves a group forces no election: it takes the leader of the group it arrives in, and that leader takes the zone up.
5. **A peer asks a restarted agent back,** once, on a `start` request. It is the only thing that finds a change the restarted agent made and lost from its queue. The request after a long outage stays too. Safety first: neither is cut to save code.
6. **A member with no role gets the zone transfer set-up from its upstream.** The HSYNC3 record states the zone owner's intent.
7. **What a provider contributed stands, frozen, once its roles are gone,** until the removal takes it away. The provider cannot change it, its own DNSKEYs included, so its key machine holds for the zone while it leaves. The removal starts at the edit that takes the roles away, and the leader of the group the zone is then in is responsible for it.
8. **The whole sync with the parent waits for catch-up,** NS and glue as well as DS. A leader that does not have all the information is in no position to decide. A leader that has just started does not know what the parent holds either: it first gets the zone's data from the other agents, its combiner and its signer, then asks the parent, then sends the difference.

Also decided: tdns-mp does not support agents that are out of step with each other (section 4).

## 7. After this plan

A provider that is named in `signers=` while it runs does not sign until its signer is restarted (#146), and the key machine's `SignersChanged` has no caller (#136). Both need what the design gives a newcomer before it has a role: comms with every member, and the other signers' DNSKEYs with what they say about them. With that in place, calling `SignersChanged` from the refresh when `signers=` changes, and binding the signing policy at that moment, is the next step. It is not part of this plan.

What else the design leaves out is listed in its section 7.
