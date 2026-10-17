# Membership and catch-up: implementation plan

**Status:** PLAN, revised 2026-10-17. No step is started. Section 5 holds the status of each step.

This is the plan for the design in `2026-10-12-membership-and-catch-up-design.md` ("the design" below). The design describes membership and catch-up as they are meant to stand. This document holds what is dated: the difference from today's code, where each rule of the design lands in the code, the steps, and the decisions the design rests on.

For issues #158, #157, #172, #149, #137 (item 2), #131 and #132.

**Base.** This revision of the plan rests on these readings of tdns-mp:

- **main**, read at `90ca02c` for the first revisions. Since then PRs #161, #163, #164, #165, #168, #187 and #188 have merged; main is `a5dbede`, and it pins tdns at `3615261f` and tdns-transport at `b15bedb7`.
- **the integration branch**, `test/e2e-fix-round-2026-10-12`, read in full at `0e000da` and as a difference up to `4bf5afc`. It is now `d05bb1c`: main with the open pull requests, pinning tdns at `42c06637` (main with tdns PR #916) and tdns-transport at `8c5d0cf`.
- **the open pull requests a step needs first,** at the heads of 2026-10-15: #162 (`2bd8bf1`, with draft #193 `b5384dd` on top), #169 (`db29f4b`), #185 (`6a673ca`) and #186 (`8ba5984`). PR #185 changed after the earlier readings: its review commits rewrote the key set-up at a zone's arrival (2.10). PR #186 does not yet carry them.

A pre-review of 2026-10-15 checked every step's statements about the code against main, the integration branch at `4f52630` and those heads, and this revision takes its corrections. The steps are implemented on main after their pull requests have merged. What a step reads of the code is to be read once more against main on the day that step starts. Line numbers are given only where they help, with their revision.

Nothing was built or run for this document: every statement about the code is a reading of it. Where a reading could not settle a point, the text says "not established" and what would establish it.

## 1. What exists, and what is new

Most of the machinery of the design exists.

**Exists, and is used as it is:** discovery, hello, beat and gossip; provider groups; the election protocol and the lease; a participant that does not vote (the auditor); the request for a zone's state (RFI SYNC) and its answer (`resync-targeted`), today behind the operator's `resync --pull`; key states on a DNSKEY operation; the rule that a zone's DS set is unknown until every signing provider has spoken; the order guard for a `replace` that arrives late.

**Promised by the guide, and not done by the code:** `guide/synchronization-model.md` (section 2) says that an agent rebuilds its state after a restart from three sources: its combiner (RFI EDITS), its signer (RFI KEYSTATE) and each peer agent (RFI SYNC). The code asks the first two and never the third (2.5). Asking the peers at a start is therefore a repair of the existing design, not an addition to it.

**From pull requests, used by this plan.** Three are on main now; the others are open:

| What | Where it comes from |
|---|---|
| `isAmong`, and the sender check of the group election | PR #163 (#143), merged |
| `VotingMembersForZone`, `AuditorsForZone`, `isVotingMember` | PR #169 (#152), a draft |
| A refused beat back is sent again; a peer that refuses a hello, or whose key is wrong at discovery, is discovered again | PR #162 (#128, #84, #145) |
| A peer that keeps refusing beats, because it has a new key, is looked up again | PR #193 (#145), a draft on top of #162 |
| `tdns-mpcli agent parentsync status`, `election`, `inquire`, `bootstrap` | PR #164 (#32), merged |
| The leader makes the zone's CSYNC and sends it by SYNC; a CSYNC is taken from the leader only; the NOTIFY waits for every recipient's confirmation, then for the propagation delay, and the parent is checked again | PR #188 (#175, #151), merged |
| `DeliveredBy` on a remote update: the sender the transport established. A sync message with no transport sender is dropped | PR #188, merged |
| `RecomputeGroups` reports a zone that arrives in a group, and its leader takes it up (`SetOnZoneJoined`); at an arrival no SIG(0) key is made while the zone publishes one or a voting member has not answered | PR #185 (#179), a draft |
| Recomputes run one at a time; the heartbeat round holds no group lock across a callback; a group that loses its last zone drops its election state; a group's timers read the group when they fire | PR #186 (#180 to #183), a draft |

**New:**

1. Membership follows the HSYNC3 records, not the roles (design 1 and 2).
2. What a sender may do is checked per message, not by admission alone, and a message counts as sent by the sender the transport established (design 3).
3. The answer to a request for state is complete: every type, the key states, always sent, and marked (design 5.4 and 5.5).
4. The request is sent by the agent itself: at its start, when it joins a zone or gets its first role, when a peer says it has started, and after a long outage (design 5.1). A leader's sync with the parent waits for the answers (design 5.6).
5. A group is defined by its members together with what each one is, so that all its zones agree on who votes. The election's edges: no election without a vote, a leader when the voting members become one, and a leader that drops a zone which leaves its group (design 4).
6. An agent whose provider has no role refuses its operator's edits (design 6).
7. Two bounds on the beats that recover a peer: how often repeated hellos cause a beat back (#131), and what happens to the work on its way for a peer that is removed (#132). And the removal itself: comms with a peer end when no zone has been shared with it for a hold time (design 3.1).
8. Nothing is changed for a zone until its voting members agree on its make-up: while a zone is not settled an agent starts no distribution for it and takes none, and a leader sends nothing to the parent (design 4.9). A row of gossip lists a zone only while there is something to do for it. And every voting member holds the zone's SIG(0) key, which taking a zone up does not replace (design 4.1).

No message type is added. One optional object is added to the sync-family payload (3.4). Two config keys are added (steps 4 and 7). Nothing is added to a row of gossip: steps 9 and 9b change which zones a row lists.

Two changes outside tdns-mp:

- **tdns-transport carries gossip in the answer to an HTTPS beat,** as it does in the answer to a DNS beat (decision 26). Steps 9 and 9b need it: today an HTTPS answer has no gossip field. It is a change of tdns-transport and a new pin.
- **A tdns parent judges a bootstrap by what it finds** (decision 25, tdns #917). Nothing in this plan waits for it. Once it is in tdns, a zone whose key is lost recovers (step 9) instead of stalling.

## 2. What is wrong today

On a test fleet, a provider with an HSYNC3 record and no role in HSYNCPARAM:

- was in nobody's gossip;
- reported no leader when the zone had an auditor, and elected itself when it had none;
- had its request for state refused by the other agents ("NOTIFY returned rcode REFUSED");
- never got the other signers' DNSKEYs until it had a role and its operator asked by hand;
- had its operator's NS edit accepted by its own agent.

With every missing step taken by hand, in the required order, adding a provider produced no bogus and no lame sample. Separately, a leader that does not sign its zone was restarted and then logged "delegation data in parent is in sync with child, no action needed" with no DS at the parent. One zone waited 30 minutes for its DS, one never got it.

The files named below are the same on main and on the integration branch unless the text says otherwise.

### 2.1 Membership is derived from the roles

`zoneParticipants` (`v2/provider_groups.go`) returns the identities that hold a role: `servers=` and `signers=` (voting) and `auditors=` (not voting), each label resolved through the zone's HSYNC3 records in state ON. A record without a role is left out on purpose, and so is a record in state OFF. A zone with HSYNC3 and no HSYNCPARAM takes every ON identity (the legacy fallback).

Every question "who is in this zone" goes through it: `ParticipantsForZone`, `participantFQDNSetForApex`, `sharedParticipantZones` and `RecomputeGroups` in the same file, `GetZoneAgentData` and `GetAgentsForZone` (`v2/agent_utils.go`), `mpZoneView.Participants` (`v2/hsync_bridge.go`), and through that the hsync engine's `ApplyHsyncDiff` and `ReconcileZone` (`v2/hsync/`). So one set answers three questions: who is talked to, who votes, and who gets a distribution and is waited for. Only the vote is kept apart, as the `voting` subset.

A role given later to a record that is already there is a change of HSYNCPARAM alone. `HsyncChanged` (`v2/hsync_utils.go`) reports it, and `ApplyHsyncDiff` runs with no HSYNC3 add: the groups are recomputed, nothing marks the peer as needed, and `reattachHsyncMemberAdds` does not run. The periodic `ReconcileZone` (60 s by default) finds the peer.

### 2.2 Admission

The transport asks `IsPeerAuthorized` (`v2/agent_authorization.go`) twice for a message: before any crypto, with no zone (`isInHSYNCAnyZone`: known at all), and after parsing, with the message's zone (`isInHSYNC`). Both want the sender and the local agent to be participants of the same zone. A sender that fails gets rcode REFUSED. A peer the role's config names (an agent's own combiner and signer) is admitted before either.

For most messages that is the only check of who sent them. `MsgHandler` (`v2/hsyncengine.go`) checks that the zone exists and has an HSYNC3 RRset, not the sender's standing in it. The handlers behind it rest on the admission: a SYNC's operations are stored and passed to the combiner, an election message is counted (on main; PR #163 checks the group path), and `CONFIG sig0key` hands the zone's SIG(0) private key to a requester that the HSYNC3 `upstream` fields relate to the answering agent.

Two tests assert the refusal: the `RoleLessRejected` case of `TestTransportBoundary_HelloRejection` (`v2/transport_integ_test.go`), which calls itself a security regression test, and `TestApplyHsyncDiff_roleLessAddExcluded` (`v2/hsync/apply_hsync_diff_test.go`). The second does not test a record without a role: its excluded record is in state OFF, in a zone with no HSYNCPARAM.

### 2.3 What a provider with a record and no role gets

| | Today | Where |
|---|---|---|
| Discovery by the others | None | `ApplyHsyncDiff` skips "HSYNC3 record without a HSYNCPARAM role"; `ReconcileZone` expects participants only |
| Its own discovery of the others | Runs: the gate on local presence (`localInHsync3`) reads the raw RRset. Its hellos are refused | `v2/hsync/hsync3_diff.go`, `isInHSYNC` |
| Gossip | None, either way: it is in no group | `BuildGossipForPeer` (`v2/gossip.go`) wants both agents in the group |
| Distributions | None | `GetZoneAgentData` leaves it out of `Agents`; `getAllAgentsForZone`, `GetDistributionRecipients` and `EnqueueForZoneAgents` (`v2/hsync_transport.go`) read that |
| Its requests (RFI) | Refused at admission | `isInHSYNC` |
| A leader to report | None, or itself (2.4) | |
| Its operator's edits | Accepted by its own agent (2.8) | `v2/apihandler_agent.go` |

### 2.4 The election's counts, and the self-election

A group's election is started by the voting member with the lowest identity when the group reaches mutual OPERATIONAL (`wireAgentGossipCallbacks`, `v2/hsync_bridge.go`). `CheckGroupState` (`v2/gossip.go`) computes that over the list its caller passes, and all five call sites pass `pg.Members`, auditors included: the `BeforeHeartbeats` hook in `v2/hsync_bridge.go`, two in `v2/hsync_transport.go` (an inbound beat, and the gossip in a beat's answer), and two in `v2/hsync/` (`beat.go`, `transport_peer.go`) through `hsync.GossipPort`. So an auditor that is down holds an election back and invalidates a leader.

A zone that no group covers uses the per-zone election. Its count comes from `SetConfiguredPeersFunc` (`v2/start_agent.go`): the zone's participants minus one, auditors included, with no look at whether the local agent is one of them.

With zero expected peers `startElection` makes the local agent leader at once ("single agent, self-elected as leader") and runs `onLeaderElected`. `startGroupElection` has the same branch. Neither checks that the local agent has a role, and neither takes a new term. Four callers can get there: the first-load callback (`v2/start_agent.go`), the hook for an HSYNC3 add (`reattachHsyncMemberAdds`, `v2/agent_utils.go`), the lease renewal (`scheduleReelection`), and the per-zone path of the operator's `parentsync-election` (`v2/apihandler_agent.go`). The group path of that command does check that the local agent votes.

What issue #172 and the fleet saw, as the code gives it: a zone with one provider has one participant. That provider's agent counts 1 - 1 = 0 and leads, correctly. An agent that has the zone in its config and no role in it, with or without a record of its own, also counts 1 - 1 = 0, and leads too. With an auditor in the zone the count is 1: the agent with no role defers an election that never starts for it, and reports no leader.

A zone that the owner reduces to one provider gets no leader (#149): an election starts when a group becomes operational or when an HSYNC3 record is added. Here the group goes away, and nothing starts the per-zone election until the agent's next start.

Three more, found by reading:

- **A lone voter's leader is never told.** A self-election keeps the term it finds, zero at a first one. `GroupElectionForGossip` tells nothing of term zero, and `ApplyGossipElection` and `MergeGossip` take an election record only when its term is above the one they hold. An observer of a group with one voting member never learns its leader. Both functions keep the lease's end of the record they took (`LeaderExpiry`, which travels in the record), so an observer knows when the leader it holds has run out.
- **An agent that does not vote arms the lease's renewal.** `ApplyGossipElection` calls `scheduleGroupReelection` with no look at the local agent. On main, when that timer fires, `startGroupElection` counts the voting members minus one, which is wrong for an agent that is not among them, and broadcasts a CALL. With PR #163 the receivers drop it. With PR #186 the timer starts nothing on an agent that has no vote (`groupForTimer`).
- **`DeferGroupElection` starts nothing.** On main it writes `pendingGroupElections`, which nothing reads. PR #186 (#183) makes it a log line, `leaveElectionToGroup`. A group's election starts on the edge to mutual OPERATIONAL and at the lease's renewal, nowhere else.

### 2.5 What an agent asks at its start

At its start `SynchedDataEngine` (`v2/syncheddataengine.go`) hydrates each zone from the agent's own provider: the contributions its combiner holds (RFI EDITS, which returns every agent's contributions as the combiner stored them), and the key inventory of its signer. `reattachHsyncMemberAdds` asks an upstream or a downstream for the zone transfer set-up (RFI CONFIG) once that peer is OPERATIONAL.

No peer is asked about the zone's state. Two things live only at the peers: what each signing provider says about its keys (2.7), and any change that was sent while the agent was down and has left its sender's queue. The confirmed queue keeps a message for 24 hours, in memory: a sender that restarts loses what it had queued.

The hydration has two weak points of its own, which matter once an agent has to vouch for its state (design 5.4):

- It runs once, when the engine starts, over the zone names from the config. A request to the combiner that fails or times out (15 s) is logged and not repeated.
- The signer is asked only when the zone's multi-provider data does not read "not a signer". Until the zone's first load that data is the stub of `v2/main_init.go`, which reads as not a signer. Not established: whether the hydration normally finds the zone loaded. A harness test that starts the engine before the zone loads would establish it.

### 2.6 What the answer to a resync contains

`tdns-mpcli agent peer resync --pull` sends RFI SYNC to every agent of the zone that is OPERATIONAL, the auditor included, once each (`CommandHandler`, `v2/hsyncengine.go`). The receiver runs `resync-targeted` (`v2/syncheddataengine.go`): one SYNC to the asker alone, through the confirmed queue (`EnqueueForSpecificAgent`), with a `replace` for each RRtype of the answering agent's own records. It has four gaps:

- no key states on the DNSKEY operation;
- no operation for an RRtype the agent holds no record of, so the asker keeps what it had;
- no message at all from an agent that holds nothing, so "nothing" and "lost" look the same;
- nothing that ties the answer to the request, or says that it is everything.

The request is acknowledged by the router's handler (`handleAppRfi`, `v2/mp_verb_handlers.go`) before `MsgHandler` sees it. An error that `MsgHandler` finds later (an unknown zone, a failed `resync-targeted`) reaches nobody: the asker has its "ok".

### 2.7 Where the key states live, and when they are sent

A signing provider's agent attaches the key states (`core.RROperation.KeyStates`) in one place: `SyncRequestHandler` (`v2/hsyncengine.go`), when its signer's key inventory differs from what it last distributed. The receiver keeps them, and the DNSKEY records, in two maps in memory (`foreignKeyStates` and `foreignDnskeys` on `MPTransportBridge`, written by `NoteForeignKeyStates`, `v2/hsync_transport.go`). The field is encoded with `omitempty`, so the wire cannot say "spoken, no keys".

A leader whose own signer does not own the zone computes the zone's DS set from those maps (`computedDSIntent`, `v2/mp_s5_computed_ds.go`). The set is unknown while any provider in `signers=` has no entry in `foreignKeyStates`. After the leader's restart the maps are empty and nobody is asked. tdns then leaves the parent's DS alone, which is right, and reports the delegation as in sync when NS and glue match (`NewDSKnown` stays false). The agent's syncher logs "in sync" and ends its retry chain (`DelegationSyncher`, `v2/delegation_sync.go`; `delegationSyncSucceeded` on main, `delegationSyncInSync` on the integration branch). The sync is asked for again when the computed set changes, at an election, on the combiner's hint, or when the zone's NS or glue change. None of those follows from the restart.

`noteComputedDSSet` already asks for a sync when the set turns from unknown to known: `sameDSIntent` is false when one side is known and the other is not. What is missing is anything that makes a provider speak.

The sending agent's own restart sends nothing either, as far as the code reads. The start-up hydration stores the keys as already distributed and clears the remembered key states so that the next inventory carries them. The first zone load does ask the signer for its inventory (`MPPreRefresh`), but at that point the zone's multi-provider data is still the stub, which reads as "not signed", and `LocalDnskeysFromKeystate` returns no result. The states go out with the next inventory the signer sends by itself, which follows a key event.

`logSilentAgents` lists every agent of the zone that has sent no key states: the auditor, and also every server that does not sign. Neither holds a key.

### 2.8 The agent's own operator

`add-rr` and `del-rr` check `getEditPolicy().canSubmit` (`v2/apihandler_agent.go`, `v2/combiner_chunk.go`): `nsmgmt`, `parentsync`, and whether the provider signs. `EvaluateUpdate` (`v2/agent_policy.go`) checks `nsmgmt` for an NS record. Neither checks that the provider has a role. The edit is stored and sent to the provider's combiner and to the zone's agents.

### 2.9 Who sent a message

**The named originator.** Over the DNS mechanism the transport establishes the sender before it reads the payload: the NOTIFY's query name, and the key the payload is decrypted with. It admits that sender, and hands the application both names: `TransportSender`, and `SenderID` as the payload gives it. The agent's route functions read the payload's name and never compare the two: `routeHelloMessage`, `routeBeatMessage`, `routeSyncMessage` (the transport's sender is its fallback only), `routeStatusUpdateMessage` and `routeRelocateMessage` (`v2/hsync_transport.go`). So any admitted peer can name another: in a vote (PR #163's check reads the named sender), in a SYNC, in a hello (which earns the named peer a beat back, #131), and in a relocate, which then moves the named peer's address. One check does read the transport's sender, since PR #188: a CSYNC is taken only when the delivering agent and the named one are both the zone's leader (`refuseCsyncNotFromLeader`, `v2/mp_s5_leader_csync.go`).

**Over HTTPS there is no second name.** The receive pipeline takes the sender from the body (`RouteAPIPayload` in tdns-transport, `apiSyncEndpoint` in `v2/api_receive.go`). The sync router has verified the client certificate against the TLSA record of the certificate's name (`tlsaVerificationMiddleware`, `v2/apirouter_sync.go`), and does not pass that name on. `/hello` is outside that check. This is issue #56.

**The exclusion is not complete on the way out.** A peer with which comms are up and no participant zone is left reads as LEGACY (`effectiveAgentState`), and `IsPeerAuthorized` admits a LEGACY peer before it looks at the zone. `handleAppSync` then refuses its SYNC; `handleAppRfi` has no such gate. So a provider that loses its last role in the zones it shares with the receiver keeps the RFI verbs, for any zone the receiver has: SYNC, AUDIT, CONFIG, and on main the election messages. The fleet showed the way in. The way out was not run.

**The combiner checks the origin's role for DNSKEY only.** `checkDNSKEYPolicy` (`v2/combiner_chunk.go`) refuses a DNSKEY whose named origin is not in `signers=`, on a combiner that applies. For NS, KEY, CDS and CSYNC nothing looks at the origin's role. Where a combiner declines such an edit it is on other grounds: it does not apply a contribution to a signed zone when its provider is not a signer (`canApply`), and stores it. In an unsigned zone an NS edit from a provider with no role would be applied.

**`PostRefresh` turns parentsync on for a zone that does not list the agent.** It sets the option for any zone whose HSYNCPARAM says `parentsync=agent` (`v2/hsync_utils.go`; line 1546 on main, near line 1585 on the integration branch, where PR #185 moved it before the diff), without the check of the local identity that the first-load callback makes.

### 2.10 Groups

`RecomputeGroups` (`v2/provider_groups.go`) keys a provider group on the zone's participant list and skips a zone with fewer than two. The key does not say what each participant is. When zones with the same participants disagree about who votes, the group's voting members are the union, with a warning.

Five things around it were filed. All five have a change on the integration branch and none is on main:

- **A zone that moves into a group which has a leader is not taken up by that leader (#179).** On main the work a leader owes a zone is started by `onLeaderElected` at election events only. PR #185 makes `RecomputeGroups` report each zone that arrived in a group (`SetOnZoneJoinedGroup`, `zonesThatJoined`), and `zoneJoinedGroup` (`v2/parentsync_leader.go`) asks for the zone when this agent leads that group.
- **The heartbeat path can deadlock against a recompute (#180).** On main `BeforeHeartbeats` holds the group manager's read lock while it calls `CheckGroupState`, whose callback takes the same read lock again. PR #186 copies the groups out and calls with the lock free.
- **Two recomputes at once can install the older result last (#181).** PR #186 runs them one at a time, each from its scan to the last word of what it changed (`recomputeMu`).
- **The election manager is not told when a group disappears (#182).** PR #186 tells it (`SetOnGroupGone`, `groupGone`): the group's election state and timers are dropped, and the gossip table forgets the group's election record. This is design 4.8.
- **Leftovers (#183).** PR #186: a group's timers read the group when they fire (`groupForTimer`); `pendingGroupElections` is gone; and `ApplyHsyncDiff` recomputes the groups also when the local identity is not in the zone's HSYNC3 RRset.

Three things are still open on the integration branch, as read:

- **A zone that arrives while its group's election runs.** `finalizeGroupElection` asks for the zones its caller read when the last message of the election was handled, not for the zones the group has when the leader is set. A zone that arrives in between is asked for by nobody: the group had no leader when it arrived, and it was not on the list.
- **An agent that led the group the zone left is told nothing.** It stops by itself where it asks `IsLeader`, which reads the zone's group of the moment. A sync chain or a held NOTIFY for the zone stays until its next timer.
- **A new SIG(0) key at a move.** On main `leaderKeySetup(zone)` (`v2/start_agent.go`) uses a local key, else asks the zone's agents that are OPERATIONAL, else generates a keypair and publishes a `replace` of the KEY RRset. The asking seldom succeeds: the answering side hands the key only to a requester that is its upstream or downstream by the HSYNC3 `upstream` fields (`MsgHandler`, `sig0key`), and a refusal there sends no answer at all, so the requester waits out its time and reads "peer did not respond". Two signers have no such relation. On a test fleet a zone that moved to a group with another leader got a new key.

  PR #185's review commits (head `6a673ca`) changed this for an arrival. `leaderKeySetup(zone, elected)` counts the voting members that have not answered, and `mayGenerateZoneKey` (`v2/parentsync_utils.go`) lets an arrival make a key only when the zone publishes none and every voting member has answered. Otherwise it returns `errZoneKeyNotHeld`, and `SetOnZoneJoined` asks again through `zoneKeyWaits`: 30 s, then doubling to 15 minutes. The election path (`elected` true) still makes a key when no peer hands one over, and the answering side still hands the key to an upstream or downstream only.

### 2.11 The beats that recover a peer

`v2/hsync/beat_retry.go`. A hello from a peer whose mechanism is already introduced gets one beat back (`Engine.BeatPeer`, called from `routeHelloMessage`). On the integration branch a beat back that fails is sent again after the fast interval, twice at most (`Engine.beatBack`, PR #162).

**#131.** One beat back per peer is on its way at a time (`beatingBack`). Nothing sets a minimum gap between two of them, and the hello's sender is the one its payload names (2.9). So a peer that repeats its hello, or any admitted peer that names it, causes a beat back for each hello that arrives after the previous beat has returned.

**#132.** The engine keeps `beatFailing`, `beatRetrying` and `beatingBack` per peer identity. A retrier holds the `*Peer` it was started with for up to 30 s and checks only that the registry has a peer of that identity. `beatPeerOnce` (`v2/hsync/beat.go`) writes its `*Peer` back into the registry after every beat, and `sendHelloToPeer` (`v2/hsync/hello.go`) does the same after a hello. `beatFailing` is cleared only by a successful beat. So a beat or a hello that is on its way when its peer is removed puts the peer back, and a removed peer keeps its failure marker, which keeps a retrier from starting when the identity returns.

Three readings bound the issue:

- `Engine.RemovePeer` has no caller outside its own test, on either revision. A peer that leaves its last shared zone stays in the registry as LEGACY, and is beaten at every round for as long as the daemon runs. Nothing replaces a stored peer with another object. The faults of #132 are therefore latent: they become real with the first caller of `RemovePeer`, which step 7 adds.
- The engine's set of zones per peer is not the set of shared zones. `ReconcileZone` (`v2/hsync/reconcile.go`) marks every participant of a zone as needed whether or not the local agent is one of them: it has no gate like the one `ApplyHsyncDiff` has (`GateOnLocalPresence`). An agent whose own record has left a zone therefore keeps that zone on its peers for as long as the zone is in its config. And a zone that leaves the config is never taken off its peers: `reconcileAllZones` visits only the zones the agent has.
- The beat's sequence number is read from the transport's count of successful beats, sent, and echoed. Nothing on the receiving side, in tdns-mp or in tdns-transport at the pinned revision, compares it with an earlier one. Beats from several loops can carry the same number, and nothing depends on it. Beats to one peer need not be sent one at a time.

### 2.12 Found on the way

- **A multi-operation update reports only its last `replace`.** `processOperations` (`v2/agent_policy.go`) assigns the result of each `replace` to `changed` instead of adding to it. An update with several `replace` operations whose last one changes nothing is stored and not passed to the combiner. The complete answer of design 5.4 always has three to five.
- **An update that changes nothing and lists nothing is never confirmed.** The short path for a remote update whose result is already there (`SynchedDataEngine`, the `remote` case) sends the final confirmation only when it has at least one applied or removed record to report. An answer of empty `replace` operations would stay in its sender's queue until it expires.
- **The sync-family payload has two types.** The sender marshals `core.AgentMsgPost`, a type of tdns (`syncAppMessage`, `v2/mp_send.go`). The receiver parses `DnsSyncPayload`, tdns-mp's own (`v2/mp_wire_payloads.go`). The sent form has no distribution ID in it: over DNS that travels in the query name, and over HTTPS the receiver makes a new one. Two agents' distribution IDs can coincide. So a request cannot be named by its distribution ID.
- **`GetZoneAgentData` relates upstream and downstream through every HSYNC3 record,** OFF ones included.

### 2.13 Nothing waits for the agents to hold the same make-up

Each provider fetches the owner's zone on its own. So for a time after an owner's edit the agents hold different versions of who the zone's members are. Nothing in the code looks for that.

- **Each agent acts by its own copy.** The recipients of a distribution (`GetDistributionRecipients`), the admission of its sender, and who leads the zone are read from the agent's own copy of the zone at that moment.
- **A SYNC is taken as it comes.** `routeSyncMessage` answers PENDING at once and passes the update on. The data engine stores it and passes it to the combiner, and the final confirmation follows. An auditor confirms when it has logged the event.
- **A local change is sent as it comes.** The `local` case of the data engine stores the update and sends it, to the combiner and to the zone's agents, in one pass.
- **A leader syncs as it comes.** For the time the copies differ, the leader of the group the zone left and the leader of the group it arrived in can both send to the parent, each from its own view.
- **What an agent tells of a zone can be stale, or double.** Its row of a group lists the group's zones as they were at the last beat round, and a message is built from the groups of the moment and the rows of the last round. Nothing acts on the lists today: they are shown, and `gossip state --zone` falls back on them when the group manager has no group for the zone.

## 3. The design in the code

Where each rule of the design lands. The design's sections are named as "design N". The steps are those of section 5.

### 3.1 Membership (design 1 and 2)

One new helper says what the zone makes of an identity, and several steps use it. Proposed, in `v2/provider_groups.go`, from step 1:

```go
type standing int

const (
    standingNone    standing = iota // no HSYNC3 record in state ON
    standingNoRole                  // an ON record, in none of servers=, signers=, auditors=
    standingAuditor                 // in auditors= only
    standingVoting                  // in servers= or signers=
)

func zoneStanding(apex *tdns.OwnerData, identity string) standing
```

It reads the records. Who is talked to stays a separate question until step 10.

| Function | Today | Change | Step |
|---|---|---|---|
| `zoneParticipants` | Role holders, and the voting subset | Returns three sets: members (every ON record), voting members, auditors. The legacy fallback is unchanged | 10 |
| `ParticipantsForZone`, `participantFQDNSetForApex`, `sharedParticipantZones` | Role holders | Members. No change of their own: they follow `zoneParticipants` | 10 |
| `isInHSYNC`, `isInHSYNCAnyZone`, LEGACY (`effectiveAgentState`, `isKnownLegacy`) | Both must hold a role | Follow: both must be members. A peer whose roles are gone and whose record stays is a member, not LEGACY. A LEGACY peer is kept for the hold time and then removed (step 7) | 7, 10 |
| `mpZoneView.Participants`, `ApplyHsyncDiff`, `ReconcileZone` | An add with no role is skipped | Follow: a member is registered and discovered. An OFF record is skipped as today | 10 |
| `GetZoneAgentData` | `Agents` are the role holders | `Agents` are the members, each with its standing. The callers that mean a vote already filter (step 6) | 10 |
| `beatZones`; the zones a hello names (`Registry.sharedZones`, fed by `ApplyHsyncDiff` and `ReconcileZone`) | Shared participant zones | Follow: shared member zones | 10 |
| `reattachHsyncMemberAdds` | CONFIG requests for a role holder; an election kick | CONFIG requests for a member, with no change of its own. The kick goes | 8, 10 |
| `SetConfiguredPeersFunc`, `SetOperationalPeersFunc` | Participants minus one; OPERATIONAL agents of the zone | Voting members other than this agent; the OPERATIONAL ones among them | 1 |
| `RecomputeGroups`, `ComputeGroupHash` | Key and hash from the participants; voting members are the union | Key and hash from the members with what each one is. No union | 8 |
| `logSilentAgents` | Every agent of the zone | The providers in `signers=` | 2 |
| `populateMPdata`, guard 3 | A zone without a record of this provider is not a multi-provider zone for it | Unchanged | |

### 3.2 Senders and recipients (design 3)

**The sender the transport established.** One middleware on the router of the agent and of the auditor, before any handler, refuses a message whose payload names another sender than the one the transport established (step 6). It covers every verb at once. A combiner's router does not get it: there the deliverer and the named origin differ by design.

Over HTTPS the middleware has nothing to compare (2.9). There the sender the transport established is the name in the client's certificate (design 3.2, decision 9). The pipeline in tdns-transport takes no sender beside the body, so step 6 makes the comparison in `apiSyncEndpoint`, before the body enters the pipeline, for the three endpoints behind the TLSA check: `/beat`, `/sync/ping` and `/msg`, on the sync routers of the agent and of the auditor. A combiner's sync router uses the same endpoint, and there `/msg` takes contributions whose originator is not the delivering agent: it is not checked. `/hello` is outside that check, because a peer's TLSA record need not be known when its hello arrives. It stays with issue #56, and so does the choice of the certificate's identity field: step 6 reads the common name, as the TLSA check does today.

**What each message asks of its sender** (design 3.3). The checks sit in the router's handlers, not in `MsgHandler`, so that a refusal is on the wire with its reason:

| Message | Check | Where | Step |
|---|---|---|---|
| Hello, beat | Admission | Unchanged | |
| Gossip | The group is known here and the sender is a member of it. From a member that does not vote: its own row only | `MergeGossip` gets the sender and the group | 6 |
| SYNC | The sender is a voting member of the zone | `handleAppSync` | 6 |
| The same operations, at a combiner | The named origin is a voting member of the zone | `CombinerProcessUpdate` | 6 |
| Election | The sender is a voting member; the local agent is one | `HandleGroupMessage` (PR #163), `HandleMessage` | 1 |
| RFI SYNC, RFI AUDIT | The sender is a member of the zone | `handleAppRfi` | 6 |
| RFI CONFIG `upstream`, `downstream` | The sender is a member of the zone, related by an ON record's `upstream` field, and not an auditor only | `handleAppRfi`, `GetZoneAgentData` | 6 |
| `CONFIG sig0key` | A voting member of the zone; the upstream relation is no longer asked for (decision 15) | `handleAppRfi` | 6 |

A STATUS-UPDATE and a RELOCATE have no rule of their own (design 3.3): they are admitted, and the sender rule holds for them. A STATUS-UPDATE from a peer can at most ask this agent to look at the parent, and a relocate can then move only its sender's own address.

**What is sent to whom.** Step 6 makes each sender choose its recipients by standing, while `Agents` still holds role holders. Step 10 then widens `Agents` and nothing else changes:

| Sent | To | Function |
|---|---|---|
| Distributions, and the wait for confirmations | Every member | `EnqueueForZoneAgents`, `GetDistributionRecipients`, `TrackDnskeyPropagation`: unchanged in whom they name. Step 9 adds when: a distribution is started, and taken, only for a zone that is settled (design 3.3, 4.9) |
| Election messages | Voting members and auditors | `broadcastElectToZone` |
| Requests for the zone's state | Voting members | `CommandHandler` (`send-rfi`), the tracker of step 4 |
| The request for the SIG(0) key | Voting members, and the leader of the group the zone left while it is a member (decision 18). Sent by every voting member that lacks the key, not by the leader alone | `leaderKeySetup` (`v2/start_agent.go`), `keyCheck` (step 9), `CommandHandler` |
| "parentsync-done" | Every member | `notifyPeersParentSyncDone`: unchanged |
| The leader's CSYNC (PR #188) | Every member, and the leader's own combiner. The NOTIFY waits for the final confirmation of each, with no time-out | `distributeCsync`, `GetDistributionRecipients`: unchanged |

**The leader's CSYNC, where two rules meet.** Since PR #188 the zone has one CSYNC, the leader's, sent as the leader's own contribution by SYNC. Two rules then apply to it at a receiving agent, one after the other, and they do not conflict:

1. Step 6, in the router's handler: the sender of a SYNC is a voting member of the zone. A leader always is one.
2. PR #188, in the data engine: a CSYNC operation is taken only when the delivering agent and the agent the update names are both the leader this agent knows for the zone (`refuseCsyncNotFromLeader`). The other operations of the same update go on. The deliverer is read from `DeliveredBy`, which step 6's middleware makes the same as the named sender for every message.

Three consequences are worth knowing:

- **Whom the NOTIFY waits for.** The leader's own combiner and every agent that `GetZoneAgentData` lists: today the role holders, the auditor among them, and after step 10 every member, a member with no role among them. That is decision 2. There is no time-out. So after step 10 a member with no role whose agent is stopped holds every NOTIFY(CSYNC) of the zone until its record is removed. An UPDATE to the parent is not held. From step 9 each agent among them confirms only once the zone is settled there. The auditor confirms at once, as before, and so does the leader's own combiner, which has no settle rule.
- **The exception of decision 2 does not reach it.** The exception names a distribution that withdraws a member: its own NS records, DNSKEYs or DS. The CSYNC is not one of those, and it is what carries an NS change, a leaving provider's NS records included, to a parent that takes NOTIFY only.
- **A catch-up answer.** Design 5.4: an answer names NS, CDS and DNSKEY, and only the leader's answer names the zone's KEY and its CSYNC, which are the group's. For the CSYNC the code agrees since PR #188: a CSYNC operation from an agent that does not lead the zone is taken out and answered with a final confirmation REJECTED, an empty `replace` too. For the KEY it does not yet: today the KEY is a contribution of the agent that published it. Step 3 is written for the CSYNC, and step 9 moves the KEY.

What the leader's CSYNC waits for when a provider leaves is parked in the removal (decision 17, 7.4). No step of this plan changes it.

### 3.3 Elections (design 4)

| Design | In the code | Step |
|---|---|---|
| 4.1 The group is its members with what each one is | `RecomputeGroups`, `ComputeGroupHash`, `ProviderGroup` | 8 |
| 4.1 A zone that arrives takes the group's leader, and the leader takes it up | PR #185. This plan adds nothing to it | before 8 |
| 4.1 Every voting member holds the zone's SIG(0) key; a new one only when every voting member has answered that it holds none | `keyCheck`, the `sig0key` case of `MsgHandler`, `leaderKeySetup` | 9 |
| 4.1 The KEY record is the group's, published by the leader | `leaderKeySetup` publishes it at every take-up already. New: it is taken from the leader only (step 9). That a member drops a KEY held under an earlier publisher's name is needed first at a roll, and goes with it (7.4) | 9, the roll |
| 4.1 An agent that led the group the zone left stops acting for it | `zoneJoinedGroup` drops the zone's sync chain, and from step 9 what it owes the parent for the zone | 8, 9 |
| 4.2 The counts | The two peer functions | 1 |
| 4.3 The gate | The five callers of `CheckGroupState` pass the voting members | 8 |
| 4.4 Start, vote, win | `startElection`, `startGroupElection`, `HandleMessage`, the two `finalize` functions, `ApplyGossipElection` | 1 |
| 4.5 One check for every change | A new `zoneChanged` on the election manager, called from `PostRefresh` | 8 |
| 4.6 One voting member; a term for a self-election | The two self-election branches take the next term | 8 |
| 4.7 What a member that does not vote takes | A newer term from a voting member at once, as today. A lower one once the lease it holds has run out: `MergeGossip`, `ApplyGossipElection` | 8 |
| 4.7 What it reports | The status commands say that this agent does not vote | 10 |
| 4.8 Retiring a group | PR #186 (#182). Not a step of this plan | before 8 |
| 4.9 A zone is settled | `zoneSettled`: since when the make-up is held, kept by the group manager, and what each voting member has told, read first hand per peer | 9 |
| 4.9 Nothing is started | The `local` case of the data engine, where a local change becomes a distribution; the answer to a request for state; `resync --push` | 9 |
| 4.9 Nothing is taken | The `remote` case of the data engine; the auditor's confirmation. The delivery is acknowledged, and the final confirmation waits | 9 |
| 4.9 A leader sends nothing to the parent | `syncHeld`, in the place of step 5's hold and in `leaderKeySetup` | 9 |
| 4.9 The telling: a zone is listed once it has been held for the fixed time | `BuildGossipForPeer`. A row lists every zone of its group today | 9 |
| 4.9 The telling: and only while it is of interest | The same builder, per peer: an ask in a beat, the answer in the answer to it | 9b |
| 4.9 A zone that arrives while an election runs | `finalizeGroupElection` reads the group's zones when it sets the leader | 8 |

### 3.4 Catch-up (design 5)

**On the wire.** One optional object at the top level of the sync-family payload, JSON key `catch_up`. Proposed:

```go
// CatchUp travels on an RFI SYNC, and on the SYNC that answers it.
type CatchUp struct {
    Request  string `json:"request"`            // the request's name, chosen by the asker
    Reason   string `json:"reason,omitempty"`   // on the request: start, join, role, peer-role, peer-start, outage, manual
    Complete *bool  `json:"complete,omitempty"` // on the answer
    Why      string `json:"why,omitempty"`      // on the answer, when it is not complete
}
```

- On an RFI SYNC it carries `request` and `reason`. The name is a new ID from the asker's own generator (`transport.GenerateDistributionID`). It has to be unique per asker only.
- On the answer it carries the same `request`, `complete`, and `why` when not complete: `no-inventory`, `own-state-not-read` or `zone-not-loaded` (proposed).
- A SYNC without `catch_up` is an ordinary distribution. An answer whose `complete` is absent reads as not complete. An RFI SYNC without `catch_up` is answered, and the answer names no request, so it matches none and counts for nothing. None of this is code for a peer out of step: it is what the fields mean.

The sender marshals a type of tdns (2.12). To add the field without a change in tdns, `syncAppMessage` marshals a struct of tdns-mp's own that embeds `core.AgentMsgPost` and adds `CatchUp`: the bytes are the same when the field is nil. `DnsSyncPayload` gets the same field for the receiving side. Inside tdns-mp the object rides on `PeerSyncRequest`, `ZoneUpdate`, `AgentMsgPost`, `SynchedDataUpdate` and `SynchedDataCmd`, one pointer field each.

**The flow.**

| Design | In the code | Step |
|---|---|---|
| 5.3 The request | `sendRfiToAgent` with `catch_up`. A plain send; the router's acknowledgement is its synchronous answer | 3 |
| 5.4 The answer | `resync-targeted`, rewritten: a `replace` for each type the agent may contribute, the key states, always sent, marked | 3 |
| 5.4 At the asker | `EvaluateUpdate` and `ProcessUpdate` as any remote update; `noteReplaceOrigin` keeps an older message from undoing it; `NoteForeignKeyStates` takes a complete answer as having spoken | 3 |
| 5.1 When | The edge to OPERATIONAL in `SendBeatWithFallback`; the zone's first load; a standing that rises at a refresh; a `start` request received | 4 |
| 5.5 The tracker, 5.7 the retries, 5.8 the pacing | New, `v2/catchup.go` | 4 |
| 5.6 What waits | `DelegationSyncher`, both sync commands | 5 |
| 5.6 "DS set unknown, waiting for" | `DelegationSyncher`, when the analysis has no DS set to compare | 5 |
| 4.9 The answer is a distribution, and waits | Owed at the answering agent and kept at the asker, until the zone is settled at each. The tracker's time for an answer follows | 9 |

### 3.5 The agent's own operator (design 6)

- `add-rr`, `del-rr` and `update-local-zonedata` refuse, and so does the `local` case of `EvaluateUpdate`, so that no other path gets past. That case also takes the DNSKEY distribution that follows the signer's inventory (`SyncRequestHandler`). This is item 2 of #137. Step 2.
- `parentsync-election` and `parentsync-bootstrap` refuse. Step 2.
- `resync --push` sends nothing to peers and says why. Step 2.
- `zone mplist` gets each member's standing. `agent parentsync status` gets the standing of this agent, the learned leader and term, and the tracker's state per voting member. Steps 4 and 10. The mpcli command exists with PR #164.

What design 2.3 asks of a provider that has lost its roles, to go on as before and to initiate nothing, has two sides. The agent's side is step 2: nothing that such a provider would contribute leaves its agent. What the others distribute it takes, applies and confirms as before, and from step 9 by the settle rule, as every member does. The signer's side is not in this plan: that it goes on signing and following the zone, and that its key machine makes no transition for the zone meanwhile. Today a signer that is taken out of `signers=` stops signing altogether (#147), and its agent and its nameserver stay on the copy from before the edit (decision 20). Both belong to the removal.

## 4. Agents in step

tdns-mp does not support agents that are out of step with each other: all agents of a zone must be in sync protocol-wise. So this plan has no code for a peer that runs an earlier build:

- no detection of a peer that answers a request for state without the marker;
- no order among the zones a beat or a hello names;
- no fallback for a group in which some agents count members and others count role holders, or compute the group's hash from another key;
- no reading of a peer whose gossip rows do not list its zones as this plan has them listed: it reads as telling no make-up for them, and nothing is started or taken for them (step 9). Agents of step 9 and agents of step 9b do not mix either.

An agent that is out of step shows as a stall, not as harm. Its answer has no marker, so it does not count as complete and is asked for again (design 5.7). A zone is in different groups on the two sides, and the sides agree on no leader for it.

Two rules for operators follow:

1. Every step of section 5 goes to all agents of a zone together. For step 8 that includes the auditor: the group's hash changes for every group. For steps 9 and 9b too: nobody waits for what an auditor tells, and it confirms a distribution when it arrives, but its own rows are built by the same rule.
2. Every agent of a zone runs the whole design before the owner starts a provider change in it.

## 5. The steps

Each step is one pull request. Each of steps 1 to 9b is safe to merge once what its "Needs first" column names is in, and changes nothing for a zone in steady state except what the step names. Step 10 is the switch and needs the others.

The sizes are estimates from reading the code, tests apart: files touched, and lines new and changed. They are an order of magnitude, not a count. Tests are likely to be two to three times as many lines.

| Step | What | Issues | Needs first | Files | New | Changed | Mostly | Status |
|---|---|---|---|---|---|---|---|---|
| 1 | No election without a vote | #172 | PR #163 (merged), PR #186 and through it PR #185, PR #169's helpers | 4 | 80 | 40 | Guards | Not started |
| 2 | An agent with no role refuses its operator's edits | #137 item 2 | Step 1 | 4 | 50 | 20 | Guards | Not started |
| 3 | The complete answer | #157 | None (PR #188 is merged) | 10 | 210 | 120 | Changes to existing functions | Not started |
| 4 | Asking by itself | #157 | Steps 1 and 3, PR #162, PR #193 | 8 | 470 | 80 | New machinery | Not started |
| 5 | The sync with the parent waits | #157 | Step 4 | 5 | 110 | 40 | Guards, and a little state | Not started |
| 6 | A rule for the sender and the recipients of every message | | Step 1 | 9 | 150 | 80 | One middleware, guards | Not started |
| 7 | Beats to a peer that repeats its hello, or is gone; the end of comms | #131, #132 | Step 6, PR #162, PR #193 | 10 | 140 | 40 | Guards, and one loop | Not started |
| 8 | The group by its make-up, and its election | #149 | Steps 1 and 6, PR #185, PR #186 | 8 | 140 | 120 | Changes to existing functions | Not started |
| 9 | Nothing is started or taken for a zone until its voting members agree on its make-up; the zone's SIG(0) key | | Steps 3 to 6 and 8, PR #185, the tdns-transport change of decision 26 | 22 | 790 | 200 | New state and three holds | Not started |
| 9b | A row lists a zone only while there is something to do for it | | Step 9 | 8 | 155 | 95 | Changes to existing functions | Not started |
| 10 | The switch: every HSYNC3 provider is a member | #158 | Steps 1, 2, 6, 8 and 9; steps 3 to 5 and 7 on every agent | 9 | 80 | 150 | Changes to existing functions | Not started |

About 2,400 new and 990 changed lines in all. Steps 4 and 9 are over half of the new lines, and step 9 alone is a third. Its two parts can be two pull requests: the settle rule, about 600 new lines, and the key, about 190.

What kind of code each step is:

- **Guards in existing functions:** steps 1, 2 and 7, most of 5 and 6, and the leader's hold of step 9.
- **Changes to what existing functions do:** steps 3, 8, 9b and 10, the key set-up of step 9, and in step 9 the two cases of the data engine that send and take a distribution. Each is split where it sends or stores, and the second half waits.
- **New machinery:** the tracker of step 4, the sender middleware of step 6 (about 30 lines), the repeated own read of step 3 (about 40 lines), the removal of a peer that shares no zone in step 7 (about 40 lines), `zoneChanged` of step 8 (about 40 lines), and in step 9 since when a make-up is held and what each peer told (about 135 lines), the check and its times (about 85 lines), the list of what is kept per zone and its release (about 150 lines), and the zone's key: who holds it, the request of every voting member, its answers matched and counted (about 150 lines).

### Step 1. No election without a vote (#172)

**Before it:** PR #163, for `isAmong` and the sender check of the group path; it is merged. PR #186 edits the same functions (`startGroupElection`, the timers): this step is made on top of it. PR #186 is a draft on an old head of PR #185, and both conflict with their bases today. If they are still drafts when this step starts, it is made on main alone, and PR #186 is brought up to it afterwards. The three helpers of PR #169 (`VotingMembersForZone`, `AuditorsForZone`, `isVotingMember`) are needed too. PR #169 is a draft that waits for another reason, so this step brings them, taken as they stand in that pull request, unless it has merged.

**Changes.**

- `v2/provider_groups.go`: `standing` and `zoneStanding` (3.1). A zone with HSYNC3 records and no HSYNCPARAM is the legacy case (design section 1): every ON record is `standingVoting`, as `zoneParticipants` has it today. Who votes has one derivation: `zoneStanding` reads it from `zoneParticipants`' voting set, and `VotingMembersForZone` and `isVotingMember` read the same set.
- `startElection`, `startGroupElection` (`v2/parentsync_leader.go`): return, with a debug line, when the zone has an HSYNC3 RRset and the local agent is not among its voting members. For a group the test is `isAmong(members, lem.localID)`. A zone with no HSYNC3 RRset is not a multi-provider zone and elects as before. This covers the four callers of 2.4, and a fifth: `NotifyPeerOperational`, which starts a deferred election when a peer becomes OPERATIONAL.
- The zero-peer branch of `startElection`: with zero voting peers counted it self-elects only when no group covers the zone. When a group covers it, the group's election decides (design 4.5 and 4.6): a group whose one voting member is this agent meets its gate with its own row. Today every zero-peer path self-elects per zone without looking for a group, which is right only while a count of zero means a single participant.
- `SetConfiguredPeersFunc`, `SetOperationalPeersFunc` (`v2/start_agent.go`): the voting members other than this agent, and the OPERATIONAL ones among them.
- `HandleMessage`: drops a CALL, VOTE or CONFIRM whose sender is not a voting member of the zone, and returns when the local agent is not one. As `HandleGroupMessage` does with PR #163.
- `finalizeGroupElection`, `finalizeElection`: a winner that is not a voting member is not taken. The election counts as having found no consensus.
- The exemption holds in all three: for a zone with no HSYNC3 RRset, `HandleMessage` and the two `finalize` functions check no standing. `isVotingMember` is false for a zone it does not know, and the existing per-zone election tests load no zone data.
- `ApplyGossipElection`: arms no renewal timer when the local agent is not among the group's voting members. With PR #186 such a timer starts nothing (`groupForTimer`); this takes the timer away.
- `PostRefresh` (`v2/hsync_utils.go`): turns parentsync on only when the local identity matches an HSYNC3 record (`matchHsyncIdentity`), as the first-load callback does.

**Names.** Log, debug, logger `elect`: "no election started: this agent does not vote in the zone", with `zone` or `group`. Log, warn: "election: the winner is not a voting member, not taken", with `zone` or `group`, `winner`, `term`.

**Tests.** Unit, in a new `v2/parentsync_leader_role_test.go`:

- `TestAnAgentWithNoRoleStartsNoElection`: from each of the five callers. After this step's count it has a non-zero count, so the guard is what stops it, not the zero branch.
- `TestAZeroPeerCountDefersToAGroupThatCoversTheZone`.
- `TestAZoneWithoutHSYNC3ElectsAsBefore`.
- `TestThePeerCountsAreTheVotingMembers`: an auditor and a record with no role are not counted.
- `TestAPerZoneVoteCountsOnlyFromAVotingMember`.
- `TestAWinnerThatDoesNotVoteIsNotTaken`.
- `TestAnObserverArmsNoRenewalTimer`.
- `TestParentSyncIsNotTurnedOnForAZoneThatDoesNotListThisAgent`.

Harness: `electionNet` (`v2/parentsync_leader_renewal_test.go`), `TestOneProviderAndAnAgentWithNoRoleHaveOneLeader`: two managers, one zone with one provider, the other agent has a record and no role.

Fleet: a zone with one provider and a second agent that has a record and no role, with no auditor. One "self-elected" line in the whole fleet. The status of the second agent shows no leader of its own.

**Done when** the fleet check passes with and without an auditor in the zone, and a run with no provider change shows no difference in who leads.

### Step 2. An agent with no role refuses its operator's edits (#137 item 2)

**Before it:** step 1, for `zoneStanding`.

**Changes.**

- `APIagent` (`v2/apihandler_agent.go`), `add-rr`, `del-rr` and `update-local-zonedata`: before the edit policy, refuse when the zone has an HSYNC3 RRset and the local standing in it is not voting. A zone with no HSYNC3 RRset is left as it is, as in step 1. `update-local-zonedata` has to be refused here: it goes through `MsgQs.Command` and `CommandHandler` onto the update queue before `EvaluateUpdate` runs.
- `EvaluateUpdate` (`v2/agent_policy.go`), the `local` case: the same refusal, first, so that no other path gets past. Its local producers are the operator's edits, the DNSKEY distribution after an inventory, and since PR #188 the leader's CSYNC (`distributeCsync`). A leader that has lost its roles keeps its lease until step 8. Its CSYNC is then refused, the refusal reaches `delegationCsyncStep` as an error, and the sync fails, which is right for an agent that no longer votes.
- `SyncRequestHandler` (`v2/hsyncengine.go`): the same test before `LocalDnskeysFromKeystate`, which records the keys and their states as distributed before the update reaches `EvaluateUpdate`. Without it a refused distribution would be remembered as sent, and the update has no channel to report the refusal on.
- `parentsync-election`, `parentsync-bootstrap`: refuse before anything else.
- `resync` (`SynchedDataEngine`): it has three sends. On an agent with no role: its own data to the zone's agents goes, and it says so. Proposed: its own data to its combiner goes too, since an empty `replace` there would change what the provider contributed. The third, every other agent's data to its own combiner under their names, goes on: it repairs the combiner from what the others contributed and changes nothing of this provider's.
- `logSilentAgents` (`v2/hsync_transport.go`): reads the providers in `signers=`, not every agent.

What such an agent takes is not changed by this step. Design 2.3 has it take what the others distribute, apply it and confirm. From step 9 it does so when the zone is settled at it, as every member does.

**Names.** The refusal of an edit: "zone %s: this provider has no role in the zone (it is listed under neither servers= nor signers=); nothing is stored and nothing is sent". Of an election: "this provider cannot lead zone %s: it has no role in it". Of the push: "zone %s: nothing sent to the other agents: this provider has no role in the zone".

**Tests.** Unit, with the API handler tests (`v2/apihandler_agent_test.go`):

- `TestAnAgentWithNoRoleRefusesItsOperatorsEdits`: the three commands; nothing reaches the update queue.
- `TestALocalUpdateFromAnAgentWithNoRoleIsRefused`: `EvaluateUpdate`, a DNSKEY distribution included.
- `TestAnAgentWithNoRoleCannotBeAskedToLead`.
- `TestResyncPushFromAnAgentWithNoRoleSendsNothingToPeers`.
- `TestOnlySigningProvidersAreNamedSilent`: no auditor, no server that does not sign.

Fleet: `addrr` on a provider with a record and no role is refused; its combiner holds nothing new.

**Done when** the fleet check passes, and the same commands work as before on an agent with a role.

### Step 3. The complete answer (#157, the answering side)

**Before it:** nothing. PR #188, for the rule of who may send a CSYNC (3.2), is merged.

**Changes, the wire.**

- `v2/mp_wire_payloads.go`: `CatchUp` (3.4), and the field on `DnsSyncPayload`.
- `v2/mp_send.go`, `syncAppMessage`: marshals the embedding struct.
- One pointer field on `PeerSyncRequest`, `ZoneUpdate`, `AgentMsgPost`, `SynchedDataUpdate`, `SynchedDataCmd`, each tagged `json:"catch_up,omitempty"`. `sendRfiToAgent`, `deliverGenericMessage`, `routeSyncMessage` and `MsgHandler` pass it along.
- Golden files: `DnsSyncPayload.json` regenerated; two new sent forms, `send-rfi-catchup.json` and `send-sync-catchup.json`. `send-sync.json` and `send-rfi.json` must not change, and neither must the API bodies that `TestGoldenAPIBodies` locks (`msg-sync-request`, `msg-rfi-request`): tdns-mp's `AgentMsgPost` has untagged fields, and a pointer without `omitempty` would add a `null` there.

**Changes, the answering agent.**

- The combiner, `sendEditsToAgent` (`v2/combiner_msg_handler.go`): it answers RFI EDITS only for a zone whose stored contributions it has loaded (`contributionsLoaded`, `v2/combiner_chunk.go`). Before that it answers that they are not loaded, with no records. Today it answers from memory, and before the zone's first load that is an empty map: an agent that counted it as its own state would send a complete answer of empty `replace` operations, and remove its NS, DNSKEY and CDS at every peer.
- `SynchedDataEngine`, the own read. A mark per zone, proposed `ownState` on `ZoneDataRepo`: when the combiner's contributions were read, and when the signer's inventory arrived. `RequestAndWaitForEdits` reports whether it applied an answer, and an answer that says the contributions are not loaded does not count. A zone whose own read is not done is read again, one zone per 30 s tick, once the zone has loaded: the combiner, and for a provider that signs with no inventory, the signer. This closes the two weak points of 2.5.
- Where the re-read runs: in the engine's own loop, on a new 30 s ticker beside the eviction ticker, as a command like the others. A tick blocks the engine for as long as its request waits, 15 s at most, and only while some zone's own read is not done, which is after a start. Run anywhere else, it would race `resync` for the one `EditsResponse` channel, on which an answer for another zone is dropped as mismatched.
- `resync-targeted` becomes one function, proposed `catchUpAnswer(zone, target, request)`:
  1. It is not complete when the zone has not loaded (`zone-not-loaded`), when the own read from the combiner is not done (`own-state-not-read`), or when the provider signs and no inventory is there (`no-inventory`). A not complete answer carries the marker and no operation (design 5.4): empty sets from an agent that has not read its own state would remove its contributions at every peer.
  2. Otherwise one `replace` for each type the agent may contribute, empty where it holds none (design 5.4): NS, CDS and DNSKEY, and in this step the KEY as well. The zone's CSYNC is the leader's alone: the answer of the agent that leads the zone names it too, and no other answer does. A CSYNC operation from any other agent is rejected since PR #188, an empty one too (3.2). Design 5.4 has the KEY as the leader's in the same way. In the code it is not yet: until step 9 the KEY is a contribution of the agent that published it, and an answer that left it out would let an asker keep a stale one. Step 9 moves it.
  3. The DNSKEY operation carries the key states, from the signer's latest inventory, through a helper split out of `LocalDnskeysFromKeystate` (proposed `inventoryKeys`) that does not touch what that function remembers.
  4. It is always enqueued, with `EnqueueForSpecificAgent`.
- `MsgHandler`, RFI SYNC: passes the request's `catch_up` to the command.
- `CommandHandler`, `send-rfi` SYNC (the operator's `resync --pull`): sends to the voting members only, each with a `catch_up` of reason `manual`.

**Changes, the asking agent.**

- A CSYNC operation in an answer goes through `refuseCsyncNotFromLeader` as in any update (PR #188). An asker that has just started may not know the leader yet: it then refuses that one operation, with a final confirmation REJECTED for the record, and takes the rest. Proposed: the answer counts as complete all the same. The zone's copy carries the CSYNC, and the leader's own distribution of it is confirmed apart.
- `processOperations` (`v2/agent_policy.go`): `changed` is true when any operation changed something (2.12).
- `SynchedDataEngine`, the `remote` case: an update that carries `catch_up` is always confirmed, with the lists the short path has, empty or not (2.12).
- `noteForeignDistribution`, `NoteForeignKeyStates`: a complete answer sets the sender's entry in `foreignKeyStates`, also when the DNSKEY operation lists no key state. `computedDSIntent` and `noteComputedDSSet` are unchanged.

**Names.** Log, info, logger `engine`: "answering a request for the zone's state", with `zone`, `peer`, `reason`, `request`, `complete`, `why`. Log, info: "a peer answered a request for the zone's state", with `zone`, `peer`, `request`, `complete`, `why`.

**Tests.** Unit:

- `TestOnlyTheLeadersAnswerCarriesACSYNC`, `TestAnAnswerWhoseCSYNCIsRefusedStillCounts`.
- `TestAnAnswerNamesEveryRRtype`, `TestAnAnswerCarriesTheKeyStates`, `TestAnAgentThatHoldsNothingStillAnswers` (an empty operation for each type, complete).
- `TestASignerWithoutAnInventoryAnswersNotComplete`, `TestAnAgentThatHasNotReadItsOwnStateSendsNoOperation`.
- `TestTheOwnReadIsRepeatedUntilItSucceeds`, `TestTheOwnReadWaitsForTheZonesFirstLoad`.
- `TestACompleteAnswerMakesItsProviderSpeak`: `computedDSIntent` is known after a complete answer from every provider in `signers=`, one of which lists no key.
- `TestAnAnswerWithoutTheMarkerIsAppliedAndDoesNotCount`.
- `TestEveryReplaceOfAnUpdateCountsAsAChange`, `TestAnAnswerThatChangesNothingIsConfirmed`.
- `TestGoldenWirePayloads` and `TestGoldenWireSendPayloads`, with the new files.

Harness: `TestTransportBoundary_CatchUpRequestAndAnswer`: RFI SYNC and its answer between two agents over the real path, the confirmation included. `integEnv` starts no network, no data engine, no message handler and no queue worker, so it is built on PR #188's `notifyRig` (`v2/mp_s5_leader_csync_test.go`), which runs the data engine and the message handler over the wire, with the reliable queue's worker added.

Also: `TestACombinerThatHasNotLoadedSaysSo`, `TestAnAnswerThatSaysNotLoadedIsNotTheOwnRead`.

Fleet: restart a leader that does not sign, then run `resync --pull` by hand. The DS set becomes known, a sync is asked for, the DS is at the parent.

**Done when** the fleet check passes. The "Today" note of section 3.2 of `guide/provider-changes.md` then loses its sentence about key states.

Not established: that the confirmation of an answer with nothing applied closes the entry in the answering agent's queue. The harness test above establishes it.

From step 9 an answer is held like any other distribution (design 4.9): it is sent when the zone is settled at the answering agent, and taken when it is settled at the asker.

### Step 4. Asking by itself (#157, the restart)

**Before it:** step 1, for `zoneStanding`. Step 3. PR #162, which makes the edge to OPERATIONAL arrive after a refused hello, a refused beat back, or a wrong key found at discovery. PR #193, on top of it, for a peer that replaced its key after the hello and whose beats are refused: PR #162 does not cover that case. PR #164, for the status command that shows the tracker, is merged.

**Changes.** A new file, `v2/catchup.go`, with the tracker. Proposed:

```go
type catchUpTracker struct {
    mu    sync.Mutex
    peers map[ZoneName]map[AgentId]*catchUpPeer
    seen  map[AgentId]time.Time // the last successful beat to each peer
}

type catchUpPeer struct {
    Request   string    // the outstanding request's name, empty when none
    Reason    string
    Asked     time.Time
    Answered  time.Time
    Complete  bool
    LastError string
    // attempt, the retry timer and the time of the last log line are kept beside these
}
```

Its functions, and who calls them:

| Function | Does | Called from |
|---|---|---|
| `Ask(zone, peer, reason)` | Sends one RFI SYNC with a new name, unless a request to that peer for that zone is outstanding or a complete answer is less than a minute old. A request clears `Complete`. For a peer that is not OPERATIONAL the request is noted and goes out at `PeerOperational` | The rows below |
| `AskZone(zone, reason)` | `Ask` for every voting member of the zone other than this agent | First load, a standing that rises, `CommandHandler` |
| `PeerOperational(peer)` | Notes the successful beat. First since this agent started: `Ask(zone, peer, "start")` for every zone they share that has loaded and in which the peer votes. After a gap above the outage time: the same with `outage`. Otherwise: asks again whatever was paused for this peer. A beat to this agent's own combiner or signer is not a peer's, and a peer that has more than one mechanism counts once | `SendBeatWithFallback`, where a beat succeeds |
| `Answered(zone, from, catchUp)` | Takes an answer that names the outstanding request. Complete: done. Not complete: a retry | `SynchedDataEngine`, the `remote` case, after an update the repo took |
| `Requested(zone, from, catchUp)` | After the answer to a request of reason `start` is enqueued: `Ask(zone, from, "peer-start")`, when the asker votes in the zone | `MsgHandler`, RFI SYNC |
| `Forget(peer)` | Drops everything kept for a peer that is removed (step 7), so that one named again later is asked as a new peer | The engine's `OnPeerRemoved` hook (`v2/hsync_bridge.go`), which is wired to `removePeerView` already: `Forget` is added to that closure |
| `CaughtUp(zone)` | Design 5.5: the own read is done, and every voting member of the zone other than this agent, as the zone's records name them now, is complete with no request outstanding or noted. Also returns who is waited for | Step 5, the status |
| `Status(zone)` | The rows for the status command | `GetParentSyncStatus` |

Rules inside it:

- **A request fails** when the send fails, when it is refused, when its answer says not complete, and when no answer has come 30 s after the acknowledgement (design 5.7; the 30 s are proposed). Step 9 changes the last: an answer waits for the zone to be settled at both ends, and that wait is not a failure.
- **Retries** (design 5.7): after 5 s, 15 s, 30 s and 60 s, then every 5 minutes, with the same reason and a new name. A retry that finds its peer not OPERATIONAL sends nothing and waits for `PeerOperational`.
- **Pacing** (design 5.8): eight requests in flight to one peer.
- **Logging:** the first failure of a request, then one line an hour.

The reasons at a refresh. `MPPreRefresh` has the served zone and the incoming one, and records the local standing in both, in two new fields of `ZoneRefreshAnalysis`. It also records whether this is the zone's first load (`zd.FirstZoneLoad`): `PostRefresh` has no such signal of its own, and at a first load tdns defers it until the zone is ready. `PostRefresh` then calls:

- at a zone's first load, `AskZone(zone, "start")`, and nothing else for that refresh: the served zone of a first load has no HSYNC3, so its standing reads as having risen from none. Proposed: a zone that is added to a running agent is a first load too, and asks with `start`;
- when the standing rose from none, at a later refresh, `AskZone(zone, "join")`;
- when it rose to voting from no role or from auditor, `AskZone(zone, "role")`;
- for each other identity that became a voting member of the zone at this refresh, `Ask(zone, peer, "peer-role")` (design 5.1). Without it `CaughtUp` never holds again once a newcomer has its role: the zone's records name a voting member that nothing ever asks, and a leader's sync stays held. `MPPreRefresh` records those identities in a third new field.

Before step 10 an agent with a record and no role has no OPERATIONAL peer in the zone, so its `join` sends nothing, and the request goes out with reason `role` when the role comes.

**Names.** Config, proposed: `multi-provider.syncengine.intervals.catchup_outage`, in seconds as its neighbours, default 3600. As each neighbouring key: in the config struct, in `ValidateSyncengineIntervals`, in the intervals log line, and in the sample configs and the configure templates. Status, a new field `catch_up` on `ParentSyncStatus`, and in `agent parentsync status`:

```
  catch-up:       caught up
  catch-up:       not caught up, waiting for agent.bravo.example.

Catch-up, per voting member:
  Answer        Asked     Answered  Reason  Identity
  complete      15:04:05  15:04:06  start   agent.alpha.example.
  not complete  15:04:05  15:04:06  start   agent.bravo.example.  (no-inventory)
  none          15:04:05  -         start   agent.charlie.example.  (refused)
```

Log, logger `catchup`: info "asking a peer for the zone's state" (`zone`, `peer`, `reason`, `request`); warn "a request for the zone's state failed, asking again" (`zone`, `peer`, `reason`, `cause`, `attempt`, `in`); info "the zone is caught up" (`zone`).

**Tests.** Unit, `v2/catchup_test.go`:

- `TestOneRequestIsOutstandingPerZoneAndPeer`, `TestNoRequestWithinAMinuteOfACompleteAnswer`.
- `TestTheRetrySchedule`, `TestARequestWithNoAnswerIsAskedAgain`, `TestARequestPausesWhileItsPeerIsNotOperational`.
- `TestAnAnswerThatNamesAnotherRequestDoesNotCount`.
- `TestOnlyAStartRequestIsAskedBack`, `TestTwoAgentsThatStartTogetherAskEachOtherOnce`.
- `TestAPeerBackAfterALongOutageIsAsked`.
- `TestAStandingThatRisesAsks`: `join`, `role`, and nothing when it falls.
- `TestAPeerThatGetsARoleIsAsked`, `TestARemovedPeerIsForgotten`.
- `TestEightRequestsInFlightToOnePeer`.

Harness: a third peer beside the two of `integEnv` (`newPeer`), `TestCatchUpAfterARestartAmongThreeAgents`: one agent restarted asks two, is asked back by two, and ends caught up. The harness's `AuthorizeAllPeers` list names alice and bob only, and is widened for the third.

Fleet: every agent restarted within ten seconds, on a zone whose leader does not sign: the DS is at the parent with no owner edit and no command. The leader alone restarted: the same.

**Done when** both fleet checks pass and the status of every agent shows every voting member as complete. The promise of `guide/synchronization-model.md` section 2 then holds.

### Step 5. The sync with the parent waits (#157, the leader)

**Before it:** step 4, on every agent of the zone: without it nothing completes a catch-up and the hold never ends. PR #188 rewrote what this step edits (`syncDelegation`, the chains of `v2/mp_s5_leader_sync.go`, and the CSYNC of `v2/mp_s5_leader_csync.go`), and it is merged.

**Changes.**

- `DelegationSyncher` (`v2/delegation_sync.go`), `SYNC-DELEGATION` and `EXPLICIT-SYNC-DELEGATION`: for the leader's sync of a multi-provider zone, after the check of the lead, when `CaughtUp` says no: note the sync as owed, log one line, send nothing. In `EXPLICIT-SYNC-DELEGATION` the test comes before the branch that reports "in sync". Both commands, so that NS and glue wait as the DS does. The place is before `syncDelegation`, and so before `delegationCsyncStep` (PR #188): a leader that is not caught up makes no CSYNC either.
- A NOTIFY that already waits when the zone stops being caught up (an `outage` or a `peer-start` request clears it). A held NOTIFY leaves in one place only, `delegationSyncReleaseAfter`, which asks who leads; the last confirmation in `delegationCsyncProgress` schedules that function and asks nothing itself. Proposed: `delegationSyncReleaseAfter` asks the hold beside the lead. A NOTIFY that is held then is dropped and the sync is owed.
- The tracker: `owed` per zone. `Answered`, and the own read of step 3, call `requestDelegationSync(zone, "the zone is caught up")` when the zone becomes caught up with a sync owed. That is the explicit sync: it looks at the parent first and sends only the difference, which is the order design 5.6 fixes. A sync that was held as an implicit one is not sent as it was.
- `EXPLICIT-SYNC-DELEGATION`, the "in sync" branch: when the zone's computed DS intent is unknown (`computedDSIntent`) and the zone names a signer, the line is not "in sync". The retry chain ends as today: the set turning known asks again. The test reads the computed intent, not tdns's `NewDSKnown`, which is false also when the parent's DS query fails and when the parent has no DS and the apex no DNSKEY.
- A new function beside `computedDSIntent`, proposed `computedDSWaitingFor(zone)`: the providers in `signers=` that have not spoken, and this provider's own signer when it has sent no inventory. When every signer has spoken and none holds a key with the SEP flag, the set is unknown and there is nobody to name; the line then says so.

Step 9 puts one more condition in the same places: the zone is settled (design 4.9, and the last bullet of design 5.6). Catch-up itself then takes longer after a start or a change of the providers, by the fixed time of step 9 and a beat: an answer is a distribution, and waits.

**Names.** Log, info, logger `zones`: "DelegationSyncher: the sync with the parent is held until the zone is caught up" (`zone`, `waiting_for`); "the zone is caught up, asking for the sync that was owed" (`zone`); "DelegationSyncher: NS and glue are in sync with the parent, the DS set is unknown" (`zone`, `waiting_for`). Status, two lines in `agent parentsync status`:

```
  parent sync:    held until the zone is caught up
  DS set:         unknown, waiting for bravo
```

**Tests.** Unit, beside `v2/mp_s5_sync_retry_test.go`:

- `TestALeadersSyncIsHeldUntilTheZoneIsCaughtUp`, `TestBothSyncCommandsAreHeld`.
- `TestTheAnswerThatCompletesTheCatchUpAsksForTheOwedSync`, `TestAHeldSyncLooksAtTheParentBeforeItSends`.
- `TestNSInSyncAndDSUnknownIsNotReportedInSync`.
- `TestAZoneWithOneVotingMemberWaitsForItsOwnReadOnly`.
- `TestALeaderThatIsNotCaughtUpMakesNoCSYNC`, `TestAWaitingNotifyIsDroppedWhenTheZoneIsNoLongerCaughtUp`.
- `TestAnAgentThatDoesNotLeadHoldsNothing`.

Fleet: one signer's agent stopped while the leader restarts: the leader reports what it waits for, sends nothing, and syncs when the agent is back.

**Done when** the fleet check passes, and the two checks of step 4 still do with no added delay beyond the catch-up itself.

Read since: `NewDSKnown` is set only in tdns's `recordDSDifference` (`v2/delegation_utils.go`, the same at every tdns pin named in this plan). It is false when the DS intent is unknown, and also when the parent's DS query fails, when the parent has no DS and the apex no DNSKEY, and when a rollover owns the DS. So the step reads the computed intent instead.

### Step 6. A rule for the sender and the recipients of every message

**Before it:** step 1. PR #163 and PR #188 are merged; PR #188's check of a CSYNC reads `DeliveredBy`, which `routeSyncMessage` keeps setting.

**Changes, the sender.**

- A new middleware, proposed `refuseNamedSender`, registered with `Router.Use` for the agent and the auditor, BEFORE `RouteToCallback`: middleware runs in the order it was added, and `RouteToCallback` hands the message to the application whenever the middleware after it returns without error. It compares every sender field the payload carries (`OriginatorID`, `MyIdentity`, `sender_id`) with the context's peer, as FQDNs, and when any of them differs it answers REFUSED and no handler runs. Comparing `IncomingMessage.SenderID` alone is not enough: `parseAppPayload` picks one of the three for it, nothing refuses two that conflict, and the route functions read the others. About 40 lines.
- `apiSyncEndpoint` (`v2/api_receive.go`), on the agent's and the auditor's sync routers: for `/beat`, `/sync/ping` and `/msg`, refuses a body whose sender is not the client certificate's name (decision 9). The certificate is read from `r.TLS.PeerCertificates`; `tlsaVerificationMiddleware` keeps its name to itself. Not on a combiner's sync router (3.2). The name is the certificate's common name, the one `tlsaVerificationMiddleware` has checked against the peer's TLSA record, compared as an FQDN with the sender the body names. A request with no client certificate does not get this far. `/hello` is not checked (3.2).
- `routeSyncMessage`: its fallback to the transport's sender goes.

**Changes, per message.**

- `handleAppSync` (`v2/mp_verb_handlers.go`): refuses, with the reason, a SYNC whose sender is not a voting member of the zone. In the form its LEGACY refusal has today, which stays for its message.
- `handleAppRfi`: on an agent or an auditor, and not for a peer its config names, refuses by RFI type as in 3.2. For `CONFIG sig0key` the requester must be a voting member here. The upstream test in `MsgHandler`'s `sig0key` case stays until step 9, so until then a voting member that is not the answering agent's upstream or downstream is admitted here and still gets no key there, as today.
- `GetZoneAgentData`: an OFF record is nobody's upstream or downstream.
- `CombinerProcessUpdate` (`v2/combiner_chunk.go`): for a zone that is not a provider zone, refuses the operations of an origin that is not a voting member of the zone, each with the reason.
- `MergeGossip(msg, from, group)`: takes nothing for a group this agent does not have or of which the sender is not a member. From a member that does not vote it takes that member's own row and nothing else: no election record, and no term from one (decision 10). The two callers in `v2/hsync_transport.go` look the group up, as they do today for `CheckGroupState`. `hsync.GossipPort` follows, and `hsync.ProviderGroupInfo` gets the voting members.

**Changes, the recipients** (3.2): `broadcastElectToZone`, `CommandHandler` (`send-rfi` AUDIT and `sig0key`), and the request for the key in `leaderKeySetup`, which since PR #185 counts its answers over the voting members and still asks every entry of `zad.Agents`.

**For a zone in steady state** nothing changes: admission already keeps these senders out. What closes is the LEGACY way out, and the named originator. One thing does change: an auditor is no longer asked for the zone's state or its SIG(0) key, and its word on who leads is no longer taken.

**Names.** Log, warn, logger `transport`: "message refused: its payload names another sender than the one it came from" (`verb`, `named`, `sender`). Log, warn, logger `api`: "sync API request refused: the body names another sender than the client certificate" (`path`, `named`, `certificate`). The refusal of a SYNC: "sync refused: %s is not a voting member of zone %s". Of an RFI: "rfi %s refused: %s is not a member of zone %s", or "is not a voting member".

**Tests.** Unit:

- `TestAPayloadThatNamesAnotherSenderIsRefused`: hello, beat, sync, rfi, relocate, through the real router as `v2/transport_dispatch_test.go` does, with each of the three sender fields; `TestARefusedMessageIsNotDelivered` (the middleware's place before `RouteToCallback`).
- `TestAnAPIMessageMustNameItsCertificatesIdentity`: `/beat`, `/sync/ping` and `/msg`, with and without a trailing dot on either name; `TestAnAPIHelloIsNotHeldToItsCertificate`; `TestACombinerTakesAForwardedContribution`.
- `TestASyncFromAMemberThatDoesNotVoteIsRefused`, `TestTheCombinerRefusesAnOriginThatDoesNotVote`.
- `TestTheSig0KeyGoesToAVotingMemberOnly`, `TestAnOFFRecordIsNobodysDownstream`.
- `TestALegacyPeerGetsNoAnswerToAnRFI`.
- `TestGossipFromAMemberThatDoesNotVoteIsItsOwnRowOnly`, `TestAnElectionRecordFromAMemberThatDoesNotVoteIsNotTaken`, `TestGossipForAnUnknownGroupIsNotTaken`.
- `TestElectionMessagesGoToVotingMembersAndAuditors`.
- `TestALeadersCSYNCPassesBothRules`, `TestACSYNCFromAVotingMemberThatDoesNotLeadIsStillRejected`: the two rules of 3.2, in their order.

Harness: `TestTransportBoundary_LegacySyncRejection` gets the RFI verbs.

Fleet: no difference in a run without a provider change. That is the test.

**Done when** the fleet run is clean, the auditor's view of a zone is unchanged, and no "message refused" line appears in it.

### Step 7. Beats to a peer that repeats its hello, or is gone; the end of comms (#131, #132)

**Before it:** PR #162, for the beat back that is sent again, and PR #193 on top of it, which looks a peer up again after refused beats: at the end of comms that is what the side that removes last sees. Step 6, because a peer kept for the hold time must have its requests refused, and today `handleAppRfi` has no sender gate.

How the three parts relate to the design: a member with no role is a peer that hellos and beats without a vote, and every step of an add or a removal changes who is a member. The sender half of #131 is closed by step 6, where a hello counts as sent by the sender the transport established. What is left of #131 is a bound. The end of comms (design 3.1, decision 11) gives `RemovePeer` its first caller, and with it the faults of #132 become live (2.11), so the guards and the caller go in together.

**Changes, #131.** `Engine.BeatPeer` (`v2/hsync/beat_retry.go`): a new map, proposed `beatBackAt`, of when the last beat back to each peer started. A call less than one fast interval after it does nothing. The first beat back after a restart has no earlier one and is not delayed. The retries of a failed beat back run inside the same beat back and are not touched.

**Changes, #132.**

- A helper, proposed `Engine.stillStored(peer)`: the registry holds this very object.
- `beatRetrier` and `beatBack` check it where they check for the identity today, and stop when it fails.
- `beatPeerOnce` and `sendHelloToPeer` do not write the peer back. The object they hold is the stored one, or the peer is gone.
- The registry write is not the only way back. After every beat `beatPeerOnce` calls `storeHook`, which runs `OnPeerStored` and so `materializeAgentView`, re-creating the agent's view. The bridge's `SendBeat` and `SendHello` materialize the view and the transport's peer before they send (`agentViewForPeer`, `GetOrCreatePeer`). Each of these asks `stillStored` first and does nothing for a peer that is gone.
- A discovery that completes runs `OnPeerDiscovered`, whose `agentViewForIdentity` puts a fresh peer with no zones into the engine's registry when the identity is absent. PR #193 starts such a discovery after three refused beats. Design 3.3 runs discovery only for an identity that a zone names: `OnPeerDiscovered`, and PR #193's look-up, check that a zone the agent holds still names the identity, and drop the result otherwise.
- `RemovePeer` (`v2/hsync/discovery.go`) deletes the peer's entries in `beatFailing` and `beatBackAt`.
- Beats to one peer are not serialised: nothing depends on the sequence number (2.11).

**Changes, the end of comms.**

- `ReconcileZone` (`v2/hsync/reconcile.go`): on an agent (`GateOnLocalPresence`), a zone in which the local identity has no ON record expects no peers. Without this an agent whose own record has left a zone would put every peer back one pass after removing it. `ApplyHsyncDiff`'s gate (`localInHsync3`) takes the same predicate: today it counts any record of the local identity, with no test of ON or OFF. One predicate for both, so that an agent whose own record is OFF reads alike in both.
- `reconcileAllZones`: a zone that the agent no longer holds is taken off its peers. Today nothing does that: the pass visits the zones the agent has, so a zone that left the config stays on its peers for good.
- With those two the engine's set of zones per peer holds the shared zones and no others (2.11), and "no zone shared" reads as: that set is empty.
- Where the time is kept: on the engine's peer object, a new field of `hsync.Peer`, proposed `Unshared time.Time`: since when no zone names the peer. It is zero while one does. It is in memory. An agent that restarts has no such peer in its registry at all, so nothing is lost with it.
- What runs the removal: the reconcile loop. `reconcileAllZones` runs every `reconcile` interval, 60 s by default, and after its pass over the zones calls a new function, proposed `pruneUnsharedPeers(now)`. For every peer that is not an infrastructure peer:
  1. a zone names it: `Unshared` is cleared. A peer that is named again within the hold time is kept this way;
  2. no zone names it and `Unshared` is zero: it is set to now;
  3. no zone names it and `Unshared` is older than the hold time: `RemovePeer`.
- `RemovePeer` exists. It stops the peer's hello retrier, takes the peer out of the engine's registry, and its hook (`removePeerView`, `v2/agent_structs.go`) drops the agent's view and the transport's peer. The peer's payload keys stay in the transport's `PayloadCrypto`, which has no way to remove them; that is harmless, since admission refuses the removed peer before any crypto and a fresh discovery overwrites them. The rounds beat the registry's peers, so the beats stop. A peer that is not in the agent's registry is not LEGACY, so it is no longer admitted. A provider that a zone names again later is a new peer to `MarkNeeded` and is discovered afresh.
- Until it is removed nothing changes for the peer: it reads as LEGACY, is admitted and beaten, and every rule of step 6 that asks for a member refuses it.
- The same loop runs on the auditor, which has no gate in `ReconcileZone`: it removes a peer when no zone it holds has named it for the hold time.

The hold time is the time a queued message is kept. A message that was queued for the peer while a zone was shared has been delivered or has expired when the peer goes.

**Names.** Config, proposed: `multi-provider.syncengine.intervals.peer_hold`, in seconds as its neighbours, default 86400. Wherever its neighbours are: the config struct (`v2/multi_provider_conf.go`), `ValidateSyncengineIntervals`, the intervals log line, `hsync.Config` and `DefaultConfig` (`PeerHold`), `hsyncConfigFromMp` (`v2/hsync_bridge.go`), the sample configs of the agent and the auditor, and the configure templates. As for its neighbours, zero or absent means the default. Log, info, logger `engine`: "peer shares no zone with this agent any more, kept for the hold time" (`peer`, `hold`); "peer is named by a zone again, kept" (`peer`); "peer removed: no zone shared for the hold time" (`peer`, `since`).

**Tests.** Unit, `v2/hsync/beat_retry_test.go`:

- `TestRepeatedHellosGetOneBeatBackPerFastInterval`, `TestTheFirstBeatBackAfterARestartIsNotDelayed`, `TestARetriedBeatBackIsNotCutShort`.
- `TestARemovedPeerIsNotBeatenAgain`, `TestABeatOnItsWayDoesNotPutARemovedPeerBack`, `TestAHelloOnItsWayDoesNotPutARemovedPeerBack`.
- `TestARemovedPeerLeavesNoFailureMarker`, `TestAReplacedPeerIsNotBeatenThroughTheOldObject`.

Unit, `v2/hsync/reconcile_test.go` and `v2/hsync/remove_peer_test.go`:

- `TestReconcileExpectsNoPeersInAZoneThatDoesNotListThisAgent`, and that an auditor's reconcile is unchanged.
- `TestAZoneTheAgentNoLongerHoldsIsTakenOffItsPeers`.
- `TestAPeerWithNoZoneIsKeptForTheHoldTime`: it is beaten, and it is still in the registry.
- `TestAPeerWithNoZoneIsRemovedAfterTheHoldTime`: no beat, no hello and no discovery goes to it after.
- `TestAPeerNamedAgainWithinTheHoldTimeIsKept`: the time is cleared, and a second loss of its zones starts the hold time anew.
- `TestAPeerNamedAgainAfterItsRemovalIsDiscoveredAfresh`.
- `TestABeatOnItsWayDoesNotRecreateARemovedPeersView`, `TestADiscoveryForAnIdentityNoZoneNamesIsDropped`.
- `TestAnInfrastructurePeerIsNeverRemoved`.

Unit, in `v2`: `TestARemovedPeerIsNoLongerAdmitted` (LEGACY and admitted before, refused after, through `IsPeerAuthorized`), `TestThePeerHoldTimeIsReadFromTheConfig`.

Fleet: one agent restarted so that it is back within ten seconds of a peer's failed beat: OPERATIONAL at every peer within the restart and three fast intervals, and no election. As for PR #162. Then, with the hold time set to a few minutes: the owner takes a provider out of every zone it shares with the others. The others show it as LEGACY, refuse its SYNC and its requests, and go on beating it. After the hold time it is in no agent's peer list and no beat goes to it. Named again in a zone, it is discovered and reaches OPERATIONAL.

**Done when** the unit tests pass, the first fleet check shows no difference from PR #162, and the second passes on both sides: at the agents that stay and at the one that left.

### Step 8. The group by its make-up, and its election (#149)

**Before it:** steps 1 and 6. PR #185 (#179), for the zone that arrives. PR #186 (#180 to #183): this step makes a zone change its group at every edit of a provider's standing, so recomputes are more frequent, and that pull request is what makes them safe. A recompute holds no lock across a callback, two recomputes do not cross, a group that is dropped loses its election state and its timers (design 4.8), and a group's timers read the group when they fire.

**Changes.**

- `RecomputeGroups`, `ComputeGroupHash`, `ProviderGroup` (`v2/provider_groups.go`, `v2/gossip_types.go`): the key and the hash are made from three sorted lists, each under its own label: the voting members, the auditors, the members with no role. `ProviderGroup` gets `Auditors` and `NoRole` beside `Members` and `VotingMembers`. The union of voting members and its warning go. Until step 10 the third list is empty.
- The gate (design 4.3): the five callers of `CheckGroupState` pass the voting members. `hsync.ProviderGroupInfo` has them since step 6.
- One check for every change (design 4.5): a new `zoneChanged(zone)` on the election manager, called from `PostRefresh` for every change of HSYNC3 or HSYNCPARAM and at the first load, for a zone with parentsync on. It replaces the logic of the first-load callback and the kick in `reattachHsyncMemberAdds`:
  1. the local agent does not vote in the zone: nothing is started, and a per-zone result it holds for the zone is dropped;
  2. a group covers the zone: a per-zone result is dropped, and nothing else is done;
  3. no group covers the zone and the local agent is its only voting member: `StartElection(zone, 0)`, unless it leads already.
- A term for a self-election (design 4.6): both self-election branches take the next term, one above the term the agent holds. What a voting member has told is in the term held already (`ApplyGossipElection` raises it), and nothing a member that does not vote says about terms is taken (step 6). So there is no separate "term heard", and no election is ever caused by a member that does not vote (decision 10).
- What a member that does not vote takes (design 4.7): `MergeGossip` and `ApplyGossipElection` take an election record with a term above the one held, as today. On an agent that does not vote in the group they also take a record with a lower term, once the lease of the leader it holds has run out. A voting member never takes a lower term.
  - The same term (design 4.7): on an agent that does not vote, a record of the term held that names another leader or a later end of the lease is taken on the same condition. Voting members that have all restarted elect at term 1 again, and term 1 is what an observer of their first election holds. Otherwise a record of the term held is not news, as today.
  - The lease's end is known in both places: it travels in the record (`GroupElectionState.LeaderExpiry`), and each function keeps it with the record it took, `MergeGossip` in the gossip table and `ApplyGossipElection` in the election manager. The auditor has the gossip table only, and the rule in `MergeGossip` covers it.
  - Whether the local agent votes in the group: `MergeGossip` has the group since step 6, and `ApplyGossipElection` reads it from the group manager, as step 1 does for the renewal timer.
  - The lease's end is the telling agent's clock, compared with the local one. A clock that is off moves the moment by as much.
  - `InvalidateGroupLeader` clears the leader and keeps the lease's end. An observer whose group has degraded therefore waits for that lease's end too.
- A zone that arrives while its group's election runs (design 4.9, its last sentence): `finalizeGroupElection` sets the leader and then reads the group's zones from the group manager, in place of the list its caller read. A zone that is on the group's list and not on its caller's arrived during the election: it is taken up through PR #185's arrival path (`onZoneJoined`, which runs `leaderKeySetup(zone, false)`), not through `onLeaderElected`, whose key set-up may make a key. One that arrives after it finds a leader, and `zoneJoinedGroup` asks for it. A zone can be asked for twice at that seam, which costs nothing: the key set-up finds the key it has, and the sync sends only a difference.
- A zone that leaves (design 4.1). `zonesThatJoined` reports only a zone that lands in a group, and a zone with fewer than two members is in none: before step 10, taking the roles of one of two providers puts the zone in no group, and nobody is told. So `RecomputeGroups` also reports each zone that left a group, wherever it went, proposed `zonesThatLeft`, and `SetOnZoneLeftGroup` carries it to the election manager. When this agent leads the group the zone left, and not the one it is in now, the zone's sync chain is dropped (`delegationSyncNotLeading`, from PR #188), through a callback set in `v2/start_agent.go`. From step 9 a sync that is owed for the zone is dropped with it.

A consequence to know: the hash of every group changes with this step. At the upgrade every group elects once, which the restart of the agents causes anyway. In the code, the tests of PRs #185 and #186 compute expected hashes from plain lists of identities at seven places; each changes with the key.

A second one: when the voting members have all restarted they elect at term 1, and a member that does not vote and stayed up holds the earlier, higher term. It shows the earlier leader until that leader's lease has run out, an hour by default, and takes the new record then. What it shows is information only: nothing acts on it.

**Names.** Log, info, logger `elect`: "zone left a group this agent leads, dropping its delegation sync" (`zone`, `group`, `now_in`).

**Tests.** Unit and harness, with `groupRig` (`v2/parentsync_leader_zone_arrival_test.go`, from PR #185) and `electionNet`:

- `TestTwoZonesWithTheSameProvidersAndAnotherMakeUpAreTwoGroups`, `TestAGroupsZonesAgreeOnWhoVotes`.
- `TestAnAuditorThatIsDownDoesNotHoldTheElectionBack`, `TestAnAuditorThatGoesDownDoesNotInvalidateTheLeader`.
- `TestALoneVoterLeadsAtATermAboveZeroAndItsObserverLearnsIt`, `TestEveryRenewalOfALoneVoterIsANewTerm`.
- `TestAnObserverTakesAHigherTermAtOnce`, `TestAnObserverKeepsItsLeaderWhileTheLeaseRuns`, `TestAnObserverTakesALowerTermWhenTheLeaseHasRunOut`, `TestAnObserverTakesTheSameTermFromRestartedVotersWhenTheLeaseHasRunOut`: for the gossip table and for the election manager.
- `TestAVotingMemberNeverTakesALowerTerm`, `TestNoElectionIsCausedByAMemberThatDoesNotVote`.
- `TestAZoneReducedToOneVotingMemberGetsALeaderWithNoRestart` (#149).
- `TestAPerZoneResultIsDroppedWhenAGroupCoversTheZone`.
- `TestAZoneThatArrivesInAGroupWithALeaderForcesNoElection`, `TestAZoneThatArrivesDuringAnElectionIsOneOfItsZones`.
- `TestAnAgentThatLedTheGroupAZoneLeftDropsItsSync`, also when the zone lands in no group.
- `TestAZoneThatArrivesDuringAnElectionMakesNoKey`.

Fleet: two providers reduced to one, with no auditor: a leader with no restart. A lease renewal with the auditor stopped. The agents of every voting member restarted while the auditor runs on, with a short lease: the auditor shows the new leader when the earlier lease has run out, and no election follows from anything it sent. A zone whose owner removes a provider that leads the zone's group: the NS change is at the parent without waiting for a lease renewal.

**Done when** the four fleet checks pass, and a run with no provider change elects each group once.

### Step 9. Nothing is started or taken for a zone that is not settled; the zone's SIG(0) key (design 4.9, 4.1)

**Before it:** step 8, which makes a group's hash the make-up: before it the hash does not say who votes. Step 6, for the sender of a beat's gossip, for the sender rule that is asked again when a kept distribution is handled, and for who may ask for the key. Steps 3 and 4, for the answer that now waits and for the tracker. Step 5, for the owed mark and the place of the leader's hold. PR #185, for `zoneJoinedGroup` and the key set-up at an arrival. And tdns-transport's answer to an HTTPS beat carrying gossip (decision 26), with the new pin: today `AgentBeatResponse` and the transport's `BeatResponse` have no gossip field, so over HTTPS an answer tells nothing.

The step has two parts, the settle rule and the key, with a size each (at its end). They can be two pull requests. It is a step of its own, after the group's new key and before the switch, for three reasons. A hold that never opens stops every change that a provider makes: it should be judged alone on a fleet. It needs steps 3 to 6, which step 8 does not. And it has to be in place before step 10, which is when a zone's make-up starts to change at every edit of a provider's standing.

It keeps today's listing: a row lists every zone of its group. Step 9b cuts the listing down, as a stage of its own (decision 24). The rule is safe with either. The argument of design 4.9 needs a telling to be one make-up that its agent has held for the fixed time, and to count for a bounded time. It does not need a zone to be left out of a row.

**The rule (design 4.9, decision 23).** A zone is settled at an agent when the agent has held the zone's make-up, unchanged, for the fixed time, and every other voting member of that make-up has told the agent the same make-up within the time a telling counts. While a zone is not settled, the agent starts nothing for it and takes nothing for it. The parts below are lettered: (a) since when a make-up is held, (b) the check, (c) nothing is started, (d) nothing is taken, (e) the leader, (f) the release, (g) catch-up, (h) elections.

**What is told. Nothing is added to the wire.**

- Every agent already tells, for each group, which zones it has in that group: its own row in the group's gossip lists them (`MemberState.Zones`, `v2/gossip.go`). With step 8 the group's hash is the make-up. So "zone Z is in my row of group G" says "I hold make-up G for Z". It tells the members of that group and nobody else.
- One thing changes in what is told: a zone is listed only once the agent has held it in that group for the fixed time (a).
- Why not a value per zone in the beat's own zone list: that list is `Zones []string` in tdns-transport's beat payload. The transport reads its first entry as the scope of the beat's authorization, and so does `parseAppPayload`. A value per zone there is a change of tdns-transport's wire type, of both readers, and a new pin. The gossip is tdns-mp's own, and it rides in the same beat.
- An absent value: a beat from a peer with no row of its own for the group, or with a row that does not list the zone, reads as "this peer does not tell this make-up for the zone". That is the hold, not a case of its own.
- The size of a beat: a row lists every zone of its group, and a beat carries every member's row. That is so today, and this step leaves it. Step 9b changes it.

**(a) Since when a make-up is held.**

The group manager knows. `recomputeSince` (`v2/provider_groups.go`) is the one place that reads every zone's records and installs the result. It runs at every change of a zone's HSYNC3 or HSYNCPARAM records (`OnHsync3Changed`, `PostRefresh`), and at the auditor's start. Proposed: a map beside the groups, `held`, with one entry per zone: the make-up (the key of step 8), the group's hash (empty for a zone in no group), and since when. It is written where the new map of groups is installed, under the manager's lock:

- a zone with no entry, or whose make-up is not the entry's: a new entry, with the time of the install;
- a zone whose make-up is the entry's: the entry stays;
- a zone the agent no longer has: the entry goes.

Four things about it:

- **A zone with fewer than two members.** The scan skips such a zone before it keeps anything for it. The entry is made before that skip: a zone with one provider has a make-up too, and its one agent waits out the fixed time after a change, like any other.
- **The first load after a start.** The first recompute that sees the zone makes the entry. So the time starts at the agent's start, as design 4.9 asks, and nothing is kept across a restart.
- **A zone that is not ready.** The scan skips it. Proposed: it keeps its entry. Not established: whether a loaded zone ever reads as not ready while it is refreshed. If it did and the entry went, the time would start over, which costs time and no safety.
- **A change that is on its way.** Between the moment a refreshed zone is in place and the recompute that follows it, the entry is of the make-up from before. The check (b) reads the zone's records when it is asked and compares. When they differ the zone is not settled.

Proposed accessor: `ZoneHeld(zone)`, which returns the entry. It is also the way to a zone's group from here on: `GetGroupForZone` walks every zone of every group and copies the group's zone list at each call.

**How a row leaves a zone out.** Two things are wrong with a row today, for this purpose. An agent's own row is written at the start of each beat round (`RefreshLocalStates`) and kept in the gossip table, so a recompute between two rounds leaves the kept row as it was. And `BuildGossipForPeer` reads which groups to send from the group manager of the moment, and the rows from the table. So a beat that is built just after a recompute can list a zone in the row of the group it left.

- One helper on the group manager, proposed `zonesToTell(group, now)`: the zones of the group whose entry in `held` is older than the fixed time. Both are read under one hold of the manager's lock, so the list is of one map.
- `BuildGossipForPeer` puts that list in this agent's own row of each message, in place of the list the kept row has. One map has each zone in one group, so no message lists a zone twice, and none lists it in a group it left. About 15 lines.
- `RefreshLocalStates` uses the same helper for the row it keeps, so that what the agent shows of itself is what it sends.
- A row that lists nothing is still sent. The builder includes a group when both agents are members of it, whatever its rows hold. The receiver replaces what it kept for the sender as a whole (below), so an empty list takes the zone away there.
- An agent with no row of its own for a group sends the others' rows only. That happens for up to a beat interval after a start, when the first row of a group is held back (`HoldFirstLocalRows`), and for a group that is new since the last round. It reads as telling nothing, which is right, and it ends well inside the fixed time.

**What is kept of what the peers tell.**

- Per peer, first hand: which group it has each zone in, and when this agent heard it. Proposed: `NoteToldZones(from, msgs, sent, at)` on the gossip table. It reads the sender's own rows only, and what it keeps for that sender is replaced as a whole. `ZoneToldBy(peer, zone, now)` returns the group and the time. The time of the sender's last beat is kept too, so that the check can tell a peer that was not heard from one that did not list the zone.
  - First hand, because a row that another member passes on can be older, and because a peer that has dropped a group sends no newer row for it: the gossip table would keep its last one for good.
  - Where it is called, and where the time comes from: for every beat that arrives, in `routeBeatMessage`, and for the answer to every beat this agent sent, in `SendBeatWithFallback` (`v2/hsync_transport.go`). `at` is this agent's clock at that moment. It is called also when the beat carries no gossip at all, which today skips the merge: such a beat says that its sender lists no zone in any group it shares with this agent.
  - Answers over both mechanisms. With the change of decision 26 the answer to an HTTPS beat carries gossip as a DNS one does. `SendBeatWithFallback` sends one beat on every eligible mechanism and reads the answers in one loop, the API's first: each is noted, and the later replaces the earlier. Without that change an HTTPS answer would wipe the sender's view at every beat, which is why the change comes first.
  - It reads the message before `MergeGossip` filters it (step 6). A row for a group this agent does not have is a view that differs, and it is exactly what has to be seen.
  - An older beat must not replace a newer view. `sent` is the sender's own time in the beat: the payload's `Time`, which the sender fills (tdns-transport `buildBeatPost`), not its legacy `Timestamp`, which stays zero. A beat that is older than the one last taken from that sender is not taken. An answer is taken when its beat was sent after the view now held was heard.
  - A zone that a sender lists in two of its own rows counts for neither. With the builder's change no agent sends that.
- The engine's own merge of the same beat (`mergeGossipFromBeat`, `v2/hsync/transport_peer.go`) is left as it is.

**The two times** (decisions 19 and 23). Both are counted in beat intervals, read from the config (`multi-provider.syncengine.intervals.beatinterval`, 30 s by default), and neither has a config key of its own.

| | Proposed constant | With the default |
|---|---|---|
| A told make-up counts for | `toldValidBeats = 2` | 60 s |
| The fixed time: how long a make-up is held before it is told | `settleHoldBeats = 3` | 90 s |

- Whose interval (design 4.9): the interval of the agent whose telling it is. An agent waits three of its own intervals before it lists a zone. A hearer counts a peer's telling for two of the intervals that peer announces in its row (`MemberState.BeatInterval`), not two of its own. So the two times of one telling always belong to one agent, and the proof of design 4.9 needs nothing about the intervals of the hearers or of the other members.
- Two, because a peer beats this agent at least once per interval of its own: one beat may be lost. Three, because the fixed time has to be the longer one, by a beat interval, the margin (design 4.9).
- A floor, proposed: the fixed time is never less than the time a telling counts plus 15 s. A beat can be 10 s on its way (the time-out of its send), which is more than one beat interval where the interval is set that short.
- No upper limit is needed for the argument. An agent that announces a long interval makes its own tellings count longer and waits longer before it tells: it slows the settling of its own zones, and nothing else.
- With a beat interval of 10 s, as a test fleet may run, a telling counts for 20 s and the fixed time is 35 s, by the floor. Every scenario that follows an owner's edit of the providers, or the start of an agent, waits that much longer than it does today.

**A told make-up counts only while it goes on being told** (decision 19, its first rule). It is applied in `ZoneToldBy`: what was heard longer ago than that peer's telling counts is not returned. So a peer that has stopped telling, that tells another make-up, or that cannot be heard reads the same in the check: it does not agree. Nothing has to notice the moment a telling runs out. The check is asked whenever an agent is about to start or take something, and an agent that was acting holds at its next attempt.

**How a peer learns that a zone has left a make-up.** The second rule of decision 19 asked an agent that has moved a zone to go on telling the members of the old group so. It is no longer a mechanism of its own (decision 23). An agent that has moved a zone lists it nowhere until it has held the new make-up for the fixed time, and its next beat to each peer says so by what it no longer lists:

- The old group still has zones at the mover: its row for the group goes on, without the zone.
- The old group is gone at the mover: it sends no row for it. The beat still arrives, with the rows of the other groups the two share.
- The two share no zone at all any more: the peer is LEGACY at the mover, and a LEGACY peer is still beaten (`SendBeatWithFallback`), for the 24 hours of step 7. Such a beat carries no gossip: the builder finds no group with both in it.

In all three the receiver replaces what it kept for that sender, and the zone is no longer there. That is why `NoteToldZones` replaces the whole of a sender's view at every beat, with or without gossip. A beat that does not arrive at all is the first rule.

**(b) The check.** Proposed: `zoneSettled(zone, now)`, in a new file `v2/settle.go`. It returns whether the zone is settled, and when it is not, what is waited for: who, and why.

1. The zone has no HSYNC3 RRset: settled. It is not a multi-provider zone, as in step 1.
2. The zone has no entry in `held`, or its records now give another make-up than the entry's: not settled. Why: `make-up-changed`.
3. The entry is younger than the fixed time: not settled. Why: `own-time`, with the time it is up.
4. For every voting member of the make-up other than this agent, `ZoneToldBy(member, zone, now)`:
   - the entry's group: the member agrees;
   - another group: why `other-make-up`, with the group;
   - nothing, and the member's last beat is older than the time a telling counts: why `not-heard`, with how long;
   - nothing, and the member's last beat is newer: why `not-listed`. The member holds another make-up for the zone, or has not held this one for the fixed time yet.

A zone in no group, and a zone whose only voting member is this agent, are settled by 1 to 3: the agent's own time. On an agent that does not vote in the zone, an auditor or a member with no role, every voting member is another member, and the rule is the same (design 4.9, "Who has to agree").

**The argument, and what the code does to it.** Design 4.9 has it ("Why it holds"): a voting member holds one make-up at a time and tells it no sooner than the fixed time after it took it up, and a peer counts what it was told for a shorter time than that. So two agents that hold different make-ups for a zone never both count the same member. Four things in the code could break that, and each is closed above: a row from before the recompute (the builder's list and the `held` entries are of one map), an old beat that arrives late (the sender's time), a beat with no gossip that is not looked at (the call for every beat), and the time between a zone's refresh and its recompute (the check compares). One thing is assumed: a beat is not delivered later than the time-out of its send. The floor of 15 s rests on it.

**(c) Nothing is started.** Where a change that a provider makes becomes a distribution today:

| What | Where it starts | How it is sent |
|---|---|---|
| The operator's `add-rr`, `del-rr` and `update-local-zonedata` | `APIagent` (`v2/apihandler_agent.go`) | A `local` update to the data engine (`SynchedDataEngine`, `v2/syncheddataengine.go`) |
| The signer's DNSKEYs with their key states | `SyncRequestHandler` (`v2/hsyncengine.go`), when the signer's inventory differs from what was last distributed | The same |
| The leader's CSYNC (PR #188) | `distributeCsync` (`v2/mp_s5_leader_csync.go`) | The same |
| The leader's KEY | `leaderKeySetup` (`v2/start_agent.go`) | `EnqueueForCombiner` and `EnqueueForZoneAgents`, called there |
| The operator's `resync --push` | The `resync` command of the data engine | The same two calls, in the engine |
| The answer to a request for state (step 3) | `catchUpAnswer`, today `resync-targeted` | `EnqueueForSpecificAgent` |

*The `local` case of the data engine* is where the first three meet. Today it evaluates the update, stores it in the agent's data, marks its records as pending under a new distribution ID, and sends: to the agent's own combiner, to the zone's agents, and a note for the key machine of which DNSKEYs went out (`TrackDnskeyPropagation`). Proposed: for a zone that is not settled it evaluates the update and stores it in the agent's data, and the marking and the three sends are owed. The records are not marked pending until they are sent: a record marked with no expected recipients reads as confirmed by everyone, to `allRecipientsConfirmed` and to `delegationCsyncProgress`, which runs on every confirmation of the zone.

- Why it stores at once: `add-rr` and `del-rr` build a `replace` from the agent's own data as it is when the command comes. A second edit made during the hold has to see the first, or its `replace` would take the first edit away when both are sent.
- What is owed: the update and its distribution ID, in a list per zone, in the order they came.
- When it is sent: the recipients are read then, not when the update came (`GetDistributionRecipients`), the records are marked pending with them under the entry's distribution ID, then the three sends, then `delegationCsyncProgress` as today.
- The agent's standing is asked again then (step 2). An agent that no longer votes in the zone sends nothing: design 2.3 has it initiate nothing. The owed entry is dropped with a log line, and its records go from the agent's own data: the agent reads its own contributions back from its combiner, the own read of step 3, and its combiner never had them. So the agent's data says again what its provider has contributed, and a later `replace` cannot carry an edit that was dropped.
- A repeat is owed once. The key machine has a distribution sent again when it has waited for its confirmations longer than `ResendAfter` (`v2/mp_key_lifecycle_driver.go`), and it sets no other limit on that wait. Not established: by which path that resend reaches the agent's data engine, and whether it comes as a new local update. If it does, an update with the same operations as one that is owed for the zone is not owed a second time.
- What the operator is told: the edit is stored and kept, and for whom the zone waits. It is not an error.
- The send to the agent's own combiner waits with the rest: it is the same distribution, and it is what changes the zone at this provider.

*The others.*

- **The leader's CSYNC** is not made while the leader's sync is held (e): the hold is asked before `delegationCsyncStep`. One whose zone stops being settled between that and the data engine is owed like any local update, and reads to the sync chain as handed over and not yet confirmed. The NOTIFY waits for the confirmations with no time-out already.
- **The leader's KEY.** `leaderKeySetup` asks the hold before anything else (e), so its two sends need no change.
- **`resync --push`** is refused while the zone is not settled, with the reason. Proposed: it is an operator's command and can be given again, and what it would push is the agent's own data, which a hold does not lose.
- **The answer to a request for state.** The request is taken as before: it is not held (design 4.9). The answer is owed, one per zone and asker. A request from the same asker that comes while one is owed replaces it. The answer is built when it is sent, so it holds the agent's data of that moment and names the latest request.

*Nothing is lost or put out of order.* One list per zone holds what is owed and what is kept (d), in the order it came, and it is handled in that order by the data engine itself (f). What it holds is in memory. An agent that restarts loses it, as it loses its queue today (2.5). For an operator's edit that is new: the operator was told that it is kept. The status shows what is owed.

**(d) Nothing is taken.** A SYNC that arrives gets three answers today, and they are three things:

1. **The transport's acknowledgement,** in the reply to the message itself, once the router's handler has accepted it (`handleAppSync`, `v2/mp_verb_handlers.go`). It says that the message arrived and passed admission and the sender rule.
2. **A confirmation with status PENDING,** sent at once by `routeSyncMessage` when it has passed the message on (`sendImmediateConfirmation`, `v2/hsync_transport.go`: "Sync received, forwarding to combiner"). At the sender it starts the wait for the final confirmation over (`MarkPending`).
3. **The final confirmation,** with what was applied and what was refused. It is sent when the receiving agent's own combiner has confirmed (`PendingRemoteConfirms`, `sendRemoteConfirmation`), or at once when the update changes nothing here. An auditor sends it when it has logged the event (`auditorConfirms`).

What the sender's queue does with a recipient that has the message and has not confirmed it (`reliable_message_queue.go` in tdns-transport, with its defaults, which tdns-mp does not change): it waits 2 minutes for the final confirmation and then sends the same message again, with the same distribution ID. The wait doubles with every resend, up to 15 minutes. A PENDING starts the current wait over. The message is given up after 24 hours, with a log line and nothing else. A send that fails is another matter: it is tried again on a backoff that starts at 2 s and stops growing at one minute.

Proposed, as the least change that fits:

- **The first two answers are given when the message arrives,** as today. They say "it is here". The text of the second says that the update is kept and why: "Sync received, kept until the zone is settled here". Refusing the delivery in their place would put the message on the backoff for failed sends: one send a minute, for as long as the hold lasts, to every recipient that is not settled.
- **The third is not given until the update has been handled.** That is what design 4.9 means by "not confirmed", as the plan reads it. The sender waits for it as for any other.
- **The update is kept** at the head of the `remote` case of the data engine, before `refuseCsyncNotFromLeader`, `EvaluateUpdate` and `ProcessUpdate`. Nothing is stored in the agent's data, nothing is passed to its combiner, and what the sending provider says about its keys is not passed to the signer (`noteForeignDistribution`). It goes on the zone's list (c), in the order it came.
- **A resend is not kept twice.** A kept update is known by its sender and its distribution ID (`OriginatingDistID`). A resend of one that is kept gets the first two answers again and is dropped.
- **When it is handled,** it takes the path it would have taken. Two things are asked by the make-up that has settled, since the router asked them when the message came: that the sender is a voting member of the zone (step 6), and for a CSYNC, who leads. One that fails is answered with a final confirmation REJECTED and the reason.
- **`MsgHandler`** waits 3 s for the data engine's word on an update (`v2/hsyncengine.go`). It gets "kept" at once, which is no error.
- **The auditor** (`AuditorEngine.recordSyncMsg`, `v2/auditor_engine.go`). It is left as it is: it logs the event when the message comes and confirms at once (`auditorConfirms`). Design 4.9 says so: an auditor changes nothing in a zone, so there is nothing for the settle rule to hold at it, and a distribution does not wait for an auditor's view of the make-up.
- **A member with no role** takes by the same code as a voting member.

How many resends that costs: none for a hold that ends within 2 minutes, which is the common case with a fixed time of 90 s. For a hold of an hour, six. Each is one message and its two answers.

What a restart does: a recipient that restarts loses what it kept. The sender has no final confirmation, sends again when its wait runs out, and the copy is kept anew. A sender that restarts loses its queue, as today. The kept copy is handled when the zone settles, and its confirmation finds no message waiting.

Not established:

- That a final confirmation which arrives after its message was given up, 24 hours after it was sent, still moves the sender's record of the distribution. `OnConfirmationReceived` is where to look. A recipient that is down for a day gives the same case today.
- What a sender does with records whose distribution was given up. As read, nothing: they stay pending.

**(e) The leader.** One helper, proposed `syncHeld(zone)`, in the place of step 5's test: the zone is not settled, or it is not caught up. It is asked:

- in `DelegationSyncher`, for both sync commands, where step 5 put its test, and so before `syncDelegation` and `delegationCsyncStep`;
- where a waiting NOTIFY is let go (step 5): a NOTIFY that is held then is dropped, and the sync is owed;
- first thing in `leaderKeySetup`, and before the bootstrap of the zone's SIG(0) key at the parent, `ParentSyncAfterKeyPublication`, which `leaderKeySetup` starts by itself and which does not pass the syncher. Design 4.9 names the bootstrap. Read since: when the parent trusts the key, that function only records the state and asks the syncher for a sync; a bootstrap UPDATE goes only when the parent does not know the key or its validation failed. So the hold before it is still needed.
- in the `DELEGATION-SYNC-SETUP` arm of `DelegationSyncher`, which runs tdns's `DelegationSyncSetup` when this agent leads. Through tdns's `Sig0KeyPreparation` that makes a key when none is held, and a new one when the published KEY has no active local private key, and publishes and bootstraps it. For a multi-provider zone the arm does nothing: the zone's key is set up by `leaderKeySetup` alone, by the rule below. Otherwise it is a second path that makes keys.

The roll of the key when a voting member leaves (decision 22) is held by the same rule. It is the removal's, and nothing of it is in this step.

The same owed mark as step 5. An agent that stops leading a zone while something is owed for the parent drops it: step 8 drops the zone's sync chain when the zone leaves a group this agent leads, and this step drops the owed mark with it.

**(f) What releases a zone.** Two things can make a zone settled: a beat, and the agent's own fixed time running out.

- The zones that have something owed or kept are in one small set, proposed `settleWaiting` on the agent's registry, with a lock of its own. The data engine puts a zone in it when the zone's list gets its first entry and takes it out when the list is empty. The syncher does the same for a sync that is owed. The auditor keeps nothing (d).
- Where a beat or an answer has been noted (`NoteToldZones`), and at the start of every beat round (`BeforeHeartbeats`, `v2/hsync_bridge.go`), the check is asked for the zones in the set. With nothing waiting that is nothing.
- A zone that is settled is released: a command to the data engine, proposed `settled`, which handles the zone's list in order, and for a zone this agent leads, what an election's winner asks for it (`onLeaderElected`): the key set-up finds the key it has, and the sync looks at the parent first and sends only a difference.
- Each entry of the list takes the path it would have taken, and that path asks the check again. An entry that finds the zone not settled stays at the head of the list, and the rest behind it.
- The round's check is what releases a zone that waits only for its own time. It can be a beat interval late. No timer per zone is kept: a change of the providers of many zones at once would set as many.

**(g) Catch-up (steps 3 to 5).** There is no deadlock.

- What an agent tells of a zone depends on its `held` entry and on nothing else. It does not ask the tracker. So a newcomer that has just got its role tells the new make-up when it has held it for the fixed time, before it has caught up, and the others tell it.
- The request for state is not held, so it is sent and taken at once. The answer waits twice: at the answering agent until the zone is settled there, and at the asker until it is settled there. Both need tellings, and tellings need only time and beats.
- So the order after an edit that gives a provider its first role is: every agent loads the edit; the fixed time passes at each; the tellings cross; the answers go; the zone is caught up; the leader syncs. Catch-up waits for the settle rule and never the other way.
- After a start it is the same. The first row of a group, which is held back for up to a beat interval (`HoldFirstLocalRows`), lists nothing either way, so that hold sits inside the fixed time and adds nothing to it.
- One thing in step 4 has to change. A request fails there when no answer has come 30 s after its acknowledgement, and under the hold no answer can come that soon after a start or a change of make-up. Proposed, in `v2/catchup.go`: the time for an answer is 30 s or two beat intervals, the longer, and it is counted from the later of the acknowledgement and the moment the zone is settled at the asker. And an answer that arrives and is kept stops that time: the data engine tells the tracker (proposed `Arrived(zone, from, catchUp)`), and `Answered` follows when the answer is handled.
- The answering side says so too: the acknowledgement of an RFI SYNC (`handleAppRfi`) says that the answer waits for the zone to be settled there. The status of the asker shows it.

**(h) Elections are not held,** and nothing in this step changes one. As read: `CheckGroupState` reads the cells of the rows (`PeerStates`) and not their zone lists; a group's election is started by its gate and its lease; `zoneChanged` (step 8) reads the zone's records. Nothing in the election path reads a row's zone list or asks about a zone's make-up. What an election's winner does for each zone, the key set-up and the sync, is held per zone (e). A group that is new, because a zone has moved to a make-up no zone had, can elect within seconds, inside the fixed time: it has a leader before the leader may act. The readers of a row's zone list are all for display (step 9b lists them). One is affected here: `gossip state --zone` on an agent whose group manager has no group for the zone finds the zone by the rows' lists, and a zone that is held back from the rows is not found until the fixed time has passed.

**Limits and costs (design 4.9, decision 23).**

- After a change of a zone's make-up, nothing that a provider makes happens for the zone until the fixed time after the last voting member has loaded the change.
- After the start of a voting member's agent, the same holds for its zones, at every agent. The catch-up of step 4 therefore ends later by the fixed time and a beat, and the checks of steps 4, 5 and 8 pass that much later.
- A voting member that cannot be heard holds every change that a provider makes in its zones, for as long as it cannot be heard. A voting member whose agent is stuck on an old copy of a zone does the same for that zone.
- A recipient that does not vote, an auditor or a member with no role, is not waited for in the agreement, and its confirmation is waited for as before. An auditor confirms when the message arrives, whatever copy of the zone it holds: the settle rule holds nothing at it. A member with no role confirms when the zone is settled at it. If the zone never settles there, because its agent is stuck on an old copy, it confirms nothing, and every distribution of the zone but its own removal waits for that confirmation. Step 10 has the case that exists today, and design section 7 has it as an open point.
- What is owed and kept is in memory.
- What is not covered: an owner's edit whose old and new sets of voting members have no member in common (one provider replaced by another, two by a third). From the fixed time after the new side has the edit until a voting member of the old side loads it, both sides act, and the old side does not have to be stuck: a transfer that takes longer than the fixed time is enough. No code closes it. The order of `guide/provider-changes.md` avoids it, one provider at a time with a voting member in common at every step; the guide says that an edit which exchanges the whole set is not to be made (its section 1).

**The zone's SIG(0) key (design 4.1, decisions 14, 15, 18, 22 and 25).** Every voting member holds it, and a new one is made only when every voting member has answered that it holds none. This part needs steps 4, 5 and 6 only and can be a pull request of its own. It is kept here because it shares the owed mark and the hold with the rest of the step.

What it starts from (2.10). On main `leaderKeySetup(zone)` (`v2/start_agent.go`) uses a local SIG(0) key, else asks the zone's agents that are OPERATIONAL, else generates a keypair. PR #185 makes it `leaderKeySetup(zone, elected)`: at an arrival a key is made only when the zone publishes none and every voting member has answered (`mayGenerateZoneKey`, `v2/parentsync_utils.go`); otherwise `errZoneKeyNotHeld`, and `zoneKeyWaits` asks again. An election's winner still generates when nobody hands a key over, and the answering side hands the key to its upstream or downstream only. This part is built on PR #185's form. `mayGenerateZoneKey` becomes the rule of "The leader" below, for both paths. `zoneKeyWaits` gives way to the tracker's entry below, on design 5.7's schedule, so that there is one schedule and not two.

*What "holds the key" is read from.* The zone publishes a KEY when the apex of the agent's copy of the zone has a KEY RRset (what `GetParentSyncStatus` shows as "KEY at apex"; the leader's KEY always goes to the apex, `publishLocations`), or when some agent's contributions in the data repo hold one. An agent holds the private part of a published KEY when one of its active keys for the zone in the local keystore (`GetSig0Keys(zone, Sig0StateActive)`, each with its KEY record) is that record. Proposed helper: `zoneKeyHeld(zone)`, which returns the published KEY records, and the local key that matches one, if any. A local key whose KEY record the zone does not publish is not the zone's key (decision 18): an agent that led the zone before may hold one of its own from then.

*A voting member asks for a key it does not hold.* Proposed: `keyCheck(zone)`. It does nothing unless this agent votes in the zone, the zone is caught up, and the zone publishes a KEY that this agent holds no private part for. Then it asks. It is called:

- by the tracker of step 4 when the zone becomes caught up, which covers a start, a join and a first role;
- from the data engine, after a remote update that carried a KEY operation: the leader's `replace` of the KEY reaches every member, and it is the first sign of a new key;
- from `PostRefresh`, when the refresh changed the apex KEY RRset. `MPPreRefresh` has both copies and notes it, in one more field of `ZoneRefreshAnalysis`.

A key that arrives is imported as today (`importSig0KeyFromPeer`). An agent that does not lead publishes nothing and sends nothing to the parent. The request and its answer are CONFIG messages, not distributions. Proposed: the settle rule does not hold them. Design 4.9 names distributions and what goes to the parent, and neither is this.

*Who is asked.* The voting members of the zone other than this agent, and the leader of the group the zone left for as long as it is still a member of the zone. That leader's name is noted for this purpose alone, where a recompute tells of a zone that has moved: `zoneJoinedGroup(zone, from, to)` on the election manager. The election of the group the zone left is still there at that moment, since a recompute tells of the zones that joined before it tells of the groups that are gone. Proposed: `keyAskAlso`, per zone, kept while that agent is a member of the zone. After a restart there is no such note. Proposed for that case: the member under whose name the published KEY record is held in the data repo, which is the agent that published it. Not asked: an auditor. The one that is asked this way is often a member with no role by then. It is not given the key (design 2.1), and it initiates nothing (design 2.3), but it answers: a holder hands the key to a voting member that asks, whatever its own standing. So the admission rule of step 6 is about the ASKER, a voting member, and the answering side needs only to hold the key. Its silence is a missing answer like any other: nothing is concluded from the round, and no key is made.

*Who hands it over, and what an answer is* (decision 15, design 3.3).

- The rule for the requester is in the router's handler, `handleAppRfi` (step 6): a voting member of the zone. A refusal there is the request's own acknowledgement, REFUSED with the reason, on the wire at once.
- `MsgHandler`, the `sig0key` case: the test of the upstream relation goes. It hands over the key whose KEY record the zone publishes. `GetSig0KeyRaw`, which it uses today, returns the first active key it finds; it is replaced by the helper above.
- "No key here" is produced in the same case, as it is today: a CONFIG message whose data is the status "no sig0 key for zone". It is sent when the answering agent holds no private part for a KEY the zone publishes. The case's other failures (the zone or the keystore is not there, the lookup fails) send nothing today. They become an answer with a status of their own, which is not "no key".
- At the requester, `RequestAndWaitForConfig` (`v2/hsync_utils.go`) returns at once when the send fails, and a refusal is a failed send. With no answer it waits 15 s. So there are four outcomes: the key; "no key here"; refused (the peer does not have this agent as a voting member: its copy of the zone differs); and silence, which is no answer in 15 s or an answer with another status. Only the second says that the peer has no key.
- An answer has to be matched to its request. `RequestAndWaitForConfig` takes whatever arrives next on one channel for all zones, and an election's winner runs the key set-up for every zone of its group at once. As read, the answer for one zone can be taken by the request for another and imported under its name. Today that is rare, because most requests get no answer. With every request answered it is not. This step matches by zone, sender and subtype, which the answer carries, and drops an answer from an agent that was not asked or for a zone with no request outstanding (design 3.3, the answer's row). Today any admitted peer can put a CONFIG on that channel, and a waiting request would import what it carries. A test with two zones asked at once would establish the fault.

*How "every one has answered no" is kept.* The tracker of step 4 gets one more entry per zone, proposed `keyWanted`: the members asked in the current round, what each answered, the attempt and the timer. A round asks every member of the set again, also one that said "no key here" before: it may have got the key since. The rounds follow the schedule of step 4: after 5 s, 15 s, 30 s and 60 s, then every 5 minutes. The entry is dropped when a key arrives, and it starts over when the zone's voting members change (the refresh fields of step 4) or when the previous leader stops being a member. It takes the place of PR #185's `zoneKeyWaits`.

*The leader.* `leaderKeySetup(zone, elected)` becomes, the same for an arrival and for an election's winner:

1. The zone is not settled, or it is not caught up (`syncHeld`): nothing is decided. While it is not caught up this agent's contributions are not complete, so it cannot know whether the zone has a key. Owed. Test: `TestALeaderDoesNotJudgeAZoneKeylessBeforeItIsCaughtUp`.
2. This agent holds the private part of a KEY the zone publishes: it goes on as today, to the publication, the inquiry, and a bootstrap only if the parent does not know the key.
3. Otherwise: the request above, to every voting member and the previous leader. Owed, and one line says who was asked and what each answered.
4. In one round every member that was asked has answered "no key here": no member holds the zone's key. A refusal or a silence in the round keeps this from being concluded: silence is never "no key". Then:
   - **The zone publishes no KEY.** A keypair is made and published, and the bootstrap waits until the zone's nameservers serve the new KEY. Until tdns's child side waits for that by itself (tdns #917), this step starts the bootstrap only when the zone's propagation delay has passed after the publication. A parent that trusts no key for the zone takes it as a first key. One that still trusts a key the zone no longer publishes, for instance one rolled at the parent and never published, takes the new key in its place under decision 25. What a tdns parent does in that case before it has decision 25's rule is not established. The inquiry that follows the bootstrap says whether the parent took the key; while it has not, the sync stays owed and the key is offered again on the schedule.
   - **The zone publishes a KEY.** The zone's key is lost. Under decision 25 the leader publishes a new KEY beside the old one, bootstraps it once the nameservers serve both, and when the parent trusts it, deletes the old key with an update that the new key signs; then the old KEY leaves the apex. Until tdns parents judge a bootstrap that way, such an offer is refused for good (tdns #917). So this step makes no key in this case: the sync stays owed, and one line says that no member holds the zone's key and that an operator has to act. The recovery is built when tdns has the rule (7.5).
5. The zone's only voting member is this agent: there is nobody to ask, and case 4 applies once it is caught up.

So a key is made in case 4, and only when every voting member has said that it holds none. Whether the parent holds a key is not asked. No query can ask that: tdns's KeyState inquiry names one keyid and must be signed with a key the asker holds. A key rolled at the parent need not be published, so what the zone publishes does not tell either. With decision 25 neither is needed: the parent judges a bootstrap by what it finds.

*The KEY record is the group's (design 4.1, decision 22).* Today `leaderKeySetup` publishes the KEY as a contribution of the agent that runs it: a `replace` to its own combiner, with the instruction where to publish it, and to the zone's agents. Every agent that takes the zone up does that. So with decision 18 a new leader publishes the same record again under its own name, and the one under the earlier leader's name stays at every combiner. That is harmless while the two are one record. Three changes make the KEY the leader's, as the CSYNC is since PR #188:

1. A KEY operation is taken from the zone's leader only. `refuseCsyncNotFromLeader` (`v2/mp_s5_leader_csync.go`) is asked for the KEY as well as the CSYNC.
2. Only the leader's answer to a request for state names the KEY (design 5.4). Step 3 has every agent that published one name it, until this step.
3. A member keeps the KEY that the leader publishes and no other: an agent that takes the leader's KEY drops a KEY it holds under another agent's name, in its own data and at its own combiner. It is first needed at a roll (decision 22) and at the recovery of a lost key, where the leader publishes a new KEY, so it goes with the roll (7.4) and not in this step. Read since: the combiner takes the union of every agent's KEY contributions, without duplicates, and nothing puts the local agent's first (`RebuildCombinerData`, `v2/combiner_utils.go`); that order is only a comment in the data engine. So until it is done, a zone whose leader publishes a new key publishes both, under two names. And step 6's combiner rule refuses an origin that does not vote, so an empty `replace` in the name of an earlier publisher that no longer votes would be refused at the combiner: the drop has to be the leader's own operation.

*Still not covered.* A holder of the key that is still a member of the zone and whose agent is stopped is silent, and while it is silent nothing is concluded. If no other voting member has the key, the zone's sync is owed until that member answers. Once its record is gone, the members that are left answer, and case 4 decides. For a zone that publishes the KEY that is the stall for an operator, until tdns parents follow decision 25. With every voting member asking for the key at its catch-up, this takes two faults at once. When the apex carries several KEY records, an agent that holds any of them goes on, and the inquiry that the bootstrap starts with tells which one the parent trusts.

**Names.**

Log, info, logger `engine`: "a change of this provider's own is kept until the zone is settled" (`zone`, `distrib`, `waiting_for`); "a distribution from a peer is kept until the zone is settled" (`zone`, `peer`, `distrib`, `waiting_for`); "the zone is settled, handling what was kept" (`zone`, `owed`, `kept`); "a kept change is dropped: this provider no longer has a role in the zone" (`zone`, `distrib`). Log, info, logger `zones`: "DelegationSyncher: the sync with the parent is held until the zone is settled" (`zone`, `waiting_for`). Log, info, logger `gossip`: "the zone's make-up has changed, telling it again from" (`zone`, `group`, `from`). A hold that lasts is logged when it starts and then once an hour.

Log, logger `agent`, for the key: info "asking for the zone's SIG(0) key: the zone publishes one that this agent does not hold" (`zone`, `asked`); warn "no SIG(0) key yet, asking again" (`zone`, `answers`, `attempt`, `in`), the first time and then once an hour; warn "no member holds the zone's SIG(0) key, and the zone publishes it: no key is made, an operator has to act" (`zone`, `asked`), the first time and then once an hour; info "no voting member holds a SIG(0) key for the zone and it publishes none, making one" (`zone`), for case 4; warn "the parent has not taken the zone's new SIG(0) key, offering it again" (`zone`, `keyid`, `in`).

Status, in `agent parentsync status`, from new fields of `ParentSyncStatus`:

```
  settled:        yes, since 15:04:40
  settled:        no: this agent has held the zone's make-up since 15:03:10 and tells it from 15:04:40
  settled:        no: waiting for agent.bravo.example. (not heard for 75s), agent.charlie.example. (tells another make-up)
  kept here:      2 changes of this provider's own, 1 distribution from agent.alpha.example., the sync with the parent
  SIG(0) key:     the zone publishes one that this agent does not hold (agent.alpha.example.: no key here; agent.bravo.example.: no answer)
  SIG(0) key:     LOST: the zone publishes one that no member holds (agent.alpha.example.: no key here; agent.bravo.example.: no key here). No key is made; an operator has to act
```

Where a distribution's state is shown at its sender, the list of `agent distrib` (`v2/apihandler_agent_distrib.go`), a recipient that has answered PENDING shows as pending, as today. The text of that answer ("kept until the zone is settled here") does not reach tdns-mp: tdns-transport's `OnConfirmationReceived` callback has no message parameter, and `ProcessConfirmation` records a PENDING with an empty reason. Showing it would be a change of tdns-transport and a new pin, and this step does not make it: the recipient's own status says what it keeps. The auditor's view of a distribution shows that member as not confirmed, as it does for a member that is slow: a PENDING is not copied to the auditors (`copyConfirmationToAuditors`). It does not show why. That is #152.

**Tests.** Unit, with `groupRig` (PR #185) and two or three agents that hold different copies of one zone.

- The telling: `TestAZoneIsListedOnlyAfterTheFixedTime` (the builder, and the kept row), `TestTheTimeStartsOverAtEveryChangeOfMakeUp`, `TestTheTimeStartsAtTheAgentsStart`, `TestAZoneWithOneProviderWaitsOutTheFixedTimeToo`, `TestARowThatListsNothingIsStillSentAndReplacesThePeersView`, `TestAMessageNeverListsAZoneInTheGroupItLeft` (built after the recompute, and in the middle of a round), `TestAZoneListedInTwoRowsCountsForNeither`.
- What is kept: `TestAPeersOwnRowIsReadFirstHand`, `TestARowForAGroupThisAgentDoesNotHaveIsAViewThatDiffers`, `TestABeatWithNoGossipSaysThatItsSenderListsNothing` (two agents that share no zone any more), `TestAnOlderBeatDoesNotReplaceANewerView`.
- The times: `TestAToldMakeUpCountsForTwoBeatIntervals` (it counts, it runs out, it counts when told again), `TestTheFixedTimeIsLongerThanATellingCounts` (for any beat interval, by a beat and by 15 s at least), `TestBothTimesOfATellingAreInTheTellersInterval`.
- The check: `TestAZoneIsSettledWhenEveryVotingMemberTellsItsMakeUp`, `TestTheCheckSaysWhoIsWaitedForAndWhy` (the five reasons), `TestOnlyVotingMembersHaveToAgree` (a silent auditor, a member with no role that tells another make-up), `TestAZoneWhoseRecordsHaveJustChangedIsNotSettled`, `TestAPeerThatCannotBeHeardCountsAsNotAgreeing`, `TestAZoneWithNoHSYNC3IsNotHeld`.
- The argument: `TestTwoAgentsNeverBothCountAMemberThatMoved`: beats lost and late, any order of loading, the owner's edits in a row.
- Starting: `TestALocalChangeIsKeptWhileTheZoneIsNotSettled` (the operator's edit, the signer's DNSKEYs, the leader's CSYNC; nothing reaches the combiner or a peer), `TestKeptChangesGoOutInTheOrderTheyCame`, `TestASecondEditSeesTheFirstWhileBothAreKept`, `TestAKeptChangeGoesToTheMembersOfTheSettledMakeUp`, `TestARepeatedDistributionIsKeptOnce`, `TestAKeptChangeIsDroppedWhenTheProviderHasLostItsRole`, `TestResyncPushIsRefusedWhileTheZoneIsNotSettled`, `TestTheAnswerToARequestWaitsAndNamesTheLatestRequest`.
- Taking: `TestAnArrivingDistributionIsKeptAndNotApplied`, `TestAKeptDistributionIsAcknowledgedAndNotConfirmed`, `TestAResentDistributionIsNotKeptTwice`, `TestAKeptDistributionIsJudgedByTheSettledMakeUp` (a sender that no longer votes, a CSYNC from an agent that no longer leads), `TestTheAuditorConfirmsWhenTheMessageArrives`, `TestAMemberWithNoRoleTakesByTheSameRule`.
- The leader: `TestALeaderSendsNothingToTheParentWhileTheZoneIsNotSettled` (both sync commands, a NOTIFY that waits, the key bootstrap), `TestALeaderThatWasActingHoldsWhenATellingRunsOut`, `TestAStaleLeaderHoldsWhenTheOthersHaveMovedTheZone`, `TestAnAgentThatNoLongerLeadsDropsWhatItOwedTheParent`, `TestAZoneInNoGroupWaitsForItsOwnTimeOnly`.
- The release: `TestTheBeatThatCompletesTheAgreementReleasesTheZone`, `TestAZoneThatWaitsForItsOwnTimeIsReleasedAtARound`, `TestWhatWasKeptIsHandledInTheOrderItCame` (changes of its own and distributions from peers, mixed), `TestAnEntryThatFindsTheZoneNotSettledStaysAtTheHead`.
- Catch-up: `TestANewcomerTellsBeforeItHasCaughtUp`, `TestAnAnswerThatWaitsIsNotAFailedRequest`, `TestTheTimeForAnAnswerStartsWhenTheZoneIsSettledHere`.
- Elections: `TestAnElectionIsNotHeldByAZoneThatIsNotSettled`.
- The key: `TestAVotingMemberAsksForAKeyItDoesNotHold` (at catch-up, on a KEY operation, on a refresh), `TestAMemberThatDoesNotVoteAsksForNoKey`, `TestASignerHandsTheKeyToAnotherSigner`, `TestTheKeyHandedOverIsTheOneTheZonePublishes`, `TestARefusedKeyRequestIsAnswered`, `TestARefusedKeyRequestCostsNoWait`, `TestAKeyAnswerIsMatchedToItsRequest`, `TestALocalKeyThatTheZoneDoesNotPublishIsNotTheZonesKey`, `TestThePreviousLeaderIsAskedForTheKey`, `TestTheKeyIsNotAskedOfAnAuditor`, `TestALeaderDoesNotGenerateAKeyWhileAMemberIsSilent`, `TestALeaderMakesAKeyOnlyWhenEveryVotingMemberHasAnsweredNoKey` (an arrival, and an election's winner), `TestNoKeyIsGeneratedWhileTheZonePublishesOne` (every member has answered "no key", the apex still has the KEY: nothing is generated, nothing is offered to the parent, the sync stays owed), `TestANewKeyIsBootstrappedOnlyAfterThePropagationDelay`, `TestAKeyThatTheParentHasNotTakenIsOfferedAgain`, `TestDelegationSyncSetupMakesNoKeyForAMultiProviderZone`, `TestAnAnswerOfAnEarlierRoundDoesNotCount`, `TestTheAnswersStartOverWhenTheVotingMembersChange`, `TestNoKeyIsDecidedBeforeTheZoneIsSettledAndCaughtUp`, `TestAKEYIsTakenFromTheLeaderOnly`, `TestOnlyTheLeadersAnswerNamesTheKEY`.

Harness, `integEnv` with a third peer (`newPeer`):

- `TestTransportBoundary_ADistributionWaitsForTheZoneToSettle`: over the real path. The delivery is acknowledged and answered PENDING when it comes, no final confirmation goes while the zone is not settled at the recipient, one goes when it is, and the entry in the sender's queue is closed.
- `TestCatchUpAfterARoleChangeAmongThreeAgents`: the order of (g), to the end.

Fleet:

1. The owner changes a zone's providers, with the transfer to one voting member's provider held back. No distribution for the zone completes and nothing reaches the parent, at any agent, until the fixed time after the last one has loaded the change. Each agent says whom it waits for.
2. The agent of one voting member is restarted. The changes in its zones pause at every agent, and resume by themselves, with no command.
3. An operator makes a change during the pause. It is applied afterwards, once, at every provider.
4. The agent of a voting member is kept on an old copy of a zone while the others load a change of its providers. It says that it holds within two beat intervals. Nothing is started or taken for the zone on either side, and it ends when that agent has loaded the change.
5. The key: a zone that moves between two groups keeps its SIG(0) key. The KEY at the apex is the same before and after, and every voting member's keystore holds it. And a lost key: with the one holder's agent stopped and its record removed, every member that is left answers "no key". The KEY is still at the apex, so, with tdns parents as they are before decision 25's rule, no key is generated and nothing is offered to the parent: the sync stays owed, and the status says that the key is lost and that an operator has to act. A key is generated on a fleet only when every voting member has answered that it holds none, and only for a zone that publishes none.

**Done when** the five fleet checks pass; a run with no change of providers and no restart shows no hold line; and the fleet checks of steps 4, 5 and 8 still pass, each later by the fixed time and a beat and by no more. For the key: a zone with two signers that moves to a group led by the other signer keeps its SIG(0) key, and the parent goes on accepting its updates. `guide/multi-provider-advanced.md` then gets the rule in its sections 4.3 and 5.1: what the first confirmation says, and when a row lists a zone.

**Size.** The settle rule: about 600 new and 140 changed lines in about 19 files. Of the new lines, about 135 are the telling (the `held` entries, the builder, what each peer told), 85 the check and the times, 190 the two holds on distributions, 125 the leader and the release, and 60 the names. The key: about 190 new and 60 changed lines in about 9 files. The third item of "The KEY record is the group's" goes with the roll and is not counted.

### Step 9b. A row lists a zone only while there is something to do for it (design 4.9, decision 24)

**Before it:** step 9, on every agent of a zone and on its auditor. Nothing else. Step 10 does not need this step, and this step does not need step 10: the two can be merged in either order.

**What it is.** After step 9 an agent's row lists every zone of its group that the agent has held for the fixed time, in every beat, to every member. That is today's listing with one condition added. This step is the form design 4.9 describes: a zone is listed to a peer only while there is something to do for it. It is a stage of its own so that the settle rule is judged on the listing that exists, and so that the change to the beats can be judged alone (decision 24).

**On the wire nothing changes beyond step 9.** A row's `zones` stays a list of names (`MemberState`, `v2/hsync/gossip.go`). The beat's payload is not touched, and tdns-transport needs nothing beyond step 9's change: gossip in the answer to an HTTPS beat (decision 26), without which an ask sent over HTTPS is never answered. What changes is which names an agent puts in its own row, and that the list depends on the peer the message goes to.

**An ask and an answer.** Gossip rides both ways in an exchange of beats: in the beat (`SendBeatWithFallback` builds it), and in the answer to the beat (tdns-transport's beat handler calls the function tdns-mp gives it, `GossipForPeer`, `v2/hsync_transport.go`). Both go through `BuildGossipForPeer`.

- **In a beat,** this agent's own row lists a zone when the agent has held it in that group for the fixed time and has something to do for it: something owed or kept (the set of step 9, part f), or a sync with the parent that is under way, which is a chain or a NOTIFY that waits (`delegationSyncChains`, `v2/mp_s5_leader_sync.go`, from PR #188). That map is a field of the config (`conf.InternalMp`), which the transport bridge does not hold, so the bridge is given a callback, proposed `syncUnderWay(zone)`, set in `v2/start_agent.go`. The second is needed because the places that let a waiting NOTIFY go ask the hold again. That tells, and it asks.
- **In the answer to a beat,** the own row lists those zones too, and every zone that the beat it answers listed, if this agent has held that zone for the fixed time. That is the answer. The zone is listed in the row of the group this agent has it in. When that is not a group the two agents share, there is no row to list it in, and the asker reads that as not agreeing.
- **An answer tells and does not ask.** Nothing is listed because a peer's answer listed it.
- **The rows of other members** that a message passes on carry no zones. Only first hand counts (step 9).

Why an answer does not ask. Read for both directions alike, a listing would never end: one agent lists a zone because it has work, the other lists it because the first did, and when the work is done the first goes on listing it because the second does. A row is a list of names and cannot say why a name is in it. So what a peer lists in a beat is an ask, and what it lists in an answer is not, as design 4.9 says. A zone then leaves the beats when the last agent with something to do for it is done ("a zone that nobody has anything to do for is in no beat").

**When the answer comes.** As the code stands, one exchange late. tdns-transport builds the answer to a beat before the application has seen the beat: `RouteToCallback` runs the beat's handler, which calls `GossipForPeer`, and only then hands the message to `routeBeatMessage`, where step 9 notes what the sender listed. Both mechanisms share that path. So the answer to an ask would ride in the answer to the asker's next beat, a beat interval later.

Proposed: a middleware of tdns-mp's own on the router, registered with `Router.Use` after the one of step 6 and, like it, before `RouteToCallback`. For a beat it notes what the sender listed and then calls the next handler. The noting of step 9 moves there from `routeBeatMessage`. The answer then rides in the same exchange. It needs no change in tdns-transport beyond step 9's: its router runs a middleware before the handler, and the parsed message is in the context by then. The cost is that a beat's gossip is decoded twice, there and in `routeBeatMessage`. About 25 lines.

**How long a zone with nothing going on waits.** One exchange of beats with each voting member. An agent that gets something to do for such a zone lists it in its next round of beats, at most one beat interval later, and has the answers with that round. A recipient of the distribution that follows does the same before it takes it. So a change in a quiet zone starts up to one beat interval later than after step 9, and is taken up to one more later. Design 4.9 names that price. No beat is sent for it outside the rounds. If it is too slow, `Engine.BeatPeer` beats one peer now, under the bound of step 7. `KickBeats` is not the tool: each kick starts the fast pace of the rounds over. Neither is in this step.

**What is noted** changes, in `NoteToldZones`:

- After step 9 a sender's view is replaced as a whole by every beat and every answer. That no longer fits: a beat lists only what its sender has something to do for, and says nothing of its other zones.
- From a beat: each zone it lists is taken, with its group and the time. Nothing else that is kept for that sender changes. The zones it lists are also kept as what that sender asks, until its next beat.
- From an answer: each zone it lists is taken. A zone that this agent's beat asked about and that no answer of that exchange lists is dropped for that sender: it was asked and did not tell. `SendBeatWithFallback` built the beat and has what it asked. It sends the beat on every eligible mechanism and reads the answers in one loop, so the zones of one exchange are judged after the last answer is read. With decision 26 every answer carries gossip; an answer with none lists nothing, and drops what was asked.
- What was told runs out after the time a telling counts, as before. That is now how most of it ends.

**The check** is that of step 9. Two things around it change:

- A zone with nothing owed, kept or under way is not asked about, so nobody has told it lately, and by the check it is not settled. That is its usual state, and it costs nothing until there is something to do. The status says that, and not that every member has gone silent.
- A reason is added to those of step 9: `asked`, for a member that was asked in the last beat and whose answer has not come.

**Who reads a row's zone list today,** as found on the integration branch (main is the same):

| Reader | What it does with the list | After this step |
|---|---|---|
| `providerGroupForGossipZone`, `providerGroupFromGossipState` (`v2/apihandler_gossip.go`) | When the group manager has no group for a zone, finds the group by the rows that list the zone, and makes the group's zone list from the rows. Behind `gossip state --zone` and the auditor's web page for a zone | Goes. The group manager is the one source. An agent or an auditor that has not loaded the zone says "no provider group for zone", where the rows could answer before |
| `gossipMatrixRow` (the same file) | Puts the length of the list in each row of the API's answer, as `zones`. The CLI does not print it | Goes |
| `gossipMemberRow`, `GossipMemberRow.Zones` (`v2/auditor_dto.go`) | Copies the list into each row of the auditor's API answer and of the page's data. No template prints it | Goes. A group's zones and their count on the page come from the group manager, as today |
| `GetGroupState`, `deepCopyMemberState`, a debug line in `RefreshLocalStates` | Copy it | Unchanged |

`RefreshLocalStates` no longer puts a zone list in the row it keeps: the list is made per peer, when a message is built.

**At a start, and when many zones change at once,** a beat is not small. An agent that has started has an answer owed or kept for every zone it shares with a peer, until it has caught up, and a change of the providers of many zones gives each of them something to do. For that time the rows are as long as after step 9. They empty when the work is done. One more case comes round: an election asks for a sync of every zone of its group at every renewal of the lease, so once per lease the leader's rows list every zone of the group for one exchange.

**Names.** Status, in `agent parentsync status`, in place of the "settled" line of step 9 where nothing is going on:

```
  settled:        not asked: nothing is kept or under way for the zone
  settled:        no: asked agent.bravo.example. at 15:04:05, no answer yet
```

Log, debug, logger `gossip`: "asking the zone's members for their make-up" (`zone`, `group`, `why`).

**The beat path: what is touched, and what is not.**

Touched, all in tdns-mp:

- which zones `BuildGossipForPeer` puts in this agent's own row, now by peer and by whether the message is a beat or an answer, and that rows passed on carry none;
- one middleware on the router, which reads what a beat's sender listed before the answer is built;
- what `NoteToldZones` keeps of a beat and of an answer, in the two places that already call it after step 9, of which one moves to the middleware.

Not touched:

- tdns-transport, beyond step 9's change: the beat's payload, its own `Zones` list and what the transport reads from it, the sequence number, `MyBeatInterval`.
- The hsync engine: the rounds and their pace, `KickBeats`, the fast interval, the retriers and the beat back of step 7, the states of a peer, the edge to OPERATIONAL.
- The gossip types on the wire: `MemberState` and `GossipMessage` as they are.
- The rest of a row and of a message: the cells (`PeerStates`), the time, the beat interval, the propagation delay, the election record, the group's name. `MergeGossip`'s rule for which row is newer, `CheckGroupState`, `HoldFirstLocalRows`, the gate of an election.

**Tests.** Unit, beside those of step 9:

- `TestARowListsNoZoneWhenNothingIsGoingOn`, `TestABeatListsTheZonesThisAgentHasSomethingToDoFor` (owed, kept, a sync under way), `TestAZoneIsStillListedOnlyAfterTheFixedTime`.
- `TestTheAnswerToABeatListsWhatTheBeatAskedAbout`, `TestTheAnswerIsInTheRowOfTheGroupThisAgentHasTheZoneIn`, `TestAnAnswerIsNotAnAsk`, `TestAZoneLeavesTheBeatsWhenTheWorkIsDone` (two agents, to the end: no list in either direction).
- `TestTheAnswerRidesInTheSameExchange`: through the real router, with the middleware.
- `TestRowsPassedOnCarryNoZones`.
- `TestABeatThatDoesNotListAZoneTakesNothingAway`, `TestAnAnswerThatDoesNotListAnAskedZoneTakesItAway`, `TestWhatWasToldStillRunsOut`.
- `TestAZoneWithNothingToDoIsNotAskedAbout`, `TestSomethingToDoAsksAndIsReleasedByTheAnswers`, `TestARecipientAsksBeforeItTakes`.
- `TestTheGroupOfAZoneComesFromTheGroupManagerOnly`.

Existing tests that change: `TestProviderGroupForGossipZone_fromGossipStateTable` (`v2/apihandler_gossip_test.go`) asserts the reader that goes, and is replaced by the last test above. The rows of `TestSnapshotGossipForZone_singleMatrix` (`v2/auditor_web_test.go`) carry zone lists that nothing reads any more. `TestTheFirstLocalRowWaitsForGoodNews` (`v2/gossip_hold_test.go`) passes a zone list to `refreshLocalRow`, whose signature loses it. No golden file carries a zone in a row. Of step 9's own tests, three are rewritten: `TestARowThatListsNothingIsStillSentAndReplacesThePeersView`, `TestABeatWithNoGossipSaysThatItsSenderListsNothing` and `TestAZoneIsListedOnlyAfterTheFixedTime`.

Harness: `TestTransportBoundary_AnAskIsAnsweredInTheSameExchange`, over both mechanisms.

Fleet: the five checks of step 9, unchanged in what they ask. And three of its own. A fleet at rest: no beat lists a zone, at any agent. An operator's change in a zone at rest: it is at every provider within two beat intervals and the usual time of a distribution, and the zone is in no beat a little later. Every agent restarted: the zones are in the beats until every agent has caught up, and in none after.

**Done when** those pass, and a run with no change of providers shows nothing held for longer than one beat interval. `guide/multi-provider-advanced.md` section 5.1 then says what a row's zone list means, and `guide/operation-and-debugging.md` section 3 that the matrix shows no zones and that a zone at rest reads "not asked". A fleet's checks of gossip that read the members and the cells of a row need no change. One that reads a row's zone list, or the `zones` count in the API's answer, does.

**Size.** About 155 new and 95 changed lines in 8 files, and about 50 removed: `v2/gossip.go` (about 70 new, 45 changed), `v2/hsync_transport.go` (25, 20), `v2/settle.go` (30, 10), `v2/mp_s5_leader_sync.go` (10 new), `v2/apihandler_gossip.go` and `v2/auditor_dto.go` (10 changed, the removed lines), and the status in the API and the CLI (20, 10). Tests: about 300 lines.

**Risks.**

1. The listing that never ends, above. It is closed by taking only a beat's listing as an ask. The tests `TestAnAnswerIsNotAnAsk` and `TestAZoneLeavesTheBeatsWhenTheWorkIsDone` are there for it.
2. Every piece of work in a zone at rest now starts with an exchange. A beat or an answer that is lost costs a beat interval, where after step 9 the tellings of the last two rounds were at hand.
3. A beat is as long as before at a start and when many zones change at once. The gain is in the steady state.
4. Agents of step 9 and of this step do not mix (section 4). An agent of step 9 replaces a peer's whole view at every beat, and would see a zone come and go with each exchange.
5. An operator loses two things on the screen: the `zones` count of a row in the API's answer, and `gossip state --zone` for a zone that the agent has not loaded.

### Step 10. The switch: every HSYNC3 provider is a member (#158)

**Before it:** steps 1, 2, 6, 8 and 9 merged. Without step 1 a member with no role elects, without step 2 it edits, without step 6 it sends a SYNC and asks for the SIG(0) key, without step 8 its group votes by a union, without step 9 the agents act for a zone by different versions of who its members are, for as long as they hold different copies of it, and the zone can have two leaders. Steps 3 to 5 and 7 on every agent, for the newcomer to catch up by itself.

**Changes.**

- `zoneParticipants`: the first set it returns is every ON record. It returns the auditors as a third set. Its doc comment, and those of the functions that follow it (3.1), are rewritten: they state today's rule as a security boundary.
- `AuditorsForZone` (PR #169; step 1 brings it) reads the third set. Today it is the participants minus the voting members, which after this change would make every member with no role an auditor, and its caller `copyConfirmationToAuditors` would copy every final confirmation to each of them. If PR #169 has merged, the auditor's list of whom a distribution waits for (`awaitedConfirmers`) widens to every member but the auditors: it reads the voting members today, and a distribution waits for a member with no role too (decision 2).
- `ZoneAgentData` gets each agent's standing. `RecomputeGroups` fills the third list of step 8.
- `zone mplist`: the members with no role, and this provider's own standing. `MPZoneInfo` is defined in `v2/api_mplist_structs.go` and filled by `MPZoneInfoFromMPZoneData` (`v2/auditor_mplist.go`), which the auditor shares and which takes no local identity: the agent's handler passes its own for the `This` column. `v2/cli/mplist.go` only prints it.
- `GetParentSyncStatus` and `agent parentsync status`: the standing of this agent, and for one that does not vote the leader and term it has learned, or that none is known yet. `gossip zone-state` says the same.
- `PostRefresh`: one log line when the local standing becomes "no role".
- Nothing in admission, discovery, beats, distributions, the transfer set-up or catch-up changes by its own code: each follows from the first change.

A consequence to know (3.2): from this step on the leader's CSYNC waits for a member with no role as well, with no time-out. A member with no role whose agent is stopped holds every NS change of the zone at a parent that takes NOTIFY only, until its record is removed.

A second, which this step changes: a receiving agent that knows no leader for the zone answers a CSYNC REJECTED (`refuseCsyncNotFromLeader`), and one REJECTED makes the leader drop its held NOTIFY and fail the sync. A newcomer with no role knows no leader until a voting member's beat tells it (design 4.7). So in this step an agent that knows no leader for the zone yet keeps the CSYNC, as step 9 keeps a distribution, answers PENDING, and judges it when it has learned the leader. A CSYNC from an agent that is not the leader it knows is still REJECTED.

A second one (step 9): from this step on every edit of a provider's standing changes the zone's make-up, also an edit that only gives or takes a role. So every step of an add or a removal is followed by the hold of step 9: nothing that a provider makes happens for the zone until the fixed time after the last voting member has loaded the edit. A member with no role is not waited for in that agreement. It takes what is distributed when the zone is settled at it, and its confirmation is waited for as before.

**Names.** `zone mplist`, two new columns: `NoRole` (labels) and `This`, one of `signer`, `server`, `signer,server`, `auditor`, `member, no role`, `not listed`. Status:

```
  this agent:     does not vote in the zone (member, no role)
  leader:         agent.alpha.example., term 7, learned from gossip
  leader:         not known yet
```

Log, info, logger `zones`: "an HSYNC3 record and no role: member, no vote, no edits" (`zone`).

**Tests.** Unit:

- The `RoleLessRejected` case becomes `MemberWithNoRole`: its hello is accepted and routed; its SYNC, its election message and its request for the SIG(0) key are refused.
- `TestApplyHsyncDiff_roleLessAddExcluded` splits in two: `TestApplyHsyncDiff_offRecordExcluded`, and `TestApplyHsyncDiff_memberWithNoRoleRegistered` (registered, and reported to `OnHsyncMembersAdded`). In package `hsync` the zone view's `Participants` is a test mirror of `zoneParticipants` (`testParticipantsFromHSYNC3`): the mirror is updated, and the change itself is tested in package `v2`, through `mpZoneView.Participants`.
- `TestMembersVotingMembersAndAuditorsOfAZone`: roles, no role, OFF, and a zone without HSYNCPARAM.
- `TestADistributionWaitsForAMemberWithNoRole`, `TestADistributionWaitsForTheAuditor`.
- `TestAMemberWithNoRoleGetsTheTransferSetUp`.
- `TestAMemberThatKnowsNoLeaderYetKeepsTheCSYNC`, `TestAMemberWithNoRoleIsNoAuditor` (`AuditorsForZone`).
- `TestAZoneWithAMemberWithNoRoleIsInAGroupOfItsOwn`.
- `TestMplistShowsEachMembersStanding`.

Harness: `integEnv`, `TestTransportBoundary_MemberWithNoRoleCatchesUp`: its hello is accepted, it gets gossip, and its request for state is answered completely.

Fleet: an add with the owner's two edits apart. After the first edit the newcomer is in every agent's gossip, reports the group's leader, has caught up with every voting member, and has its `addrr` refused. The zone is in the group that has the newcomer as a member with no role, and that group's leader has taken it up; a new group has elected, among its voting members. After the second edit the zone is in the group in which the newcomer votes. No sample is bogus or lame at any point. Then the removal's first edit: the zone moves to a group that the leaving provider cannot lead, at once. Each of these is looked for after the hold of step 9, which every agent reports while it lasts.

**Done when** the fleet check passes for a provider that is added as a server. `guide/provider-changes.md` then loses the "Today" notes of its sections 2 and 3.2.

For a leaving signer the last part of the fleet check needs more than this plan. Today a signer that is taken out of `signers=` stops signing and drops to its combiner's serial, and its own agent refuses the lower serial: it stays on the old copy of the zone and does not see the owner's edit. The other agents refuse what it sends, so the zone stalls and is not harmed. That belongs to the removal (#147).

Step 9 adds to that case. The zone never settles at an agent that is stuck on the old copy: it holds the old make-up, and the others no longer tell it. So it keeps every distribution it is sent and confirms none. After this step it is a recipient, as a member with no role, so every distribution of the zone waits for its confirmation: another signer's new key does not get past its distribution, and the leader's NOTIFY(CSYNC) does not leave. Without step 9 it would take and confirm them by its old copy. So until #147 is fixed, taking a signer's roles away stalls what the providers make for the zone, from that edit until the provider's record is removed. Nothing is harmed, and the status of every agent says whom it waits for.

## 6. Decisions

Decided by the project owner on 2026-10-12. The design is written with them.

1. **How the asker knows that an answer is complete.** One message that is complete by construction, with a marker that names the request. A `replace` per type is a whole set, and the answer for one zone is small.
2. **A member with no role receives every distribution, and the distribution waits for its confirmation,** like any member. A provider on its way out still serves, and a new key of another signer must be at every server that still answers before it is used: the roll waits instead of answers going bogus. And being able to keep up with the other providers is a condition for serving the zone: if a provider cannot, that has to show before the zone owner gives it a role, not after. One exception, from the external review: a distribution that withdraws a member with no role does not wait for that member, whose agent may already be stopped. No step of this plan sends such a distribution: it is the removal's (#159, #138).
3. **An auditor that is down does not hold an election back.** The gate is the voting members. A SYNC is another matter: where a zone has an auditor, the auditor is a required participant, and the SYNC is not complete without its confirmation.
4. **A group is the set of providers with roles together with the set of providers without a role** (and the auditors), which is not the same as the set of providers. A provider with no role in a zone cannot lead it. Elections are per group. A zone that joins or leaves a group forces no election: it takes the leader of the group it arrives in, and that leader takes the zone up.
5. **A peer asks a restarted agent back,** once, on a `start` request. It is the only thing that finds a change the restarted agent made and lost from its queue. The request after a long outage stays too. Safety first: neither is cut to save code.
6. **A member with no role gets the zone transfer set-up from its upstream.** The HSYNC3 record states the zone owner's intent.
7. **What a provider contributed stands once its roles are gone,** until the removal takes it away. The provider cannot change it, its own DNSKEYs included, so its key machine holds for the zone while it leaves: no rollover and no new DNSKEY, and signing and re-signing go on with the keys it has. The removal starts at the edit that takes the roles away, and the leader of the group the zone is then in is responsible for it.
8. **The whole sync with the parent waits for catch-up,** NS and glue as well as DS. A leader that does not have all the information is in no position to decide. A leader that has just started does not know what the parent holds either: it first gets the zone's data from the other agents, its combiner and its signer, then asks the parent, then sends the difference.

9. **The sender rule holds over HTTPS too.** An agent or an auditor refuses an HTTPS `/beat`, `/sync/ping` or `/msg` whose body names another sender than the client certificate's name. It is done in step 6, ahead of issue #56, which keeps `/hello` and the choice of the certificate's identity field.
10. **A member that does not vote causes no election, and nothing it says about terms is taken.** A receiver takes its own row from it and nothing else. For who leads, it takes a newer term from a voting member at once. Whatever else a voting member tells it about who leads (a lower term, or the same term with another leader) it takes once the lease of the leader it holds has run out. A self-election still takes a term above zero, so that gossip tells it.
11. **Comms end when no zone is shared.** When the last zone shared with a peer is gone, the agent keeps the peer for a hold time of 24 hours and then removes it and stops beating it. A peer that is named again within the hold time is kept. A provider that a zone names again later is discovered afresh. Until it is removed the agent goes on beating it and takes its hellos and beats, which is the one exception to admission by a shared zone, and every message from it that requires a member is refused.
12. **A leader acts for a zone only when the views of it agree.** Agents see the owner's edit at different moments, with no network partition needed, and for that time a zone can have two leaders that sync the parent from different views. A leader sends nothing to the parent for a zone until every voting member of the zone's group holds the same make-up for it, and the leader of the group the zone left has shown that make-up, or has dropped the zone, or a short fixed time has passed (decision 16). Until then the sync is owed. Step 9. From the external review of this design. Since decision 23 this is one case of a wider rule: what holds the leader's sync holds everything that a provider makes for the zone. Its second half, about the leader of the group the zone left, is no longer a mechanism.
13. **The auditors stay in what defines a group.** The external review proposed to take them out, since an auditor neither votes nor leads. They stay: gossip is per group, and an auditor takes part in it as a member. The costs are accepted: an auditor edit moves the zone to another group, and the same providers with another auditor are another group. Auditors are few, and a zone's auditor is meant to be stable.
14. **What withdraws a member does not wait for it** (the exception in decision 2), and **taking a zone up gives it no new SIG(0) key while a voting member holds one, or has not answered** (step 9; decision 18 says when a new one is made). Both from the external review. Two things the code added to them are decided since: who is handed the key (decision 15), and what the leader's CSYNC waits for (decision 17).
15. **Any voting member of a zone may be handed its SIG(0) key** by a voting member that has it, and a refusal is answered. Before, only an agent's upstream or downstream was handed it, so a leader that was another signer could never get it.
16. **The hold's way out is a fixed time, not the previous leader's lease.** A lease belongs to a group and is renewed while the group has any zone, so a previous leader that is stuck on one zone would hold that zone's sync for ever. The new leader waits until the previous leader has shown the make-up or dropped the zone, or a few beat intervals have passed. That is safe because the first condition holds the previous leader too. In step 9 the time is three beat intervals from the zone's arrival, one more than a told make-up counts for (decision 19). Decision 23 takes away what this decision chose between: there is no second condition, nothing notes the group a zone left, and no previous leader is waited for. The fixed time stays, as the time an agent holds a make-up before it tells it, and it is still three beat intervals.
17. **The leader's CSYNC and a leaving provider is parked in the removal design.** The leader waits for every recipient's confirmation of the CSYNC with no time-out (PR #188), a member with no role is a recipient after the switch, and the CSYNC carries a leaving provider's NS removal to a NOTIFY-only parent. What the parent's scan does with a nameserver that lacks the record is not established. Nothing in this plan changes whom the leader's CSYNC waits for.
18. **Every voting member holds the zone's SIG(0) key, and a new one is made only when every voting member has answered that it holds none.** Today the private key is only at the agent that led the zone when the key was made; with its roles gone, or its agent stopped, nobody could sync the zone again. Every voting member now asks for a key it does not hold, at catch-up and when the zone publishes a KEY it has no private part for. A leader that has none asks the voting members and the previous leader, and silence is never "no key". Also accepted as proposed in step 9: a local key counts only if its KEY record is among those the zone publishes.
    - When every one of them has answered "no key" and the zone publishes no KEY, a new key is made and bootstrapped with the parent.
    - When the zone still publishes a KEY, the key is lost. Since the third external re-review (2026-10-13) no key is made then: a second key offered beside the first is refused by a tdns parent for good (tdns #917). The sync stays owed and an operator is told. The project owner accepted that stall (2026-10-13).
    - Decision 25 (2026-10-17) gives the way out: once tdns parents judge a bootstrap by what they find, the leader publishes a new KEY beside the lost one, bootstraps it, and deletes the old one with an update the new key signs. Until then the stall stays. Step 9 has the detail, and 7.5 the recovery.
19. **Two rules under the hold, from the external re-review.** What an agent was told counts only while it goes on being told: a told make-up counts for two beat intervals. And an agent that has moved a zone out of a group goes on telling that group's members so for the fixed time, also when it shares the zone with none of them. With them one voting member that has seen the edit stops the previous leader, and the fixed time of decision 16 stays: it is longer than the time a told make-up counts. The re-review proposed to keep the hold for as long as the previous leader reports the old make-up; the project owner keeps the fixed time. Step 9 has the detail: the two times are two and three beat intervals, and the second rule needs no row of its own, since a beat that no longer lists the zone says it. Since decision 23 the first rule stands as it is, and the second is no longer a mechanism of its own: an agent that has moved a zone lists it nowhere until it has held the new make-up for the fixed time, and the members of the old group see it gone from its rows at its next beat.
20. **A provider that has lost its roles goes on exactly as before, and initiates nothing** (2026-10-13; design 2.3). It takes the owner's zone and what the others distribute, signs with the keys it has, moves its serial on, notifies its downstream and serves. It makes no change of its own: no edit, no rollover, no new DNSKEY. The other providers go on treating what it contributed as before, and each withdrawal is a step of the removal. This says in full what decision 7 meant: that the provider can change nothing was never that it stops. What the others distribute it takes by the settle rule, as every member does (decision 23). It was decided on the lab's runs of the remove-a-signer scenario (2026-10-12, a parent that takes UPDATE), where the code does stop:
    - The leaving signer stopped signing at the owner's edit (#147). Its signer handed out the new zone unsigned, at a lower serial than its last signed copy, so its agent refused it and its nameserver stayed on the copy from before the edit. That copy still listed the provider's own NS.
    - The other two providers served the NS RRset without it. The parent refused the removal 39 times in ten minutes: "the nameservers of the zone do not agree on its NS RRset". The removal waited for the provider it was removing.
    - The remaining signer dropped the leaving signer's DNSKEYs from its key set 3 seconds after the edit, and the leader asked the parent to remove the leaving signer's DS together with its NS. Only the parent's refusal kept the DS there.

    None of the three is changed by this plan: they are the removal's work (#147, #138). The plan's own part is the agent's side (step 2).
21. **The leader withdraws a leaving provider's records, with or without that provider** (2026-10-13; design section 7). The design covers a provider that cooperates while it leaves. One that does not cooperate will have to be removed later, so the mechanism must not depend on the leaving provider: the withdrawal is the leader's operation, every other member applies it, and nothing waits for the provider it names. The owner's edit is its authority, by the rule the project owner gave for it: the leader may delete the DNSKEY and CDS records that another provider contributed, given that the provider is no longer listed in `signers=`, and the NS records and glue that another provider contributed, given that it is no longer listed in `servers=`. It may only delete, and a member applies the delete only from the zone's leader and only when its own copy of the zone says the same. That is a permission and not a timetable: the order and the waits are the removal's. A provider that cooperates applies it like any other change, which is what decision 20 asks of it, and the delete of its own DNSKEYs is where it stops signing and serving. Its form is open; a `replace` cannot be it (#159). It belongs to the removal, not to this plan.
22. **The zone's SIG(0) key is the group's, and it is rolled when a voting member leaves** (2026-10-13; design 4.1). The key is not owned by the agent that made it: every voting member holds the private key (decision 18), and the KEY record is published by the leader on the group's behalf, like the CSYNC, so it is no provider's contribution and is not among what a leader deletes (decision 21). A voting member that leaves still holds the private key, so the key must be rolled, and that is the leader's responsibility. The roll is the first step of the removal (decided 2026-10-13): with a provider that cooperates first or last does not matter, with one that does not the earlier the better. It must complete: if it fails, the removal goes on and the roll is tried again as its last step, and after that until it succeeds. It is the removal's work; this plan's steps 6 and 9 (who is handed the key, and who holds it) are what it builds on. Today the KEY is a contribution of the agent that generated it (`leaderKeySetup` publishes it with that agent as its origin), so the change of step 9 has to move it.

    What exists for a roll, as read in tdns and not run:
    - tdns has one, with no operator step at the parent. The child side is `RolloverSig0KeyWithParent` (tdns `v2/ops_key.go`): it makes a new key, sends "add the new KEY" signed with the old key, then "delete the old KEY" signed with the new one, then switches its keystore and publishes. Its only caller is the zone API's `roll-key`.
    - The parent side is `ApproveTrustUpdate` (tdns `v2/updateresponder.go`): a KEY add or delete in an update that validated under a key the parent trusts is approved. So the add rides on the old key's trust and the delete on the new key's.
    - A second key that arrives self-signed, as a bootstrap, is another path: it is stored as known and not trusted, and the parent then verifies it from what the child publishes. That is what the lab saw when a leader made a new key at take-up: accepted where every nameserver served the new KEY, "key known, but validation failed" where the leaving provider's nameserver served its old copy.
    - tdns-mp has no caller for the roll. The agent's key lives in the agent's own keystore, not in the daemon's zone keystore the tdns function is written for.

    A roll has been run in tdns by the project owner, some time ago, and never in tdns-mp or on the lab's fleets: a test of it is to be designed before the leader's roll is built on it.

    One more reason for the roll to go through the old key: a self-signed upload of a second key races the key's publication. The child offers the key as soon as the parent says it does not know it, in the second the key is made; the parent then finds another KEY published at the zone's apex and records a failed verification that it does not revisit (tdns issue #917; seen in the lab on 2026-10-13, where a newcomer made a key at take-up). The roll's own updates need no verification from DNS.

    What a leader's roll adds, in order: the new key at the leader; the add at the parent, signed with the old key; the new private key to every voting member that stays, which needs a hand-over the leader starts (today a member can only ask); the new KEY published as the leader's, in place of the old, only after the parent has taken it; the delete of the old key at the parent, signed with the new one; and every member retires the old private key.

23. **Nothing is changed for a zone until its voting members agree on its make-up** (2026-10-13; design 4.9). The hold of decision 12 had a hole. Its fixed time was counted from the zone's arrival at the new leader only, so a voting member that both leaders counted, and that loaded the owner's edit later than the new leader, could be counted by both for as long as a telling counts. The fix: an agent tells a make-up for a zone only once it has held it for the fixed time, on its own clock, which starts again at every change of the make-up and at the agent's start. The project owner then widened the rule: after a change of a zone's providers nothing is to change until things have settled, in the zone as well as at the parent. Of two forms, a pause for a time at each provider that has seen the edit, and agreement among the voting members, agreement was chosen: a provider that has not seen the edit is in no pause, so time alone does not hold it.
    - A zone is settled at an agent when the agent has held its make-up for the fixed time and every other voting member of that make-up has told it the same make-up within the time a telling counts.
    - While it is not settled the agent starts nothing for the zone: no distribution of its own, and, if it leads, nothing to the parent, the bootstrap and the roll of the zone's SIG(0) key included. And it takes nothing: a distribution that arrives is kept, neither applied nor confirmed, and handled when the zone is settled.
    - Only the voting members have to agree. A member with no role takes by the same rule and is waited for as a recipient as before. An auditor changes nothing and confirms at once, as before.
    - Not held: the owner's zone itself (its transfer, signing and serving), beats and gossip, elections, and a request for the zone's state. The answer to such a request is a distribution, and waits. "Nothing is to change" means what a provider makes. Every provider, a leaving one included, goes on following the owner's zone while the voting members settle; a nameserver that stopped doing so would be the one that disagrees with the others on the zone's NS RRset, which is what the lab saw (decision 20).
    - What is kept is judged when the zone is settled, by the zone as the agent then holds it: applied and confirmed, or refused. Nothing kept under one make-up is applied under another without being judged again.
    - What it does not cover: an owner's edit whose old and new sets of voting members have no member in common. From the fixed time after the new side has the edit until a voting member of the old side loads it, both sides act; the old side does not have to be stuck. Only the order of the owner's edits closes that (one provider at a time, each edit settled before the next), and the guide says that an edit which exchanges the whole set is not to be made (its section 1).
    - The margin between the two times (one beat interval, and never less than a beat's send time-out with a reserve) is what covers a telling that is heard late and clocks that run apart. A telling later than the margin is counted for too long.
    - It replaces the second half of decision 12 and what decisions 16 and 19 added to it. No group that a zone left is noted, and no previous leader is waited for.
    - The costs, accepted: after a change of make-up nothing that a provider makes happens for the zone until the fixed time after the last voting member has loaded the change; the same after the start of a voting member's agent, for its zones; and a voting member that cannot be heard holds every change that a provider makes in its zones.

    Step 9 has the detail.
24. **A row lists a zone only while there is something to do for it, as a stage of its own after the settle rule** (2026-10-13; design 4.9, "The telling"). A row of gossip lists every zone of its group today, and a beat carries every member's row, so a beat grows with the number of zones. The first decision was to leave that as it is and to put a cheaper form off, with one idea for later: to list only the zones added to a group and removed from it since the last beat. This replaces that idea. A zone is listed to a peer only when the agent has held it for the fixed time and either has something owed or kept for it or was asked about it by that peer. Listing a zone in a beat tells and asks, and the peer answers; an answer tells and does not ask, or two agents would go on listing a zone to each other. A zone that nobody has anything to do for is in no beat. The project owner took it as an improvement, with one concern: churn in the code of the beats, which was considered settled. So it is a stage of its own. First the settle rule on today's full listing (step 9), then the listing (step 9b), each judged alone on a fleet. Step 9b says which parts of the beat path it touches and which it does not.

25. **A parent judges a bootstrap by what it finds** (2026-10-17; design 4.1; written into tdns #917). A bootstrap is for a first key and for a key whose trust has broken, for instance a lost private key. A key that works is changed by a roll: the new key added in an update the old one signs, the old one deleted in an update the new one signs, with nothing to verify from DNS and nothing that has to be published. So what a zone publishes does not say which key the parent trusts. A parent that trusts a key OLD and gets a bootstrap for NEW looks for NEW where its policy says, at the child's apex or at its nameservers. If every nameserver it asks serves NEW only, NEW replaces OLD. If they serve OLD and NEW, it trusts both, and the child deletes OLD with an update that NEW signs (not with a second bootstrap). If they serve OLD only, or the nameservers disagree, it keeps OLD and nothing of NEW, not even a mark of a failure, so that the child can offer NEW again once it has propagated. The lookups are rate-limited per child. A KeyState inquiry for "any key" would be cleaner, but it is a change of the option's specification, and the path that uses only what the child can see must work regardless. For tdns-mp it means: step 9 makes a key only when every voting member has answered "no key", and asks nothing of the parent before it does; and a zone whose key is lost can recover once tdns parents follow this rule (decision 18).
26. **The answer to an HTTPS beat carries gossip** (2026-10-17), as the answer to a DNS beat does. Today it has no gossip field, so the settle rule of step 9, which counts a peer's telling from the answer to every beat, and the ask and answer of step 9b, would work over DNS only. It is a change of tdns-transport and a new pin, and step 9 needs it first.

Also decided:

- tdns-mp does not support agents that are out of step with each other (section 4).
- Issues #131 and #132 go with the membership work (step 7).
- Issues #180 to #183 are fixed in one pull request of their own. Step 8 needs it first.

## 7. What this plan depends on, and what comes after

### 7.1 To be merged first

| What | State, 2026-10-16 | Steps that need it |
|---|---|---|
| PR #163 (#143, #130) | Merged | 1, 6 |
| PR #188 (#175 with #151) | Merged | 3, 5, 6 |
| PR #164 (#32) | Merged | 4, 5, 9, 10, for the status command |
| PR #162 (#84, #128, #145) | Open, mergeable | 4, 7 |
| PR #193 (#145, refused beats), a draft on top of #162 | Open | 4, 7 |
| PR #169 (#152), or its three helpers | A draft | 1 |
| PR #185 (#179) | A draft; conflicts with main | 8, 9; and 1 through #186 |
| PR #186 (#180 to #183), on top of #185 | A draft, on an old head of #185; conflicts | 1 (the same functions), 8 |
| tdns-transport: gossip in the answer to an HTTPS beat (decision 26), and the pin | Not started | 9, 9b |

Not needed by any step, and worth having: tdns #917's two sides. The child's bootstrap waiting until the nameservers serve the key; until then step 9 waits the propagation delay. The parent's rule of decision 25; until then a lost key is a stall (7.5).

PRs #161, #165, #166, #167, #168, #187 (#144), #189 (#171, #170) and #190 (#73) are needed by no step. Three of them edit a function or a file that a step edits, in another place: PR #167 (`v2/combiner_chunk.go`, step 6), PR #168 (`routeBeatMessage`, steps 6, 9 and 9b), and PR #187 (`MPPreRefresh`, step 4).

### 7.2 Issues #179 to #183, each against the steps

None of the five is a step of this plan. Each has a change on the integration branch (2.10).

- **#179, a zone that arrives in a group with a leader (PR #185).** It is design 4.1. Three things it leaves open are steps of this plan: the zone that leaves (step 8), the zone that arrives while an election runs (step 8), and the new SIG(0) key (step 9).
- **#180, the deadlock (PR #186).** Step 8 edits the five callers of `CheckGroupState`, one of which was the place of the deadlock, and step 10 makes recomputes more frequent.
- **#181, two recomputes at once (PR #186).** With step 8 a zone's group is how its leader is found, and a provider change is two or three recomputes in a row on every agent. Step 9 writes since when each zone's make-up is held in that same recompute, and its key part leans on the order in which a recompute tells what it changed: the zones that joined first, the groups that are gone after.
- **#182, the election manager is not told (PR #186).** It is design 4.8. With step 8's key a group never changes its make-up: a change is another group. So what is left of "a group changes" is that it gains and loses zones, and that it disappears.
- **#183, the leftovers (PR #186).** Two of the three bear on this plan. A group's timers now read the group when they fire. And an agent whose own record is removed now recomputes, so that the zone leaves its old group there too: that is the last edit of every removal.

### 7.3 Other work that is decided, and where it meets this plan

- **#175 with #151 (PR #188):** the leader makes the zone's CSYNC, sends it to every member by SYNC, and sends the NOTIFY when all have confirmed and the propagation delay has passed, with a ceiling on that delay (`delegationsync.notify-wait-max`). It meets this plan in four places, all in 3.2 and in the steps named there: the answer of step 3 carries a CSYNC from the leader only; the hold of step 5 comes before the CSYNC is made; the sender rule of step 6 and the leader rule of that pull request apply one after the other; and after step 10 the confirmations waited for include a member with no role. A fifth is step 9: the CSYNC is made, and each recipient confirms it, only when the zone is settled there.
- **#171 and #170 (PR #189):** a combiner that restarts serves its stored `_signal` KEYs again; the auditor's identity zone is re-signed. Neither is in a step. #171 is next to the own read of step 3, and a reading for it found that a combiner that has just restarted does answer RFI EDITS before it has loaded its stored contributions, with an empty map: the same at PR #189's head. Step 3 changes that answer.
- **#73 (PR #190):** an identity zone listed in the config with parentsync gets a warning. No step touches it. Step 1's guard leaves a zone with no HSYNC3 records as it is.
- **#56 and #59, HTTPS:** step 6 adds one comparison (3.2). The rest, `/hello` included, stays with #56.

### 7.4 The removal starts where this plan ends

The removal (#147, #138, #159, items 3 to 5 of #137) is not in this plan. Its starting point is the member with no role of step 10, and the design's section 7 holds what is decided for it.

Four things this plan leaves to it:

- The leaving signer's agent stays on an old copy of the zone (step 10, the last paragraph).
- The leader's CSYNC and a leaving provider (decision 17). The leader waits for every recipient's confirmation of the zone's CSYNC with no time-out (PR #188), a member with no role is a recipient after step 10, and at a parent that takes NOTIFY only the CSYNC is what carries the leaving provider's NS removal. Whether not waiting helps is not established: the parent scans every nameserver it delegates to, the leaving provider's among them.
- The signer's side of design 2.3: a provider that has lost its roles goes on signing and following the zone (3.5, decision 20).
- The roll of the zone's SIG(0) key when a voting member leaves (decision 22). The leader sends it to the parent, so the settle rule of step 9 holds it as it holds the sync and the bootstrap. Nothing of the roll itself is in this plan.
- With the roll: a member keeps the KEY that the leader publishes and no other (step 9, the third item of "The KEY record is the group's"). A roll is where two KEY records first differ.

### 7.5 After this plan

The recovery of a lost SIG(0) key (decisions 18 and 25), once tdns parents judge a bootstrap by what they find (tdns #917): the leader publishes a new KEY beside the lost one, bootstraps it once the nameservers serve both, deletes the old key with an update the new key signs, and takes the old KEY off the apex. Until then step 9's stall stands. It needs the third item of step 9's "The KEY record is the group's" too, which goes with the roll (7.4).

A provider that is named in `signers=` while it runs does not sign until its signer is restarted (#146), and the key machine's `SignersChanged` has no caller (#136). Both need what the design gives a newcomer before it has a role: comms with every member, and the other signers' DNSKEYs with what they say about them. With that in place, calling `SignersChanged` from the refresh when `signers=` changes, and binding the signing policy at that moment, is the next step. It is not part of this plan.

Two things that the settle rule of step 9 leaves for later. What an agent keeps for a zone that is not settled is in memory: an agent that restarts during a hold loses an operator's edit that the operator was told is kept. And the auditor's view of a distribution does not say that a member keeps it because the zone is not settled there (#152).

What else the design leaves out is listed in its section 7.
