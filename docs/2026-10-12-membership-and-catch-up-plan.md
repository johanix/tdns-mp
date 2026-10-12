# Membership and catch-up: implementation plan

**Status:** PLAN, revised 2026-10-12. No step is started. Section 5 holds the status of each step.

This is the plan for the design in `2026-10-12-membership-and-catch-up-design.md` ("the design" below). The design describes membership and catch-up as they are meant to stand. This document holds what is dated: the difference from today's code, where each rule of the design lands in the code, the steps, and the decisions the design rests on.

For issues #158, #157, #172, #149, #137 (item 2), #131 and #132.

**Base.** Two revisions of tdns-mp were read for this revision of the plan:

- **main**, `90ca02c`.
- **the integration branch**, `test/e2e-fix-round-2026-10-12` at `4bf5afc`. It is main with the open pull requests #161 to #169, as they stood when it was built, and six draft pull requests: #185 (the change for #179), #186 (#180 to #183, on top of #185), #187 (the fix for #144), #188 (#175 with #151), #189 (#171 and #170) and #190 (#73). It was read in full at `0e000da`. What it gained up to `4bf5afc`, which is #186, the second half of #188, #189 and #190, was read as a difference, and the steps are corrected for it.

The steps of this plan are implemented on main after those have merged, so the integration branch is the better picture of the starting point. Where the two differ in something a step touches, the text says so. Line numbers are given only where they help, with their revision.

tdns is pinned at `81ce1fda` on main and at `ea645621` on the integration branch. tdns-transport is pinned at `b15bedb7` on both.

Nothing was built or run for this document: every statement about the code is a reading of it. Where a reading could not settle a point, the text says "not established" and what would establish it.

## 1. What exists, and what is new

Most of the machinery of the design exists.

**Exists, and is used as it is:** discovery, hello, beat and gossip; provider groups; the election protocol and the lease; a participant that does not vote (the auditor); the request for a zone's state (RFI SYNC) and its answer (`resync-targeted`), today behind the operator's `resync --pull`; key states on a DNSKEY operation; the rule that a zone's DS set is unknown until every signing provider has spoken; the order guard for a `replace` that arrives late.

**Promised by the guide, and not done by the code:** `guide/synchronization-model.md` (section 2) says that an agent rebuilds its state after a restart from three sources: its combiner (RFI EDITS), its signer (RFI KEYSTATE) and each peer agent (RFI SYNC). The code asks the first two and never the third (2.5). Asking the peers at a start is therefore a repair of the existing design, not an addition to it.

**On the integration branch, not on main, and used by this plan:**

| What | Where it comes from |
|---|---|
| `isAmong`, and the sender check of the group election | PR #163 (#143) |
| `VotingMembersForZone`, `AuditorsForZone`, `isVotingMember` | PR #169 (#152), a draft |
| A refused beat back is sent again; a peer that refuses a hello, or whose key is wrong, is discovered again | PR #162 (#128, #84, #145) |
| `tdns-mpcli agent parentsync status`, `election`, `inquire`, `bootstrap` | PR #164 (#32). Main has the API commands only |
| The leader makes the zone's CSYNC and sends it by SYNC; a CSYNC is taken from the leader only; the NOTIFY waits for every recipient's confirmation, then for the propagation delay, and the parent is checked again | PR #188 (#175, #151), a draft |
| `DeliveredBy` on a remote update: the sender the transport established | PR #188 |
| `RecomputeGroups` reports a zone that arrives in a group, and its leader takes it up | PR #185 (#179), a draft |
| Recomputes run one at a time; the heartbeat round holds no group lock across a callback; a group that loses its last zone drops its election state; a group's timers read the group when they fire | PR #186 (#180 to #183), a draft |

**New:**

1. Membership follows the HSYNC3 records, not the roles (design 1 and 2).
2. What a sender may do is checked per message, not by admission alone, and a message counts as sent by the sender the transport established (design 3).
3. The answer to a request for state is complete: every type, the key states, always sent, and marked (design 5.4 and 5.5).
4. The request is sent by the agent itself: at its start, when it joins a zone or gets its first role, when a peer says it has started, and after a long outage (design 5.1). A leader's sync with the parent waits for the answers (design 5.6).
5. A group is defined by its members together with what each one is, so that all its zones agree on who votes. The election's edges: no election without a vote, a leader when the voting members become one, and a leader that drops a zone which leaves its group (design 4).
6. An agent whose provider has no role refuses its operator's edits (design 6).
7. Two bounds on the beats that recover a peer: how often repeated hellos cause a beat back (#131), and what happens to the work on its way for a peer that is removed (#132). And the removal itself: comms with a peer end when no zone has been shared with it for a hold time (design 3.1).
8. A leader acts for a zone only when the views of it agree, and taking a zone up gives it no new SIG(0) key (design 4.9 and 4.1).

No message type is added. One optional object is added to the sync-family payload (3.4). Two config keys are added (steps 4 and 7).

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
- **A new SIG(0) key at a move.** `leaderKeySetup` (`v2/start_agent.go`) uses a local key, else asks the zone's agents that are OPERATIONAL, else generates a keypair and publishes a `replace` of the KEY RRset. The asking seldom succeeds: the answering side hands the key only to a requester that is its upstream or downstream by the HSYNC3 `upstream` fields (`MsgHandler`, `sig0key`), and a refusal there sends no answer at all, so the requester waits out its time and reads "peer did not respond". Two signers have no such relation. On a test fleet a zone that moved to a group with another leader got a new key.

### 2.11 The beats that recover a peer

`v2/hsync/beat_retry.go`. A hello from a peer whose mechanism is already introduced gets one beat back (`Engine.BeatPeer`, called from `routeHelloMessage`). On the integration branch a beat back that fails is sent again after the fast interval, twice at most (`Engine.beatBack`, PR #162).

**#131.** One beat back per peer is on its way at a time (`beatingBack`). Nothing sets a minimum gap between two of them, and the hello's sender is the one its payload names (2.9). So a peer that repeats its hello, or any admitted peer that names it, causes a beat back for each hello that arrives after the previous beat has returned.

**#132.** The engine keeps `beatFailing`, `beatRetrying` and `beatingBack` per peer identity. A retrier holds the `*Peer` it was started with for up to 30 s and checks only that the registry has a peer of that identity. `beatPeerOnce` (`v2/hsync/beat.go`) writes its `*Peer` back into the registry after every beat, and `sendHelloToPeer` (`v2/hsync/hello.go`) does the same after a hello. `beatFailing` is cleared only by a successful beat. So a beat or a hello that is on its way when its peer is removed puts the peer back, and a removed peer keeps its failure marker, which keeps a retrier from starting when the identity returns.

Three readings bound the issue:

- `Engine.RemovePeer` has no caller outside its own test, on either revision. A peer that leaves its last shared zone stays in the registry as LEGACY, and is beaten at every round for as long as the daemon runs. Nothing replaces a stored peer with another object. The faults of #132 are therefore latent: they become real with the first caller of `RemovePeer`, which step 7 adds.
- The engine's set of zones per peer is not the set of shared zones. `ReconcileZone` (`v2/hsync/reconcile.go`) marks every participant of a zone as needed whether or not the local agent is one of them: it has no gate like the one `ApplyHsyncDiff` has (`GateOnLocalPresence`). An agent whose own record has left a zone therefore keeps that zone on its peers for as long as the zone is in its config. And a zone that leaves the config is never taken off its peers: `reconcileAllZones` visits only the zones the agent has.
- The beat's sequence number is read from the transport's count of successful beats, sent, and echoed. Nothing on the receiving side, in tdns-mp or in tdns-transport at the pinned revision, compares it with an earlier one. Beats from several loops can carry the same number, and nothing depends on it. Beats to one peer need not be sent one at a time.

### 2.12 Found on the way

- **A multi-operation update reports only its last `replace`.** `processOperations` (`v2/agent_policy.go`) assigns the result of each `replace` to `changed` instead of adding to it. An update with several `replace` operations whose last one changes nothing is stored and not passed to the combiner. The complete answer of design 5.4 always has four or five.
- **An update that changes nothing and lists nothing is never confirmed.** The short path for a remote update whose result is already there (`SynchedDataEngine`, the `remote` case) sends the final confirmation only when it has at least one applied or removed record to report. An answer of five empty `replace` operations would stay in its sender's queue until it expires.
- **The sync-family payload has two types.** The sender marshals `core.AgentMsgPost`, a type of tdns (`syncAppMessage`, `v2/mp_send.go`). The receiver parses `DnsSyncPayload`, tdns-mp's own (`v2/mp_wire_payloads.go`). The sent form has no distribution ID in it: over DNS that travels in the query name, and over HTTPS the receiver makes a new one. Two agents' distribution IDs can coincide. So a request cannot be named by its distribution ID.
- **`GetZoneAgentData` relates upstream and downstream through every HSYNC3 record,** OFF ones included.

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

Over HTTPS the middleware has nothing to compare (2.9). There the sender the transport established is the name in the client's certificate (design 3.2, decision 9). The pipeline in tdns-transport takes no sender beside the body, so step 6 makes the comparison in `apiSyncEndpoint`, before the body enters the pipeline, for the three endpoints behind the TLSA check: `/beat`, `/ping` and `/msg`. `/hello` is outside that check, because a peer's TLSA record need not be known when its hello arrives. It stays with issue #56, and so does the choice of the certificate's identity field: step 6 reads the common name, as the TLSA check does today.

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
| Distributions, and the wait for confirmations | Every member | `EnqueueForZoneAgents`, `GetDistributionRecipients`, `TrackDnskeyPropagation`: unchanged |
| Election messages | Voting members and auditors | `broadcastElectToZone` |
| Requests for the zone's state | Voting members | `CommandHandler` (`send-rfi`), the tracker of step 4 |
| The request for the SIG(0) key | Voting members | `leaderKeySetup` (`v2/start_agent.go`), `CommandHandler` |
| "parentsync-done" | Every member | `notifyPeersParentSyncDone`: unchanged |
| The leader's CSYNC (PR #188) | Every member, and the leader's own combiner. The NOTIFY waits for the final confirmation of each, with no time-out | `distributeCsync`, `GetDistributionRecipients`: unchanged |

**The leader's CSYNC, where two rules meet.** Since PR #188 the zone has one CSYNC, the leader's, sent as the leader's own contribution by SYNC. Two rules then apply to it at a receiving agent, one after the other, and they do not conflict:

1. Step 6, in the router's handler: the sender of a SYNC is a voting member of the zone. A leader always is one.
2. PR #188, in the data engine: a CSYNC operation is taken only when the delivering agent and the agent the update names are both the leader this agent knows for the zone (`refuseCsyncNotFromLeader`). The other operations of the same update go on. The deliverer is read from `DeliveredBy`, which step 6's middleware makes the same as the named sender for every message.

Three consequences are worth knowing:

- **Whom the NOTIFY waits for.** The leader's own combiner and every agent that `GetZoneAgentData` lists: today the role holders, the auditor among them, and after step 10 every member, a member with no role among them. That is decision 2. There is no time-out. So after step 10 a member with no role whose agent is stopped holds every NOTIFY(CSYNC) of the zone until its record is removed. An UPDATE to the parent is not held.
- **The exception of decision 2 does not reach it.** The exception names a distribution that withdraws a member: its own NS records, DNSKEYs or DS. The CSYNC is not one of those, and it is what carries an NS change, a leaving provider's NS records included, to a parent that takes NOTIFY only. No step of this plan changes what the CSYNC waits for.
- **A catch-up answer.** Design 5.4 names CSYNC among the types every answer carries. With PR #188 a CSYNC operation from an agent that does not lead the zone is taken out and answered with a final confirmation REJECTED, an empty `replace` too. So in step 3 only the zone's leader puts a CSYNC operation in its answer.

### 3.3 Elections (design 4)

| Design | In the code | Step |
|---|---|---|
| 4.1 The group is its members with what each one is | `RecomputeGroups`, `ComputeGroupHash`, `ProviderGroup` | 8 |
| 4.1 A zone that arrives takes the group's leader, and the leader takes it up | PR #185. This plan adds nothing to it | before 8 |
| 4.1 Taking a zone up never gives it a new SIG(0) key | `leaderKeySetup` | 9 |
| 4.1 An agent that led the group the zone left stops acting for it | `zoneJoinedGroup` drops the zone's sync chain | 8 |
| 4.2 The counts | The two peer functions | 1 |
| 4.3 The gate | The five callers of `CheckGroupState` pass the voting members | 8 |
| 4.4 Start, vote, win | `startElection`, `startGroupElection`, `HandleMessage`, the two `finalize` functions, `ApplyGossipElection` | 1 |
| 4.5 One check for every change | A new `zoneChanged` on the election manager, called from `PostRefresh` | 8 |
| 4.6 One voting member; a term for a self-election | The two self-election branches take the next term | 8 |
| 4.7 What a member that does not vote takes | A newer term from a voting member at once, as today. A lower one once the lease it holds has run out: `MergeGossip`, `ApplyGossipElection` | 8 |
| 4.7 What it reports | The status commands say that this agent does not vote | 10 |
| 4.8 Retiring a group | PR #186 (#182). Not a step of this plan | before 8 |
| 4.9 Every agent tells which make-up it holds for a zone | It does today: its own row in a group's gossip lists the zones it has in that group. Read first hand, per peer | 9 |
| 4.9 A leader acts only when the views agree | One more condition beside step 5's hold; the group a zone left, noted in `zoneJoinedGroup` | 9 |
| 4.9 A zone that arrives while an election runs | `finalizeGroupElection` reads the group's zones when it sets the leader | 8 |

### 3.4 Catch-up (design 5)

**On the wire.** One optional object at the top level of the sync-family payload, JSON key `catch_up`. Proposed:

```go
// CatchUp travels on an RFI SYNC, and on the SYNC that answers it.
type CatchUp struct {
    Request  string `json:"request"`            // the request's name, chosen by the asker
    Reason   string `json:"reason,omitempty"`   // on the request: start, join, role, peer-start, outage, manual
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
| 5.4 The answer | `resync-targeted`, rewritten: five `replace` operations, the key states, always sent, marked | 3 |
| 5.4 At the asker | `EvaluateUpdate` and `ProcessUpdate` as any remote update; `noteReplaceOrigin` keeps an older message from undoing it; `NoteForeignKeyStates` takes a complete answer as having spoken | 3 |
| 5.1 When | The edge to OPERATIONAL in `SendBeatWithFallback`; the zone's first load; a standing that rises at a refresh; a `start` request received | 4 |
| 5.5 The tracker, 5.7 the retries, 5.8 the pacing | New, `v2/catchup.go` | 4 |
| 5.6 What waits | `DelegationSyncher`, both sync commands | 5 |
| 5.6 "DS set unknown, waiting for" | `DelegationSyncher`, when the analysis has no DS set to compare | 5 |

### 3.5 The agent's own operator (design 6)

- `add-rr`, `del-rr` and `update-local-zonedata` refuse, and so does the `local` case of `EvaluateUpdate`, so that no other path gets past. That case also takes the DNSKEY distribution that follows the signer's inventory (`SyncRequestHandler`). This is item 2 of #137. Step 2.
- `parentsync-election` and `parentsync-bootstrap` refuse. Step 2.
- `resync --push` sends nothing to peers and says why. Step 2.
- `zone mplist` gets each member's standing. `agent parentsync status` gets the standing of this agent, the learned leader and term, and the tracker's state per voting member. Steps 4 and 10. The mpcli command exists with PR #164.

The freeze of design 2.2 has two sides. The agent's side is step 2: nothing that a provider with no role would contribute leaves its agent. The signer's side, that its key machine makes no transition for the zone while the provider has no role, is not in this plan. Today a signer that is taken out of `signers=` stops signing altogether (#147), and what its key machine does while it leaves belongs to the removal.

## 4. Agents in step

tdns-mp does not support agents that are out of step with each other: all agents of a zone must be in sync protocol-wise. So this plan has no code for a peer that runs an earlier build:

- no detection of a peer that answers a request for state without the marker;
- no order among the zones a beat or a hello names;
- no fallback for a group in which some agents count members and others count role holders, or compute the group's hash from another key;
- no reading of a peer whose gossip rows do not list its zones: it reads as holding no make-up for them, and a leader holds (step 9).

An agent that is out of step shows as a stall, not as harm. Its answer has no marker, so it does not count as complete and is asked for again (design 5.7). A zone is in different groups on the two sides, and the sides agree on no leader for it.

Two rules for operators follow:

1. Every step of section 5 goes to all agents of a zone together. For step 8 that includes the auditor: the group's hash changes for every group.
2. Every agent of a zone runs the whole design before the owner starts a provider change in it.

## 5. The steps

Each step is one pull request. Each of steps 1 to 9 is safe to merge once what its "Needs first" column names is in, and changes nothing for a zone in steady state except what the step names. Step 10 is the switch and needs the others.

The sizes are estimates from reading the code, tests apart: files touched, and lines new and changed. They are an order of magnitude, not a count. Tests are likely to be two to three times as many lines.

| Step | What | Issues | Needs first | Files | New | Changed | Mostly | Status |
|---|---|---|---|---|---|---|---|---|
| 1 | No election without a vote | #172 | PR #163 | 4 | 80 | 40 | Guards | Not started |
| 2 | An agent with no role refuses its operator's edits | #137 item 2 | Step 1 | 4 | 50 | 20 | Guards | Not started |
| 3 | The complete answer | #157 | PR #188 | 10 | 210 | 120 | Changes to existing functions | Not started |
| 4 | Asking by itself | #157 | Step 3, PR #162, PR #164 | 8 | 470 | 80 | New machinery | Not started |
| 5 | The sync with the parent waits | #157 | Step 4, PR #188 | 5 | 110 | 40 | Guards, and a little state | Not started |
| 6 | A rule for the sender and the recipients of every message | | Step 1, PR #163, PR #188 | 9 | 150 | 80 | One middleware, guards | Not started |
| 7 | Beats to a peer that repeats its hello, or is gone; the end of comms | #131, #132 | PR #162 | 10 | 140 | 40 | Guards, and one loop | Not started |
| 8 | The group by its make-up, and its election | #149 | Steps 1 and 6, PR #185, PR #186 | 8 | 140 | 120 | Changes to existing functions | Not started |
| 9 | A leader acts only when the views of a zone agree; no new key | | Steps 4, 5, 6 and 8, PR #185 | 9 | 230 | 60 | New state and a second hold | Not started |
| 10 | The switch: every HSYNC3 provider is a member | #158 | Steps 1 to 9 | 9 | 80 | 150 | Changes to existing functions | Not started |

About 1,650 new and 750 changed lines in all. Steps 4 and 9 are four tenths of the new lines.

What kind of code each step is:

- **Guards in existing functions:** steps 1, 2 and 7, most of 5 and 6.
- **Changes to what existing functions do:** steps 3, 8 and 10, and the key set-up of step 9.
- **New machinery:** the tracker of step 4, the sender middleware of step 6 (about 30 lines), the repeated own read of step 3 (about 40 lines), the removal of a peer that shares no zone in step 7 (about 40 lines), `zoneChanged` of step 8 (about 40 lines), and in step 9 the zones each peer told and the group a zone left (about 120 lines) and the repeated request for a key (about 50 lines).

### Step 1. No election without a vote (#172)

**Before it:** PR #163, for `isAmong` and the sender check of the group path. PR #186 edits the same functions (`startGroupElection`, the timers): this step is made on top of it. The three helpers of PR #169 (`VotingMembersForZone`, `AuditorsForZone`, `isVotingMember`) are needed too. PR #169 is a draft that waits for another reason, so this step brings them, taken as they stand in that pull request, unless it has merged.

**Changes.**

- `v2/provider_groups.go`: `standing` and `zoneStanding` (3.1).
- `startElection`, `startGroupElection` (`v2/parentsync_leader.go`): return, with a debug line, when the zone has an HSYNC3 RRset and the local agent is not among its voting members. For a group the test is `isAmong(members, lem.localID)`. A zone with no HSYNC3 RRset is not a multi-provider zone and elects as before. This covers the four callers of 2.4.
- `SetConfiguredPeersFunc`, `SetOperationalPeersFunc` (`v2/start_agent.go`): the voting members other than this agent, and the OPERATIONAL ones among them.
- `HandleMessage`: drops a CALL, VOTE or CONFIRM whose sender is not a voting member of the zone, and returns when the local agent is not one. As `HandleGroupMessage` does with PR #163.
- `finalizeGroupElection`, `finalizeElection`: a winner that is not a voting member is not taken. The election counts as having found no consensus.
- `ApplyGossipElection`: arms no renewal timer when the local agent is not among the group's voting members. With PR #186 such a timer starts nothing (`groupForTimer`); this takes the timer away.
- `PostRefresh` (`v2/hsync_utils.go`): turns parentsync on only when the local identity matches an HSYNC3 record (`matchHsyncIdentity`), as the first-load callback does.

**Names.** Log, debug, logger `elect`: "no election started: this agent does not vote in the zone", with `zone` or `group`. Log, warn: "election: the winner is not a voting member, not taken", with `zone` or `group`, `winner`, `term`.

**Tests.** Unit, in a new `v2/parentsync_leader_role_test.go`:

- `TestAnAgentWithNoRoleStartsNoElection`: zero expected peers, from each of the four callers.
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

- `APIagent` (`v2/apihandler_agent.go`), `add-rr` and `del-rr`: before the edit policy, refuse when the zone has an HSYNC3 RRset and the local standing in it is not voting. A zone with no HSYNC3 RRset is left as it is, as in step 1.
- `EvaluateUpdate` (`v2/agent_policy.go`), the `local` case: the same refusal, first. This covers `update-local-zonedata` and the DNSKEY distribution after an inventory.
- `parentsync-election`, `parentsync-bootstrap`: refuse before anything else.
- `resync` (`SynchedDataEngine`): on an agent with no role it sends nothing to the zone's agents and says so. It still reads its combiner. Proposed: it does not send its own contributions to its combiner either, since an empty `replace` there would change what the provider contributed.
- `logSilentAgents` (`v2/hsync_transport.go`): reads the providers in `signers=`, not every agent.

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

**Before it:** PR #188, for the rule of who may send a CSYNC (3.2). Nothing else.

**Changes, the wire.**

- `v2/mp_wire_payloads.go`: `CatchUp` (3.4), and the field on `DnsSyncPayload`.
- `v2/mp_send.go`, `syncAppMessage`: marshals the embedding struct.
- One pointer field on `PeerSyncRequest`, `ZoneUpdate`, `AgentMsgPost`, `SynchedDataUpdate`, `SynchedDataCmd`. `sendRfiToAgent`, `deliverGenericMessage`, `routeSyncMessage` and `MsgHandler` pass it along.
- Golden files: `DnsSyncPayload.json` regenerated; two new sent forms, `send-rfi-catchup.json` and `send-sync-catchup.json`. `send-sync.json` and `send-rfi.json` must not change.

**Changes, the answering agent.**

- `SynchedDataEngine`, the own read. A mark per zone, proposed `ownState` on `ZoneDataRepo`: when the combiner's contributions were read, and when the signer's inventory arrived. `RequestAndWaitForEdits` reports whether it applied an answer. A zone whose own read is not done is read again, one zone per 30 s tick, once the zone has loaded: the combiner, and for a provider that signs with no inventory, the signer. This closes the two weak points of 2.5.
- `resync-targeted` becomes one function, proposed `catchUpAnswer(zone, target, request)`:
  1. It is not complete when the zone has not loaded (`zone-not-loaded`), when the own read from the combiner is not done (`own-state-not-read`), or when the provider signs and no inventory is there (`no-inventory`). A not complete answer carries the marker and no operation (design 5.4): empty sets from an agent that has not read its own state would remove its contributions at every peer.
  2. Otherwise one `replace` for each of NS, KEY, CDS and DNSKEY, empty where the agent holds none. And one for CSYNC when the answering agent leads the zone, and only then (3.2): a CSYNC operation from any other agent is rejected since PR #188, an empty one too.
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
- `TestAnAnswerNamesEveryRRtype`, `TestAnAnswerCarriesTheKeyStates`, `TestAnAgentThatHoldsNothingStillAnswers` (four empty operations, complete).
- `TestASignerWithoutAnInventoryAnswersNotComplete`, `TestAnAgentThatHasNotReadItsOwnStateSendsNoOperation`.
- `TestTheOwnReadIsRepeatedUntilItSucceeds`, `TestTheOwnReadWaitsForTheZonesFirstLoad`.
- `TestACompleteAnswerMakesItsProviderSpeak`: `computedDSIntent` is known after a complete answer from every provider in `signers=`, one of which lists no key.
- `TestAnAnswerWithoutTheMarkerIsAppliedAndDoesNotCount`.
- `TestEveryReplaceOfAnUpdateCountsAsAChange`, `TestAnAnswerThatChangesNothingIsConfirmed`.
- `TestGoldenWirePayloads` and `TestGoldenWireSendPayloads`, with the new files.

Harness: `integEnv` (`v2/transport_harness_test.go`), `TestTransportBoundary_CatchUpRequestAndAnswer`: RFI SYNC and its answer between two agents over the real path, the confirmation included.

Fleet: restart a leader that does not sign, then run `resync --pull` by hand. The DS set becomes known, a sync is asked for, the DS is at the parent.

**Done when** the fleet check passes. The "Today" note of section 3.2 of `guide/provider-changes.md` then loses its sentence about key states.

Not established: that the confirmation of an answer with nothing applied closes the entry in the answering agent's queue. The harness test above establishes it.

### Step 4. Asking by itself (#157, the restart)

**Before it:** step 3. PR #162, which makes the edge to OPERATIONAL arrive after a refused hello, a refused beat back or a wrong key. PR #164, for the status command that shows the tracker.

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
| `PeerOperational(peer)` | Notes the successful beat. First since this agent started: `Ask(zone, peer, "start")` for every zone they share that has loaded and in which the peer votes. After a gap above the outage time: the same with `outage`. Otherwise: asks again whatever was paused for this peer | `SendBeatWithFallback`, where a beat succeeds |
| `Answered(zone, from, catchUp)` | Takes an answer that names the outstanding request. Complete: done. Not complete: a retry | `SynchedDataEngine`, the `remote` case, after an update the repo took |
| `Requested(zone, from, catchUp)` | After the answer to a request of reason `start` is enqueued: `Ask(zone, from, "peer-start")`, when the asker votes in the zone | `MsgHandler`, RFI SYNC |
| `Forget(peer)` | Drops everything kept for a peer that is removed (step 7), so that one named again later is asked as a new peer | The engine's `OnPeerRemoved` hook (`v2/hsync_bridge.go`), wired by whichever of steps 4 and 7 merges second |
| `CaughtUp(zone)` | Design 5.5: the own read is done, and every voting member of the zone other than this agent, as the zone's records name them now, is complete with no request outstanding or noted. Also returns who is waited for | Step 5, the status |
| `Status(zone)` | The rows for the status command | `GetParentSyncStatus` |

Rules inside it:

- **A request fails** when the send fails, when it is refused, when its answer says not complete, and when no answer has come 30 s after the acknowledgement (design 5.7; the 30 s are proposed).
- **Retries** (design 5.7): after 5 s, 15 s, 30 s and 60 s, then every 5 minutes, with the same reason and a new name. A retry that finds its peer not OPERATIONAL sends nothing and waits for `PeerOperational`.
- **Pacing** (design 5.8): eight requests in flight to one peer.
- **Logging:** the first failure of a request, then one line an hour.

The reasons at a refresh. `MPPreRefresh` has the served zone and the incoming one, and records the local standing in both, in two new fields of `ZoneRefreshAnalysis`. `PostRefresh` then calls:

- at a zone's first load, `AskZone(zone, "start")`. Proposed: a zone that is added to a running agent is a first load too, and asks with `start`;
- when the standing rose from none, `AskZone(zone, "join")`;
- when it rose to voting from no role or from auditor, `AskZone(zone, "role")`;
- for each other identity that became a voting member of the zone at this refresh, `Ask(zone, peer, "peer-role")` (design 5.1). Without it `CaughtUp` never holds again once a newcomer has its role: the zone's records name a voting member that nothing ever asks, and a leader's sync stays held. `MPPreRefresh` records those identities in a third new field.

Before step 10 an agent with a record and no role has no OPERATIONAL peer in the zone, so its `join` sends nothing, and the request goes out with reason `role` when the role comes.

**Names.** Config, proposed: `multi-provider.syncengine.intervals.catchup_outage`, in seconds as its neighbours, default 3600. Status, a new field `catch_up` on `ParentSyncStatus`, and in `agent parentsync status`:

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

Harness: a third peer beside the two of `integEnv` (`newPeer`), `TestCatchUpAfterARestartAmongThreeAgents`: one agent restarted asks two, is asked back by two, and ends caught up.

Fleet: every agent restarted within ten seconds, on a zone whose leader does not sign: the DS is at the parent with no owner edit and no command. The leader alone restarted: the same.

**Done when** both fleet checks pass and the status of every agent shows every voting member as complete. The promise of `guide/synchronization-model.md` section 2 then holds.

### Step 5. The sync with the parent waits (#157, the leader)

**Before it:** step 4, on every agent of the zone: without it nothing completes a catch-up and the hold never ends. PR #188, which rewrote what this step edits: `syncDelegation`, the chains of `v2/mp_s5_leader_sync.go`, and the CSYNC of `v2/mp_s5_leader_csync.go`.

**Changes.**

- `DelegationSyncher` (`v2/delegation_sync.go`), `SYNC-DELEGATION` and `EXPLICIT-SYNC-DELEGATION`: for the leader's sync of a multi-provider zone, after the check of the lead, when `CaughtUp` says no: note the sync as owed, log one line, send nothing. Both commands, so that NS and glue wait as the DS does. The place is before `syncDelegation`, and so before `delegationCsyncStep` (PR #188): a leader that is not caught up makes no CSYNC either.
- A NOTIFY that already waits when the zone stops being caught up (an `outage` or a `peer-start` request clears it). Proposed: the two places that let a waiting NOTIFY go, `delegationSyncReleaseAfter` and the last confirmation in `delegationCsyncProgress`, ask the hold as they ask who leads. A NOTIFY that is held then is dropped and the sync is owed.
- The tracker: `owed` per zone. `Answered`, and the own read of step 3, call `requestDelegationSync(zone, "the zone is caught up")` when the zone becomes caught up with a sync owed. That is the explicit sync: it looks at the parent first and sends only the difference, which is the order design 5.6 fixes. A sync that was held as an implicit one is not sent as it was.
- `EXPLICIT-SYNC-DELEGATION`, the "in sync" branch: when the analysis has no DS set to compare (`NewDSKnown` is false) and the zone names a signer, the line is not "in sync". The retry chain ends as today: the set turning known asks again.
- A new function beside `computedDSIntent`, proposed `computedDSWaitingFor(zone)`: the providers in `signers=` that have not spoken, and this provider's own signer when it has sent no inventory. When every signer has spoken and none holds a key with the SEP flag, the set is unknown and there is nobody to name; the line then says so.

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

Not established: that `NewDSKnown` is false exactly when the zone's DS intent is unknown. It is set in tdns (`recordDSDifference`); the branches of `compareParentDS` that reach it were not all traced.

### Step 6. A rule for the sender and the recipients of every message

**Before it:** step 1, PR #163. PR #188, whose check of a CSYNC reads `DeliveredBy`: `routeSyncMessage` keeps setting it.

**Changes, the sender.**

- A new middleware, proposed `refuseNamedSender`, registered with `Router.Use` for the agent and the auditor, where `StartIncomingMessageRouter` registers its callback: when the context's peer and the parsed message's sender differ as FQDNs, it answers REFUSED and no handler runs. About 30 lines.
- `apiSyncEndpoint` (`v2/api_receive.go`): for `/beat`, `/ping` and `/msg`, refuses a body whose sender is not the client certificate's name (decision 9). The name is the certificate's common name, the one `tlsaVerificationMiddleware` has checked against the peer's TLSA record, compared as an FQDN with the sender the body names. A request with no client certificate does not get this far. `/hello` is not checked (3.2).
- `routeSyncMessage`: its fallback to the transport's sender goes.

**Changes, per message.**

- `handleAppSync` (`v2/mp_verb_handlers.go`): refuses, with the reason, a SYNC whose sender is not a voting member of the zone. In the form its LEGACY refusal has today, which stays for its message.
- `handleAppRfi`: on an agent or an auditor, and not for a peer its config names, refuses by RFI type as in 3.2.
- `GetZoneAgentData`: an OFF record is nobody's upstream or downstream.
- `CombinerProcessUpdate` (`v2/combiner_chunk.go`): for a zone that is not a provider zone, refuses the operations of an origin that is not a voting member of the zone, each with the reason.
- `MergeGossip(msg, from, group)`: takes nothing for a group this agent does not have or of which the sender is not a member. From a member that does not vote it takes that member's own row and nothing else: no election record, and no term from one (decision 10). The two callers in `v2/hsync_transport.go` look the group up, as they do today for `CheckGroupState`. `hsync.GossipPort` follows, and `hsync.ProviderGroupInfo` gets the voting members.

**Changes, the recipients** (3.2): `broadcastElectToZone`, `CommandHandler` (`send-rfi` AUDIT and `sig0key`), `leaderKeySetup`.

**For a zone in steady state** nothing changes: admission already keeps these senders out. What closes is the LEGACY way out, and the named originator. One thing does change: an auditor is no longer asked for the zone's state or its SIG(0) key, and its word on who leads is no longer taken.

**Names.** Log, warn, logger `transport`: "message refused: its payload names another sender than the one it came from" (`verb`, `named`, `sender`). Log, warn, logger `api`: "sync API request refused: the body names another sender than the client certificate" (`path`, `named`, `certificate`). The refusal of a SYNC: "sync refused: %s is not a voting member of zone %s". Of an RFI: "rfi %s refused: %s is not a member of zone %s", or "is not a voting member".

**Tests.** Unit:

- `TestAPayloadThatNamesAnotherSenderIsRefused`: hello, beat, sync, rfi, relocate, through the real router as `v2/transport_dispatch_test.go` does.
- `TestAnAPIMessageMustNameItsCertificatesIdentity`: `/beat`, `/ping` and `/msg`, with and without a trailing dot on either name; `TestAnAPIHelloIsNotHeldToItsCertificate`.
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

**Before it:** PR #162, for the beat back that is sent again.

How the three parts relate to the design: a member with no role is a peer that hellos and beats without a vote, and every step of an add or a removal changes who is a member. The sender half of #131 is closed by step 6, where a hello counts as sent by the sender the transport established. What is left of #131 is a bound. The end of comms (design 3.1, decision 11) gives `RemovePeer` its first caller, and with it the faults of #132 become live (2.11), so the guards and the caller go in together.

**Changes, #131.** `Engine.BeatPeer` (`v2/hsync/beat_retry.go`): a new map, proposed `beatBackAt`, of when the last beat back to each peer started. A call less than one fast interval after it does nothing. The first beat back after a restart has no earlier one and is not delayed. The retries of a failed beat back run inside the same beat back and are not touched.

**Changes, #132.**

- A helper, proposed `Engine.stillStored(peer)`: the registry holds this very object.
- `beatRetrier` and `beatBack` check it where they check for the identity today, and stop when it fails.
- `beatPeerOnce` and `sendHelloToPeer` do not write the peer back. The object they hold is the stored one, or the peer is gone.
- `RemovePeer` (`v2/hsync/discovery.go`) deletes the peer's entries in `beatFailing` and `beatBackAt`.
- Beats to one peer are not serialised: nothing depends on the sequence number (2.11).

**Changes, the end of comms.**

- `ReconcileZone` (`v2/hsync/reconcile.go`): on an agent (`GateOnLocalPresence`), a zone whose participants do not include the local agent expects no peers. Without this an agent whose own record has left a zone would put every peer back one pass after removing it.
- `reconcileAllZones`: a zone that the agent no longer holds is taken off its peers. Today nothing does that: the pass visits the zones the agent has, so a zone that left the config stays on its peers for good.
- With those two the engine's set of zones per peer holds the shared zones and no others (2.11), and "no zone shared" reads as: that set is empty.
- Where the time is kept: on the engine's peer object, a new field of `hsync.Peer`, proposed `Unshared time.Time`: since when no zone names the peer. It is zero while one does. It is in memory. An agent that restarts has no such peer in its registry at all, so nothing is lost with it.
- What runs the removal: the reconcile loop. `reconcileAllZones` runs every `reconcile` interval, 60 s by default, and after its pass over the zones calls a new function, proposed `pruneUnsharedPeers(now)`. For every peer that is not an infrastructure peer:
  1. a zone names it: `Unshared` is cleared. A peer that is named again within the hold time is kept this way;
  2. no zone names it and `Unshared` is zero: it is set to now;
  3. no zone names it and `Unshared` is older than the hold time: `RemovePeer`.
- `RemovePeer` exists. It stops the peer's hello retrier, takes the peer out of the engine's registry, and its hook (`removePeerView`, `v2/agent_structs.go`) drops the agent's view and the transport's peer, keys and addresses included. The rounds beat the registry's peers, so the beats stop. A peer that is not in the agent's registry is not LEGACY, so it is no longer admitted. A provider that a zone names again later is a new peer to `MarkNeeded` and is discovered afresh.
- Until it is removed nothing changes for the peer: it reads as LEGACY, is admitted and beaten, and every rule of step 6 that asks for a member refuses it.
- The same loop runs on the auditor, which has no gate in `ReconcileZone`: it removes a peer when no zone it holds has named it for the hold time.

The hold time is the time a queued message is kept. A message that was queued for the peer while a zone was shared has been delivered or has expired when the peer goes.

**Names.** Config, proposed: `multi-provider.syncengine.intervals.peer_hold`, in seconds as its neighbours, default 86400. `hsync.Config` gets `PeerHold`, and `hsyncConfigFromMp` (`v2/hsync_bridge.go`) fills it. As for its neighbours, zero or absent means the default. Log, info, logger `engine`: "peer shares no zone with this agent any more, kept for the hold time" (`peer`, `hold`); "peer is named by a zone again, kept" (`peer`); "peer removed: no zone shared for the hold time" (`peer`, `since`).

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
- A zone that arrives while its group's election runs (design 4.9, its last sentence): `finalizeGroupElection` sets the leader and then reads the group's zones from the group manager, in place of the list its caller read. A zone that arrived before that is on the list. One that arrives after it finds a leader, and `zoneJoinedGroup` asks for it. A zone can be asked for twice at that seam, which costs nothing: the key set-up finds the key it has, and the sync sends only a difference.
- A zone that leaves (design 4.1): `zoneJoinedGroup` gets one more case. When this agent leads the group the zone left and not the one it arrived in, the zone's sync chain is dropped (`delegationSyncNotLeading`), through a callback set in `v2/start_agent.go`.

A consequence to know: the hash of every group changes with this step. At the upgrade every group elects once, which the restart of the agents causes anyway.

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
- `TestAnAgentThatLedTheGroupAZoneLeftDropsItsSync`.

Fleet: two providers reduced to one, with no auditor: a leader with no restart. A lease renewal with the auditor stopped. The agents of every voting member restarted while the auditor runs on, with a short lease: the auditor shows the new leader when the earlier lease has run out, and no election follows from anything it sent. A zone whose owner removes a provider that leads the zone's group: the NS change is at the parent without waiting for a lease renewal.

**Done when** the four fleet checks pass, and a run with no provider change elects each group once.

### Step 9. A leader acts for a zone only when the views of it agree; no new key (design 4.9, 4.1)

**Before it:** step 5, for the owed mark and the place of the hold. Step 6, for the sender of a beat's gossip. Step 8, which makes a group's hash the make-up: before it the hash does not say who votes. Step 4, for the retry schedule. PR #185, for `zoneJoinedGroup`.

This is a step of its own, between the group's new key and the switch, for three reasons. It is a gate on the parent sync, as step 5 is, and a gate that never opens stops every sync: it should be judged alone on a fleet. It needs steps 5, 6 and 8, which step 8 does not. And it has to be in place before step 10, which is when a zone's group starts to change at every edit of a provider's standing.

**What is told. Nothing is added to the wire.**

- Every agent already tells, for each group, which zones it has in that group: its own row in the group's gossip lists them (`MemberState.Zones`, written by `RefreshLocalStates` from the group's zones, `v2/gossip.go`). With step 8 the group's hash is the make-up. So "zone Z is in my row of group G" says "I hold make-up G for Z", which is what design 4.9 asks every agent to tell.
- Why not a value per zone in the beat's own zone list: that list is `Zones []string` in tdns-transport's beat payload. The transport reads its first entry as the scope of the beat's authorization, and so does `parseAppPayload`. A value per zone there is a change of tdns-transport's wire type, of both readers, and a new pin. The gossip is tdns-mp's own, and it rides in the same beat.
- An absent value: a beat from a peer with no row of its own for the group, or with a row that does not list the zone, reads as "this peer does not hold this make-up for the zone". That is the hold, not a case of its own.
- Not established: how large a beat gets. A row lists every zone of its group, and a beat carries every member's row. That is so today.

**What is kept.**

- Per peer, first hand: which group it has each zone in, and when it said so. Proposed: `NoteToldZones(from, msgs, at)` on the gossip table, called in the two places gossip is merged (`routeBeatMessage`, and the gossip of a beat's answer in `SendBeatWithFallback`, `v2/hsync_transport.go`), with the sender that step 6 passes there. It reads the sender's own rows only and replaces what was kept for that sender. `ZoneToldBy(peer, zone)` returns the group and the time.
  - First hand, because a row that another member passes on can be older, and because a peer that has dropped a group sends no newer row for it: the gossip table would keep its last one for good.
  - It reads the message before `MergeGossip` filters it (step 6). A row for a group this agent does not have is a view that differs, and it is exactly what has to be seen.
- Per zone, the group it left. `RecomputeGroups` knows no leaders. The place is `zoneJoinedGroup(zone, from, to)` on the election manager, which it calls for each zone it has moved. The election of the group the zone left is still there at that moment: a recompute tells of the zones that joined before it tells of the groups that are gone. Proposed: `zoneLeft{group, leader, leaseEnd, at}`, kept per zone, noted when the zone had a group, that group had a leader, and the leader is not this agent.
  - The lease's end is read from the election of the group the zone left for as long as this agent still has that group, since a lease is renewed. When the group is gone here, the end noted at the move stands.
  - An agent that has restarted has no such note: at its first load of the zone there is no group the zone left. The second condition below then asks for nothing. The design does not say what else it could do.

**The check.** Proposed: `viewsAgree(zone)`, which also returns who is waited for. A zone in no group agrees.

1. Every voting member of the zone's group other than this agent has the zone in that group: `ZoneToldBy(member, zone)` is the group's hash.
2. For each group the zone left: its leader has the zone in the group this agent has it in; or its own rows, first hand and later than the move, do not list the zone in the group it left; or its lease has run out. The second is what "no longer has the zone" looks like. A previous leader that is no longer a member of the zone is not in the new group and sends no row for it, so it can show only that the zone has left its row of the old one.

Every leader runs the check on its own view, and that is what makes it hold from both sides. A leader that has not seen the edit still has the zone in the old group, and the voting members that have seen it no longer list the zone there: the first condition fails for the stale leader too, one beat after any of them has moved the zone.

**The hold.** One helper, proposed `syncHeld(zone)`, in the place of step 5's test: not caught up, or the views do not agree. It is asked:

- in `DelegationSyncher`, for both sync commands, where step 5 put its test;
- where a waiting NOTIFY is let go (step 5);
- before the key's bootstrap at the parent, `ParentSyncAfterKeyPublication`, which `leaderKeySetup` starts by itself and which does not pass the syncher. Not established: whether it sends anything but a query when the parent already holds the key.

The same owed mark as step 5. What ends the hold: a beat that changes a peer's told zones, for a zone with something owed whose check now passes; and a timer at the lease's end of a group the zone left. What is then asked is what an election's winner asks for the zone (`onLeaderElected`), not the sync alone: it finds the key it has, and the sync sends only a difference. A recompute that has moved a zone also brings the next beat round forward (`KickBeats`), so that this agent's own row goes out soon.

**No new key for a zone that has one (design 4.1).** `leaderKeySetup` (`v2/start_agent.go`) today uses a local SIG(0) key, else asks the zone's agents that are OPERATIONAL, else generates a keypair ("no peer has SIG(0) key, will generate new keypair"). It becomes:

1. A local key: as today.
2. The zone is not caught up: nothing is decided. This agent's contributions are not complete, so it cannot know whether the zone has a key. Owed.
3. The zone publishes a KEY: the apex of the agent's copy of the zone has a KEY RRset (what `GetParentSyncStatus` shows as "KEY at apex"; the leader's KEY always goes to the apex, `publishLocations`), or some agent's contributions in the data repo hold one. Then the voting members are asked with `CONFIG sig0key`, and when none hands the key over, they are asked again on the schedule of step 4: after 5 s, 15 s, 30 s and 60 s, then every 5 minutes. Nothing is generated. Owed, and one line says who was asked.
4. No KEY anywhere: a keypair is generated, as today.

The tracker of step 4 gets the retry beside its own: one more entry per zone, proposed `keyWanted`, with the attempt and the timer, and the same delays. A key that arrives is imported as today, and the zone is taken up.

**Who is handed the key (decision 15, design 3.3).** Today the answering side hands the key only to a requester that is its upstream or downstream by the HSYNC3 `upstream` fields (`MsgHandler`, `sig0key`), and a refusal sends no answer. Two signers have no such relation, so today that case ends in a new key. Decided: a voting member of the zone is handed the key, related or not, since any voting member may come to lead it; and a refusal is answered, so that the requester does not wait out its time. `MsgHandler`'s `sig0key` case drops the test of the upstream relation and keeps the test that the requester is a voting member (step 6); its refusal becomes an answer. Tests: `TestASignerHandsTheKeyToAnotherSigner`, `TestARefusedKeyRequestIsAnswered`.

**Consequences to know.**

- One agent that is stuck on an old copy of a zone holds that zone's parent sync for as long as it is stuck, if it led the group the zone left. Its lease does not run out while that group has other zones: the other voting members renew it. That is the design ("without end when one agent is stuck"), and it is exactly what a signer that is taken out of `signers=` does today (#147): its agent stays on the old copy. With PR #185 alone the new leader syncs at once. With this step the NS change of that removal does not reach the parent until the leaving provider's agent has seen the edit.
- After a restart an agent remembers no group that a zone left.

**Names.** Log, info, logger `zones`: "DelegationSyncher: the sync with the parent is held until the zone's members agree on its make-up" (`zone`, `waiting_for`); "the zone's members agree on its make-up, asking for what was owed" (`zone`). Log, warn, logger `agent`: "no SIG(0) key generated: the zone publishes one that this agent does not hold, asking again" (`zone`, `asked`, `attempt`, `in`), the first time and then once an hour. Status, in `agent parentsync status`:

```
  parent sync:    held until every member has the zone's make-up (waiting for agent.bravo.example.)
  parent sync:    held until the leader of the group the zone left has it (agent.charlie.example., lease ends 15:04:05)
  SIG(0) key:     the zone publishes one that this agent does not hold (asked agent.alpha.example., agent.bravo.example.)
```

**Tests.** Unit, with `groupRig` (PR #185) and two agents that hold different copies of one zone:

- `TestALeaderHoldsItsSyncWhileAVotingMemberHasAnotherMakeUp`.
- `TestALeaderHoldsItsSyncUntilThePreviousLeaderHasTheMakeUpOrLostItsLease`: the three ways out, each alone.
- `TestAStaleLeaderHoldsItsSyncWhenTheOthersHaveMovedTheZone`.
- `TestAPeersOwnRowIsReadFirstHand`: a row passed on by another member is not taken as that peer's view.
- `TestARowForAGroupThisAgentDoesNotHaveIsAViewThatDiffers`.
- `TestTheHoldEndsWhenTheLastViewArrives`, `TestTheHoldEndsAtThePreviousLeadersLeaseEnd`.
- `TestARestartedLeaderWaitsForNoPreviousLeader`, `TestAZoneInNoGroupIsNotHeld`.
- `TestTheKeyBootstrapWaitsForTheSameHold`.
- `TestALeaderDoesNotGenerateAKeyForAZoneThatPublishesOne`, `TestAKeyRequestIsRepeatedUntilAPeerAnswers`, `TestAZoneWithNoKeyStillGetsOne`, `TestNoKeyIsDecidedBeforeTheZoneIsCaughtUp`, `TestTheKeyIsAskedOfVotingMembersOnly`.

Fleet: an owner's edit that moves a zone to a group with another leader, with the transfer to one voting member's provider held back: no leader sends anything to the parent, each says whom it waits for, and one sync follows when the last copy has arrived. The same with the previous leader's agent stopped: the sync follows when its lease has run out. A zone that moves between two groups keeps its SIG(0) key: the KEY at the apex is the same before and after.

**Done when** the three fleet checks pass, and a run with no provider change shows no hold line. For the key: a zone with two signers that moves to a group led by the other signer keeps its SIG(0) key, and the parent goes on accepting its updates.

### Step 10. The switch: every HSYNC3 provider is a member (#158)

**Before it:** steps 1, 2, 6, 8 and 9 merged. Without step 1 a member with no role elects, without step 2 it edits, without step 6 it sends a SYNC and asks for the SIG(0) key, without step 8 its group votes by a union, without step 9 a zone has two leaders for as long as the agents hold different copies of it. Steps 3 to 5 and 7 on every agent, for the newcomer to catch up by itself.

**Changes.**

- `zoneParticipants`: the first set it returns is every ON record. It returns the auditors as a third set. Its doc comment, and those of the functions that follow it (3.1), are rewritten: they state today's rule as a security boundary.
- `ZoneAgentData` gets each agent's standing. `RecomputeGroups` fills the third list of step 8.
- `zone mplist` (`MPZoneInfo`, `v2/cli/mplist.go`): the members with no role, and this provider's own standing.
- `GetParentSyncStatus` and `agent parentsync status`: the standing of this agent, and for one that does not vote the leader and term it has learned, or that none is known yet. `gossip zone-state` says the same.
- `PostRefresh`: one log line when the local standing becomes "no role".
- Nothing in admission, discovery, beats, distributions, the transfer set-up or catch-up changes by its own code: each follows from the first change.

A consequence to know (3.2): from this step on the leader's CSYNC waits for a member with no role as well, with no time-out. A member with no role whose agent is stopped holds every NS change of the zone at a parent that takes NOTIFY only, until its record is removed.

**Names.** `zone mplist`, two new columns: `NoRole` (labels) and `This`, one of `signer`, `server`, `signer,server`, `auditor`, `member, no role`, `not listed`. Status:

```
  this agent:     does not vote in the zone (member, no role)
  leader:         agent.alpha.example., term 7, learned from gossip
  leader:         not known yet
```

Log, info, logger `zones`: "an HSYNC3 record and no role: member, no vote, no edits" (`zone`).

**Tests.** Unit:

- The `RoleLessRejected` case becomes `MemberWithNoRole`: its hello is accepted and routed; its SYNC, its election message and its request for the SIG(0) key are refused.
- `TestApplyHsyncDiff_roleLessAddExcluded` splits in two: `TestApplyHsyncDiff_offRecordExcluded`, and `TestApplyHsyncDiff_memberWithNoRoleRegistered` (registered, and reported to `OnHsyncMembersAdded`).
- `TestMembersVotingMembersAndAuditorsOfAZone`: roles, no role, OFF, and a zone without HSYNCPARAM.
- `TestADistributionWaitsForAMemberWithNoRole`, `TestADistributionWaitsForTheAuditor`.
- `TestAMemberWithNoRoleGetsTheTransferSetUp`.
- `TestAZoneWithAMemberWithNoRoleIsInAGroupOfItsOwn`.
- `TestMplistShowsEachMembersStanding`.

Harness: `integEnv`, `TestTransportBoundary_MemberWithNoRoleCatchesUp`: its hello is accepted, it gets gossip, and its request for state is answered completely.

Fleet: an add with the owner's two edits apart. After the first edit the newcomer is in every agent's gossip, reports the group's leader, has caught up with every voting member, and has its `addrr` refused. The zone is in the group that has the newcomer as a member with no role, and that group's leader has taken it up; a new group has elected, among its voting members. After the second edit the zone is in the group in which the newcomer votes. No sample is bogus or lame at any point. Then the removal's first edit: the zone moves to a group that the leaving provider cannot lead, at once.

**Done when** the fleet check passes for a provider that is added as a server. `guide/provider-changes.md` then loses the "Today" notes of its sections 2 and 3.2.

For a leaving signer the last part of the fleet check needs more than this plan. Today a signer that is taken out of `signers=` stops signing and drops to its combiner's serial, and its own agent refuses the lower serial: it stays on the old copy of the zone and does not see the owner's edit. The other agents refuse what it sends, so the zone stalls and is not harmed. That belongs to the removal (#147).

## 6. Decisions

Decided by the project owner on 2026-10-12. The design is written with them.

1. **How the asker knows that an answer is complete.** One message that is complete by construction, with a marker that names the request. A `replace` per type is a whole set, and the answer for one zone is small.
2. **A member with no role receives every distribution, and the distribution waits for its confirmation,** like any member. A provider on its way out still serves, and a new key of another signer must be at every server that still answers before it is used: the roll waits instead of answers going bogus. And being able to keep up with the other providers is a condition for serving the zone: if a provider cannot, that has to show before the zone owner gives it a role, not after. One exception, from the external review: a distribution that withdraws a member with no role does not wait for that member, whose agent may already be stopped. No step of this plan sends such a distribution: it is the removal's (#159, #138).
3. **An auditor that is down does not hold an election back.** The gate is the voting members. A SYNC is another matter: where a zone has an auditor, the auditor is a required participant, and the SYNC is not complete without its confirmation.
4. **A group is the set of providers with roles together with the set of providers without a role** (and the auditors), which is not the same as the set of providers. A provider with no role in a zone cannot lead it. Elections are per group. A zone that joins or leaves a group forces no election: it takes the leader of the group it arrives in, and that leader takes the zone up.
5. **A peer asks a restarted agent back,** once, on a `start` request. It is the only thing that finds a change the restarted agent made and lost from its queue. The request after a long outage stays too. Safety first: neither is cut to save code.
6. **A member with no role gets the zone transfer set-up from its upstream.** The HSYNC3 record states the zone owner's intent.
7. **What a provider contributed stands, frozen, once its roles are gone,** until the removal takes it away. The provider cannot change it, its own DNSKEYs included, so its key machine holds for the zone while it leaves: no rollover and no new DNSKEY, and signing and re-signing go on with the keys it has. The removal starts at the edit that takes the roles away, and the leader of the group the zone is then in is responsible for it.
8. **The whole sync with the parent waits for catch-up,** NS and glue as well as DS. A leader that does not have all the information is in no position to decide. A leader that has just started does not know what the parent holds either: it first gets the zone's data from the other agents, its combiner and its signer, then asks the parent, then sends the difference.

9. **The sender rule holds over HTTPS too.** An agent refuses an HTTPS `/beat`, `/ping` or `/msg` whose body names another sender than the client certificate's name. It is done in step 6, ahead of issue #56, which keeps `/hello` and the choice of the certificate's identity field.
10. **A member that does not vote causes no election, and nothing it says about terms is taken.** A receiver takes its own row from it and nothing else. For who leads, it takes a newer term from a voting member at once. Whatever else a voting member tells it about who leads (a lower term, or the same term with another leader) it takes once the lease of the leader it holds has run out. A self-election still takes a term above zero, so that gossip tells it.
11. **Comms end when no zone is shared.** When the last zone shared with a peer is gone, the agent keeps the peer for a hold time of 24 hours and then removes it and stops beating it. A peer that is named again within the hold time is kept. A provider that a zone names again later is discovered afresh. Until it is removed the agent goes on beating it and takes its hellos and beats, which is the one exception to admission by a shared zone, and every message from it that requires a member is refused.
12. **A leader acts for a zone only when the views of it agree.** Agents see the owner's edit at different moments, with no network partition needed, and for that time a zone can have two leaders that sync the parent from different views. A leader sends nothing to the parent for a zone until every voting member of the zone's group holds the same make-up for it, and the leader of the group the zone left has shown that make-up, or no longer has the zone, or has lost its lease. Until then the sync is owed. Step 9. From the external review of this design.
13. **The auditors stay in what defines a group.** The external review proposed to take them out, since an auditor neither votes nor leads. They stay: gossip is per group, and an auditor takes part in it as a member. The costs are accepted: an auditor edit moves the zone to another group, and the same providers with another auditor are another group. Auditors are few, and a zone's auditor is meant to be stable.
14. **What withdraws a member does not wait for it** (the exception in decision 2), and **taking a zone up never gives it a new SIG(0) key** (step 9). Both from the external review. Two things the code adds to them are in 3.2 and in step 9: the leader's CSYNC waits for every member and is not what the exception names, and a key is handed today only to an upstream or a downstream.
15. **Any voting member of a zone may be handed its SIG(0) key** by a voting member that has it, and a refusal is answered. Before, only an agent's upstream or downstream was handed it, so a leader that was another signer could never get it.

Also decided:

- tdns-mp does not support agents that are out of step with each other (section 4).
- Issues #131 and #132 go with the membership work (step 7).
- Issues #180 to #183 are fixed in one pull request of their own. Step 8 needs it first.

## 7. What this plan depends on, and what comes after

### 7.1 To be merged first

| What | Steps that need it |
|---|---|
| PR #163 (#143, #130) | 1, 6 |
| PR #162 (#84, #128, #145) | 4, 7 |
| PR #164 (#32) | 4, 5, 9, 10, for the status command |
| PR #169 (#152), or its three helpers | 1 |
| PR #185 (#179), a draft | 8, 9 |
| PR #186 (#180 to #183), a draft, on top of #185 | 1 (the same functions), 8 |
| PR #188 (#175 with #151), a draft | 3, 5, 6 |

PRs #161, #165, #166, #167, #168, #187 (#144), #189 (#171, #170) and #190 (#73) are needed by no step. Three of them edit a function or a file that a step edits, in another place: PR #167 (`v2/combiner_chunk.go`, step 6), PR #168 (`routeBeatMessage`, steps 6 and 9), and PR #187 (`MPPreRefresh`, step 4).

### 7.2 Issues #179 to #183, each against the steps

None of the five is a step of this plan. Each has a change on the integration branch (2.10).

- **#179, a zone that arrives in a group with a leader (PR #185).** It is design 4.1. Three things it leaves open are steps of this plan: the zone that leaves (step 8), the zone that arrives while an election runs (step 8), and the new SIG(0) key (step 9).
- **#180, the deadlock (PR #186).** Step 8 edits the five callers of `CheckGroupState`, one of which was the place of the deadlock, and step 10 makes recomputes more frequent.
- **#181, two recomputes at once (PR #186).** With step 8 a zone's group is how its leader is found, and a provider change is two or three recomputes in a row on every agent. Step 9 leans on the order in which a recompute tells what it changed: the zones that joined first, the groups that are gone after.
- **#182, the election manager is not told (PR #186).** It is design 4.8. With step 8's key a group never changes its make-up: a change is another group. So what is left of "a group changes" is that it gains and loses zones, and that it disappears.
- **#183, the leftovers (PR #186).** Two of the three bear on this plan. A group's timers now read the group when they fire. And an agent whose own record is removed now recomputes, so that the zone leaves its old group there too: that is the last edit of every removal.

### 7.3 Other work that is decided, and where it meets this plan

- **#175 with #151 (PR #188):** the leader makes the zone's CSYNC, sends it to every member by SYNC, and sends the NOTIFY when all have confirmed and the propagation delay has passed, with a ceiling on that delay (`delegationsync.notify-wait-max`). It meets this plan in four places, all in 3.2 and in the steps named there: the answer of step 3 carries a CSYNC from the leader only; the hold of step 5 comes before the CSYNC is made; the sender rule of step 6 and the leader rule of that pull request apply one after the other; and after step 10 the confirmations waited for include a member with no role.
- **#171 and #170 (PR #189):** a combiner that restarts serves its stored `_signal` KEYs again; the auditor's identity zone is re-signed. Neither is in a step. #171 is next to the own read of step 3: not established is whether a combiner that has just restarted answers RFI EDITS before it has loaded its stored contributions. `contributionsLoaded` and the EDITS case of `v2/combiner_msg_handler.go` are where to look.
- **#73 (PR #190):** an identity zone listed in the config with parentsync gets a warning. No step touches it. Step 1's guard leaves a zone with no HSYNC3 records as it is.
- **#56 and #59, HTTPS:** step 6 adds one comparison (3.2). The rest, `/hello` included, stays with #56.

### 7.4 The removal starts where this plan ends

The removal (#147, #138, #159, items 3 to 5 of #137) is not in this plan. Its starting point is the member with no role of step 10, and the design's section 7 holds what is decided for it.

Two things this plan leaves to it:

- The leaving signer's agent stays on an old copy of the zone (step 10, the last paragraph).
- The signer's side of the freeze (3.5).

### 7.5 After this plan

A provider that is named in `signers=` while it runs does not sign until its signer is restarted (#146), and the key machine's `SignersChanged` has no caller (#136). Both need what the design gives a newcomer before it has a role: comms with every member, and the other signers' DNSKEYs with what they say about them. With that in place, calling `SignersChanged` from the refresh when `signers=` changes, and binding the signing policy at that moment, is the next step. It is not part of this plan.

What else the design leaves out is listed in its section 7.
