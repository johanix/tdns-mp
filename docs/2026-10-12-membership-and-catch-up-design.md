# Membership and catch-up: every HSYNC3 provider is a member, and a member asks for what it does not know

**Status:** PROPOSAL, 2026-10-12.

This document describes membership and catch-up in tdns-mp as a whole: who is a member of a zone's group, what each kind of member may do, how an election counts, and how an agent learns the state of a zone. It describes the design as it is meant to stand. Parts of it are in the code today and parts are not.

The difference from today's code, the steps of the work and the questions that are still open are in the plan beside it: `2026-10-12-membership-and-catch-up-plan.md`. A place marked "(question N)" depends on an open question there, and is written with the recommended answer.

It is the design behind sections 2, 3.1 to 3.2 and the membership side of section 4 of `guide/provider-changes.md`.

## 1. The rules

1. Every provider with an HSYNC3 record in the zone is a member of the zone's group, with or without a role in HSYNCPARAM. Discovery and comms run with it.
2. A member with no role is in transition, in or out. It does not vote and cannot lead.
3. Catching up is a request: a member that has identity and comms asks the others for the zone's current state.
4. A restart is the same case.
5. An add is the HSYNC3 record first and a role later. A removal is the roles first and the record later.
6. Safety before everything: an operation may stall, the zone must never go bogus or lame.
7. Which NS records a provider adds is its operator's decision.

A record in state OFF is not a member. A zone with HSYNC3 records and no HSYNCPARAM is the legacy case: every ON record is a voting member.

One rule follows from these and shapes the rest: **a member with no role can talk and catch up, and can change nothing.** Admission says who may talk. Each message type says what its sender must be.

## 2. Standings

### 2.1 The four standings

| | Voting member | Auditor | Member with no role | Not a member |
|---|---|---|---|---|
| Defined by | ON record, label in `servers=` or `signers=` | ON record, label in `auditors=` only | ON record, label in none | No record, or OFF |
| Discovery, hello, beat | Yes | Yes | Yes | No |
| Gossip: its own row is taken | Yes | Yes | Yes | No |
| Gossip: it learns who leads | Yes | Yes | Yes | No |
| Gossip: its word on who leads is taken | Yes | No | No | No |
| Receives distributions | Yes | Yes | Yes (question 2) | No |
| Its confirmation is waited for | Yes | Yes (it confirms at once) | Yes (question 2) | No |
| Contributes: its operations are applied | Yes, by the edit policy | No | No: refused | No |
| Asks for the zone's state | Yes | Yes | Yes | Refused |
| Is asked for the zone's state | Yes | No | No | No |
| Zone transfer set-up with its upstream | Yes | No | Yes (question 6) | No |
| Gets the zone's SIG(0) key | Yes | No | No | No |
| Votes, may start an election | Yes | No | No | No |
| May lead | Yes | No | No | No |

### 2.2 The transitions

Each one is one edit by the zone owner.

| From, to | At the other agents | At the provider's own agent |
|---|---|---|
| No record, to a record with no role | Discovery, hello, beats. The zone moves to a group that includes it. The voting members elect again, without it. | It asks every voting member for the zone's state and its upstream for the transfer set-up. It shows "member, no role" and refuses its operator's edits. |
| No role, to a role | The zone moves to the group in which it votes. One election, with it. Its contributions are taken. | It asks for the zone's state once more. It may vote and lead. Edits follow the edit policy. |
| A role, to no role | The zone moves to a group in which it does not vote. If it led, it stops being the leader at the moment the zone says so. What it contributed stands, and it cannot change it (question 7). | It stops voting, gives up the lead, refuses edits. It goes on serving: the rest of the removal is not in this design. |
| A record, to no record | It leaves the zone's group. Comms end unless another zone is shared. | The zone is no longer a multi-provider zone for it. |

## 3. Who may talk, and what a sender may do

### 3.1 Admission

A message is admitted when its sender and the receiving agent are members of the same zone. That is checked twice: before any crypto, for any zone at all, and after parsing, for the zone the message names. A sender that fails gets rcode REFUSED.

Admission decides nothing else. No handler rests on it alone: each message type has its own rule for the sender (3.3).

A provider whose roles are gone and whose record stays is a member. A peer with which comms are up and no zone is shared any more (LEGACY) stays admitted. It is a member of no zone here, so every rule of 3.3 that asks for a member refuses it.

### 3.2 The sender is the one the transport established

On an agent, a message counts as sent by the sender the transport established. A payload that names another originator is dropped. An agent forwards nothing to another agent, so nothing legitimate is lost. Without this rule a member with no role could name a voting member in a SYNC or in a vote.

A combiner is the exception, by design: the agent that delivers an operation and the origin it names differ. There the rule of 3.3 is applied to the named origin.

### 3.3 What each message asks of its sender

| Message | The sender must be | If it is not |
|---|---|---|
| Hello, beat | Admitted (3.1) | REFUSED |
| Gossip, carried in a beat | A member of the group. From a voting member all of it is taken. From any other member: its own row and the term number of an election, never who leads | The rest is not taken |
| SYNC: contributions to the zone | A voting member of the zone | Refused, with the reason. Nothing is stored, passed to a combiner or applied |
| The same operations, at a combiner | Named origin: a voting member of the zone | The operation is refused |
| Election: CALL, VOTE, CONFIRM | A voting member, of the group or of the zone | Dropped, never counted |
| RFI SYNC: a request for the zone's state | A member of the zone | Refused |
| RFI CONFIG: the zone transfer set-up | A member that the HSYNC3 `upstream` fields relate to the answering agent (question 6) | Refused |
| `CONFIG sig0key`: the zone's SIG(0) private key | A voting member, related in the same way | Refused |

An auditor falls under the same rules: its operations are not applied and its votes are not counted.

What is sent to whom:

- **Distributions** go to every member, and every member's confirmation is waited for (question 2).
- **Election messages** go to the voting members and the auditors.
- **Requests for the zone's state** go to the voting members. An auditor holds nothing, and a member with no role contributes nothing.
- **Gossip** of a group goes to that group's members. A group is one member list, so a member learns of no zone it is not a member of.
- **Discovery** runs only for an identity that the zone owner names in an HSYNC3 record.

## 4. Groups and elections

### 4.1 The group and its hash

A provider group is one member list: zones with the same members share a group, and one election. The group's hash is taken over the members' identities, with a member that has no role entered with a marker after its name. Two things follow:

- A zone in which every member has a role has the plain list and the plain hash. The marker is there only while a provider is on its way in or out.
- A zone with a member that has no role is never in the same group as a zone in which that member votes. So a member cannot come to lead a zone in which it has no role by way of another zone.

When the zones of one group disagree about who votes, the group's voting members are the union. With the marker one case is left: an identity that is an auditor in one zone and a provider in another zone with the same members. So the lead is also checked against the zone: the leader of a zone must be a voting member of that zone, derived from the zone data at the moment of use. That check is what makes a leader whose roles are taken away stop at once, at itself and at the others.

A zone with fewer than two members is in no group and has an election of its own, per zone.

Each step of an add or a removal moves the zone to another group and costs one election (question 4). The election takes about a second once the voting members see each other, and the new leader's sync sends only a difference.

Agents see the owner's edit at different moments. For that interval the old group and the new one can each have a leader for the zone.

### 4.2 The counts

Every count is taken from the voting members: the peers an election expects, the peers that have to be reachable, and the order in which a lease is renewed. An agent that is not a voting member of the zone has no count at all: it runs no election.

### 4.3 The gate: the voting members see each other

An election starts when the voting members are mutually OPERATIONAL. The voting member with the lowest identity starts it. The full matrix, every member's row, is still gossiped and shown.

A member with no role does not hold an election back. On its way in its agent may not be running yet. On its way out its operator may stop it before the owner removes the record, and the remaining providers need a leader to finish the removal. The same rule takes the auditor out of the gate (question 3): who cannot vote cannot block the vote.

### 4.4 Who may start, vote and win

- **Start.** A voting member only, whatever asks for the election: the zone's first load, a timer, the operator's command. An agent that does not vote and learns a leader from gossip arms no renewal timer.
- **Vote.** A voting member only. A vote from anybody else is not counted (3.3).
- **Win.** The winner is determined from the votes of voting members, and is taken only if it is one itself.

### 4.5 One check for every change

Every change of the zone's HSYNC3 or HSYNCPARAM records, and the zone's first load, runs one check for the zone. It applies to a zone that syncs with its parent through its agents.

- The local agent does not vote in the zone: nothing is started, and a lead it holds for the zone is dropped.
- A group covers the zone: the election is left to the group's gate, and a per-zone result for the zone is dropped.
- No group covers the zone and the local agent is its only voting member: the agent elects itself, unless it leads already.

### 4.6 One voting member

- **The roles go, the record stays.** The zone moves to a group of two members and one voting member. The gate is met by that member's own row, it expects no peers, and it leads. No restart is needed.
- **The record goes.** No group is left. The check of 4.5 makes the remaining provider elect itself.
- **A term for it.** A self-election takes a new term, as any election does: one above the highest term the agent holds or has heard of. Without a term the member with no role beside it never learns who leads.

### 4.7 What a member with no role reports as leader

It learns the leader from gossip: the decided term that a voting member tells. `agent parentsync status` and `gossip zone-state` show that leader and term, and that this agent does not vote. Before the first beat from a voting member it reports that no leader is known yet. It never reports itself.

### 4.8 Retiring a group

When no zone is left in a group, the group's election state and timers go with it. A group whose voting members change under the same hash has its leader invalidated and elects again.

## 5. Catch-up

### 5.1 When it is sent

| Case | Reason word | Who asks whom |
|---|---|---|
| The agent starts | `start` | The agent asks every voting member of every zone it is a member of |
| The agent becomes a member of a zone | `join` | The agent asks every voting member of that zone |
| The agent is given its first role in a zone | `role` | The same, once more |
| A peer says that it has started | `peer-start` | The agent that got a `start` request answers it, and then asks that peer back (question 5) |
| A peer is OPERATIONAL again after more than an hour | `outage` | The agent asks that peer, for each zone they share. The hour is a config value, well below the 24 hours a queued message is kept |
| The operator runs `resync --pull` | `manual` | The agent asks every voting member of the zone |

A request to a peer goes out when that peer is OPERATIONAL from here and the zone's first load is done.

The `peer-start` case is there because a restarted agent has lost its queue: a change it made just before it stopped may never have reached a peer, and it does not know which. Only `start` is answered with a request back. No agent asks a peer about a zone while a request to it for that zone is outstanding, or within a minute of a complete answer.

### 5.2 To whom, for which zones

Every voting member of the zone other than the asker. The zones are those in which the asker is a member, with or without a role.

### 5.3 What is asked

RFI SYNC, with the reason word and a name for the request. It is a plain send with a synchronous acknowledgement, not a queued message.

### 5.4 What is answered

One SYNC to the asker alone, through the confirmed queue, holding the answering agent's own contributions to the zone.

1. **Every RRtype is named.** One `replace` for each type a provider may contribute (NS, KEY, CDS, CSYNC, DNSKEY), empty where the agent holds none. The asker's stale records go.
2. **The key states travel.** When the answering agent's provider signs the zone, the DNSKEY operation carries the key states, from its signer's latest inventory.
3. **An answer always goes out,** also from an agent that holds nothing.
4. **The marker.** The SYNC names the request it answers and says `complete` or not, with the reason when not. An agent answers "not complete" when it cannot vouch for its own state: its provider signs and it has no inventory from its signer yet, or it has not finished reading its own contributions back from its combiner.

The asker handles the operations as it handles any remote update: it evaluates them, applies them, passes them to its own combiner and confirms. An older message that leaves a queue later does not undo the answer.

A complete answer from a provider in `signers=` counts as that provider having spoken about its keys, also when it lists no key.

### 5.5 How completeness is known

By construction and by the marker (question 1): a `replace` is the sender's whole set for a type, the answer names every type, so one answer is everything that agent holds for the zone. The marker says so and names the request.

The asker keeps, per zone and peer: asked when, answered when, complete or not, and the last error. It is kept in memory, since a restart asks again anyway.

A zone is **caught up** when every voting member other than this agent has answered completely since this agent started, became a member of the zone, or last asked.

### 5.6 What waits for it

- **The DS set.** For a leader whose own signer does not own the zone, the zone's DS set is unknown while a provider in `signers=` has not spoken about its keys. A complete answer makes a provider speak, and a set that turns from unknown to known asks for a sync with the parent.
- **The leader's sync with the parent.** Nothing is sent while the zone is not caught up. One line says what is waited for, the sync is noted as owed, and the answer that completes the catch-up asks for it. This holds for NS as well as DS (question 8): a leader that missed a peer's change would send the parent its own older view.
- **Not "in sync".** When NS and glue are in step with the parent and there is no DS set to compare, for a zone that names a signer, the leader does not report "in sync". It reports "DS set unknown, waiting for" and the provider.
- **Nothing else.** Voting, the agent's own edits, and what it confirms to others do not wait.

The stall this adds is small. Catch-up needs the voting members to be reachable, and so does having a leader.

### 5.7 Retries

A request that fails, is refused, or is answered "not complete" is sent again after 5 s, 15 s, 30 s and 60 s, and then every 5 minutes, for as long as the peer is OPERATIONAL. There is no bound: a stall must stay visible and end when its cause ends. The first failure is logged, then one line an hour. A peer that stops being OPERATIONAL pauses its requests, and they start again when it is back. A refusal is expected for a short while after a join, until the peer has loaded the zone with the new record.

### 5.8 The cost

With Z zones and P voting peers per zone, a start sends Z x P requests and receives as many answers. Each answer is one small message and its two confirmations. A `start` is asked back, which doubles it. An agent with 1,000 zones and two peers handles about 4,000 requests and 4,000 answers at its start. Requests to one peer are paced, eight in flight, as discovery is, so the start takes tens of seconds, not one burst. After a restart nearly every answer changes nothing at the asker. One request per peer for many zones would cut the count and is a wire change: left for when it is needed.

## 6. What an agent with no role does for its own operator

- **It refuses edits.** `add-rr`, `del-rr` and `update-local-zonedata` answer that the provider has no role in the zone: the zone lists it under neither `servers=` nor `signers=`. Nothing is stored and nothing is sent, to its combiner or to anybody.
- **It refuses to lead.** `parentsync-election` and `parentsync-bootstrap` answer that this provider cannot lead the zone.
- **It may ask.** `resync --pull` works. `resync --push` sends nothing to peers and says why.
- **It shows where it stands.** `zone mplist` shows the member list with each member's standing, and this provider's own: signer, server, auditor, "member, no role", or not listed. `agent parentsync status` shows the leader and term it has learned, that it does not vote, and for each voting member whether the zone's state has been answered completely, and since when.
- **It logs the transition once:** an HSYNC3 record and no role: member, no vote, no edits.

## 7. Not part of this design

- **A provider named in `signers=` while it runs** (#146, #136). This design gives a newcomer what that needs before it has a role: comms with every member, and the other signers' DNSKEYs with what they say about them.
- **The rest of a removal:** when a leaving provider stops signing and serving, who removes its NS and its DS and in what order, "safe to remove" (#147, #138, #159, items 3 to 5 of #137). The member with no role of this design is its starting point.
- **A server that becomes a signer and serves its own signatures too early** (#160), and wrong answers before a provider is listed (item 1 of #137).
- **New confirmed message types:** a leader's statement about the parent that every member verifies, and the transfer set-up.
- **Keeping key states across a restart.** Not done on purpose: a stale DS set can remove a DS that is needed, an unknown one cannot.
- **A leader for a zone whose parent the owner updates.** There is no election for a zone without `parentsync=agent`.
- **The meaning of the HSYNC3 state field.** OFF stays out of the group.
- **The unused option `mp-not-listed-error`** (item 4 of #137).
- **Ordered delivery** (#51), and one request for many zones.
- **The auditor's view of a blocked distribution** (#152).
- **HTTPS as the only mechanism** (#59, #56).
