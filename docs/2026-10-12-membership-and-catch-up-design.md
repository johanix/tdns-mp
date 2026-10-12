# Membership and catch-up: every HSYNC3 provider is a member, and a member asks for what it does not know

**Status:** PROPOSAL, 2026-10-12.

This document describes membership and catch-up in tdns-mp as a whole: who is a member of a zone's group, what each kind of member may do, how an election counts, and how an agent learns the state of a zone. It describes the design as it is meant to stand. Parts of it are in the code today and parts are not.

The difference from today's code and the steps of the work are in the plan beside it: `2026-10-12-membership-and-catch-up-plan.md`. Its section 6 lists the decisions this design rests on.

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
| Receives distributions | Yes | Yes | Yes | No |
| Its confirmation is waited for | Yes | Yes (it confirms at once) | Yes, except for what withdraws it (3.3) | No |
| Contributes: its operations are applied | Yes, by the edit policy | No | No: refused | No |
| Asks for the zone's state | Yes | Yes | Yes | Refused |
| Is asked for the zone's state | Yes | No | No | No |
| Zone transfer set-up with its upstream | Yes | No | Yes | No |
| Gets the zone's SIG(0) key | Yes | No | No | No |
| Votes, may start an election | Yes | No | No | No |
| May lead | Yes | No | No | No |

### 2.2 The transitions

Each one is one edit by the zone owner.

| From, to | At the other agents | At the provider's own agent |
|---|---|---|
| No record, to a record with no role | Discovery, hello, beats. The zone moves to the group that has it as a member with no role, and takes that group's leader (4.1). | It asks every voting member for the zone's state and its upstream for the transfer set-up. It shows "member, no role" and refuses its operator's edits. |
| No role, to a role | The zone moves to the group in which it votes, and takes that group's leader. Its contributions are taken. | It asks for the zone's state once more. It may vote and lead. Edits follow the edit policy. |
| A role, to no role | The zone moves to the group that has it as a member with no role. If it led the zone it no longer does: that group has a leader of its own, and the removal is that leader's to run (section 7). What the provider contributed stands until the removal takes it away. | It no longer votes or leads for the zone, and refuses edits. It can change nothing of what it contributed, its own DNSKEYs included: its key machine holds for the zone. Hold means no rollover and no new DNSKEY. It goes on signing, and re-signing, with the keys it has, and it goes on serving, until the removal withdraws them. |
| A record, to no record | It leaves the zone's group. When no zone is shared with it any more, comms end after a hold time (3.1). | The zone is no longer a multi-provider zone for it. |

## 3. Who may talk, and what a sender may do

### 3.1 Admission

A message is admitted when its sender and the receiving agent are members of the same zone. That is checked twice: before any crypto, for any zone at all, and after parsing, for the zone the message names. A sender that fails gets rcode REFUSED.

Admission decides nothing else. No handler rests on it alone: each message type has its own rule for the sender (3.3).

A provider whose roles are gone and whose record stays is a member.

**Comms end when no zone is shared.** When the last zone shared with a peer is gone, the agent keeps the peer for a hold time of 24 hours, which is how long a queued message is kept, and then removes it and stops beating it. This is the one exception to admission by a shared zone: until the peer is removed the agent goes on beating it and takes its hellos and beats. It is a member of no zone here, so every message from it that requires a member is refused (3.3). A peer that a zone names again within the hold time is kept. One that is named again later is discovered afresh.

### 3.2 The sender is the one the transport established

On an agent, a message counts as sent by the sender the transport established. A payload that names another originator is dropped. An agent forwards nothing to another agent, so nothing legitimate is lost. Without this rule a member with no role could name a voting member in a SYNC or in a vote.

A combiner is the exception, by design: the agent that delivers an operation and the origin it names differ. There the rule of 3.3 is applied to the named origin.

The rule holds for every mechanism. Over HTTPS the sender the transport established is the name in the client's certificate, and a message whose body names another sender is refused.

### 3.3 What each message asks of its sender

| Message | The sender must be | If it is not |
|---|---|---|
| Hello, beat | Admitted (3.1) | REFUSED |
| Gossip, carried in a beat | A member of the group. From a voting member all of it is taken. From any other member: its own row only | The rest is not taken |
| SYNC: contributions to the zone | A voting member of the zone | Refused, with the reason. Nothing is stored, passed to a combiner or applied |
| The same operations, at a combiner | Named origin: a voting member of the zone | The operation is refused |
| Election: CALL, VOTE, CONFIRM | A voting member, of the group or of the zone | Dropped, never counted |
| RFI SYNC: a request for the zone's state | A member of the zone | Refused |
| RFI CONFIG: the zone transfer set-up | A voting member or a member with no role that the HSYNC3 `upstream` fields relate to the answering agent: the HSYNC3 record states the zone owner's intent. Not an auditor | Refused |
| RFI AUDIT | A member of the zone | Refused |
| `CONFIG sig0key`: the zone's SIG(0) private key | A voting member of the zone. The `upstream` fields play no part: any voting member may come to lead the zone, and a leader cannot do its work without the key | Refused, and the refusal is answered, so that the asker does not wait for nothing |

An auditor falls under the same rules: its operations are not applied and its votes are not counted. A status update and a relocate have no rule of their own: they are admitted (3.1), and they count as sent by the sender the transport established (3.2), so a peer can relocate nobody but itself.

What is sent to whom:

- **Distributions** go to every member, and every member's confirmation is waited for: the voting members, a member with no role, and the auditor. Where a zone has an auditor, it is a required participant: a SYNC is not complete without the auditor's confirmation. For a member with no role the wait is also a test. Being able to keep up with the other providers is a condition for serving the zone, and it has to show before the zone owner gives the provider a role, not after. There is one exception: a distribution that withdraws a member with no role, which is to say its own NS records, DNSKEYs or DS, does not wait for that member. Its operator may already have stopped its agent, and its removal must not depend on it.
- **Election messages** go to the voting members and the auditors.
- **Requests for the zone's state** go to the voting members. An auditor holds nothing, and a member with no role contributes nothing.
- **Gossip** of a group goes to that group's members.
- **Discovery** runs only for an identity that the zone owner names in an HSYNC3 record.

## 4. Groups and elections

### 4.1 The group

A provider group is a set of providers together with what each of them is: the voting members, the auditors, and the members with no role. Every zone with exactly that make-up belongs to the group. A zone's group follows from the zone's own HSYNC3 and HSYNCPARAM records and from nothing else.

So the providers a, b and c with a role each are one group, and a and b with a role and c with none are another, although the same three providers are in both.

The auditors are part of the make-up because gossip is per group, and an auditor takes part in its group's gossip as a member: it gets the group's state, gives its own row, and learns who leads. Two things follow, and both are accepted. A zone whose owner changes its auditor moves to another group, which costs the hold of 4.9 and nothing more. And the same providers with another auditor are another group, with its own election and its own share of every beat. Auditors are few, and an auditor is by its purpose the stable part of a zone: it is there to watch the other changes, not to be changed.

There is one election per group, among its voting members, and the group's leader leads all its zones. All zones of a group agree on who votes, by definition. So a leader has a role in every zone it leads, and a provider with no role in a zone never leads that zone.

**A zone that joins or leaves a group forces no election.** A zone that arrives in a group with a leader takes that leader. A group elects when it has no leader: when it is new, when its lease runs out, or when its leader is lost.

**The leader takes up a zone that arrives.** When a zone arrives in a group, the group's leader does for that zone what it does for every zone of the group when it is elected. An agent that led the group the zone left stops acting for it.

**Taking a zone up never gives it a new SIG(0) key.** A zone that publishes a KEY has a key, and the parent holds it. A leader that does not have that key asks the voting members for it, and asks again until one hands it over, on the schedule of 5.7. A peer that is slow, restarting or silent is a peer to ask again, not a peer without the key. Until the leader has the key its sync with the parent is owed and not sent. A key is generated only for a zone that publishes none.

An example. The group of a, b and c has 100,000 zones, and c leads it. The owner of one zone takes c's roles away. That zone moves to the group "a and b, with c as a member with no role". If that group exists, the zone takes its leader. If it is new, a and b elect. Nothing is elected in the first group, which now has 99,999 zones and c as its leader. Later the owner removes c's record, and the zone moves to the group of a and b and takes its leader.

Elections are held per distinct make-up, never per zone: 40,000 zones that drop c at once land in one group and share one election.

A zone with fewer than two members is in no group and has an election of its own, per zone.

Agents see the owner's edit at different moments. For that interval the old group and the new one can each have a leader for the zone. Section 4.9 says what a leader does about it.

### 4.2 The counts

Every count is taken from the voting members: the peers an election expects, the peers that have to be reachable, and the order in which a lease is renewed. An agent that is not a voting member of the zone has no count at all: it runs no election.

### 4.3 The gate: the voting members see each other

An election starts when the voting members are mutually OPERATIONAL. The voting member with the lowest identity starts it. The full matrix, every member's row, is still gossiped and shown.

A member with no role does not hold an election back. On its way in its agent may not be running yet. On its way out its operator may stop it before the owner removes the record, and the remaining providers need a leader to finish the removal. The same rule takes the auditor out of the gate: who cannot vote cannot block the vote. An auditor that is down therefore stops no election. It does stop every distribution in its zones (3.3).

### 4.4 Who may start, vote and win

- **Start.** A voting member only, whatever asks for the election: the zone's first load, a timer, the operator's command. An agent that does not vote and learns a leader from gossip arms no renewal timer.
- **Vote.** A voting member only. A vote from anybody else is not counted (3.3).
- **Win.** The winner is determined from the votes of voting members, and is taken only if it is one itself.

### 4.5 One check for every change

Every change of the zone's HSYNC3 or HSYNCPARAM records, and the zone's first load, runs one check for the zone. It applies to a zone that syncs with its parent through its agents.

- The local agent does not vote in the zone: nothing is started, and a lead it holds for the zone is dropped.
- A group covers the zone: a per-zone result for the zone is dropped. A group with a leader keeps it, and the leader takes the zone up (4.1). A group without one is left to its gate.
- No group covers the zone and the local agent is its only voting member: the agent elects itself, unless it leads already.

### 4.6 One voting member

- **The roles go, the record stays.** The zone moves to a group of two members and one voting member. If the group is new, the gate is met by that member's own row, it expects no peers, and it leads. No restart is needed.
- **The record goes.** No group is left. The check of 4.5 makes the remaining provider elect itself.
- **A term for it.** A self-election takes a new term, as any election does: one above the highest term the agent holds or has heard from a voting member. Without a term the member with no role beside it never learns who leads.

### 4.7 What a member with no role reports as leader

It learns the leader from gossip: the decided term that a voting member tells. `agent parentsync status` and `gossip zone-state` show that leader and term, and that this agent does not vote. Before the first beat from a voting member it reports that no leader is known yet. It never reports itself.

The same holds for an auditor. A member that does not vote causes no election, and nothing it says about terms is taken. It takes a newer term from a voting member at once. Whatever else a voting member tells it about who leads (a lower term, or the same term with another leader or a later end of the lease) it takes once the lease of the leader it holds has run out: the voting members have then started over, for example because they all restarted. Until that lease has run out it may show the earlier leader. What it shows is information only: nothing acts on it.

### 4.8 Retiring a group

When no zone is left in a group, the group's election state and timers go with it.

### 4.9 A leader acts for a zone only when the views of it agree

Each provider fetches the owner's zone on its own, so two agents can hold different versions of a zone's HSYNC3 and HSYNCPARAM records while they are in full contact with each other. That takes no network partition. It lasts seconds when every provider is notified and transfers at once, longer when one transfer is late, and without end when one agent is stuck on an old copy. For that time the zone can have two leaders: the leader of the group the zone left, which has not seen the edit, and the leader of the group it arrived in. Each would sync the parent from its own view, and the parent would take whichever write came last. For a signer that was just removed, one of them publishes its DS and the other withdraws it.

So a leader sends nothing to the parent for a zone, the bootstrap of the zone's SIG(0) key included, until both of these hold:

- every voting member of the zone's group holds the same make-up for the zone as the leader does;
- the leader of the group the zone left has shown that it holds that make-up too, or that it no longer has the zone, or a short fixed time has passed since the zone arrived: a few beat intervals.

Until then the sync is owed and not sent, and one line says who is waited for. This is the hold of 5.6 for another kind of not knowing: there the leader lacks the zone's data, here the group lacks one view of who the zone's members are.

To make it possible, every agent tells the members of each of its groups which zones it has in that group, and so which make-up it holds for each of them. A previous leader that is in none of the new leader's groups any more tells it nothing about the zone: it shows that it has dropped the zone by no longer listing it in the group the zone left. When the agents are in contact a disagreement shows within a beat, and the hold then lasts as long as the disagreement does. When the previous leader cannot be reached, or is stuck on an old copy of the zone, the hold ends with the fixed time.

The fixed time is enough because the first condition holds every leader, the previous one too. A previous leader that is alive hears within a beat that its peers no longer have the zone in its group, and from then on it holds its own sync. One that is not alive sends nothing. Its lease is no way out: a lease belongs to a group, not to a zone, and it is renewed for as long as that group has any zone left, so a previous leader that is stuck on one zone would hold that zone's sync for ever.

After a restart an agent knows of no group that a zone has left, and the second condition then asks for nothing. The first condition and the catch-up of section 5 carry that case.

One case is not covered. An owner who replaces a zone's only provider by another in one edit leaves a previous leader that has no peer to tell it anything. If its agent is then stuck on the old copy, it and the new provider both act. The order of an add and a removal in `guide/provider-changes.md` avoids it: the new provider is added before the old one is taken away.

A zone that arrives while its group's election is running is one of the zones that election is held for.

## 5. Catch-up

### 5.1 When it is sent

| Case | Reason word | Who asks whom |
|---|---|---|
| The agent starts | `start` | The agent asks every voting member of every zone it is a member of |
| The agent becomes a member of a zone | `join` | The agent asks every voting member of that zone |
| The agent is given its first role in a zone | `role` | The same, once more |
| A peer is given its first role in a zone | `peer-role` | The agent asks that peer. Without it a zone would never be caught up again once a newcomer has its role: the zone would name a voting member that nobody has asked |
| A peer says that it has started | `peer-start` | The agent that got a `start` request answers it, and then asks that peer back |
| A peer is OPERATIONAL again after more than an hour | `outage` | The agent asks that peer, for each zone they share. The hour is a config value, well below the 24 hours a queued message is kept |
| The operator runs `resync --pull` | `manual` | The agent asks every voting member of the zone |

A request to a peer goes out when that peer is OPERATIONAL from here and the zone's first load is done.

The `peer-start` case is there because a restarted agent has lost its queue: a change it made just before it stopped may never have reached a peer, and it does not know which. Only `start` is answered with a request back. No agent asks a peer about a zone while a request to it for that zone is outstanding, or within a minute of a complete answer.

### 5.2 To whom, for which zones

Every voting member of the zone other than the asker. The zones are those in which the asker is a member, with or without a role.

### 5.3 What is asked

RFI SYNC, with the reason word and a name for the request, both carried in the message. It is a plain send with a synchronous acknowledgement, not a queued message.

### 5.4 What is answered

One SYNC to the asker alone, through the confirmed queue, holding the answering agent's own contributions to the zone.

1. **Every RRtype is named.** One `replace` for each type the answering agent may contribute (NS, KEY, CDS, DNSKEY), empty where it holds none. The asker's stale records go. The zone's CSYNC is the leader's alone, so only the leader's answer names it.
2. **The key states travel.** When the answering agent's provider signs the zone, the DNSKEY operation carries the key states, from its signer's latest inventory.
3. **An answer always goes out,** also from an agent that holds nothing.
4. **The marker.** The SYNC names the request it answers and says `complete` or not, with the reason when not. An agent answers "not complete" when it cannot vouch for its own state: its provider signs and it has no inventory from its signer yet, or it has not finished reading its own contributions back from its combiner. A "not complete" answer carries the marker and no operation: empty sets from an agent that has not read its own state would remove its contributions at every peer.

The asker handles the operations as it handles any remote update: it evaluates them, applies them, passes them to its own combiner and confirms. An older message that leaves a queue later does not undo the answer.

A complete answer from a provider in `signers=` counts as that provider having spoken about its keys, also when it lists no key.

### 5.5 How completeness is known

By construction and by the marker: a `replace` is the sender's whole set for a type, the answer names every type, so one answer is everything that agent holds for the zone. The marker says so and names the request. An answer without the marker does not count as complete.

The asker keeps, per zone and peer: asked when, answered when, complete or not, and the last error. It is kept in memory, since a restart asks again anyway.

A zone is **caught up** when this agent has read its own provider's state back from its combiner and its signer, and every voting member other than this agent has answered completely since this agent started, became a member of the zone, or last asked.

### 5.6 What waits for it

- **The DS set.** For a leader whose own signer does not own the zone, the zone's DS set is unknown while a provider in `signers=` has not spoken about its keys. A complete answer makes a provider speak, and a set that turns from unknown to known asks for a sync with the parent.
- **The leader's sync with the parent.** The order is fixed: first the zone's data from every source (the other agents, its own combiner, its own signer), then a look at what the parent holds, then only the difference. A leader that has just started remembers nothing of what the parent has, and does not assume it. Nothing is sent while the zone is not caught up. One line says what is waited for, the sync is noted as owed, and the answer that completes the catch-up asks for it. This holds for NS and glue as well as DS: a leader that missed a peer's change would send the parent its own older view. A leader that does not have all the information is in no position to decide.
- **Not "in sync".** When NS and glue are in step with the parent and there is no DS set to compare, for a zone that names a signer, the leader does not report "in sync". It reports "DS set unknown, waiting for" and the provider. When every signer has spoken and none of them holds a key that a DS is made from, it says that.
- **Nothing else.** Voting, the agent's own edits, and what it confirms to others do not wait.

The stall this adds is small. Catch-up needs the voting members to be reachable, and so does having a leader.

### 5.7 Retries

A request that fails, is refused, is answered "not complete", or is acknowledged and then not answered is sent again after 5 s, 15 s, 30 s and 60 s, and then every 5 minutes, for as long as the peer is OPERATIONAL. There is no bound: a stall must stay visible and end when its cause ends. The first failure is logged, then one line an hour. A peer that stops being OPERATIONAL pauses its requests, and they start again when it is back. A refusal is expected for a short while after a join, until the peer has loaded the zone with the new record.

### 5.8 The cost

With Z zones and P voting peers per zone, a start sends Z x P requests and receives as many answers. Each answer is one small message and its two confirmations. A `start` is asked back, which doubles it. An agent with 1,000 zones and two peers handles about 4,000 requests and 4,000 answers at its start. Requests to one peer are paced, eight in flight, as discovery is, so the start takes tens of seconds, not one burst. After a restart nearly every answer changes nothing at the asker. One request per peer for many zones would cut the count and is a wire change: left for when it is needed.

## 6. What an agent with no role does for its own operator

- **It refuses edits.** `add-rr`, `del-rr` and `update-local-zonedata` answer that the provider has no role in the zone: the zone lists it under neither `servers=` nor `signers=`. Nothing is stored and nothing is sent, to its combiner or to anybody.
- **It refuses to lead.** `parentsync-election` and `parentsync-bootstrap` answer that this provider cannot lead the zone.
- **It may ask.** `resync --pull` works. `resync --push` sends nothing to peers and says why.
- **It shows where it stands.** `zone mplist` shows the member list with each member's standing, and this provider's own: signer, server, auditor, "member, no role", or not listed. `agent parentsync status` shows the leader and term it has learned, that it does not vote, and for each voting member whether the zone's state has been answered completely, and since when.
- **It logs the transition once:** an HSYNC3 record and no role: member, no vote, no edits.

## 7. Not part of this design

- **Agents that are out of step with each other.** All agents of a zone must be in sync protocol-wise. Nothing in this design makes an agent cope with a peer that follows other rules.
- **A provider named in `signers=` while it runs** (#146, #136). This design gives a newcomer what that needs before it has a role: comms with every member, and the other signers' DNSKEYs with what they say about them.
- **The rest of a removal:** when a leaving provider stops signing and serving, the waits, and "safe to remove" (#147, #138, #159, items 3 to 5 of #137). The member with no role of this design is its starting point. Decided for it already:
  - The removal starts at the zone owner's edit that takes the provider's roles away.
  - It runs at the parent first (the NS, then the DS), then in the zone, and last at the provider's own servers.
  - The leader of the group the zone is in after that edit is responsible for it. That leader is never the leaving provider, and it needs nothing from it: when a step is safe is a matter of time and TTL.
  - While it leaves, the provider's key machine holds for the zone: no rollover and no new DNSKEY, and signing and re-signing go on with the keys it has. A leaving signer that stopped signing would let its signatures expire while resolvers are still sent to it.
  - The rule needs no direction: the leader sees to it that nothing points at a member with no role. For a provider on its way in there is nothing to remove.
  - Open: whether the zone's NS RRset or the parent's changes first. A parent that takes NOTIFY only copies the NS RRset from the zone.
  - Open: how the leaving provider's own records are withdrawn. A `replace` is the sender's own set (5.4), so the leader cannot withdraw another provider's contributions with one (#159). Whatever does it is a distribution that does not wait for the leaving provider (3.3).
  - Open: the leader's CSYNC and a leaving provider. The leader waits for every recipient's confirmation of the zone's CSYNC before it sends the NOTIFY, with no time-out, and a member with no role is a recipient. At a parent that takes NOTIFY only, the CSYNC is what carries a leaving provider's NS removal, so a leaving provider whose agent is stopped would hold its own removal. Not waiting for it may only move the stall: the parent scans every nameserver it delegates to, the leaving provider's among them, and what its scan does with a nameserver that lacks the record, or does not answer, is not established. To be settled with the point above.
- **A server that becomes a signer and serves its own signatures too early** (#160), and wrong answers before a provider is listed (item 1 of #137).
- **New confirmed message types:** a leader's statement about the parent that every member verifies, and the transfer set-up.
- **Keeping key states across a restart.** Not done on purpose: a stale DS set can remove a DS that is needed, an unknown one cannot.
- **A leader for a zone whose parent the owner updates.** There is no election for a zone without `parentsync=agent`.
- **The meaning of the HSYNC3 state field.** OFF stays out of the group.
- **The unused option `mp-not-listed-error`** (item 4 of #137).
- **Ordered delivery** (#51), and one request for many zones.
- **The auditor's view of a blocked distribution** (#152).
- **HTTPS as the only mechanism** (#59, #56).
