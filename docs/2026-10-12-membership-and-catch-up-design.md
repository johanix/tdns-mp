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
| A role, to no role | The zone moves to the group that has it as a member with no role. If it led the zone it no longer does: that group has a leader of its own, and the removal is that leader's to run (section 7). The edit by itself withdraws nothing of what the provider contributed: its NS records stay in the zone, its DNSKEYs stay in every signer's key set, and its DS stays at the parent, until the removal takes each of them away in its turn. | It no longer votes or leads for the zone. It goes on exactly as before, except that it initiates nothing (2.3). |
| A record, to no record | It leaves the zone's group. When no zone is shared with it any more, comms end after a hold time (3.1). | The zone is no longer a multi-provider zone for it. |

### 2.3 A provider that has lost its roles goes on, and initiates nothing

A provider whose roles the owner has taken away is still delegated to, and resolvers are still sent to it, until the removal has run. So for that time it does exactly what it did before, with one exception.

**What it goes on doing.** It takes every new version of the owner's zone, as it comes. It takes what the other members distribute, applies it and confirms, by the same rule as every member (4.9). It answers what it is asked. If it holds the zone's SIG(0) key, that includes a voting member's request for the key: handing the key over is an answer and not a change of its own, and a leader that took the zone up after it may have nobody else to ask (4.1). If it signed, it signs and re-signs with the keys it has. It moves its serial on, notifies its downstream servers, and serves.

**The exception: it initiates nothing.** It refuses its operator's edits for the zone. It starts no key rollover and makes no new DNSKEY, and a rollover that is under way stops where it is. It can change nothing of what it contributed, its own NS records and DNSKEYs included, and it does not withdraw them itself: the leader does (section 7). Every change that concerns it comes from the others, and it processes each as it processes any other.

**Why it must follow the zone.** A leaving provider that stopped signing would let its signatures expire while resolvers are still sent to it. One that stopped following the zone would be the one nameserver that serves another NS RRset than the rest, and a parent does not change a delegation while the child's nameservers disagree about it. The removal would then wait for the provider it is removing.

**The others do the same from their side.** They go on treating what the provider has contributed as before, until the removal withdraws it. A signer that dropped the leaving signer's DNSKEYs from its own key set at the owner's edit would make the leaving signer's answers fail validation at every resolver that holds that key set.

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

- **Distributions** go to every member, and every member's confirmation is waited for: the voting members, a member with no role, and the auditor. Where a zone has an auditor, it is a required participant: a SYNC is not complete without the auditor's confirmation. For a member with no role the wait is also a test. Being able to keep up with the other providers is a condition for serving the zone, and it has to show before the zone owner gives the provider a role, not after. There is one exception: a distribution that withdraws a member with no role, which is to say its own NS records, DNSKEYs or DS, does not wait for that member. Its operator may already have stopped its agent, and its removal must not depend on it. A distribution is started, and taken, only for a zone that is settled (4.9).
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

**Every voting member holds the zone's SIG(0) key.** A voting member that does not hold the key asks for it: when it catches up, and whenever the zone publishes a KEY that it has no private part for. Whoever holds it hands it over to a voting member that asks (3.3): a voting member, and also a provider that has lost its roles and still holds it (2.3). So the key does not sit at the one leader that made it, and a zone does not lose its parent sync with one provider.

**The key is the group's, not its maker's.** The zone's KEY record is nobody's contribution. The zone's leader publishes it on the group's behalf, as it publishes the CSYNC, and a member keeps the KEY that the leader of the zone publishes and no other. So nothing of the key has to be withdrawn when the provider that made it leaves.

**When a voting member leaves, the key is rolled.** A provider that no longer votes for the zone still holds the private key it was given. The leader makes a new key, hands it to the voting members that remain, and has the parent take it in place of the old one. That is the leader's responsibility, and part of the removal (section 7). A member with no role is not handed the new key (2.1).

**Taking a zone up gives it a new key only when no voting member has one.** A zone that publishes a KEY has a key, and the parent holds it. A leader that does not have it asks the voting members, and the leader of the group the zone left for as long as that one is still a member, and asks again when one of them is silent, on the schedule of 5.7. A peer that is slow, restarting or silent is a peer to ask again, not a peer without the key. Until the leader has a key its sync with the parent is owed and not sent. Only when every one of them has answered that it has no key does the leader generate a new one and bootstrap it with the parent. Whether a zone publishes a KEY is judged only once this agent is caught up (5.5): before that, an empty set says only that it has not heard yet. A zone that then publishes none, and whose parent holds none, gets a key.

An example. The group of a, b and c has 100,000 zones, and c leads it. The owner of one zone takes c's roles away. That zone moves to the group "a and b, with c as a member with no role". If that group exists, the zone takes its leader. If it is new, a and b elect. Nothing is elected in the first group, which now has 99,999 zones and c as its leader. Later the owner removes c's record, and the zone moves to the group of a and b and takes its leader.

Elections are held per distinct make-up, never per zone: 40,000 zones that drop c at once land in one group and share one election.

A zone with fewer than two members is in no group and has an election of its own, per zone.

Agents see the owner's edit at different moments. For that interval the old group and the new one can each have a leader for the zone. Section 4.9 says what is done about it.

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

### 4.9 Nothing is changed for a zone until its voting members agree on its make-up

Each provider fetches the owner's zone on its own, so two agents can hold different versions of a zone's HSYNC3 and HSYNCPARAM records while they are in full contact with each other. That takes no network partition. It lasts seconds when every provider is notified and transfers at once, longer when one transfer is late, and without end when one agent is stuck on an old copy. For that time the zone can have two leaders: the leader of the group the zone left, which has not seen the edit, and the leader of the group it arrived in. Each would sync the parent from its own view, and the parent would take whichever write came last. And each provider would apply what the others send it by its own version of who the zone's members are.

So after a change of a zone's make-up, nothing that a provider does is changed for the zone until the zone is **settled**. A zone is settled at an agent when both of these hold:

- the agent has held the zone's make-up, unchanged, for a fixed time;
- every other voting member of that make-up has told the agent the same make-up, not longer ago than a telling counts.

While a zone is not settled at an agent:

- **It starts nothing for the zone.** No distribution of its own, and, if it leads, nothing to the parent: no sync, and no bootstrap and no roll of the zone's SIG(0) key. What it would have started is owed, and is started when the zone is settled.
- **It takes nothing for the zone.** A distribution that arrives is kept and not applied. Its sender is told at once that it has arrived and is kept. It is judged when the zone is settled, by the zone as this agent then holds it: applied and confirmed, or refused. A distribution whose sender is by then no voting member is refused, and so is a leader's delete whose condition no longer holds (section 7). Nothing that was kept under one make-up is applied under another without being judged again.
- One line says who is waited for.

This is the hold of 5.6 for another kind of not knowing: there an agent lacks the zone's data, here the group lacks one view of who the zone's members are.

**What does not wait.** The owner's zone itself: every new version is transferred, signed and served as it comes (2.3). Beats and gossip. Elections, which are held per group and not per zone. A request for the zone's state (5.3); the answer to it is a distribution, and waits like any other.

**The telling.** An agent tells a peer which make-up it holds for a zone by listing the zone in its row of that group's gossip, which every beat carries. Two things decide whether a zone is listed.

- The agent has held the zone in that make-up for the fixed time. The time is counted on the agent's own clock, and it starts again at every change of the zone's make-up and at the agent's start.
- The zone is of interest now. In a beat that the agent sends, that is a zone it has something owed, kept or under way for. In its answer to a peer's beat, it is also every zone that the beat listed.

So a zone listed in a beat tells, and it asks. A zone listed in the answer to a beat tells only: an answer is not answered, or two agents would go on listing a zone to each other for ever. When nothing is owed, kept or under way any more, the agent stops listing the zone, the tellings it holds run out, and the next piece of work asks again. An agent's row is therefore made for each peer and for each message: what one peer asked is answered to that peer, not to the group. What a peer hears of a zone from an agent is one make-up that the agent has held for the fixed time, or nothing. A zone that nobody has anything to do for is in no beat.

**A telling counts only while it goes on being told.** A make-up that a peer has told counts for two beat intervals and then has to be heard again. A peer that stops telling it, tells another, or cannot be heard counts as not agreeing.

**The two times.** The fixed time is three beat intervals and a telling counts for two. Agents may beat at different intervals, and each announces its own: both times are counted in the longest interval that a member of the group announces. The difference between the two, one beat interval, is the margin, and it has a lower limit of its own. A telling counts from when it is heard, on the hearer's clock, so the margin has to cover two things: the longest time a beat can be under way, which is the time after which its sender gives it up, and how far two agents' clocks can run apart in the time a telling counts.

**Why it holds.** Take two agents that hold different make-ups for a zone, and a voting member that both of them count. That member held one make-up at a time. The agent of the make-up it left counts its word for no longer than a telling counts after the member last told it. The other agent hears the new make-up from it no earlier than the fixed time after it moved. The fixed time is the longer, so at no moment do both count it, whatever is lost and however often the owner changes the zone. What is late is covered up to the margin: a telling that is heard later than the margin after it was sent, or a clock that is slow by as much, is counted for too long, and for that long both can be settled. Two agents can therefore both act for a zone under different make-ups only when the two make-ups have no voting member in common. That is the case named below, and no other.

**Who has to agree.** The voting members, and only they. A member with no role and an auditor do not: a leaving provider that is stuck on an old copy must not be able to hold its own removal (section 7), and an auditor that is down holds no election (4.3). Both still receive every distribution, and their confirmations are waited for as before (3.3).

- A member with no role takes a distribution by the same rule as everyone: when the zone is settled at it.
- An auditor changes nothing in a zone. It records what it receives and confirms at once, as before.

**What it costs.**

- After a change of a zone's make-up, nothing that a provider makes happens for the zone until the fixed time after the last voting member has loaded the change.
- After the start of a voting member's agent, the same holds for its zones until it tells them again.
- A voting member that cannot be heard holds every change that a provider makes in its zones. A distribution already waited for its confirmation. Now it is not started.
- A member with no role that is stuck on an old copy of the zone keeps what it is sent and confirms none of it. Its own removal does not wait for it (3.3). Every other distribution in the zone does, until its record is gone. Section 7 has this as an open point.

**A beat stays small.** It grows with the number of zones that something is owed or kept for, not with the number of zones. The price is one exchange of beats before an agent can act for a zone it had nothing to do for until then.

**What is not covered: an edit that leaves no voting member in common.** The proof needs a voting member that both make-ups have. An owner's edit whose old and new sets of voting members are disjoint leaves none: one provider replaced by another, two replaced by a third, any exchange of the whole set in one edit. Nobody on the new side waits for anybody on the old side, and the old side does not have to be stuck. The voting members of the old make-up go on agreeing with each other for as long as none of them has loaded the edit, and a sole one has nobody to wait for at all. So from the fixed time after the new side has the edit, until a voting member of the old side loads it, both sides act, and the parent takes whichever write arrives last. A transfer that takes longer than the fixed time is enough. An old side that never loads the edit is the case that never ends.

No rule between agents closes this: the two sides have nobody in common to carry it. What closes it is the order of the owner's edits. A set of voting members is changed one provider at a time, with a voting member in common at every step, and the next edit waits until the one before has settled. `guide/provider-changes.md` describes an add and a removal in that order; it has to say as well that an edit which exchanges the whole set is not to be made.

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

1. **Every RRtype is named.** One `replace` for each type the answering agent may contribute (NS, CDS, DNSKEY), empty where it holds none. The asker's stale records go. The zone's KEY and its CSYNC are the group's, published by the leader alone (4.1), so only the leader's answer names them.
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
- **Nothing else.** Voting, the agent's own edits, and what it confirms to others do not wait for the catch-up. The last two wait for the zone to be settled (4.9).

The stall this adds is small. Catch-up needs the voting members to be reachable, and so does having a leader.

### 5.7 Retries

A request that fails, is refused, is answered "not complete", or is acknowledged and then not answered is sent again after 5 s, 15 s, 30 s and 60 s, and then every 5 minutes, for as long as the peer is OPERATIONAL. There is no bound: a stall must stay visible and end when its cause ends. The first failure is logged, then one line an hour. A peer that stops being OPERATIONAL pauses its requests, and they start again when it is back. A refusal is expected for a short while after a join, until the peer has loaded the zone with the new record. An answer that waits for the zone to be settled (4.9) is not a failed request: the time to the next try is counted from when the zone is settled at the asker, and an answer that has arrived and is kept ends the tries.

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
  - While it leaves, the provider goes on exactly as before and initiates nothing (2.3). The owner's edit withdraws nothing by itself, at the leaving provider or at any other: each withdrawal is a step of the removal.
  - The rule needs no direction: the leader sees to it that nothing points at a member with no role. For a provider on its way in there is nothing to remove.
  - Open: whether the zone's NS RRset or the parent's changes first. What is known: a parent that takes NOTIFY only copies the NS RRset from the zone. A parent that takes UPDATE and checks the child accepts either order, as long as the child's nameservers agree on the NS RRset and it keeps no NS that the agreed set lacks. It refuses when some nameservers have changed and one has not. With the leaving provider following the zone (2.3), a change in the zone reaches every nameserver, the leaving provider's among them, and the leader's ordinary sync then carries it to the parent.
  - The leader withdraws the leaving provider's records, and needs nothing from that provider to do it. This design covers a provider that cooperates while it leaves; one that does not will have to be removed too, and the same mechanism must serve both. So the withdrawal is the leader's own operation: it names a provider and takes away what that provider contributed. Every other member applies it whether or not the leaving provider takes part, and it does not wait for the leaving provider (3.3). A leaving provider that cooperates applies it like any other change (2.3).
  - What the leader may do, and on what condition. It may delete the DNSKEY and CDS records that another provider contributed, given that the provider is no longer listed in `signers=`. It may delete the NS records and the glue that another provider contributed, given that the provider is no longer listed in `servers=`. It may only delete. The owner's edit is thereby the authority, also for a provider whose HSYNC3 record is gone.
  - A member applies such a delete only when it comes from the leader of the zone's group, and when its own copy of the zone says the same of the provider. A delete that arrives while the zone is not settled at a member is kept like any distribution, and judged when the zone is settled (4.9): a member that has not yet seen the owner's edit does not refuse it for good, and one whose copy by then names the provider in the role again refuses it.
  - That is a permission, not a timetable. When each delete is safe is the leader's procedure: the NS first, then the DS, then the DNSKEYs, with the waits between. Open: whether a member also checks the timing itself, for instance that the parent holds no DS for a DNSKEY it is asked to drop.
  - A leaving provider that cooperates applies these deletes like any other change (2.3). The delete of its own DNSKEYs is the end for it: it stops signing and serving the zone.
  - The zone's SIG(0) key is rolled, by the leader, because the leaving provider still holds the private key (4.1). The parent is told with the old key: the new key is added by an update that the old key signs, so the parent has nothing to verify from the zone, and the old key is deleted by an update that the new key signs. The zone publishes the new KEY only after the parent has taken it.
  - The roll is the first step of the removal: with a provider that cooperates the order does not matter, and with one that does not, the earlier the better. The roll has to complete. If it fails, the removal goes on with its other steps and the roll is tried again as the last one, and again after that until it has succeeded.
  - Open: whether a distribution waits for a provider that has lost its roles at all. The wait is there for a newcomer, to show that it keeps up before it is given a role (3.3). A provider on its way out has nothing to show, and one that is stuck on an old copy holds every distribution in the zone but its own removal (4.9).
  - Open: the form of the delete. A `replace` is the sender's own set (5.4), so it cannot be one (#159).
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
