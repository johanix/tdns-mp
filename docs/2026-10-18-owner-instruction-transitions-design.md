# Changes to the zone owner's instructions: numbered by the owner, agreed before they act, carried out by the leader

**Status:** PROPOSAL, 2026-10-18, revision 6 (2026-10-26); rule 2 amended 2026-10-28.

This document describes how tdns-mp handles a change of a zone owner's instructions: every edit of the zone's HSYNC3 or HSYNCPARAM records. It describes the design as it is meant to stand. The difference from today's code and the steps of the work are in the plan beside it, `2026-10-18-owner-instruction-transitions-plan.md`, whose section 6 lists the decisions this design rests on and the parts of the membership design it changes.

It builds on the membership design, `2026-10-12-membership-and-catch-up-design.md` ("membership" below), and is implemented after that design's plan (its steps 1 to 8). It takes over what that design kept aside on 2026-10-18:

- its section 4.9, the hold after a change of a zone's make-up, which this design replaces with a hold after any change of the owner's instructions;
- the listing by interest of its 4.9 and decision 24, in the form of rule 4 below;
- the zone's SIG(0) key, as its section 4.1 describes it, but for what that design's plan builds in its step 7b since 2026-10-19: every voting member holds the key, and no key is made while the zone publishes one;
- the switch of its rule 1 in the code: every provider with an HSYNC3 record is a member;
- the rest of a removal (its section 7), which here is what the leader carries out after an edit that takes a provider's roles away.

Revision 2 took an adversarial reading and six code readings of revision 1. Revision 3 took three critics' readings of revision 2 and of the plan. Revision 4 took a check of revision 3. Revision 5 takes a check of revision 4 (2026-10-18). Revision 6 takes an external review of revision 5 (2026-10-24) and the project owner's answers to it (2026-10-26): agreeing targets the highest serial the judge accepts (3.1), 3.7 says why a telling must be fresh, and the plan's readings of the leader a member with no record listens to (3.4), of where an older serial is fetched (3.1), and of the order of the NS RRsets in a removal (5.2) are now the design's. At the project owner's word (2026-10-27) it names a set of instructions by its serial throughout, where earlier revisions said "version"; the digest is the serial's check.

## 1. Why

Each provider fetches the owner's zone on its own, and each part of a provider acts on its own copy the moment it loads it: the agent, the combiner, the signer, the provider's own nameservers where they publish `_signal` records, and code in tdns that the agent calls. So for a while after an owner's edit the providers act by different serials of the owner's instructions, and the parts of one provider can too. That takes no network partition: a late transfer is enough.

Every corner case found in the membership work came from that. A guard per kind of change left the next kind uncovered (issue #200 lists the faults found that way). This design handles all of them alike. A change of the owner's instructions is a **transition** from one numbered set of instructions to the next. It is agreed by the providers before any of them acts on it, carried out by the leader, and seen to be done.

## 2. The rules

1. **The owner numbers its instructions.** HSYNCPARAM carries `serial=N`, an unsigned 32-bit number compared by serial-number arithmetic (RFC 1982). The owner raises it at every edit of the zone's HSYNC3 or HSYNCPARAM records. One edit may change several things; it is one transition. A raised serial with unchanged contents is a transition too, with nothing to carry out. A zone's **instructions at serial N** are its HSYNC3 RRset and its HSYNCPARAM record as the owner publishes them with that serial.
2. **A digest checks the number.** Each agent computes a digest of one canonical reading of the instructions, and the same function decides whether two copies differ. The reading is what the code acts on, and nothing else:
   - for each HSYNC3 record in state ON, its label and its upstream (each without a trailing dot) and its identity (as a case-folded FQDN); the labels of the records in state OFF;
   - whether an HSYNCPARAM record is present at all (HSYNC3 without HSYNCPARAM is the legacy case, in which every ON record votes);
   - each known HSYNCPARAM key except the serial, with absent keys read as their defaults and the provider lists as sorted sets.

   Unknown and private-use keys, TTLs and signatures are not in it. The reading and its digest are tdns-mp's own: the draft does not define them, so only agents of tdns-mp compare digests. Instructions are named by their serial, and the digest checks it: the pair (serial, digest). Records are compared by label and identity together: an identity changed under a label is the removal of one provider's record and the addition of another's.

   These are **owner errors**, and each holds the zone (3.6):
   - two voting members tell the same serial with different digests, or a voting member tells a digest for the active serial that differs from this agent's own copy: an edit without a raised serial. A member that does not vote and tells a conflict is shown, and holds nothing;
   - more than one HSYNCPARAM record, or two HSYNC3 records with one label in any state (the draft forbids both);
   - a copy that drops HSYNCPARAM while HSYNC3 stays, or that drops both while more than one provider is listed under the active serial.

   A copy whose serial is lower than the highest the agent has held is not adopted, with a warning; an owner who wants old instructions back publishes them with a new, higher serial. A zone whose HSYNCPARAM has no serial is at serial 0, and a change of its instructions at serial 0 is an edit without a raised serial: the key is required for a zone that is to change its providers.

   *Amended 2026-10-28* (the project owner's decisions; plan decisions 106 to 108, tdns-mp #306 and #308). Three more owner errors, each a copy with no reading:
   - one identity under two HSYNC3 labels, the converse of two records with one label;
   - HSYNCPARAM without `serial=`;
   - HSYNC3 without HSYNCPARAM.

   So every reading has HSYNCPARAM and a serial. This replaces, above, the legacy case of the reading's second item, the owner error of a copy that drops HSYNCPARAM while HSYNC3 stays, and the zone at serial 0; the digest still writes the second item. At a first load, with no serial held, a copy with no reading starts no multi-provider work until one that reads arrives; with a serial held, it holds the zone (3.6). Rule 5's part with "a zone whose copy carries no serial" no longer arises. tdns parses these records as before, and a zone keeps loading and being served.
3. **Each agent keeps serials per zone, on disk.** The **active** serial it acts by, with its instructions; the serial it was thawed from, with its instructions, until the transition is done; every newer serial it has held and told, with its instructions, until a transition passes it; the highest serial it has ever held; the last thaw it heard; and the zone's phase, its current step and that step's sets (3.5). Each agent's combiner and signer keep, on disk, the last serial and the sets their agent handed them. None of this is lost at a restart. An operator command forgets a zone's stored serials; it is for a steady zone only, run at every agent of the zone together. A zone that leaves an agent's configuration takes its serials with it. An agent changes its active serial only as 3.2 and 3.4 say: at the leader's word, a voting member's first-hand relay of it, or, for a zone with no voting member under N, the tellings of every voting member under the new serial.
4. **What an agent tells, it tells first hand.** Every message an agent sends carries, for the zone it concerns: its active serial, its newest serial and the serial it agrees on (3.1), each with its digest; the last thaw it heard, whether it refuses its newest serial and why, and whether its provider has a key rollover under way. With it, each agent tells its own provider's nameserver names, from its configuration, and the removals under way it holds, with the step it holds. A telling counts for the thaw only while it is fresh: heard within the configured time of 3.2, since what it says of rollovers can change after it was sent (3.7). A beat carries this for each zone the sender has something to do for: every zone that is not steady at it, every zone with an owner error or a refused serial, and every zone with work owed, kept or under way (membership decision 24). A zone steady at both agents with nothing to do needs nothing told. A receiver knows at once whether the two are in step, and if not, which of them lags.

   What changes state is taken only from a message its sender sent: a telling, the leader's word, a rollover flag, a refusal, an election record and its term. The answer to a beat counts for nothing. Over HTTPS both ends now check the other's certificate against its TLSA record (tdns-mp #242 and #246), but over DNS an answer without the payload envelope is still accepted, and one rule for both mechanisms is simpler. Gossip in an answer is shown and changes nothing. The argument of 3.7 needs payload encryption between agents: a zone with a voting member that has it off is not thawed, and its status says why.
5. **One reader.** Nothing in tdns-mp, and nothing in tdns that the agent calls, reads HSYNC3 or HSYNCPARAM from the zone to decide something, except the transition machinery. Every decision reads the agent's active instructions through one accessor, and every step's sets: groups and elections, admission and discovery, the recipients of a distribution, the delegation sync option, the DS set, the expected confirmations of a key's distribution, the edit policy, the key's hand-over, and the hooks of membership steps 4 and 8, which run when the active serial changes and at every first load, not at a refresh. The combiner, the signer and the provider's nameservers take what they need from their agent (3.5). A part that has never been handed anything: for a zone whose copy carries no serial (the first start after the upgrade), it acts by its own copy until its agent hands it a serial; for a zone whose copy carries a serial, it asks its agent before its first combine or signing, and meanwhile serves what it last served.
6. **Messages between serials.**
   - A confirmation reports a fact and is always taken. For a decision, an answer stamped with an active serial that differs from the stamp of the send it answers is a "not yet": the sender asks again once the two are in step, at once if they already are when the answer comes. An auditor's confirmation counts whatever serials it holds: it changes nothing.
   - A request (RFI) is answered whatever its stamp: the answer is judged by the asker.
   - A distribution is stamped when it is sent, not when it is queued. One stamped with an active serial lower than the receiver's is answered "made under older instructions": a final answer that the sender's key machine reads as pending; the sender then judges the change again by the newer instructions and sends it again if they still call for it. One stamped higher than the receiver's active serial, or received while the receiver does not yet know its active serial (3.4), is kept until the receiver's active serial has caught up. This holds for the leader's withdrawals too (5.2).

The membership rules stand where this design does not change them: safety before everything (an operation may stall, the zone must never go bogus or lame), and all agents of a zone run the same rules (no mixed versions).

## 3. A transition

| Phase | Begins | What holds | Ends |
|---|---|---|---|
| Steady at N | | Everything runs by N | An agent holds a serial above N |
| Agreeing | At each agent, when it holds a serial above N that the judge accepts (3.1) | Nothing new starts; work under way finishes by N; the providers agree on the next serial | The thaw |
| Reconciling | At the thaw | The leader carries out what the new serial calls for, step by step; nothing else new starts | "Done" |
| Steady at V | | Everything runs by V | |

Every group with two or more voting members elects a leader, whatever its `parentsync`: transitions need one. A zone in no group is led by its only voting member.

### 3.1 Agreeing

An agent enters this phase for a zone when it holds a serial above its active one that the judge accepts against it (below): from its own copy, or after it has heard of one first hand and fetched it. A fetch goes down the provider's chain (the agent asks its signer and its combiner to fetch from the owner) and is paced, so that an upstream that keeps serving an old copy causes no fetch at every beat. The status names a member that tells a serial nobody else holds.

- **Nothing new starts for the zone.** No operator edit, no distribution of the agent's own, no new key rollover, no new sync with the parent, no new offer of the zone's SIG(0) key. The agent tells its signer to start no new rollover, and its tellings count for the thaw only once its signer has confirmed that hold. What would have started is kept on disk, in order, apart from the data that catch-up answers and syncs read, and handled when the transition is done, by its instructions. An operator is told that the edit is kept and why.
- **Work under way finishes, by N.** A key rollover under way runs to its end, every phase of it, its distributions and its syncs of the delegation included; such a sync carries the whole delegation by the sets the parts hold (3.3), not by a serial's lists. While a rollover waits for the parent to trust a key just made, that key's offers and bootstrap go on too. Distributions stamped N between agents whose active serial is N are taken as before.
- **An emergency rollover may start**, by N. Its distributions and its parent syncs are exempt from the freeze, and the thaw waits for it. A provider that has lost its roles, or that the serial being agreed takes away, makes none: its keys go with its removal.
- **What is not held:** the owner's zone itself (transferred, signed and served as it comes), beats and gossip, elections, catch-up requests and their answers (membership 5), and the requests for the zone's SIG(0) key.
- **The providers agree.** Every agent tells its newest serial, and the serial it agrees on, in every beat. Each holds its active instructions and every newer serial it has held, so each computes the same difference between them.
- **An unsafe transition is refused.** The difference is judged by a function of the two serials alone, so every agent judges alike, and each tells its refusal. A member that moves straight to a serial on a first-hand thaw (3.2) judges the thaw's own pair, from and to, with the from-serial fetched if it lacks it, never its own older active serial against the new one; it refuses only a serial it cannot read. The from-serial is fetched from the leader, or from a voting member that tells it as its active serial or as its last thaw's from, and checked against its digest: the owner serves only its newest copy. Refused is a transition that:
  - removes the ON record of a provider that has a role under N, or gives a role to a label that has no ON record under N. The owner's order, a record before a role and roles before a record, is thereby a rule. (An edit that removes a record while that provider's removal is under way waits for "done", as every newer serial during a reconciliation does: 3.3);
  - changes the identity under a label that has a role;
  - moves a signer to `servers=` only, or empties `signers=` of a signed zone;
  - leaves an ON record whose upstream names a label that is not in `signers=` under V or has no ON record under V, or removes a signer that is a remaining server's upstream;
  - needs a step that cannot be carried out yet (5.1, 5.3, 5.6).

  An agent that holds no serial above N that the judge accepts keeps the zone steady at N. It is not frozen: nobody acts on a refused serial.
- **The serial agreed on** is the highest serial the agent holds that the judge accepts against N. A newer serial that the judge accepts becomes the serial agreed on. A newer serial that it refuses does not replace it: the agent holds it, tells it as its newest with its refusal, and judges it again against the serial agreed on once that transition is done (3.3). So an owner who publishes a record and then its role before the first is thawed loses neither. An agent told first hand, by a voting member, a higher serial agreed on than its own, which it does not hold, fetches it from that member, as it fetches a from-serial. The serials in between are kept until a thaw passes them.

### 3.2 The thaw

The leader of the zone's group under N thaws the zone to a serial V when all of these hold:

- every voting member under N, the leader included, tells, first hand and in its latest message, active N and that it agrees on V, by serial and digest, and has its signer's hold confirmed; a refusal of a serial above V holds nothing; the leader agrees on V too;
- no key rollover is under way in the zone, by every voting member's latest telling, an emergency rollover included;
- the leader has nothing in flight towards the parent: no sync, no retry of an UPDATE, no offer of the zone's key, no NOTIFY waiting. Entering agreeing, the leader stops starting such work except for a rollover under way, and cancels what it has left at the thaw's turn through a context of its own for the zone. The same drain is made at every hand-over of the zone's leadership.

**A leaving voting member** is one that votes under N and not under V. One whose telling has not met the first two conditions for a configured time, counted from when this agent first holds V, heard or not, is excused from these conditions, its rollover flag included:

- a rollover whose only missing confirmation is the excused member's counts as paused, not under way; the key machine does not promote across that wait, and no step of the reconciliation waits for a rollover paused only on excused members;
- if it was the leader, it is excused only once its lease has run out in each remaining agent's own view, so that its leadership has ended. A leaving leader that is heard and renews its lease but never meets the conditions stalls the zone, safely, at N, until its operator stops it; the status says so;
- for as long as it is unheard, it is also excused from the gate of the group under N, so the group can elect without it. That affects every zone of the group, which is accepted: a member that cannot be heard holds every one of them today. The excusal ends when it is heard again.

The excusal applies during the reconciliation too: a leaving member that has not confirmed a step for the configured time is planned as excused from then on. A provider that is gone must not hold its own removal. The owner must not revoke a leaving provider's access to the zone before "done".

A zone in no group, or whose only voting member is one agent, is thawed by that agent's own word. A zone with no voting member under N is thawed when every voting member under V tells V: nothing under N can act.

The thaw names its serials: from (N, digest) to (V, digest). It travels first hand in the leader's messages, and every member keeps telling the last thaw it heard. An agent makes V active on the first first-hand "active V" it hears from the leader or from a voting member that has made V active, provided it holds V. A member whose active serial is older than the "from" of such a telling, and that holds the newer serial, moves straight to it: the leader plans from what is in place anyway. A member whose active serial is lower than a first-hand "active" telling and that does not hold that serial starts nothing and fetches. Members that do not vote take the thaw from any voting member. So a thaw reaches every member, even when the leader under N stops right after it.

If the leader under N is lost before it thaws, its group elects again and the new leader thaws. A group whose lost leader is not a leaving member stays without a leader until that member is heard again or the owner removes it, as membership 4.3's gate has it: the zone stalls, safely, at N. When V changes the zone's make-up, the zone moves at the thaw to its group under V, and that group's leader carries out the reconciliation. That leader is never a provider that V takes away.

### 3.3 Reconciling

The leader under V carries out what the difference between N and V calls for, starting from what is actually in place, and keeps what it needs to go on after a restart or a change of leader (the leaving providers' nameserver names, its step) on disk. Each step is sent to every member and confirmed. An agent confirms a step only once its combiner and its signer hold the step's sets. What the steps are for each kind of change is section 5.

- **Until the first step, the parts keep the sets they hold.** Nobody leaves or enters a set it holds, for any purpose, until a step of the leader's says so. At the thaw the sets held are N's: a thaw never hands a serial's lists at once. A build that lacks the steps of a kind of change refuses that kind (3.1), so every transition such a build lets through changes no set of 3.5. The sets name each provider by label and identity, fixed when the step that made them was taken. The purposes of 3.5, `nsmgmt` and `parentsync` among them, change only at a step; groups, admission and discovery follow the activation. An agent that restarts during the reconciliation hands its parts nothing new until it has the current step's sets again.
- **No new key rollover starts** until the transition is done. An emergency rollover may start at any time; every DS and DNSKEY step, of an addition or a removal, waits for it, the others do not.
- **Nothing else new starts.** Operator edits are kept, on disk, until "done".
- **A provider whose removal is under way stays a member,** with no role, until its removal is done. Every agent keeps the removal's state on disk, from the leader's first-hand steps, and tells it in its stamp. An agent that missed the end drops it when the leader's first-hand stamp shows the transition done. A leader without the state takes it from the members' stamps.
- **A newer serial during reconciling waits** until the transition under way is done. Agents hold it and tell it as their newest, and nothing of it is agreed or thawed before "done": one transition at a time. An owner who made a mistake publishes the correction; it takes effect after "done". So no later thaw ever lands inside a reconciliation, and a removal is never interrupted.
- **The last step of every transition** is that every voting member's combiner and signer hold V. Members with no role are waited for within their time-out (section 4); excused leaving members are not waited for.
- **Done.** The leader says so, first hand, and every agent's status and the auditor show the zone at V, done. Then each agent drops from its own stores what the active instructions do not entitle any provider to (the sweep), never while the zone is frozen and never towards its peers. A newer serial that waited is then agreed. The agent's own kept changes are handled by V, in order. (The distributions of others that were kept are handled at the activation, rule 6.) The owner can see that the next edit may follow.

### 3.4 After a start

An agent that starts reads its stored serials. It votes, beats, gossips, catches up, and answers and asks for the zone's key, as always. It starts nothing for a zone until it knows the zone's active serial, and keeps what it receives meanwhile (rule 6):

- an agent with a stored record knows it from that record;
- a member with no record takes the leader's word only, first hand: the word of the agent that leads the zone's group under the serial the word names, by the election records it has heard first hand;
- a leader with no record takes the active serial that every voting member with a record tells, when there is at least one and they all agree, the last thaw told breaking a tie; a member that has no record counts as no objection. Otherwise it waits, names who differs, and the status names the forget command as the operator's remedy;
- at the first start after the upgrade, when no record exists anywhere, the zones are placed in groups by their newest copy, and the leader of that group makes active the newest serial every voting member tells, with no rollover or parent condition: nothing is active yet to protect.

A member whose copy is older than the active serial starts nothing and fetches until it holds it. A provider that is new under a serial is in the same position: it may talk, from its newest copy, and starts nothing until it hears the active serial. A member's tellings count only from its last start: it announces each start (membership 5.1).

### 3.5 What the provider's parts do

Today a provider's combiner, its signer and its nameservers each act on the copy of the zone they serve. Under this design they act by what their agent hands them: the active serial, and the current step's sets. These are, for each purpose, the providers that count:

- whose NS records are served;
- whose DNSKEYs are published;
- whose KSKs have a DS, and whose CDS records are published;
- whose confirmations a key's distribution expects;
- who signs;
- whether the zone's KEY and CDS records are published at the providers' `_signal` names.

During a removal the leaving provider leaves these one at a time (5.2). A combiner applies a removal in any origin's name that its own agent delivers: a delete, or a `replace` whose records are a subset of what that origin holds. It judges what it has stored by origin at every combine, not only when it arrives. The agent hands its parts the serial and sets again whenever one of them reports that it has started.

### 3.6 Owner errors and refusals

An owner error (rule 2) holds the zone as agreeing does: nothing new starts, work under way finishes by the active serial. It ends only at a higher serial, never when the contents are reverted at the same serial. A refused transition (3.1) leaves the zone steady at N, unless a serial between N and it is accepted, and an agent never makes active a serial it has refused.

### 3.7 Why it holds

Nobody acts by V until every voting member under N, but an excused leaving member, has told active N and that it agrees on V, first hand. An agent that has told V holds it on disk, and a held serial is never given up: a higher serial wins and a lower one is refused, also across a restart. So once a voting member under N has told V, and its signer has confirmed the hold, it starts nothing more by N except a rollover under way or an emergency rollover, and the thaw waits for both. The forget command (rule 3) is the one exception to never giving a serial up, and it is for a steady zone only. Before the thaw the only agents that can start anything are those that have not seen V, and they all act by the same N. The leader under N has nothing in flight at the parent when it thaws. After the thaw agents act by V, and until the leader's first step their parts keep the sets they hold. A message made under one serial and received under another is caught by its stamp (rule 4) and kept or answered by rule 6. Nothing that changes state is taken from an unauthenticated answer.

Two things follow that the hold of membership 4.9 could not give:

- **No fixed hold.** A make-up can go back and forth, so membership 4.9 had to hear a telling of it again and again, for a fixed time. A serial only goes forward, so the serial a voting member has told stays told: it need not be repeated to stay true. What a telling says of rollovers is not like that: a member may start an emergency rollover after its last telling. So the thaw reads every voting member's latest telling, and counts it only while it is fresh (rule 4). In a fleet whose members are heard, that costs no time; a member that is not heard holds the zone (3.8).
- **The roles of the whole set exchanged in one edit, with the records kept, is covered.** The new side cannot act before the thaw, and the thaw needs every voting member of the old side. Under the owner's order of 3.1 every voting member under V was a member under N and hears the thaw there, and every voting member under N stays a member through its removal. A stuck old member stalls the zone, safely, at N. A gone or stuck leaving member that is not the leader is excused; a heard, stuck leaving leader stalls the zone until it is stopped.

What no rule between agents covers is the owner's own action at the parent and in its own NS RRset:

- After an edit that takes the parent sync over, the owner writes to the parent only after "done" (5.5). On a build where the steps of 5.5 do not exist yet, the edit is refused and the owner must not write to the parent.
- Under `nsmgmt=owner`, the owner drops a leaving provider's NS records from its NS RRset in the edit that takes the provider's server role away. On a build where the steps of 5.2 do not exist yet, that edit is refused, and the owner keeps the provider's NS records in its NS RRset and at the parent.
- Under `nsmgmt=owner` the owner's NS RRset is served by every provider as it comes. It may name a provider's nameservers only once that provider's role transition is done; every agent reports an NS RRset that names the servers of a provider whose role is not done.

### 3.8 What it costs

- After an edit, nothing that a provider makes happens for the zone until the last voting member under N has loaded the edit and its signer has confirmed the hold, a rollover under way has ended (a KSK or algorithm rollover can take DS TTLs), the leader's work at the parent has drained, and the reconciliation's steps are done. A removal holds the zone through the parent's NS TTL and then its DS TTL, which can be days. The status names what holds the zone: a member, a rollover, the parent, a wait and when it ends.
- A voting member that cannot be heard, or that is stuck on an old copy, holds the zone at N for as long, unless it is a leaving member that is not the leader and whose telling has not counted for the configured time. A heard, stuck leaving leader holds the zone until its operator stops it.
- The owner raises the serial at every edit, follows the order of records and roles, does not revoke a leaving provider's access before "done", and waits for "done" before the next edit.

## 4. Members that do not vote

- An auditor confirms at once, whatever serials it holds. It is never waited for in the agreement.
- A member with no role, on its way in or out, is waited for by a distribution with a time-out, as a leaving provider is (5.2). After the time-out the sender goes on; a member with no role cannot hold the zone.

## 5. The kinds of change

The leader orders a transition that changes several things: additions first, then role changes, then removals. When a leaving provider is excused, its NS step comes before any addition's DNSKEY step, and once its NS TTL has passed it leaves the expected confirmations and the paused rollovers resume. A leaving signer that serves nothing, excused or not, has no NS step: nobody is delegated to it, and it leaves the expected confirmations at the reconciliation's first step. An addition starts at the provider's own servers and ends at the parent; a removal starts at the parent and ends at the provider's own servers.

### 5.1 A provider is added, or put back

The owner's order is a rule (3.1): the HSYNC3 record first, a role later, each its own edit and its own transition.

- **The record.** The newcomer is a member with no role: discovery, comms and catch-up run with it, and it changes nothing (membership 1 and 2). The transition is done once the parts hold the new serial. A newcomer whose agent is not running yet holds nothing up. Before the owner gives it a role, the owner checks that it has caught up: every agent's status shows that.
- **A role, as a server.** Its servers must serve its upstream's copy before anything points at them. Its operator sets that transfer up (the asking half of membership decision 6 is not designed), and the step waits until its agent confirms that it receives the zone from its upstream at an SOA serial no lower than the zone's.
- **A role, as a signer.** In order, each confirmed, the DNSKEY and DS steps waiting for an emergency rollover: its signer makes its first keys, which the signer's hold lets it do as a step of the leader's; every signer publishes them; its DS goes to the parent; the caches' time passes; its own signatures are served. The last needs its signer to run its key machine and have its keys published before it serves its own signatures (#160), and its servers to serve its own signer's copy at an SOA serial above the one they served. Until those exist the transition that needs them is refused. Its NS records reach the zone and the parent last, by its operator's choice (membership rule 7).
- **A provider put back** into `servers=` or `signers=` after its records were withdrawn: its own agent sends a complete `replace` of what it contributes, and every agent asks it for the zone's state, as for a peer given its first role (membership 5.1, whose `peer-role` this widens).

### 5.2 A provider's roles are taken away

The owner's order stays: the roles first, the record later. The leader under V runs the removal and needs nothing from the leaving provider. The provider goes on exactly as before and initiates nothing (membership 2.3): its own agent hands its signer "keep signing" until step 4. The leader's first step names the leaving provider's nameserver names: those it told in its stamp, and those the parent's NS RRset holds for it at the removal's start. Every agent keeps them on disk with the removal's state, so that any leader can go on with the removal.

1. The zone's SIG(0) key is rolled (section 6), because the leaving provider holds the private key. The roll is the zone's obligation, not a gate: if it fails, the removal goes on, and the roll is retried on its own schedule until it has succeeded. The status shows it.
2. The leaving provider's NS records leave the zone: withdrawn by the leader under `nsmgmt=agent`, dropped by the owner in its own NS RRset under `nsmgmt=owner` (in the edit that takes the server role away). The step waits until the parent's NS RRset no longer names the leaving provider's nameservers, and counts the NS RRset's TTL from then. When that TTL has passed, the leaving provider leaves a key distribution's expected confirmations; that is part of this step, sent even while the zone is frozen.
3. Waiting for an emergency rollover, the leaving provider leaves the providers whose KSKs have a DS and whose CDS records are published, at every part that counts them; its CDS records are withdrawn, and its DS leaves the parent.
4. After the DS RRset's TTL, waiting for an emergency rollover, its DNSKEYs are withdrawn, and it leaves the providers whose keys are published and who sign: then it stops signing.
5. Its operator is told that the zone is safe to remove.

**The withdrawal.** The leader withdraws another provider's records by an operation of its own: an empty `replace` of one RRtype, which names the provider in a field of its own (the message's sender is the leader). It may only delete. A member applies it when the sender is the zone's leader under the active serial and the active instructions do not list the provider in the list that RRtype depends on: `servers=` for NS records, `signers=` for DNSKEY and CDS records. Its confirmation goes to the leader. Withdrawals and the provider's own operations are ordered by the active serial stamped at their send, then by their creation time.

**Waiting for a leaving provider.** A distribution waits for a leaving provider's confirmation with a time-out (section 4), except a distribution of another signer's new DNSKEY while the leaving provider is still delegated to: resolvers sent to it need that key. After the time-out the leader goes on, and for a CDS or a CSYNC the parent's own check of the nameservers decides.

**The record.** Last, after every cache has expired: a transition of its own, with nothing to carry out. Comms with the provider end after the membership design's hold time.

**The order of the zone's NS RRset and the parent's.** Under `nsmgmt=agent` the zone's NS RRset goes first: the leader's withdrawal at every member; then the leader's explicit sync with the parent; then a watch on the parent until its NS RRset no longer names the leaving provider's nameservers. Under `nsmgmt=owner` the order is the owner's: its edit drops the names from the zone first.

### 5.3 A provider changes roles

- **A server becomes a signer too.** As in 5.1's signer role, with the same preconditions; until they exist the transition is refused.
- **A signer becomes a server only.** Refused (3.1). The owner removes the provider and adds it back.

### 5.4 NS management

A change of `nsmgmt`. To the owner: at the leader's first step each combiner stops applying the agents' NS records, by the sets its agent hands it, each agent drops its own NS records from its data, and catch-up answers carry an empty NS set; the owner's NS RRset is served. To the agents: each provider contributes its NS records again, through its operator. Nothing stored from an earlier time is applied by itself.

### 5.5 Parent sync

A change of `parentsync`.

- **From agent to owner**, in order: every provider withdraws its CDS and CSYNC records, confirmed; their TTL passes; the agents' SIG(0) key is deleted at the parent by an update that key signs, or the owner is told to delete it; every agent stops syncing, its tdns work towards the parent ended (the drain of 3.2); then "done". The owner writes to the parent only after "done".
- **From owner to agent:** the owner stops writing to the parent before it raises the serial. At its first step the leader takes the zone up, as an elected leader takes up every zone of its group: it looks at the parent first and sends only the difference (membership 5.6), and sets up the zone's SIG(0) key.

### 5.6 Other keys

- **An upstream.** The downstream provider's servers move to another signer's chain. The step waits until its agent confirms that it receives the zone from the new upstream at an SOA serial no lower than the one it serves. Until that check exists the transition is refused.
- **`pubkey` and `pubcds`.** A step publishes or withdraws the zone's KEY, or its CDS, at the providers' `_signal` names. The providers' nameservers take this from their agent, not from their own copy.
- **The auditors**, and `suffix`, which decides nothing today: a transition with nothing to carry out.

## 6. The zone's SIG(0) key

The rules of membership 4.1 for the key stand as written there, now under this design. A voting member asks for a key it does not hold; during a transition it asks every voting member under both serials. The key is the group's, published by the leader. When a voting member leaves, the key is rolled, first in the removal and as the zone's obligation (5.2). A new key is made only when every voting member has answered that it holds none, and a parent judges a bootstrap by what it finds (tdns #917). The zone's key is set up only by the leader's key set-up; tdns's own set-up path makes no key for a multi-provider zone.

- A zone whose apex publishes several KEYs has no zone key: nothing is imported, retired or made, no sync that needs the key is asked for, and the status tells the operator to leave one. Nothing picks one for the operator.
- A leader whose zone key the parent refuses (BADKEY, and a re-bootstrap the parent refuses) takes no action of its own: the syncs that need the key stay held, and the status says that the parent refuses the zone's key. It stays so until tdns parents judge a bootstrap by what they find (tdns #917), when the recovery below applies.
- The key's offers and its bootstrap are held during a transition like every other change, except as a step of the reconciliation (5.2 step 1, 5.5) and while a rollover under way waits for the parent to trust a key just made (3.1).
- The recovery of a lost key (a new KEY published beside one that nobody holds, then bootstrapped, then the old one deleted) is a leader action of its own. It starts only in a steady zone, is held during a transition, and is built once tdns parents judge a bootstrap by what they find.

## 7. Not part of this design

- **What the parent's scan does** with a nameserver that lacks a record, or does not answer. It decides the outcome after the time-out of 5.2.
- **The timing and the operator's view of removing a provider that does not cooperate.** The leader's withdrawal does not depend on the provider, and a gone or stuck leaving member is excused from the thaw, so the mechanism serves that case.
- **Who answered a beat.** Over HTTPS the transport now checks it against the peer's TLSA record (tdns-mp #242 and #246); over DNS it does not yet refuse an answer without the payload envelope. Answers count for nothing either way (rule 4).
- **The transfer set-up asked for by a member itself** (the asking half of membership decision 6). Today the operator sets it up, and the steps of 5.1 and 5.6 wait for its agent's confirmation.
- **The end of multi-provider service.** The owner reduces the zone to one provider by transitions, and then removes its HSYNC3 and HSYNCPARAM records. With one provider nothing needs agreeing.
- **A transition the owner asks to be rolled back** other than by a new, higher serial.
- **The meaning of the HSYNC3 state field,** beyond OFF being no member.
