# Changes to the zone owner's instructions: implementation plan

**Status:** PLAN, 2026-10-18, for revision 6 of the design (2026-10-26). Section 5 holds the status of each step (refreshed 2026-10-27, against tdns-mp main `d2cc1d8`): P1’s key and membership’s ground are done on main; S1 is merged (tdns-mp #280, main `3c9f6d7`, 2026-10-27); S2 is built (#281); P3 is built (2026-10-28); S3–S22 and the remaining P steps are not started. Revised 2026-10-26 for revision 6: an external review of revision 5 (2026-10-24) and the project owner's answers to it (decisions 94 to 102). An external re-review of revision 6 (2026-10-27) found it ready to merge and S1 and S2 ready to build; its notes for them are in S1, S2, S3 and P2. From 2026-10-27, at the project owner's word, it says "serial" where it said "version", as the design does; proposed names follow (`MPActingSerial`, `CompareSerials`).

This is the plan for the design in `2026-10-18-owner-instruction-transitions-design.md`, revision 6 ("the design" below; its sections are named "design N"). The design describes how a change of the zone owner's HSYNC3 or HSYNCPARAM records is numbered, agreed and carried out, as it is meant to stand. This document holds what is dated: what exists, what is wrong today, where each rule lands in the code, the steps, and the decisions the design rests on.

It follows the membership plan, `2026-10-12-membership-and-catch-up-plan.md` ("the membership plan"). Its steps 1 to 8 are implemented first and are this plan's ground. Its steps 9, 9b and 10, marked moved there, are this plan's starting material: they are taken up in S6 to S9, S14, S15 and S22, but for the part of step 9's key that membership step 7b builds since 2026-10-19 (membership decision 46).

**The membership plan's decisions of 2026-10-19** (the project owner's answers to its 13 open questions) that touch this plan: the removal of a provider is this plan's (membership decision 40; S12, S16, S17b); membership step 6 takes nothing but the rows from a beat's answer (membership decision 35; S5a); no catch-up answer names the zone's KEY until S14 (membership decision 27); every voting member holds the zone's key from membership step 7b, before step 8, and no key is made on either path while the zone publishes one (membership decision 46, which replaces decision 32; S14 keeps only what this design adds); until the switch, step 7's gate asks for a role as admission does (membership decision 31; S15); an agent with no vote in a zone leads it no more (membership decision 34; S15). From the external review of the membership plan, the same day: a SYNC carries its distribution ID in the payload, so that a SYNC's confirmation over HTTPS reaches its sender, in a small pull request before membership step 3 (membership decision 41; S5b's confirmations rely on it); and a provider in `servers=` or `signers=` does not move to `auditors=`: it is removed and added back as an auditor, and nothing looks for that edit (membership decision 45). This plan does not cover that move: the judge refuses it as a kind of change with no steps (S4), with nothing written for it. This plan's own decisions keep their numbers; "decision N" alone is this plan's.

**Base.** Refreshed 2026-10-27: tdns-mp main at `d2cc1d8` (2026-10-27), which pins every tdns module at `c3c2a48d` (with #928, #926, #951 and #952) and tdns-transport at `860bae6`; membership steps 1 to 8 and 7b are merged, and so is the part of the mop-up between the two projects (tdns-mp #267) that has landed (7.1). The citations of sections 1 to 5 were read at `ec1c6b3` (2026-10-18), before the membership work landed, and are not re-read here: each step re-reads them on the day it starts, against main as it is then. The external review of revision 5 counted about 133 call sites in `v2/` that touch the HSYNC3 and HSYNCPARAM accessors at `5209e32`; S3 re-counts them on the day.

Nothing was built or run for this document. Every statement about the code is a reading: six readings of revision 1 of the design, each of one area, and an adversarial reading, whose findings revision 2 took; then three critics' readings of revision 2 and of this plan (an adversary, an implementer and a consistency reading), whose findings revision 3 took; then a check of revision 3 and of this plan, two readings, whose findings revision 4 took; then a check of revision 4, whose findings revision 5 and this revision of the plan take. Where a reading could not settle a point, the text says "not established". What a step reads of the code is to be read once more on the day that step starts.

## 1. What exists, and what is new

**Exists, and is used as it is:**

- A change detector. `HsyncChanged` compares the old and new HSYNC3 and HSYNCPARAM RRsets by packed RDATA (`ec1c6b3:v2/hsync_utils.go:32-117`) in every role (`:1328-1342`), and `PostRefresh` routes a change to `ApplyHsyncDiff` and the groups (`:1562-1602`).
- Groups from the zone's records: `zoneParticipants` and `RecomputeGroups` (`ec1c6b3:v2/provider_groups.go:82-144, 212-296`); membership step 8 keys them on the make-up.
- A group election when a group becomes operational, whatever the zones' `parentsync` (`ec1c6b3:v2/hsync_bridge.go:274-304`). The per-zone election at a first load runs only with `parentsync=agent` (`v2/start_agent.go:228-247`).
- Gossip rows per group, merged by timestamp (`ec1c6b3:v2/hsync/gossip.go:14-32`; `v2/gossip.go:175-232, 235-327`). tdns-transport carries a beat's gossip as opaque JSON (`f76a204:v2/transport/transport.go:110`).
- A pattern for fields of tdns-mp's own on a payload of tdns's: `keystateWirePayload` (`ec1c6b3:v2/mp_send.go:78-81`), and membership step 3's wrapper around `core.AgentMsgPost` for `catch_up`.
- The confirmed queue hands its entry to the send function at every attempt (`f76a204:v2/transport/reliable_message_queue.go:478-489`), and tdns-mp builds the payload there (`ec1c6b3:v2/hsync_transport.go:1906-1950`). So a message can be stamped when it is sent.
- The key machine's order for a new signer: keys applied by every other signer before they are published, a KSK's DS before it signs (`ec1c6b3:v2/mp_key_lifecycle.go:268-305, 328-339`). It does not promote a key while another signer's "applied" is missing (`:209-218`).
- The combiner stores contributions per origin and RRtype (`ec1c6b3:v2/combiner_utils.go:887`) and merges them per origin in `RebuildCombinerData` (`:1113-1144`).
- The combiner publishes the zone's KEY at the `_signal` names of a provider's nameservers when the agent's publish instruction says `at-ns` (`ec1c6b3:v2/combiner_chunk.go:581-603`; `v2/agent_publish_locations.go:20-28`).
- A rule "from the leader only": `refuseCsyncNotFromLeader` (`ec1c6b3:v2/mp_s5_leader_csync.go:434`).
- tdns's work towards the parent stops on its caller's context: the UPDATE retries and the BADKEY re-bootstrap (tdns `3615261f:v2/delsync_retry.go:33-58, 86`), and the key poll (`v2/parentsync_bootstrap.go:30`).
- From membership steps 1 to 8: the standing of a member, the complete answer and the own read (step 3), the catch-up tracker (step 4), the leader's hold until caught up (step 5), the rule for every message's sender (step 6), the end of comms (step 7), groups by make-up and `zoneChanged` (step 8).

**New:**

1. The owner's serial in HSYNCPARAM, one canonical reading of the instructions, and its digest (design rules 1 and 2).
2. Serials per zone on disk at the agent: the active serial, the serial it was thawed from, the newer serials held, the last thaw, the phase, the step and its sets, and the removals under way with the leaving providers' NS names. The serial and the step's sets handed to the combiner and the signer, on disk at each (rule 3).
3. A stamp on every message and in beats, taken first hand only; nothing that changes state taken from an answer (rule 4).
4. One accessor for the active instructions; the combiner, the signer and the provider's nameservers take what they need from their agent (rule 5).
5. The rule for a message made under one serial and received under another (rule 6).
6. The phases: the freeze, the thaw with its excused leaving members, the reconciliation and "done"; the restart rule (design 3).
7. The steps of each kind of change (design 5), with the leader's withdrawal and the leader's roll of the zone's SIG(0) key.
8. The zone's SIG(0) key under a transition (what membership step 7b leaves of it: the holds, `keyPending`, the KEY as the group's), the switch that makes every HSYNC3 provider a member, and the listing by interest (moved from the membership plan).

No message type and no verb are added. Added on the wire, all in tdns-mp's own payloads:

- a stamp field on the sync-family, CONFIG, EDITS and AUDIT payloads (S5b);
- a gossip entry for stamps, whose one row also carries the provider's nameserver names (S5a), and in the stamp the step and its sets, and the removals under way the sender holds with the step it holds (S12);
- an RFI subtype, proposed `instructions`, for a serial's instructions by (serial, digest) (S7);
- a withdrawal field on the sync wrapper (S16);
- a hand-over object to the combiner, with a `refresh` flag (S10);
- KEYSTATE signals `hold` (S6) and `acting`, with a `refresh` field (S11);
- in the signer's inventory: a `hold` field (S6); the rollover predicate, the missing confirmers per key, and marks for "not signing" and "nothing handed" (S11);
- a "kept" PENDING copied to the auditors (S8).

One field on tdns-transport's confirmation (P2). Two new config keys (S7, S12); S5a and S18a read one that exists.

## 2. What is wrong today

Each part of a provider acts on its own copy of the zone the moment it loads it. The combiner and the signer load an owner's edit before their agent does: the signer pulls from the combiner and the agent from the signer (`ec1c6b3:v2/cli/configure/templates/mpsigner.yaml.tmpl:107-114`, `mpagent.yaml.tmpl:167-168`). The provider's own nameservers, when they run tdns-auth with `use-hsyncparam`, publish and withdraw the zone's KEY and CDS at `_signal` names by `pubkey` and `pubcds` in their own copy (tdns `3615261f:v2/signal_republish.go:64-80, 379-392`; `v2/signal_withdraw.go:198`). Nothing numbers the instructions: HSYNCPARAM has keys 0 to 7 (tdns `3615261f:v2/core/rr_hsyncparam.go:56-65`), and nothing keeps a serial per zone (`ec1c6b3:v2/mp_extension.go:68-97`; no table in `v2/db_schema_hsync.go`). Readers take the first HSYNCPARAM record (`ec1c6b3:v2/provider_groups.go:61`, `v2/agent_policy.go:183`). For HSYNC3, `zoneParticipants` keeps the last ON record per label and skips OFF records (`ec1c6b3:v2/provider_groups.go:92-104`), while `matchHsyncIdentity` takes the first record whose identity matches and never tests the state (`v2/hsync_utils.go:929-941`): an OFF record of the local identity gives a label there. tdns reads `parentsync` from its own copy (tdns `3615261f:v2/parentsync_bootstrap.go:445-472`, called at `:53`). The answer to a beat is not authenticated (`ec1c6b3:v2/hsync_transport.go:292`; tdns-transport `f76a204:v2/transport/dns.go:706-714`), and its gossip is merged, election records included (`ec1c6b3:v2/hsync_transport.go:1801-1817`; `v2/gossip.go:199-211`).

Issue #200 lists the faults found that way: nine items, of which item 1 is a plain bug (PR #209, and tdns #926 for its tdns half) and the others need this design. Items 2 and 3 are closed by S11 and S13, item 4 by S13, items 5 and 6 by S4, item 7 by S19, item 8 by S18a, item 9 by S18b, S21 and 7.3 item 12. A reading of 2026-10-17, kept with the project's reviews, checked them against the code: about 52 sites in 14 files decide from a copy of HSYNC3 or HSYNCPARAM. They are not repeated here. The membership plan's settle rule (its step 9) was never built; S6 to S9 replace it.

## 3. The design in the code

| Design | In the code | Step |
|---|---|---|
| Rule 1: the owner's serial, 32 bits, RFC 1982 | tdns core: key 8; tdns-mp: `CompareSerial` | P1, S1 |
| Rule 2: one canonical reading, its digest; HSYNCPARAM present or not | `ReadInstructions`, `Digest`, `HasParam` (new `v2/instructions.go`); `HsyncChanged` compares serials | S1, S3 |
| Rule 2: records compared by label and identity | `CompareSerials`; the judge | S1, S4 |
| Rule 2: two HSYNCPARAM records, two records with one label | `ReadInstructions` returns the owner error | S1 |
| Rule 2: one serial, two digests, between voting members only | At the agent's own copy, the store's conflict mark; between agents, the stamps of voting members | S2, S5a |
| Rule 2: HSYNCPARAM dropped, or both dropped with more than one provider; a lower serial; serial 0 | The store's `Note` | S2, S4 |
| Rule 3: serials per zone on disk: active, from, newer held, highest, last thaw, phase, step and its sets; the removals under way | `MPZoneInstructions`, `MPZoneRemovals`, `v2/instructions_store.go` | S2, S7, S12, S17b |
| Rule 3: the parts keep what they were handed | `MPActingSerial` at the combiner and the signer | S10, S11 |
| Rule 3: the forget command, the one exception to never giving a serial up; a zone that leaves the configuration | The store | S2 |
| Rule 3: the active serial changes at the leader's word, a voting member's first-hand relay of it, or, for a zone with no voting member under N, the tellings of every voting member under V | `Activate`, called by the thaw | S7 |
| Rule 4: stamps in beats: active, newest, last thaw, refusal, rollover; the provider's nameserver names; the removals under way held, with the step held | A gossip entry outside the groups | S5a, S12 |
| Rule 4: a beat lists the zones with something to do | The stamp entry's zones | S22 (S5a lists more) |
| Rule 4: stamps on SYNC, RFI, CONFIG and confirmations | The payload wrappers; tdns-transport's confirmation | S5b, P2, S10 |
| Rule 4: nothing that changes state is taken from an answer; an answer's gossip is shown only | Stamps, election records and terms from messages only | S5a, S5b |
| Rule 4: payload encryption on, or no thaw | The stamp; `thawReady` | S5a, S7 |
| Rule 4: a telling counts for the thaw only while fresh, heard within the configured time | `thawReady` | S7 |
| Rule 5: one accessor; a test that fails on a direct read | `instructionsFor`, `readingOf`, `rolesFor`; a source gate | S3 |
| Rule 5: membership steps 4 and 8 at activation and at every first load, not at a refresh | `onActiveChanged` | S3, S9 |
| Rule 5, 3.3: groups, admission and discovery follow the activation; the purposes of 3.5, `nsmgmt` and `parentsync` among them, change only at a step | The active reading for the first; `rolesFor` and `onSetsChanged` for the rest | S3, S12 |
| Rule 5: code in tdns that the agent calls | A hook in tdns for `parentsync`; the `DELEGATION-SYNC-SETUP` arm, which does nothing for a multi-provider zone | P3, S3; the arm, membership step 7b |
| Rule 5: the provider's nameservers | Their reconciler off for a multi-provider zone; the `_signal` step | P6, S21 |
| Rule 5: the combiner and the signer take what they need from their agent | The hand-over | S10, S11, S13 |
| Rule 5: a part never handed anything: by its copy without a serial; asks first with one | "Provisional"; the start report | S10, S11 |
| Rule 6: a confirmation is always taken; an answer stamped with an active serial other than its send's is "not yet"; sent again once in step, at once if already | `ProcessDnskeyConfirmation`, `outcome` | S8 |
| Rule 6: a request is answered whatever its stamp | The RFI and CONFIG paths | S8 |
| Rule 6: stamped when sent | `deliverGenericMessage` | S5b |
| Rule 6: lower is "made under older instructions"; higher, or the active serial not known, is kept | `instrReceive`, the kept list | S8, S9 (list: S6) |
| Rule 6: the leader's withdrawals too | `acceptWithdrawal` | S16 |
| 3 Every group with two or more voting members elects | The first-load gate | S7 |
| 3.1 Agreeing begins; the fetch down the chain, paced | The store; the fetch | S2, S5a, S10, S11 |
| 3.1 Nothing new starts; kept on disk, in order, apart from what catch-up answers read; the operator is told | `zoneFrozen`, the owed list, `syncHeld` | S6 |
| 3.1 No new rollover: the signer is told, and its hold confirmed before a telling counts | KEYSTATE `hold`; the inventory | S6, S7, S11 |
| 3.1 Work under way finishes, every phase; key offers while a rollover waits on `keyPending`; a rollover's sync carries the delegation by the sets the parts hold | One predicate; the exemptions; the readers of the sets | S3, S5a, S6, S11, S14 |
| 3.1 An emergency rollover may start, not at a provider with no role under N or under the serial agreed | The operator's `signer key rollover` | S6 |
| 3.1 What is not held | Catch-up, CONFIG, the key's requests pass | S6 |
| 3.1 An unsafe transition is refused and told; the zone stays steady | `judgeTransition(from, to)`; the stamp | S4, S5a |
| 3.1 A member that moves straight judges the thaw's own pair, the from-serial fetched if it lacks it | The judge; the RFI `instructions` | S4, S7 |
| 3.1 A record removed while its provider's removal is not done is agreed; the provider keeps the last identity listed | Not a refusal; the members' set | S4, S15 |
| 3.1 A newer serial during agreeing | The thaw's target | S7 |
| 3.2 The thaw: active N and agreeing V from every voting member, the leader included, first hand and fresh, no refusal, the signer's hold; no rollover; nothing at the parent | `thawReady` | S7 |
| 3.2 The leader's parent work drains; at every hand-over and invalidation | `v2/parent_work.go` | S7 |
| 3.2 An excused leaving member: a telling that has not counted for the configured time from when this agent first holds V; its flag; paused rollovers; a leader after its lease in each agent's own view, a heard stuck one stalls; the gate while unheard; during the reconciliation, a leaving member that has not confirmed a step for the configured time is planned as excused | The thaw, the gate, the inventory, the planner | S7, S11, S12 |
| 3.2 No group, one voting member, no voting member under N | `thawReady` | S7 |
| 3.2 The thaw names its serials; relayed; a member behind moves straight; one without the serial fetches | The stamp's `thaw`; `Activate` | S2, S7 |
| 3.2 The leader lost: re-elected without an excused leaving leader; a lost leader that is not leaving stalls its group (membership 4.3); the zone moves to its group under V | Membership step 8; `onActiveChanged` | S7 |
| 3.3 Each step sent and confirmed once the parts hold it; the step and its sets on disk | The step machine; the step in the stamp | S12, S13 |
| 3.3 Until the first step, the parts keep N's sets; a restarted agent hands nothing new | Step 0; `rolesFor(from, to, step)` | S2, S3, S12 |
| 3.3 The sets name each provider by label and identity, fixed when the step that made them was taken; every label resolver resolves a provider whose removal is under way through the removal's stored identity | `rolesFor`'s pairs; the resolvers | S3, S10, S11, S15 |
| 3.3 No new rollover until done; every DS and DNSKEY step waits for an emergency one | The hold; the planner | S6, S12, S17b, S18b, S20 |
| 3.3 A provider whose removal is under way stays a member until its removal is done; its state and NS names on disk at every agent, from the leader's steps, told in every member's stamp with the step held; dropped on the leader's "done"; a leader without it takes it from the members' stamps | The members' set; the removals on disk; the stamp | S2, S12, S15, S17b |
| 3.3 A newer serial during reconciling waits until "done", held and told as newest; then it is agreed | The store holds it; `thawReady` needs the transition done | S2, S7, S12 |
| 3.3 The last step; excused members not waited for; "done" | The step machine | S12 |
| 3.3 The sweep at "done", never while frozen, never towards peers | `v2/entitlement.go` | S17b |
| 3.3 Others' kept distributions at the activation; own kept changes at "done", in order | The two releases | S6, S8 |
| 3.4 After a start: the own record; a member: the leader's word; a leader: what every voting member with a record tells, else the forget remedy named; the first start after the upgrade | `activeKnown` | S9 |
| 3.4 Kept meanwhile, catch-up answers included | `Arrived` | S9 |
| 3.5 The parts act by what their agent hands, per purpose | The hand-over carries the step's sets | S10, S11, S13, S21 |
| 3.5 The combiner applies a removal in any origin's name; judges stored contributions at every combine | `RebuildCombinerData`, `checkDNSKEYPolicy`; membership step 6's rule relaxed | S10, S16 |
| 3.5 The agent hands again when a part reports a start | The tracker | S10, S11 |
| 3.6 An owner error holds; a refusal leaves the zone steady and is never activated | The store's phase | S4, S6, S7 |
| 3.7 The owner writes to the parent only after "done"; on an interim build the edit is refused | The guide | S4, S20, P4 |
| 3.7 An owner's NS RRset that names a provider not done is reported | The stamp row's nameserver names | S5a, S19 |
| 3.8 The status names what holds the zone | The status lines | S6, S7, S12 |
| 4 An auditor confirms at once | Unchanged; exempt from rule 6 | S8 |
| 4 A member with no role is waited for with a time-out | The awaited sets split | S12 |
| 5 Additions, then role changes, then removals; an excused leaver's NS step first; every leaving signer that serves nothing, excused or not, leaves the confirmers at the first step; no step waits for a rollover paused only on excused members | The planner; the sets | S12, S13, S17b |
| 5.1 The record | Nothing to carry out | S12, S15, S18a |
| 5.1 A server role | The transfer confirmation | S18a |
| 5.1 A signer role; its first keys under the hold | Refused until it can be carried out; the hold's exemption | S4; S18b with P5 |
| 5.1 A provider put back | Its complete `replace`; `peer-role` widened | S3, S18a |
| 5.2 The leaving NS names, from its stamp and the parent's NS RRset at the removal's start, named in the leader's first step and kept at every agent; the five steps; under `nsmgmt=owner` the owner drops the names; the CDS at the DS step | The runner | S17b; the roll S17a |
| 5.2 The withdrawal; ordered by the stamp at send, then the creation time | `withdraw` on the sync wrapper | S16 |
| 5.2 Waiting for a leaving provider; the expected confirmers after the NS TTL, counted from when the parent no longer names the names, as part of the NS step and sent while frozen | The time-out and its one exception; the fifth set | S12, S13, S17b |
| 5.2 The record last | Nothing to carry out; comms end as membership step 7 has it | S12 |
| 5.3 A server becomes a signer | Refused until it can be carried out | S4; S18b with P5 |
| 5.3 A signer becomes a server only | Refused | S4 |
| 5.4 NS management | The runner | S19 |
| 5.5 Parent sync | The runner; PR #209 reworked | S20 |
| 5.6 An upstream | The runner | S21 |
| 5.6 `pubkey` and `pubcds` | The `_signal` step; the nameservers' reconciler off | S21, P6 |
| 5.6 The auditors, `suffix` | Nothing to carry out | S7 |
| 6 Every voting member holds the zone's SIG(0) key; a new one only when every agent asked holds none and the zone publishes none; tdns's set-up makes no key for a multi-provider zone | `zoneKeyHeld`, `keyCheck`, `keyWanted`, `leaderKeySetup`, the `DELEGATION-SYNC-SETUP` arm | Membership step 7b |
| 6 The key under a transition: asked of the voting members under both serials, an answer counts at the asker's active serial; the KEY taken from the leader only; only the leader's catch-up answer names the KEY, from its keystore | What membership step 7b leaves of the moved step 9's key part | S14 |
| 6 Offers held, except as a step and while a rollover waits on `keyPending` | `syncHeld` | S6, S14 |
| 6 The roll when a voting member leaves | `leaderRollZoneKey` | S17a |
| 6 The recovery of a lost key | After this plan | 7.4 |

## 4. Agents in step

tdns-mp does not support agents that are out of step with each other: all agents of a zone run the same rules. This plan has no code for a peer of an earlier build. A peer that sends no stamp tells no serial, so nobody thaws: it shows as a stall, not as harm.

Every step goes to all agents of a zone together, and to every part it changes or its fleet check runs on. Rebuilt from each step's Changes and its Fleet line:

- **The agent:** every step from S1.
- **The combiner:** S1, S3, S10, S12, S13, S16, S17a, S17b, S19, S20, S21.
- **The signer:** S1, S3, S6, S11, S12, S13, S17b, S18b, S20.
- **The auditor:** S1, S2, S3, S4, S5a, S5b, S7, S8, S9, S12, S15, S22.
- **The provider's nameservers:** P6, when they run tdns-auth with `use-hsyncparam`, before S7. The owner's primary: P1, when it is tdns-auth.

S12 changes no code at the combiner or the signer, and S17b none at the signer: their checks run there, on the builds of S10, S11 and S13.

**The order of upgrade.**

1. The serial key (P1) is in tdns's core module and pinned (S1). The owner's primary, when it is tdns-auth, runs a build with it: an older tdns refuses the key name in a zone file. Over the wire an older part keeps key 8 as an unknown key and passes it on (tdns `3615261f:v2/core/rr_hsyncparam.go:34-36`).
2. The owner's tools (P4) put `serial` in every zone that is to change its providers, and raise it at every edit, before S7 reaches a fleet. From S7 on, a change at serial 0 is an owner error and holds the zone (S4).
3. S1 to S6 change nothing for a zone at rest and can go out one at a time. Until S7 the active serial follows the copy, refused copies included: S4 shows a refusal and does not enforce it. S10 and S11 are on a fleet before S7: without them the parts act by their own copy, as today. Their fleet checks that need a refused serial to stay unhanded run with S7. P6 is on the providers' nameservers before S7 too: from S7 the judge refuses a change of `pubkey` or `pubcds`, and without P6 the nameservers would act on it from their own copy. S7, S8 and S9 go out together: S7 without S8 takes a message made under N after the thaw to V, and S7 without S9 lets a restarted agent act by a record that nobody confirmed.
4. **The first start after the upgrade to S7.** Records written by S2 to S6 followed the copy, not the leader. S2 marks them not enforced, and S9 counts them as no record. So at the first start every voting member tells its newest serial, and the leader makes the newest serial that every voting member tells active, with no rollover or parent condition (design 3.4). The owner makes no edit while the fleet is upgraded.
5. **Interim builds.** From S7, until a kind of change has its steps (S16 to S21), the judge refuses it (S4, decision 29). A fleet on an interim build from S7 is safe, and cannot change its providers. A change of `pubkey` or `pubcds` is refused until S21, and with P6 the providers' nameservers do not act on it. A change of `parentsync` is refused until S20: PR #209's switch does not act on it in that stretch, the agents go on syncing, and the owner must not write to the parent (design 3.7; the guide, S4; P4).

Two rules for operators, as in the membership plan: every step goes to all agents of a zone together; and every agent runs every step through S21 before the owner starts a provider change in the zone.

## 5. The steps

Each step is one pull request. Each is safe to merge once what its "Needs first" column names is in, and changes nothing for a zone at rest except what the step names. The P steps are outside tdns-mp and come first.

The sizes are estimates from reading the code, tests apart: files touched, and lines new and changed. They are an order of magnitude, not a count. They are de-duplicated: where two readings proposed the same change, it is counted once, in the step that makes it.

**Status column (2026-10-27).** Checked against tdns-mp `main` @ `d2cc1d8` and the pins in §7.1. Membership steps 1–8 and 7b are on main and are no longer listed under "Needs first". P1’s key (#928) and #926 are in the pin; the draft’s assignment of key 8 is still open. Of S1–S22, S1 is merged (#280) and S2 is built (#281); nothing else is implemented. Since 2026-10-24 the mop-up of tdns-mp #267 has merged #269, #271, #272, #274, #275 and #263, and has tdns-mp #270, #278 and #279 and tdns-transport #41, #42 (a design) and #43 open. What touches a step is in its row and in 7.1.

| Step | What | Needs first | Files | New | Changed | Status |
|---|---|---|---|---|---|---|
| P1 | tdns: the HSYNCPARAM `serial` key; the draft's number | The draft's number (key shipped as 8) | tdns: 1 | 60 | 10 | **Done in tdns** (#928, #929 in pin). Draft PR #3 still open. |
| P2 | tdns-transport: an application field on confirmations | Nothing | tdns-transport: 5 | 45 | 25 | Not started. After tdns-transport #41 and #43, which change the queue and the confirmation path |
| P3 | tdns: `parentsync` asked of the application; tdns #926 | Nothing (#926 done) | tdns: 2 | 20 | 10 | **#926 done.** The hook is built (2026-10-28, tdns branch `claude/211-p3-parentsync-hook`); its pull request follows. tdns-mp sets it in S3 |
| P4 | The owner's tools raise the serial | P1 at the owner's primary (key available) | Outside the repositories | - | - | Not started |
| P5 | tdns: keys published before a signer serves its signatures (#160); a policy bound when signing starts (#146) | Nothing | tdns: not established | - | - | Not started (#160, #146 open) |
| P6 | tdns: the provider's nameservers stop reading `pubkey` and `pubcds` from their copy of a multi-provider zone; on them before S7 | Nothing | tdns: 2 | 30 | 10 | Not started. Its open questions are answered (2026-10-28, below); the project owner decides three points; built by another session |
| S1 | The canonical reading and its digest | P1's key on the pin (#209 done) | 8 | 240 | 30 | **Done**: merged as #280 (main `3c9f6d7`, 2026-10-27). Golden digest `d7294061a3f8f5af` |
| S2 | Serials per zone on disk, shown | S1 (membership 1–8 done) | 16 | 365 | 85 | **Built** (2026-10-27): #281, which carries this cell. Active follows the copy, "not enforced" |
| S3 | One accessor; the hooks at activation and at a first load; the gate test; tdns/v2 re-pinned | S2; P3 (#185, #186, #208, #916/#933 done) | 30 | 345 | 450 | Not started. Also moves #275's signing-set reader (S3) |
| S4 | Owner errors and refused transitions | S3 | 9 | 245 | 60 | Not started |
| S5a | Stamps in beats; each member's serial; the fetch; nothing taken from an answer | S2, S4 (membership step 6 done) | 15 | 530 | 140 | Not started |
| S5b | Stamps on messages and confirmations | S5a; P2 (membership step 3 done) | 8 | 190 | 85 | Not started |
| S6 | The freeze | S4, S5b (membership steps 3 and 5 done) | 17 | 605 | 140 | Not started |
| S7 | The thaw | S6; S10 and S11 on the fleet first; P6 at the providers' nameservers; out with S8 and S9 | 19 | 815 | 145 | Not started |
| S8 | Messages between serials | S7; PR #169's copy to the auditors (still draft) | 10 | 440 | 105 | Not started |
| S9 | The restart rule | S8 (membership step 4 done) | 9 | 325 | 65 | Not started |
| S10 | One reader at the combiner | S3 (#208 and membership step 3 done) | 18 | 580 | 180 | Not started |
| S11 | One reader at the signer | S10, S6 | 16 | 430 | 150 | Not started. With S13, replaces #275's pause |
| S12 | The reconciliation core | S9, S10, S11 | 13 | 545 | 105 | Not started |
| S13 | Steps reach the parts; the DS set follows the step | S12 (#208 done) | 11 | 305 | 130 | Not started. With S11, replaces #275 (the interim for #147) |
| S14 | The zone's SIG(0) key: what membership step 7b leaves | S8, S9 (membership 4–7b done) | 7 | 120 | 45 | Not started |
| S15 | The switch: every HSYNC3 provider is a member | S12, S14 | 10 | 140 | 165 | Not started |
| S16 | The leader's withdrawal | S8, S10, S15 | 12 | 265 | 125 | Not started |
| S17a | The leader's roll of the zone's SIG(0) key | S7, S14, S16 | 8 | 270 | 70 | Not started |
| S17b | The removal, and the sweep | S13, S15, S16, S17a | 14 | 675 | 130 | Not started |
| S18a | A record, a server role, a provider put back | S13, S15, S16 | 6 | 190 | 40 | Not started |
| S18b | A signer added; a server becomes a signer | S18a, S11, S12; P5 | 6 | 290 | 75 | Not started |
| S19 | NS management | S5a, S10, S12 | 5 | 130 | 40 | Not started |
| S20 | Parent sync | S12, S14, S17a; P3 (#209 done) | 7 | 220 | 60 | Not started |
| S21 | An upstream; `pubkey` and `pubcds` | S18a, S12; P6 (#167 done) | 7 | 170 | 40 | Not started |
| S22 | Tellings by interest | S5a, S12 (membership step 8 done) | 5 | 90 | 60 | Not started |

**Totals.** S1 to S22, in tdns-mp: about 8,520 new and 2,720 changed lines, in 25 pull requests, or 26 if S7's parent work goes first as a pull request of its own. Of that, the core (S1 to S9) is about 4,100 new and 1,305 changed; the parts (S10 to S13) about 1,860 and 565; the key, the switch and the kinds of change (S14 to S22) about 2,560 and 850. P1 to P3 and P6, in tdns and tdns-transport: about 155 new and 55 changed. Tests: two to three times the 11,240 lines of code, so about 22,500 to 33,700 lines. Membership decision 46 (2026-10-19) moved about 155 new and 45 changed lines of S14 into membership step 7b; they are counted there, not here.

For comparison: the membership plan sized its steps 9, 9b and 10 at about 1,100 new and 470 changed lines. They hold here, larger, as S6 to S9, S14, S15 and S22, less the part of step 9's key that membership step 7b took (about 155 new and 45 changed lines of S14). The revision of this plan for revision 4 came to about 8,555 new and 2,740 changed. Revision 5 adds about 120 and 25. It adds the sets by label and identity and their resolvers (S3), the fresh telling and the thaw of a done zone only (S7), the removals in every member's stamp, the leader that takes them from there, and the excusal during the reconciliation (S12), the leaving NS names from the stamp and the parent and the removal under `nsmgmt=owner` (S17b), and the leader's KEY from its keystore (S14). It removes what an interrupted reconciliation needed (S2, S12, S16, S17b).

**Why this order, and the splits.**

- S5 is two steps. The stamp in beats needs nothing outside tdns-mp. The stamp on a confirmation needs P2 and a new pin of tdns-transport.
- S10 needs S3; S11 needs S10 and S6. They can be built beside S5a to S9. Both are on a fleet before S7, and S7 needs S11's inventory to tell a paused rollover from one under way.
- P6 is on the providers' nameservers before S7. From S7 nobody may act on a refused serial (design 3.1), and without P6 the nameservers act on a refused change of `pubkey` or `pubcds` from their own copy.
- The reconciliation core (S12) comes before the hand-over of each step's sets (S13). The core's last step, "the parts hold V", needs only S10 and S11; the per-purpose sets of a step need the steps to exist.
- The zone's SIG(0) key (S14) and the switch (S15) come before the withdrawal and the removal. The removal starts with the roll of the key, which builds on membership step 7b (every voting member holds the key, one active key per zone) and on S14 (the KEY as the group's). And a provider whose roles are taken away must stay a member, with no role, to apply the withdrawal of its own records and to follow the steps: before the switch it is no member at all (`ec1c6b3:v2/provider_groups.go:82-144` returns role holders only), and nothing reaches it after the thaw.
- The removal is two steps: the roll (S17a) has never been run in tdns-mp (membership decision 22) and is judged alone on a fleet first.
- The additions are two steps: a signer role needs P5, which is outside tdns-mp and not established. Until then S4 refuses it.
- tdns is re-pinned in two moves. S1 was to raise only the core module for P1; **P1’s key is already in the pin** (#928), so S1 consumes `GetSerial` and re-pins only if the pin has moved. The re-pin of tdns/v2 goes with P3 in S3, where it is needed; #916 and #917’s child side (#933) are already in the lineage (7.1).

**The first removal of a provider** (a server under `nsmgmt=agent`, the commonest transition) needs S1 to S17b, every one of them, and P2, P3, P4 and P6: each step from S2 to S17b is a "before it" of a later one on that path (S10 and S11 for S7 and S12, S14 for S15 and S17a, S15 for S16 and S17b). It needs none of S18a to S22, and not P5. Until S17b, S4 refuses a removal.

### P1. The HSYNCPARAM `serial` key (tdns, and the draft)

**Status (2026-10-24):** **Done in tdns.** #928 and #929 are merged and in tdns-mp’s pinned core. The draft’s assignment of key 8 and the Label rules remains open ([draft PR #3](https://github.com/johanix/draft-leon-dnsop-signaling-zone-owner-intent/pull/3)). No further tdns code for P1; S1 uses the key.

**Before it:** the draft assigns the key's number. Proposed: 8, the next after `pubcds` (tdns `3615261f:v2/core/rr_hsyncparam.go:56-65`). A private-use number does not fit: the draft allows one only within one administrative domain, and tdns never acts on such a key (`:34-36`).

**Changes.** In tdns `v2/core/rr_hsyncparam.go`:

- `HSYNCPARAM_SERIAL = 8` beside the key constants (`:56-65`), in the name map (`:68-77`) and in `makeHSYNCPARAMKeyValue` (`:156-181`).
- A new value type: on the wire 4 octets in network order, any other length refused; in text decimal, 0 to 4294967295, written `serial=7` or `serial="7"`, no sign, no hex.
- An accessor `GetSerial() (uint32, bool)`. Nothing in tdns acts on the value.
- `Parse` refuses a repeated key (`:246-285`), as `Pack` does (`:191-194`), so a zone file with one fails at its load and not at its first transfer.
- **Lists are Labels, and a malformed list is refused** (the project owner, 2026-10-19; tdns#928 at `e6d64979`). A Label is 1 to 16 characters, each a lowercase ASCII letter, a digit or a hyphen, so Labels compare octet by octet with no case folding. `servers`, `signers` and `auditors` are Labels separated by commas and nothing else, the same on the wire and in text. The wire decoder, the text parser and the encoder refuse an empty item, a space, an uppercase letter, more than 16 characters and any other character; the text parser no longer drops empty items or trims spaces. An empty value is the empty list. The draft (#3) defines the same Label syntax, and a receiver MUST reject a malformed list. tdns#929, stacked on #928, puts HSYNC3's label and upstream under the same rule (an upstream may also be "."): `Parse`, `Unpack` and `Pack` refuse anything else, and the label is stored as written, so "alpha." is refused where it used to be stored and sent as "alpha." after `dns.Fqdn`. HSYNC3's state field and a new name for the RRtype wait for a new codepoint, later.
- **The upgrade order this sets.** HSYNC3 records written by today's tdns carry the trailing dot on the wire. With #929 the parts refuse them, so the owner's primary must run a tdns with #929 before any part re-pins, and every copy of the zone must be reloaded from source or transferred again. The owner's primary is outside the providers' fleet; the guide must say this to the owner (P4). Checked (tdns#929, "Upgrade order (hard)"): one refused record fails the whole transfer, since the dns library stops at the first record it cannot unpack and tdns's AXFR and IXFR give up, so one dotted label stops every update of the zone at every upgraded part. The order is upstream first: the owner's primary, then each part in the order the zone flows. An old part that restarts reloads its saved copy through the old parser, which puts the dot back, and so breaks only a new part downstream of it, which that order rules out.

Then a new pseudo-version of the core module. tdns-mp re-pins only the core module in S1. *(Done: the pin already carries #928/#929; S1 does not invent the key.)*

**Names.** The key name `serial`.

**Tests.** Unit: `TestHsyncparamKeyNumbersMatchTheDraft` (`rr_hsyncparam_test.go:18`) gets key 8; `TestHsyncparamWireEncoding` gets `00 08 00 04 00 00 00 07`; `TestHsyncparamPresentationRoundTrip`. New: `TestHsyncparamSerialRefusesBadValues` (empty, -1, 1.5, 0x10, 4294967296, "7 8"), `TestHsyncparamSerialWireLengthIsFour`, `TestHsyncparamParseRefusesARepeatedKey`, `TestHsyncparamKey8FromAnOlderWriterIsTheSerial`. *(These landed with #928.)*

**Fleet.** A zone with `serial="1"` loads at a tdns-auth primary built with this, and reaches every agent through combiners and signers on the old pin, unchanged. With #929: a primary on the new tdns and parts on the old pin still exchange the zone (the old `Unpack` takes an undotted label as it is, and tdns-mp's trims are no-ops on it; checked on the core tdns-mp pins); a primary on the old tdns and parts on the new pin do not, which is the order above.

**Done when** merged and tagged, and the draft has the number. *(tdns half met; draft number still open.)*

**Size.** tdns: 1 file and its test; about 60 new and 10 changed lines.

### P2. tdns-transport: an application field on confirmations

**Status (2026-10-24):** Not started.

**Before it:** nothing.

**Changes.** `ConfirmRequest` (`f76a204:v2/transport/transport.go:140-154`) gets `App json.RawMessage`; so do `DnsConfirmPayload`, as `app,omitempty` (`v2/transport/dns.go:848-866`), and `IncomingConfirmation`. `DNSTransport.Confirm` sends it, and `HandleConfirmation` (`handlers.go:23-58`) passes it on. `OnConfirmationReceived` (`chunk_notify_handler.go:70`) takes one struct in place of its ten positional parameters, and the struct carries the confirmation's `Message` as well as `App`, so that a PENDING's text reaches the sender (S8); `ConfirmationCallback` (`message_context.go:39`) follows. The golden confirm payload is updated. *2026-10-27:* the HTTPS mechanism carries confirmations since tdns-transport #31 and tdns-mp #229: `APITransport.Confirm` posts the payload `buildConfirmPayload` builds (`860bae6:v2/transport/api.go:303`, `dns.go:463`), which `DNSTransport.Confirm` uses too. So `App` goes over both mechanisms, and tdns-mp's `/msg` `confirm` receiver (`v2/api_receive.go`) must pass `App` and `Message` into `IncomingConfirmation` as `HandleConfirmation` does (S5b).

**Tests.** The confirm golden with `app`; `TestConfirmCarriesTheApplicationField`; `TestAConfirmWithoutTheFieldIsAsBefore`; `TestTheCallbackGetsTheMessage`.

**Done when** merged and tagged; tdns-mp pins it in S5b.

**Size.** 5 files, about 45 new and 25 changed lines.

### P3. tdns: `parentsync` asked of the application, and tdns #926

**Status (2026-10-28):** **#926 done** (in the pin). The hook is built on tdns main `d2b65a97`: `ParentSyncAgentFunc` and `RegisterParentSyncAgentFunc` in `v2/parentsync_bootstrap.go`, after the pattern of `RegisterKeyLifecycleOwner`. `ZoneHasParentSyncAgent` asks it when one is registered, and both its readers (`ParentSyncAfterKeyPublication`, and the poll's check before every step, #926) go through it. Its pull request follows; tdns-mp sets the hook in S3.

**Before it:** tdns #926 (`e7bfb9fa`), which stops the key poll when the owner takes the sync over — merged and pinned.

**Changes.** `ZoneHasParentSyncAgent` (tdns `3615261f:v2/parentsync_bootstrap.go:445-472`) reads `parentsync` from the zone's copy, first record only. It is called by `ParentSyncAfterKeyPublication` (`:53`), which tdns-mp starts (`ec1c6b3:v2/start_agent.go:376`), and by #926's poll (`e7bfb9fa:v2/parentsync_bootstrap.go`, `agentKeyStatePoll`). A hook, proposed `ParentSyncAgentFunc func(ZoneName) bool`, set by the application; when unset, the copy as today. tdns-mp re-pins tdns/v2 and sets the hook in S3.

**Tests.** `TestTheParentSyncHookOverridesTheCopy`; `TestNoHookReadsTheCopy`.

**Size.** 1 to 2 files, about 20 new and 10 changed lines.

### P4. The owner's tools

**Status (2026-10-27):** Not started outside this repository. In it, S1 writes `serial="1"` in the configure example zone and the policy matrix generator.

Every zone that is to change its providers carries `serial`. The owner's zone generators raise it at every edit of HSYNC3 or HSYNCPARAM, and never by 2^31 or more at once (RFC 1982's undefined half is never adopted; an agent left behind by such a jump needs S2's forget command). A primary that does not know HSYNCPARAM gets the RFC 3597 form with key 8. The owner keeps the order of records and roles, does not revoke a leaving provider's access to the zone before "done", and waits for "done" before the next edit (an edit made earlier waits at the agents anyway, design 3.3). Under `nsmgmt=owner` it drops a leaving provider's NS records from its own NS RRset in the edit that takes the provider's server role away (design 3.7, 5.2). After a change of `parentsync` from agent to owner it writes to the parent only after "done"; on an interim build that refuses the change it does not write to the parent at all (design 3.7). In tdns-mp itself, S1 changes the two files an owner's tool reads (the configure example zone, the policy matrix generator), and S4, S17b and S20 the guide. Not sized.

### P5. tdns: what a signer role needs

**Status (2026-10-24):** Not started; tdns-mp issues #160 and #146 remain open.

Two preconditions of a signer role (design 5.1, 5.3), outside tdns-mp:

- A signer that runs its key machine and has its keys published without serving its own signatures (#160).
- A DNSSEC policy bound when inline signing is turned on while the signer runs (#146). Not established whether tdns-mp can do this with tdns's `SetZonePolicyForOwner`, which it calls as `bindPolicyForOwner`.

Needed by S18b only. Until then S4 refuses a move into `signers=`.

### P6. tdns: the provider's nameservers and `pubkey`, `pubcds`

**Status (2026-10-24):** Not started.

**Before it:** nothing. Needed on the providers' nameservers before S7 (section 4), and by S21.

The provider's nameservers are a reader of the owner's instructions (design 1, rule 5): a tdns-auth secondary with `use-hsyncparam` publishes the zone's KEY and its CDS and CDNSKEY at `_signal` names by `pubkey` and `pubcds` in its own copy, and withdraws them (tdns `3615261f:v2/signal_republish.go:64-80, 97-110, 379-392`; `v2/signal_withdraw.go:198`). Design 5.6 has them take this from their agent.

**Changes, proposed (7.3).** The reconciler skips a zone whose copy carries HSYNC3 records: it neither publishes nor withdraws for it, and logs that once. A zone without HSYNC3 is as today. The publication becomes a step of the agent's (S21), through its combiner, which publishes the KEY at the `_signal` names today (`ec1c6b3:v2/combiner_chunk.go:581-603`). Not established: whether the reconciler and the combiner write the same records in the same zone, what the reconciler has published must become at the switch, and what a multi-provider zone lacks at the `_signal` names from P6 until S21. To be read before P6 starts.

*2026-10-28: the three points, read at tdns main `d2b65a97` and tdns-mp main.*
1. *The same records in the same zone:* the same owner name for the KEY (`_sig0key.<child>._signal.<ns>`, spelled alike by tdns's `signalOwnerName` and tdns-mp's `Sig0KeyOwnerName`), never the same zone copy. The combiner writes into a provider zone it serves, which the nameservers take as secondaries. The reconciler writes only into a zone that is primary on its own tdns-auth (`signalPublishTargets`), so it skips such a zone, and the combiner has no provider zone for one that is primary on the nameserver. Only the reconciler publishes CDS and CDNSKEY at `_dsboot`; tdns-mp has no producer for them.
2. *At the switch:* nothing in tdns-mp can take the reconciler's records over, since they sit in a zone tdns-mp does not serve. Kept, a `_dsboot` CDS goes stale at the next key roll, and a parent that bootstraps from it gets a DS for a key the zone no longer publishes. Proposed: they are withdrawn. The reconciler takes its own use-hsyncparam ledger rows of a zone with HSYNC3 as no longer warranted. The skip covers only the use-hsyncparam half, not a primary's own at-ns bootstrap under `parentsync`.
3. *From P6 to S21:* no `_dsboot` CDS for a multi-provider zone, so a parent does not bootstrap its DS through it, and no `_sig0key` KEY under a nameserver whose zone is primary on a use-hsyncparam secondary. Both fail safe: the zone stays insecure, or the sync waits. As far as the repositories show, no multi-provider zone uses the reconciler today.

The project owner decides three points: withdrawal rather than freezing, the scope to the use-hsyncparam half, and shipping it on.

**Tests.** `TestTheSignalReconcilerSkipsAMultiProviderZone`; `TestAZoneWithoutHSYNC3IsAsBefore`.

**Size.** tdns: 2 files, about 30 new and 10 changed lines.

### S1. The canonical reading and its digest

**Status (2026-10-27):** Built, against main `1c28505`; no go.mod change. Where the text left a choice:

- `ReadInstructions` returns no reading and no error for an apex with neither record. Any HSYNC3 state but OFF reads as ON, as `zoneParticipants` has it.
- `CompareSerial` returns 0 for equal serials and for RFC 1982's undefined half alike; `CompareSerials` tells them apart by testing equality first. It returns the order and the ON records added and removed, matched by label and identity (for S4's judge).
- `mplist` and the auditor's views keep the lists of the first HSYNCPARAM record, which is what the code acts on until S3; only the serial, the digest and the owner error come from the reading. A zone with an owner error shows `ERR`, with the error below the table.
- The `strings.TrimSuffix(h3.Label, ".")` calls in the readers stay (`1c28505:v2/hsync_utils.go:1072`, `v2/provider_groups.go:140, 265`): S3 replaces those readers. The configure generator refuses an agent identity whose label is not a Label.

**Before it:** P1, pinned. PR #209, which moves the `PostRefresh` block that S3 moves again (`6eeb002`). No membership step is needed; it lands after them to keep conflicts out of `mplist`.

**Changes.**

- `v2/go.mod`: the re-pin of the core module only (`ec1c6b3:v2/go.mod:13`). tdns/v2 stays at `3615261f` until S3. *2026-10-27:* not needed; every tdns module is pinned at `c3c2a48d`, which has `HSYNCPARAM_SERIAL`, `GetSerial` and the Label parser (#928, #929).
- New `v2/instructions.go`. Proposed:

```go
// Instructions is the canonical reading of a zone's HSYNC3 and HSYNCPARAM
// records (design rule 2): what the code acts on, and nothing else.
type Instructions struct {
    Serial   uint32         // 0 when the key is absent; not in the digest
    HasParam bool           // false: HSYNC3 without HSYNCPARAM, the legacy case
    Records  []InstrRecord  // ON records, sorted by label
    Off      []string       // labels of OFF records, sorted
    Servers, Signers, Auditors []string // sorted sets of Labels (P1), compared octet by octet
    NSmgmt, ParentSync uint8 // absent reads as the default
    Suffix   string
    Pubkey, Pubcds bool
}
type InstrRecord struct{ Label, Identity, Upstream string } // label and upstream Labels as written (P1, tdns#929); identity a lower-case FQDN; "" for no upstream

func ReadInstructions(apex *tdns.OwnerData) (*Instructions, error) // or an owner error
func (in *Instructions) Digest() string                           // 16 hex digits
func CompareSerial(a, b uint32) int                                // RFC 1982; 0 when undefined
```

- The reading follows rule 2. tdns's parser adds a trailing dot to a label and an upstream (tdns `3615261f:v2/core/rr_hsync3.go:54, 61`); the reading drops it. Unknown and private-use keys, TTLs and signatures are not read.
- `HasParam` is in the digest. Without it, HSYNC3 without HSYNCPARAM and an HSYNCPARAM with no lists would read alike, and they do not mean the same: in the first every ON record votes (`ec1c6b3:v2/provider_groups.go:106-113`; membership step 1), in the second nobody has a role.
- The lists need no folding or trimming here: with P1, tdns refuses a malformed list when the zone loads, so a reading has Labels only. With tdns#929 the same holds for HSYNC3's label and upstream, and the `strings.TrimSuffix(h3.Label, ".")` calls go (`ed6d874:v2/hsync_utils.go:939, 1052`, `v2/provider_groups.go:103`, `v2/combiner_chunk.go:1516`). The configure generator must not write a list tdns refuses: `providerLabel` (`ed6d874:v2/cli/configure/render.go:149-159`) lowercases the first label of the agent's identity (the second after `agent`) but does not check the Label rule, so an identity whose label is longer than 16 characters or holds another character gives an example zone that does not load. With the re-pin it refuses such an identity, with a message that asks for a shorter label.
- Owner errors: `errTwoHsyncparams` (more than one record), `errDuplicateLabel` (two HSYNC3 records with one label, in any state). HSYNC3 without HSYNCPARAM is the legacy reading; S2 decides what it means against a held serial.
- The digest: SHA-256 over a versioned, length-prefixed encoding of the reading without the serial, first 8 octets as 16 hex digits, the form of `ComputeGroupHash` (`ec1c6b3:v2/provider_groups.go:32-50`).
- `CompareSerials(held, copy)`: same, newer, older, conflict (same serial, another digest), or undefined (RFC 1982's undefined half, read as not newer). Records are matched by label and identity together: an identity changed under a label is one record removed and another added (rule 2).
- Shown, read-only: `MPZoneInfo` (`ec1c6b3:v2/api_mplist_structs.go:13-25`) gets `Serial`, `Digest` and `OwnerError` of the copy, through `MPZoneInfoFromMPZoneData` (`v2/auditor_mplist.go`) and `ListMPZones` (`v2/cli/mplist.go`). The auditor's config errors (`v2/auditor_hsync_check.go:31-60`) get the two owner errors.
- The owner's tools in this repository write `serial="1"`: `v2/cli/configure/templates/mptest.example.zone.tmpl:20`, `tests/mp-policy-matrix/gen.py:123`.

No decision reads the reading yet.

**Notes from the re-review (2026-10-27)**, for the implementer:

- Two comparisons, kept apart: `CompareSerial(a, b uint32) int`, RFC 1982 arithmetic on two serials, and `CompareSerials(held, copy)`, the (serial, digest) comparison with records matched by label and identity.
- tdns writes an HSYNC3 record with no upstream as `"."` (`c3c2a48d:v2/core/rr_hsync3.go:92`). The reading turns it into `""`, and drops a trailing dot on a label or upstream given by a test that bypasses the parser.
- `MPZoneInfoFromMPZoneData` (`d2cc1d8:v2/auditor_mplist.go:21`) takes the first HSYNCPARAM record and returns early without one; it calls `ReadInstructions` instead. A legacy zone (HSYNC3, no HSYNCPARAM) has serial 0 and a digest.
- The auditor's duplicate-label check cannot come from `hsync3IdentitiesByLabel` (`v2/auditor_helpers.go:60`), whose map keeps one record per label. `checkMPZoneHSYNCConfig` (`v2/auditor_hsync_check.go:27`) reports the reading's owner error.

**Names.** `zone mplist` columns `Serial` and `Digest`. Config errors: "two HSYNCPARAM records", "two HSYNC3 records with the label %s".

**Tests.** Unit, `v2/instructions_test.go`: `TestTheDigestIgnoresOrderTTLAndSignatures`, `TestTheDigestIgnoresTheSerial`, `TestTheDigestIgnoresUnknownKeys`, `TestTheDigestSeesAnOffLabelButNotItsFields`, `TestTheDigestSeesEveryFieldTheCodeActsOn` (a table: label, identity, upstream, each list, `nsmgmt`, `parentsync`, `suffix`, `pubkey`, `pubcds`, `HasParam`), `TestNoHsyncparamAndAnEmptyHsyncparamReadDifferently`, `TestIdentitiesAreCaseFolded`, `TestALabelsTrailingDotIsNoDifference`, `TestAbsentAndDefaultKeysReadTheSame`, `TestListsAreSets`, `TestTwoHsyncparamRecordsAreAnOwnerError`, `TestTwoRecordsWithOneLabelAreAnOwnerErrorInAnyState`, `TestAMissingSerialIsZero`, `TestSerialsCompareByRFC1982` (the wrap, and the undefined half), `TestCompareSerials`, `TestAnIdentityChangedUnderALabelIsARemovalAndAnAddition`, `TestTheDigestIsPinned` (a golden value), `TestMplistShowsTheCopysSerialAndDigest`, `TestTheAuditorListsTheOwnerErrors`.

**Fleet.** On every agent, combiner, signer and auditor: `zone mplist` shows the same serial and digest for each zone. Reordering `servers=` changes no digest. A test zone given two HSYNCPARAM records shows the owner error in `mplist` and in the auditor's config errors. Nothing else changes.

**Done when** the fleet check passes and the golden digest is in.

**Size.** 8 files, about 240 new and 30 changed lines.

### S2. Serials per zone on disk, shown

**Status (2026-10-27):** Built, on S1's branch. Where the text left a choice:

- Storage: `MPZoneInstructions` has one row per zone: the active serial, its digest, the phase and `enforced` in columns of their own, and the whole state as JSON (the newer serials held with their readings, the from-serial, the last thaw, the owner error, the step and its sets). `MPZoneRemovals` is as proposed. The phase follows from the state; the column is for reading the table. The highest serial ever held is the newest held or the active one: a held serial goes only at a thaw at or below its target, or by forget.
- The copy is read in the post-refresh callback, after `PostRefresh`, from the zone as served; `MPPreRefresh` is not changed. A refresh that brings the same copy writes nothing.
- An owner error ends at a copy above the serial held when it was noted; with nothing held then, at the next copy that reads.
- `Activate` takes the thaw's pair, from and to: the from-serial is the active one, or for a member behind it, a newer one it holds. It sets `enforced`.
- Forget does not note the copy again; the next load does (`zone reload`). On the auditor, only the two tables are created.

**Before it:** S1. Membership steps 1 to 8, only to keep conflicts out of `ParentSyncStatus` and `mplist`.

**Changes.**

- New `v2/instructions_store.go`, per zone, on the agent and on the auditor:
  - the copy's serial, or its owner error;
  - every serial held above the active one, each with its reading; the newest is the highest (rule 3). They are kept until a thaw passes them, so a thaw to N+1 that comes after N+2 was loaded still finds N+1;
  - the active serial and its reading;
  - the serial it was thawed from, with its reading, until the transition is done;
  - the highest serial ever held, with its digest;
  - the last thaw heard, from (serial, digest) to (serial, digest) (S7 fills it);
  - the phase (steady, agreeing, reconciling, owner error), the refusal of the newest serial and its reason (S4), the step and its sets: the sets the parts hold, each provider named by label and identity (S3; S12 fills them);
  - the removals under way: for each leaving provider, its label and identity as the leader's first step names them, the step this agent holds, and its NS names, taken from the leader's first-hand steps, or at a leader without them from the members' stamps (S12, S17b). A removal is dropped at its own last step, or when the leader's first-hand stamp shows the transition done (design 3.3);
  - conflict marks per serial, kept until a higher serial;
  - `enforced` on the active record: S7 sets it. Records written before are marked not enforced (section 4).
- `Note(zone, copy)`, at the first load and at every refresh: `MPPreRefresh` computes the copy's serial (`ec1c6b3:v2/hsync_utils.go:1328-1342`) and `PostRefresh` calls `Note` (`:1562ff`). It classifies the copy:
  - newer: held, and the newest;
  - the same: nothing;
  - older, or undefined: not adopted, with a warning (rule 2);
  - the same serial with another digest: a conflict mark;
  - no reading: owner error;
  - a change at serial 0: a conflict (rule 2);
  - HSYNC3 without HSYNCPARAM after a serial with HSYNCPARAM was held: owner error (rule 2);
  - neither record, while the active serial lists more than one provider: owner error (rule 2). With at most one provider: the zone's serials end (design 7, the end of multi-provider service).
- In this step the active serial follows the copy, because the readers still read the copy. The classification is logged and shown as "not enforced".
- `Activate(zone, to)`, for S7: succeeds only when `to` is held, is above the active serial and is not refused. The old active serial becomes the from-serial, kept until "done"; held serials at or below `to` are dropped. The step's sets stay as they are: N's sets, step 0 of the new transition (design 3.3). The leader thaws only a zone whose transition is done (S7: one transition at a time), so a thaw shows that transition done: `Activate` drops what an agent that missed the end still holds of its step and its removals.
- A member whose active serial is older than the thaw's "from" moves straight to `to` (design 3.2). It judges the thaw's own pair, from and to (S4), with the from-serial fetched if it lacks it (S7), never its own older active serial against `to`; it refuses only a serial it cannot read. It keeps the thaw's from-serial, and S12 has it take the step's sets from the leader's stamp before it hands its parts anything new.
- `Done(zone)`, for S12, on the leader's first-hand stamp that shows the transition done: drops the from-serial, the step and every removal still held. A removal ends within its transition (design 3.3), so this only clears what an agent that missed the end still holds.
- Storage: a new HsyncDB table, proposed `MPZoneInstructions` (zone, kind active, from, held or highest, serial, digest, reading as JSON, phase, refusal, step, step's sets as JSON, last thaw, enforced, since), and the conflict marks; a second, proposed `MPZoneRemovals` (zone, label, identity, step held, NS names as JSON, since). Read at the start, before the first load. Written before a change is told. Deleted when the zone leaves the configuration (rule 3).
- The forget command (rule 3), the one exception to never giving a serial up (design 3.7): it clears a zone's stored serials. It is for a steady zone only, run at every agent of the zone together; it refuses while the zone is not steady at this agent, which a removal under way never is. Its use: a zone that the owner re-creates at a lower serial, an agent left behind by a jump of 2^31 or more, and S9's restart wait, at the agents that hold a record.
- Shown: `ParentSyncStatus` (`ec1c6b3:v2/gossip_types.go:169-191`) gets an `instructions` block, filled by `GetParentSyncStatus` (`v2/parentsync_leader.go:1553`) and printed by `agent parentsync status`. `MPZoneInfo` gets `Active` and `Newest`, printed in `mplist` as `7`, `7->8` or `ERR`. The auditor's `ZoneMPViewDTO` (`v2/auditor_mplist.go:86-112`) shows its own.

**Notes from the re-review (2026-10-27).** Check that the auditor's start-up opens the HsyncDB that the new tables need (`main_init.go`), as the agent's does. `mplist` keeps S1's `Serial` and `Digest` columns, and `Serial` shows `7`, `7->8` or `ERR`, so the columns change once.

**Names.** Status:

```
  instructions:   active 41 (5f3a19c2e07b4d11), newest 42 (9c01aa47b2e3f650), copy 42; not enforced
  instructions:   owner error: serial 42 with two digests (9c01aa47b2e3f650, 77ab0e1d4c9b3a22)
```

Log, warn, logger `zones`: "a copy of the zone's instructions below the highest held is not adopted" (`zone`, `copy`, `highest`), once an hour; "owner error in the zone's instructions" (`zone`, `error`). CLI: `tdns-mpcli agent zone instructions forget --zone Z`, refused unless the zone is steady here.

**Tests.** Unit, `v2/instructions_store_test.go`: `TestANewerSerialIsHeldAndBecomesNewest`, `TestALowerSerialIsNotAdopted`, `TestTheSameSerialWithAnotherDigestIsAConflict`, `TestAConflictLastsUntilAHigherSerial`, `TestACopyWithoutAReadingChangesNothingHeld`, `TestAChangeAtSerialZeroIsAConflict`, `TestHSYNC3WithoutHSYNCPARAMAfterAHeldSerialIsAnOwnerError`, `TestBothRecordsDroppedWithTwoProvidersIsAnOwnerError`, `TestTheEndOfMultiProviderServiceEndsTheSerials`, `TestActivateNeedsAHeldSerialAboveTheActive`, `TestActivateRefusesARefusedSerial`, `TestActivateKeepsTheFromSerialUntilDone`, `TestAtTheThawTheStepsSetsAreTheFromSerials`, `TestANewerSerialDuringReconcilingIsHeldAsNewest`, `TestDoneOnTheLeadersStampDropsTheRemovalsHeld`, `TestAThawDropsWhatAnAgentThatMissedTheEndHolds`, `TestAMemberBehindTheFromMovesStraightToTheTarget`, `TestASerialHeldAboveActiveIsKeptWhenANewerOneArrives`, `TestSerialsAtOrBelowTheNewActiveAreDropped`, `TestTheLastThawIsKept`, `TestTheStoreSurvivesARestart`, `TestTheStoreIsReadBeforeTheFirstLoad`, `TestAZoneThatLeavesTheConfigLosesItsSerials`, `TestForgetClearsASteadyZonesSerials`, `TestForgetIsRefusedForAZoneThatIsNotSteady`, `TestActiveFollowsTheCopyUntilEnforced`, `TestRecordsWrittenBeforeEnforcementAreMarked`, `TestStatusShowsActiveNewestCopyAndOwnerError`, `TestTheAuditorKeepsSerialsToo`.

**Fleet.** On every agent and the auditor. An owner edit with a raised serial: each shows the new serial as newest and active. An edit without a raised serial: each shows the owner error with both digests, and the zone behaves as today. An old backup restored at the owner's primary: shown as not adopted. An agent restarted: its status shows the stored serials before the zone's first load has completed.

**Done when** the fleet checks pass.

**Size.** 16 files, about 365 new and 85 changed lines.

### S3. One accessor; the hooks at activation and at a first load; the gate test

**Before it:** S2. P3, and with it the re-pin of tdns/v2, to a tdns in which #916 is not merged, or in which #917's child side is (7.1): past #916 the child's bootstrap race shows. #917's child side is tdns PR #933, merged on 2026-10-19 and pinned, with #916, since tdns-mp PR #219, which pins tdns main at `38faefbb`. So that condition is met. From membership step 7b no key is made while the zone publishes one. Membership steps 4 and 8, whose refresh hooks move here. PRs #185 and #186, merged on 2026-10-19, through step 8. PRs #213 and #217, merged, whose key readers move here (below). PR #208, whose two new readers move here (`foreignKeyWithdrawn` at the signer, `foreignDSWithheld` at the agent; `b7534c3`).

**Changes.**

- `v2/go.mod`: the re-pin of tdns/v2 (`ec1c6b3:v2/go.mod:10`), with P3 and #926.
- One accessor, proposed `instructionsFor(zone)`, in `v2/instructions.go`. On the agent and the auditor it gives the store's active reading. On the combiner and the signer it gives the reading of their own copy until S10 and S11. For a zone the store does not have yet it gives the copy's reading, which keeps the test fixtures with HSYNCPARAM working.
- The readers in `MPPreRefresh` take a reading as an argument, not a zone name: at a first load the served copy is empty, so an accessor by name gives nothing and `MPdata` would be nil. Proposed `readingOf(apex)` for the apex being analysed. At the agent they get the store's active reading and the step's sets, which until S7 are those of the apex being analysed; at the combiner and the signer, until S10 and S11, `readingOf(apex)`. This covers `populateMPdata` on its wrapper around the new zone (`ec1c6b3:v2/hsync_utils.go:1384-1393`), the signer switch (`:1398-1446`) and the combiner's allow-edits check (`:1450-1464`).
- One function for roles, proposed `rolesFor(from, to, step)`, with a set per purpose (design 3.5):
  - `Servers`: whose NS records are served;
  - `KeySigners`: whose DNSKEYs are published, whose foreign rows are kept;
  - `DSSigners`: whose KSKs have a DS, and whose CDS records are published;
  - `KeyConfirmers`: whose confirmations a key's distribution expects;
  - `Signing`: who signs;
  - `Signal`: whether the zone's KEY (`pubkey`) and CDS (`pubcds`) are published at the providers' `_signal` names;
  - and `NSmgmt`, `ParentSync`, `Hold`.

  Each set names each provider by label and identity, fixed when the step that made the set was taken (design 3.3). At rest `from` and `to` are the active serial and every signer set is its `signers=`. With a transition and no step yet, every set is the one the parts hold: N's (S2 keeps it; design 3.3). S13 fills the steps. In the legacy reading (`HasParam` false) every ON record votes, as `zoneParticipants` has it today.
- Every reader moves (rule 5). Groups, admission and discovery read the active reading: they follow the activation. Every other reader reads `rolesFor` for the current step, `nsmgmt` and `parentsync` included: they change only at a step (design 3.3). Until S12 the step's sets are the active serial's lists, so both kinds follow the active serial as before:
  - groups, admission and discovery, by the active reading: `zoneParticipants` takes a reading (`ec1c6b3:v2/provider_groups.go:82-144`); `ParticipantsForZone`, `participantFQDNSetForApex`, `sharedParticipantZones`, `RecomputeGroups` (`:212-296`), `GetZoneAgentData` (`v2/agent_utils.go:167-229`), `mpZoneView` (`v2/hsync_bridge.go:206ff`), and `isInHSYNC` (`v2/agent_authorization.go:101-129`); and the key's peers and its admission since PRs #213 and #217, `mayHoldZoneSig0Key`, `zoneListsAgent` and `roleLessKeyHolders` (`9969013:v2/provider_groups.go:166, 224, 251`), and through them `keyHandOverAdmits` (`9969013:v2/agent_authorization.go:193`), which read the zone's HSYNC3 from the apex today;
  - the multi-provider data: `populateMPdata` (`v2/hsync_utils.go:1127-1228`), with `matchHsyncIdentity` (`:914-942`), `getHSYNCPARAM` (`:978-988`), `isServer`, `isSigner` and `isAuditor` (`:991-1018`) and `analyzeHsyncSigners` (`:1031-1117`), becomes `mpdataFrom(roles)`;
  - the combiner: `getEditPolicy` (`v2/combiner_chunk.go:162-191`), `checkDNSKEYPolicy` (`:1471-1524`), `checkMPauthorization` (`:326-356`), `combinerShouldApplyEdits` (`v2/combiner_utils.go:19-24`);
  - the signer: the inline-signing switch and multi-signer mode (`v2/hsync_utils.go:1398-1446`), the empty inventory (`v2/signer_msg_handler.go:179-190`), `otherSignerLabels` (`v2/mp_key_lifecycle_engine.go:73-110`), `foreignDSFor` through `applyForeignLocked` (`v2/mp_key_lifecycle_foreign.go:43-49, 141-147`);
  - the agent: `computedDSIntent` (`v2/mp_s5_computed_ds.go:118-146`), `publishLocations` (`v2/agent_publish_locations.go:20-28`), `EvaluateUpdate`'s `nsmgmt` (`v2/agent_policy.go:178-195`), `signingAgents` (`v2/hsync_transport.go:2218-2229`), the leader's CSYNC (`v2/mp_s5_leader_csync.go:94`), the NOTIFY wait (`v2/mp_s5_leader_sync.go:673-679`), the first-load `parentsync` switch (`v2/start_agent.go:208-219`), PR #209's `followParentSyncParam`, `LocalDnskeysFromKeystate` (`v2/hsync_utils.go:196`), `canSubmit` (`v2/apihandler_agent.go:116`);
  - the auditor: `zoneMemberRole` (`v2/auditor_engine.go:251-302`), `hsync3IdentitiesByLabel` (`v2/auditor_helpers.go:60-85`), `GetAuditors` (`:31-35`), `expectedHSYNC3Identities` (`v2/auditor_detectors.go:174-195`), which decides which providers are missing from the served HSYNC3 and today counts OFF records;
  - the display: `v2/auditor_mplist.go:53, 133` and `v2/apihandler_agent_hsync.go:67` read through the accessor;
  - tdns: P3's hook, set from the step's `ParentSync`.

  The multi-provider data, the combiner's, the signer's and the agent's readers take the step's sets; the auditor's and the display's take the active reading.
- **Readers that came after this plan was read** (2026-10-27). tdns-mp #275, the interim for #147, keeps a signing set per zone in the keystore (`MPSigningProviders`): `nextSigningSet` (`d2cc1d8:v2/leaving_signer.go:48`) reads HSYNC3 and HSYNCPARAM from the apex, and `populateMPdata` (`v2/hsync_utils.go:1275`) takes the set. The gate would flag it. Here it reads the store's active reading; S11 and S13 replace it, and the set and its table go with S13. tdns-mp #279 (open) makes a zone named in `key-lifecycle-zones` owned from the signer's start; it reads the configuration, not the records, and S11 keeps its rule. #275 also runs `afterSigningSetChange` (`d2cc1d8:v2/leaving_signer.go:196`, from the post-refresh callback in `v2/config.go:88`), which asks for a delegation sync when the signing set changed: it moves with `onSetsChanged` here and goes with S13. The rest of this list is re-read on the day the step starts, as the base says.
- Dead code the gate would flag is deleted: `ValidateHsyncRRset` (`v2/hsync_utils.go:854`) and `PublishKeyToCombiner` (`v2/parentsync_leader.go:1721`), neither called.
- The legacy HSYNC and HSYNC2 paths go: `v2/hsync_utils.go:946-975, 1060-1113, 1147-1148` and `v2/combiner_chunk.go:339-340`. They fall outside the canonical reading. About 90 lines removed, counted in the changed lines.
- `HsyncChanged` (`v2/hsync_utils.go:32-117`) reports a change when the serial or the digest differs. A TTL, a list's order, a label's dot or an OFF record's fields are no change.
- Two hooks, which split what `PostRefresh` runs at an HSYNC change today (`:1562-1602`).
  - `onActiveChanged(zone, from, to)`, from the two active readings: `ApplyHsyncDiff` with the identities that entered or left (`v2/hsync/hsync3_diff.go:64-163`); `RecomputeGroups`, and through it PR #186's callbacks; membership step 8's `zoneChanged`; step 4's catch-up reasons (`join`, `role`, `peer-role`), with `peer-role` widened to every provider that enters `servers=` or `signers=` (design 5.1, a provider put back).
  - `onSetsChanged(zone, sets)`, from the step's sets: the `parentsync` option, both ways, and P3's hook; the recompute of `MPdata`, `MPOptions` and the combiner's allow-edits, so that a change takes effect without a transfer.

  Both are called:
  - when the store's active serial changes (S12 calls `onSetsChanged` again at every step); until S7 that is at the refresh, since the active serial follows the copy;
  - at every first load, as `onActiveChanged(zone, none, active)` and `onSetsChanged(zone, sets)`, whatever the store holds (rule 5). Today the first load counts as a change because `HsyncChanged` sees every record as added when there is no old apex (`ec1c6b3:v2/hsync_utils.go:62-79`), and that is the only path to `RecomputeGroups` on the agent (`v2/hsync_bridge.go:398-401`). After a restart the store already holds the active serial and the first copy equals it, so without this call a restarted agent would have no provider groups, no leader and no sync.
- An OFF record gives no label. Today `matchHsyncIdentity` returns the first record whose identity matches and never tests the state (`ec1c6b3:v2/hsync_utils.go:929-941`), and so does `checkDNSKEYPolicy`'s label lookup (`v2/combiner_chunk.go:1496-1509`); `zoneParticipants` skips OFF records (`v2/provider_groups.go:92-104`). This is a change of behaviour: an OFF record of the local identity gives a label there today.
- **Labels are resolved through the sets** (design 3.3). Today each of these maps a label to an identity, or back, through the zone's HSYNC3 records. Each takes the identity from the pair in the step's set instead, and for a provider whose removal is under way from the removal's stored identity (S2): the combiner's filter by origin in `RebuildCombinerData` (S10; `ec1c6b3:v2/combiner_utils.go:1113-1144`); `checkDNSKEYPolicy`'s label lookup (`v2/combiner_chunk.go:1494-1513`); the signer's own label, through `matchHsyncIdentity` (`v2/hsync_utils.go:914-942`); `otherSignerLabels` (`v2/mp_key_lifecycle_engine.go:73-110`); `signingAgents` (`v2/hsync_transport.go:2218-2229`); `computedDSIntent`'s shares by label (`v2/mp_s5_computed_ds.go:137-148`); and `isInHSYNC` (`v2/agent_authorization.go:101-129`), which so admits such a provider (S15). Until S17b no removal exists, so the second source has nothing to read.
- A copy with no reading keeps the last good reading, at every part, with one log line, instead of taking the first record.
- Identities compare case-folded everywhere (S1). Today several readers compare them with their case (`ec1c6b3:v2/hsync/hsync3_diff.go:23, 54`).
- A source gate in the style of `mp_no_hooks_gate_test.go`: no read of `TypeHSYNC3`, `TypeHSYNCPARAM` or `getHSYNCPARAM` outside the reading, the change detector and the store. `v2/cli/hsync_cmds.go:428`, which uses `TypeHSYNC3` as a query type, is allowed by name.

Nothing changes for a zone at rest, except that an OFF record gives no label.

**Names.** Log, info, logger `zones`: "the zone's active instructions changed" (`zone`, `from`, `to`); warn "the zone's copy has no reading of its instructions, keeping the last" (`zone`, `error`).

**Tests.** Unit: `TestAReorderedListIsNoChange`, `TestAnOffRecordsFieldsAreNoChange`, `TestATTLOrSignatureChangeIsNoChange`, `TestARoleMoveIsAChange`, `TestTheHookGetsTheTwoActiveReadings`, `TestTheHookRunsAtEveryFirstLoad`, `TestARestartWithAStoredSerialHasGroupsAndPeersAfterTheFirstLoad`, `TestGroupsComeFromTheActiveReadingNotTheCopy` (the store's active differs from the copy, and the group follows the active), `TestMPdataFollowsTheStepsSetsWithoutATransfer`, `TestThePreRefreshReadersGetAReadingOfTheApex`, `TestAdmissionReadsTheActiveReading`, `TestApplyHsyncDiffGetsOnlyIdentitiesThatEnteredOrLeft`, `TestCatchUpReasonsComeFromTheActiveChange`, `TestPeerRoleFiresForAProviderThatEntersAList`, `TestZoneChangedRunsAtAnActiveChange`, `TestParentsyncFollowsTheStepsSetsBothWays`, `TestNsmgmtAndParentsyncDoNotChangeAtTheActivation` (a transition with no step yet: the option, P3's hook and `EvaluateUpdate` keep the held values), `TestTdnsAsksTheAgentForParentsync`, `TestRolesFromTheReadingAgreeWithTodaysFlags` (signer, server, both, auditor, no role, unsigned, no HSYNCPARAM), `TestWithATransitionAndNoStepTheSetsAreThoseHeld`, `TestTheSetsNameEachProviderByLabelAndIdentity`, `TestEveryLabelResolverReadsTheSetsNotTheRecords` (a table over the resolvers above), `TestAProviderWhoseRemovalIsUnderWayIsResolvedThroughItsStoredIdentity`, `TestEveryDecisionFollowsTheActiveSerialNotTheCopy` (a table over the readers above), `TestAnOffRecordGivesNoLabel` (in `matchHsyncIdentity` and in `checkDNSKEYPolicy`), `TestTheAuditorsExpectedIdentitiesSkipOffRecords`, `TestACopyWithoutAReadingKeepsTheLastOne`, `TestLabelsAreResolvedThroughTheReading`, `TestNoDecisionReadsTheZonesOwnHSYNCRecords` (the gate). The existing `TestApplyHsyncDiff_*` (`v2/hsync/apply_hsync_diff_test.go`) take the identity difference; tests of the legacy HSYNC and HSYNC2 paths go.

**Fleet.** On every agent, combiner, signer and auditor. The fleet checks of membership steps 4 and 8 pass unchanged, also after every agent is restarted. An owner reorder of `servers=`, and an edit of an OFF record's upstream, cause no recompute, no discovery and no election (no "HSYNC RRset changed" in the logs). A change of `parentsync` from agent to owner stops the leader's sync at the next refresh, as PR #209's check has it. The new tdns pin: a run with a key rollover and a leader hand-over shows no difference.

**Done when** the fleet checks pass and the gate test is in.

**Size.** 30 files, about 345 new and 450 changed lines.

### S4. Owner errors and refused transitions

**Before it:** S3.

**Changes.**

- New `v2/transition_judge.go`: `judgeTransition(from, to *Instructions) []Refusal`, a function of the two serials alone (design 3.1). `from` is the agent's active serial; for a member that moves straight on a first-hand thaw it is the thaw's from-serial (S2, S7). Records are matched by label and identity (S1). Refused:
  1. the ON record of a provider is removed that has a role under `from` (`record-with-role-removed`);
  2. a role is given to a label with no ON record under `from` (`role-without-record`);
  3. the identity under a label with a role changes (`identity-changed`);
  4. a signer moves to `servers=` only (`signer-to-server`);
  5. `signers=` is emptied while it was not empty under `from` (`signers-emptied`);
  6. an ON record's upstream names a label that is not in `signers=` under the new serial, or has no ON record under it (`upstream-dangling`);
  7. a signer that is a remaining server's upstream under `from` leaves `signers=` (`upstream-signer-removed`): the owner moves the server's upstream first, as its own edit;
  8. an upstream changes, or a provider moves into `signers=`, while the step it needs cannot be carried out (`step-missing`);
  9. a kind of change whose steps are not built yet (`not-built`, decision 29): taking roles away until S17b, a server role until S18a, a move into `signers=` until S18b, `nsmgmt` until S19, `parentsync` until S20, an upstream, `pubkey` or `pubcds` until S21. Each of those steps lifts its row. The judge reads a constant per kind, not config.
- Not refused: a record removed while that provider's removal is not done (design 3.1). The provider stays a member, with the identity of the last serial that listed it, until its removal is done (S2's removals, S15, S17b).
- The judgement is made again when the active serial changes.
- The owner errors are the store's (S2). Between agents they come with S5a.
- The store's phase records a refused newest serial as "refused", with the reason. The serial agreed on is the highest serial held that the judge accepts against the active one (design 3.1, decision 94); with none, the zone stays steady at the active serial (design 3.6). A refused serial is judged again when the active serial changes. S5a tells both in the stamp.
- Shown in the status, in `mplist` and in the auditor's config errors; one log line per zone and serial.
  *2026-10-27, from the external review of S2 (`2026-10-27-tdns-mp-PR281-s2-serials-on-disk-review.md`, N3):* the store's own owner errors (one serial with two digests, HSYNCPARAM dropped, both records dropped) already show in `mplist`, in `agent parentsync status` and on the auditor's zone page. They do not reach the auditor's config errors yet: `checkMPZoneHSYNCConfig` (`v2/auditor_hsync_check.go`) has no handle on the store, and reports only the copy's own owner errors (S1). S4 gives it the store, for its owner errors and its refusals.
- Not enforced here. From S7 a refused serial is never thawed nor activated, and S6's freeze holds a zone in owner error.
- The guide: `guide/customer-zone-setup.md` and `guide/provider-changes.md` say to raise the serial at every edit, never by 2^31 or more; to keep the order of records and roles; not to revoke a leaving provider's access to the zone before "done"; that the next edit waits for "done"; what is refused; that on a build before S20 a change of `parentsync` is refused and the owner must not write to the parent; that on a build before S17b a removal is refused, and the owner keeps the provider's NS records in its NS RRset and at the parent (7.2); and that every agent of a zone is upgraded before an owner edit, since a mixed fleet only stalls (section 4).

**Names.** Status:

```
  instructions:   42 refused: removes the record of agent.charlie.example., which has a role under 41
  instructions:   held: owner error: serial 42 with two digests (9c01aa47b2e3f650, 77ab0e1d4c9b3a22)
```

Log, warn, logger `zones`: "a change of the zone's instructions is refused" (`zone`, `from`, `to`, `reason`).

**Tests.** Unit: `TestARecordWithARoleRemovedIsRefused`, `TestARecordRemovedWhileItsRemovalIsNotDoneIsAgreed`, `TestTheJudgeIsAFunctionOfTwoSerials`, `TestAMemberThatMovesStraightIsJudgedOnTheThawsPair`, `TestARoleForALabelWithoutARecordIsRefused`, `TestAnIdentityChangeUnderALabelWithARoleIsRefused`, `TestAnIdentityChangeUnderALabelWithNoRoleIsAgreed`, `TestASignerMovedToServersOnlyIsRefused`, `TestASignerLeavingBothListsWithItsRecordKeptIsAgreed` (once S17b has lifted `not-built`), `TestEmptyingSignersIsRefused`, `TestAnUpstreamThatNamesNoSignerIsRefused`, `TestAnUpstreamThatNamesALabelWithoutARecordIsRefused`, `TestRemovingASignerThatIsARemainingServersUpstreamIsRefused`, `TestAnUpstreamChangeIsRefusedUntilItsStepExists`, `TestAMoveIntoSignersIsRefusedUntilItsStepExists`, `TestAKindWithoutItsStepsIsRefused`, `TestARefusedSerialLeavesTheZoneSteady`, `TestANewerSafeSerialReplacesARefusedOne`, `TestAnEditWithoutARaisedSerialIsAnOwnerError`, `TestTheOwnerErrorEndsAtAHigherSerialOnly`, `TestRevertedContentsAtTheSameSerialDoNotEndTheOwnerError`, `TestAZoneWithoutSerialIsAnOwnerErrorAtItsFirstChange`, `TestEveryAgentGivesTheSameReason`.

**Fleet.** On every agent and the auditor. A signer moved to `servers=` only: each shows it refused with the reason. Before S7 the parts still act by their copy; the check that nothing changes runs again with S7, S10 and S11.

**Done when** the fleet check shows the refusal at every agent and the auditor.

**Size.** 9 files, about 245 new and 60 changed lines.

### S5a. Stamps in beats; each member's serial; the fetch; nothing taken from an answer

**Before it:** S2, and S4 for the error and refusal codes. Membership step 6: a beat's sender is the one the transport established, and `MergeGossip` takes nothing for a group the receiver does not have.

**Changes.**

- The stamp. Proposed:

```go
// InstrStamp is what an agent tells of one zone's instructions (design rule 4).
type InstrStamp struct {
    Active       uint32    `json:"active"`
    ActiveDigest string    `json:"active_digest"`
    Newest       uint32    `json:"newest"`
    NewestDigest string    `json:"newest_digest"`
    Agreeing     uint32    `json:"agreeing,omitempty"`        // the serial agreed on: the highest held that the judge accepts (S4)
    AgreeingDigest string  `json:"agreeing_digest,omitempty"`
    Known        bool      `json:"known"`              // false: no active serial known since this start (S9)
    Refused      string    `json:"refused,omitempty"`  // the judge's code, when this agent refuses its newest serial (S4)
    Error        string    `json:"error,omitempty"`    // an owner error's code
    Rollover     bool      `json:"rollover,omitempty"` // this provider has a key rollover under way
    WaitsOn      []string  `json:"waits_on,omitempty"` // the rollover waits only for these signers' confirmations (S11)
    Hold         bool      `json:"hold,omitempty"`     // this agent's signer has confirmed the hold for the serial agreed on (S6)
    Crypto       bool      `json:"crypto"`             // payload encryption is on at this agent
    Thaw         *Thaw     `json:"thaw,omitempty"`     // the last thaw heard: from and to (serial, digest) (S7)
    Step         *StepView `json:"step,omitempty"`     // the leader's current step and its sets; a member's step held (S12)
    Removals     []RemovalView `json:"removals,omitempty"` // the removals under way this agent holds, with the step it holds (S12, S17b)
    Done         bool      `json:"done,omitempty"`     // the active serial's transition is done (S12)
}
```

- Where it goes: one more `GossipMessage` in every beat, with a reserved empty group hash, whose only row is the sender's own `MemberState` with `Instr map[string]InstrStamp`, `Epoch`, `Seq` and `Nameservers` (`ec1c6b3:v2/hsync/gossip.go:14-32`). `Nameservers` are the provider's own nameserver names, from `multi-provider.local.nameservers` (`ec1c6b3:v2/multi_provider_conf.go:106-109`): rule 4 has each agent tell them, and S19's report reads them. `BuildGossipForPeer` (`v2/gossip.go:235-327`) appends it. `MergeGossip` (`:175-232`), the auditor's decoder (`v2/auditor_engine.go:364-371`) and the engine's (`v2/hsync/transport_peer.go:205-214`) skip it. A row per group would break at a thaw that changes the make-up: the sender then sends no row for a group it has left (decision 30).
- `Epoch` is a counter kept on disk and raised at every start, not a start time: a clock that runs backwards across a restart would make new stamps look older than old ones. A new epoch replaces what was kept of that sender (design 3.4: a member's tellings count only from its last start).
- Which zones: every zone the two agents share under the sender's active or newest serial, and every zone with a removal under way. That is more than rule 4 asks; S22 brings it to rule 4's form.
- Noted first hand, in `routeBeatMessage` (`ec1c6b3:v2/hsync_transport.go:857-873`), before `MergeGossip`, and only when the row's identity is the transport's sender. `Epoch` and `Seq` order one sender's stamps.
- **Nothing that changes state is taken from an answer** (rule 4, decision 12). In `SendBeatWithFallback` (`ec1c6b3:v2/hsync_transport.go:1801-1817`), which both callers use (`v2/hsync_bridge.go:105`, `v2/hsync_infra_beat.go:77`), and in the auditor's beat path, the gossip of a beat answer, of either mechanism, is kept for the display only: its stamps are not counted, its rows do not feed `CheckGroupState`, and no election record or term is taken from it. Today the answer's gossip goes to `MergeGossip`, which stores a higher-term election record and fires `onElectionUpdate` (`v2/gossip.go:199-211`). Membership step 6 does this (membership decision 35, 2026-10-19: `MergeGossip` takes only the rows from a beat's answer, no election record and no term). S5a adds only that an answer's stamps are not counted.
- Each member's serial, per peer and zone: the latest first-hand stamp and when it was heard. The same serial with another digest is an owner error, a conflict mark in the store, only when both tellers are voting members under the active or the newest serial, or when a voting member's digest for the active serial differs from this agent's own copy (rule 2). A conflict told by a member that does not vote is shown and holds nothing. The status says which side lags.
- The rollover flag: one predicate, proposed `rolloverUnderWay`, defined in the key machine (`v2/mp_key_lifecycle.go`) as a function of the key rows and the machine's flags, and used by S5a, S6, S7 and S11. Proposed, to be read again on the day: an own key in `mpdist`, `published`, `retired` or `mpremove`; a KSK whose DS withdrawal has started while the parent still serves the DS; `AlgRollInFlight`; `RolloverRequested` (`v2/mp_key_lifecycle_driver.go:318-320`; the states and columns at `v2/mp_key_lifecycle.go:66-110`); a DNSKEY propagation pending for the zone. In this step the agent applies it to its signer's last inventory; S11 has the signer apply it to its own state and report the result.
- The fetch (design 3.1): a first-hand stamp whose newest is above this agent's newest asks a refresh of its own copy (`conf.Config.Internal.RefreshZoneCh`, `ec1c6b3:v2/apihandler_agent_routes.go:15`), at most once per serial and once a minute. S10 and S11 add the provider's chain. The status names a member that tells a serial nobody else holds.
- Payload encryption: each agent tells in `Crypto` whether it is on, and the receiver notes whether the member's beats came in the payload envelope. An agent with it off says so at start and in its status. S7 thaws no zone with a voting member that has it off (rule 4).

**Names.** Status, per member:

```
Instructions, per member:
  Active  Newest  Rollover  Hold  Heard     Identity
  41      42      no        yes   15:04:05  agent.alpha.example.
  41      41      yes       no    15:04:02  agent.bravo.example.   (lags)
```

Log, info, logger `gossip`: "a member tells newer instructions, fetching the zone" (`zone`, `member`, `serial`); warn "owner error: two voting members tell one serial with two digests" (`zone`, `serial`, `members`); info "a member that does not vote tells another digest" (`zone`, `serial`, `member`); warn, at start, "payload encryption is off: no transition of a zone this agent votes for is thawed".

**Tests.** Unit, `v2/instr_stamp_test.go`: `TestAStampIsToldForEveryZoneTheTwoShare`, `TestAStampIsToldUnderEitherSerial`, `TestTheStampEntryCarriesOnlyTheSendersRow`, `TestTheStampEntryIsNotMergedAsAGroup`, `TestAStampFromABeatIsFirstHand`, `TestAStampFromABeatAnswerIsNotCounted`, `TestAStampInABeatAnswerChangesNoThawState`, `TestAnElectionRecordInABeatAnswerIsNotTaken`, `TestGossipRowsInABeatAnswerChangeNoGroupState`, `TestARowWhoseIdentityIsNotTheSenderIsNotNoted`, `TestAnOlderSeqDoesNotReplaceANewerStamp`, `TestANewEpochReplacesAPeersStamps`, `TestTheEpochIsACounterThatSurvivesARestart`, `TestAVotingPeersOtherDigestAtTheSameSerialIsAnOwnerError`, `TestADigestConflictFromAMemberThatDoesNotVoteHoldsNothing`, `TestTheStampCarriesARefusal`, `TestTheStatusSaysWhichPeerLags`, `TestTheRolloverPredicateCoversEveryPhase` (each state, a withdrawn DS still served, an algorithm rollover, a requested one), `TestTheRolloverFlagFollowsTheInventory`, `TestHearingANewerSerialFetchesOncePerSerialAndMinute`, `TestAMemberTellingASerialNobodyHoldsIsNamed`, `TestTheStampTellsPayloadEncryption`, `TestTheStampRowCarriesTheProvidersNameservers`. Golden: `TestGoldenGossipWithStamps`; the existing gossip goldens are unchanged. Harness: `TestTransportBoundary_StampsInBeatsOverBothMechanisms`, over DNS and over HTTPS on PR #201's `apiGossipEnv`; `TestTransportBoundary_AnElectionInABeatAnswerIsNotTaken`.

**Fleet.** On every agent and the auditor. At rest: every beat carries the stamps; measure the bytes per zone. An owner edit with a raised serial: within two beat intervals of the last load, every agent's status shows each member's newest. One agent's transfer held back: the others show it lagging, and it fetches once a minute. An edit without a raised serial, made between two providers' transfers: both mark the conflict within a beat interval. An election held while one agent hears another only through beat answers: no election record is taken from an answer.

**Done when** the fleet checks pass.

**Size.** 15 files, about 530 new and 140 changed lines.

### S5b. Stamps on messages and confirmations

**Before it:** S5a. P2 and a new pin of tdns-transport. Membership step 3, for the sync wrapper, and the pull request of membership decision 41, without which no confirmation of a SYNC sent over HTTPS reaches its sender.

**Changes.**

- `Instr *InstrStamp` on the sync wrapper of membership step 3 (around `ec1c6b3:v2/mp_send.go:28-57`), on the EDITS, CONFIG and AUDIT wrappers (`:123-197`), and on `DnsSyncPayload`, `DnsConfigPayload`, `DnsEditsPayload` and `DnsAuditPayload` (`v2/mp_wire_payloads.go`); one pointer field on `PeerSyncRequest` and `SynchedDataUpdate`.
- Stamped when sent, not when queued (rule 6): `deliverGenericMessage` (`v2/hsync_transport.go:1906-1950`) builds the payload at every attempt, so it sets the stamp there; `sendRfiToAgent` (`v2/hsyncengine.go:695-737`) and the CONFIG sends set it when they send. Each distribution records, per recipient, the stamp of each send: the tracked records, `PendingDnskeyPropagation`, the queue entry. S8 reads it.
- Confirmations carry the confirmer's stamp in P2's field: `sendImmediateConfirmation` (`v2/hsync_transport.go:1432-1467`), `sendRemoteConfirmation` (`:1472-1530`), `auditorConfirms` (`v2/auditor_engine.go:152`). The combiner has no serial to stamp before S10, so `combinerSendConfirmation` (`v2/combiner_msg_handler.go:288`) is stamped there. The `OnConfirmationReceived` closure (`v2/hsync_transport.go:394-428`) parses it into `ConfirmationDetail.Instr` and a stamp per agent on `PendingDnskeyPropagation`.
- Every message a member sent notes its stamp as first hand, ordered as in S5a. The transport's inline acknowledgement is an answer and is not noted.
- No receiver rule yet (S8).

**Names.** `agent distrib` (`v2/apihandler_agent_distrib.go`) shows each recipient's stamp beside its confirmation.

**Tests.** Unit: `TestEverySyncFamilyMessageCarriesTheSendersStamp` (sync, update, rfi), `TestConfigEditsAndAuditCarryTheStamp`, `TestAResendCarriesTheStampOfItsSend` (a resend after the active serial moved), `TestEveryConfirmationCarriesTheConfirmersStamp` (pending, final, auditor's), `TestAConfirmationStampReachesTheTrackers`, `TestAStampFromAMessageCountsAsFirstHand`, `TestTheInlineAcknowledgementIsNotATelling`, `TestADistributionRecordsTheStampOfEachSend`. Golden: `DnsSyncPayload.json` regenerated; new `send-sync-instr.json` and `send-rfi-instr.json`; `send-sync.json`, `send-rfi.json` and `TestGoldenAPIBodies` unchanged for a message without a stamp. Harness: `TestTransportBoundary_ConfirmationCarriesTheReceiversStamp`, on PR #188's `notifyRig`.

**Fleet.** On every agent and the auditor. No change of behaviour in a run with an owner edit and a restart. `agent distrib` shows the stamps.

**Done when** the fleet check passes.

**Size.** 8 files, about 190 new and 85 changed lines.

### S6. The freeze

**Before it:** S4, S5b. Membership steps 3 (the re-read) and 5 (the owed mark).

The step is dormant until S7: while the active serial follows the copy, the newest equals the active and every transition is done. Its tests set the two apart.

**Changes.**

- New `v2/instr_freeze.go`: `zoneFrozen(zone)` with its reasons: agreeing (a serial agreed on above active, decision 94), reconciling (not done), owner error, active not known (S9). A refused newest with no serial agreed on is not a reason (design 3.6).
- Nothing new starts (design 3.1). In the `local` case of the data engine (`ec1c6b3:v2/syncheddataengine.go:156-263`), an operator's `add-rr`, `del-rr` and `update-local-zonedata` go on the owed list, and their sends are owed. They are kept apart from the agent's data: catch-up answers (membership step 3's complete answer, built from the agent's own contributions) and syncs read the data only, so a kept edit reaches no peer and no parent before "done". A second edit, and the operator's view, see the data with the owed list laid over it. A leader's CSYNC outside a step is owed too.
- Two lists per zone, each in order, on disk (rule 3, design 3.1): the owed list (this provider's own changes, released at "done") and the kept list (other agents' distributions, released at the activation; S8 fills it). A new HsyncDB table, proposed `MPKept` (zone, list, sequence, distribution, update as JSON, since). Only the data engine takes from them. At the release the recipients are read then; an owed entry whose provider no longer votes is dropped and membership step 3's re-read runs; a repeat is owed once; a resend is known by its sender and `OriginatingDistID`. An owed edit is applied to the data at its release, not before.
- What passes: a DNSKEY distribution after an inventory (a rollover under way, or an emergency one; that no new rollover starts is the signer's job, below); a step's own distributions (a predicate S12 fills); catch-up requests and answers, which are never held (design 3.1); CONFIG requests and answers; the key's requests and answers.
- The signer's hold: a KEYSTATE signal `hold` (zone, on or off), sent by the agent to its signer (`handleAppKeystate`, `ec1c6b3:v2/mp_verb_handlers.go:136-215`; `keystateWirePayload`, `v2/mp_send.go:78-81`). Under a hold the key machine's tick (`v2/mp_key_lifecycle_driver.go`) starts nothing new: no lifetime rollover, no standby key. Every phase of a rollover already under way runs, by S5a's predicate, the phases of an algorithm rollover included (design 3.1: work under way finishes). The emergency rollover is the operator's `signer key rollover` (`v2/apihandler_signer_key.go:63`, which sets `RolloverRequested`, `v2/mp_key_lifecycle_driver.go:318`): it still starts under a hold, except at a provider with no role under the active serial, or with none under the serial being agreed (design 3.1: its keys go with its removal). S11 folds the signal into the hand-over.
- The signer confirms the hold: its next inventory (`pushKeystateInventoryToAllAgents`) carries `hold` for the zone. A signer that does not sign the zone confirms it the same way. The agent sets `Hold` in its stamp once an inventory with the hold has arrived after it held its newest serial; S7 counts a telling only with it (design 3.1, 3.7).
- The leader: `syncHeld(zone, why)` holds when the zone is frozen and `why` is neither a step's own sync nor the DS sync of a rollover under way; or it is not caught up (membership step 5); or `keyPending` (S14, which lets the key's offers pass while a rollover waits on it). It is asked at four places: both sync commands of `DelegationSyncher` (`ec1c6b3:v2/delegation_sync.go:77, 121`), the release of a held NOTIFY (`delegationSyncReleaseAfter`, `v2/mp_s5_leader_sync.go:496`), `leaderKeySetup` (`v2/start_agent.go:252`), and before `ParentSyncAfterKeyPublication`. In `leaderKeySetup` it holds three things only: the decision that no key exists, the KEY's publication and the offers (S14). Asking for the key and using a key it holds go on. The `DELEGATION-SYNC-SETUP` arm needs no hold: from membership step 7b it does nothing for a multi-provider zone, and the zone's key is `leaderKeySetup`'s alone. A held sync is owed.
- During a freeze a DS set can change only through a rollover under way or an emergency one, so the leader lets a sync pass whose cause is a change of the DS set. It carries the whole delegation by the sets the parts hold, not by a serial's lists (design 3.1): the NS RRset the zone serves, which the combiner builds by the `Servers` it holds (S10), and the DS set by the `DSSigners` held (`computedDSIntent`, S3, S13). tdns builds the sync from the zone's own data (`SyncZoneDelegation`, `ec1c6b3:v2/delegation_sync.go:254, 261`) and from the DS source tdns-mp hands it (`SetComputedDSSource`, `v2/main_init.go:616`), so S3's readers give this with no code of its own here.
- `resync --push` is refused while frozen, with the reason (7.3).
- The operator is told that the edit is kept, and why (`v2/apihandler_agent.go`).
- The release at "done", proposed `instrDone(zone)`: the owed list in order, the owed sync ("the transition is done"), and for a zone this agent leads the take-up that `onLeaderElected` runs. The kept list is released at the activation (S8), before it.

**Names.** Status:

```
  frozen:         agreeing on 42, waiting for agent.bravo.example.
  kept here:      2 changes of this provider's own, the sync with the parent
```

Log, info, logger `engine`: "a change of this provider's own is kept until the transition is done" (`zone`, `distrib`, `why`); "the transition is done, handling what was kept" (`zone`, `owed`). Logger `zones`: "DelegationSyncher: the sync with the parent is held during the transition" (`zone`, `phase`). Logger `signer`: "the key machine holds for the zone: nothing new starts" (`zone`).

**Tests.** Unit: `TestAnOperatorEditDuringAgreeingIsKept`, `TestAKeptEditIsNotInACatchUpAnswer`, `TestAKeptEditIsNotInASync`, `TestASecondKeptEditSeesTheFirst`, `TestKeptEditsGoOutInOrderWhenTheTransitionIsDone`, `TestAKeptEditGoesToTheMembersOfTheNewInstructions`, `TestAKeptEditIsDroppedWhenTheProviderHasLostItsRole`, `TestTheListsSurviveARestart`, `TestARolloverUnderWayIsNotHeld`, `TestEveryPhaseOfARolloverUnderWayRunsUnderAHold` (an algorithm rollover's included), `TestTheEmergencyRolloverIsTheOperatorsRollover`, `TestAnEmergencyRolloverStartsDuringAgreeing`, `TestAProviderWithNoRoleStartsNoEmergencyRollover`, `TestAProviderThatTheAgreedSerialTakesAwayStartsNoEmergencyRollover`, `TestNoRolloverStartsUnderAHold`, `TestTheSignerConfirmsTheHoldInItsInventory`, `TestTheStampSaysHoldOnlyAfterTheConfirmation`, `TestTheLeaderSendsNothingNewToTheParentDuringATransition` (both commands, a waiting NOTIFY, the key's bootstrap, `DELEGATION-SYNC-SETUP`), `TestTheDSSyncOfARolloverUnderWayPasses`, `TestARolloversSyncDuringAFreezeCarriesTheSetsThePartsHold`, `TestAStepsOwnSyncIsNotHeld`, `TestResyncPushIsRefusedDuringATransition`, `TestCatchUpRequestsAndAnswersAreNotHeld`, `TestTheOwedSyncIsAskedForWhenTheTransitionIsDone`, `TestTheOperatorIsToldWhyTheEditIsKept`. Harness: `TestTransportBoundary_AnEditDuringATransitionReachesNoPeer`, on `notifyRig`.

**Fleet.** On every agent and signer. Until S7: a run with no provider change shows no hold line and no difference. The checks of the freeze itself run with S7.

**Done when** the unit tests pass and the fleet run shows no difference.

**Size.** 17 files, about 605 new and 140 changed lines.

### S7. The thaw

**Before it:** S6, S5a, S4. S10 and S11 on the fleet first (section 4): without them a refused serial keeps the agents at N while the provider's combiner and signer act by their own copy at V, and S7 needs S11's inventory to tell a paused rollover. P6 on the providers' nameservers first, for the same reason. It goes to a fleet together with S8 and S9.

**Changes.**

- **Work towards the parent runs on a context of its own per zone.** New `v2/parent_work.go`: `parentCtx(zone)`, `cancelParentWork(zone, why)`, `parentWorkUnderWay(zone)`. Every path to the parent takes it: `DelegationSyncSetup` (`ec1c6b3:v2/delegation_sync.go:52`; from membership step 7b it does not run for a multi-provider zone), `SyncZoneDelegation` (`:254`, `:261`), `ParentSyncAfterKeyPublication` (`v2/start_agent.go:376`), the operator's `parentsync-bootstrap` (`v2/apihandler_agent.go:656`). tdns stops on it (section 1), so tdns needs no change (decision 33). `parentWorkUnderWay` counts the leader's NOTIFY chain too: held NOTIFYs and the re-check timers of `delegationSyncChains` (`v2/mp_s5_leader_sync.go:490-500`). It is cancelled, and the chain dropped as `delegationSyncNotLeading` drops it, at the thaw's turn (below); at every hand-over of the zone's leadership (membership step 8's zone-left hook, `delegationSyncNotLeading`); when the group's leader is invalidated (`InvalidateGroupLeader`, `v2/hsync_bridge.go:305-309`), which today leaves up to 75 s of UPDATE retries running (tdns `3615261f:v2/delsync_retry.go:18-19`); and when the owner takes the sync over (PR #209's hook). This part can go first, as a pull request of its own: it closes the first point PR #209 leaves open, a key poll already running.
- **Every group with two or more voting members elects a leader, whatever its `parentsync`** (design 3). The group election already runs whatever the zones' `parentsync` (`ec1c6b3:v2/hsync_bridge.go:274-304`); the per-zone election at a first load is gated on it (`v2/start_agent.go:228-247`), and that gate goes for a multi-provider zone. The leader's work at the parent stays gated on `parentsync=agent` (`syncHeld`, the option). A zone in no group is led by its only voting member. This changes membership section 7 (section 6).
- **The leader**, in new `v2/instr_thaw.go`: `thawReady(zone)` holds when all of these do (design 3.2):
  - this agent leads the zone's group under the active serial N (`ZoneLeader`, `ec1c6b3:v2/parentsync_leader.go:888-920`), or the zone is in no group, or this agent is its only voting member;
  - the transition to N is done (design 3.3: one transition at a time);
  - it agrees on a serial V above N, the highest it holds that the judge accepts against N (decision 94), and there is no owner error;
  - every other voting member under N, but an excused one, tells in its latest first-hand stamp, heard within `leaving-timeout` (rule 4: a telling counts only while it is fresh), active N and agreeing V, by serial and digest, with its active serial known, no error, and `Hold` (its signer has confirmed the hold); a refusal of a serial above V holds nothing;
  - its own signer has confirmed the hold: an inventory with the hold has arrived after this agent held V (design 3.2: the leader included);
  - every voting member under N and V has payload encryption on, by its stamp and by the envelope its messages came in (rule 4); otherwise the status says why;
  - no key rollover is under way, by every voting member's latest telling and by its own provider's (S5a's predicate, an emergency rollover included). A rollover whose only missing confirmations are those of excused members (`WaitsOn`, S11) counts as paused, not under way; the key machine does not promote across that wait (`ec1c6b3:v2/mp_key_lifecycle.go:209-218`);
  - `parentWorkUnderWay` is false. Entering agreeing the leader starts no parent work but a rollover's (S6); at the thaw's turn it cancels what is left, and thaws when the context reports nothing under way.
- It is asked after every first-hand stamp for a zone in the waiting set, at every beat round (`BeforeHeartbeats`, `ec1c6b3:v2/hsync_bridge.go:403-413`), when its own newest changes, when its own signer confirms the hold, and when its own rollover ends.
- **A leaving voting member** (design 3.2) is one that votes under N and not under V. One whose telling has not met design 3.2's first two conditions (active N and agreeing V, known, no error, `Hold`; no rollover under way) for the configured time, counted from when this agent first holds V, heard or not, is excused from them, its rollover flag included. So a member that is silent, stuck on an old copy, stuck with its rollover flag on, without its signer's hold, or refusing, is excused alike. If it leads under N, each agent excuses it only once that leader's lease has run out in its own view, so that its leadership has ended. A leaving leader that is heard and renews its lease but never meets the conditions stalls the zone, safely, at N, until its operator stops it; the status says so. For as long as it is unheard, it is also excused from the gate of the group under N: the voting list that membership step 8 gives `CheckGroupState` leaves it out, for every zone of the group, so the group can elect without it. That excusal ends when it is heard again. Its actions under N after the thaw are refused as made under older instructions (S8).
- **No voting member under N**: each voting member under V makes V active when every voting member under V tells V, first hand and fresh (design 3.2; rule 3 names this case).
- **The thaw.** The leader writes V to disk as active and enforced, with N as the from-serial and the thaw as the last thaw heard, then activates it through the store (`onActiveChanged`: the zone moves to its group under V), and its stamp carries `thaw {from, to}` and active V.
- **Who else activates** (design 3.2). An agent makes V active on the first first-hand stamp that tells active V from the zone's leader or from a voting member that has made V active (so it votes under V), provided it holds V and does not refuse it (rule 3). A member whose active serial is older than the thaw's "from" and that holds V moves straight to V (`Activate`, S2): the leader plans from what is in place anyway. It judges the thaw's own pair (S4). When it lacks the from-serial it asks for it, by (serial, digest), of the leader or of a voting member whose stamp tells it as its active serial or as its last thaw's from: an RFI, proposed subtype `instructions`, answered with the ON HSYNC3 records and the HSYNCPARAM record in presentation form, which the asker checks against the digest (the hand-over's form, S10). It is a request, answered whatever its stamp (rule 6), and on the mechanism it came by, as tdns-mp #270 (open) answers RFI CONFIG and AUDIT. Until it has the from-serial it starts nothing (7.2). A member whose active serial is lower than a first-hand "active" telling and that does not hold that serial starts nothing, fetches (S5a) and says so. A member that does not vote takes the thaw from any voting member. Every member keeps telling the last thaw it heard.
- **A newer serial during agreeing** becomes the serial agreed on when the judge accepts it against N. One it refuses does not replace the serial being agreed: it is held and told as the newest, with its refusal, and judged again against V once V's transition is done (decision 94). An agent told first hand, by a voting member, a higher serial agreed on than its own, which it does not hold, asks that member for it by the `instructions` RFI above and checks it against the digest. The serials between stay held.
- **A newer serial during reconciling waits** (design 3.3). Agents hold it (S2) and tell it as their newest; `thawReady` is false until the transition under way is done, so nothing of it is agreed or thawed before "done" (S12). No thaw ever lands inside a reconciliation.
- **A lost leader**: when the leader under N is lost before it thaws and is excused, the group elects again (membership step 8), and the new leader thaws by the same tellings. A lost leader that is not leaving keeps its group without a leader until it is heard again or the owner removes it, as membership 4.3's gate has it (`ec1c6b3:v2/gossip.go:383-431`; `v2/hsync_bridge.go:305-309`): the zone stalls, safely, at N, and the status names it (design 3.2).
- **Enforcement on.** From this step the active serial moves only by `Activate`; `Note` no longer moves it. S6's freeze is live. An agent never activates a serial it refused. Until S12, a transition is done at the thaw, and the parts are handed V's sets at once. Those are the sets they hold (design 3.3): until S12 every transition that the judge lets through changes no set of design 3.5.
- The status names what holds the zone: a member, a refusal, a rollover, the parent, payload encryption, a heard leaving leader, a lost leader (design 3.8).

**Names.** Config, proposed: `multi-provider.transitions.leaving-timeout`, in seconds, default 3600: a leaving voting member whose telling has not met the thaw's first two conditions for this long, counted from when this agent first holds V, heard or not, is excused; a telling heard longer ago does not count for the thaw (rule 4); and S12 excuses a leaving member that has not confirmed a step for this long. In the config struct (`v2/multi_provider_conf.go`), its validation, the sample configs and the configure templates. Status:

```
  instructions:   active 41 (done), newest 42; agreeing: waiting for agent.bravo.example. (tells 41), agent.charlie.example. (rollover under way), the parent (a sync in flight)
  instructions:   active 41, newest 43 (refused: role-without-record), agreeing on 42: waiting for agent.bravo.example. (no hold yet)
  instructions:   active 41, newest 42; agreeing: agent.delta.example. excused (leaving, no telling that counts since 14:02:11)
  instructions:   active 41, newest 42; agreeing: held by agent.echo.example., the leader, which leaves and renews its lease; its operator must stop it
  instructions:   active 41, newest 42; agreeing: no leader (agent.alpha.example. not heard since 14:10:03); waiting for it or for the owner to remove it
  instructions:   thawed to 42 at 15:04:05 by agent.alpha.example.
```

Log, info, logger `zones`: "thawing the zone" (`zone`, `from`, `to`); "the zone's active instructions are now" (`zone`, `serial`, `by`); "a leaving voting member is excused" (`zone`, `member`, `since`, `why`); warn "a leaving leader holds the zone: it renews its lease and its telling does not count" (`zone`, `member`), once an hour; "a leaving voting member is excused from the group's gate" (`group`, `member`); "parent work for the zone cancelled" (`zone`, `why`).

**Tests.** Unit, `v2/instr_thaw_test.go`: `TestTheLeaderThawsWhenEveryVotingMemberTellsActiveNAndAgreeingV`, `TestNoThawWhileAVotingMemberTellsAnotherActiveSerial`, `TestATellingInABeatAnswerDoesNotCount`, `TestATellingRelayedInAnotherMembersRowDoesNotCount`, `TestATellingWithoutTheSignersHoldDoesNotCount`, `TestATellingHeardLongerAgoThanTheConfiguredTimeDoesNotCount`, `TestNoThawWhileTheTransitionUnderWayIsNotDone`, `TestNoThawWithoutTheLeadersOwnHold`, `TestNoThawWhileAVotingMemberRefuses`, `TestNoThawWithPayloadEncryptionOffAtAVotingMember`, `TestNoThawWhileARolloverIsUnderWay` (the leader's, a member's, an emergency one), `TestAPausedRolloverDoesNotHoldTheThaw`, `TestNoThawOnADigestMismatch`, `TestNoThawOfARefusedTransition`, `TestNoThawWhileTheLeaderHasParentWorkInFlight`, `TestParentWorkCountsTheNotifyChain`, `TestTheThawCancelsTheLeadersParentWork`, `TestAHandOverOfLeadershipDrainsTheParentWork`, `TestTheParentContextIsCancelledWhenLeadershipIsInvalidated`, `TestAGroupWithParentsyncOwnerElects`, `TestANewerSerialDuringAgreeingIsTheOneAgreedOn`, `TestARefusedNewerSerialDoesNotReplaceTheSerialAgreedOn` (a record then its role, published before the first thaw), `TestARefusedNewerSerialIsJudgedAgainAfterDone`, `TestAnAgentFetchesASerialAgreedOnThatItDoesNotHold`, `TestOnlyVotingMembersUnderTheActiveSerialCount` (an auditor, a member with no role, a newcomer of V), `TestAZoneWithOneVotingMemberThawsItself`, `TestAZoneInNoGroupThawsItself`, `TestAZoneWithNoVotingMemberUnderNThawsWhenTheNewVotersAgree`, `TestALeavingMemberSilentForTheTimeIsExcused` (heard and unheard), `TestALeavingMemberWhoseTellingDoesNotCountIsExcused` (a stuck rollover flag, no hold, a refusal), `TestTheExcusalTimeCountsFromWhenThisAgentFirstHoldsV`, `TestAnExcusedMembersRolloverFlagIsIgnored`, `TestALeavingLeaderIsExcusedOnlyAfterItsLeaseInThisAgentsView`, `TestAHeardLeavingLeaderThatRenewsItsLeaseStallsTheZone`, `TestALostLeaderThatIsNotLeavingStallsItsGroup`, `TestAnUnheardExcusedMemberIsLeftOutOfTheGroupsGate`, `TestTheGateExcusalEndsWhenTheMemberIsHeard`, `TestAMemberActivatesOnTheLeadersActiveStamp`, `TestAMemberActivatesOnAVotingMemberUnderV`, `TestAMemberThatDoesNotVoteTakesTheThawFromAnyVotingMember`, `TestAMemberBehindTheThawsFromMovesStraightToTheToldSerial`, `TestAMemberThatMovesStraightJudgesTheThawsPairNotItsOwn` (active N-1, holds V, not N: it fetches N and activates V), `TestTheFromSerialIsFetchedAndCheckedAgainstItsDigest`, `TestAMemberThatDoesNotHoldTheSerialStartsNothingAndFetches`, `TestAMemberNeverActivatesASerialItRefused`, `TestANewLeaderThawsWhenTheOldExcusedOneIsLost`, `TestTheActiveSerialIsWrittenBeforeItIsTold`, `TestTheLastThawIsToldAndKept`, `TestTheZoneMovesToItsGroupUnderTheNewSerialAtTheThaw`. Parent work: `TestTheOwnerTakingTheSyncOverCancelsAKeyPollInFlight`, `TestAnUpdateRetryStopsWhenTheZonesParentWorkIsCancelled`, `TestABadkeyReBootstrapIsNotSentAfterTheCancel`, `TestACancelledZoneGetsAFreshContextForItsNextSync`. Harness: `TestTransportBoundary_TheLeaderThawsOnFirstHandTellings` (the one real agent leads; the stand-ins beat it with stamps; one whose telling comes only in an answer holds the thaw), `TestTransportBoundary_NothingReachesTheParentAfterTheThaw`, on `notifyRig`'s parent stand-in.

**Fleet.** On every agent and the auditor, with S8 and S9, and S10 and S11 in. An owner edit of `suffix` with a raised serial, with one agent's transfer held back: every agent shows "agreeing" and names it; released, the leader thaws within a beat interval of its telling, and every agent shows the new active serial within two. A KSK rollover started just before the edit: the thaw follows its end, and the rollover's DS reaches the parent meanwhile. An edit without a raised serial: an owner error at every agent, no thaw. One agent with payload encryption off: no thaw, and every status says why. An operator's `add-rr` during agreeing: kept, in no catch-up answer, and applied once at every provider after the thaw. No UPDATE or NOTIFY reaches the parent between the first load and the thaw but the rollover's DS. A signer moved to `servers=` only: refused, the provider keeps signing, nothing changes at the parent. A zone with `parentsync=owner` and two voting members: its group has a leader. A leaving member whose agent runs but whose signer is stopped: excused after the time. A member stopped at N-1 across one transition and restarted after the next thaw: it fetches the from-serial and activates. The fleet checks of S10 and S11 that need a refused serial run here.

**Done when** the fleet checks pass.

**Size.** 19 files, about 815 new and 145 changed lines.

### S8. Messages between serials

**Before it:** S7, S5b. Membership steps 3 (the complete answer) and 6 (the sender rule, asked again at release). PR #169, for its copy of a confirmation to the auditors (`copyConfirmationToAuditors`, `db29f4b:v2/hsync_transport.go:1474-1556`), which #152 builds on; if #169 has not merged when S8 starts, that part of S8 waits for it.

**Changes.**

- At the receiver, at the head of the `remote` case (`ec1c6b3:v2/syncheddataengine.go:264`), before `refuseCsyncNotFromLeader`, `EvaluateUpdate` and `ProcessUpdate`: proposed `instrReceive(update)`, which takes, keeps or refuses by the active serial in the stamp against its own (rule 6):
  - the same: taken as today, also during agreeing;
  - higher, or this agent's active serial not known (S9): kept on the kept list (S6). The transport's acknowledgement and a PENDING go at once, the PENDING saying "kept: this agent acts by serial S, the message was made under S'" (P2 carries the text). The final confirmation follows when it is handled, judged by the instructions then active: the sender rule, and the leader rule for a CSYNC or a KEY. A resend is not kept twice;
  - lower: "made under older instructions", a final confirmation REJECTED with the token `stale-instructions` and the receiver's stamp. Nothing is stored or passed on. The transport's acknowledgement stays ok, so the message does not go on the failed-send backoff (decision 31). The same holds for the leader's withdrawals (S16).
- A confirmation is always taken. The auditor confirms at once whatever it holds (`ec1c6b3:v2/auditor_engine.go:152`), and its confirmation counts. A request (RFI SYNC, CONFIG, AUDIT) is answered whatever its stamp, by the answerer's active instructions; the asker judges the answer.
- The release, proposed `instrActivated(zone)`, when the active serial changes or becomes known: kept entries at the new serial are taken in order, lower ones are refused as stale, higher ones stay (design 3.3: others' kept distributions at the activation, own changes at "done", S6).
- **#152: the auditor sees that a member keeps a distribution.** The "kept" PENDING is copied to the zone's auditors with its text, by PR #169's path, which copies only final confirmations today (`db29f4b:v2/hsync_transport.go:1487-1488`; the copy is `DnsConfirmCopyPayload`, `db29f4b:v2/mp_wire_payloads.go:51`). The auditor shows that member as keeping the distribution, and why, in its view of the distribution, until the final confirmation's copy replaces it. Membership plan 7.5 hands #152 to this design.
- At the sender: an answer (REJECTED, IGNORED, stale) from a peer whose stamp's active serial differs from the stamp of the send it answers is "not yet". `ProcessDnskeyConfirmation` (`v2/hsync_transport.go:2309`, "a key's first final answer from an agent stands" at `:2364`) records no result for that agent; `outcome` (`:2240-2270`) does not count an "ignored" from it as a rejection; `ProcessConfirmation` leaves the records pending for it; `settleQueuedMessage` (`:1420`) settles the queue entry, so the old send is not resent. So the key machine reads it as pending, and its sticky rejection (`v2/mp_key_lifecycle.go:213`) never sees it.
- Sent again once the two are in step (rule 6): when the sender's active serial changes, for each distribution left open that way; and at once when a "not yet" arrives while the sender's active serial already equals the answerer's stamped one, since the trigger has then fired already. Its own contributions go again to those members as a complete `replace` per type (membership step 3's answer form, with no `catch_up`), if the active instructions still let it contribute; a key distribution still pending gets `EvResend` (`v2/mp_key_lifecycle_driver.go`), so the signer distributes again under the new set of confirmers. In the key's rounds (`keyWanted`, membership step 7b), a "no key here" from a peer at another active serial does not count; S14 builds that rule and its test.

**Names.** The PENDING text above. Log, info, logger `engine`: "a distribution made under newer instructions is kept" (`zone`, `peer`, `distrib`, `made_under`, `active`); "a distribution made under older instructions is refused" (same fields); "an answer from a peer at other instructions is not final; sending again when in step" (`zone`, `peer`, `distrib`).

**Tests.** Unit: `TestAMessageMadeUnderTheSameActiveSerialIsTaken`, `TestAMessageMadeUnderAHigherSerialIsKeptAndAcknowledged`, `TestAKeptMessageIsTakenWhenTheActiveSerialCatchesUp`, `TestAKeptMessageIsRefusedWhenTheActiveSerialPassesIt`, `TestAStaleMessageIsRefusedWithTheReceiversStamp`, `TestAStaleRefusalIsAFinalConfirmationNotATransportRefusal`, `TestAResentKeptMessageIsKeptOnce`, `TestAKeptMessageIsJudgedByTheInstructionsActiveAtRelease`, `TestAConfirmationIsAlwaysTaken`, `TestTheAuditorConfirmsWhateverTheStamp`, `TestARequestIsAnsweredWhateverItsStamp`, `TestARejectionFromAPeerAtAnotherSerialIsNotFinal`, `TestAnIgnoredFromAPeerAtAnotherSerialIsNotFinal`, `TestTheOldSendIsNotResentByTheQueue`, `TestAfterActivationOwnContributionsGoAgainToThosePeers`, `TestANotYetThatArrivesAfterActivationIsSentAgainAtOnce`, `TestAKeyDistributionMadeUnderAnOlderSerialIsResent`, `TestKeptRemoteUpdatesDoNotWaitBehindOwedLocalOnes`, `TestThePendingTextReachesTheSender`, `TestAKeptPendingIsCopiedToTheAuditors`, `TestTheAuditorShowsAMemberKeepingADistributionAndWhy`, `TestTheFinalCopyReplacesTheKeptOne`. Harness, on `notifyRig`: `TestTransportBoundary_AMessageAcrossTheThawIsKeptThenTaken`, `TestTransportBoundary_AStaleMessageIsRefusedAndSentAgain`.

**Fleet.** On every agent and the auditor. A thaw while distributions are in flight: "kept" and "stale" lines appear, and every distribution completes, and the auditor's view names each member that keeps one, and why. A key rollover at a signer started just after a thaw, with one member slow to activate: no key distribution is left rejected or pending, and the sticky "ignored as a rejection" of #200 does not recur.

**Done when** the fleet checks pass.

**Size.** 10 files, about 440 new and 105 changed lines.

### S9. The restart rule

**Before it:** S8. Membership step 4 (the tracker's `Ask`, `Answered` and `CaughtUp`).

**Changes.** New `v2/instr_restart.go` (design 3.4):

- At start an agent reads its stored serials (S2). It votes, beats, gossips, catches up, and asks for and answers the zone's key, as always.
- At start, before the first load, the zones are placed in groups: `RecomputeGroups` runs from the stored active readings, and for a zone with none from its newest copy, for talking and for the first activation after the upgrade, whose leader is that group's (below). S3's two hooks at the first load run again over the same readings and the stored step's sets.
- It starts nothing for a zone until it knows the zone's active serial:
  - an agent with its own enforced record knows it from that record;
  - a member with no record takes the leader's word only, first hand: a stamp that tells a known active serial from the agent that leads the zone's group under that serial (7.2);
  - a leader with no record takes the active serial that every voting member with a record tells, when there is at least one and they all agree; the last thaw they tell breaks a tie between a from-serial and its target. A member that tells `known: false` counts as no objection. Otherwise it waits, its status names who differs, and names the forget command (S2) as the operator's remedy.
  - the auditor, which votes in nothing, runs the rule of a member: its own record, or the leader's word.
- No enforced record anywhere: every voting member tells `known: false`. The leader makes active the newest serial every voting member tells, by the thaw's check with no rollover and no parent condition: nothing is active yet to protect, and every voting member tells the same serial. This is the first start after the upgrade (section 4), and a fleet that lost every record. Without this a rollover in `mpdist` would wait for confirmations that are kept until the activation, and the activation for the rollover (`ec1c6b3:v2/mp_key_lifecycle.go:209-218`).
- A member whose copy is older than the active serial starts nothing and fetches (S5a) until it holds it. A provider that is new under a serial is in the same position: it talks from its newest copy and starts nothing until it hears the active serial.
- A member's tellings count only from its last start: its new epoch replaces what was kept of it (S5a). Design 3.4 has the start announced through membership 5.1, whose start request goes to voting members only; the epoch reaches every member (7.2).
- While the active serial is not known: the zone is frozen (S6's reason), every distribution is kept (S8), catch-up answers included (design 3.4, rule 6), and no leader action runs (`syncHeld`).
- New in `v2/catchup.go`: `Arrived(zone, from, catchUp)`, which stops the tracker's time for an answer when a catch-up answer arrives and is kept, and the answer-time rule, 30 s or two beat intervals, counted from when the active serial became known. `CaughtUp` counts the answer once it is handled. Membership step 4 does not build `Arrived`; it belonged to the moved step 9.

**Names.** Status: "instructions: active not known since the start; waiting for the leader's word"; "instructions: no record; the voting members with a record differ (agent.bravo.example. tells 41, agent.charlie.example. tells 42); to start over, run `agent zone instructions forget` at the agents that hold a record". Log, info, logger `zones`: "the zone's active instructions are known" (`zone`, `serial`, `from`: own record, leader, the voting members with a record, common newest).

**Tests.** Unit: `TestARestartedAgentTakesItsOwnRecord`, `TestARestartedLeaderTakesItsOwnRecord`, `TestAMemberWithNoRecordTakesOnlyTheLeadersWord`, `TestAMemberWithNoRecordIgnoresAnotherMembersActive`, `TestALeaderWithNoRecordTakesWhatEveryVotingMemberWithARecordTells`, `TestAMemberWithNoRecordCountsAsNoObjection`, `TestTheLastThawToldBreaksATie`, `TestALeaderAndAMemberWithNoRecordDoNotWaitForEachOther`, `TestRecordsThatDifferNameTheForgetRemedy`, `TestTheAuditorTakesItsRecordOrTheLeadersWord`, `TestAnAgentWithNoRecordStartsNothingUntilItKnowsTheActiveSerial`, `TestARestartedAgentStillVotesBeatsAndAsksForCatchUp`, `TestStartUpPlacesZonesInGroupsFromTheStoredReadings`, `TestTheFirstStartAfterTheUpgradeMakesTheCommonNewestActive`, `TestTheFirstActivationAfterTheUpgradeIgnoresARolloverUnderWay`, `TestRecordsWrittenBeforeEnforcementCountAsNone`, `TestACopyBelowTheHighestHeldIsRefusedAfterARestart`, `TestAMemberWhoseCopyIsOlderFetchesAndStartsNothing`, `TestANewcomerStartsNothingUntilItHearsTheActiveSerial`, `TestTellingsCountOnlyFromTheLastStart`, `TestARestartDuringAgreeingWithARolloverUnderWayDoesNotDeadlock`, `TestACatchUpAnswerIsKeptWhileTheActiveSerialIsUnknown`, `TestArrivedStopsTheAnswerTime`, `TestEveryAgentRestartedResumes`.

**Fleet.** On every agent and the auditor. One voting member's agent restarted during agreeing, with a rollover under way at another signer: it resumes, the rollover ends, the thaw follows. The leader restarted during agreeing: the same active serial, then the thaw. Every agent restarted at rest: every zone active from its records after one exchange of beats, its groups in place before the first load, with no hold line after. The first start of an S7 to S9 build, with a rollover under way at one signer: every zone active at its common newest after one exchange. The leader and one member reinstalled, a third voting member with its record: the zone active at that member's serial after one exchange. The auditor restarted: it shows the active serial after one exchange.

**Done when** the fleet checks pass.

**Size.** 9 files, about 325 new and 65 changed lines.

### S10. One reader at the combiner

This step also closes tdns-mp #235 (2026-10-20): a combiner whose copy of the zone lags its agent's rejects a new signer's DNSKEYs as "not a signer", and nothing judges them again once it catches up. Judged by the sets its agent hands it, the combiner is never behind its agent.

**Before it:** S3. Membership step 3 (the sync wrapper, the own read, and its own flag that the stored contributions were read; PR #167's `contributionsLoaded` is not that flag, membership plan step 3). PR #208, whose restore before the first load is in the same function. It can be built beside S5a to S9, and is on a fleet before S7.

**Changes.**

- The hand-over: one object, proposed `ActingHandover`: the zone, serial and digest; the ON HSYNC3 records and the HSYNCPARAM record in presentation form; the phase and the step; the step's sets per purpose, each provider by label and identity (S3's `rolesFor`, filled by S12 and S13); and an order key (active serial, newest serial, phase, step). An optional field of membership step 3's sync wrapper, on an `update` with no operations through the confirmed queue (`EnqueueForCombiner`, `ec1c6b3:v2/hsync_transport.go:1986-2003`), at high priority (decision 32).
- The combiner, in `CombinerProcessUpdate`: takes it only from an agent of its `agents:` list, never through manual approval (`v2/combiner_msg_handler.go:163`) or `SavePendingEdit`. It parses the records, recomputes the digest and refuses a mismatch; refuses an order key below the one it holds, answering with what it holds; stores it in a new HsyncDB table, proposed `MPActingSerial`; sets its acting serial, recomputes its multi-provider data and edit rights, rebuilds and combines, and confirms (`combinerSendConfirmation`, `:288`).
- The combiner's confirmations carry its stamp: the serial it acts by (moved here from S5b, since the combiner has no serial before this step).
- One agent per part: the config check refuses a multi-provider combiner with more than one agent (today `ec1c6b3:v2/hsync_utils.go:884-905` takes every `mp.Agents` entry), so it is clear whose hand-over counts (7.3).
- Once a serial is handed, `MPPreRefresh` no longer sets the combiner's acting serial from its copy. `RegisterCombinerOnFirstLoad` restores the handed serial before the first load, beside PR #208's restore of the contributions.
- A combiner never handed anything (rule 5):
  - for a zone whose copy carries no serial (the first start after the upgrade), it acts by its own copy, marked provisional;
  - for a zone whose copy carries a serial (a lost database, a reinstall), it asks its agent before its first combine: its start report is the request, and the agent hands over at once. Meanwhile it serves what it last served: it combines its restored contributions without judging them again by origin, so nothing it served is removed. With nothing restored either, it serves the copy as it comes, and its status says so.
- EDITS answers carry what the combiner holds (`sendEditsToAgent`, `:362`).
- The agent: a tracker per zone, new `v2/acting_handover.go`: the serial it wants its combiner to act by (the active serial, its phase, its step and the step's sets), what the combiner holds, the hand-over in flight. It hands over on every change; learns what the combiner holds from the confirmation, and at start from its own read; hands again when the combiner reports a start (its first beat after one) and on a slow ticker until it holds (design 3.5).
- Nothing goes to the combiner under a serial and step it has not confirmed holding: the `local` and `remote` paths (`v2/syncheddataengine.go:208, 330, 724, 801`), which carry the leader's CSYNC too (the `local` case at `:208`), the leader's KEY (`v2/start_agent.go:353`), the catch-up apply, `resync --push`. Such an update waits on the zone's list and goes out, in order, on the confirmation. A REJECTED or IGNORED from the combiner for an update sent under another serial is not final: it is sent again.
- The filter by role is in `RebuildCombinerData` (`v2/combiner_utils.go:1113-1144`), which merges the contributions per origin: DNSKEY contributions only from origins in `KeySigners`, CDS only from origins in `DSSigners` (design 3.5), an origin matched by the identity the set names, not through the copy's HSYNC3 records (S3). `RebuildCombinerData` runs before `CombineWithLocalChanges` at every hand-over and at every combine, so a hand-over judges again what is stored. (`combineInto`, `:360-391`, sees only the merged data and has no origin.) `checkDNSKEYPolicy` (`v2/combiner_chunk.go:1471-1524`, called at `:964-979`) refuses only DNSKEY records added for an origin outside `KeySigners`. Removals in another origin's name are S16's.
- The chain fetch (S5a): a `refresh` flag on the hand-over's carrier asks the combiner to refresh the zone from the owner.

**Names.** Status, at the agent and in the combiner's API (`v2/apihandler_combiner_mp.go`): "combiner: acting by 42 (9c01aa47b2e3f650), handed by its agent at 15:04:05"; "combiner: provisional, by its own copy"; "combiner: waiting for its agent's hand-over, serving what it served". Log, info, logger `combiner`: "acting by the serial the agent handed" (`zone`, `serial`, `step`). Config error: "a multi-provider combiner has more than one agent".

**Tests.** Unit: `TestTheCombinerActsByTheHandedSerialNotItsCopy` (the copy says `nsmgmt=owner`, the handed serial `agent`: the contributed NS stay applied through a refresh), `TestAHandOverRecombinesTheZoneAtOnce`, `TestAHandOverFromAnyoneButItsOwnAgentIsRefused`, `TestAHandOverWhoseRecordsDoNotGiveItsDigestIsRefused`, `TestAnOlderHandOverIsRefusedWithWhatIsHeld`, `TestAHandOverIsNotHeldForManualApproval`, `TestTheHandedSerialSurvivesACombinerRestart`, `TestAFirstLoadWithNothingHandedAndNoSerialIsProvisional`, `TestAFirstLoadWithNothingHandedAndASerialWaitsForTheAgent`, `TestWhileWaitingTheCombinerRemovesNoStoredContribution`, `TestTheAgentHandsAgainUntilItsCombinerHolds`, `TestTheAgentLearnsWhatItsCombinerHoldsFromTheOwnRead`, `TestTheAgentSendsNothingToItsCombinerUnderASerialItDoesNotHold`, `TestWhatWaitedForTheCombinerGoesOutInOrderWhenItHolds`, `TestACombinerRefusalUnderAnotherSerialIsSentAgain`, `TestADNSKEYAddedByAnOriginOutsideKeySignersIsRefused`, `TestTheRebuildFiltersDNSKEYByKeySignersAndCDSByDSSigners`, `TestAStoredDNSKEYIsJudgedAgainAtEveryCombine`, `TestTheCombinersConfirmationCarriesItsStamp`, `TestACombinerWithTwoAgentsIsAConfigError`, `TestTheCombinerRefreshesWhenItsAgentAsks`. Harness: `TestCombinerFirstCopyIsCombinedByTheHandedSerial`, on `startMPServedZone` as PR #208's `TestCombinerFirstCopyHoldsThePersistedContributions`; `TestTransportBoundary_TheCombinerConfirmsAHandOver`, on `notifyRig` with the queue worker.

**Fleet.** On every agent and combiner. Before S7: a run with no provider change shows no difference, and every combiner shows "acting by" the agent's serial. With S7 (the checks need a refused serial that the agent does not hand over): a change of `nsmgmt` from agent to owner, refused until S19: every combiner keeps applying the contributed NS, though its copy says owner. Restarted, it still does, and its status says why. An operator's `add-rr` of NS while one combiner is stopped and its agent hands over a serial: the edit reaches that combiner once, after the hand-over. A combiner whose database is removed, restarted with the zone's copy at a serial: it waits for its agent and serves the zone without a lame or bogus sample. No lame sample.

**Done when** the fleet checks pass.

**Size.** 18 files, about 580 new and 180 changed lines.

### S11. One reader at the signer

**Before it:** S10 (the object, the table, the tracker). S6 (the `hold` signal and its confirmation, which it folds in). Membership step 3 (the own read of the signer). It is on a fleet before S7.

**Changes.**

- The same object on a KEYSTATE signal `acting` (`handleAppKeystate`, `ec1c6b3:v2/mp_verb_handlers.go:136-215`). S6's `hold` becomes a field of it, with the step's exemption (S18b).
- The signer takes it only from an agent of its `agents:` list, checks the digest and the order key, stores it in its KeyDB, and applies it at once, not at its next refresh:
  - the inline-signing switch and multi-signer mode, split out of `MPPreRefresh` (`v2/hsync_utils.go:1398-1446`) into one function both paths call;
  - `syncForeignDNSKEYs` (`v2/signer_keydb.go:49-130`) over the zone it serves, with `KeySigners`, and a re-sign;
  - for a zone the key machine runs: `otherSignerLabels` (`v2/mp_key_lifecycle_engine.go:73-110`) reads `KeyConfirmers`, and the signer's own label is the one its identity has in the handed sets (S3), and `SignersChanged` runs when `KeyConfirmers` changed (`v2/mp_key_lifecycle_driver.go:823`, its first caller outside tests, #136); `applyForeignLocked` for `DSSigners`;
  - then it pushes its inventory, which says what it holds.
- One agent per part, as S10: the config check refuses a multi-provider signer with more than one agent.
- First load: the signer restores the handed serial before the refresh engine starts (`v2/main_init.go:112-146`). `MPPreRefresh` and the key machine (`NewZoneKeyLifecycle`, `driver.go:171`; `Reload`, `:1253`) read it. A signer never handed anything acts by its own copy, marked provisional, for a zone whose copy carries no serial. For a zone whose copy carries a serial it asks its agent first (its start report and an inventory marked "nothing handed"), and meanwhile serves what it last served: it keeps its foreign DNSKEY rows and its multi-signer mode and applies no change of roles from its copy until it is handed one.
- A zone the acting serial does not let this provider sign stays owned and is not run: no release to tdns's key machine, and no take and release at every tick (`v2/mp_key_lifecycle_engine.go:366-374, 476, 537`). Signals and foreign words for it are taken and logged.
- The signer sends its real inventory, marked as not signing, instead of an empty one (`v2/signer_msg_handler.go:179-190`), and `LocalDnskeysFromKeystate` (`v2/hsync_utils.go:196-290`) withdraws nothing from such an inventory: today a provider that leaves `signers=` withdraws its own DNSKEYs and stops signing at once (#147). *2026-10-27:* since tdns-mp #275 (main `b921a94`) it keeps signing and its DNSKEYs stay, and every key machine of the zone pauses while it is in the zone's signing set and out of `signers=`, until its HSYNC3 record goes. This step and S13 replace that pause with the handed sets.
- The inventory carries S5a's predicate, evaluated by the signer on its own state (`rolloverUnderWay`), and for each key waiting in `mpdist` or `mpremove` the other signers whose "applied" is missing. S5a's flag and `WaitsOn` read them; S7 counts a rollover waiting only on excused members as paused. It also carries `hold` for the serial it was handed (S6).
- The agent: the signer half of the tracker. It sends `acting` on every change; counts the signer as holding once an inventory with that serial arrives; sends again on the ticker; and at start learns from its own read.
- The chain fetch: a `refresh` field in the same signal.

**Names.** `signer key status`: "acting by 42, handed at 15:04:05"; "provisional"; "waiting for its agent's hand-over". Log, info, logger `signer`: "acting by the serial the agent handed" (`zone`, `serial`, `step`); "the zone stays owned and idle: this provider does not sign it" (`zone`).

**Tests.** Unit: `TestTheSignerSignsByTheHandedSerialNotItsCopy`, `TestTheSignerKeepsTheOtherSignersDNSKEYsUntilHanded`, `TestTheExpectedSetFollowsKeyConfirmers`, `TestAHandOverThatChangesTheConfirmersCallsSignersChanged`, `TestForeignDSFollowsTheHandedDSSigners`, `TestTheInventoryCarriesWhatTheSignerHolds`, `TestTheInventoryNamesTheMissingConfirmers`, `TestTheSignersHandedSerialSurvivesARestart`, `TestASignersFirstLoadWithNothingHandedAndNoSerialIsProvisional`, `TestASignerWithNothingHandedAndASerialKeepsItsForeignRows`, `TestAKeystateActingFromAnotherSenderIsRefused`, `TestASignerWithTwoAgentsIsAConfigError`, `TestTheAgentResendsUntilTheInventorySaysHeld`, `TestASignerThatDoesNotSignKeepsTheZoneOwnedAndIdle`, `TestAnInventoryMarkedNotSigningWithdrawsNoKeys`, `TestTheInventoryCarriesTheRolloverPredicate`, `TestTheHoldIsAFieldOfTheHandOver`, `TestTheSignerRefreshesWhenItsAgentAsks`. Harness: `TestASignerWhoseCopyDropsItSignsByTheHandedSerial`, on `startMPServedZone` and `startMPUpstream` (`v2/signer_relayed_serial_test.go`): the upstream moves from two signers to one, the served copy stays signed and its SOA serial moves on, also after a restart.

**Fleet.** On every agent and signer. Before S7: a server-only provider's signer shows the zone owned and idle, and gains no key for it over a day; a run with no provider change shows no difference. With S7 (the check needs a refused serial): the owner takes a signer out of `signers=`, refused until S17b: every signer acts by the active serial, the leaving one keeps signing, no DNSKEY RRset changes and the parent's DS stays. Then restart that provider's combiner and signer: nothing changes. No bogus sample.

**Done when** the fleet checks pass.

**Size.** 16 files, about 430 new and 150 changed lines.

### S12. The reconciliation core

**Before it:** S9, S10, S11.

**Changes.**

- New `v2/reconcile.go`: the step machine of the leader under V (design 3.3). From the two readings and what is in place it plans the steps: additions, then role changes, then removals (design 5), each kind's steps from its runner (S16 to S21 register them), and last, "every voting member's combiner and signer hold V". When a leaving provider is excused (S7, or below), its NS step comes before any addition's DNSKEY step; every leaving signer that serves nothing, excused or not, has no NS step and leaves `KeyConfirmers` at the first step (design 5; S13). A new leader plans again from what is in place, removals under way included.
- **Step 0.** Until the leader's first step, the parts keep the sets they hold, for every purpose of design 3.5, `nsmgmt` and `parentsync` among them: N's (S2 keeps them). A thaw never hands a serial's lists at once. The sets name each provider by label and identity, fixed when the step that made them was taken (S3). Groups, admission and discovery follow the activation (S3). Each agent hands its parts V with step 0's sets at its activation, and runs `onSetsChanged` at every step.
- The step travels in the leader's stamp: the step's number and its sets per purpose, with their digest (7.3), step 0 included, and for each removal under way the leaving provider, its label and identity, and its NS names (design 5.2). Each agent stores the step and its sets (S2), hands its parts the step's view (S10, S11), and tells "step k held" in its own stamp once both parts hold it. The leader counts these from the members' own stamps only. An agent that restarts during the reconciliation, or that moved straight to V (S2), hands its parts nothing new until it has the current step's sets from the leader's stamp. The leader keeps its step, and what it needs to plan again, on disk.
- **The removals in every stamp** (design 3.3, rule 4). Each agent keeps the removals on disk from the leader's first-hand steps (S2), and tells them in its own stamp (`Removals`, S5a), each with the step it holds. An agent that missed a removal's end drops it when the leader's first-hand stamp shows the transition done (S2's `Done`). A leader without the state, after a lost store, takes it from the voting members' first-hand stamps: the leaving provider, its label and identity, its NS names, and the furthest step a member holds; it then plans from there and from what is in place (S17b).
- **The excusal during the reconciliation** (design 3.2). A leaving member that has not confirmed a step for `leaving-timeout` (S7), counted from when the step was sent, is excused from then on: the planner plans the rest as for an excused member (its NS step first, if it has not been taken), no later step waits for it, and S7's rule for paused rollovers applies. The leader under V is never a provider that V takes away (design 3.2), so a leaving leader is no case here.
- **Every DS and DNSKEY step waits for an emergency rollover** (design 3.3), of an addition or a removal; the others do not. A runner marks its DS and DNSKEY steps; the planner holds such a step while S5a's predicate reports an emergency rollover at any voting member. No step waits for a rollover paused only on excused members (design 3.2): the planner, and every wait of a step on a rollover, skip one whose `WaitsOn` (S11) names only excused members.
- **Members with no role are waited for with a time-out** (design 4). A distribution, a step, and the leader's NOTIFY for its CSYNC wait for a member with no role, on its way in or out, up to the configured time, then go on with one log line naming who did not confirm. `delegationCsyncProgress` (`ec1c6b3:v2/mp_s5_leader_csync.go:271-373`), which today waits "with no time-out" (`:46-50`), and the DNSKEY tracking (`TrackDnskeyPropagation`, `v2/hsync_transport.go:2189`; `outcome`, `:2240-2270`) split their awaited sets into voting members and members with no role, with a timer at the time-out. The one exception, another signer's new DNSKEY while a leaving provider is still delegated to, is S17b's. The auditor confirms at once (S8).
- **A newer serial during reconciling waits until "done"** (design 3.3: one transition at a time). Agents hold it (S2) and tell it as their newest; the steps go on by V's plan, which the newer serial does not change; nothing of the newer serial is agreed or thawed (S7's `thawReady` needs the transition done). So no thaw lands inside a reconciliation, and a removal is never interrupted.
- **"Done"** when the last step is held by every voting member under V, by every member with no role or its time-out, and with no wait for a leaving member that is excused (design 3.3). The leader's stamp says done, first hand, and every agent's after it has heard; the status and the auditor show "at V, done". Then the store drops the from-serial, the step and the removals (S2), the sweep runs (S17b; 7.2), S6's `instrDone` releases the owed list, and a newer serial that waited is judged (S4) and agreed (S7).
- No new rollover starts until done (S6's hold stays through reconciling); an emergency one may.
- The predicate S6 asks: a step's own distributions and syncs pass the freeze.
- Until a runner exists, a transition has only its last step.

**Names.** Config, proposed: `multi-provider.transitions.no-role-timeout`, in seconds, default 900, wherever S7's key is. Status:

```
  instructions:   reconciling 41->42: step 2 of 3 (withdraw the NS of agent.charlie.example.), waiting for agent.bravo.example.
  instructions:   reconciling 41->42: step 0 (the sets held), waiting for the leader's first step
  instructions:   reconciling 41->42: step 2 of 3; 43 held, waits until done
  instructions:   at 42, done since 15:10:00
```

Log, info, logger `zones`: "transition step sent" (`zone`, `step`, `what`); "transition done" (`zone`, `serial`); warn "a member with no role did not confirm in time, going on" (`zone`, `member`, `what`); info "a leaving member that has not confirmed a step is excused" (`zone`, `member`, `step`, `since`); info "a DS or DNSKEY step waits for an emergency rollover" (`zone`, `step`, `provider`); info "a newer serial of the zone's instructions waits until the transition is done" (`zone`, `serial`).

**Tests.** Unit: `TestATransitionWithNothingToCarryOutIsDoneWhenEveryPartHoldsIt`, `TestDoneWaitsForEveryVotingMembersParts`, `TestUntilTheFirstStepThePartsKeepTheSetsTheyHold`, `TestAtTheThawThePartsKeepTheFromSerialsSets`, `TestNsmgmtAndParentsyncChangeOnlyAtAStep`, `TestStepZeroIsInTheLeadersStamp`, `TestEveryAgentKeepsTheRemovalsFromTheLeadersSteps`, `TestEveryMemberTellsTheRemovalsItHoldsWithTheStepItHolds`, `TestAnAgentThatMissedTheEndDropsTheRemovalOnTheLeadersDone`, `TestALeaderWithoutTheStateTakesItFromTheMembersStamps`, `TestALeavingMemberThatDoesNotConfirmAStepIsExcusedFromThenOn`, `TestAnAgentThatMovedStraightTakesTheSetsFromTheLeader`, `TestARestartedAgentHandsNothingNewUntilItHasTheStep`, `TestTheStepSurvivesARestart`, `TestAMemberWithNoRoleIsWaitedForWithATimeOut`, `TestANewcomerWhoseAgentIsNotRunningHoldsNothingUp`, `TestAnExcusedLeavingMemberIsNotWaitedFor`, `TestTheAuditorIsNotWaitedFor`, `TestStepsAreOrderedAdditionsRoleChangesRemovals`, `TestAnExcusedLeaversNSStepComesBeforeAnAdditionsDNSKEYStep`, `TestEveryDSAndDNSKEYStepWaitsForAnEmergencyRollover`, `TestOtherStepsDoNotWaitForAnEmergencyRollover`, `TestNoStepWaitsForARolloverPausedOnlyOnExcusedMembers`, `TestTheLeaderPlansFromWhatIsInPlace`, `TestANewLeaderPlansAgainFromWhatIsInPlace`, `TestANewerSerialDuringReconcilingWaitsForDone` (the steps go on unchanged, nothing of it is agreed), `TestTheWaitingSerialIsAgreedAfterDone`, `TestAStepIsConfirmedOnlyByTheMembersOwnStamp`, `TestAStepIsConfirmedOnlyWhenTheCombinerAndSignerHoldIt`, `TestTheCSYNCNotifyGoesOnWithoutAMemberWithNoRoleAfterTheTimeOut`, `TestTheCSYNCNotifyWaitsForEveryVotingMember`, `TestDoneReleasesTheOwedList`, `TestDoneDropsTheFromSerialAndTheRemovals`, `TestNoRolloverStartsBeforeDone`, `TestTheNoRoleTimeOutIsReadFromTheConfig`. Harness: `TestTransportBoundary_AStepIsHandedAndConfirmed`, on `notifyRig`: a stand-in leader announces a step, and the agent confirms only after its combiner's confirmation and its signer's inventory.

**Fleet.** On every agent, combiner, signer and the auditor. An edit of `suffix` with a raised serial: "done" shows only after every provider's combiner and signer report the new serial, and the auditor shows it. One provider's combiner stopped: no "done" until it is back. A second `suffix` edit before "done": every agent holds it and tells it as newest, the first transition's steps go on unchanged to "done", and only then is the second agreed, thawed and done.

**Done when** the fleet checks pass.

**Size.** 13 files, about 545 new and 105 changed lines.

### S13. Steps reach the parts; the DS set follows the step

**Before it:** S12. PR #208, whose two readers read the step here.

**Changes.**

- `rolesFor(from, to, step)` fills each step's sets per purpose (design 3.5, 5.2). A leaving provider leaves:
  - `Servers` at its NS step;
  - `KeyConfirmers` within its NS step, once the NS TTL has passed, counted from when the parent no longer names its nameservers (design 5.2 step 2). Every leaving signer that serves nothing has no NS step, since nobody is delegated to it, and leaves at the reconciliation's first step, excused or not (design 5);
  - `DSSigners` at its DS step, so its DS and its CDS go together (design 5.2 step 3);
  - `KeySigners` and `Signing` at its DNSKEY step.

  With no step, every set is the one the parts hold (S2, S12); at rest every set is the active serial's list.
- The hand-over (S10, S11) carries the step's sets. A leaving provider's own agent hands its signer "keep signing" until the DNSKEY step (design 5.2).
- The DS readers take `DSSigners`: `computedDSIntent` (`ec1c6b3:v2/mp_s5_computed_ds.go:112-240`, signers at `:122`) and PR #208's `foreignDSWithheld` at the leader; and the agent's `MPKeyLifecycleOwner.DSIntent` (`57ca7a6:v2/mp_key_lifecycle_owner.go:188`), the set the explicit sync hands the parent. Its hold-back (`foreignDSCheck`, PR #208) keeps another provider's DS only while that provider is in `signers=` and its key states disagree with the inventory, so the edit that takes a signer out of `signers=` drops its DS at once. A rig run on 2026-10-19 (parent-leave, X2, on PR #216) showed it: the parent applied the NS removal, and the leader deleted the leaving signer's DS 7 s later, before the NS TTL; the DS chain was broken for most samples. That is #200 item 4, part of #138, on main. Under this step the provider stays in the step's `DSSigners` until the removal's DS step (S17b), so its DS stays in the set by the set, not by key states. Test: `TestALeavingSignersDSStaysUntilTheDSStep`, from that run's sequence; `foreignDSFor` through the signer's wire at the owning signer (`v2/mp_key_lifecycle_engine.go:45-112`; `v2/mp_key_lifecycle_foreign.go:43-49, 146-148`). `syncForeignDNSKEYs`' others and the multi-signer flag (`v2/signer_keydb.go:88`) take `KeySigners`, and PR #208's `foreignKeyWithdrawn` reads "the agent no longer lists the provider in `KeySigners`". `otherSignerLabels` and `signingAgents` (`v2/hsync_transport.go:2218-2229`) take `KeyConfirmers`, by the identities it names (S3).
- The CDS has two carriers today: a contribution at the combiner (`ec1c6b3:v2/combiner_utils.go:32`) and the signer's DS engine, woken from the key rows (`v2/mp_key_lifecycle_engine.go:221-230`; tdns `3615261f:v2/ds_engine.go`). Not established which a given deployment uses; both follow `DSSigners` (S10's rebuild, and the signer's foreign rows).
- For a zone the leader's own signer owns, the DS set is that signer's inventory: the leader counts the DS step held only once that inventory reports the step.
- A joining signer's DS follows its key states, as today.
- With this step S11 and S13 close #147: a provider taken out of `signers=` keeps signing until its DNSKEY step. They replace #275's interim: its signing set, its keystore table and the key machines' pause go here.

**Names.** Status: the step's sets per purpose, at the leader and at each agent.

**Tests.** Unit: `TestEachStepsSetsAreHandedToBothParts`, `TestALeavingSignerSignsAndAppliesUntilItsDNSKEYStep`, `TestALeavingSignersDSStaysInTheComputedSetUntilTheDSStep`, `TestALeavingSignersCDSLeavesAtTheDSStep` (both carriers), `TestAKeyConfirmerLeavesOnceTheNSTTLHasPassedSinceTheParentDroppedItsNames`, `TestEveryLeavingSignerThatServesNothingLeavesTheConfirmersAtTheFirstStep` (excused or not), `TestAnOwningSignerKeepsALeavingSignersDSUntilTheDSStep`, `TestTheDSStepWaitsForTheSignersInventoryAtThatStep`, `TestTheLastSignerLeftKeepsTheLeavingSignersKeysUntilTheDNSKEYStep` (#138), `TestAtRestTheSetsAreTheActiveLists`, `TestAJoiningSignersDSFollowsItsKeyStates`, `TestForeignKeyWithdrawnTakesTheAgentsList`.

**Fleet.** On every agent, combiner and signer. A run with no provider change shows no difference. The order of the DS is checked with S17b.

**Done when** the fleet run shows no difference.

**Size.** 11 files, about 305 new and 130 changed lines.

### S14. The zone's SIG(0) key

What is left of the key part of the membership plan's step 9, under this design (design 6). Membership step 7b (membership decision 46, 2026-10-19) builds the rest before this plan starts: every voting member holds the zone's key (`zoneKeyHeld`, `zoneUsesKey`, one active key per zone, `keyCheck` and the `keyWanted` rounds in place of PR #185's `zoneKeyWaits`, `zoneKeyPeers` with PR #217's `roleLessKeyHolders`), the holder hands over the key the zone publishes, a key is made only when every agent asked says "no key here" and the zone publishes none, a lost key is reported and not replaced, the election waits for the key before it asks for the sync, and the `DELEGATION-SYNC-SETUP` arm does nothing for a multi-provider zone. Membership step 6 judges the asker by the sender the transport established. This step does not repeat any of that.

**Before it:** S8 (a key answer is judged by its stamp), S9. Membership steps 4 to 7b. Merged: PRs #185, #198, #213 and #217 (as membership step 7b lists them). Every key set-up of a zone runs under PR #185's per-zone lock `inKeySetup`, which took the place of PR #209's in `SetOnLeaderElected`; from membership step 7b `keyWanted`'s rounds take it too. tdns-mp #206 (the at-ns KEY published only under the leader's nameservers), fixed here or before (7.1).

**Changes.** What this design adds to membership step 7b:

- Who is asked: during a transition, every voting member under both serials (design 6), besides step 7b's `zoneKeyPeers`.
- A key answer counts only when it carries the asker's active serial; a round starts over when the active serial changes.
- While `syncHeld` holds (S6), `leaderKeySetup` holds three things only: the decision that no key exists (it returns `errZoneKeyNotHeld`, as membership step 7b has it before the zone is caught up; the moved step 9's case 1), the KEY's publication, and the offers. Asking for the key and using a key it holds go on (design 3.1). The hold until the zone is caught up is step 7b's.
- `keyPending(zone)`: true while this agent leads the zone, `zoneUsesKey` says yes, and this agent holds no key, or holds one whose `parent_state` (which tdns writes) says the parent does not trust it yet. While it is true, every sync the leader asks for, the election's included, is held (`syncHeld`, S6), and tdns asks for it when the parent trusts the key (`ParentSyncAfterKeyPublication`). For a zone whose parent takes no UPDATE nothing is held for the key. Step 7b's election waits only until the key is held; this waits until the parent trusts it.
- The offers again. At the leader, `keyWanted` (membership step 7b) is kept until the key is usable (`keyPending` false), not dropped when the key is held, and its rounds call `ParentSyncAfterKeyPublication` again, at most every 5 minutes, under the zone's parent context (S7). The roll has a schedule of its own (S17a).
- **The key's offers and bootstrap pass the freeze while a rollover under way waits on `keyPending`** (design 3.1, 6): the rollover's DS sync waits for the key, so holding the offers would leave the rollover and the thaw waiting for each other. Otherwise the offers and the bootstrap are held during a transition, except as a step (S17a, S20).
- **The KEY record is the group's.** The KEY is taken from the leader only (`refuseCsyncNotFromLeader`, `ec1c6b3:v2/mp_s5_leader_csync.go:434`, asked for the KEY too). That a member then drops a KEY held under another name, which closes what membership step 7b leaves "still not covered" (an apex with several KEY records), is S17a's: it needs S16's combiner flag. Until S17a, step 7b's fleet precondition stays in force: each zone with `parentsync=agent` publishes one KEY. Which of several published KEYs is the zone's key, and what a leader whose held KEY the parent refuses does, are decided (decisions 98 and 99).
- **Only the leader's catch-up answer names the zone's KEY.** It takes it from its keystore: the active key whose KEY record the zone publishes (`zoneKeyHeld`). It does not take it from its data repo (`ZoneDataRepo`, `ec1c6b3:v2/sde_types.go:76`), which never holds what `leaderKeySetup` published: that goes to the combiner and to the peers directly (`EnqueueForCombiner` and `EnqueueForZoneAgents`). A member's answer never names the KEY. Until S14 no catch-up answer names it: that is membership decision 27, and each asker keeps the KEY it holds until then.
- A lost key while the zone publishes its KEY stays a stall for the operator, with status `LOST`, until the recovery (7.4). Membership step 7b reports it; this step gives it the status.
- The wait before a new key's bootstrap, until the zone's nameservers serve the key, is tdns's now: tdns PR #933 (#917's child side), pinned since tdns-mp PR #219. So the moved step 9's own wait, and its test `TestANewKeyIsBootstrappedOnlyAfterThePropagationDelay`, go.
- Readiness findings handed to this plan: N7 (the previous leader is noted only when the zone lands in another group) is void with PR #217, which asks every agent the zone lists ON with no role. N8 (a key imported at the leader goes on at once to the publication and the inquiry, the moved step 9's case 2) is membership step 7b's path: `keyCheck` at the leader runs `leaderKeySetup`, and the round that ends with the key held asks for the sync once. It is checked with step 7b, and read against step 7b's `leaderKeySetup` when this step starts. N14 is void under the serial.

**Names.** Status in `agent parentsync status`: `SIG(0) key: LOST`, and "SIG(0) key: new key 5012 made and offered; the parent has not taken it yet" while the parent has not taken the key. Log, info, logger `agent`: "the parent has not taken the zone's SIG(0) key, offering it again" (`zone`, `keyid`, `parent_state`, `in`), at each offer. Membership step 7b's log lines are kept. The ask status (who was asked and what each answered), the line for a key made when nobody holds one and the zone publishes none, and the line for the skipped `DELEGATION-SYNC-SETUP` arm are step 7b's.

**Tests.** Unit, new: `TestTwoLeadersNeverBothMakeAKey` (decision 101), `TestAKeyAnswerFromAnotherActiveSerialDoesNotCount`, `TestTheKeyRoundStartsOverAtAChangeOfActiveSerial`, `TestDuringATransitionTheKeyIsAskedOfVotingMembersUnderBothSerials`, `TestTheKeyOffersAreHeldDuringATransition`, `TestTheKeyOffersPassWhileARolloverWaitsOnKeyPending`, `TestTheSyncIsHeldUntilTheKeyIsUsable` (the election's sync included), `TestANotifyOnlyParentIsNotHeldForAKey`, `TestAKeyThatTheParentHasNotTakenIsOfferedAgain`, `TestAKEYIsTakenFromTheLeaderOnly`, `TestOnlyTheLeadersAnswerNamesTheKEY`, `TestTheLeadersAnswerTakesTheKEYFromItsKeystoreNotItsData` (a KEY published by `leaderKeySetup` and absent from the data repo), `TestALostKeyShowsLOST`. Membership step 7b's key tests stay green. Four tests of the moved step 9 belong with membership step 7b, which builds what they test: `TestAnAnswerOfAnEarlierRoundDoesNotCount`, `TestTheAnswersStartOverWhenTheVotingMembersChange`, `TestTwoKeysAnsweredAtOnceImportOne` and `TestAMembersKeyIsTheZonesKeyWhenTheZonePublishesNone`. `TestAMemberThatDoesNotVoteAsksForNoKey`, for a member with no role, belongs with S15.

**Fleet.** On every agent. A zone with two signers whose lead moves to the other signer by a numbered edit: the KEY at the apex is the same, and the parent accepts the next UPDATE. A KSK rollover at a newly elected leader whose key the parent does not trust yet, during agreeing: the key is offered, the parent takes it, the rollover's DS follows, then the thaw. A lost key, set up as step 7b's fleet has it (the key deleted by hand from every keystore, the KEY still published): the status says `LOST`, nothing is offered, and the sync stays owed.

**Done when** the fleet checks pass.

**Size.** About 7 files, 120 new and 45 changed lines. Membership decision 46 moved the rest of what this step had, about 155 new and 45 changed lines, into membership step 7b; it is counted there, not in this plan's totals.

### S15. The switch: every HSYNC3 provider is a member

The membership plan's step 10 (#158), under this design.

**Before it:** S12 (the time-out for members with no role), S14. Membership steps 1 to 8 on every agent.

**Changes.**

- `zoneParticipants` takes the active reading (S3) and returns three sets: the members, the voting members and the auditors. `AuditorsForZone` reads the third.
- The members are every ON record of the active serial, and every provider whose removal is under way by the removals on disk (S2, S17b), whatever its record says, under the removal's stored identity (design 3.3; S3's resolvers, `isInHSYNC` among them). It stays a member, with no role, until its removal is done. Until S17b no removal exists, so the clause has nothing to read.
- `ZoneAgentData` gets each agent's standing; `RecomputeGroups` fills membership step 8's third list.
- `zone mplist` gets the `NoRole` and `This` columns; `agent parentsync status` the standing and the leader learned from gossip.
- `onActiveChanged` logs once when the local standing becomes "no role".
- An agent that knows no leader yet keeps a CSYNC, or the leader's KEY, on the kept list (S6) and judges it once it learns the leader: at the election update (`ApplyGossipElection`) or at the end of a lease. At a member that does not vote, once the leader it knows is the sender, or the earlier lease has run out.
- Admission, discovery, beats, distributions and catch-up follow from the first change. From this step a member with no role is a recipient, waited for with S12's time-out.
- PR #217's admission for the key alone (`keyHandOverAdmits`, enforced by `keyHandOverGate`), which membership step 7b uses for a provider listed ON with no role, becomes ordinary admission: such a provider is a member from this step. `keyHandOverGate` is retired, or narrowed to what admission still refuses, as the reading of the code shows when this step starts. `roleLessKeyHolders` reads this step's members with no role, not the zone's HSYNC3. PR #217 leaves two points to this plan: a record turned OFF or removed must lead to a roll of the key, since the leaver still holds it (S17a, started by S17b); and a no-role identity that the agent registry does not hold is skipped by #217's ask rather than counted as unanswered.
- Membership step 7's gate. Until this step it asks for a role, as admission does (membership decision 31), so comms end on both sides for a provider whose roles are gone and whose record stays. This step puts the ON-record test back in step 7's gate as well as in admission.
- Leadership stays with the voting members. Membership decision 34: `IsLeader` reads false for a zone with HSYNC3 in which this agent does not vote, so an agent whose roles are gone leads no more at once. A member with no role is a member here and still leads nothing.

**Names.** As the membership plan's step 10: the `mplist` columns, the status lines, and the log line "an HSYNC3 record and no role: member, no vote, no edits".

**Tests.** From the membership plan's step 10: the `RoleLessRejected` case becomes `MemberWithNoRole`; `TestApplyHsyncDiff_offRecordExcluded`; `TestApplyHsyncDiff_memberWithNoRoleRegistered`; `TestMembersVotingMembersAndAuditorsOfAZone`; `TestADistributionWaitsForTheAuditor`; `TestAMemberWithNoRoleIsAnsweredTheTransferSetUp`; `TestAMemberThatKnowsNoLeaderYetKeepsTheCSYNC`; `TestAMemberThatKnowsNoLeaderYetKeepsTheLeadersKEY`; `TestTheKeptCSYNCIsJudgedWhenTheLeaderIsLearned`; `TestAnObserverKeepsTheNewLeadersCSYNCUntilTheEarlierLeaseRunsOut`; `TestAnObserverKeepsTheNewLeadersKEY`; `TestAnEntryKeptForTheLeaderDoesNotHoldTheZonesOtherDistributions`; `TestACatchUpAnswerWithTheLeadersCSYNCIsKeptWhole`; `TestAMemberWithNoRoleIsNoAuditor`; `TestAZoneWithAMemberWithNoRoleIsInAGroupOfItsOwn`; `TestMplistShowsEachMembersStanding`. New: `TestMembershipIsReadFromTheActiveInstructions`, `TestAProviderWhoseRemovalIsUnderWayStaysAMemberWhateverItsRecordSays`, `TestAProviderWhoseRemovalIsUnderWayIsAdmittedUnderItsStoredIdentity`, `TestAMemberWithNoRoleIsWaitedForWithTheTimeOut`, and from the moved step 9 `TestAMemberThatDoesNotVoteAsksForNoKey`, for a member with no role. Harness: `TestTransportBoundary_MemberWithNoRoleCatchesUp`.

**Fleet.** On every agent and the auditor. The owner adds a provider's record, with a raised serial: agreeing, the thaw, and "done" once every part holds the serial (the newcomer's after the time-out, if its agent is not running). The newcomer is in every agent's gossip, reports the leader, has caught up, and has its `add-rr` refused. No sample is bogus or lame.

**Done when** the fleet check passes.

**Size.** 10 files, about 140 new and 165 changed lines.

### S16. The leader's withdrawal

**Before it:** S8 (stamps and rule 6), S10 (the combiner's filter by role), S15 (the leaving provider is a member with no role and a recipient). Membership steps 3 and 6.

**Changes.** (Design 5.2, "The withdrawal".)

- On the wire: a field on membership step 3's sync wrapper, proposed `withdraw: {provider, rrtype}`. The update carries one operation: an empty `replace` of NS, DNSKEY or CDS. Glue is not a contribution (`ec1c6b3:v2/combiner_utils.go:29-38`). The message's sender is the leader, so step 6's middleware passes it.
- At a receiving agent: `routeSyncMessage` sets the update's agent to the named provider, `DeliveredBy` to the leader, and marks it a withdrawal. After S8's rule (a withdrawal made under an older active serial is refused as stale, one made under a newer one is kept: rule 6), proposed `acceptWithdrawal`: the deliverer leads the zone's group under the active serial; the active instructions do not list the provider in `servers=` for NS, in `signers=` for DNSKEY and CDS; a `replace` that carries records, or any other operation, is refused. A member that knows no leader yet keeps it (S15). `noteReplaceOrigin` (`v2/agent_policy.go:27-41`) is not asked. `PendingRemoteConfirms` (`v2/syncheddataengine.go:346-357`) names the deliverer, so the confirmation goes to the leader.
- The order (design 5.2): withdrawals and a provider's own operations are ordered by the active serial stamped at their send (rule 6), then by their creation time, which the payload carries (`ec1c6b3:v2/hsync_transport.go:1933`), at the combiner (`staleCombinerReplace`, `v2/combiner_chunk.go:1539-1553`, its caller `:1036-1046`) and at the agent (`processReplaceOp`, `v2/agent_policy.go:457-475`).
- **The combiner applies a removal in any origin's name that its own agent delivers** (design 3.5): a delete, or a `replace` whose records are a subset of what that origin holds. Such a removal passes membership step 6's rule that the named origin must vote, and the KEY and CDS de-duplication. A `replace` that adds a record, even a smaller one, is judged as before. This is the one place that relaxes step 6's combiner rule. To the combiner the agent sends the withdrawal in the provider's name, with a flag honoured only from the combiner's own agent.
- At the leader, new `v2/withdrawal.go`: `sendWithdrawal` marks the provider's records as pending removal and sends to its own combiner and to every member; `withdrawalDone` reads the tracking, with S12's time-out for members with no role. A new leader, planning again from what is in place (S12), sends a withdrawal again if its plan still calls for it; one refused as stale is sent again by rule 6 if the active instructions still call for it.
- The leaving provider's NS names are not taken from the withdrawal: every agent keeps them from the leader's first step (S12, S17b).
- A debug command, `agent debug withdraw`, refused unless this agent leads and the acceptance holds here.

**Names.** Log, info, logger `engine`: "withdrawing another provider's records" (`zone`, `provider`, `rrtype`); "a withdrawal is refused" (`zone`, `provider`, `rrtype`, `why`).

**Tests.** Unit: `TestAWithdrawalIsTakenFromTheLeaderOnly`, `TestAWithdrawalOfAListedProviderIsRefused`, `TestAWithdrawalWithRecordsIsRefused`, `TestAWithdrawalStampedAheadIsKeptUntilTheActiveSerialCatchesUp`, `TestAWithdrawalStampedBehindIsRefusedAsStale`, `TestANewLeaderSendsAWithdrawalAgainWhenItsPlanCallsForIt`, `TestAWithdrawalIsNotStaleByTheLeadersClock`, `TestAReplaceAtAHigherSerialWinsOverTheLeadersWithdrawalWhateverTheClocks`, `TestAReplaceAtALowerSerialIsStale`, `TestARemovalInAnyOriginsNameFromItsOwnAgentIsApplied` (a delete, a subset `replace`), `TestASmallerReplaceThatAddsARecordIsRefused`, `TestAWithdrawalPassesTheCombinersOriginChecks`, `TestTheCombinerTakesTheFlagFromItsOwnAgentOnly`, `TestTheConfirmationOfAWithdrawalGoesToTheLeader`, `TestTheLeavingProviderAppliesTheWithdrawalOfItsOwnRecords`, `TestAMemberThatKnowsNoLeaderKeepsAWithdrawal`, `TestWithdrawalsAreOrderedByTheStampAtSendThenTheCreationTime`, `TestWithdrawalDoneReadsEveryRecipient`. Harness: `TestTransportBoundary_AWithdrawalReachesTheRecipientsCombiner`, on `notifyRig`.

**Fleet.** On every agent and combiner, with S17b: a removal is refused until then (S4), so no provider is out of `servers=` while still a member.

**Done when** the unit and harness tests pass; the fleet check passes with S17b's.

**Size.** 12 files, about 265 new and 125 changed lines.

### S17a. The leader's roll of the zone's SIG(0) key

**Before it:** S14, S16 (the combiner's flag, for the KEY purge), S7 (the parent context). Membership step 7b: one active key per zone, `zoneKeyHeld`, `keyCheck`, and the import that retires the other key, which the roll's phases have to fit (below). A fleet test of a roll designed first: a roll has never been run in tdns-mp (membership decision 22).

**Changes.**

- New `v2/parentsync_roll.go`: the leader's roll, built from tdns's exported pieces (`LookupDSYNCTarget`, `Sig0KeyMgmt`, `CreateUpdate`, `SignMsg`, `SendUpdate`). tdns's `RolloverSig0KeyWithParent` (`3615261f:v2/ops_key.go:325`) cannot be used: each call makes a new key, so its phases cannot be resumed, and it publishes through `PublishKeyRRs`, not through the combiner. In order:
  1. a new key at the leader, kept `published` (tdns `3615261f:v2/structs.go:64`), not active: the leader keeps one active key (membership step 7b), and tdns reads only one (`v2/keystore.go:1199-1272`);
  2. the add at the parent, signed with the old key;
  3. once a KeyState inquiry shows the parent has taken it, the new KEY published as the leader's `replace` (S14);
  4. the voting members ask for it (`keyCheck`, membership step 7b) and import it, which retires the old one there. While the roll is between steps 3 and 5, the leader's `zoneKeyHeld` names the `published` new key whose KEY the zone publishes, the holder hands that key over, the leader's `keyCheck` runs no set-up, and nothing is retired at the leader;
  5. after the KEY's confirmations, members with no role with the time-out: the new key made active and the old one retired at the leader, then the delete of the old key at the parent, signed with the new key.
- The roll's phase and its new key's name are kept on disk, so a retry after a restart resumes.
- The roll is the zone's obligation, not a gate (design 5.2): started by S17b, retried on a schedule of its own until it succeeds (at the leader `keyWanted` is dropped once the key is usable, membership step 7b and S14, so its rounds do not carry the roll), shown in the status. Held while the zone is frozen, except as a step. A failed add leaves the old key in use; a failed delete is retried, and the parent trusts both keys until then.
- A member keeps the leader's KEY and no other: on taking the leader's KEY it drops a KEY held under another name, in its data and at its combiner, by a flagged purge (the third KEY item of the membership plan's step 9).
- The delete of a key at the parent is a function of its own; S20 uses it.
- First caller: `agent zone dsync roll-sig0-key` (`ec1c6b3:v2/cli/agent_zone_cmds.go:271-305`), for a multi-provider zone this agent leads.

**Names.** Status: "SIG(0) key: rolling: new key 5012 added at the parent, waiting for the members"; "SIG(0) key: roll owed, next try at 15:20". Log, info, logger `agent`: "rolling the zone's SIG(0) key" (`zone`, `phase`, `old`, `new`); warn "the roll of the zone's SIG(0) key failed, trying again" (`zone`, `phase`, `in`).

**Tests.** Unit: `TestTheRollAddsTheNewKeySignedWithTheOld`, `TestTheNewKeyIsNotActiveAtTheLeaderBeforeStepFive`, `TestTheNewKEYIsPublishedOnlyAfterTheParentHasTakenIt`, `TestTheOldKeyIsDeletedWithAnUpdateTheNewKeySigns`, `TestEveryVotingMemberHoldsTheRolledKey`, `TestAMemberWithNoRoleIsNotHandedTheRolledKey`, `TestAMemberKeepsTheLeadersKEYAndNoOther`, `TestAFailedAddLeavesTheOldKeyInUse`, `TestAFailedDeleteIsRetried`, `TestAFailedRollIsRetriedOnItsOwnSchedule`, `TestTheRollResumesAfterARestart`, `TestARollIsHeldWhileTheZoneIsAgreeing`, `TestTheRollCommandOnAnMPZoneTakesThisPath`.

**Fleet.** On every agent and combiner. Three voting members and a tdns parent that takes UPDATE; a roll by the command. The parent accepts the leader's next sync and refuses an update signed with the old key. Every voting member holds the new key active and the old one retired; the apex has one KEY. The leader stopped: the new leader's first sync is accepted. An apex that carried two KEY records before: after the next leader's publication every member holds the one KEY the leader publishes.

**Done when** the fleet check passes.

**Size.** 8 files, about 270 new and 70 changed lines.

### S17b. The removal, and the sweep

**Before it:** S13, S15, S16, S17a.

**Changes.**

- New `v2/reconcile_remove.go`: the runner for a transition that takes a provider out of `servers=`, `signers=` or both (design 5.2), registered with S12's planner. It lifts S4's `not-built` for a removal. It plans from what is in place. The provider stays a member, with no role, until its removal is done (S15), and its own agent hands its signer "keep signing" until step 4. The leader's first step names the leaving provider's NS names: those it tells in its stamp (S5a's `Nameservers`), and those the parent's NS RRset holds for it at the removal's start (`AnalyseZoneDelegation`, `ec1c6b3:v2/delegation_sync.go:66, 124`; how a name is known to be its, 7.2). They are not taken from the leader's data (design 5.2). Every agent keeps them on disk with the removal's state, from the leader's first-hand steps, and tells them in its stamp (S2, S12). A new leader goes on with the removal from that state; a leader without it takes it from the members' stamps (S12). Then:
  1. If the provider voted and the zone uses a key, start the roll (S17a): an obligation, not a gate.
  2. If it leaves `servers=`: under `nsmgmt=agent`, withdraw its NS (S16) and wait for the confirmations; under `nsmgmt=owner` withdraw nothing: the owner has dropped the names from its own NS RRset in the edit that took the server role away (design 5.2, 3.7). Then ask the explicit sync and watch the parent until its NS RRset no longer names the stored names. From then, when the larger of the parent's and the zone's NS TTL, plus the propagation delay (`delegationNotifyWait`), has passed, the provider leaves `KeyConfirmers` (S13), and a rollover paused on it resumes. That leave is part of this step: the step's own hand-over, which passes the freeze (S6, S12). Under `nsmgmt=owner` an NS RRset of the owner's that still names the stored names holds the step, safely, and the status says so (S19's report, once S19 is in).
  3. If it leaves `signers=`, waiting for an emergency rollover (S12): the step's `DSSigners` drop it (S13), which withdraws its CDS at both carriers (the combiner's rebuild, and its DS engine at the owning signer) and, where its CDS is a contribution, an empty `replace` of CDS (S16); every member confirms that its parts hold the step; the leader syncs and watches the parent until its DS is gone. The CDS goes before the watch, so a parent that follows CDS does not keep the DS.
  4. Wait the parent's DS TTL, as last served, and the DNSKEY TTL. Then, waiting for an emergency rollover: withdraw its DNSKEY (S16); `KeySigners` and `Signing` drop it, and its own agent hands its signer no role: it stops signing.
  5. The removal is done: every agent drops it from disk, and the leaving agent shows "safe to remove". The transition is done when its other steps are (S12).
- Only steps 3 and 4 wait for an emergency rollover (design 3.3).
- A provider that leaves `servers=` only has no DS or DNSKEY step; a signer that does not serve has no NS step and leaves `KeyConfirmers` at the reconciliation's first step, excused or not (design 5; S13).
- **An excused leaving provider** (S7, or excused during the reconciliation by S12's rule): its NS step comes before any addition's DNSKEY step in the same transition (S12's planner), so that a new signer's DNSKEY does not wait for a member that cannot confirm; once its NS TTL has passed it leaves `KeyConfirmers` and the paused rollovers resume (design 5). No step waits for a rollover paused only on excused members (S12).
- Waiting for the leaving provider: S12's time-out, except another signer's new DNSKEY while the leaving provider is still delegated to, that is until the NS TTL in its step 2 has passed (design 5.2).
- Planning again, at a new leader, reads what is in place: the removals on disk with their NS names, or the members' stamps, the provider's records in the leader's data, and the parent's NS and DS. A wait whose start is not known starts now. No later serial is thawed while the removal is under way (design 3.3), so a plan never meets a newer serial's lists.
- New `v2/entitlement.go`, the sweep (design 3.3): when a transition is done, each agent drops from its data and from its combiner every contribution the active instructions do not entitle its origin to: NS needs `nsmgmt=agent` and the origin in `servers=`; DNSKEY and CDS need the origin in `signers=`; KEY and CSYNC are the leader's, once the leader's own is there. The combiner gets a flagged purge from its own agent, beside `PurgeContributionsForOrigin` (`ec1c6b3:v2/combiner_utils.go:1205`). Nothing goes to peers. It never runs while the zone is frozen (design 3.3); a removal ends within its transition, so none is under way at "done". At a "done" with a newer serial waiting, it runs, by V, before that serial's agreement starts (7.2). It catches a withdrawal lost to a restart (catch-up asks voting members only, so nobody answers for the leaving provider).
- The guide: `guide/provider-changes.md` section 4 rewritten; `guide/customer-zone-setup.md` 2.1 and `guide/data-changes.md` stop describing the purge by hand (#159 item 4). It says not to revoke the leaving provider's access to the zone before "done", and, under `nsmgmt=owner`, to drop the leaving provider's NS records from the owner's NS RRset in the edit that takes its server role away.

**Names.** Status: "reconciling 41->42: removing agent.charlie.example., step 2 (its NS), waiting until the parent no longer names ns1.charlie.example."; "reconciling 41->42: removing agent.charlie.example., step 2 (its NS), waiting for the NS TTL until 2026-10-20 15:00"; "reconciling 41->42: removing agent.charlie.example., step 3 (its DS), waiting until the parent no longer serves its DS"; "removing agent.charlie.example. (excused): its NS first"; at the leaving agent "safe to remove". Log, info, logger `zones`: "removal step" (`zone`, `provider`, `step`, `until`); logger `engine`: "swept a contribution its origin is not entitled to" (`zone`, `origin`, `rrtype`).

**Tests.** Unit: `TestARemovalWithdrawsNSThenDSThenDNSKEY`, `TestTheLeadersFirstStepNamesTheLeavingNSNames`, `TestTheLeavingNSNamesComeFromItsStampAndTheParentNotTheLeadersData`, `TestEveryAgentKeepsTheLeavingNSNamesFromTheLeadersFirstStep`, `TestANewLeaderTakesTheKeptNSNames`, `TestALeaderWithoutTheStateTakesTheRemovalFromTheMembersStamps`, `TestUnderNsmgmtOwnerTheLeaderWithdrawsNoNSAndWatchesTheParent`, `TestTheNSTTLCountsFromWhenTheParentNoLongerNamesTheNames`, `TestTheConfirmersLeaveIsPartOfTheNSStepAndPassesTheFreeze`, `TestTheDSIsNotWithdrawnBeforeTheParentDroppedTheNSAndTheNSTTLPassed`, `TestTheCDSGoesAtTheDSStep`, `TestTheDNSKEYsAreNotWithdrawnBeforeTheDSTTLPassed`, `TestTheRollStartsFirstAndDoesNotHoldTheRemoval`, `TestARemovalFromServersOnlyHasNoDSOrDNSKEYStep`, `TestARemovalOfASignerThatDoesNotServeHasNoNSStep`, `TestASignerThatServesNothingHoldsNoAdditionsKeys` (excused or not), `TestTheLeavingProviderSignsUntilItsDNSKEYsAreWithdrawn`, `TestTheRemovalNeedsNothingFromTheLeavingProvider`, `TestAnEmergencyRolloverHoldsOnlyTheDSAndDNSKEYSteps`, `TestAnotherSignersNewDNSKEYWaitsForTheLeavingSignerUntilItsNSTTLPassed`, `TestTheLeavingSignerLeavesTheConfirmersWhenItsNSTTLPassed`, `TestAnExcusedLeaversNSStepComesFirstAndItsPausedRolloversResume`, `TestALeaverExcusedDuringTheReconciliationIsPlannedAsExcused`, `TestANewLeaderPlansAgainFromWhatIsInPlace`, `TestAWaitWhoseStartIsUnknownStartsNow`, `TestASuffixEditDuringTheNSStepWaitsForDoneAndIsThenAgreed` (the removal's sets and steps do not change), `TestARecordEditDuringTheRemovalWaitsForDone`, `TestTheLeavingProviderIsToldSafeToRemove`, `TestALostWithdrawalIsSweptWhenTheZoneIsDone`, `TestNothingIsSweptWhileTheZoneIsFrozen`, `TestTheSweepRunsBeforeAWaitingSerialIsAgreed`, `TestAKEYUnderAnEarlierPublishersNameIsSweptOnceTheLeadersKEYIsHere`, `TestASweepSendsNothingToPeers`, `TestAnEntitledContributionIsNeverSwept`. Harness: `TestTransportBoundary_ARemovalsWithdrawalsReachEveryMember`.

**Fleet.** On every agent, combiner and signer. Three providers, two signing; first at a parent that takes UPDATE, then at one that takes NOTIFY only and follows CDS; one signer taken out of both lists, its record kept. No bogus or lame sample. The parent's NS loses it first; its CDS and DS go after the NS TTL; its DNSKEYs leave every DNSKEY RRset after the DS TTL; it signs until then and then shows "safe to remove"; the record's edit follows, and comms end after the hold time. Again with its agent stopped from the edit on, while a KSK rollover is under way at the other signer: the thaw comes once it is excused, the rollover pauses, resumes after its NS TTL, and the removal completes with the time-out logged. Again with its agent running but its transfer of the zone cut off: it is excused after the time, heard. Again with its agent stopped after the thaw, during the NS step: after the configured time it is planned as excused, and no later step waits for it. A swap of signers A and C for A and D, with C stopped: D's DNSKEY step follows C's NS step. Again with C a signer that serves nothing, once stopped and once running: C leaves the confirmers at the first step, and D's keys and an emergency rollover at A are not held. Again with a `suffix` edit during the NS step and an auditor edit during the DS wait: every agent holds each and tells it as newest, no part changes a set, the removal runs to "done", and then each edit is agreed, thawed and done. An edit that removes C's record before its removal is done: held until "done", then agreed. Again under `nsmgmt=owner`, at a parent that takes NOTIFY only, with C a server: the owner's edit drops C's NS from its NS RRset as it takes C's server role away; no agent withdraws an NS; the leader's CSYNC and NOTIFY go out; the step waits until the parent's NS RRset no longer names C's names (those C told, and those the parent held for it at the start), counts the NS TTL from then, and only then C leaves the confirmers; no lame sample. During the NS step, one remaining provider's agent and combiner restarted before the combiner applied the withdrawal: after "done" it serves the same NS RRset as the others. The leader replaced during the NS step: the new leader watches for the same names. The leader's store removed and the leader restarted during the DS wait: it takes the removal from the members' stamps and goes on. S16's debug withdraw from a non-leader, or for a listed provider, is refused at every member. A removal that moves the lead: the new leader holds the zone's key already (membership step 7b), the zone's KEY does not change before the roll, and the new leader runs the roll.

**Done when** the fleet checks pass.

**Size.** 14 files, about 675 new and 130 changed lines.

### S18a. A record, a server role, a provider put back

**Before it:** S13, S15, S16 (the order of a `replace` by serial).

**Changes.**

- The record (design 5.1): nothing to carry out; done once the parts hold the serial (S12). The newcomer catches up as a member with no role (membership 1 and 2), and every agent's status shows whether it has.
- New `v2/serving_check.go`: proposed `servingChainOK(zone, upstream, minSerial)`. It queries the provider's own nameservers, named in `multi-provider.local.nameservers` (`ec1c6b3:v2/multi_provider_conf.go:106-109`), through the IMR: the SOA serial is at least `minSerial`, and the RRSIGs are by the expected signers' keys. The agent's confirmation of the step carries the result: the transfer confirmation.
- The runner for a provider that enters `servers=` (design 5.1), which lifts S4's `not-built` for a server role: one step, held until the provider's agent confirms that its servers serve the zone from its upstream at an SOA serial no lower than the zone's. Its operator sets the transfer up (decision 6 of the membership plan has no asking half); past a time the status tells the operator what to point where. Its NS reach the zone and the parent last, by its operator (membership rule 7).
- A provider put back (design 5.1, #200 item 8): when a thaw gives a provider a list it was not in, after its records were withdrawn, its own agent sends a complete `replace` of the types it may now contribute (the catch-up answer's form), and every agent asks it for its state (`peer-role`, moved to the activation and widened in S3). This widens membership 5.1's `peer-role`, "given its first role". The combiner takes the contributions by the step's sets (S10). NS stays its operator's to add again.

**Names.** Status: "waiting for agent.delta.example.'s nameservers to serve the zone from its upstream at serial 2026101801 or later". Log, info, logger `zones`: "the transfer confirmation for the step" (`zone`, `provider`, `ok`, `serial`).

**Tests.** Unit: `TestARecordIsDoneWhenThePartsHoldIt`, `TestAServerRoleStepWaitsUntilTheProvidersServersServeTheUpstreamsCopy`, `TestTheServingCheckReadsTheSOAAndTheSigners`, `TestTheStatusSaysWhatTheOperatorMustPoint`, `TestAProviderThatEntersAListIsAskedForItsState`, `TestAProviderPutBackSendsItsContributionsAgain`, `TestAServerPutBackGetsNoNSUntilItsOperatorAddsThem`.

**Fleet.** On every agent. A server added in two edits (the record, then `servers=`), its NS added by its operator after "done": no bogus or lame sample; the newcomer had caught up before the second edit; the second edit's step waited until its servers served the zone. A server taken out and put back by later edits: it contributes again, and every agent asked it for its state.

**Done when** the fleet check passes.

**Size.** 6 files, about 190 new and 40 changed lines.

### S18b. A signer added; a server becomes a signer

**Before it:** S18a, S11, S12. P5. It lifts S4's refusal of a move into `signers=`.

**Changes.**

- The joiner's signer takes the zone, binds its policy (`bindPolicyForOwner`), makes its first keys and distributes them (`v2/mp_key_lifecycle_engine.go`), as a step of the leader's (design 5.1): the signer's hold stays on through the reconciliation (S6, S12), so the hand-over's `Hold` carries an exemption for the step's own key work: the joiner's first keys, and the other signers' `SignersChanged` distributions as it enters their `KeyConfirmers` (S11, S13). Without the exemption step 1 would wait for keys the hold forbids.
- New `v2/reconcile_add.go`, the leader's steps (design 5.1, 5.3):
  1. the DNSKEY step, waiting for an emergency rollover (S12): the joiner enters `KeySigners` and `KeyConfirmers`; wait until its key states show a KSK and a ZSK published, which needs every other signer to have applied them (`ec1c6b3:v2/mp_key_lifecycle.go:268-305`);
  2. the DS step, waiting for an emergency rollover: the joiner enters `DSSigners`; its KSK's `ds=1` puts its DS in the DS set; the leader syncs (under `parentsync=agent`) and watches the parent;
  3. the caches' time: the key machine waits the DS TTL at the parent (`:328-339`);
  4. its own signatures served: the joiner enters `Signing`; P5's mode ends at its signer, and its servers serve its own signer's copy, at an SOA serial above the one they served. The leader's step tells its agent that it may switch; its status and log tell its operator once. Done waits until its nameservers serve a DNSKEY RRset signed by its own KSK, checked with S18a's query.
- Under `parentsync=owner` the owner adds the DS, and the step's test is the same.

**Names.** Status: "adding signer agent.delta.example.: step 2 (its DS at the parent)". Log, info, logger `zones`: "the provider may switch its servers to its own signer" (`zone`, `provider`), once.

**Tests.** Unit: `TestASignerAddIsDoneWhenItsServersServeItsOwnSignatures`, `TestAJoiningSignerMintsUnderTheHold`, `TestTheHoldsExemptionCoversOnlyTheStepsKeyWork`, `TestTheJoinersDNSKEYAndDSStepsWaitForAnEmergencyRollover`, `TestTheJoinersDSIsSentOnlyAfterEverySignerAppliedItsKeys`, `TestTheJoinerServesNoOwnSignaturesBeforeItsDSHasBeenServedForTheDSTTL`, `TestTheJoinersOperatorEditsAreKeptUntilDone`, `TestASignerAddUnderParentsyncOwnerWaitsForTheOwnersDS`, `TestAServerTurnedSignerIsNotToldToSwitchBeforeItsKeysAreActive`, `TestItsOperatorIsToldOnce`, `TestAServerThatBecomesASignerIsTakenAndMakesItsFirstKeys`.

**Fleet.** On every agent and signer. A signer added in three edits (the record, `signers=`, `servers=`), its NS added after "done". No bogus or lame sample; no sample in which a provider in the NS RRset serves a DNSKEY RRset whose KSK has no DS at the parent; the joiner signs without a restart. A server made a signer: the same, and its served SOA serial never goes down (#160's check).

**Done when** the fleet checks pass.

**Size.** 6 files, about 290 new and 75 changed lines.

### S19. NS management

**Before it:** S10 (the combiner by its handed role), S12, S5a (the nameserver names in the stamp row). Membership step 3 (the catch-up answer).

**Changes.**

- The runner for a change of `nsmgmt` (design 5.4), which lifts S4's `not-built`. Its first step hands the new `nsmgmt` (design 5.4); until then the parts and the agents' readers keep the `nsmgmt` they hold (S3, S12):
  - to the owner: each combiner stops applying the agents' NS by the role its agent hands it (`canApply`, `ec1c6b3:v2/combiner_chunk.go:97-127`, reads the handed `nsmgmt`), each agent drops its own NS from its data, and catch-up answers carry an empty NS set. The owner's NS RRset is served. Done when the parts hold the serial;
  - to the agents: each combiner drops the stored NS of every origin when the handed role changes `nsmgmt`, and persists that (`ReplaceCombinerDataByRRtype`, `v2/combiner_utils.go:887`); nothing stored is applied by itself. Each provider's operator contributes its NS again.
- The report of design 3.7: under `nsmgmt=owner` every agent reports an owner's NS RRset that names the servers of a provider whose role transition is not done, by the nameserver names each agent tells in its stamp row (S5a, rule 4).

**Names.** Status, warn: "the owner's NS RRset names the servers of agent.delta.example., whose role is not done". Log, warn, logger `zones`, the same line, once an hour.

**Tests.** Unit: `TestNsmgmtToOwnerStopsApplyingAgentNSAtEveryCombiner`, `TestNsmgmtToOwnerDropsEachAgentsOwnNS`, `TestACatchUpAnswerUnderNsmgmtOwnerNamesNoNS`, `TestNsmgmtToAgentsRevivesNoStoredNS`, `TestTheNsmgmtChangeTakesEffectAtTheFirstStepNotAtTheThaw`, `TestTheOwnersNSRRsetNamingAProviderNotDoneIsReported`, `TestAProviderWithoutConfiguredNameserversIsNotChecked`.

**Fleet.** On every agent and combiner. Three providers, each with an NS of its own; `nsmgmt` agent to owner, then back, with one provider's NS name taken out of service in between. After the first change every provider serves the owner's NS RRset and the parent follows. After the second, no agent NS comes back until an operator adds one, and that one reaches the parent; no stale name reaches it.

**Done when** the fleet check passes.

**Size.** 5 files, about 130 new and 40 changed lines.

### S20. Parent sync

**Before it:** S12, S14, S17a (the delete at the parent), S7 (the parent context, and a leader for every group whatever its `parentsync`). P3. PR #209, whose `followParentSyncParam` S3 moved to `onSetsChanged`, so that it follows the step's `ParentSync`.

**Changes.** The runner for a change of `parentsync` (design 5.5), which lifts S4's `not-built`. Until this step a change of `parentsync` is refused, PR #209's switch does not act on one, and the owner must not write to the parent (section 4). The option and P3's hook follow the step's `ParentSync` (S3), so they change at step 4 below, or at the first step for a take-up, never at the thaw.

- From agent to owner, reconciled by the leader of the group under V, in order, each confirmed:
  1. waiting for an emergency rollover (S12): every provider withdraws its CDS and CSYNC. Each combiner, handed `parentsync=owner`, stops applying CDS and CSYNC (`canApply`); each signer, handed the same, stops serving its CDS through its DS engine, where it serves one (S13's two carriers);
  2. their TTL passes;
  3. the agents' SIG(0) key is deleted at the parent by an update that key signs (S17a's delete), or, at a parent that takes NOTIFY only or after a failure, the owner is told to delete it;
  4. every agent stops syncing: the option off (`SetRuntimeOption`), the chain and a held NOTIFY ended and the zone's sync runs cancelled (PR #209's `delegationSyncOwnerSyncs`, which at `ed6d874` does both under the chains' lock, by `endChainLocked` and `cancelRunsLocked`), the owed mark dropped, the zone's parent context cancelled (S7). The combiners stop applying the agents' KEY;
  5. "done", once the leader has nothing in flight. The owner writes to the parent only after it (P4, the guide).
- From owner to agent: the owner stops writing before it raises the serial (the guide). At the first step every agent turns the option on, and the leader takes the zone up as at an arrival (`onZoneJoined`: `leaderKeySetup(zone, false)` by membership step 7b's rules, with S14's holds, then the explicit sync, which looks at the parent first and sends only the difference). This replaces PR #209's give-back (`delegationSyncGivenBack`, which runs the election's key set-up after `PostRefresh`). It keeps the membership plan's step 1 rule: an option that comes on because the zone's records now name this agent is no give-back, so a take-up is never run twice. Done when the KEY is published and confirmed, or the zone uses no key; the parent's trust in the key stays owed under `keyPending`, not under the transition.
- PR #209's tests are rewritten to drive the thaw and the steps.

**Names.** Status: "parent sync to the owner: step 3 (the agents' key deleted at the parent)". Log, info, logger `zones`: "parent sync handed to the owner" (`zone`); "parent sync taken up by the agents" (`zone`).

**Tests.** Unit: `TestTheAgentsStopSyncingAtTheirStepAndNotAtTheRefresh`, `TestParentsyncToOwnerWithdrawsCDSAndCSYNCFirst`, `TestTheCDSStepWaitsForAnEmergencyRollover`, `TestParentsyncToOwnerDeletesTheAgentsKeyAtTheParent`, `TestTheKEYStaysUntilTheKeyIsDeletedAtTheParent`, `TestParentsyncToOwnerIsDoneOnlyWhenNothingIsInFlight`, `TestParentsyncToOwnerDropsTheOwedSyncAndTheParentContext`, `TestParentsyncToAgentTakesTheZoneUpAtTheFirstStep`, `TestTheTakeUpsKEYIsOfferedOnlyAfterEveryMemberConfirmedIt`, `TestATakeUpTheParentDoesNotTrustYetIsDoneAndTheSyncOwed`.

**Fleet.** On every agent, combiner and signer. Agent to owner, with a lease renewal after "done": nothing from any agent reaches the parent after "done", and the owner's change at the parent is not undone. Owner to agent: the leader syncs at the first step, without waiting for a renewal, and every nameserver serves the KEY before it is offered.

**Done when** the fleet checks pass.

**Size.** 7 files, about 220 new and 60 changed lines.

### S21. An upstream; `pubkey` and `pubcds`

**Before it:** S18a (the serving check), S12. P6. PR #167, whose combiner reads `pubkey` (`lacksPubkeyConsent`). tdns-mp #206 fixed (S14).

**Changes.**

- An upstream (design 5.6): the runner lifts S4's `not-built` and `step-missing` for it. One step: the downstream provider's agent confirms that its servers serve the zone from the new upstream at an SOA serial no lower than the one they served (S18a's check against the new upstream). Its status tells its operator what to point where. S4 already refuses a dangling upstream and the removal of a signer that is a remaining server's upstream, so the owner moves an upstream first, as its own edit.
- `pubkey` and `pubcds` (design 5.6), which lift S4's `not-built` for them: one step publishes or withdraws, at the providers' `_signal` names, the zone's KEY (`pubkey`) or its CDS and CDNSKEY (`pubcds`), by the step's `Signal` set (S3, S13). The agent hands it to its combiner. The KEY goes as today, through the agent's publish instruction and the combiner's `at-ns` path (`ec1c6b3:v2/agent_publish_locations.go:20-28`, which reads the step's `Signal`; `v2/combiner_chunk.go:581-603`); PR #167's combiner check reads the handed serial (S10). The CDS and CDNSKEY at the `_dsboot` names are new in the combiner, on the same path. With P6 the provider's nameservers no longer act on their own copy (7.3).
- The auditors and `suffix`: nothing to carry out, agreed from S7.

**Names.** Status: "waiting for agent.echo.example.'s nameservers to serve the zone from its new upstream". Log, info, logger `zones`: "the zone's KEY at the _signal names published" or "withdrawn" (`zone`); "the zone's CDS at the _signal names published" or "withdrawn" (`zone`).

**Tests.** Unit: `TestAnUpstreamChangeIsAStepThatWaitsForTheServers`, `TestTheStatusSaysWhatTheOperatorMustPointForAnUpstream`, `TestPubkeyOnPublishesTheKEYAtTheSignalNames`, `TestPubkeyOffWithdrawsIt`, `TestPubcdsOnPublishesTheCDSAtTheSignalNames`, `TestPubcdsOffWithdrawsIt`, `TestTheSignalPublicationFollowsTheStepNotTheCopy`.

**Fleet.** On every agent and combiner, and the provider's nameservers with P6. Server B's upstream moved from signer A to signer C: B's status says what to point where; the step completes only once B's servers serve C's copy; nothing else for the zone moves meanwhile; no bogus sample. `pubkey` and `pubcds` on and off: the KEY and the CDS appear and go at every provider's `_signal` names at the step, not when a nameserver loads the edit.

**Done when** the fleet checks pass.

**Size.** 7 files, about 170 new and 40 changed lines.

### S22. Tellings by interest

What is left of the membership plan's step 9b (its decision 24), in the form of design rule 4, for beats only. Answers count for nothing (rule 4), so 9b's half for answers goes.

**Before it:** S5a, S12, membership step 8.

**Changes.**

- The stamp entry lists a zone to peer P only when the sender has something to do for it, or P's latest first-hand stamp for it is not steady or differs from the sender's (rule 4). The sender has something to do for a zone when it is not steady there (newest above active, not done, active not known), has an owner error or refuses its newest serial, or has work owed, kept or under way: the owed or the kept list is not empty, a rollover is under way, a catch-up is owed, or a distribution to P is open. At rest nothing is listed. A new epoch at P makes every zone differ, so each is listed once.
- Optional: a row's `Zones` list (`ec1c6b3:v2/gossip.go:467-470`) left empty, and the display readers that find a zone's group from the rows go (`v2/apihandler_gossip.go:114, 139, 201`; `v2/auditor_dto.go:547-548`).

**Names.** None new.

**Tests.** Unit: `TestAStampIsToldOnlyWhileSomethingIsGoingOn`, `TestAStampIsToldWhileWorkIsOwedKeptOrUnderWay`, `TestAStampIsToldToAPeerWhoseStampDiffers`, `TestAPeersRestartListsEveryZoneOnce`, `TestARowListsNoZoneWhenNothingIsGoingOn`, `TestABeatAnswerListsNothingByInterest`, `TestTheGroupOfAZoneComesFromTheGroupManagerOnly` (in place of `TestProviderGroupForGossipZone_fromGossipStateTable`). `TestSnapshotGossipForZone_singleMatrix` and `TestTheFirstLocalRowWaitsForGoodNews` are adjusted.

**Fleet.** On every agent and the auditor. At rest no beat carries a stamp. An owner edit: the zone's stamps are in the beats until "done", and in none after.

**Done when** the fleet checks pass.

**Size.** 5 files, about 90 new and 60 changed lines.

## 6. Decisions

Decided by the project owner on 2026-10-17 and 2026-10-18, except where marked. Those marked *taken without the project owner* were taken by the writer of the design or of this plan on 2026-10-18, while the project owner was away, on his instruction to go on without waiting; each is listed in the report to him and stands unless he says otherwise.

1. **The owner numbers its instructions** (2026-10-17). An explicit `serial` key in HSYNCPARAM, raised by the owner at every edit of HSYNC3 or HSYNCPARAM, in place of a serial computed by the agents. A digest of the contents is kept beside it as a check. Its order is what lets an agent know whether it lags, what gives a held message a final answer, and what the owner can read; a hash alone gives none of the three.
2. **One reader per provider** (2026-10-17). A provider's combiner and signer take their roles and policies from their agent, not from their own copy of the zone. Revision 2 widens it to the agent's own readers and to code in tdns that the agent calls (decision 18); revision 3 to the provider's nameservers (decision 45).
3. **An answer between serials is not final** (2026-10-17), including an "ignored" from a provider the sender's copy calls a signer.
4. **The owner's floor for `parentsync`** (2026-10-17). After an edit from agent to owner, the owner does not write to the parent until every provider shows the transition as done. Revision 2 gives that transition steps (decision 25).
5. **The faults of issue #200 are fixed whichever way this goes** (2026-10-17). Item 1 is a plain bug, fixed apart (PR #209; tdns #926 for its tdns half); the others are steps of this plan (section 2 maps them). From S7 to S20 a change of `parentsync` is refused, so PR #209's switch does not act in that stretch (section 4).
6. **Every message carries the sender's serial** (2026-10-17): SYNC, requests, confirmations, and the beats. A receiver sees at once whether it or the sender lags. Revision 2: the active and newest serials by serial and digest, and the rollover flag. Revision 3: the last thaw and a refusal too (rule 4).
7. **The freeze** (2026-10-17 and 2026-10-18). From the moment an agent holds a newer serial, nothing new that a provider makes starts for the zone. A key rollover under way runs to its end. The agreement on the new serial goes on in parallel. The leader thaws the zone only when every voting member agrees and no rollover is under way. No new rollover starts during the reconciliation; it waits.
8. **What moved here from the membership plan** (2026-10-18): its steps 9, 9b and 10, its design section 4.9 and the SIG(0) key part of its 4.1; and the four questions of its 7.1: who answered a beat, two exceptions to its decision 23, the recovery of a lost key for tdns parents, and the asking half of its decision 6. Here: step 9's settle rule is replaced by S6 to S9, its key part is S14, step 9b is S22 in rule 4's form for beats only (decision 59), step 10 is S15; the two exceptions are closed by S7's context per zone; the other three questions come after this plan (7.4). *Changed on 2026-10-19 by membership decision 46:* membership step 7b builds the key part without the holds; S14 keeps the holds, `keyPending`, the serial rule and the KEY as the group's.
9. **The removal's open points** (2026-10-18). A distribution waits for a leaving provider's confirmation, with a time-out; the leader's CSYNC is one case of it. The leader withdraws another provider's records by a `replace` in that provider's name; a member takes it when the sender is the zone's leader under the active serial and the transition takes the provider out of the list the RRtype depends on: `servers=` for NS records and glue, `signers=` for DNSKEY and CDS records. A move between `servers=` and `signers=` is a transition like any other. *Revised in revision 2, taken without the project owner:* a member takes it when the active instructions do not list the provider; the provider is named in a field of its own, since membership step 6 refuses a payload that names another sender; and glue is not in the rule, since it is not a contribution (`ec1c6b3:v2/combiner_utils.go:29-38`). *Revised in revision 3, taken without the project owner:* a withdrawal follows rule 6 like any distribution (decision 51).
10. **The removal is part of this design.** *Taken without the project owner.* In it, the removal is what the leader carries out after an edit that takes a provider's roles away. Keeping it apart would leave the reconciliation of the commonest transition undesigned. While it stands, the membership documents' scope notes are to mark their section 7 and plan 7.4 as moved here, and the membership plan's 7.5, which still leaves the removal to the project owner, to say so. They do not yet; this plan changes no other document.
11. **The open points of the first note take their proposals.** *Taken without the project owner.* Operator edits are kept during the reconciliation, on disk. An emergency rollover may start in any phase, and the thaw, and every DS or DNSKEY step, waits for it (decision 58); a provider that has lost its roles makes none. A newer serial during the agreement becomes the serial agreed on, and the serials between are kept; during the reconciliation it freezes the zone again and the leader plans again from what is in place. A zone with no serial is at serial 0, and a change at serial 0 is an owner error. An agent that has started starts nothing for a zone until it knows the zone's active serial (design 3.4). The leader under the old serial thaws. An unsafe transition is refused as a whole. *Changed by revision 5* (decision 84): during the reconciliation a newer serial waits until "done", and nobody plans again at a newer serial.
12. **Nothing that changes state is taken from an answer.** *Taken without the project owner.* The thaw counts a member's telling only from a message that member sent. Revision 2 extends it to the thaw itself, an "active" telling, a rollover flag and an election record. Revision 3: an answer's gossip is shown and changes nothing (S5a), and with payload encryption off at a voting member there is no thaw (decision 48). Who answers a beat is not checked yet (`ec1c6b3:v2/hsync_transport.go:292`; tdns-transport `f76a204:v2/transport/dns.go:706-714`).
13. **Adding an HSYNC3 record is a transition with nothing to carry out.** *Taken without the project owner.* Revision 2: it is done once the parts hold the new serial, and a newcomer whose agent is not running is waited for only up to the time-out of design 4. The owner checks the newcomer's catch-up before giving it a role.

Added by revision 2 of the design, from the adversarial reading and the code readings, each *taken without the project owner*:

14. **The serial is 32 bits, compared by RFC 1982.** Compared as a plain number, a serial that reaches the top leaves the owner no higher one. The key is 8, as the draft is to assign it (7.3).
15. **The digest reads exactly what the code acts on** (rule 2): the ON records' labels, identities (case-folded) and upstreams; the OFF labels; whether HSYNCPARAM is present; every known key but the serial, defaults filled and lists as sets. A wider digest asks for a raised serial for nothing; a narrower one hides a real change. Its form: SHA-256 over a versioned encoding, truncated to 64 bits as `ComputeGroupHash` is (`ec1c6b3:v2/provider_groups.go:32-50`).
16. **The owner's order is a rule.** A record before a role, the roles before the record. An edit that removes the record of a provider with a role, or gives a role to a label without a record, is refused. Then every voting member under the new serial was a member under the old one and hears the thaw there.
17. **Serials are kept on disk.** The agent keeps its active serial, the serials it has held and told, the highest serial and the phase; the parts keep what they were handed. A combiner or a signer never handed anything acts by its own copy until it is. Without this a restart forgets a refused lower serial, and a restarted part acts by its copy. Revision 3 adds the from-serial, the last thaw, the refusal and the step's sets (decision 36), lets a part with a serialed copy ask first (decision 44), and lets the serials be given up (decision 54). Revision 4 adds the removals under way (decision 66).
18. **One accessor.** Nothing in tdns-mp, nor in tdns where the agent calls it, reads HSYNC3 or HSYNCPARAM to decide, except the transition machinery; a test fails on a direct read.
19. **The thaw names its serials, and is relayed.** The thaw names its serials, from and to. A voting member that has made the new serial active relays it in its own stamp; members that do not vote take it from any voting member. *Changed by revision 3* (decision 35): activation no longer goes one serial at a time. Revision 4: rule 3 says that the active serial changes at the leader's word or a voting member's first-hand relay of it. Revision 5: rule 3 also names the zone with no voting member under the old serial, made active by the tellings of every voting member under the new one.
20. **The leader's work at the parent drains before it thaws**, through a context of its own for the zone, and at every hand-over of the zone's leadership.
21. **A leaving voting member that is gone is excused**, after a configured time unheard. *Replaced by decision 34.*
22. **A refused transition leaves the zone steady.** Every agent judges the same serials alike, so nobody acts on it; freezing would hold rollovers and operator edits for an owner's mistake. Revision 3: the refusal is told (decision 37).
23. **The roll of the zone's SIG(0) key is the zone's obligation, not a gate.** The removal goes on; the roll is retried until it succeeds. This restores the rule of the membership plan's decision 22.
24. **Members with no role are waited for with a time-out**, on their way in or out. An auditor confirms at once.
25. **`parentsync` from agent to owner has steps**: the CDS and CSYNC withdrawn, their TTL, the agents' key deleted at the parent, the drain, then "done". From owner to agent, the owner stops writing before it raises the serial.
26. **An upstream change, and a move into `signers=`, are refused until their steps can be carried out.**
27. **The owner's NS RRset is the owner's action.** Under `nsmgmt=owner` it may name a provider's servers only once that provider's role transition is done; every agent reports one that does.

Taken while planning, each *taken without the project owner*:

28. **The order of the steps** (section 5): the zone's SIG(0) key and the switch before the withdrawal and the removal; the reconciliation core before each step's sets reach the parts.
29. **A kind of change whose steps are not built is refused**, with the reason `not-built`, so that no interim build carries one out half-built. The step that builds the kind lifts it. Revision 3 adds `pubcds`, lifted by S21.
30. **Stamps ride in a gossip entry outside the groups**, one row, the sender's own, never relayed. A row per group breaks at a thaw that changes the make-up: the sender sends no row for a group it has left.
31. **A stale distribution gets a final REJECTED that names `stale-instructions`** and carries the receiver's stamp. The transport's acknowledgement stays ok, so the message does not go on the failed-send backoff, and the sender reads it as "not yet".
32. **The hand-over uses carriers that exist**: an `update` to the combiner through the confirmed queue, KEYSTATE signals to the signer, the inventory and EDITS answers back. No new verb.
33. **The context per zone for work at the parent is tdns-mp's.** tdns's calls stop on the caller's context (tdns `3615261f:v2/delsync_retry.go:33-58`, `v2/parentsync_bootstrap.go:30`); tdns-mp passes the syncher's (`ec1c6b3:v2/delegation_sync.go:52, 254`). This corrects the membership plan's step 9, which read the UPDATE retry as not closable from tdns-mp.

Added by revision 3 of the design, from three critics' readings of revision 2 and of the plan, each *taken without the project owner*:

34. **A leaving voting member is excused after a configured time without telling a newer serial, heard or not.** Its rollover flag is excused too. A rollover whose only missing confirmation is the excused member's counts as paused, and the key machine does not promote across that wait. Its NS step comes before any addition's DNSKEY step, and once its NS TTL has passed it leaves the expected confirmations and the paused rollovers resume. A leaving leader is excused only once its lease has run out. While it is unheard it is also excused from the gate of the group under the old serial, for every zone of that group, until it is heard again; that effect is accepted. Replaces decision 21: a gone, stuck or uncooperative leaving provider must not hold its own removal. *Changed by revision 4* (decisions 69 and 70) and by revision 5 (decisions 87 and 88).
35. **The thaw needs every voting member under N to tell active N and newest V**, to refuse nothing, and to have its signer's hold confirmed. A member whose active serial is older than the thaw's "from" and that holds the serial told active moves straight to it; one that does not hold it starts nothing and fetches. Without this a member that fell behind could never catch up. *Changed by revision 6 (decision 94): it tells that it agrees on V, and a refusal of a serial above V holds nothing.*
36. **Until the leader's first step, every set is the old serial's**, and the from-serial and the step's sets are kept on disk. Without this the thaw itself would drop a leaving signer's keys and DS while it is still delegated to. *Changed by revision 4* (decision 65): the sets the parts hold. Revision 5 (decision 84): with one transition at a time, those are the old serial's at every thaw.
37. **Refusals are told** in the stamp. The thaw needs that no voting member refuses; an agent never activates a serial it refused.
38. **Four more refusals**: an identity changed under a label with a role (records are compared by label and identity); an ON record whose upstream names a label that is not a signer with an ON record; the removal of a signer that is a remaining server's upstream; a record removed while that provider's removal is not done. *Changed by revision 4* (decision 67): the fourth is no longer refused.
39. **A provider whose removal is under way stays a member**, with no role, until its removal is done, whatever its record says. Revision 4: across interrupting transitions (decision 66). *Changed by revision 5* (decision 84): no transition interrupts a removal.
40. **A digest conflict counts only between voting members.** One told by a member that does not vote is shown and holds nothing: a member with no role changes nothing.
41. **A telling counts only once the agent's signer has confirmed the hold.** Otherwise a signer slow to get the hold could start a rollover after its agent's last telling.
42. **The key's offers and bootstrap pass the freeze while a rollover under way waits on `keyPending`.** Otherwise the rollover and the thaw wait for each other.
43. **Kept operator edits are kept apart** from the data that catch-up answers and syncs read. Otherwise a kept edit reaches the peers that ask for catch-up and no other.
44. **A part never handed anything asks its agent first** when its copy carries a serial, and serves what it last served meanwhile. With no serial in the copy it acts by its copy.
45. **The provider's nameservers are a reader.** `pubkey` and `pubcds` are steps, and the nameservers take them from their agent (P6, S21; how, 7.3).
46. **Every group of two or more voting members elects a leader, whatever its `parentsync`.** Transitions need one. Changes membership section 7.
47. **A leaving signer's CDS goes at the DS step**, so that a parent that follows CDS does not keep its DS.
48. **No thaw with payload encryption off at a voting member.** The argument of design 3.7 needs it; the status says why. Settles the plan's former open point.
49. **The restart rule is tightened.** A member with no record takes the leader's word only; a leader with no record takes a serial only when every voting member tells the same known active serial; the first activation after the upgrade has no rollover or parent condition, since nothing is active yet to protect. *Changed by revision 4* (decision 73) for the leader with no record.
50. **The expected key confirmers are a set of their own**, which a leaving provider leaves when the NS TTL after its NS step has passed. *Changed by revision 5* (decision 90): the TTL counts from when the parent no longer names its nameservers, and the leave is part of the NS step.
51. **Withdrawals follow rule 6.** One made under an older active serial is refused as stale, and the leader sends it again if its plan still calls for it.
52. **A "not yet" that arrives when the serials are already equal is sent again at once.**
53. **While the active serial is not known, distributions are kept, catch-up answers included.**
54. **A zone's stored serials can be given up**: by the forget command, for a steady zone, at every agent together; and when the zone leaves an agent's configuration.
55. **The sweep runs at "done"**, never while the zone is frozen and never towards peers. Revision 4: nor while a removal is under way (decision 66). Revision 5: a removal ends within its transition, so that clause goes (decision 84).
56. **A provider put back sends a complete `replace`, and every agent asks it for its state.** Membership step 4's `peer-role` is widened to it.
57. **The combiner applies a removal in any origin's name that its own agent delivers**: a delete, or a `replace` whose records are a subset of what the origin holds.
58. **Every DS and DNSKEY step waits for an emergency rollover**, of an addition or a removal; the others do not.
59. **Tellings are listed by interest, in beats only.** Answers count for nothing, so the half of the membership plan's step 9b for answers goes.
60. **tdns's `DELEGATION-SYNC-SETUP` arm makes no key for a multi-provider zone.** The zone's key is the leader's key set-up's alone. *Built by membership step 7b since membership decision 46 (2026-10-19), before this plan.*

Taken while revising the plan, each *taken without the project owner*:

61. **tdns is re-pinned in two moves.** S1 raises only the core module; S3 re-pins tdns/v2 with P3, to a tdns without #916 or with #917's child side.
62. **One predicate for "a key rollover under way"**, defined in the key machine and used by S5a, S6, S7 and S11. The emergency rollover is the operator's `signer key rollover`.
63. **Every agent that applies an NS withdrawal keeps the names it removed until "done"**, so that a new leader can plan the removal again. *Replaced by decision 66*: every agent keeps them from the leader's first step.
64. **The legacy HSYNC and HSYNC2 paths go in S3.** They fall outside the canonical reading.

Added by revision 4 of the design, from a check of revision 3 and of this plan, each *taken without the project owner*:

65. **At a thaw the parts keep the sets they hold.** At a first thaw those are the old serial's lists; at a thaw that interrupts a reconciliation, the interrupted step's sets. The purposes of design 3.5, `nsmgmt` and `parentsync` among them, change only at a step; groups, admission and discovery follow the activation. Without it a later thaw would hand the interrupted serial's lists and drop a leaving signer that is still delegated to: bogus. Changes decision 36. *Changed by revision 5* (decision 84): no thaw interrupts a reconciliation, so the parts keep the old serial's sets at every thaw.
66. **A removal stays under way until its own last step,** across interrupting transitions. Its state and the leaving providers' NS names are kept on disk at every agent, from the leader's first-hand steps; the leader's first step names the NS names. The sweep never runs while a removal is under way. Replaces decision 63. *Changed by revision 5* (decisions 84, 86 and 90): no transition interrupts a removal; its state is told in every member's stamp; the NS names come from the leaving provider's stamp and the parent.
67. **A record removed while that provider's removal is not done is agreed.** The provider stays a member, with the identity of the last serial that listed it, until its removal is done. The judge is again a function of the two serials alone. Changes decision 38.
68. **A member that moves straight judges the thaw's own pair,** from and to, with the from-serial fetched if it lacks it, never its own older active serial; it refuses only a serial it cannot read. Without it a member left behind by one transition refuses the next for good.
69. **The excusal is for a telling that has not met the thaw's first two conditions** for the configured time, counted from when this agent first holds V, heard or not: a member stuck with its rollover flag on, without its signer's hold, or refusing, is excused like a silent one. A leaving leader is excused once its lease has run out in each agent's own view; a heard, stuck leaving leader stalls the zone, safely, until its operator stops it. Changes decision 34. *Changed by revision 5* (decision 87).
70. **No step waits for a rollover paused only on excused members, and an excused leaving signer that serves nothing leaves the expected confirmations at the first step.** Without it a gone signer-only provider would hold a swap, or an emergency rollover, for good. *Changed by revision 5* (decision 88): every leaving signer that serves nothing, excused or not.
71. **A lost leader that is not leaving stalls its group,** as membership 4.3's gate has it, until it is heard again or the owner removes it. The zone stalls, safely, at the old serial.
72. **The leader's own signer's hold is a thaw condition.**
73. **A leader with no record takes the active serial that every voting member with a record tells,** when there is at least one and they all agree, the last thaw told breaking a tie; a member with no record counts as no objection. Otherwise the status names the forget command. Without it a leader and a member with no record wait for each other. Changes decision 49.
74. **Each agent tells its own provider's nameserver names,** from its configuration, for the report of design 3.7. Revision 5: and for a removal's NS step (decision 90), with the removals it holds (decision 86).
75. **Withdrawals and a provider's own operations are ordered by the active serial stamped at their send, then by their creation time.**
76. **Rule 6's "not yet" is judged against the stamp of the send the answer answers.**
77. **Other agents' kept distributions are handled at the activation; the agent's own kept changes at "done".**
78. **The forget command is the one exception to never giving a held serial up.**
79. **"Which the leader may hasten" is gone.** The removal's waits are the caches'.

Taken while revising the plan for revision 4, each *taken without the project owner*:

80. **P6 comes before S7.** From S7 nobody may act on a refused serial, and the providers' nameservers would act on a refused change of `pubkey` or `pubcds` from their own copy.
81. **A member fetches a from-serial it lacks by an RFI, proposed subtype `instructions`,** answered with the records in presentation form and checked against the digest (S7, 7.2).
82. **#152 is S8's.** A "kept" PENDING is copied to the auditors with its text, on PR #169's copy path.
83. **Section 4 lists a part for a step when the step changes it or the step's fleet check runs on it.**

Added by revision 5 of the design, from a check of revision 4, each *taken without the project owner*:

84. **One transition at a time.** A newer serial during the reconciliation waits until the transition under way is done. Agents hold it and tell it as their newest; nothing of it is agreed or thawed before "done"; after "done" it is agreed. So no thaw lands inside a reconciliation, and a removal is never interrupted. This replaces the part of decision 11 that had the zone freeze again and the leader plan again from what is in place, which was itself taken without the project owner. It changes decisions 36, 39, 55, 65 and 66. Gone from the plan with it: the interrupted step's sets as step 0, removals carried across later thaws, and planning again at a newer serial.
85. **The sets name each provider by label and identity**, fixed when the step that made them was taken. Every label resolver resolves a provider whose removal is under way through the removal's stored identity.
86. **Every member tells the removals under way it holds, with the step it holds.** An agent that missed the end drops a removal when the leader's first-hand stamp shows the transition done; a leader without the state takes it from the members' stamps. Changes decision 66.
87. **A telling counts for the thaw only while it is fresh**, heard within the configured time. The excusal applies during the reconciliation too: a leaving member that has not confirmed a step for the configured time is planned as excused from then on. Changes decision 69.
88. **Every leaving signer that serves nothing, excused or not, leaves the expected key confirmers at the reconciliation's first step.** Changes decision 70.
89. **A rollover's sync during a freeze carries the delegation by the sets the parts hold**, not by a serial's lists.
90. **A leaving provider's nameserver names come from what it told in its stamp and from the parent's NS RRset at the removal's start**, not from the leader's data. Under `nsmgmt=owner` the owner drops them from its own NS RRset in the edit that takes the server role away. The NS step waits until the parent's NS RRset no longer names them and counts the NS TTL from then; the leave from the expected confirmers after that TTL is part of the step, sent even while the zone is frozen. Changes decisions 50 and 66.

Taken while revising the plan for revision 5, each *taken without the project owner*:

91. **Only the leader's catch-up answer names the zone's KEY, and it takes it from its keystore**: the active key whose KEY record the zone publishes (`zoneKeyHeld`, membership step 7b's helper), not from its data repo, which never holds what `leaderKeySetup` published. Until S14 no catch-up answer names the KEY, as membership decision 27 has it.
92. **Which of the parent's NS names are a leaving provider's** is read as in 7.2: those that no remaining provider tells or contributes, and, under `nsmgmt=owner`, that the owner's NS RRset under the new serial does not name.
93. **At a "done" with a newer serial waiting, the sweep runs first**, by the serial just done, and the waiting serial's agreement starts after it (7.2).

Taken with the project owner on 2026-10-26, after the external review of revision 5:

94. **Agreeing targets the highest serial the judge accepts.** A newer serial that the judge refuses against N does not replace the serial being agreed; it is held, told with its refusal, and judged again against the serial agreed on once that transition is done. A serial agreed on that an agent lacks is fetched from a voting member that tells it (S7's `instructions` RFI). Settles 7.2 item 2.
95. **A telling counts for the thaw only while it is fresh** (decision 87) stands, for what it says of rollovers; design 3.7 says so. The serial told needs no repeating.
96. **The zone's NS RRset goes before the parent's** in a removal under `nsmgmt=agent`, as 7.3 item 6 proposed; design 5.2 says so.
97. **A removal holds the zone through its waits** (7.3 item 9), as the design has it; the status names the wait and when it ends. Letting ordinary work resume during pure waits may come later.
98. **Several KEYs at the apex: no zone key** until the operator leaves one; nothing picks one (7.3 item 18; design 6).
99. **A leader whose key the parent refuses takes no action of its own:** its syncs stay held and the status says why, until tdns parents follow #917 (7.3 item 19; design 6).
100. **The recovery of a lost key is not built now** for tdns parents (7.3 item 20; 7.4).
101. **Two leaders never both make a key** is shown by a test in S14, `TestTwoLeadersNeverBothMakeAKey` (7.3 item 21).
102. **The canonical reading and its digest stay tdns-mp's own,** not the draft's (7.3 item 2; design rule 2).

**Carried over from the membership plan:** on the zone's SIG(0) key, what membership step 7b leaves of its decisions 18 and 25 (membership decision 46): the holds of a transition, the wait for the parent's trust (`keyPending`) and the recovery of a lost key (7.4; not built now for tdns parents, decision 100). The rest of decision 18, the second half of decision 14 (no new key at a take-up while a voting member holds one or has not answered) and decision 25's rule that no key is made before every agent asked has answered are membership step 7b's. The hand-over half of decision 15 is on main: since PR #213 any voting member is handed the key and a refusal is answered, and since PR #217 a provider listed ON with no role hands it over; from S15 that is ordinary admission. Its decision 22 (the key is the group's, and is rolled when a voting member leaves), with one change: the roll is retried on its own schedule until it succeeds (design 5.2 step 1, decision 23), not first "as its last step" of the removal. Its decisions 12, 16, 19 and 23 on the hold after a change of make-up, and its design section 4.9, are replaced by decisions 1, 7 and 12 above: what was held and kept stays as it was, the fixed time and the time a telling counts go.

**What this design replaces or changes in the membership design and plan,** each with what replaces it:

- **Decision 2's exception, the first half of decision 14 that states it, and design 2.1 ("except for what withdraws it") and 3.3:** a withdrawal did not wait for the member it withdraws. Now a distribution waits for a leaving provider, and for any member with no role, with a time-out (decision 24; design 4 and 5.2). Design 3.3's time-out is that time-out.
- **Decision 17 (parked) and decision 21** (the member's own copy says the same; a `replace` cannot be the withdrawal; glue): replaced by decision 9 as revised, and decision 51.
- **Section 7 ("no election for a zone without `parentsync=agent`"):** every group of two or more voting members elects (decision 46).
- **Decision 24, the listing by interest:** it stands, in the form of design rule 4, for beats only; the half of step 9b for answers goes (decision 59).
- **Decision 26 (gossip in the answer to an HTTPS beat is merged), step 6's `MergeGossip` for answers, and design 3.3's gossip row** ("carried in a beat and in the answer to one ... From a voting member all of it is taken"): an answer's gossip is shown and changes nothing; no election record or term is taken from it (rule 4; decision 12). Settled 2026-10-19: membership step 6 does it (membership decision 35).
- **The hooks of steps 4 and 8 at a refresh** (membership plan, "the reasons at a refresh"), **and design 4.5's check** at every change of the zone's HSYNC3 or HSYNCPARAM records: they run when the active serial changes and at every first load, not at a refresh (rule 5; decision 18; S3).
- **Design 4.3's gate** (the voting members mutually OPERATIONAL, with step 8's voting list): an excused leaving member that is unheard is left out of it, for every zone of the group, until it is heard again (decision 34; design 3.2; S7).
- **Step 4's `peer-role`** ("given its first role"): widened to a provider put back (decision 56; design 5.1).
- **Step 6's combiner rule** (the named origin must vote): relaxed for a removal that the combiner's own agent delivers (decision 57; design 3.5; S16).
- **Section 4.9, decisions 12, 16, 19 and 23:** replaced, as above.
- **Section 4.1's key part:** what membership step 7b leaves of it is taken over here (S14; decision 8 as changed by membership decision 46). **Rule 1's switch, section 7's removal and plan 7.4:** taken over here (decisions 8 and 10).
- **Plan 7.5's #152** (the auditor's view does not say that a member keeps a distribution): taken into S8 (decision 82).
- **Plan 7.1, item 1** (no catch-up answer names the zone's KEY), now membership decision 27: stands until S14; from S14 the leader's answer names it, from its keystore (decision 91).

## 7. What this plan depends on, and what comes after

### 7.1 To be done first

Refreshed 2026-10-27 against tdns-mp `main` @ `d2cc1d8` (pins every tdns module at `v2.0.0-20261026162903-c3c2a48d4e2f`, which includes #928, #926, #951 and #952; tdns-transport `v2.0.0-20261027063808-860bae61c2b0`). The membership work (#178’s steps 1–8 and 7b) finished on main after this plan’s 2026-10-19 table; the rows below say what is still open for *this* plan.

| What | State, 2026-10-24 | Needed by |
|---|---|---|
| The membership plan's steps 1 to 8, step 7b included (membership decision 46) | **Done** on main: PRs #222–#228, #250–#252 (step 8 merge `30c28c3`). Ground for this plan. | Every step from S2; S14, S17a and S20 build on step 7b's key set-up |
| tdns: the HSYNCPARAM `serial` key (P1) | **Done** in tdns: #928 merged (`219121ae`); in the pinned core (`HSYNCPARAM_SERIAL`, `GetSerial`). S1 calls it (2026-10-27). No new core key work. | S1 (consume `GetSerial`; re-pin only if the pin has moved) |
| The draft: the key's number (8 proposed) and its rules: raised at every edit, RFC 1982, absent is 0, one HSYNCPARAM, one record per label in any state | **Still open:** [draft PR #3](https://github.com/johanix/draft-leon-dnsop-signaling-zone-owner-intent/pull/3) (not merged). tdns already ships key 8. | P1 / interop docs |
| tdns: `parentsync` asked of the application (P3), and the re-pin of tdns/v2 | **Built** (2026-10-28), pull request to follow: `RegisterParentSyncAgentFunc`; without a hook, tdns reads the copy as before. The re-pin goes with S3. | S3 |
| tdns #926 (the key poll checks `parentsync` before every step) | **Done.** Merged (`9febcafd`); present in the current pin. | P3, S20 |
| tdns: a context per zone | **Not needed:** tdns's calls take the caller's context (decision 33). Unchanged. | S7 |
| tdns #916 (KeyState answered by the parent side when the server hosts the child too) | **Done.** Merged; on main since tdns-mp #219 (and later pins). | S3 / correct on the wire |
| tdns #917, both sides | **Child done:** tdns #933 merged and in the pin. **Parent side still open:** issue #917, no PR. | Parent side for the recovery of a lost key (7.4) |
| tdns: #160's mode and #146's policy binding (P5) | **Still not established.** tdns-mp issues #160 and #146 remain open; no implementing PR. | S18b |
| tdns: the provider's nameservers stop reading `pubkey` and `pubcds` from their copy (P6) | **Still missing.** No PR. Its open questions are answered (2026-10-28, P6); the project owner decides three points. | S7 (on the nameservers before it), S21 |
| tdns-transport: an application field on confirmations, with the message (P2) | **Still missing.** No PR. `IncomingConfirmation` has no application stamp field. | S5b, S8 |
| The owner's tools (P4): the serial in every zone, raised at every edit | **Still missing** outside this repository. S1 writes `serial="1"` in the configure example zone and the policy matrix generator; raising it at every edit is the owner's. | Before S7 reaches a fleet |
| tdns-mp #209 (#200 item 1) | **Done.** Merged 2026-10-19; `followParentSyncParam` on main. | S1, S3, S20 |
| tdns-mp #167 (`contributionsLoaded`; the combiner's `lacksPubkeyConsent`) | **Done.** Merged 2026-10-19; both helpers on main (`combiner_chunk.go`). | S21 |
| tdns-mp #208 (#207) | **Done.** Merged 2026-10-18 (`1d49624` on main). | S3, S10, S13 |
| tdns-mp #206 (the at-ns KEY is published only under the leader's nameservers) | **Still open** (issue). | S14 (fixed there or before), S17a, S21 |
| tdns-mp #147 (a provider taken out of `signers=` stops signing at once) | **Interim merged:** tdns-mp #275 (main `b921a94`, 2026-10-27). The leaving provider keeps signing, its DS and DNSKEYs stay, and every key machine of the zone pauses while it is in the signing set. The issue stays open. | Closed by S11 and S13, which replace the interim; S3 moves its reader |
| tdns-mp #279 (#191: a zone named in `key-lifecycle-zones` is owned from the signer's start) | **Open**; CodeRabbit and the rig under way. | S11 keeps its rule |
| tdns-mp #270 and tdns-transport #43 (#238, #236: RFI CONFIG and AUDIT answered on the request's mechanism; a send that starts on a chosen mechanism) | **Open.** | S7's `instructions` RFI is answered the same way; the agent's confirmations go through #43's send |
| tdns-transport #41 (#40: one recipient that does not answer no longer holds back the others) | **Open.** | P2, in the same package; S5a and S8, whose messages go through the queue |
| tdns-transport #42 (a design: the DNS carrier dials only a DNS address) | **Open**; built after #43 and #270. It renames `CurrentAddress` at tdns-mp's callers. | Before S3, to keep conflicts out of `hsync_transport.go` and `hsync_bridge.go` |
| tdns-mp #274 (#267 item 3: no delegation-sync work dropped) | **Done** (main `8f3ca4f`). A full queue is owed, a failed refresh sync is retried, the ns-changed hint asks for nothing (#248), the newest KEYSTATE inventory is kept. | S19 and S20 build on it |
| tdns #952 (a BADKEY re-bootstrap makes no key, and waits until the key is served) | **Done**, in the pin. | Decision 99 (S14) builds on it |
| tdns-mp #276 (a key poll goroutine outlives its test and races the next) | **Open** (issue). | Before S2: every step gates on the race suite |
| tdns-mp #185 (#179) and #186 (#180 to #183) | **Done.** Merged 2026-10-19. | Membership steps 7b and 8; S3 |
| tdns-mp #217 (#179: the key set-up also asks every agent listed ON with no role) | **Done.** Merged 2026-10-19; `zoneKeyPeers` / `roleLessKeyHolders` on main. | Membership step 7b; S3; S15 |
| tdns-mp #219 (tdns pinned at main `38faefbb`: #931, #933, #916, #932 and #935) | **Done.** Merged 2026-10-19. Later pins moved past that SHA; the named tdns PRs remain in the lineage. | S3; S14 |
| tdns-mp #169 | **Still draft**, open. Membership step 1 did not land `copyConfirmationToAuditors` on main; that copy path is still this PR’s. | S8, for #152 |
| tdns-mp #152 (the auditor's view does not say that a member keeps a distribution) | **Still open** (issue); closed by S8 with #169. | S8 |

**Still blocking a first fleet that can change providers:** P2, P3, P4, P6, and (for signer-add) P5; plus #169/#152 for auditor visibility of kept distributions. Membership, P1’s key, #167, #208, #209, #185, #186, #217, #219, #916, #926, and #917’s child side are no longer prerequisites to start S1–S6 against main.

Needed by no step: tdns-mp #166, #189, #190; tdns #922, #923, #924, #891, #886, #791, #789, #634, #395.

### 7.2 Problems with the design found while planning

Revision 6 settled items 1, 2, 3 and 8: the design now says what the plan read (design 3.1, 3.4, 3.7), and item 2 is settled by decision 94. Their text stays below, marked, so that their numbers hold. What revision 4 settled is gone from this list: rule 3 and the relay; the leaving leader (the lease in each agent's own view, the time from when an agent first holds V, a heard stuck leader stalls); a lost leader that is not leaving; the judge as a function of two serials; "at the thaw" in 5.4 and 5.5; the leaving NS names at a new leader; "made under" against the stamp at send; the source of a provider's nameserver names; and "which the leader may hasten". Revision 5 settled none of the five items that were left; items 6 to 9 are new with it. None of what is left makes the design unbuildable. Each is a gap or an ambiguity; the plan builds the reading given, and the design should say it.

1. *Settled by revision 6 (design 3.4).* **Which leader a member with no record listens to, and who leads the first activation.** Design 3.4 has a member with no record take "the leader's word only", and at the first start after the upgrade has "the leader" make the common newest serial active. A member with no record does not know the active serial, so it does not know the zone's group. The plan (S9): a member takes a known active serial from the agent that leads the zone's group under that serial, by the election records it has first hand; at the first start the zones are placed in groups by their newest copy, and that group's leader makes the first activation.
2. **A refused newest serial with an acceptable one between.** If the owner publishes V1 (a record) and V2 (its role) before V1 is thawed, the judge sees V2 against N and refuses it, and V1 is never agreed on. A V2 that comes after V1's thaw waits for "done" and is judged against V1 (design 3.3), so only the first case is left. The plan of revision 5 was: as the design had it; the zone stays at N, and the status tells the owner to publish a corrected serial with a higher serial. *Settled by revision 6 (decision 94):* the refused V2 does not replace V1; V1 is agreed and done, then V2 is judged against V1.
3. *Settled by revision 6 (design 3.1).* **Where a member that moves straight fetches the from-serial.** Design 3.1 has it judge the thaw's own pair, "with the from-serial fetched if it lacks it". The owner serves only its newest copy, so the provider's chain cannot give an older serial. The plan (S7): it asks the leader, or a voting member that tells that serial as its active serial or its last thaw's from, by an RFI of subtype `instructions`, and checks the answer against the digest. Until it has it, it starts nothing.
4. **A start's announcement.** Design 3.4: a member's tellings count only from its last start, "it announces each start (membership 5.1)". Membership 5.1's start request goes to voting members only. The plan (S5a): the stamp's epoch, a counter raised at every start, which every member receives in beats.
5. **The agents' KEY at a hand-over of the parent sync.** S20 has the combiners stop applying the agents' KEY when the agents stop syncing (its step 4); design 5.5 does not say what becomes of the KEY.
6. **Which of the parent's NS names are the leaving provider's.** Design 5.2 takes the leaving provider's names from its stamp and from "those the parent's NS RRset holds for it at the removal's start", and does not say how a name at the parent is known to be its. The plan (S17b, decision 92): a name in the parent's NS RRset at the removal's start that no remaining provider tells in its stamp or contributes, and, under `nsmgmt=owner`, that the owner's NS RRset under V does not name. A name given to the wrong provider only holds the step, safely, and the status names it.
7. **The sweep at a "done" with a newer serial waiting.** Design 3.3 runs the sweep at "done", never while the zone is frozen, and has a newer serial that waited agreed at "done"; agreeing is frozen. The plan (S12, S17b, decision 93): the sweep runs first, by V, and then the waiting serial's agreement starts, as the design's order reads.
8. *Settled by revision 6 (design 3.7).* **The interim build sentence in design 3.7.** Its second bullet, on the owner's NS RRset in a removal (5.2), ends "On a build where the steps of 5.5 do not exist yet, the edit is refused and the owner must not write to the parent". 5.5 is the parent sync, which the first bullet covers. The plan reads both: before S20 a change of `parentsync` is refused and the owner must not write to the parent; before S17b a removal is refused, and the owner keeps the provider's NS records in its NS RRset and at the parent (S4's guide).
9. **A record removed while its removal is not done.** Design 3.1 agrees such an edit and keeps the provider a member with the last identity listed. With one transition at a time it cannot be active before "done", and the removal is done by then; the judge does not refuse it anyway, since the provider has no role under V. The plan keeps the clause and its one test in S4, and S15 reads the removal's stored identity (decision 85).

### 7.3 Open points

1. **The key's number.** 8, assigned by the draft (proposed). A private-use number does not fit providers of several administrative domains, and tdns does not act on one.
2. **Whether the canonical reading and its digest go into the draft.** Needed only if implementations other than tdns-mp are to compare digests. *Decided (decision 102): not now; design rule 2 says they are tdns-mp's own.*
3. **The step's carrier.** In the leader's stamp, confirmed by each member's stamp (proposed, S12), or a confirmed message of its own.
4. **The two times and their keys.** `multi-provider.transitions.leaving-timeout` (proposed 3600 s) and `multi-provider.transitions.no-role-timeout` (proposed 900 s). The first serves three rules (design 3.2, rule 4): the excusal at the thaw, how long a telling counts, and the excusal of a leaving member that leaves a step unconfirmed. Proposed: one key for the three. The other way: a key of its own for the freshness of a telling.
5. **One agent per part.** A combiner or signer configured with more than one agent (`ec1c6b3:v2/hsync_utils.go:884-905` takes every `mp.Agents` entry): whose hand-over counts. Proposed, and built by S10 and S11: one agent per part for a multi-provider zone, and the config check refuses more.
6. **The order of the zone's NS RRset and the parent's in a removal** (design 5.2 leaves it open). Proposed, as S17b builds it: the zone's NS RRset first (the withdrawal at every member), then the explicit sync, then a watch on the parent until it no longer names the leaving provider's nameservers. The other way: the parent first, then the zone. Under `nsmgmt=owner` the order is the owner's: its edit drops the names from the zone first (design 5.2). *Decided (decision 96): as proposed; design 5.2 says so.*
7. **How the provider's nameservers take `pubkey` and `pubcds` from their agent** (design 5.6). Proposed: their `use-hsyncparam` reconciler skips a multi-provider zone (P6), and the agent publishes at the `_signal` names through its combiner, by the step's sets (S21). The other way: tdns-auth takes a per-zone setting from the provider's agent over its API, which needs a link from each agent to its nameservers that does not exist.
8. **The size of a mass edit.** With S5a, every changed zone's stamp is in every beat until "done": 40,000 zones at about 60 bytes is 2.4 MB per beat per peer, about what today's rows list already. S22 cuts the rest state; nothing cuts the mass edit itself.
9. **The removal's waits.** A removal waits the parent's NS TTL and then its DS TTL, two days and one under a large TLD. The zone stays in reconciliation, with planned rollovers, operator edits and the owner's next edit held (one transition at a time, design 3.3). Proposed: as the design has it. The other way: ordinary work resumes once only waits remain. *Decided (decision 97): as the design has it, with the status naming the wait and when it ends.*
10. **"Safe to remove" and the record.** After "done" the leaving provider is a member only by its record, waited for with the time-out, until the owner removes the record. Proposed: its status says "safe to stop once the owner has removed the record".
11. **Taking a multi-provider zone unsigned.** Refused for good, or a later kind of change: the DS removed at the parent first, its TTL, then no signing.
12. **The server's switch to its own signer** (S18b): the operator's step, as proposed, or a relay mode in tdns.
13. **A part that sees a newer serial in its copy than it was handed.** May it hold its key machine on its own, in the safe direction only? Proposed: no; one reader.
14. **The auditor's page:** whether it shows what each provider's parts hold.
15. **`resync --push` during a transition:** refused (proposed) or kept.
16. **How often** the agent repeats an unchanged hand-over, and whether per zone or per batch.
17. **"Done" for a take-up of `parentsync`:** without the parent's trust in the key (proposed), or with it.
18. **Which of several published KEYs is the zone's key.** Open for the project owner. Since PR 178's `bab04b1`, membership step 7b holds no key as the zone's while the apex carries several: nothing is imported, retired or made, no sync that needs the key is asked for, and an error line tells the operator to leave one KEY. A rule that picks one without the operator is not written. Until S17a, step 7b's fleet precondition stands: each zone with `parentsync=agent` publishes one KEY. *Decided (decision 98): step 7b's rule stands; nothing picks one for the operator (design 6).*
19. **A leader whose held KEY the parent refuses.** Open for the project owner. The leader holds the zone's key and the parent does not trust it: its UPDATE gets BADKEY, and a tdns parent with the default policy refuses the re-bootstrap (membership step 7b, "still not covered"). Since the leader holds the zone's key, no round asks for another. From S14 `keyPending` holds its syncs and the offers repeat, which such a parent goes on refusing. No rule and no status says what follows. *Decided (decision 99): no action of its own; the syncs stay held and the status says that the parent refuses the zone's key, until tdns parents follow #917 (design 6).*
20. **Whether the recovery of a lost key is built now for tdns parents.** Open for the project owner. The membership plan hands the question here (its 7.1 and 7.5): a tdns parent as pinned takes a second key once it finds it served, when its policy takes a self-signed upload. This plan builds the recovery only once tdns parents follow #917 (7.4). *Decided (decision 100): not now.*
21. **Two leaders for a time, in a zone that publishes no KEY, can each make a key** (membership step 7b, "still not covered"; membership 2.13). The design is expected to close it: groups follow the leader's word at the activation, and S7 drains the leader's parent work at every hand-over. No step shows it yet. Proposed: a test, `TestTwoLeadersNeverBothMakeAKey`. *Decided (decision 101): the test, in S14.*

### 7.4 After this plan

- **The recovery of a lost SIG(0) key** (design 6; membership decisions 18 and 25). A leader action of its own that starts only in a steady zone and is held during a transition: a new KEY published beside the old one, bootstrapped once the nameservers serve both, then the old key deleted at the parent by an update the new key signs, and taken off the apex. It reuses S17a's delete and "a member keeps the leader's KEY". Built once tdns parents judge a bootstrap by what they find (tdns #917). A tdns parent as pinned refuses a self-signed upload by default (tdns `3615261f:v2/delegation_policy.go:48`). Whether it is built sooner for tdns parents is open (7.3). Until then the stall for the operator stands: from membership step 7b no key is made while the zone publishes one, and S14 shows it as `SIG(0) key: LOST`.
- **Who answered a beat.** *Update 2026-10-26:* the HTTPS half is done: the client checks the server against its TLSA record (tdns-transport #35, tdns #942, tdns-mp #242), and the server checks the client's certificate (tdns-mp #246). The DNS half below is still open, and answers still count for nothing (design rule 4). As planned on 2026-10-18: over HTTPS, a `VerifyConnection` against the dialled peer's TLSA record in the TLS config tdns-mp builds (`ec1c6b3:v2/hsync_transport.go:289-293`), probably with no change of tdns-transport; over DNS, tdns-transport refuses a confirm without the payload envelope while payload crypto is on, and stops falling back to a plain answer (tdns-transport `f76a204:v2/transport/dns.go:706-714`, `handlers.go:245-256`). With it, answers could count, and a peer that changed could be heard a beat sooner. Nothing in this plan needs it (decision 12).
- **The asking half of the membership plan's decision 6.** A member asks its upstream for the transfer set-up and applies the answer. It needs a tdns call that changes a configured secondary's primaries at run time, which does not exist, and still does not reach an operator's own nameservers. Until then the operator sets it up, and the steps of S18a and S21 wait for the transfer confirmation.
- What the design leaves out (its section 7): what the parent's scan does with a nameserver that lacks a record after S12's time-out; the timing and operator view of a provider that does not cooperate while it is removed; the end of multi-provider service beyond S2's reading; a rollback other than by a higher serial; the meaning of the HSYNC3 state field beyond OFF.
