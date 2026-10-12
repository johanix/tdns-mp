# Confirmations are copied to the zone's auditors

**Status:** implemented on branch `feat/auditor-liveness-and-pending`, for issue #152. Unit and transport-harness tests only; not yet run on a test fleet. The design text is not rewritten after review (dated amendments at the end).

**Provisional:** how the copy travels (section 3). It is sent once, unconfirmed, under the transport's own `confirm` verb. Section 7 lists what that leaves open: a lost copy is not repaired, and a copy can meet a peer that is not an auditor. A message type of its own, sent through the confirmed queue, would close both, and is the likely replacement. The auditor's side (sections 5 and 6) does not depend on which of the two carries the copy.

## 1. What was missing

A distribution goes from its originating agent to every other member of the zone, the auditor included. Each receiving agent answers PENDING at once and gives its final word when its combiner has answered. Both go to the originator and to nobody else.

So the auditor saw an operation start and nothing after that. With one agent stopped and an NS record added by another, a test fleet's auditor had the SYNC in its event log and could not say that the operation was pending, for how long, or on whom. The originating agent had all of it. Showing a blocked operation is what the auditor is for.

## 2. The decided design (2026-10-11)

Each agent sends its final confirmation of a distribution to the originator **and to every auditor of the zone**.

- It is driven by events. The auditor never polls, and never has to choose when to ask.
- The auditor knows the zone's members. With their confirmations it can say "pending on X for N minutes" from its own clock, and show a rejection with its reason.
- It does not depend on the originating agent staying up.

The cost is one more message per confirmation for each auditor. Considered and not chosen: the auditor asking the agents for their pending operations.

## 3. On the wire

The copy is the confirmation message itself, verb `confirm`, with one field added:

```
"originator": "agent.alpha.example."
```

The field is needed. A distribution ID does not say whose distribution it is: every agent numbers its own from the second its process started, so two agents' IDs coincide, most of all when a fleet starts together. The copy's sender is the confirming agent. Without the originator the auditor cannot tell which distribution was confirmed.

`MPTransportBridge.copyConfirmationToAuditors` sends it, right after `sendRemoteConfirmation` has sent the originator's. `DNSTransport.Confirm` builds its payload from a fixed set of fields, so the copy is built in tdns-mp (`DnsConfirmCopyPayload`: transport's `DnsConfirmPayload` and the field) and sent with `DNSTransport.SendApp`, fire and forget. It is the same NOTIFY(CHUNK) either way. If tdns-transport later takes the field itself, the wire does not change.

Who gets a copy, and what is copied:

- The identities that hold the `auditors=` role in the zone and no `servers=` or `signers=` role (`AuditorsForZone`). A provider that the zone lists as an auditor too gets the distribution in its own right, and no copy.
- Not the originator, and not the sender itself.
- The final confirmation only. The immediate PENDING says that the message arrived, nothing more.
- An auditor sends no copies. Its own confirmation is not a member's answer.

On the auditor the verb is still transport's. tdns-mp adds a route for it (`routeConfirmMessage`) that acts only where there is auditor state. It takes the copy's sender as the transport established it and drops a payload that names another; it drops a copy whose originator is not a voting member of the zone.

## 4. Old agents, old auditors

- **An auditor on older code that gets a copy.** The JSON decoder ignores the field. The transport's confirm handler calls `OnConfirmationReceived`, as for any confirmation: it looks for a queued message with that ID to that sender (an auditor queues none), for a DNSKEY distribution with that ID (an auditor tracks none), and hands the confirmation to the auditor engine, which writes a `confirm` row in the event log. Nothing else happens.
- **An agent on older code.** It sends no copies. The auditor therefore lists a member that has sent it none since the auditor started as `unknown`, not `pending`, and raises no observation for it. A member counts as one that sends copies from its first copy, in any zone.
- **A group without an auditor.** `AuditorsForZone` is empty and nothing is sent.
- **A copy at a peer that is not an auditor** (an agent that a zone lists under `auditors=`). The route returns at once. The transport's handler treats it as it treats every confirmation: nothing is queued or tracked under that ID, so nothing changes. See section 7 for the one case where an ID can match.

## 5. What the auditor keeps

Per zone, per originator and distribution ID (`AuditZoneState.Distributions`):

- the originator, a one-line summary of what the distribution carries, when the auditor first saw it and when the distribution itself arrived;
- the members awaited: the zone's voting members when the distribution arrived, without the originator. An auditor is not awaited;
- for each member the status of its final confirmation, when it was seen, and the reason of a refusal.

The distribution and a copy can arrive in either order. A copy that comes first is kept and counts when the distribution arrives.

Bounds:

- 200 distributions per zone. When full, the oldest that the auditor never received itself goes first, then the oldest with no confirmation missing, then the oldest that still waits.
- A distribution with no confirmation missing is dropped an hour after the auditor last saw anything of it. One that still waits is dropped after 24 hours: the sender's reliable queue gives a message up after that.
- A refusal's reason and a summary are cut at 300 bytes, and a distribution ID longer than a DNS label is not followed: all three are what a peer sent.

The state is in memory, like the rest of the auditor's zone state.

## 6. The view and the observation

`tdns-mpcli auditor confirmations [-z zone] [--pending]`, API command `confirmations`. It lists each distribution with its originator, age, state and summary, and below it each member as `confirmed`, `pending`, `rejected` (with the reason) or `unknown`.

It is a view of its own and not part of `auditor zones`. `zones` prints every zone's provider table and takes no zone filter, and its snapshot is also what the dashboard and the detectors read.

A detector raises one observation when a distribution has waited longer than `audit.pending_threshold` for a member, counted from when the distribution reached the auditor. The default is 2 minutes, the wait after which the originator itself sends the distribution again. The observation names the distribution, its originator and the member. A second one follows when the member has confirmed, or refused.

## 7. Not covered

- **A lost copy.** A copy is sent once and nothing answers it, as with the confirmation it copies. But a lost confirmation is repaired by the originator's resend, and a lost copy is not: the member stays `pending` at the auditor although the originator has its answer. Sending the copy through the reliable queue, confirmed by the auditor, would close this.
- **An auditor restart.** A distribution sent before the auditor started is not followed: the other members may have confirmed it to the process that is gone. A blocked operation from before the restart is not shown after it.
- **A member that has confirmed nothing since the auditor started.** It reads `unknown` (section 4), also when it runs this code. A distribution blocked on it is listed, but not as `pending`, and no observation is raised. The first copy from the member, for any distribution, ends this. A way for an agent to say that it sends copies, in its hello or its gossip row, would remove the case; neither carries such a field today.
- **A distribution to one member only** (a resync on request). It does not reach the auditor; its confirmation does. It is listed as `unseen`, with no members awaited.
- **A change of members while a distribution waits.** The members awaited are those the zone had when the distribution arrived.
- **A copy at an agent that a zone lists as its auditor.** The transport's handler matches a confirmation to a queued message by distribution ID and sender. IDs coincide (section 3), so a copy could settle such an agent's own message to the same member. This needs a zone that names an agent under `auditors=`. Distribution IDs that are unique across agents would remove the case.
- **The web dashboard** does not show the view.
