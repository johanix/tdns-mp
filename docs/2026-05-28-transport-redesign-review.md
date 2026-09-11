# Transport redesign: plan review vs current code + today's bugs

Date: 2026-05-28
Status: REVIEW (analysis only; no code changes). Requested after a day
of testbed bugs that all traced back to overlapping peer registries.
Reviewed: `2026-04-15-transport-interface-redesign.md` (master, updated
2026-05-28), `2026-05-08-transport-refactor-next-bites.md`,
`2026-05-19-peer-discovery-engine-extraction.md`,
`2026-04-30-transport-refactor-semi-easy-bites.md`, and
tdns-transport `2026-05-27-in-channel-chunk-transport-design.md`.

## Correction (after re-reading the 2026-05-19 doc)

An earlier draft of this review anchored on the 04-15 master and claimed
the plan "does not account for the third registry / does not address
consolidation." **That was unfair.** The
`2026-05-19-peer-discovery-engine-extraction.md` doc already *decides*
the consolidation and already names today's bug class:
- **§D-3 (Decision B):** `AgentRegistry` **embeds `*hsync.Registry`**;
  hsync.Registry owns `S`/`RemoteAgents`/`helloContexts` + protocol
  methods; AgentRegistry keeps only MP-level state (gossip/groups/
  elections/transport). = consolidate the two MP-side registries → one.
- **§D-4 (B):** event-driven `ApplyHsyncDiff` for all roles + reconcile
  as a safety net (fixes the registration-latency gap).
- **§D-5:** rejects additive-only reconcile *because* "stale registry
  entries skew gossip matrices and `peer list`" — i.e. today's Bug 1.

So the plan, taken as **04-15 master + 05-19 extraction together**,
already targets the right end state. The points below stand as
corroboration + a few genuine refinements (see "What this review still
adds", end).

## TL;DR

- **(a) The plan still works as a direction**, and the codebase is
  progressing along it — but the plan is (i) status-stale (several
  "PLAN" bites are already implemented) and, more importantly, (ii)
  **out of date on the registry model**: it still frames a *two*-registry
  problem, but the peer-discovery-engine-extraction work (Cut A, 2026-05-19)
  introduced a **third** peer-state store (`hsync.Registry`). The plan's
  §C resolution does not account for it.
- **(b) The target is directionally right and today's bugs strongly
  validate it** — every bug was a symptom of duplicated peer state +
  asymmetric sync, which is exactly what the plan's "single source of
  truth per concern, loose coupling by PeerID" is meant to kill. **But we
  can do better**: extend the partition to absorb the third registry
  (end state = two stores, not three), treat the sync/bridge functions as
  things to *delete* rather than maintain, derive zone membership from
  HSYNCPARAM instead of storing-and-syncing it, and **reprioritize the
  registry-consolidation work earlier** since that is where the bug class
  lives.

## Background: today's bugs were all one root cause

Four bugs fixed today, plus loose ends, all trace to **three peer/agent
registries with overlapping fields and partial/asymmetric setters**:
- `tdnsmp.AgentRegistry` (`Agent`: `Zones`, `ApiDetails`/`DnsDetails`
  with addresses + per-mechanism state) — what `peer list` shows and
  what distribution recipients are read from.
- `hsync.Registry` (`hsync.Peer`: `Zones`, `ApiDetails`/`DnsDetails`) —
  the shared HsyncEngine's store; feeds AgentRegistry via `OnPeerStored`.
- `transport.PeerRegistry` (`transport.Peer`: `DiscoveryAddr`/
  `OperationalAddr`, `Mechanisms`, `SharedZones`) — what the send path
  actually reads.

Zone membership is held in **all three**; addresses + per-mechanism
state in **all three**. The bridges are partial and one-directional:
- `GetOrCreatePeer` copied state but (until today's fix) not the
  address → combiner unreachable ("no address available", Bug 2).
- `mergeAgentDetails` is fill-gaps-only — it never overwrites, so a
  *changed* address on an existing agent is silently not propagated
  (a latent Bug-2 waiting to happen).
- `syncHsyncPeerFromAgent` doesn't copy `Zones`; there is **no removal
  hook** anywhere, so a pruned membership never propagates → stale
  `agent.Zones` (Bug 1 surface).
- Membership stored in `agent.Zones` drifted from the authoritative
  HSYNCPARAM roles (Bug 1).

So: the user's instinct is correct — finishing the transport redesign
is the structural cure for this whole bug class.

## (a) Does the plan still work, or has the codebase moved?

**The plan's spine is intact.** The 9-phase structure, the tiered
transport API, and the resolved open questions still describe a valid
destination, and the code is genuinely on that path: Phase 0 (test
harness) done; Phase 1 per-mechanism state on `transport.Peer` done
(steps 1–4); `Agent.PeerID` (Phase 7 step 1) done; the early- and
semi-easy bites are in.

**But the codebase has moved past the plan in three ways:**

1. **The bite-plan docs lag the code.** `2026-04-30-...semi-easy-bites.md`
   is marked `Status: PLAN`, yet its bites are already implemented in
   this worktree — Bite H (`GetOrCreatePeer` split out of
   `SyncPeerFromAgent`, `hsync_transport.go:1431`), Bites D/E/F/G all
   live. The master plan's inline annotations stop around 2026-04-30.
   Net: the plan needs a status refresh, but its direction holds.

2. **A third registry now exists that the 04-15 master §C predates —
   but the 05-19 doc already resolves it.** The master plan's "dual
   registry problem" (§C) names only `transport.PeerRegistry` +
   `AgentRegistry`. Cut A (2026-05-19) added `hsync.Registry` as a
   *permanent* MP-side store. The 05-19 doc **§D-3 decides** the
   consolidation (option B: `AgentRegistry` *embeds* `*hsync.Registry`;
   hsync.Registry owns `S`/`RemoteAgents`/`helloContexts` + protocol
   methods; AgentRegistry keeps gossip/groups/elections). So the
   end-state model is settled — but it's split across two docs (04-15
   §C/Phase 7 = transport-side; 05-19 §D-3 = MP-side), and the 04-15
   master text was never updated to reference it. The plan is therefore
   *correct but fragmented*, not *incomplete*.

3. **The `Send` signature diverged.** The plan specifies
   `tm.Send(ctx, peerID string, msg)`; the actual `TransportManager.Send`
   is `Send(ctx, peer *Peer, req)`. Minor, but it means the "fully
   generic, by-peer-ID reliable queue" the plan envisioned isn't realized
   — callers still resolve `*Peer` first.

**Verdict (a):** the plan works as a direction and most phases are still
valid steps, but it must be (i) re-statused and (ii) have its registry
end-state (04-15 §C + 05-19 §D-3) stated in one place.

### Verified code status (read from the branch, not the plan docs)

The plan docs and several code comments **undercount** what is already
done — verified directly in the `peer-discovery-engine-extraction`
worktree on 2026-05-28:

- **The shared `hsync.Engine` migration is DONE for both roles.** The
  agent runs `HsyncDataEngine` (`hsync_data_engine.go`), which wraps
  `core *hsync.Engine`, wired at `start_agent.go:352`. The auditor runs
  `AuditorEngine`, also wrapping `hsync.Engine`, wired via
  `NewAuditorEngine`. So the headline "Cut A" migration — the
  highest-risk live swap onto the shared engine — **already shipped and
  is running on the testbed.** This is *not* pending work.
- **`hsyncengine.go` (28KB) is NOT a dead/parallel engine.** Its
  handlers (`SyncRequestHandler`, `MsgHandler`, `HandleStatusRequest`,
  `CommandHandler`) are the message-processing *bodies* that
  `HsyncDataEngine` delegates to (`hsync_data_engine.go:58/89/95`). What
  remains is *absorbing* these `AgentRegistry` methods into the engine /
  `hsync.Registry` and deleting the thin wrappers — which is the **same
  work** as the 05-19 §D-3 embedding, not a separate migration.
- **Stale comments confirmed:** `NewHsyncDataEngine` carries "Not wired
  until Phase 5" (it *is* wired); `start_auditor.go` says the auditor
  "does NOT run HsyncEngine" (it does). Treat plan/comment status claims
  as lower-confidence than the code.

**Meta-finding:** before sequencing any remaining work, do a
code-vs-doc reconciliation pass. Twice on 2026-05-28 the docs/comments
claimed work was pending that was in fact already in production. An
accurate "what's actually left" list must come from the code.

## (b) Is the target architecture right given today's bugs? Can we do better?

**The target is right in principle.** The plan's load-bearing decision —
"single source of truth *per concern*": transport owns identity/address/
per-mechanism-state/liveness/crypto/stats; the app owns zones/roles/
groups/elections; joined only by `Agent.PeerID`; delete the sync
functions — is exactly the cure for today's bugs. With one owner per
datum and no bidirectional sync, Bug 2 (address divergence) and the
`mergeAgentDetails` latent bug cannot occur, because there is nothing to
sync and nothing to drift. The decision to keep **two** stores (not one)
is also correct: the transport/app split is what makes tdns-transport
reusable, and collapsing to a single registry would reintroduce the role
coupling the whole redesign exists to remove.

**Four ways to do better, informed by today:**

1. **Make the partition cover all three registries — end state is two
   stores, zero overlap.** Resolve doc 3's Open Item 3 *toward
   consolidation*: fold `AgentRegistry` into `hsync.Registry` (one MP-side
   store), and **slim `hsync.Peer` to MP metadata only** — remove its
   `ApiDetails`/`DnsDetails` address + beat-counter duplication and have
   it read transport state via `transport.PeerRegistry.Get(peerID)`. Then
   there are exactly two stores: `transport.PeerRegistry` (transport
   state) and one MP registry (zones/roles/groups/elections), joined by
   PeerID. The plan's §C needs to be rewritten in these terms.

2. **Treat the bridge/sync functions as things to *delete*, not improve.**
   Today proved they are irreducibly bug-prone: `GetOrCreatePeer`'s
   partial copy, `mergeAgentDetails`' fill-only merge, the missing
   removal hook. The temptation (and what we did today) is to patch each
   asymmetry; the structural fix is one-owner-per-datum so the functions
   disappear. Phase 7 already says "delete `SyncPeerFromAgent`"; extend
   it to delete the `hsync`↔`Agent` bridge (`hsyncPeerToAgent`,
   `syncHsyncPeerFromAgent`, `mergeAgentDetails`, `OnPeerStored`) too.

3. **Derive zone membership; don't store-and-sync it.** Today's Bug 1 fix
   established that participants are a pure function of HSYNCPARAM roles
   resolved through ON HSYNC3 labels. The strongest version of the target
   is: do not keep a parallel `peer.Zones`/`SharedZones` map that must be
   kept in sync at all — derive membership from the zone's authoritative
   RRsets on demand (or cache with a single explicit invalidation). The
   plan already removes `ZoneRelation`/`SharedZones` from transport;
   apply the same "derive, don't duplicate" rule to the MP side, rather
   than just moving the stored map from transport into MP.

4. **Reprioritize: pull the registry consolidation earlier.** The current
   sequence front-loads N1–N10 + Phases 2–6 (type migration, handler
   cleanup, chunk-handler split, discovery-body move) and leaves the
   registry/bridge deletion to Phase 7 at the end. But the entire bug
   class that's hurting the testbed lives in the registry overlap. The
   highest-leverage move is to bring the single-source-of-truth work
   (Phase 1 step 6 + Phase 7 bridge deletion, *extended* to the third
   registry) forward, ahead of the cosmetic/type-migration phases.

**Verdict (b):** keep the plan's target (two partitioned stores, coupled
by PeerID, sync functions deleted) — today's bugs are evidence *for* it,
not against. Improve it by (1) explicitly absorbing the third registry so
the end state is genuinely two non-overlapping stores, (2) committing to
deleting the bridges rather than maintaining them, (3) deriving zone
membership instead of storing it, and (4) sequencing the registry
consolidation first.

## What this review still adds (net of the 2026-05-19 decisions)

The 05-19 doc already decides the MP-side consolidation and the
removes-fix. Three things this review contributes on top:

1. **The consolidation is split across two docs; both halves must land.**
   05-19 §D-3 fixes the *MP-side* overlap (`AgentRegistry` +
   `hsync.Registry` → one). But Bug 2 (combiner "no address available")
   was the *transport-side* overlap — `transport.PeerRegistry` vs
   `AgentRegistry`, the `SyncPeerFromAgent`/`GetOrCreatePeer` partial
   copy — which is the **04-15 master §C / Phase 7**. So the full bug
   class only closes when D-3 *and* Phase 7 both land. Track them as one
   "registry consolidation" effort spanning both docs, not two unrelated
   phases. (Today: Bug 1 = MP-side half, Bug 2 = transport-side half.)

2. **Derive, don't sync-correctly.** §D-5 fixes the reconcile to *apply
   removes* so the stored registry tracks HSYNC3. Today's Bug 1 fix went
   further: derive participants from HSYNCPARAM on demand, so there is no
   stored zone-membership copy to reconcile at all. For zone membership
   specifically (a pure function of the authoritative RRsets), deriving
   is strictly stronger than keeping a stored copy correct — consider it
   the end form of D-5, not just "make reconcile apply removes."

3. **Prioritize it.** Pull D-3 / D-4 / D-5 + the transport-side Phase 7
   ahead of the type-migration / handler / chunk-split phases. The
   testbed pain is entirely in the registry overlap; the other phases are
   real but not the current source of bugs.

## C refinement: the opaque-message seam (send/receive symmetry)

Workstream C ("strip MP knowledge from transport") is split across the
master plan's Phase 2 (remove MP request/response *types*), Phase 3
(move the receive-side `Handle*` handlers to tdns-mp), and Phase 4
(split the chunk handler). It names the pieces but does **not** state
them as one coherent mechanism, and three things are underspecified:

**Gap 1 — ELECT-* is absent from the inventory.** Verified in code:
elections ride *inside* RFI as `RfiType` values
(`hsyncengine.go:263` handles `ELECT-CALL/VOTE/CONFIRM`;
`parentsync_leader.go` broadcasts `"ELECT-CALL"`). So `HandleRfi`
covers them transitively. The plan should state explicitly that the
entire election protocol is app-level and transport never knows
"ELECT" exists.

**Gap 2 — the send side has no symmetric move.** Phase 3 moves the
*receive* handlers and Phase 2 removes the request structs, but nothing
addresses the **typed send methods** on the concrete transport:
`DNSTransport.Sync/Confirm/Keystate/Edits/Config/Audit`
(`dns.go:603/700/743/785`, plus the interface's
`Sync/Confirm/Relocate`). Phase 2 strips their argument *types* but
never says "collapse the typed send verbs into one generic
opaque-message send." Bite 3's `tm.Send` is explicitly a *shim layered
over* these typed methods, not their replacement — so the end-state
send API is undefined.

**Gap 3 — no single dispatch seam is named.** Dispatch lives in two
places today: `DNSMessageRouter` (keys on `MessageType` constants;
`dns_message_router.go`) and `chunk_notify_handler` (keys on
`"beat"/"sync"` strings). Phase 3 touches the first, Phase 4 the
second; neither states the unifying contract.

**The refinement — state C as one opaque-message contract:**

> Transport's message vocabulary is exactly `hello / beat / ping /
> confirm / chunk` **plus one generic opaque app-message carrier**
> (today's `Sync`, generalized to `{Scope, TypeToken string, Payload
> json.RawMessage}`). Every MP verb — SYNC, UPDATE, RFI and its
> subtypes KEYSTATE / EDITS / CONFIG / AUDIT / ELECT-* / STATUS — is an
> app-level `TypeToken` value that transport never interprets.
>
> - **Send side:** the typed `DNSTransport.Sync/Keystate/Edits/Config/
>   Audit` methods collapse into the single opaque carrier; tdns-mp sets
>   `TypeToken`. Transport keeps only its own verbs + the carrier.
> - **Receive side:** transport dispatches *only* its own ~5 types via
>   the router, and hands everything else to **one** tdns-mp callback as
>   `(senderID, TypeToken, rawPayload)`. tdns-mp owns the entire verb
>   dispatch table (the moved `Handle*` handlers register behind that
>   one callback).
> - **Chunk handler (Phase 4):** after reassembly+decrypt, it feeds the
>   same single callback — it does not itself know verb semantics.

This makes Phases 2/3/4 the *three edits that implement one seam*, not
three loosely related cleanups. Infrastructure largely exists:
`DNSMessageRouter` is already a generic
`map[MessageType][]*HandlerRegistration` with `Route()` + registration
— so the work is shrinking transport's *registered* set to its own
verbs and defining the one opaque entry point, not building new
machinery.

## Suggested next step (for discussion)

Before resuming the bite sequence, update the master plan's §C from a
two-registry to a three-registry model with the explicit end state
"`transport.PeerRegistry` + one MP registry (hsync.Registry, AgentRegistry
folded in), zero field overlap, joined by PeerID, all bridges deleted,
zone membership derived from HSYNCPARAM." Then re-order the phases so that
consolidation lands before Phases 2–4. The type-migration / handler /
chunk-split phases are real but lower-risk and not the source of the
current pain.

## Effort assessment (in Claude-implementation units, not calendar)

These are estimates of *my* (Claude's) active engagement, in
"sessions like 2026-05-28" (investigate → land → operator deploys →
debug emergent breakage). The bottleneck is **verification on the
NetBSD testbed, which I cannot drive** — not typing. Raw diff-writing is
a small fraction; the cost is the deploy/observe/debug loop and the
runtime surprises a live distributed refactor guarantees. Refactor
estimates skew long, and the variance here points up (cross-repo,
can't-test-locally, distributed state — exactly what bit us today).

| Workstream | Status / what's left | Sessions | Risk |
|---|---|---|---|
| A. Registry consolidation (05-19 §D-3 embed + §D-4/D-5 + 04-15 Phase 7 transport-side bridge deletion + Phase 1 step 5/6 + derive-membership) | the bug-class cure | 2–4 | high (behavior, ~25 call sites, runtime-only breakage) |
| B. Shared-engine migration | **mostly DONE** (agent+auditor already on `hsync.Engine`); residual handler-body absorption **collapses into A** | ~0 (folded into A) | — |
| C. Transport API cleanup (Phase 2 strip MP types ~141→121 fields/13 types; Phase 3 routers; Phase 4 chunk-handler split) | reusability — the strategic goal, not a bug source | 3–5 | high, cross-repo |
| D. Phase 5 remainder (Hello/Beat parallel-send semantics — *needs a design decision*; liveness middleware) | | 1–2 | medium |
| E. Phase 6 pt2 (move discovery body into transport) | | ~1 | medium |
| F. Phases 8–9 + Gossip→AppData wire break + doc tasks | | 1–2 | low |

**Total ≈ 8–13 sessions** (down from an initial 10–17 once B was
verified already-done and folded into A). The single highest-risk step
I'd have flagged — swapping the agent onto the shared engine — is
**already behind us and in production**, which de-risks the remainder.

**Sequencing:** A first (≈25–30% of the effort, retires essentially the
entire current bug class, and gives C a single peer-state owner to
migrate against). Then D/E, then C (most work, least urgent — it buys
transport *reusability*, not bug fixes), then F. After A the system is
usable and more correct than today, but tdns-transport is not yet
reusable (that is C).

Caveats that gate me, not speed: (1) Phase 5 parallel-send semantics is
an undecided design point needing an operator call; (2) the §D-3
embedding is a live swap of the backing store under ~25 readers — land
it alone, deploy, observe before stacking on it.
