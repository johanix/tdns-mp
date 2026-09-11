# Sendoff prompt — adversarial review of the stacked Phases 1–4

Date: 2026-08-25
Purpose: hand a fresh agent the task of reviewing the four stacked,
never-deployed transport-consolidation phases in tdns-mp +
tdns-transport, *before* the blocking testbed pass runs.

Everything below the line is the prompt. It is self-contained: it
assumes no prior conversation.

---

You are reviewing a stack of four refactoring phases in the tdns-mp
multi-provider DNSSEC coordination layer. The code compiles, the unit
suite is green, and the race detector is clean — I have verified all
of that already, so do not spend your budget re-running it and
reporting success. Your job is to find what those signals cannot see.

## Why this review exists

These four phases were written between 2026-06-14 and 2026-07-10 and
have **never run on a testbed**. The last live verification was
2026-06-13, against code that predates all of them. The project's own
plan calls a stacked testbed pass BLOCKING for the next stage. This
review is the cheap pass that runs first: find the defects that a live
fleet would find, before anyone deploys to a live fleet.

The phases were also executed with a discipline the authors explicitly
abandoned mid-flight. The original plan called for one testbed
checkpoint and one git tag per phase; neither happened. There is a
single tag, `end0-complete-pre-d2`, sitting *before* the whole stack.
So there is no per-phase bisect point and no per-phase live evidence.
Treat every phase boundary as unvalidated.

## What to review

Two repos that move as a pair. Both are already checked out:

- `/Users/johani/src/git/tdns-project/tdns-mp` — branch
  `phase-4-c0-gate`, review range **`388dd3b..92e64a6`**
  (13 commits, 49 files, +1023/−1553 under `v2/`)
- `/Users/johani/src/git/tdns-project/tdns-transport` — branch
  `phase-2.6-discovery`, review range **`892e5de..37c0dfb`**
  (2 commits, +580/−36 under `v2/`)

Note the asymmetry: transport stops at Phase 2.6 because Phases 3–4
did not touch it. That is expected, not a defect.

What each phase did:

| Phase | Commit(s) | Change |
|-------|-----------|--------|
| 1 (E1.b) | `31d0dd7` | One `hsync.Peer` allocation per peer; deleted the deep-copy bridge. `*Agent` becomes a *view* over that pointer. |
| 2 | `234933d` | Deleted `AgentDetails`, the telemetry store believed to be dead. |
| 2.5 | mp `c181439`, transport `c5604ae` | Moved `agentMeta.Crypto` to per-mechanism crypto slots on `transport.Peer`; deleted the sidecar. |
| 2.6 | mp `a17deb0`, transport `37c0dfb` | Moved the whole discovery *process* into transport; retired `DiscoveryDriver`. MP keeps only the gate. |
| 3a–c | `8c3611f` | Inbound-beat collapse, `RemoteAgents` deletion, added `OnPeerRemoved`. |
| 3d | `4ffc0bc` | Bulk U1000 dead-code sweep. |
| 4 | `92e64a6` | The C0 gate: golden-wire test suite + mixed-fleet runbook. |

Background docs, in descending order of authority. Read the first one
properly; consult the others as needed. Do not read the whole `docs/`
directory — it is ~55 files and most of it is superseded evolution
trail.

- `docs/2026-08-24-transport-redesign-consolidated-plan-v4.md` —
  current source of truth. Its "standing cautions" and "predicted
  deltas" sections are directly relevant to you.
- `docs/2026-06-14-road-to-stage-C-plan.md` — the per-phase specs.
  Marked SUPERSEDED for remaining work but authoritative for what each
  phase was *supposed* to do. Comparing intent against the diff is a
  large part of this review.
- `docs/2026-07-10-stage-c-mixed-fleet-runbook.md` — the wire contract.

## Where to concentrate

These are the known-weak seams. Do not treat the list as exhaustive,
but do not leave any of them unexamined either.

**1. The embed trap — the highest-value target.** `Agent` no longer
has `ApiDetails` / `DnsDetails` fields, but it embeds `*hsync.Peer`,
which still *does*. So `agent.ApiDetails` still compiles and silently
resolves to the retired store. Phase 2's own notes concede the
compiler could not prove that deletion complete; every call site was
hand-enumerated. Hand enumeration is exactly the process that misses
things. Find any surviving read or write that lands on the embedded
field and therefore reads state nothing writes any more. Note that
`hsync.PeerDetails` is deliberately not deleted until Stage D, so the
trap is live for the whole of Stage C.

**2. The failure and decay paths.** This is the reviewer's best
argument for finding real bugs: the stacked code has never executed an
ERROR or decay path live. One concrete precedent —
`SendBeatWithFallback` leaked `agent.Mu` on its failure branches,
harmless before E1.a but "a guaranteed first-failed-beat deadlock"
after it, because E1.a made peers share a mutex. That specific
function was deleted, but the *class* stands: E1.a/E1.b changed the
aliasing of peer state, so any lock discipline written against the old
copy-per-peer model may now be wrong. Audit every mutex acquisition
that touches peer state on an error branch, and every early return
between an acquire and its release.

**3. Reliable-message-queue readiness.** `IsRecipientReady` already hid
a silent bug once: it read `AgentDetails.State` after that field's
writers were deleted, so every queued zone update to an agent
recipient was deferred until the 24-hour expiry, with no error
anywhere. It was fixed in `edfa079` (which is itself in your review
range and also never deployed). Verify the fix is complete and that no
sibling predicate has the same shape — reading a field whose writer
was removed by one of these phases.

**4. Newly-live and dead seams.** `OnPeerDiscovered` was never invoked
in production before Phase 2.6 and now fires on every successful
registration. `OnPeerRemoved` is wired but has no production caller at
all — only tests call `Engine.RemovePeer`. Check both for
re-entrancy, ordering against registration, and whether "no production
caller" is actually true.

**5. The 3d dead-code sweep.** A bulk U1000-driven deletion made
immediately after four phases that changed what is reachable. Staticcheck
cannot see reflection, interface satisfaction that only matters at
runtime, or a symbol whose only caller was deleted in the *same* stack
but whose behavior was load-bearing. Verify a sample of the deletions
against the possibility that the caller's absence is itself the bug.

**6. Invariants the plan says must survive.** Discovery probes only
locally-supported transports; a URI without an address is not KNOWN;
OPERATIONAL is set only on outbound beat success; decay-on-read lives
on `transport.Peer`; `OnDiscoveryFailed` fires on *all* failure paths.
Each is a fix that predates these phases and must still hold after
them. Check that the Phase 2.6 relocation of discovery into transport
did not drop any of them.

## Four changes that are intended, not bugs

The plan pre-declares these. If you find them, do not report them as
defects — but do verify each one is implemented as described, since a
half-implemented intentional change is a real defect:

- `peer status` State now derives from `effectiveAgentState`, matching
  gossip and peer-list, rather than the stale NG-lagged shadow.
- A distrib row for a peer not yet in `PeerRegistry` shows NEEDED
  instead of the row being skipped.
- Dual-mechanism `PreferredTransport` now resolves to `"API"`.
  DNS-only fleets are unaffected.
- A peer that stops publishing a transport keeps a stale offered-flag
  until ContactInfo cleanup.

## Wire compatibility

Every step in this stack is supposed to be wire-compatible: an
upgraded node must interoperate with un-upgraded nodes indefinitely.
The contract is in the mixed-fleet runbook; the short version is that
the verb is the JSON payload key `MessageType` (legacy `type` as
fallback), additive fields are safe, and renamed or removed fields and
tags are not. Two failure shapes matter. A payload carrying both
`MessageType` and `type` with *different* values is refused outright —
loud, easy to hit if a sender is half-migrated. A *renamed verb*
resolves to UNKNOWN and is dropped after delivery — silent, and the
golden-wire tests cannot see it, because they lock bytes rather than
dispatch.

So: check the diff for any change to a JSON tag, a payload field, or a
verb string, anywhere in the range. Anything you find there is
high-severity by default.

## Ground rules

- **Do not fix anything.** No edits to source, tests, or docs. This is
  a findings pass; the operator decides what gets fixed and in what
  order.
- **Do not deploy anything** or touch any host over SSH. Testbed hosts
  are handled separately.
- Do not re-run the build or the unit suite to confirm they pass —
  that is established. Run a *targeted* test only when you need it to
  confirm or refute a specific finding.
- Read code, not just diffs. A deletion's consequence usually lives in
  a file the diff does not touch.

## What to hand back

A findings list, ordered most-severe first. For each finding:

1. **The defect**, in one sentence.
2. **A concrete failure scenario** — specific inputs or sequence of
   events leading to a specific wrong outcome. "This looks fragile" is
   not a finding. If you cannot construct a scenario, say so and
   downgrade it.
3. **`file:line`** for the site, plus the phase/commit that introduced
   it.
4. **Confidence**, and what would settle it — ideally an observation
   the upcoming testbed pass could make cheaply.

Then, separately, a short list of **what you could not determine from
static review** and would want the live fleet to answer. That list is
as valuable as the findings: it feeds directly into the testbed
probe set.

Be adversarial about your own findings before reporting them. A false
positive here costs the operator a deployment window.
