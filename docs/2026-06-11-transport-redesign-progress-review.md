# Transport redesign: progress review — plan vs implementation reality

Date: 2026-06-11
Status: REVIEW (analysis only; no code changes).
Question under review: is the transport redesign on track to end in
the target design, or is the stream of newly discovered problems a
sign that it will not work out?

Reviewed:
- The plan corpus: `2026-04-15-transport-interface-redesign.md`
  (master/target), `2026-05-28-transport-redesign-review.md`,
  `2026-05-29/30` consolidated plans v1+v2 and both adversarial
  review passes, `2026-05-28-peer-discovery-fallout.md`,
  `2026-06-01-a3d-field-ownership.md`,
  `2026-06-03-a3d-dead-code-triage.md`,
  `2026-06-03-a3d-spine-cluster-scope.md`, plus the bite-era docs
  for history.
- The branch pair `transport-redesign-v1-A`: tdns-mp tip `2bed32a`
  (last code commit `95c3cf6`, Spine-1a), tdns-transport tip
  `495eab4`. Full commit walk of `main..tip` (124 commits, both
  repos), reflog-dated.
- Fresh verification run 2026-06-11: `go build` / `go test -count=1`
  / `go test -race` in tdns-mp/v2 and tdns-transport/v2; static
  purity grep of the transport package; per-marker code checks
  against the plan's claimed status.

## TL;DR — verdict

**On track, convergent, and honest — but entering its riskiest
stretch with three loose ends that should be closed first.**

1. The discovered problems (third registry, three per-peer state
   stores, backwards slice ordering, bridge-clobber trap) are all
   *more instances of the disease the redesign exists to cure*, not
   contradictions of the target design. The target architecture
   text has survived every discovery unchanged since 2026-05-30,
   and its essence (two stores joined by PeerID, opaque carrier)
   since 2026-04-15. That is the signature of a convergent
   refactor, not a failing one.
2. Code reality matches the documented status *exactly* — verified
   marker-by-marker. This project does not have the usual
   docs-drift problem in its current generation of docs (the v2
   "verified status read from code" discipline fixed it).
3. tdns-mp at the tip: builds, full suite green including `-race`,
   all 7 `TestTransportBoundary_*` scenarios pass.
4. **But:** the branch has been parked for 8 days at exactly the
   gate the spine doc calls "the biggest INVARIANT risk"
   (Spine-1a `.State`, awaiting testbed verify); tdns-transport
   does **not build standalone** at the tip (cross-repo go.mod
   drift); and Stage C — the actual reusable-library goal, with
   the highest wire-break risk — is at 0% with an estimate that
   predates everything learned in Stage A.

## 1. Where the implementation actually is (verified)

| Plan step | Status | Evidence |
|---|---|---|
| Stage 0 (0.1–0.3) | DONE | `4ba559b`, `3c59382`+`bad9b87`, `6e04424` (05-30) |
| A1 (A1.0–A1.2) | DONE, testbed-confirmed | `c0de553`, `88955d8`, `7e65286` |
| A2 (incl. auth/HELLO boundary) | DONE, testbed-confirmed | `5efdd8f`; harness has `RoleLessRejected` subtest, passing |
| A3a (lock order) | DONE | mp `14d8f4b` + transport `614417f` |
| A3b | dissolved into A3d | entanglement finding, `f018e7b` |
| A3c (RemoteAgents index) | DONE | `16415f4` |
| A3d | **~60–70%, in flight** | see below |
| A4 | core absorbed into A3d; residual = Spine-4 | `c0c508b` decision |
| A5 (bridge teardown) | NOT STARTED | `hsync_bridge_sync.go` intact (all 9 funcs); no `OnPeerRemoved` anywhere |
| Stage C (C1–C7) | NOT STARTED | all MP types/handlers/role-routers still in transport; 88 exported types (target <30); `BeatRequest.Gossip` unrenamed |
| Stage D, E, F | NOT STARTED | `TM.Send` still rejects Hello/Beat (`manager.go:346`); no `DiscoveryService` in transport; discovery lives in `tdns-mp/v2/hsync/discovery.go` |

A3d itself: done — A3d.0 view types (`431f9d1`), A3d.1 embed
(`eb584f7`, still dual-mapped by design until A3d.4), legacy
hello/discovery retirement (`6b671ac`, testbed-confirmed
`b304e1f`), ContactInfo slice (`3a536dd` after one revert),
dead-code sweep A (`512c864`, `0e87326`), crypto A3d.3a/3b
(`67363b3`, `dc8bb8d` — `AgentDetails` confirmed crypto-free),
Spine-1a (`95c3cf6`). Remaining — Spine-1b (stop writing
`AgentDetails.State`, display redirect), Spine-2 (address; needs
the DNS-URI home decision), Spine-3 (telemetry; needs *added*
API-side transport writes, not pure redirect), Spine-4 (the
`SyncPeerFromAgent`/`PopulateFromAgent` inversion sweep), then the
dual-map removal, inbound pipeline collapse, and
`hsync.Registry.RemoteAgents` deletion.

**Build/test verification (2026-06-11):**

| Check | Result |
|---|---|
| tdns-mp/v2 `go build ./...` | PASS |
| tdns-mp/v2 `go test ./... -count=1` | PASS (all pkgs) |
| tdns-mp/v2 `go test -race` | PASS |
| 7 × `TestTransportBoundary_*` | ALL PASS |
| tdns-transport/v2 `go build ./...` | **FAIL** — see Finding F1 |
| tdns-transport/v2 `go test ./...` | **FAIL** — F1 + pre-existing hpke Example failures (F2) |
| tdns/v2 (main) `go build ./...` | PASS |

**Velocity:** 39 redesign-branch commits (37 mp + 2 transport)
over 12 calendar days, all on three burst days (05-30: 12,
06-01: 7, 06-03: 20), separated by 1–2-day testbed gaps. Last
commit 2026-06-03 ~22:00. The current 8-day silence is 4× the
longest prior gap — consistent with a wait-on-operator testbed
gate (`2bed32a` records exactly that), but it is the longest the
branch has ever sat, and it sits on the riskiest slice.

**Branch topology:** `main..tip` = 124 commits, but only 37 are
the plan-of-record implementation; the rest are inherited
pre-plan work (semi-easy bites, hsync.Engine extraction,
mp-config-cutover, tactical bug patches). `tip..main` = 0 — main
has been dormant since 2026-05-26, so there is no rebase pressure
and an eventual merge is a fast-forward.

## 2. Review of the plan

### What the plan does right (and demonstrably, not just on paper)

- **The probe discipline works.** It is not ceremony: it caught
  the ContactInfo regression (first attempt `a766387` derived
  ContactInfo from `BaseUri`; testbed showed config-only infra
  peers wrongly "complete"; reverted `d8eb11d`, redone correctly
  17 minutes later with a transport-side home), and it caught the
  `peer reset` split-brain after the embed (`MarkNeeded`
  short-circuit; fixed with `Engine.Rediscover` + regression
  test, `d4577d4`). Two real regressions, both stopped at the
  probe, neither escaped.
- **Failures are converted into method.** The writer-path-audit
  rule (field-ownership §8.3: enumerate ALL writer paths before
  redirecting any reader; never derive a field from a sibling) was
  extracted from the ContactInfo failure and then correctly
  *disqualified* BeatInterval as a slice before it could repeat
  the trap. This is the strongest quality signal in the corpus.
- **Status is code-verified.** The 05-28 meta-finding ("twice the
  docs claimed work pending that was in production") was fixed:
  v2 carries a verified-from-code status block, and this review's
  independent marker-by-marker check found **zero divergence**
  between documented and actual state. That is rare.
- **The adversarial-review loop worked.** Pass-1/pass-2 findings
  (auth boundary on raw HSYNC3, A5/C ordering impossibility,
  triple inbound pipeline, three LEGACY definitions) were real,
  and v2 demonstrably folded them in rather than appending them.
  A2's security fix (role-less identity rejected at auth/HELLO)
  is already landed and testbed-confirmed — a delivered
  correctness win, not just refactoring.
- **One step = one commit + testbed checkpoint** keeps every
  failure small and attributable. The revert cycle took 27
  minutes, not a day.

### Where the plan is weak

**W1 — Authority fragmentation is recurring.** v2 declares itself
"the single source of truth … no separate amendment layers", yet
binding state now lives in four places: v2, the 06-01 A3d
addendum, that addendum's own §8.1 resequencing (which supersedes
v2's A3d.2/A3d.4 sub-decomposition *and* the addendum's own §8
list), and the 06-03 spine/triage docs. An implementer must today
read v2 §A3 → addendum §8 → addendum §8.1 ("§8 is backwards") →
spine doc §5 to know what Spine-1b actually is. This is the same
failure mode pass-2 called "the document fights itself", in
milder form. It is manageable while one person holds the context;
it will bite at the Stage C handoff or after any pause — such as
the current one.

**W2 — Estimates are systematically one decomposition level
short.** A3 → A3a–d; A3d absorbs A3b and A4's core; A3d.2/4 →
per-field vertical slices; spine → Spine-1–4; Spine-1 → 1a/1b.
Every split was correct and none was wasted work — but each was
discovered *during* implementation, roughly one level per working
day. The 05-28 effort table said Stage A = 2–4 sessions of the
total 8–13; through 06-03 roughly 4–5 sessions are consumed
(05-28 review, 05-29/30 planning+Stage 0+A1/A2/A3a/A3c, 06-01,
06-03) with A at ~70–80%. Stage A will land at or above the top
of its range — consistent with the estimate's own "variance
points up", but the same correction has *not* been applied
forward to C (3–5) / D / E / F.

**W3 — The state-store census keeps growing after the fact, and
the next known instance is parked in the thinnest part of the
plan.** 04-15: two registries. 05-28: three (the third created by
this project's own Cut A while the redesign was underway — worth
naming as a process lesson: extraction work added a parallel
store mid-redesign). 06-03: three per-peer state *stores*
(`AgentDetails` / `hsync.PeerDetails` / `transport.Peer`), "not
the two the plan assumed". The fourth instance is already known:
NG liveness on `hsync.PeerDetails` (DEGRADED/INTERRUPTED is
NG-only today and *not displayed*), which Stage D inherits — and
Stage D is three bullets. Given the observed pattern, entering D
without a scope doc of A3d's quality would be repeating the
mistake the project has now made (and then corrected) three
times.

**W4 — The automated probe leg is currently not executable as
written.** The plan binds "go test ./... in **all three repos**"
plus the `cmd/transport-exercise` consumer (pass-2 M2). Reality
at the tip: tdns-transport/v2 does not build standalone (F1
below), its hpke Examples fail (F2, pre-existing), and the
boundary suite runs only through tdns-mp's replace-routed build.
For Stage A this is tolerable — all A-stage code is exercised via
tdns-mp. For Stage C it is not: C changes transport's public API,
and the things that must keep building are exactly the standalone
transport repo and its non-MP consumer. The probe that protects C
is the one that is broken today.

**W5 — Stage C's risks are identified but nothing landed mitigates
them yet.** The mixed-fleet runbook is one bullet ("bind an
explicit runbook step"); the C6 wire-safety gate ("moved structs
MUST keep marshalling `MessageType`… highest wire-break risk in
C") has no regression test; the 7 boundary scenarios
characterize today's behavior, not the seam. C is also where the
per-stage probes are weakest relative to the failure mode (silent
wire drift delivering-but-not-dispatching, which the plan itself
predicts as "the most likely surprise").

**W6 — Two non-mechanical decisions are embedded in "mechanical"
remaining work.** Spine-2 needs the DNS-URI display home decision
("no transport string home" — spine doc §1); Spine-3 must *add*
API-side hello/beat transport writes (a behavior surface, not a
pure redirect). Neither is hard, but both should be decided
before implementation per the project's own writer-path-audit
rule, or they become the next mid-slice surprise.

## 3. The discovery pattern — divergent or convergent?

The question asked: do the newly discovered problems mean this
won't end in the target design? The discovery ladder:

| Date | Discovery | Plan impact |
|---|---|---|
| 05-28 | Third registry (`hsync.Registry`, created by Cut A); 4 testbed bugs all from registry overlap | Reprioritize: Stage A before C; target extended to absorb third registry |
| 05-30 | A3b/A3d entanglement (no writer deletable until one map exists) | A3b folded into A3d |
| 06-01 | A3d/A4 binary dissolves (~302 reads would be rewritten twice) | A4 core folded into A3d |
| 06-01 | Per-field writer audit: planned "redirect reads, then collapse writers" is backwards | §8.1 resequencing into per-field vertical slices |
| 06-03 | Three per-peer state stores, not two; bridge-clobber trap (`syncHsyncPeerFromAgent` wholesale replace) | Spine fields gated until A5; BeatInterval re-filed |
| 06-03 | Half-built diagnostics feature (write-only fields) masking the live surface | Dead-code triage A/B; operator KEEP decisions |

Three observations argue **convergent**:

1. **Every discovery is more of the same disease.** Each one is
   another instance of duplicated peer state with partial sync —
   precisely the thing the target design eliminates. None is a
   counter-example to the design; each *strengthens* the case for
   it. A divergent refactor looks different: discoveries that the
   target itself is wrong (e.g. "transport genuinely needs zone
   knowledge", "two stores can't represent X"). Nothing of that
   kind has surfaced in 12k lines of docs or 124 commits.
2. **The unknown has been converted into enumerated checklists.**
   `AgentDetails` is now crypto-free and every remaining field has
   a named destination and verdict (spine doc §1's table). The
   dead set is triaged A/B with operator decisions recorded. What
   was an open-ended audit on 06-01 is a finite punch list on
   06-03. Scope that stops growing *within* a step is the
   convergence criterion, and A3d's has.
3. **Each split landed.** Nothing split has then failed or been
   abandoned; the two regressions were caught by the probes and
   fixed within the same session. The decomposition is fractal
   but the leaves complete.

The honest qualifier: convergence is demonstrated **for Stage A**.
The same discovery dynamics have not yet touched Stage C/D/E, and
the one structural unknown the audits have flagged but not
dissolved is the NG liveness unification (Stage D, the one place
where the INVARIANT discipline by definition cannot fully hold,
because the end state *changes displayed behavior* — DEGRADED/
INTERRUPTED becoming visible).

## 4. New findings from this review's verification

**F1 — tdns-transport/v2 does not build standalone at the tip
(BLOCKING for the three-repo probe; not caused by branch code).**
`go build ./...` exits 1: go.mod needs tidying (missing indirect
`johanix/dnssec-algorithms`), and after a tidy the transport
package still fails:
`../../tdns/v2/algorithms/algorithms.go:71: undefined:
dns.Algorithm / dns.RegisterAlgorithm`. Root cause: the local
`replace` web routes tdns-transport's tdns/v2 dependency at the
*moving* sibling checkout, and tdns main's recent PQ-algorithms
work requires the johanix/dns fork — which tdns-mp/v2 pins
(go.mod:80) but tdns-transport/v2 does not. tdns-mp is unaffected
(its own replace+pin set is coherent; the transport code builds
and is fully tested through it). Fix is small (add the fork
replace + tidy), but until it lands, the plan's "all three repos"
probe and any `cmd/transport-exercise` check are fiction, and
Stage C must not start in this state (W4).

**F2 — hpke Example tests fail, pre-existing.** Four
`Example*` functions in `tdns-transport/v2/hpke` have `// Output:`
blocks containing placeholders (`[N] bytes`, `[base64 string]…`)
that can never match real output. `git diff origin/main...tip --
hpke/` is empty — this predates the branch. Either drop the
Output blocks (making them non-running examples) or fix the
expectations; as is, the transport suite can never be green.

**F3 — `CleanupZoneRelationships` is wired but still a stub.**
`agent_utils.go:300` remains "cleanup not yet implemented" while
being wired as the `OnLocalRemoved` hook (`hsync_bridge.go:285`).
A1.0's own binding was "implement the zone teardown there, or
explicitly drop with a stated alternative; do not leave
dangling". It is currently dangling-but-wired: a local-removal
event fires a no-op. Decide and record.

**F4 — The riskiest pending item is the one parked.** Spine-1a
redirected the ~15 canonical `.State` readers (operational
gating for elections, RFI, gossip) to `transport.Peer`. The spine
doc calls `.State` "the real risk… many readers, the
LEGACY↔OPERATIONAL transition, the enum mapping" and gates
everything on testbed byte-comparison of `gossip state` /
`peer list`. That verification has now been outstanding for 8
days. Until it runs, Spine-1b–4 are blocked and the A3d
convergence claim is provisional.

**F5 — Branch/release posture is undefined while wire risk
approaches.** 124 unmerged commits; main dormant since 05-26;
go.mod carries "Revert before publishing" local replaces with the
published tdns-transport pin frozen at the 05-25 merge-base.
Nothing mid-A3d is releasable, which is fine *now* — every step
through E is wire-compatible — but Stage C's mixed-fleet
brittleness (`parsePayload` strict checks) makes "how does this
land on main / get deployed fleet-wide" a real design input, not
an afterthought. There is no recorded decision on whether Stage A
merges to main at the A5 checkpoint or the branch runs through F.

**F6 — Minor hygiene.** Editor backup files (`Makefile~`,
`types.go~`, `combiner_chunk.go~`) tracked in/under the tree;
stale doc duplicates (`2026-04-15-legacy-dependency-analysis.md`
vs `04-14`). Cosmetic.

## 5. Are we on track? — direct answer

**For Stage A's goal (retire the registry-overlap bug class):
yes, with high confidence.** A1+A2 already closed the actual
security hole (role-less admission) and are testbed-confirmed.
A3d is a finite, enumerated punch list executing under a probe
discipline that has caught both regressions it produced. The
remaining A-stage risks (Spine-1a verify, the `.State` slice,
A5's bridge-clobber release) are identified, bounded, and gated.

**For the full target (tdns-transport as a reusable library):
plausible but not yet de-risked.** All evidence of convergence
comes from Stage A; Stage C is 0%, owns the highest-consequence
failure mode (silent wire breaks), depends on the currently
broken standalone transport build, and carries an estimate that
predates every Stage A lesson. Apply the observed growth factor
(~1.5–2× at each decomposition) to C's 3–5 sessions and the
honest total is closer to 12–18 sessions than the original 8–13.
That is a schedule observation, not a feasibility one — nothing
discovered contradicts the end state.

**What would change this verdict** (watch for these):
- Spine-1a testbed verification failing in a way that questions
  `transport.Peer.EffectiveState()` as the canonical read — that
  would strike at the A3d premise, not just a slice.
- Stage D discovering that NG liveness cannot unify onto
  `transport.Peer` without behavior change beyond an explainable
  delta.
- A mixed-fleet wire break during Stage C that the runbook +
  probes fail to contain.

None of these is currently in evidence.

## 6. Recommendations (priority order)

1. **Unblock the gate: run the Spine-1a testbed verification.**
   Everything in A3d stacks behind it, and 8 days parked on the
   highest-risk slice is the project's single point of schedule
   and confidence loss right now.
2. **Restore the three-repo build before any Stage C work.** Add
   the johanix/dns fork replace + `go mod tidy` in
   tdns-transport/v2; fix or neutralize the hpke Example
   expectations (F2); add `cmd/transport-exercise` to the probe
   run. Alternatively, formally amend the probe wording — but
   given C changes transport's public API, fixing it is strongly
   preferable to waiving it.
3. **Re-consolidate status into one place.** Fold the §8.1
   resequencing + spine state back into v2 (or cut a slim v3
   status header) so an implementer — or you after a two-week
   pause — reads one table, not a four-document chain (W1).
4. **Decide the branch/release strategy at the A5 checkpoint.**
   Recommended shape: land Stage A complete (through A5 +
   testbed), merge to main, cut a fresh branch for Stage C. That
   keeps the wire-risk stage on a short branch with a releasable
   base, and forces the go.mod publishing story (F5) to be
   resolved once, deliberately.
5. **Pre-decide the two non-mechanical A3d items** (Spine-2
   DNS-URI home; Spine-3 added API-side writes) before
   implementing them — per the project's own writer-path-audit
   rule (W6). Also close F3 (`CleanupZoneRelationships`) with an
   implement-or-drop decision.
6. **Before C1: make the mixed-fleet runbook a procedure and the
   C6 wire contract a test.** A marshal-compare regression test
   (golden JSON for the 13 payload types, byte-exact tags) is
   cheap and converts C's highest risk from "reviewer vigilance"
   to "CI failure".
7. **Write a Stage D scope doc before entering D.** D inherits
   the fourth state store (`hsync.PeerDetails` liveness) and the
   only deliberate user-visible behavior change short of F1
   (DEGRADED/INTERRUPTED becoming displayed). Three bullets in v2
   is not enough given what the spine audit now knows (W3).
8. **Re-estimate C–F with the observed growth factor** and treat
   8–13 sessions as superseded. This changes nothing technically
   but keeps the "are we on track" question honest at every
   checkpoint.
