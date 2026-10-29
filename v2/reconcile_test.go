package tdnsmp

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
)

// The reconciliation (plan S12), on the thaw rig: agent a leads a zone that
// a and b serve and n has a record in, thawed from 41 (n) to 42 (v). The
// agent hands its combiner and its signer what it acts by, and each holds
// it when the rig says so (partsTake).

type reconcileRig struct {
	*thawRig
	combiner, signer *handoverTracker
}

func newReconcileRig(t *testing.T, zone, leader string) *reconcileRig {
	t.Helper()
	r := &reconcileRig{thawRig: newThawRig(t, zone, leader)}
	mpzd, _ := Zones.Get(zone)
	mpzd.Ready = true
	mpzd.Options[tdns.OptMultiProvider] = true
	queued := func(ZoneName, *ZoneUpdate, string) (string, error) { return "", nil }
	r.combiner = newHandoverTracker(AgentId(roleA), queued)
	r.signer = newHandoverTracker(AgentId(roleA), queued)
	r.signer.toSigner = true
	r.conf.InternalMp.Handover, r.conf.InternalMp.SignerHandover = r.combiner, r.signer
	r.stamps.stepHeld = r.conf.holdsStep
	return r
}

// thawNow has the leader thaw the zone from n to v: b agrees, both signers
// hold.
func (r *reconcileRig) thawNow() {
	r.t.Helper()
	r.hold()
	r.hear(roleB, r.agreeing(), true)
	r.conf.thawTurn(r.zone)
	if r.active() != r.v.Serial {
		r.t.Fatalf("not thawed: %v", r.view().waits)
	}
}

// partsTake has this agent's combiner and signer hold what it hands them.
func (r *reconcileRig) partsTake() {
	for _, tr := range []*handoverTracker{r.combiner, r.signer} {
		tr.mu.Lock()
		var want *ActingHandover
		if z := tr.zones[handoverKey(r.zone)]; z != nil {
			want = z.want
		}
		tr.mu.Unlock()
		tr.learned(r.zone, want)
	}
}

// own is this agent's own stamp of the zone.
func (r *reconcileRig) own() InstrStamp {
	r.t.Helper()
	st, ok := r.stamps.ownStamp(r.zone)
	if !ok {
		r.t.Fatal("no stamp of the zone")
	}
	return st
}

// holdsToo has id tell the step this agent holds, held by both its parts.
func (r *reconcileRig) holdsToo(id string) {
	st := r.own()
	st.StepHeld = true
	r.hear(id, st, true)
}

// step is the store's step of the zone: its number, and whether it holds one.
func (r *reconcileRig) step() (InstrStep, bool) {
	in, ok := r.store.reconcileInputs(r.zone)
	if !ok {
		r.t.Fatal("no serials kept")
	}
	return in.step.InstrStep, in.hasStep
}

// turn is the zone's turn at now.
func (r *reconcileRig) turn(now time.Time) { r.conf.reconcileTurn(r.zone, now) }

// wanted is what this agent hands its combiner now.
func (r *reconcileRig) wanted() *ActingHandover { return r.wantedBy(r.combiner) }

// wantedBy is what this agent hands the part tr tracks now.
func (r *reconcileRig) wantedBy(tr *handoverTracker) *ActingHandover {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if z := tr.zones[handoverKey(r.zone)]; z != nil {
		return z.want
	}
	return nil
}

// captureLog has lg write to a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := lg
	lg = slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { lg = prev })
	return &buf
}

func providerLabels(ps []Provider) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Label)
	}
	return out
}

// A transition with nothing to carry out has only its last step. It is
// done once every voting member's combiner and signer hold it: the store
// drops the from-serial and the step, the zone is no longer frozen, and
// the status says when it was done.
func TestATransitionWithNothingToCarryOutIsDoneWhenEveryPartHoldsIt(t *testing.T) {
	r := newReconcileRig(t, "nothing.reconcile.example.", roleA)
	logs := captureLog(t)
	r.agree()
	r.thawNow()
	// step 0: the sets held, which every voting member's parts hold
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	st, ok := r.step()
	if !ok || st.Number != 1 || st.Of != 1 || !slices.Equal(st.Taken, []string{lastStepKey}) {
		t.Fatalf("the last step was not taken: %+v", st)
	}
	if !strings.Contains(logs.String(), `msg="transition step sent"`) {
		t.Errorf("no log line for the step: %s", logs)
	}
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	s := status(t, r.store, r.zone)
	if s.Phase != PhaseSteady || s.From != nil || s.Step != 0 || s.DoneAt.IsZero() {
		t.Fatalf("not done: %+v", s)
	}
	if why := r.conf.zoneFrozen(r.zone); len(why) > 0 {
		t.Errorf("frozen after done: %v", why)
	}
	if line := r.conf.thawLine(r.zone); !strings.HasPrefix(line, "at 42, done since ") {
		t.Errorf("the status: %q", line)
	}
	if !strings.Contains(logs.String(), `msg="transition done"`) || !strings.Contains(logs.String(), "serial=42") {
		t.Errorf("no log line for done: %s", logs)
	}
	if own := r.own(); own.Reconciling || own.Step != nil {
		t.Errorf("the leader's stamp after done: %+v", own)
	}
}

// TestDoneWaitsForEveryVotingMembersParts, with
// TestAStepIsConfirmedOnlyWhenTheCombinerAndSignerHoldIt: a step is held
// only once this agent's combiner and signer both hold it, and every other
// voting member tells, first hand, that its parts hold it.
func TestDoneWaitsForEveryVotingMembersParts(t *testing.T) {
	r := newReconcileRig(t, "parts.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	r.turn(time.Now())
	if st, _ := r.step(); st.Number != 0 {
		t.Fatal("a step was taken before anyone held step 0")
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "waiting for "+roleA+" (its combiner and signer), "+roleB) {
		t.Errorf("the status: %q", line)
	}
	// the combiner alone
	r.combiner.learned(r.zone, r.wanted())
	if r.own().StepHeld {
		t.Error("the stamp says the step is held with the signer not holding it")
	}
	r.signer.learned(r.zone, r.wanted())
	if !r.own().StepHeld {
		t.Error("the stamp does not say the step is held with both parts holding it")
	}
	// b tells the step, but not that its parts hold it
	st := r.own()
	st.StepHeld = false
	r.hear(roleB, st, true)
	r.turn(time.Now())
	if n, _ := r.step(); n.Number != 0 {
		t.Fatal("a step was taken before b's parts held step 0")
	}
	r.holdsToo(roleB)
	r.turn(time.Now())
	r.partsTake()
	r.turn(time.Now())
	if s := status(t, r.store, r.zone); s.Phase != PhaseReconciling {
		t.Fatal("done before b held the last step")
	}
	if line := r.conf.thawLine(r.zone); !strings.HasSuffix(line, "waiting for "+roleB) {
		t.Errorf("the status: %q", line)
	}
	r.holdsToo(roleB)
	r.turn(time.Now())
	if s := status(t, r.store, r.zone); s.Phase != PhaseSteady {
		t.Errorf("not done once every part held it: %+v", s)
	}
}

// TestUntilTheFirstStepThePartsKeepTheSetsTheyHold, with
// TestAtTheThawThePartsKeepTheFromSerialsSets and
// TestNsmgmtAndParentsyncChangeOnlyAtAStep: a thaw hands V's serial with
// the sets held, N's, and never V's lists at once; nsmgmt and parentsync
// with them. The last step hands V's lists.
func TestUntilTheFirstStepThePartsKeepTheSetsTheyHold(t *testing.T) {
	r := newReconcileRig(t, "keep.reconcile.example.", roleA)
	// v gives n a server role and leaves the NS to the owner: kinds of change
	// the judge refuses until their steps exist (S18a, S19), here as if one did
	r.v = jAt(t, 42, `servers="a,b,n" nsmgmt="owner" suffix="v"`, freezeRecords...)
	r.holdUnjudged(r.v, time.Now())
	r.hear(roleN, tells(r.n, r.v), true) // a voting member under V: its payload encryption
	r.thawNow()
	h := r.wanted()
	if h == nil || h.Serial != 42 || h.Step != 0 {
		t.Fatalf("the hand-over at the thaw: %v", h)
	}
	if got := providerLabels(h.Sets.Servers); !slices.Equal(got, []string{"a", "b"}) || h.Sets.NSmgmt != rolesFor(r.n, r.n, 0).NSmgmt {
		t.Errorf("the sets at the thaw: servers %v, nsmgmt %d", got, h.Sets.NSmgmt)
	}
	if got := providerLabels(rolesForZone(ZoneName(r.zone)).Servers); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("the readers' sets at the thaw: %v", got)
	}
	r.partsTake()
	r.holdsToo(roleB)
	r.holdsToo(roleN)
	r.turn(time.Now())
	h = r.wanted()
	if got := providerLabels(h.Sets.Servers); h.Step != 1 || !slices.Equal(got, []string{"a", "b", "n"}) || h.Sets.NSmgmt != rolesFor(r.v, r.v, 0).NSmgmt {
		t.Errorf("the last step's sets: step %d, servers %v, nsmgmt %d", h.Step, got, h.Sets.NSmgmt)
	}
}

// TestStepZeroIsInTheLeadersStamp: from the thaw the leader's stamp tells
// that it reconciles, with step 0 and its sets' digest.
func TestStepZeroIsInTheLeadersStamp(t *testing.T) {
	r := newReconcileRig(t, "zero.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	st := r.own()
	if !st.Reconciling || st.Step == nil || st.Step.Number != 0 {
		t.Fatalf("the leader's stamp: %+v", st)
	}
	_, digest, _ := stepDigest(rolesFor(r.n, r.n, 0))
	if st.Step.Digest != digest {
		t.Errorf("step 0's digest %s, want N's sets' %s", st.Step.Digest, digest)
	}
	var sets Roles
	if err := json.Unmarshal(st.Step.Sets, &sets); err != nil || !slices.Equal(providerLabels(sets.Servers), []string{"a", "b"}) {
		t.Errorf("step 0's sets: %+v %v", sets, err)
	}
}

// leaderStep is a stamp of the leader b's: active v, reconciling, at the
// step with the sets and the removals given.
func (r *reconcileRig) leaderStep(n int, sets Roles, taken []string, removals ...InstrRemoval) InstrStamp {
	r.t.Helper()
	raw, digest, err := stepDigest(sets)
	if err != nil {
		r.t.Fatal(err)
	}
	st := tells(r.v, r.v)
	st.Thaw = &Thaw{From: sd(r.n), To: sd(r.v)}
	st.Reconciling = true
	st.Step = &InstrStep{Number: n, Of: 3, What: "a step", Sets: raw, Digest: digest, Taken: taken}
	st.Removals = removals
	return st
}

// member is this agent as a member of a zone b leads, thawed to v on b's
// word.
func newMemberRig(t *testing.T, zone string) *reconcileRig {
	t.Helper()
	r := newReconcileRig(t, zone, roleB)
	r.agree()
	st := tells(r.v, r.v)
	st.Thaw, st.Reconciling = &Thaw{From: sd(r.n), To: sd(r.v)}, true
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if r.active() != 42 {
		t.Fatal("the member did not activate v")
	}
	return r
}

// TestEveryAgentKeepsTheRemovalsFromTheLeadersSteps, with
// TestEveryMemberTellsTheRemovalsItHoldsWithTheStepItHolds: a member takes
// the leader's step and its removals from the leader's first-hand stamp,
// keeps them on disk, hands its parts the step's sets, and tells the
// removals with the step it holds.
func TestEveryAgentKeepsTheRemovalsFromTheLeadersSteps(t *testing.T) {
	r := newMemberRig(t, "removals.reconcile.example.")
	sets := rolesFor(r.n, r.n, 0)
	sets.Servers = sets.Servers[:1]
	rm := InstrRemoval{Label: "n", Identity: roleN, NSNames: []string{"ns1.n.example."}}
	r.hear(roleB, r.leaderStep(1, sets, []string{"remove b ns"}, rm), true)
	r.conf.thawTurn(r.zone)
	st, ok := r.step()
	if !ok || st.Number != 1 || st.What != "a step" || !slices.Equal(st.Taken, []string{"remove b ns"}) {
		t.Fatalf("the member's step: %+v", st)
	}
	if h := r.wanted(); h == nil || h.Step != 1 || !slices.Equal(providerLabels(h.Sets.Servers), []string{"a"}) {
		t.Errorf("the hand-over: %v", h)
	}
	// on disk
	r.load()
	s := status(t, r.store, r.zone)
	if len(s.Removals) != 1 || s.Removals[0].Label != "n" || !slices.Equal(s.Removals[0].NSNames, rm.NSNames) || s.Step != 1 {
		t.Fatalf("after a restart: %+v", s)
	}
	own, _ := r.stamps.ownStamp(r.zone)
	if len(own.Removals) != 1 || own.Removals[0].Step != 1 || own.Removals[0].Identity != roleN {
		t.Errorf("the member's stamp: %+v", own.Removals)
	}
}

// TestAnAgentThatMissedTheEndDropsTheRemovalOnTheLeadersDone, with
// TestDoneDropsTheFromSerialAndTheRemovals.
func TestAnAgentThatMissedTheEndDropsTheRemovalOnTheLeadersDone(t *testing.T) {
	r := newMemberRig(t, "missed.reconcile.example.")
	r.hear(roleB, r.leaderStep(1, rolesFor(r.n, r.n, 0), []string{"x"}, InstrRemoval{Label: "n", Identity: roleN}), true)
	r.conf.thawTurn(r.zone)
	if s := status(t, r.store, r.zone); len(s.Removals) != 1 {
		t.Fatalf("the removal was not kept: %+v", s)
	}
	done := tells(r.v, r.v)
	done.Thaw = &Thaw{From: sd(r.n), To: sd(r.v)}
	r.hear(roleB, done, true)
	r.conf.thawTurn(r.zone)
	s := status(t, r.store, r.zone)
	if s.Phase != PhaseSteady || s.From != nil || len(s.Removals) > 0 || s.Step != 0 {
		t.Errorf("after the leader's done: %+v", s)
	}
	if h := r.wanted(); h == nil || h.Phase != PhaseSteady || h.Step != 0 {
		t.Errorf("the hand-over after done: %v", h)
	}
}

// A member takes only the leader's step: another member's is not taken,
// nor is a step of the leader's behind its own.
func TestAMemberTakesTheStepFromTheLeaderOnly(t *testing.T) {
	r := newMemberRig(t, "onlyleader.reconcile.example.")
	other := r.leaderStep(2, rolesFor(r.n, r.n, 0), []string{"x", "y"})
	r.hear(roleN, other, true)
	r.conf.thawTurn(r.zone)
	if st, _ := r.step(); st.Number != 0 {
		t.Fatalf("took n's step: %+v", st)
	}
	r.hear(roleB, r.leaderStep(2, rolesFor(r.n, r.n, 0), []string{"x", "y"}), true)
	r.conf.thawTurn(r.zone)
	r.hear(roleB, r.leaderStep(1, rolesFor(r.n, r.n, 0), []string{"x"}), true)
	r.conf.thawTurn(r.zone)
	if st, _ := r.step(); st.Number != 2 {
		t.Errorf("went back to the leader's step 1: %+v", st)
	}
}

// TestALeaderWithoutTheStateTakesItFromTheMembersStamps: a leader that
// holds no step's sets (it knew its active serial by the members' word)
// waits until every other voting member under V is heard, then takes the
// furthest step one tells, with its removals.
func TestALeaderWithoutTheStateTakesItFromTheMembersStamps(t *testing.T) {
	r := newReconcileRig(t, "nostate.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.From, z.Sets, z.Step, z.Taken, z.Pending = nil, nil, 0, nil, true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r.stamps.kept = map[string]*memberStamp{} // a start: nothing heard
	r.turn(time.Now())
	if _, ok := r.step(); ok {
		t.Fatal("took a step before b was heard")
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "waiting for the leader's step, waiting for "+roleB+" (not heard)") {
		t.Errorf("the status: %q", line)
	}
	if r.wanted() != nil && r.conf.wantedHandover(r.zone) != nil {
		t.Error("a leader with no step's sets hands its parts something new")
	}
	sets := rolesFor(r.n, r.n, 0)
	sets.Servers = sets.Servers[:1]
	r.hear(roleB, r.leaderStep(2, sets, []string{"x", "y"}, InstrRemoval{Label: "n", Identity: roleN, NSNames: []string{"ns.n.example."}}), true)
	r.turn(time.Now())
	st, ok := r.step()
	if !ok || st.Number != 2 || !slices.Equal(st.Taken, []string{"x", "y"}) {
		t.Fatalf("the step taken: %+v", st)
	}
	if s := status(t, r.store, r.zone); len(s.Removals) != 1 || s.Removals[0].Label != "n" {
		t.Errorf("the removals taken: %+v", s.Removals)
	}
}

// TestANewLeaderPlansAgainFromWhatIsInPlace, with
// TestTheLeaderPlansFromWhatIsInPlace: a leader that holds step 1 of a
// plan, as a member it took it from the leader before, goes on from there;
// one behind a voting member's step takes that step first.
func TestANewLeaderPlansAgainFromWhatIsInPlace(t *testing.T) {
	defer withRunners(stepRunner{name: "test", kind: stepRemoval, steps: func(p planView) []plannedStep {
		return []plannedStep{{key: "one", what: "one"}, {key: "two", what: "two"}}
	}})()
	r := newReconcileRig(t, "newleader.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	sets := rolesFor(r.n, r.n, 0)
	r.hear(roleB, r.leaderStep(1, sets, []string{"one"}), true)
	r.turn(time.Now())
	if st, _ := r.step(); st.Number != 1 || !slices.Equal(st.Taken, []string{"one"}) {
		t.Fatalf("did not take b's further step: %+v", st)
	}
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	if st, _ := r.step(); st.Number != 2 || !slices.Equal(st.Taken, []string{"one", "two"}) || st.Of != 3 {
		t.Fatalf("the next step from what is in place: %+v", st)
	}
}

// withRunners has the runners given be the registered ones, until the
// function it returns is called.
func withRunners(rs ...stepRunner) func() {
	prev := stepRunners
	stepRunners = rs
	return func() { stepRunners = prev }
}

// TestStepsAreOrderedAdditionsRoleChangesRemovals, with
// TestAnExcusedLeaversNSStepComesBeforeAnAdditionsDNSKEYStep.
func TestStepsAreOrderedAdditionsRoleChangesRemovals(t *testing.T) {
	defer withRunners(
		stepRunner{name: "removal", kind: stepRemoval, steps: func(planView) []plannedStep {
			return []plannedStep{{key: "c ns", provider: roleN, leaverNS: true}, {key: "c ds", provider: roleN, keys: true}}
		}},
		stepRunner{name: "role", kind: stepRoleChange, steps: func(planView) []plannedStep { return []plannedStep{{key: "b role"}} }},
		stepRunner{name: "addition", kind: stepAddition, steps: func(planView) []plannedStep {
			return []plannedStep{{key: "d record"}, {key: "d dnskey", keys: true}}
		}},
	)()
	n := freezeAt(t, 41, "n", "a,b", "")
	keys := func(steps []plannedStep) []string {
		var out []string
		for _, st := range steps {
			out = append(out, st.key)
		}
		return out
	}
	got := keys(planSteps(planView{to: n}))
	if want := []string{"d record", "d dnskey", "b role", "c ns", "c ds", lastStepKey}; !slices.Equal(got, want) {
		t.Errorf("the order:\n got %v\nwant %v", got, want)
	}
	got = keys(planSteps(planView{to: n, excused: map[string]bool{canonicalName(roleN): true}}))
	if want := []string{"d record", "c ns", "d dnskey", "b role", "c ds", lastStepKey}; !slices.Equal(got, want) {
		t.Errorf("with c excused:\n got %v\nwant %v", got, want)
	}
}

// TestEveryDSAndDNSKEYStepWaitsForAnEmergencyRollover, with
// TestOtherStepsDoNotWaitForAnEmergencyRollover and
// TestNoStepWaitsForARolloverPausedOnlyOnExcusedMembers.
func TestEveryDSAndDNSKEYStepWaitsForAnEmergencyRollover(t *testing.T) {
	defer withRunners(stepRunner{name: "test", kind: stepRemoval, steps: func(planView) []plannedStep {
		return []plannedStep{{key: "ns", what: "ns"}, {key: "ds", what: "ds", keys: true}}
	}})()
	logs := captureLog(t)
	r := newReconcileRig(t, "rollover.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	r.partsTake()
	rolling := func() {
		st := r.own()
		st.StepHeld, st.Rollover = true, true
		r.hear(roleB, st, true)
	}
	rolling()
	r.turn(time.Now())
	if st, _ := r.step(); st.Number != 1 {
		t.Fatalf("the NS step waited for the rollover: %+v", st)
	}
	r.partsTake()
	rolling()
	r.turn(time.Now())
	if st, _ := r.step(); st.Number != 1 {
		t.Fatalf("the DS step did not wait for the rollover: %+v", st)
	}
	if !strings.Contains(logs.String(), `msg="a DS or DNSKEY step waits for an emergency rollover"`) {
		t.Errorf("no log line: %s", logs)
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "the next step waits for an emergency rollover at "+roleB) {
		t.Errorf("the status: %q", line)
	}
	// paused only on an excused member: n, excused here
	if err := r.store.excuse(r.zone, roleN); err != nil {
		t.Fatal(err)
	}
	st := r.own()
	st.StepHeld, st.Rollover, st.WaitsOn = true, true, []string{"n"}
	r.hear(roleB, st, true)
	r.turn(time.Now())
	if st, _ := r.step(); st.Number != 2 {
		t.Errorf("the DS step waited for a rollover paused only on an excused member: %+v", st)
	}
}

// leavingRig is the reconcile rig with n a server under 41 and none under
// 42: n is a leaving member. The kind of change is refused until S17b;
// here the zone is thawed as if it were not.
func newLeavingRig(t *testing.T, zone string) *reconcileRig {
	t.Helper()
	r := newReconcileRig(t, zone, roleA)
	r.n = freezeAt(t, 41, "n", "a,b,n", "")
	r.v = freezeAt(t, 42, "v", "a,b", "")
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.Active.Reading, z.Active.SerialDigest = r.n, sd(r.n)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r.holdUnjudged(r.v, time.Now())
	if err := r.conf.activate(r.zone, Thaw{From: sd(r.n), To: sd(r.v)}, roleA); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestALeavingMemberThatDoesNotConfirmAStepIsExcusedFromThenOn, with
// TestAnExcusedLeavingMemberIsNotWaitedFor: a leaving member that is heard
// and does not confirm a step holds it up to no-role-timeout; one that has
// not confirmed a step for leaving-timeout is excused, with a log line,
// and kept so on disk.
func TestALeavingMemberThatDoesNotConfirmAStepIsExcusedFromThenOn(t *testing.T) {
	logs := captureLog(t)
	r := newLeavingRig(t, "leaving.reconcile.example.")
	r.partsTake()
	r.holdsToo(roleB)
	st := r.own()
	st.StepHeld = false
	r.hear(roleN, st, true) // heard, its parts do not hold the step
	now := time.Now()
	r.turn(now)
	if st, _ := r.step(); st.Number != 0 {
		t.Fatal("went on without the leaving member before its time-out")
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, roleN+" (leaving)") {
		t.Errorf("the status: %q", line)
	}
	r.hear(roleN, st, true)
	r.turn(now.Add(2 * time.Hour))
	if !strings.Contains(logs.String(), `msg="a leaving member that has not confirmed a step is excused"`) {
		t.Fatalf("not excused: %s", logs)
	}
	if in, _ := r.store.reconcileInputs(r.zone); !slices.Contains(in.excused, canonicalName(roleN)) {
		t.Errorf("the excusal is not kept: %v", in.excused)
	}
	r.turn(now.Add(2 * time.Hour))
	if st, _ := r.step(); st.Number != 1 {
		t.Errorf("waited for the excused member: %+v", st)
	}
}

// TestAMemberWithNoRoleIsWaitedForWithATimeOut, with
// TestANewcomerWhoseAgentIsNotRunningHoldsNothingUp: n has a record and no
// role. Not heard, it holds nothing up; heard, it is waited for up to
// no-role-timeout, then the step goes on with a log line.
func TestAMemberWithNoRoleIsWaitedForWithATimeOut(t *testing.T) {
	logs := captureLog(t)
	r := newReconcileRig(t, "norole.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	if st, _ := r.step(); st.Number != 1 {
		t.Fatalf("n, not heard, held step 0: %+v", st)
	}
	r.partsTake()
	r.holdsToo(roleB)
	st := r.own()
	st.StepHeld = false
	r.hear(roleN, st, true)
	now := time.Now()
	r.turn(now)
	if s := status(t, r.store, r.zone); s.Phase != PhaseReconciling {
		t.Fatal("done without waiting for n, heard")
	}
	if line := r.conf.thawLine(r.zone); !strings.HasSuffix(line, "waiting for "+roleN+" (no role)") {
		t.Errorf("the status: %q", line)
	}
	r.hear(roleN, st, true)
	r.turn(now.Add(16 * time.Minute))
	if s := status(t, r.store, r.zone); s.Phase != PhaseSteady {
		t.Errorf("not done after the time-out: %+v", s)
	}
	if !strings.Contains(logs.String(), `msg="a member with no role did not confirm in time, going on"`) {
		t.Errorf("no log line: %s", logs)
	}
}

// TestTheAuditorIsNotWaitedFor: n is the auditor under 42.
func TestTheAuditorIsNotWaitedFor(t *testing.T) {
	r := newReconcileRig(t, "auditor.reconcile.example.", roleA)
	r.v = freezeAt(t, 42, "v", "a,b", "n")
	r.holdUnjudged(r.v, time.Now())
	r.thawNow()
	st := r.own()
	r.hear(roleN, st, true)
	for range 2 {
		r.partsTake()
		r.holdsToo(roleB)
		r.turn(time.Now())
	}
	if s := status(t, r.store, r.zone); s.Phase != PhaseSteady {
		t.Errorf("the auditor held the transition: %+v", s)
	}
}

// TestANewerSerialDuringReconcilingWaitsForDone, with
// TestTheWaitingSerialIsAgreedAfterDone: 43, held during the
// reconciliation, changes no step and is not agreed until done.
func TestANewerSerialDuringReconcilingWaitsForDone(t *testing.T) {
	logs := captureLog(t)
	r := newReconcileRig(t, "newer.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	w := freezeAt(t, 43, "w", "a,b", "")
	r.store.Note(r.zone, w, nil)
	r.partsTake()
	r.holdsToo(roleB)
	r.conf.thawTurn(r.zone)
	if st, _ := r.step(); st.Number != 1 || r.active() != 42 {
		t.Fatalf("the steps did not go on unchanged: step %d, active %d", st.Number, r.active())
	}
	if _, ok := r.conf.thawView(r.zone, time.Now()); ok {
		t.Error("43 is agreed during the reconciliation")
	}
	if line := r.conf.thawLine(r.zone); !strings.HasSuffix(line, "; 43 held, waits until done") {
		t.Errorf("the status: %q", line)
	}
	if !strings.Contains(logs.String(), `msg="a newer serial of the zone's instructions waits until the transition is done"`) {
		t.Errorf("no log line: %s", logs)
	}
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	v, ok := r.conf.thawView(r.zone, time.Now())
	if !ok || v.to != sd(w) {
		t.Errorf("43 is not agreed after done: %+v %v", v, ok)
	}
}

// TestAStepIsConfirmedOnlyByTheMembersOwnStamp: b's telling that it holds
// the step, relayed in n's beat, does not count.
func TestAStepIsConfirmedOnlyByTheMembersOwnStamp(t *testing.T) {
	r := newReconcileRig(t, "ownstamp.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	r.partsTake()
	st := r.own()
	st.StepHeld = true
	r.seq++
	r.stamps.note(&GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
		roleB: {Identity: roleB, Timestamp: time.Now(), Epoch: 1, Seq: r.seq, Crypto: true, Instr: map[string]InstrStamp{r.zone: st}}}}, roleN, transport.MechanismDNS)
	r.turn(time.Now())
	if s, _ := r.step(); s.Number != 0 {
		t.Errorf("a relayed telling confirmed the step: %+v", s)
	}
}

// TestAnAgentThatMovedStraightTakesTheSetsFromTheLeader, with
// TestARestartedAgentHandsNothingNewUntilItHasTheStep: a member that moves
// straight to the thaw's target holds no step's sets, hands its parts
// nothing new, and takes the step from the leader's stamp.
func TestAnAgentThatMovedStraightTakesTheSetsFromTheLeader(t *testing.T) {
	r := newReconcileRig(t, "straight.reconcile.example.", roleB)
	r.agree()
	w := freezeAt(t, 43, "w", "a,b", "")
	r.store.Note(r.zone, w, nil)
	r.partsTake() // the parts hold what was handed before, at 41
	before := r.wanted()
	if err := r.conf.activate(r.zone, Thaw{From: sd(r.v), To: sd(w)}, roleB); err != nil {
		t.Fatal(err)
	}
	if !r.store.pending(r.zone) || r.conf.wantedHandover(r.zone) != nil {
		t.Fatal("a member that moved straight would hand its parts something new")
	}
	if h := r.wanted(); !h.sameAs(before) {
		t.Errorf("the hand-over changed: %v, was %v", h, before)
	}
	st := tells(w, w)
	st.Reconciling, st.Thaw = true, &Thaw{From: sd(r.v), To: sd(w)}
	raw, digest, _ := stepDigest(rolesFor(w, w, 0))
	st.Step = &InstrStep{Number: 1, Of: 1, Sets: raw, Digest: digest, Taken: []string{lastStepKey}}
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if h := r.wanted(); h == nil || h.Serial != 43 || h.Step != 1 {
		t.Errorf("the leader's step was not handed: %v", h)
	}
}

// TestTheStepSurvivesARestart.
func TestTheStepSurvivesARestart(t *testing.T) {
	r := newReconcileRig(t, "restart.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	before, _ := r.step()
	r.load()
	after, ok := r.step()
	if !ok || after.Number != before.Number || after.Digest != before.Digest || !slices.Equal(after.Taken, before.Taken) {
		t.Errorf("after a restart: %+v, before %+v", after, before)
	}
	if s := status(t, r.store, r.zone); s.From == nil || s.Phase != PhaseReconciling {
		t.Errorf("the transition after a restart: %+v", s)
	}
}

// TestDoneReleasesTheOwedList, with TestNoRolloverStartsBeforeDone: the
// zone is frozen until done, and the hand-over holds its signer's key
// machine; at done the hold is let go and the data engine is asked to
// release what the zone kept.
func TestDoneReleasesTheOwedList(t *testing.T) {
	r := newReconcileRig(t, "release.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	if len(r.conf.zoneFrozen(r.zone)) == 0 {
		t.Fatal("not frozen during the reconciliation")
	}
	if h := r.wantedBy(r.signer); h == nil || !h.Sets.Hold {
		t.Errorf("the signer is not held during the reconciliation: %v", h)
	}
	for len(r.conf.InternalMp.MsgQs.SynchedDataCmd) > 0 {
		<-r.conf.InternalMp.MsgQs.SynchedDataCmd
	}
	for range 2 {
		r.partsTake()
		r.holdsToo(roleB)
		r.turn(time.Now())
	}
	select {
	case cmd := <-r.conf.InternalMp.MsgQs.SynchedDataCmd:
		if cmd.Cmd != "instr-done" {
			t.Errorf("the engine was asked %q", cmd.Cmd)
		}
	default:
		t.Error("the release was not asked at done")
	}
	if h := r.wantedBy(r.signer); h == nil || h.Sets.Hold {
		t.Errorf("the hold is not let go at done: %v", h)
	}
}

// TestAStepsOwnSyncIsNotHeld: a step's own sync and distributions pass the
// freeze.
func TestAStepsOwnSyncIsNotHeld(t *testing.T) {
	r := newReconcileRig(t, "stepsync.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	if held, _ := r.conf.syncHeld(r.zone, syncOther); !held {
		t.Fatal("a sync of no step's passes the freeze")
	}
	if held, why := r.conf.syncHeld(r.zone, syncStep); held {
		t.Errorf("a step's own sync is held: %s", why)
	}
	why, err := r.conf.oweIfFrozen(&SynchedDataUpdate{Zone: ZoneName(r.zone), Step: true})
	if err != nil || why != "" {
		t.Errorf("a step's own distribution is owed: %q %v", why, err)
	}
}

// TestTheNoRoleTimeOutIsReadFromTheConfig.
func TestTheNoRoleTimeOutIsReadFromTheConfig(t *testing.T) {
	mp := &MultiProviderConf{}
	if got := noRoleTimeoutFor(mp); got != 15*time.Minute {
		t.Errorf("the default: %s", got)
	}
	mp.Transitions.NoRoleTimeout = 60
	if got := noRoleTimeoutFor(mp); got != time.Minute {
		t.Errorf("configured 60: %s", got)
	}
	mp.Transitions.NoRoleTimeout = -1
	if err := ValidateTransitions(mp); err == nil || !strings.Contains(err.Error(), "no-role-timeout") {
		t.Errorf("a negative time-out: %v", err)
	}
}

// TestTheCSYNCNotifyGoesOnWithoutAMemberWithNoRoleAfterTheTimeOut, with
// TestTheCSYNCNotifyWaitsForEveryVotingMember: the NOTIFY waits for the
// CSYNC's confirmations; once only members with no role are left, it goes
// on after the time-out. A voting member left waits with no time-out.
func TestTheCSYNCNotifyGoesOnWithoutAMemberWithNoRoleAfterTheTimeOut(t *testing.T) {
	r := newReconcileRig(t, "csync.reconcile.example.", roleA)
	zone := ZoneName(r.zone)
	made := time.Now()
	now := made.Add(time.Minute)
	if only, wait := noRoleOnly(zone, []string{roleN}, made, now, 15*time.Minute); !only || wait != 14*time.Minute {
		t.Errorf("n alone, before the time-out: %v %s", only, wait)
	}
	if only, wait := noRoleOnly(zone, []string{roleN}, made, now.Add(15*time.Minute), 15*time.Minute); !only || wait > 0 {
		t.Errorf("n alone, after the time-out: %v %s", only, wait)
	}
	if only, _ := noRoleOnly(zone, []string{roleB, roleN}, made, now.Add(time.Hour), 15*time.Minute); only {
		t.Error("b, a voting member, is left and the NOTIFY would go on")
	}
	if only, _ := noRoleOnly(zone, []string{freezeCombiner}, made, now.Add(time.Hour), 15*time.Minute); only {
		t.Error("this agent's combiner is left and the NOTIFY would go on")
	}
}

// A DNSKEY distribution waits for a member with no role up to the
// time-out, then goes on without it; a voting member is waited for.
func TestADNSKEYDistributionGoesOnWithoutAMemberWithNoRoleAfterTheTimeOut(t *testing.T) {
	r := newReconcileRig(t, "dnskey.reconcile.example.", roleA)
	tm := r.conf.InternalMp.MPTransport
	tm.noRoleTimeout = time.Hour // the test ends the wait itself
	tm.TrackDnskeyPropagation(ZoneName(r.zone), "d1", []uint16{4711}, nil, []AgentId{roleB, roleN})
	tm.ProcessDnskeyConfirmation("d1", roleB, transport.ConfirmSuccess.String(), nil, nil)
	tm.dnskeyPropMu.Lock()
	_, waiting := tm.pendingDnskeyPropagations["d1"]
	tm.dnskeyPropMu.Unlock()
	if !waiting {
		t.Fatal("the distribution did not wait for n")
	}
	tm.dnskeyNoRoleTimedOut("d1")
	tm.dnskeyPropMu.Lock()
	_, waiting = tm.pendingDnskeyPropagations["d1"]
	tm.dnskeyPropMu.Unlock()
	if waiting {
		t.Error("the distribution still waits for n after the time-out")
	}
	// b, a voting member, is waited for whatever the time
	tm.TrackDnskeyPropagation(ZoneName(r.zone), "d2", []uint16{4711}, nil, []AgentId{roleB, roleN})
	tm.dnskeyNoRoleTimedOut("d2")
	tm.dnskeyPropMu.Lock()
	_, waiting = tm.pendingDnskeyPropagations["d2"]
	tm.dnskeyPropMu.Unlock()
	if !waiting {
		t.Error("the distribution went on without b")
	}
}

// A member with no record that takes the leader's word while the leader
// reconciles holds no step's sets: it hands its parts nothing new, and
// takes the step from the leader's stamp. One that takes it from a leader
// at rest is at rest too (plan S9, S12).
func TestAMemberWithNoRecordFollowsTheLeadersReconciliation(t *testing.T) {
	r := newReconcileRig(t, "norecordstep.reconcile.example.", roleB)
	r.noRecord(r.n)
	r.leadGroup(r.n, roleB)
	st := r.leaderStep(1, rolesFor(r.n, r.n, 0), []string{lastStepKey})
	st.Active, st.ActiveDigest, st.Newest, st.NewestDigest = r.n.Serial, r.n.Digest(), r.n.Serial, r.n.Digest()
	st.Thaw = &Thaw{From: SerialDigest{Serial: 40, Digest: "x"}, To: sd(r.n)}
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if r.known() != 41 {
		t.Fatalf("not known on the leader's word: %+v", status(t, r.store, r.zone))
	}
	if s := status(t, r.store, r.zone); s.Phase != PhaseReconciling {
		t.Fatalf("known from a leader that reconciles, and at rest: %+v", s)
	}
	r.conf.thawTurn(r.zone)
	if got, ok := r.step(); !ok || got.Number != 1 {
		t.Fatalf("the leader's step was not taken: %+v", got)
	}
	st.Reconciling, st.Step = false, nil
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if s := status(t, r.store, r.zone); s.Phase != PhaseSteady {
		t.Errorf("not done on the leader's word: %+v", s)
	}
}

// A runner's own part of a step (S18a's serving check at the newcomer)
// holds the step at this agent: its stamp tells the step held only once
// that part is done too, and as the leader it waits for it.
func TestARunnersOwnPartHoldsTheStep(t *testing.T) {
	serving := false
	defer withRunners(stepRunner{name: "test", kind: stepAddition,
		steps: func(planView) []plannedStep { return nil },
		holds: func(*Config, string, InstrStep) bool { return serving }})()
	r := newReconcileRig(t, "ownpart.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	r.partsTake()
	if r.own().StepHeld {
		t.Fatal("the step is told held before the runner's part is done")
	}
	r.holdsToo(roleB)
	r.turn(time.Now())
	if st, _ := r.step(); st.Number != 0 {
		t.Fatal("the leader went on before its own part was done")
	}
	serving = true
	if !r.own().StepHeld {
		t.Fatal("the step is not told held once the runner's part is done")
	}
	r.turn(time.Now())
	if st, _ := r.step(); st.Number != 1 {
		t.Errorf("the leader did not go on: %+v", st)
	}
}
