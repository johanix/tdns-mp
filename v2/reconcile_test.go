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
	"github.com/miekg/dns"
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
	r.operational(roleB) // heard, but telling nothing of the zone (plan S22)
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "waiting for "+roleB+" (tells nothing of the zone)") {
		t.Errorf("the status with b heard: %q", line)
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
	// d's DNSKEY step taken before c was excused: no DNSKEY or DS step of an
	// addition is left, and c's NS step stays after b's role change
	got = keys(planSteps(planView{to: n, excused: map[string]bool{canonicalName(roleN): true}, taken: []string{"d record", "d dnskey"}}))
	if want := []string{"d record", "d dnskey", "b role", "c ns", "c ds", lastStepKey}; !slices.Equal(got, want) {
		t.Errorf("with c excused after d's DNSKEY step:\n got %v\nwant %v", got, want)
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

// A change of the sets asks the data engine to look at this agent's CSYNC
// again while it waits for a recipient: a voting recipient may have no role
// since, and no confirmation may come to look at its time-out (CodeRabbit
// on #327). With no CSYNC waiting, nothing is asked.
func TestAChangeOfTheSetsLooksAgainAtTheCSYNCThatWaits(t *testing.T) {
	r := newReconcileRig(t, "csyncrole.reconcile.example.", roleA)
	q := make(chan *SynchedDataCmd, 4)
	r.conf.InternalMp.MsgQs = &MsgQs{SynchedDataCmd: q}
	mpzd, _ := Zones.Get(r.zone)
	looks := func() int {
		n := 0
		for {
			select {
			case cmd := <-q:
				if cmd.Cmd == "csync-progress" && cmd.Zone == ZoneName(r.zone) {
					n++
				}
			default:
				return n
			}
		}
	}
	r.conf.onSetsChanged(mpzd, true)
	if n := looks(); n != 0 {
		t.Fatalf("no CSYNC waits, and %d looks were asked for", n)
	}
	c := &r.conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	if c.csyncs == nil {
		c.csyncs = map[string]*delegationCsync{}
	}
	c.csyncs[r.zone] = &delegationCsync{record: "csync", made: time.Now(), awaited: []string{roleB}}
	c.mu.Unlock()
	r.conf.onSetsChanged(mpzd, true)
	if n := looks(); n != 1 {
		t.Errorf("the sets changed while the CSYNC waits for b: %d looks asked for, want 1", n)
	}
}

// A member that votes under N and is the auditor under V is not leaving: the
// auditor is not waited for, and its stamps never tell a step held, so a
// step goes on without it and it is not excused (CodeRabbit on #327).
func TestAVoterThatBecomesTheAuditorIsNotLeaving(t *testing.T) {
	logs := captureLog(t)
	r := newReconcileRig(t, "toauditor.reconcile.example.", roleA)
	r.n = freezeAt(t, 41, "n", "a,b,n", "")
	r.v = freezeAt(t, 42, "v", "a,b", "n")
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
	r.partsTake()
	r.holdsToo(roleB)
	st := r.own()
	st.StepHeld = false
	r.hear(roleN, st, true) // heard, as the auditor is, its step never held
	now := time.Now()
	r.turn(now)
	if st, _ := r.step(); st.Number != 1 {
		t.Errorf("the step waited for the auditor: %+v, status %q", st, r.conf.thawLine(r.zone))
	}
	r.turn(now.Add(2 * time.Hour))
	if strings.Contains(logs.String(), `msg="a leaving member that has not confirmed a step is excused"`) {
		t.Error("the auditor was excused as a leaving member")
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

// A member with no role that tells no active serial, or one above V, cannot
// hold a step of V, so no step waits for it (plan S12, status item 9): the
// transition goes on to done. One that tells V or a serial below it can come
// to hold the step, and is waited for.
func TestAMemberWithNoRoleThatCannotHoldTheStepIsNotWaitedFor(t *testing.T) {
	for _, c := range []struct {
		name, zone string
		tells      func(r *reconcileRig, st *InstrStamp)
		waits      bool
	}{
		{"it knows no active serial", "unknown.norole.reconcile.example.", func(_ *reconcileRig, st *InstrStamp) {
			st.Known, st.Active, st.ActiveDigest, st.Reconciling, st.Step, st.StepHeld = false, 0, "", false, nil, false
		}, false},
		{"it tells a serial above V", "above.norole.reconcile.example.", func(r *reconcileRig, st *InstrStamp) {
			st.Active, st.ActiveDigest, st.Step, st.StepHeld = r.v.Serial+2, "above", nil, false
		}, false},
		{"it tells V, the step not held", "atv.norole.reconcile.example.", func(_ *reconcileRig, st *InstrStamp) {
			st.StepHeld = false
		}, true},
		{"it tells a serial below V", "below.norole.reconcile.example.", func(r *reconcileRig, st *InstrStamp) {
			st.Active, st.ActiveDigest, st.Reconciling, st.Step, st.StepHeld = r.n.Serial, r.n.Digest(), false, nil, false
		}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newReconcileRig(t, c.zone, roleA)
			r.agree()
			r.thawNow()
			r.partsTake()
			r.holdsToo(roleB)
			st := r.own()
			c.tells(r, &st)
			r.hear(roleN, st, true)
			r.turn(time.Now())
			step, _ := r.step()
			if c.waits {
				if step.Number != 0 {
					t.Fatalf("went on without n: %+v", step)
				}
				if line := r.conf.thawLine(r.zone); !strings.HasSuffix(line, "waiting for "+roleN+" (no role)") {
					t.Errorf("the status: %q", line)
				}
				return
			}
			if step.Number != 1 {
				t.Fatalf("step 0 waited for n: %+v, status %q", step, r.conf.thawLine(r.zone))
			}
			r.partsTake()
			r.holdsToo(roleB)
			r.hear(roleN, st, true)
			r.turn(time.Now())
			if s := status(t, r.store, r.zone); s.Phase != PhaseSteady {
				t.Errorf("not done: %+v, status %q", s, r.conf.thawLine(r.zone))
			}
		})
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
	if only, wait := nonVotingOnly(zone, []string{roleN}, made, now, 15*time.Minute); !only || wait != 14*time.Minute {
		t.Errorf("n alone, before the time-out: %v %s", only, wait)
	}
	if only, wait := nonVotingOnly(zone, []string{roleN}, made, now.Add(15*time.Minute), 15*time.Minute); !only || wait > 0 {
		t.Errorf("n alone, after the time-out: %v %s", only, wait)
	}
	if only, _ := nonVotingOnly(zone, []string{roleB, roleN}, made, now.Add(time.Hour), 15*time.Minute); only {
		t.Error("b, a voting member, is left and the NOTIFY would go on")
	}
	if only, _ := nonVotingOnly(zone, []string{freezeCombiner}, made, now.Add(time.Hour), 15*time.Minute); only {
		t.Error("this agent's combiner is left and the NOTIFY would go on")
	}
}

// A DNSKEY distribution waits for a member with no role up to the
// time-out, then goes on without it; a voting member is waited for.
func TestADNSKEYDistributionGoesOnWithoutAMemberWithNoRoleAfterTheTimeOut(t *testing.T) {
	r := newReconcileRig(t, "dnskey.reconcile.example.", roleA)
	tm := r.conf.InternalMp.MPTransport
	tm.noRoleTimeout = time.Hour // the test ends the wait itself
	tm.TrackDnskeyPropagation(t.Context(), ZoneName(r.zone), "d1", []uint16{4711}, nil, []AgentId{roleB, roleN})
	tm.ProcessDnskeyConfirmation("d1", roleB, transport.ConfirmSuccess.String(), nil, nil)
	tm.dnskeyPropMu.Lock()
	_, waiting := tm.pendingDnskeyPropagations["d1"]
	tm.dnskeyPropMu.Unlock()
	if !waiting {
		t.Fatal("the distribution did not wait for n")
	}
	tm.dnskeyNoRoleTimedOut(t.Context(), "d1")
	tm.dnskeyPropMu.Lock()
	_, waiting = tm.pendingDnskeyPropagations["d1"]
	tm.dnskeyPropMu.Unlock()
	if waiting {
		t.Error("the distribution still waits for n after the time-out")
	}
	// b, a voting member, is waited for whatever the time
	tm.TrackDnskeyPropagation(t.Context(), ZoneName(r.zone), "d2", []uint16{4711}, nil, []AgentId{roleB, roleN})
	tm.dnskeyNoRoleTimedOut(t.Context(), "d2")
	tm.dnskeyPropMu.Lock()
	_, waiting = tm.pendingDnskeyPropagations["d2"]
	tm.dnskeyPropMu.Unlock()
	if !waiting {
		t.Error("the distribution went on without b")
	}
}

// An auditor that has gone silent holds a DNSKEY distribution, and so the mark
// a next keys step and the thaw wait on (rolloverAt), only up to the time-out,
// and the leader's CSYNC the same: it is never waited for in the agreement
// (design 4). One that has not spoken by then is still sent to by the queue.
func TestASilentAuditorHoldsNothingPastTheTimeOut(t *testing.T) {
	r := newReconcileRig(t, "silentauditor.reconcile.example.", roleA)
	active := freezeAt(t, 42, "v", "a,b", "n")
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.Active.Reading, z.Active.SerialDigest = active, sd(active)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if st := zoneStanding(instructionsFor(ZoneName(r.zone)), roleN); st != standingAuditor {
		t.Fatalf("n's standing is %d, want the auditor", st)
	}
	tm := r.conf.InternalMp.MPTransport
	tm.noRoleTimeout = time.Hour // the test ends the wait itself
	tm.TrackDnskeyPropagation(t.Context(), ZoneName(r.zone), "d1", []uint16{4711}, nil, []AgentId{roleB, roleN})
	tm.ProcessDnskeyConfirmation("d1", roleB, transport.ConfirmSuccess.String(), nil, nil)
	if !tm.dnskeyPropagationPending(r.zone) {
		t.Fatal("the distribution did not wait for the auditor")
	}
	tm.dnskeyNoRoleTimedOut(t.Context(), "d1")
	if tm.dnskeyPropagationPending(r.zone) {
		t.Error("the distribution, and with it the mark, still waits for the auditor after the time-out")
	}
	// b, a voting member, is waited for whatever the time
	tm.TrackDnskeyPropagation(t.Context(), ZoneName(r.zone), "d2", []uint16{4711}, nil, []AgentId{roleB, roleN})
	tm.dnskeyNoRoleTimedOut(t.Context(), "d2")
	if !tm.dnskeyPropagationPending(r.zone) {
		t.Error("the distribution went on without b")
	}
	// the leader's CSYNC
	now := time.Now()
	if only, wait := nonVotingOnly(ZoneName(r.zone), []string{roleN}, now.Add(-15*time.Minute), now, 15*time.Minute); !only || wait > 0 {
		t.Errorf("the CSYNC with the auditor alone left, after the time-out: %v %s", only, wait)
	}
	if only, _ := nonVotingOnly(ZoneName(r.zone), []string{roleB, roleN}, now.Add(-time.Hour), now, 15*time.Minute); only {
		t.Error("b, a voting member, is left and the NOTIFY would go on")
	}
}

// A silent auditor holds no tracked record: an addition is accepted and a
// removal done once this agent's combiner and the voting members have answered,
// and whether it has answered does not decide the state. An auditor that is up
// held a removal too, since its answer names the records as applied.
func TestASilentAuditorHoldsNoTrackedRecord(t *testing.T) {
	r := newReconcileRig(t, "trackedauditor.reconcile.example.", roleA)
	active := freezeAt(t, 42, "v", "a,b", "n")
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.Active.Reading, z.Active.SerialDigest = active, sd(active)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	zone, us := ZoneName(r.zone), AgentId(roleA)
	recipients := []string{freezeCombiner, roleB, roleN}
	rr, err := dns.NewRR(r.zone + " 3600 IN NS ns9.provider.example.")
	if err != nil {
		t.Fatal(err)
	}
	tracked := func(state RRState, distID string) (*ZoneDataRepo, *TrackedRR) {
		zdr, err := NewZoneDataRepo()
		if err != nil {
			t.Fatal(err)
		}
		set := &TrackedRRset{Tracked: []TrackedRR{{RR: rr, State: state, DistributionID: distID, ExpectedRecipients: recipients}}}
		zdr.Tracking[zone] = map[AgentId]map[uint16]*TrackedRRset{us: {dns.TypeNS: set}}
		return zdr, &set.Tracked[0]
	}
	applied := func(distID, source string) *ConfirmationDetail {
		return &ConfirmationDetail{DistributionID: distID, Zone: zone, Source: source, Status: "ok", AppliedRecords: []string{rr.String()}}
	}
	removed := func(distID, source string) *ConfirmationDetail {
		return &ConfirmationDetail{DistributionID: distID, Zone: zone, Source: source, Status: "ok", RemovedRecords: []string{rr.String()}}
	}
	ignored := func(distID, source string) *ConfirmationDetail {
		return &ConfirmationDetail{DistributionID: distID, Zone: zone, Source: source, Status: "IGNORED", IgnoredRecords: []string{rr.String()}}
	}

	zdr, tr := tracked(RRStatePending, "add")
	zdr.ProcessConfirmation(applied("add", freezeCombiner), nil)
	if tr.State != RRStatePending {
		t.Fatalf("the addition went on without b: %v", tr.State)
	}
	zdr.ProcessConfirmation(applied("add", roleB), nil)
	if tr.State != RRStateAccepted {
		t.Errorf("the addition with only the auditor silent: %v, want accepted", tr.State)
	}
	zdr.ProcessConfirmation(applied("add", roleN), nil)
	if got := tr.Confirmations[roleN].Status; got != "accepted" {
		t.Errorf("the auditor's late answer reads %q, want it recorded", got)
	}

	zdr, tr = tracked(RRStatePendingRemoval, "del")
	zdr.ProcessConfirmation(removed("del", freezeCombiner), nil)
	zdr.ProcessConfirmation(applied("del", roleN), nil) // what auditorConfirms sends
	if tr.State != RRStatePendingRemoval {
		t.Fatalf("the removal went on without b: %v", tr.State)
	}
	zdr.ProcessConfirmation(removed("del", roleB), nil)
	if tr.State != RRStateRemoved {
		t.Errorf("the removal with only the auditor not counted: %v, want removed", tr.State)
	}

	// every provider ignores the record: the auditor's answer changes nothing, before or after
	for _, order := range [][]*ConfirmationDetail{
		{applied("ign", roleN), ignored("ign", freezeCombiner), ignored("ign", roleB)},
		{ignored("ign", freezeCombiner), ignored("ign", roleB), applied("ign", roleN)},
	} {
		zdr, tr = tracked(RRStatePending, "ign")
		for _, d := range order {
			zdr.ProcessConfirmation(d, nil)
		}
		if tr.State != RRStateIgnored {
			t.Errorf("every provider ignored the record, and it reads %v", tr.State)
		}
	}
}

// What a member with no vote rejects decides nothing (design 4): the answer is
// recorded, and it rejects no key or record and fails no CSYNC. A voting
// member's rejection does all of that.
func TestARejectionFromAMemberWithNoVoteDecidesNothing(t *testing.T) {
	r := newReconcileRig(t, "rejectauditor.reconcile.example.", roleA)
	active := freezeAt(t, 42, "v", "a,b", "n")
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.Active.Reading, z.Active.SerialDigest = active, sd(active)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	zone, us := ZoneName(r.zone), AgentId(r.conf.MpConfig().Identity)
	tm := r.conf.InternalMp.MPTransport
	tm.noRoleTimeout = time.Hour // the test ends the wait itself

	key := testDnskeyRR(t, r.zone, 257)
	kt := key.KeyTag()
	track := func(distID string) *PendingDnskeyPropagation {
		tm.TrackDnskeyPropagation(t.Context(), zone, distID, []uint16{kt}, nil, []AgentId{roleB, roleN})
		tm.dnskeyPropMu.Lock()
		defer tm.dnskeyPropMu.Unlock()
		return tm.pendingDnskeyPropagations[distID]
	}
	keyRejected := func(distID string, from AgentId, why string) {
		tm.ProcessDnskeyConfirmation(distID, string(from), transport.ConfirmRejected.String(), nil, []RejectedItemInfo{{Record: key.String(), Reason: why}})
	}
	p := track("k1")
	keyRejected("k1", roleN, "n refuses")
	tm.ProcessDnskeyConfirmation("k1", roleB, transport.ConfirmSuccess.String(), []string{key.String()}, nil)
	if propagated, _, rejected, _ := p.outcome(); len(propagated) != 1 || len(rejected) != 0 {
		t.Errorf("the key the auditor rejected and b applied: propagated %v rejected %v", propagated, rejected)
	}
	if got := p.Results[roleN][kt]; got != "rejected" {
		t.Errorf("the auditor's answer reads %q, want it recorded", got)
	}
	p = track("k2")
	keyRejected("k2", roleN, "n refuses")
	keyRejected("k2", roleB, "b refuses")
	if _, _, rejected, msg := p.outcome(); len(rejected) != 1 || msg != "b refuses" {
		t.Errorf("the key b rejected: rejected %v, reason %q", rejected, msg)
	}

	rr, err := dns.NewRR(r.zone + " 3600 IN NS ns9.provider.example.")
	if err != nil {
		t.Fatal(err)
	}
	tracked := func(state RRState, distID string) (*ZoneDataRepo, *TrackedRR) {
		zdr, err := NewZoneDataRepo()
		if err != nil {
			t.Fatal(err)
		}
		set := &TrackedRRset{Tracked: []TrackedRR{{RR: rr, State: state, DistributionID: distID, ExpectedRecipients: []string{freezeCombiner, roleB, roleN}}}}
		zdr.Tracking[zone] = map[AgentId]map[uint16]*TrackedRRset{us: {dns.TypeNS: set}}
		return zdr, &set.Tracked[0]
	}
	confirm := func(distID, from string, change func(*ConfirmationDetail)) *ConfirmationDetail {
		d := &ConfirmationDetail{DistributionID: distID, Zone: zone, Source: from, Status: "ok"}
		change(d)
		return d
	}
	applied := func(d *ConfirmationDetail) { d.AppliedRecords = []string{rr.String()} }
	removed := func(d *ConfirmationDetail) { d.RemovedRecords = []string{rr.String()} }
	refused := func(d *ConfirmationDetail) {
		d.Status, d.RejectedItems = "REJECTED", []RejectedItemInfo{{Record: rr.String(), Reason: "refused"}}
	}

	zdr, tr := tracked(RRStatePending, "add")
	zdr.ProcessConfirmation(confirm("add", roleN, refused), nil)
	if tr.State != RRStatePending || tr.Confirmations[roleN].Status != "rejected" {
		t.Errorf("the auditor rejected the addition: %v, its answer %q", tr.State, tr.Confirmations[roleN].Status)
	}
	zdr.ProcessConfirmation(confirm("add", freezeCombiner, applied), nil)
	zdr.ProcessConfirmation(confirm("add", roleB, applied), nil)
	if tr.State != RRStateAccepted {
		t.Errorf("the addition the auditor rejected and the others applied: %v", tr.State)
	}
	zdr, tr = tracked(RRStatePendingRemoval, "del")
	zdr.ProcessConfirmation(confirm("del", roleN, refused), nil)
	if tr.State != RRStatePendingRemoval {
		t.Errorf("the auditor rejected the removal: %v", tr.State)
	}
	zdr.ProcessConfirmation(confirm("del", freezeCombiner, removed), nil)
	zdr.ProcessConfirmation(confirm("del", roleB, removed), nil)
	if tr.State != RRStateRemoved {
		t.Errorf("the removal the auditor rejected and the others did: %v", tr.State)
	}
	zdr, tr = tracked(RRStatePending, "add2")
	zdr.ProcessConfirmation(confirm("add2", roleB, refused), nil)
	if tr.State != RRStateRejected {
		t.Errorf("b rejected the addition: %v", tr.State)
	}

	// the CSYNC: this record stands in for the zone's
	csync := func(distID string) (*ZoneDataRepo, *delegationCsync, func(*ConfirmationDetail)) {
		zdr, err := NewZoneDataRepo()
		if err != nil {
			t.Fatal(err)
		}
		set := &TrackedRRset{Tracked: []TrackedRR{{RR: rr, State: RRStatePending, DistributionID: distID, ExpectedRecipients: []string{freezeCombiner, roleB, roleN}}}}
		zdr.Tracking[zone] = map[AgentId]map[uint16]*TrackedRRset{us: {dns.TypeCSYNC: set}}
		cur := &delegationCsync{record: rr.String(), distID: distID, made: time.Now()}
		c := &r.conf.InternalMp.delegationSyncChains
		c.mu.Lock()
		if c.csyncs == nil {
			c.csyncs = map[string]*delegationCsync{}
		}
		c.csyncs[r.zone] = cur
		c.mu.Unlock()
		return zdr, cur, func(d *ConfirmationDetail) {
			zdr.ProcessConfirmation(d, nil)
			r.conf.delegationCsyncProgress(t.Context(), zdr, zone, d)
		}
	}
	failed := func(d *ConfirmationDetail) { d.Status = "FAILED" }
	_, cur, hear := csync("c1")
	hear(confirm("c1", roleN, refused))
	hear(confirm("c1", roleN, failed))
	if cur.failed != nil {
		t.Errorf("the auditor's rejection failed the CSYNC: %v", cur.failed)
	}
	zdr, cur, hear = csync("c2")
	hear(confirm("c2", roleN, failed))
	hear(confirm("c2", freezeCombiner, applied))
	hear(confirm("c2", roleB, applied))
	if cur.failed != nil || cur.confirmed {
		t.Errorf("with only the auditor left, inside the time-out: failed %v, confirmed %v", cur.failed, cur.confirmed)
	}
	cur.made = time.Now().Add(-time.Hour)
	r.conf.delegationCsyncProgress(t.Context(), zdr, zone, nil)
	if !cur.confirmed {
		t.Errorf("with only the auditor left, after the time-out: not confirmed, awaiting %v", cur.awaited)
	}
	_, cur, hear = csync("c3")
	hear(confirm("c3", roleB, failed))
	if cur.failed == nil {
		t.Error("b's final word that it failed did not fail the CSYNC")
	}
}

// A member that votes when a record is sent, and has lost its vote when it
// answers, decides nothing. If the voters have all answered by then the record
// is settled at that answer, as they left it: nothing else would look at it
// again.
func TestAnAnswerFromAMemberThatLostItsVoteSettlesTheRecord(t *testing.T) {
	r := newReconcileRig(t, "lostvoterecord.reconcile.example.", roleA)
	activate := func(in *Instructions) {
		t.Helper()
		if err := r.store.update(r.zone, func(z *zoneSerials) error {
			z.Active.Reading, z.Active.SerialDigest = in, sd(in)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	votes, noVote := freezeAt(t, 42, "v", "a,b,n", ""), freezeAt(t, 43, "w", "a,b", "")
	zone, us := ZoneName(r.zone), AgentId(r.conf.MpConfig().Identity)
	rr, err := dns.NewRR(r.zone + " 3600 IN NS ns9.provider.example.")
	if err != nil {
		t.Fatal(err)
	}
	confirm := func(zdr *ZoneDataRepo, distID, from string, change func(*ConfirmationDetail)) {
		d := &ConfirmationDetail{DistributionID: distID, Zone: zone, Source: from, Status: "ok"}
		change(d)
		zdr.ProcessConfirmation(d, nil)
	}
	applied := func(d *ConfirmationDetail) { d.AppliedRecords = []string{rr.String()} }
	ignored := func(d *ConfirmationDetail) { d.Status, d.IgnoredRecords = "IGNORED", []string{rr.String()} }
	removed := func(d *ConfirmationDetail) { d.RemovedRecords = []string{rr.String()} }
	refused := func(d *ConfirmationDetail) {
		d.Status, d.RejectedItems = "REJECTED", []RejectedItemInfo{{Record: rr.String(), Reason: "refused"}}
	}

	for _, tc := range []struct {
		name       string
		state      RRState
		voters     func(*ConfirmationDetail)
		recipients []string
		late       func(*ConfirmationDetail)
		status     string
		after      RRState
	}{
		{"an addition the voters applied", RRStatePending, applied, []string{freezeCombiner, roleB, roleN}, refused, "rejected", RRStateAccepted},
		{"an addition the voters ignored", RRStatePending, ignored, []string{freezeCombiner, roleB, roleN}, refused, "rejected", RRStateIgnored},
		{"an addition the voters ignored, n applying it", RRStatePending, ignored, []string{freezeCombiner, roleB, roleN}, applied, "accepted", RRStateIgnored},
		{"an addition the voters applied, n applying it", RRStatePending, applied, []string{freezeCombiner, roleB, roleN}, applied, "accepted", RRStateAccepted},
		{"a removal the voters did", RRStatePendingRemoval, removed, []string{freezeCombiner, roleB, roleN}, refused, "rejected", RRStateRemoved},
		// nobody is known to confirm it: nothing to settle it on
		{"an addition with no recipients yet", RRStatePending, nil, nil, refused, "rejected", RRStatePending},
		{"a removal with no recipients yet", RRStatePendingRemoval, nil, nil, refused, "rejected", RRStatePendingRemoval},
	} {
		activate(votes)
		zdr, err := NewZoneDataRepo()
		if err != nil {
			t.Fatal(err)
		}
		set := &TrackedRRset{Tracked: []TrackedRR{{RR: rr, State: tc.state, DistributionID: "d", ExpectedRecipients: tc.recipients}}}
		zdr.Tracking[zone] = map[AgentId]map[uint16]*TrackedRRset{us: {dns.TypeNS: set}}
		tr := &set.Tracked[0]
		if tc.voters != nil {
			confirm(zdr, "d", freezeCombiner, tc.voters)
			confirm(zdr, "d", roleB, tc.voters)
		}
		if tr.State != tc.state {
			t.Errorf("%s, with n still to answer: %v", tc.name, tr.State)
		}
		activate(noVote)
		confirm(zdr, "d", roleN, tc.late)
		if tr.State != tc.after || tr.Reason != "" || tr.Confirmations[roleN].Status != tc.status {
			t.Errorf("%s, and n answers with no vote: %v, reason %q, its answer %q", tc.name, tr.State, tr.Reason, tr.Confirmations[roleN].Status)
		}
	}
}

// lostVoteRig is a zone of the leader a, where n votes until a test changes the
// active serial, with what the tests below read and write of a tracked record.
type lostVoteRig struct {
	*reconcileRig
	zone ZoneName
	us   AgentId
	rr   dns.RR
}

func newLostVoteRig(t *testing.T, name string) *lostVoteRig {
	t.Helper()
	r := newReconcileRig(t, name, roleA)
	rr, err := dns.NewRR(name + " 3600 IN NS ns9.provider.example.")
	if err != nil {
		t.Fatal(err)
	}
	return &lostVoteRig{r, ZoneName(name), AgentId(r.conf.MpConfig().Identity), rr}
}

func (r *lostVoteRig) activate(t *testing.T, in *Instructions) {
	t.Helper()
	if err := r.store.update(string(r.zone), func(z *zoneSerials) error {
		z.Active.Reading, z.Active.SerialDigest = in, sd(in)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (r *lostVoteRig) tracked(t *testing.T, state RRState, recipients []string) (*ZoneDataRepo, *TrackedRR) {
	t.Helper()
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	set := &TrackedRRset{Tracked: []TrackedRR{{RR: r.rr, State: state, DistributionID: "d", ExpectedRecipients: recipients}}}
	zdr.Tracking[r.zone] = map[AgentId]map[uint16]*TrackedRRset{r.us: {dns.TypeNS: set}}
	return zdr, &set.Tracked[0]
}

func (r *lostVoteRig) confirm(zdr *ZoneDataRepo, from string, change func(*ConfirmationDetail)) {
	d := &ConfirmationDetail{DistributionID: "d", Zone: r.zone, Source: from, Status: "ok"}
	change(d)
	zdr.ProcessConfirmation(d, nil)
}

// A record that waits for a member that has lost its vote, and stays silent, is
// settled when the vote goes, as the voters left it: no confirmation is coming.
// One a voter has not answered waits on. One with no recipient that votes has
// no answer to settle it on, and stays as it is.
func TestARecordSettlesWhenTheSilentMemberItWaitsForLosesItsVote(t *testing.T) {
	r := newLostVoteRig(t, "lostvotesilent.reconcile.example.")
	votes, noVote := freezeAt(t, 42, "v", "a,b,n", ""), freezeAt(t, 43, "w", "a,b", "")
	applied := func(d *ConfirmationDetail) { d.AppliedRecords = []string{r.rr.String()} }
	ignored := func(d *ConfirmationDetail) { d.Status, d.IgnoredRecords = "IGNORED", []string{r.rr.String()} }
	removed := func(d *ConfirmationDetail) { d.RemovedRecords = []string{r.rr.String()} }
	all := []string{freezeCombiner, roleB, roleN}

	for _, tc := range []struct {
		name       string
		state      RRState
		recipients []string
		answer     func(*ConfirmationDetail)
		answered   []string
		after      RRState
	}{
		{"an addition the voters applied", RRStatePending, all, applied, []string{freezeCombiner, roleB}, RRStateAccepted},
		{"an addition the voters ignored", RRStatePending, all, ignored, []string{freezeCombiner, roleB}, RRStateIgnored},
		{"a removal the voters did", RRStatePendingRemoval, all, removed, []string{freezeCombiner, roleB}, RRStateRemoved},
		{"an addition b has not answered", RRStatePending, all, applied, []string{freezeCombiner}, RRStatePending},
		{"a removal b has not answered", RRStatePendingRemoval, all, removed, []string{freezeCombiner}, RRStatePendingRemoval},
		{"an addition with n its only recipient", RRStatePending, []string{roleN}, nil, nil, RRStatePending},
		{"a removal with n its only recipient", RRStatePendingRemoval, []string{roleN}, nil, nil, RRStatePendingRemoval},
		{"an addition with no recipients yet", RRStatePending, nil, nil, nil, RRStatePending},
		{"a removal with no recipients yet", RRStatePendingRemoval, nil, nil, nil, RRStatePendingRemoval},
	} {
		r.activate(t, votes)
		zdr, tr := r.tracked(t, tc.state, tc.recipients)
		for _, from := range tc.answered {
			r.confirm(zdr, from, tc.answer)
		}
		r.conf.instrActivated(t.Context(), zdr, r.zone)
		if tr.State != tc.state {
			t.Errorf("%s, while n votes: %v", tc.name, tr.State)
		}
		r.activate(t, noVote)
		r.conf.instrActivated(t.Context(), zdr, r.zone)
		if tr.State != tc.after {
			t.Errorf("%s, when n has lost its vote: %v, want %v", tc.name, tr.State, tc.after)
		}
		if got, ok := tr.Confirmations[roleN]; ok {
			t.Errorf("%s: n has said nothing, and its answer reads %q", tc.name, got.Status)
		}
	}

	refused := func(d *ConfirmationDetail) {
		d.Status, d.RejectedItems = "REJECTED", []RejectedItemInfo{{Record: r.rr.String(), Reason: "refused"}}
	}
	// n's rejection is no removal: as the only recipient, with no vote, it
	// leaves the record where it was
	r.activate(t, noVote)
	zdr, tr := r.tracked(t, RRStatePendingRemoval, []string{roleN})
	r.confirm(zdr, roleN, refused)
	if tr.State != RRStatePendingRemoval {
		t.Errorf("a removal n alone was to answer, and rejected with no vote: %v", tr.State)
	}
	// a rejection from before n had a vote decides nothing, by the project
	// owner's ruling, also once n has one: the removal finishes when the
	// voters have removed the record, and n is not asked again
	zdr, tr = r.tracked(t, RRStatePendingRemoval, all)
	r.confirm(zdr, roleN, refused)
	r.activate(t, votes)
	r.confirm(zdr, freezeCombiner, removed)
	r.confirm(zdr, roleB, removed)
	if tr.State != RRStateRemoved {
		t.Errorf("a removal the voters did, that n rejected before it had a vote: %v", tr.State)
	}
}

// A provider is down when another withdraws a record, and is then removed. It
// loses its vote when the leader's step names the removal, not at the
// activation. The record settles then, and a catch-up answer, which reads the
// repo, stops naming what was withdrawn.
func TestAWithdrawnRecordDoesNotComeBackOnceTheSilentProviderIsRemoved(t *testing.T) {
	r := newLostVoteRig(t, "withdrawnback.reconcile.example.")
	told := 0
	r.store.onActive = func(string) { told++ }
	r.activate(t, freezeAt(t, 42, "v", "a,b,n", ""))
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	zdr.AddConfirmedRR(r.zone, r.us, r.rr)
	zdr.markOwnState(r.zone, true, "")
	tr := zdr.trackedRR(r.zone, r.us, dns.TypeNS, r.rr.String())
	tr.State, tr.DistributionID, tr.ExpectedRecipients = RRStatePendingRemoval, "d", []string{freezeCombiner, roleB, roleN}
	named := func() bool {
		zu := r.conf.buildCatchUpAnswer(zdr, r.zone, &CatchUp{Request: "r1", Reason: "start"})
		return slices.Contains(ops(zu)["NS"].Records, r.rr.String())
	}
	removed := func(d *ConfirmationDetail) { d.RemovedRecords = []string{r.rr.String()} }
	r.confirm(zdr, freezeCombiner, removed)
	r.confirm(zdr, roleB, removed)
	if tr.State != RRStatePendingRemoval || !named() {
		t.Fatalf("with n down and still voting: %v, named %v", tr.State, named())
	}

	// the serial that has no record of n: nothing names its removal yet, and
	// the record waits on
	r.activate(t, jAt(t, 43, `servers="a,b" nsmgmt="agent" suffix="w"`, freezeRecords[:2]...))
	r.conf.instrActivated(t.Context(), zdr, r.zone)
	if tr.State != RRStatePendingRemoval {
		t.Fatalf("at the activation, before the removal's step: %v", tr.State)
	}

	// the step names the removal: the engine is told, and looks again
	told = 0
	setRemoval := func(step int) {
		t.Helper()
		if err := r.store.update(string(r.zone), func(z *zoneSerials) error {
			z.Removals = []Removal{{Label: "n", Identity: roleN, Step: step}}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	setRemoval(1)
	if told != 1 {
		t.Errorf("a removal under way that starts was told %d times, want once", told)
	}
	r.conf.instrActivated(t.Context(), zdr, r.zone)
	if tr.State != RRStateRemoved || named() {
		t.Errorf("when the removal has taken n's vote: %v, named %v", tr.State, named())
	}
	// the same member still leaving, at the next step, is nothing new
	told = 0
	setRemoval(2)
	if told != 0 {
		t.Errorf("a removal already under way was told again %d times", told)
	}
}

// A member with no vote can answer after the voters have settled the zone's
// CSYNC (allRecipientsConfirmed). Whatever it answers ends the wait for it at
// once, so the NOTIFY does not wait out the time-out for a member that has
// answered, and it changes nothing of what the voters settled. Only a member
// that is silent, or at other instructions, is waited for, up to the time-out.
func TestALateAnswerFromAMemberWithNoVoteEndsTheCsyncsWaitForIt(t *testing.T) {
	for _, member := range []struct {
		name, zone, auditors string
		want                 standing
	}{
		{"auditor", "lateauditor.reconcile.example.", "n", standingAuditor},
		{"no role", "latenorole.reconcile.example.", "", standingNoRole},
	} {
		t.Run(member.name, func(t *testing.T) {
			r := newReconcileRig(t, member.zone, roleA)
			active := freezeAt(t, 42, "v", "a,b", member.auditors)
			if err := r.store.update(r.zone, func(z *zoneSerials) error {
				z.Active.Reading, z.Active.SerialDigest = active, sd(active)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			zone, us := ZoneName(r.zone), AgentId(r.conf.MpConfig().Identity)
			if st := zoneStanding(instructionsFor(zone), roleN); st != member.want {
				t.Fatalf("n's standing is %d, want %d", st, member.want)
			}
			rr, err := dns.NewRR(r.zone + " 3600 IN NS ns9.provider.example.")
			if err != nil {
				t.Fatal(err)
			}
			applied := func(d *ConfirmationDetail) { d.AppliedRecords = []string{rr.String()} }
			ignored := func(d *ConfirmationDetail) { d.Status, d.IgnoredRecords = "IGNORED", []string{rr.String()} }
			refused := func(d *ConfirmationDetail) {
				d.Status, d.RejectedItems = "REJECTED", []RejectedItemInfo{{Record: rr.String(), Reason: "refused"}}
			}
			// the CSYNC, with the voters' answers in; this record stands in for it
			settled := func(distID string, voters func(*ConfirmationDetail)) (*TrackedRR, *delegationCsync, func(string, func(*ConfirmationDetail))) {
				zdr, err := NewZoneDataRepo()
				if err != nil {
					t.Fatal(err)
				}
				set := &TrackedRRset{Tracked: []TrackedRR{{RR: rr, State: RRStatePending, DistributionID: distID, ExpectedRecipients: []string{freezeCombiner, roleB, roleN}}}}
				zdr.Tracking[zone] = map[AgentId]map[uint16]*TrackedRRset{us: {dns.TypeCSYNC: set}}
				cur := &delegationCsync{record: rr.String(), distID: distID, made: time.Now()}
				c := &r.conf.InternalMp.delegationSyncChains
				c.mu.Lock()
				if c.csyncs == nil {
					c.csyncs = map[string]*delegationCsync{}
				}
				c.csyncs[r.zone] = cur
				c.mu.Unlock()
				hear := func(from string, change func(*ConfirmationDetail)) {
					d := &ConfirmationDetail{DistributionID: distID, Zone: zone, Source: from, Status: "ok"}
					change(d)
					zdr.ProcessConfirmation(d, nil)
					r.conf.delegationCsyncProgress(t.Context(), zdr, zone, d)
				}
				hear(freezeCombiner, voters)
				hear(roleB, voters)
				return &set.Tracked[0], cur, hear
			}

			for _, voters := range []struct {
				name   string
				answer func(*ConfirmationDetail)
				state  RRState
			}{
				{"applied", applied, RRStateAccepted},
				{"ignored", ignored, RRStateIgnored},
			} {
				for _, late := range []struct {
					name   string
					answer func(*ConfirmationDetail)
					status string
				}{
					{"applied", applied, "accepted"},
					{"ignored", ignored, "ignored"},
					{"rejected", refused, "rejected"},
				} {
					what := "the voters " + voters.name + " the CSYNC and n " + late.name + " it"
					tr, cur, hear := settled(voters.name+late.name, voters.answer)
					if tr.State != voters.state || cur.confirmed {
						t.Errorf("%s, before n's answer: %v, confirmed %v", what, tr.State, cur.confirmed)
					}
					hear(roleN, late.answer)
					if !cur.confirmed || cur.failed != nil {
						t.Errorf("%s: confirmed %v, failed %v, awaiting %v", what, cur.confirmed, cur.failed, cur.awaited)
					}
					if tr.State != voters.state || tr.Confirmations[roleN].Status != late.status {
						t.Errorf("%s: the record reads %v, n's answer %q", what, tr.State, tr.Confirmations[roleN].Status)
					}
				}
			}

			// silent, it is waited for up to the time-out and no longer
			_, cur, hear := settled("silent", applied)
			if cur.confirmed {
				t.Error("the CSYNC was confirmed inside the time-out with n silent")
			}
			// at other instructions it has decided nothing yet (rule 6)
			hear(roleN, func(d *ConfirmationDetail) { ignored(d); d.NotYet = true })
			if cur.confirmed {
				t.Error("a word from n at other instructions ended the wait for it")
			}
			cur.made = time.Now().Add(-time.Hour)
			hear(roleB, applied) // the engine looks again
			if !cur.confirmed {
				t.Errorf("after the time-out with n silent: not confirmed, awaiting %v", cur.awaited)
			}

			// a voter's word on a settled record stays as it was
			tr, cur, hear := settled("voter", applied)
			hear(roleB, ignored)
			hear(roleB, refused)
			if tr.Confirmations[roleB].Status != "accepted" || tr.State != RRStateAccepted || cur.failed != nil {
				t.Errorf("b's late words: its answer %q, the record %v, failed %v", tr.Confirmations[roleB].Status, tr.State, cur.failed)
			}
		})
	}
}

// A member that votes when a DNSKEY distribution starts and has no role
// after a thaw while the distribution waits is not waited for past a
// time-out: the look at the time-out is made, and made again.
func TestADNSKEYDistributionGoesOnWithoutAMemberThatLostItsRoleWhileItWaited(t *testing.T) {
	r := newReconcileRig(t, "dnskeylost.reconcile.example.", roleA)
	r.n = freezeAt(t, 41, "n", "a,b,n", "")
	r.v = freezeAt(t, 42, "v", "a,b", "")
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.Active.Reading, z.Active.SerialDigest = r.n, sd(r.n)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r.holdUnjudged(r.v, time.Now())
	tm := r.conf.InternalMp.MPTransport
	tm.noRoleTimeout = 10 * time.Millisecond
	waiting := func() bool {
		tm.dnskeyPropMu.Lock()
		defer tm.dnskeyPropMu.Unlock()
		_, ok := tm.pendingDnskeyPropagations["d1"]
		return ok
	}
	tm.TrackDnskeyPropagation(t.Context(), ZoneName(r.zone), "d1", []uint16{4711}, nil, []AgentId{roleB, roleN})
	tm.ProcessDnskeyConfirmation("d1", roleB, transport.ConfirmSuccess.String(), nil, nil)
	time.Sleep(50 * time.Millisecond) // time-outs pass while n votes
	if !waiting() {
		t.Fatal("the distribution went on without n while n votes")
	}
	if err := r.conf.activate(r.zone, Thaw{From: sd(r.n), To: sd(r.v)}, roleA); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(2 * time.Second); waiting(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the distribution still waits for n, which has no role since the thaw")
		}
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

// An agent that holds no step's sets hands its parts nothing new, and its
// signer keeps what it holds, held: the zone is frozen (S9's holdLast).
func TestAPendingAgentHoldsItsSignerOnWhatItHolds(t *testing.T) {
	r := newReconcileRig(t, "pendinghold.reconcile.example.", roleB)
	r.conf.handOverToParts(r.zone)
	r.partsTake()
	if h := r.wantedBy(r.signer); h == nil || h.Sets.Hold {
		t.Fatalf("the signer at rest: %v", h)
	}
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.Sets, z.Pending = nil, true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r.conf.handOverToParts(r.zone)
	h := r.wantedBy(r.signer)
	if h == nil || !h.Sets.Hold || h.Serial != r.n.Serial {
		t.Errorf("the signer while no step's sets are held: %v", h)
	}
}

// The DNSKEY distribution's time-out for members with no role counts from
// the first of its resends: the signer resends sooner than the time-out,
// and each resend takes the one before it over (foldIntoResend). The
// first one's time-out then ends the resend's wait, and a member that
// timed out is not waited for again by a later resend (external review of
// #327, F1).
func TestADNSKEYNoRoleTimeOutCountsFromTheFirstOfItsResends(t *testing.T) {
	r := newReconcileRig(t, "dnskeyresend.reconcile.example.", roleA)
	tm := r.conf.InternalMp.MPTransport
	tm.noRoleTimeout = time.Hour // the test ends the waits itself
	zone := ZoneName(r.zone)
	pending := func(id string) bool {
		tm.dnskeyPropMu.Lock()
		defer tm.dnskeyPropMu.Unlock()
		_, ok := tm.pendingDnskeyPropagations[id]
		return ok
	}
	tm.TrackDnskeyPropagation(t.Context(), zone, "d1", []uint16{4711}, nil, []AgentId{roleB, roleN})
	tm.ProcessDnskeyConfirmation("d1", roleB, transport.ConfirmSuccess.String(), nil, nil)
	tm.TrackDnskeyPropagation(t.Context(), zone, "d2", []uint16{4711}, nil, []AgentId{roleB, roleN})
	tm.foldIntoResend(zone, "d2")
	if !pending("d2") {
		t.Fatal("the resend did not wait for n")
	}
	tm.dnskeyNoRoleTimedOut(t.Context(), "d1")
	if pending("d2") {
		t.Error("the first distribution's time-out did not end the resend's wait for n")
	}

	tm.TrackDnskeyPropagation(t.Context(), zone, "d3", []uint16{4711}, nil, []AgentId{roleB, roleN})
	tm.dnskeyNoRoleTimedOut(t.Context(), "d3") // n times out; b, voting, is waited for
	tm.TrackDnskeyPropagation(t.Context(), zone, "d4", []uint16{4711}, nil, []AgentId{roleB, roleN})
	tm.foldIntoResend(zone, "d4")
	tm.ProcessDnskeyConfirmation("d4", roleB, transport.ConfirmSuccess.String(), nil, nil)
	if pending("d4") {
		t.Error("the resend waited for n again, which had timed out")
	}
}

// A leader goes on past a voting member already at rest at V: done with the
// transition, its parts hold V's lists, and it tells no step any more, as
// after a new leader took over from one that had just finished (external
// review of #327, F2).
func TestALeaderGoesOnPastAVoterAlreadyAtRestAtV(t *testing.T) {
	r := newReconcileRig(t, "atrest.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	done := r.own()
	done.Reconciling, done.Step, done.StepHeld, done.Removals = false, nil, false, nil
	for range 3 {
		r.partsTake()
		r.hear(roleB, done, true)
		r.turn(time.Now())
	}
	if s := status(t, r.store, r.zone); s.Phase != PhaseSteady {
		t.Errorf("the leader waits for b, at rest at 42: %+v, status %q", s, r.conf.thawLine(r.zone))
	}
}

// A leader that holds no step's sets takes no step until every other voting
// member under V is heard, though one heard tells a step: one not heard may
// tell a further step (external review of #327, F3).
func TestALeaderWithNoStepWaitsForEveryVoterBeforeItTakesOne(t *testing.T) {
	r := newReconcileRig(t, "unheard.reconcile.example.", roleA)
	r.n = freezeAt(t, 41, "n", "a,b,n", "")
	r.v = freezeAt(t, 42, "v", "a,b,n", "")
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
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.From, z.Sets, z.Step, z.Taken, z.Pending = nil, nil, 0, nil, true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r.stamps.kept = map[string]*memberStamp{} // a start: nothing heard
	r.hear(roleB, r.leaderStep(0, rolesFor(r.n, r.n, 0), nil), true)
	r.turn(time.Now())
	if st, ok := r.step(); ok {
		t.Fatalf("took b's step %d before n was heard", st.Number)
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, roleN+" (not heard)") {
		t.Errorf("the status: %q", line)
	}
}

// The auditor's zone page shows the transition as the agent's status does:
// the step, or when the last one was done (external review of #327, F4).
func TestTheAuditorsZonePageShowsTheTransition(t *testing.T) {
	r := newReconcileRig(t, "auditorpage.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	for range 2 {
		r.partsTake()
		r.holdsToo(roleB)
		r.turn(time.Now())
	}
	if line := r.conf.instructionsLine(r.zone); !strings.Contains(line, "at 42, done since") {
		t.Errorf("the auditor's line: %q, want the transition done", line)
	}
}

// A CSYNC's look at its time-out for members with no role, made, lets the
// next one be armed and asks the data engine for the progress that arms
// it; a look for a CSYNC made since leaves the newer one alone (external
// review of #327, N1).
func TestAMadeCSYNCLookLetsTheNextBeArmed(t *testing.T) {
	r := newReconcileRig(t, "csynclook.reconcile.example.", roleA)
	q := make(chan *SynchedDataCmd, 4)
	r.conf.InternalMp.MsgQs = &MsgQs{SynchedDataCmd: q}
	c := &r.conf.InternalMp.delegationSyncChains
	cur := &delegationCsync{record: "csync", made: time.Now(), awaited: []string{roleN}, noRoleAt: true}
	c.mu.Lock()
	if c.csyncs == nil {
		c.csyncs = map[string]*delegationCsync{}
	}
	c.csyncs[r.zone] = cur
	c.mu.Unlock()
	r.conf.csyncLooked(t.Context(), ZoneName(r.zone), cur)
	c.mu.Lock()
	armed := cur.noRoleAt
	c.mu.Unlock()
	if armed {
		t.Error("the look made, the CSYNC still counts one as set: no next one is armed")
	}
	select {
	case cmd := <-q:
		if cmd.Cmd != "csync-progress" {
			t.Errorf("asked %q, want the CSYNC's progress", cmd.Cmd)
		}
	default:
		t.Error("the look made asks the data engine for nothing")
	}
	newer := &delegationCsync{record: "csync2", made: time.Now(), noRoleAt: true}
	c.mu.Lock()
	c.csyncs[r.zone] = newer
	c.mu.Unlock()
	r.conf.csyncLooked(t.Context(), ZoneName(r.zone), cur)
	if !newer.noRoleAt {
		t.Error("a look for an older CSYNC cleared the newer one's")
	}
}

// With no engine ctx, a CSYNC look that finds the data engine's queue full
// schedules no retry, which would outlive the engine; the engine's next
// round looks instead (external review of #327, F5).
func TestACSYNCLookWithNoEngineSchedulesNoRetry(t *testing.T) {
	r := newReconcileRig(t, "nilctx.reconcile.example.", roleA)
	q := make(chan *SynchedDataCmd, 1)
	q <- &SynchedDataCmd{Cmd: "a full queue"}
	r.conf.InternalMp.MsgQs = &MsgQs{SynchedDataCmd: q}
	r.conf.askCsyncProgress(nil, ZoneName(r.zone))
	done := make(chan struct{})
	go func() { r.conf.waitDelegationSyncTimers(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("a retry with no engine to end it was scheduled")
	}
}

// "Done" with a newer serial held goes from reconciling straight to
// agreeing on it, frozen throughout: the owed list is not released and the
// signer stays held until that serial's transition is done (item 7, as
// decided; external review of #327, F6).
func TestDoneWithAWaitingSerialKeepsTheOwedList(t *testing.T) {
	logs := captureLog(t)
	r := newReconcileRig(t, "keptowed.reconcile.example.", roleA)
	r.agree()
	r.thawNow()
	r.store.Note(r.zone, freezeAt(t, 43, "w", "a,b", ""), nil)
	for len(r.conf.InternalMp.MsgQs.SynchedDataCmd) > 0 {
		<-r.conf.InternalMp.MsgQs.SynchedDataCmd
	}
	for range 2 {
		r.partsTake()
		r.holdsToo(roleB)
		r.turn(time.Now())
	}
	if !strings.Contains(logs.String(), `msg="transition done"`) {
		t.Fatalf("not done: %q", r.conf.thawLine(r.zone))
	}
	if len(r.conf.zoneFrozen(r.zone)) == 0 {
		t.Error("the zone is not frozen at done with 43 waiting")
	}
	for len(r.conf.InternalMp.MsgQs.SynchedDataCmd) > 0 {
		if cmd := <-r.conf.InternalMp.MsgQs.SynchedDataCmd; cmd.Cmd == "instr-done" {
			t.Error("the owed list was released at done with 43 waiting")
		}
	}
	if h := r.wantedBy(r.signer); h == nil || !h.Sets.Hold {
		t.Errorf("the signer's hold is let go at done with 43 waiting: %v", h)
	}
}

// What a member with no role rejects decides nothing, by the project owner's
// ruling, also if the member gains a vote before the distribution ends. Its
// rejection from before that is not counted then, and it is not asked again; a
// rejection it gives once it has its vote counts.
func TestARejectionOfAKeyFromBeforeAMemberHadAVoteDecidesNothing(t *testing.T) {
	for _, tc := range []struct{ name, zone, auditors string }{
		{"no role", "laterolekey.reconcile.example.", ""},
		{"auditor", "lateauditorkey.reconcile.example.", "n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReconcileRig(t, tc.zone, roleA)
			activate := func(in *Instructions) {
				t.Helper()
				if err := r.store.update(r.zone, func(z *zoneSerials) error {
					z.Active.Reading, z.Active.SerialDigest = in, sd(in)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			activate(freezeAt(t, 42, "v", "a,b", tc.auditors))
			zone := ZoneName(r.zone)
			tm := r.conf.InternalMp.MPTransport
			tm.noRoleTimeout = time.Hour // the test ends the wait itself
			key := testDnskeyRR(t, r.zone, 257)
			kt := key.KeyTag()
			track := func(distID string) *PendingDnskeyPropagation {
				tm.TrackDnskeyPropagation(t.Context(), zone, distID, []uint16{kt}, nil, []AgentId{roleB, roleN})
				tm.dnskeyPropMu.Lock()
				defer tm.dnskeyPropMu.Unlock()
				return tm.pendingDnskeyPropagations[distID]
			}
			items := []RejectedItemInfo{{Record: key.String(), Reason: "n refuses"}}
			direct, credited := track("direct"), track("credited")
			tm.ProcessDnskeyConfirmation("direct", roleN, transport.ConfirmRejected.String(), nil, items)
			tm.dnskeyPropMu.Lock()
			tm.creditFromAnswerLocked(&sentAnswer{zone: zone, asker: roleN, at: time.Now(), keys: map[uint16]bool{kt: true}}, roleN, transport.ConfirmRejected.String(), nil, items, nil)
			tm.dnskeyPropMu.Unlock()
			if !direct.ExpectedAgents[roleN] || !credited.ExpectedAgents[roleN] {
				t.Fatalf("n's answer did not end the wait for it: %v %v", direct.ExpectedAgents, credited.ExpectedAgents)
			}

			activate(freezeAt(t, 43, "w", "a,b,n", ""))
			if !canHoldAKey(zone, roleN) {
				t.Fatal("n has no vote after the thaw")
			}
			for name, p := range map[string]*PendingDnskeyPropagation{"a direct answer": direct, "an answer to a catch-up": credited} {
				if propagated, _, rejected, msg := p.outcome(); len(propagated) != 1 || len(rejected) != 0 || msg != "" {
					t.Errorf("n rejected the key in %s before it had a vote: propagated %v, rejected %v, reason %q", name, propagated, rejected, msg)
				}
				if got := p.Results[roleN][kt]; got != "rejected" {
					t.Errorf("n's answer in %s reads %q, want it recorded", name, got)
				}
			}

			afterwards := track("afterwards")
			tm.ProcessDnskeyConfirmation("afterwards", roleN, transport.ConfirmRejected.String(), nil, items)
			if _, _, rejected, msg := afterwards.outcome(); len(rejected) != 1 || msg != "n refuses" {
				t.Errorf("n rejected the key with a vote: rejected %v, reason %q", rejected, msg)
			}
		})
	}
}

// TestALeavingProvidersRejectionOfAKeyCountsWhileItIsWaitedFor, by the project
// owner's ruling: a leaving provider may still be delegated to (design 5.2), so
// while it is among the key confirmers a distribution has no time-out for it,
// and what it rejects or ignores holds the key. Once a step takes it out it
// decides nothing, what it answered before included. A member with no role
// never does, and a leaving provider's rejection of anything else does not
// (nonVotingMember, TestARejectionFromAMemberWithNoVoteDecidesNothing).
func TestALeavingProvidersRejectionOfAKeyCountsWhileItIsWaitedFor(t *testing.T) {
	r := newMemberRig(t, "leaverkey.reconcile.example.")
	zone := ZoneName(r.zone)
	tm := r.conf.InternalMp.MPTransport
	tm.noRoleTimeout = time.Hour // the test ends the wait itself

	key := testDnskeyRR(t, r.zone, 257)
	kt := key.KeyTag()
	track := func(distID string) *PendingDnskeyPropagation {
		tm.TrackDnskeyPropagation(t.Context(), zone, distID, []uint16{kt}, nil, []AgentId{roleB, roleN})
		tm.dnskeyPropMu.Lock()
		defer tm.dnskeyPropMu.Unlock()
		return tm.pendingDnskeyPropagations[distID]
	}
	refused := func(distID string) {
		tm.ProcessDnskeyConfirmation(distID, roleN, transport.ConfirmRejected.String(), nil, []RejectedItemInfo{{Record: key.String(), Reason: "n refuses"}})
	}
	applied := func(distID string) {
		tm.ProcessDnskeyConfirmation(distID, roleB, transport.ConfirmSuccess.String(), []string{key.String()}, nil)
	}
	waits := func(distID string) bool {
		tm.dnskeyPropMu.Lock()
		defer tm.dnskeyPropMu.Unlock()
		_, ok := tm.pendingDnskeyPropagations[distID]
		return ok
	}
	step := func(n int, stillConfirms bool) {
		t.Helper()
		sets := rolesFor(r.v, r.v, 0)
		if stillConfirms {
			sets.KeyConfirmers = append(slices.Clone(sets.KeyConfirmers), Provider{Label: "n"})
		}
		r.hear(roleB, r.leaderStep(n, sets, []string{"x"}, InstrRemoval{Label: "n", Identity: roleN}), true)
		r.conf.thawTurn(r.zone)
		if st, ok := r.step(); !ok || st.Number != n {
			t.Fatalf("the member's step: %+v", st)
		}
		if got := stillConfirmsKeys(zone, roleN); got != stillConfirms {
			t.Fatalf("at step %d n still confirms keys: %v", n, got)
		}
	}

	// a member with no role, not leaving: its rejection decides nothing
	if st := zoneStanding(instructionsFor(zone), roleN); st != standingNoRole {
		t.Fatalf("n's standing is %d, want a member with no role", st)
	}
	p := track("none")
	refused("none")
	if propagated, _, rejected, _ := p.outcome(); len(propagated) != 1 || len(rejected) != 0 {
		t.Errorf("the key a member with no role rejected: propagated %v rejected %v", propagated, rejected)
	}
	tm.ProcessDnskeyConfirmation("none", roleB, transport.ConfirmSuccess.String(), []string{key.String()}, nil)

	// leaving, and still among the key confirmers
	step(1, true)
	if !nonVotingMember(zone, roleN) {
		t.Error("n has a vote: what it rejects other than a key would decide")
	}
	p = track("rejects")
	refused("rejects")
	applied("rejects")
	if _, _, rejected, msg := p.outcome(); len(rejected) != 1 || msg != "n refuses" {
		t.Errorf("the key the leaver rejected while waited for: rejected %v, reason %q", rejected, msg)
	}
	ign := track("ignores")
	if !ign.Signing[roleN] {
		t.Fatal("the leaver is not among the signing agents")
	}
	tm.ProcessDnskeyConfirmation("ignores", roleN, transport.ConfirmIgnored.String(), nil, nil)
	if _, _, rejected, _ := ign.outcome(); len(rejected) != 1 {
		t.Errorf("the key the leaver ignored while waited for: rejected %v", rejected)
	}
	// a rejection's reason goes before a signer's ignoring it, whoever sorts first
	both := track("both")
	refused("both")
	tm.ProcessDnskeyConfirmation("both", roleB, transport.ConfirmIgnored.String(), nil, nil)
	if _, _, rejected, msg := both.outcome(); len(rejected) != 1 || msg != "n refuses" {
		t.Errorf("the key the leaver rejected and b ignored: rejected %v, reason %q", rejected, msg)
	}
	track("waits")
	applied("waits")
	tm.dnskeyNoRoleTimedOut(t.Context(), "waits")
	if !waits("waits") {
		t.Error("the distribution went on without a leaver that still confirms keys")
	}
	before := track("before")
	refused("before")

	// a step takes it out
	step(2, false)
	if _, _, rejected, msg := before.outcome(); len(rejected) != 0 || msg != "" {
		t.Errorf("what the leaver rejected before it left still rejects the key: %v, reason %q", rejected, msg)
	}
	// and its reason is not the one the signer hears when b rejects the key
	tm.ProcessDnskeyConfirmation("before", roleB, transport.ConfirmRejected.String(), nil, []RejectedItemInfo{{Record: key.String(), Reason: "b refuses"}})
	if _, _, rejected, msg := before.outcome(); len(rejected) != 1 || msg != "b refuses" {
		t.Errorf("the key b rejected after the leaver's rejection stopped counting: rejected %v, reason %q", rejected, msg)
	}
	if _, _, rejected, _ := ign.outcome(); len(rejected) != 0 {
		t.Errorf("what the leaver ignored before it left still rejects the key: %v", rejected)
	}
	p = track("after")
	refused("after")
	if propagated, _, rejected, _ := p.outcome(); len(propagated) != 1 || len(rejected) != 0 {
		t.Errorf("the key the leaver rejected after it left: propagated %v rejected %v", propagated, rejected)
	}
	tm.dnskeyNoRoleTimedOut(t.Context(), "waits")
	if waits("waits") {
		t.Error("the distribution still waits for a provider that left the key confirmers, after the time-out")
	}
	// b, a voting member, decides throughout
	p = track("voter")
	tm.ProcessDnskeyConfirmation("voter", roleB, transport.ConfirmRejected.String(), nil, []RejectedItemInfo{{Record: key.String(), Reason: "b refuses"}})
	if _, _, rejected, msg := p.outcome(); len(rejected) != 1 || msg != "b refuses" {
		t.Errorf("the key b rejected: rejected %v, reason %q", rejected, msg)
	}
	// the same when b's rejection comes as its answer to a catch-up
	p = track("credited")
	refused("credited")
	tm.dnskeyPropMu.Lock()
	tm.creditFromAnswerLocked(&sentAnswer{zone: zone, asker: roleB, at: time.Now(), keys: map[uint16]bool{kt: true}}, roleB, transport.ConfirmRejected.String(), nil, []RejectedItemInfo{{Record: key.String(), Reason: "b refuses"}}, nil)
	tm.dnskeyPropMu.Unlock()
	if _, _, rejected, msg := p.outcome(); len(rejected) != 1 || msg != "b refuses" {
		t.Errorf("the key b rejected in its answer to a catch-up: rejected %v, reason %q", rejected, msg)
	}
}
