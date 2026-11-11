/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The judge's tests (plan S4). alpha signs and serves, beta serves from
// alpha, charlie serves.
const (
	jAlpha    = `3600 IN HSYNC3 ON alpha agent.alpha.example. .`
	jBeta     = `3600 IN HSYNC3 ON beta agent.beta.example. alpha`
	jCharlie  = `3600 IN HSYNC3 ON charlie agent.charlie.example. .`
	jServers3 = `servers="alpha,beta,charlie" signers="alpha"`
	jServers2 = `servers="alpha,beta" signers="alpha"`
	allKinds  = kindRolesTaken | kindServerRole | kindSignerRole | kindNSmgmt | kindParentSync | kindUpstream | kindPubkey
)

// jAt reads records under an HSYNCPARAM with serial and param.
func jAt(t *testing.T, serial uint32, param string, records ...string) *Instructions {
	t.Helper()
	return readOf(t, append(slices.Clone(records), fmt.Sprintf(`3600 IN HSYNCPARAM serial="%d" %s`, serial, param))...)
}

func wantRefusals(t *testing.T, what string, got []Refusal, want ...Refusal) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s:\n got %v\nwant %v", what, got, want)
	}
}

func hasRefusal(t *testing.T, what string, got []Refusal, want Refusal) {
	t.Helper()
	if !slices.Contains(got, want) {
		t.Errorf("%s: %v does not hold %v", what, got, want)
	}
}

// heldAt is the store's held serial, or its active one.
func heldAt(t *testing.T, s *InstructionStore, serial uint32) heldSerial {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.zones[storeZone].held(serial)
	if h == nil {
		t.Fatalf("serial %d is not held", serial)
	}
	return *h
}

func TestARecordWithARoleRemovedIsRefused(t *testing.T) {
	from := jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie)
	want := Refusal{RefusedRecordWithRoleRemoved, "removes the record of agent.charlie.example., which has a role under 41"}
	wantRefusals(t, "removed", judgeTransition(from, jAt(t, 42, jServers3, jAlpha, jBeta)), want)
	wantRefusals(t, "turned OFF", judgeTransition(from, jAt(t, 42, jServers3, jAlpha, jBeta, `3600 IN HSYNC3 OFF charlie agent.charlie.example. .`)), want)
}

func TestARecordRemovedWhileItsRemovalIsNotDoneIsAgreed(t *testing.T) {
	// charlie's roles went at 41, and its removal is under way
	from, to := jAt(t, 41, jServers2, jAlpha, jBeta, jCharlie), jAt(t, 42, jServers2, jAlpha, jBeta)
	wantRefusals(t, "the judge", judgeTransition(from, to))
	s := newStore(t)
	noteKnown(t, s, storeZone, from)
	enforced(t, s, storeZone)
	if err := s.update(storeZone, func(z *zoneSerials) error {
		z.Removals = []Removal{{Label: "charlie", Identity: "agent.charlie.example.", Step: 2}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	noteKnown(t, s, storeZone, to)
	if st := status(t, s, storeZone); len(st.Refused) != 0 || *st.Newest != sd(to) || st.Phase != PhaseReconciling {
		t.Errorf("newest %s refused %v phase %s; want 42 held, agreed, reconciling", serialOf(st.Newest), st.Refused, st.Phase)
	}
	// the provider keeps the identity of the last serial that listed it
	if r, ok := s.removal(storeZone, "charlie", ""); !ok || r.Identity != "agent.charlie.example." {
		t.Errorf("the removal under way: %v %v", r, ok)
	}
}

func TestTheJudgeIsAFunctionOfTwoSerials(t *testing.T) {
	from := jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie)
	between := jAt(t, 42, jServers3+` suffix="mp"`, jAlpha, jBeta, jCharlie)
	to := jAt(t, 43, jServers3, jAlpha, jBeta)
	want := judgeTransition(from, to)
	if len(want) == 0 {
		t.Fatal("43 is agreed against 41")
	}
	wantRefusals(t, "judged again", judgeTransition(from, to), want...)

	// Two agents, one of which holds another serial and a removal as well:
	// the same pair, the same refusal.
	plain := newStore(t)
	noteKnown(t, plain, storeZone, from)
	enforced(t, plain, storeZone)
	noteKnown(t, plain, storeZone, to)
	busy := newStore(t)
	noteKnown(t, busy, storeZone, from)
	enforced(t, busy, storeZone)
	if err := busy.update(storeZone, func(z *zoneSerials) error {
		z.Removals = []Removal{{Label: "delta", Identity: "agent.delta.example.", Step: 1}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	noteKnown(t, busy, storeZone, between)
	noteKnown(t, busy, storeZone, to)
	wantRefusals(t, "an agent with nothing else", heldAt(t, plain, 43).Refused, want...)
	wantRefusals(t, "an agent with more held", heldAt(t, busy, 43).Refused, want...)
}

func TestAMemberThatMovesStraightIsJudgedOnTheThawsPair(t *testing.T) {
	forty := jAt(t, 40, jServers3, jAlpha, jBeta, jCharlie)
	fortyOne := jAt(t, 41, jServers2, jAlpha, jBeta, jCharlie) // takes charlie's role
	fortyTwo := jAt(t, 42, jServers2+` suffix="mp"`, jAlpha, jBeta, jCharlie)
	s := newStore(t)
	noteKnown(t, s, storeZone, forty)
	enforced(t, s, storeZone)
	noteKnown(t, s, storeZone, fortyOne)
	noteKnown(t, s, storeZone, fortyTwo)
	if len(heldAt(t, s, 42).Refused) == 0 {
		t.Fatal("42 is agreed against this member's active 40")
	}
	if err := s.Activate(storeZone, Thaw{From: sd(forty), To: sd(fortyTwo)}); err == nil {
		t.Fatal("a thaw from 40 activated 42, which the judge refuses against 40")
	}
	// The thaw is from 41 to 42: this member, behind at 40, judges that pair.
	if err := s.Activate(storeZone, Thaw{From: sd(fortyOne), To: sd(fortyTwo)}); err != nil {
		t.Fatalf("the thaw 41 -> 42: %v", err)
	}
	if st := status(t, s, storeZone); *st.Active != sd(fortyTwo) || *st.From != sd(fortyOne) {
		t.Errorf("active %s from %s; want 42 from 41", serialOf(st.Active), serialOf(st.From))
	}
}

func TestARoleForALabelWithoutARecordIsRefused(t *testing.T) {
	got := judgeTransition(jAt(t, 41, jServers2, jAlpha, jBeta), jAt(t, 42, jServers3, jAlpha, jBeta, jCharlie))
	if len(got) == 0 || got[0] != (Refusal{RefusedRoleWithoutRecord, "gives a role to agent.charlie.example., which has no record under 41"}) {
		t.Errorf("a record and its role in one edit: %v", got)
	}
	got = judgeTransition(jAt(t, 41, jServers2, jAlpha, jBeta, jCharlie), jAt(t, 42, jServers3, jAlpha, jBeta))
	if len(got) == 0 || got[0] != (Refusal{RefusedRoleWithoutRecord, "gives a role to agent.charlie.example., whose record it removes"}) {
		t.Errorf("a role given in the edit that removes the record: %v", got)
	}
}

func TestAnIdentityChangeUnderALabelWithARoleIsRefused(t *testing.T) {
	from := jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie)
	wantRefusals(t, "another identity", judgeTransition(from, jAt(t, 42, jServers3, jAlpha, jBeta, `3600 IN HSYNC3 ON charlie agent.other.example. .`)),
		Refusal{RefusedIdentityChanged, "changes the identity under charlie, which has a role, from agent.charlie.example. to agent.other.example."})
	wantRefusals(t, "the identity in other case", judgeTransition(from, jAt(t, 42, jServers3, jAlpha, jBeta, `3600 IN HSYNC3 ON charlie Agent.CHARLIE.example. .`)))
}

func TestAnIdentityChangeUnderALabelWithNoRoleIsAgreed(t *testing.T) {
	wantRefusals(t, "charlie has no role", judgeTransition(jAt(t, 41, jServers2, jAlpha, jBeta, jCharlie),
		jAt(t, 42, jServers2, jAlpha, jBeta, `3600 IN HSYNC3 ON charlie agent.other.example. .`)))
}

func TestASignerMovedToServersOnlyIsRefused(t *testing.T) {
	got := judgeTransition(jAt(t, 41, `servers="alpha,beta,charlie" signers="alpha,charlie"`, jAlpha, jBeta, jCharlie),
		jAt(t, 42, jServers3, jAlpha, jBeta, jCharlie))
	if len(got) == 0 || got[0] != (Refusal{RefusedSignerToServer, "moves the signer agent.charlie.example. to servers= only"}) {
		t.Errorf("charlie moved to servers= only: %v", got)
	}
}

func TestASignerLeavingBothListsWithItsRecordKeptIsAgreed(t *testing.T) {
	from := jAt(t, 41, `servers="alpha,beta,charlie" signers="alpha,charlie"`, jAlpha, jBeta, jCharlie)
	to := jAt(t, 42, jServers2, jAlpha, jBeta, jCharlie)
	// nothing refuses it but that its steps are not built (S17b)
	wantRefusals(t, "before S17b", judgeTransition(from, to), Refusal{RefusedNotBuilt, "takes a role from agent.charlie.example.: not built yet"})
	wantRefusals(t, "once S17b has built it", judge(from, to, builtKinds|kindRolesTaken, carriedKinds))
}

func TestEmptyingSignersIsRefused(t *testing.T) {
	hasRefusal(t, "signers= emptied", judgeTransition(jAt(t, 41, `servers="alpha,charlie" signers="alpha"`, jAlpha, jCharlie),
		jAt(t, 42, `servers="alpha,charlie"`, jAlpha, jCharlie)),
		Refusal{RefusedSignersEmptied, "empties signers=, which lists alpha under 41"})
}

func TestAnUpstreamThatNamesNoSignerIsRefused(t *testing.T) {
	hasRefusal(t, "beta's upstream charlie", judgeTransition(jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie),
		jAt(t, 42, jServers3, jAlpha, `3600 IN HSYNC3 ON beta agent.beta.example. charlie`, jCharlie)),
		Refusal{RefusedUpstreamDangling, "the upstream of agent.beta.example. names charlie, which is not in signers= under 42"})
}

func TestAnUpstreamThatNamesALabelWithoutARecordIsRefused(t *testing.T) {
	param, delta := `servers="alpha,beta" signers="alpha,delta"`, `3600 IN HSYNC3 OFF delta agent.delta.example. .`
	hasRefusal(t, "beta's upstream delta, OFF", judgeTransition(jAt(t, 41, param, jAlpha, jBeta, delta),
		jAt(t, 42, param, jAlpha, `3600 IN HSYNC3 ON beta agent.beta.example. delta`, delta)),
		Refusal{RefusedUpstreamDangling, "the upstream of agent.beta.example. names delta, which has no record under 42"})
}

func TestRemovingASignerThatIsARemainingServersUpstreamIsRefused(t *testing.T) {
	hasRefusal(t, "alpha out of signers=", judgeTransition(jAt(t, 41, `servers="alpha,beta,charlie" signers="alpha,charlie"`, jAlpha, jBeta, jCharlie),
		jAt(t, 42, `servers="beta,charlie" signers="charlie"`, jAlpha, jBeta, jCharlie)),
		Refusal{RefusedUpstreamSignerRemoved, "takes agent.alpha.example. out of signers=, while it is the upstream of the server agent.beta.example. under 41"})
}

func TestAnUpstreamChangeIsRefusedUntilItsStepExists(t *testing.T) {
	param := `servers="alpha,beta,charlie" signers="alpha,charlie"`
	from := jAt(t, 41, param, jAlpha, jBeta, jCharlie)
	to := jAt(t, 42, param, jAlpha, `3600 IN HSYNC3 ON beta agent.beta.example. charlie`, jCharlie)
	wantRefusals(t, "now", judgeTransition(from, to), Refusal{RefusedStepMissing, "changes the upstream of agent.beta.example., a step that cannot be carried out yet"})
	wantRefusals(t, "its check exists", judge(from, to, builtKinds, carriedKinds|kindUpstream), Refusal{RefusedNotBuilt, "changes the upstream of agent.beta.example.: not built yet"})
	wantRefusals(t, "S21", judge(from, to, builtKinds|kindUpstream, carriedKinds|kindUpstream))
}

func TestAMoveIntoSignersIsRefusedUntilItsStepExists(t *testing.T) {
	from := jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie)
	to := jAt(t, 42, `servers="alpha,beta,charlie" signers="alpha,charlie"`, jAlpha, jBeta, jCharlie)
	wantRefusals(t, "now", judgeTransition(from, to), Refusal{RefusedStepMissing, "moves agent.charlie.example. into signers=, a step that cannot be carried out yet"})
	wantRefusals(t, "P5", judge(from, to, builtKinds, carriedKinds|kindSignerRole), Refusal{RefusedNotBuilt, "moves agent.charlie.example. into signers=: not built yet"})
	wantRefusals(t, "S18b", judge(from, to, builtKinds|kindSignerRole, carriedKinds|kindSignerRole))
}

func TestAKindWithoutItsStepsIsRefused(t *testing.T) {
	from := jAt(t, 41, jServers2, jAlpha, jBeta, jCharlie)
	for _, c := range []struct{ param, reason string }{
		{jServers2 + ` nsmgmt="agent"`, "changes nsmgmt"},
		{jServers2 + ` parentsync="agent"`, "changes parentsync"},
		{jServers2 + ` pubkey`, "changes pubkey"},
		{jServers2 + ` pubcds`, "changes pubcds"},
		{`servers="alpha" signers="alpha"`, "takes a role from agent.beta.example."},
	} {
		to := jAt(t, 42, c.param, jAlpha, jBeta, jCharlie)
		wantRefusals(t, c.reason, judgeTransition(from, to), Refusal{RefusedNotBuilt, c.reason + ": not built yet"})
		wantRefusals(t, c.reason+", once built", judge(from, to, allKinds, allKinds))
	}
	// the auditors and the suffix: nothing to carry out (design 5.6)
	wantRefusals(t, "auditors and suffix", judgeTransition(from, jAt(t, 42, jServers2+` auditors="charlie" suffix="mp"`, jAlpha, jBeta, jCharlie)))
}

func TestARefusedSerialLeavesTheZoneSteady(t *testing.T) {
	from, to := jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie), jAt(t, 42, jServers3, jAlpha, jBeta)
	s := newStore(t)
	noteKnown(t, s, storeZone, from)
	enforced(t, s, storeZone)
	noteKnown(t, s, storeZone, to)
	st := status(t, s, storeZone)
	if *st.Active != sd(from) || *st.Newest != sd(to) || st.Agreeing != nil || len(st.Refused) != 1 || st.Phase != PhaseRefused {
		t.Fatalf("active %s newest %s agreeing %s refused %v phase %s; want 41, 42, none, refused",
			serialOf(st.Active), serialOf(st.Newest), serialOf(st.Agreeing), st.Refused, st.Phase)
	}
	if err := s.Activate(storeZone, Thaw{From: sd(from), To: sd(to)}); err == nil {
		t.Error("a refused serial was activated")
	}
	// steady, not frozen: the forget command takes it
	if err := s.Forget(storeZone); err != nil {
		t.Errorf("forget: %v", err)
	}
}

func TestANewerSafeSerialReplacesARefusedOne(t *testing.T) {
	from := jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie)
	refused := jAt(t, 42, jServers3, jAlpha, jBeta)
	safe := jAt(t, 43, jServers3+` suffix="mp"`, jAlpha, jBeta, jCharlie)
	s := newStore(t)
	noteKnown(t, s, storeZone, from)
	enforced(t, s, storeZone)
	noteKnown(t, s, storeZone, refused)
	noteKnown(t, s, storeZone, safe)
	st := status(t, s, storeZone)
	if *st.Newest != sd(safe) || st.Agreeing == nil || *st.Agreeing != sd(safe) || len(st.Refused) != 0 || st.Phase != PhaseAgreeing {
		t.Fatalf("newest %s agreeing %s refused %v phase %s; want 43, 43, none, agreeing",
			serialOf(st.Newest), serialOf(st.Agreeing), st.Refused, st.Phase)
	}
	if len(heldAt(t, s, 42).Refused) == 0 {
		t.Error("42 is no longer refused")
	}
	if err := s.Activate(storeZone, Thaw{From: sd(from), To: sd(safe)}); err != nil {
		t.Errorf("the thaw to 43: %v", err)
	}
}

func TestARefusedSerialIsJudgedAgainWhenTheActiveSerialChanges(t *testing.T) {
	// The owner publishes a record, and then its role before the first is
	// thawed (design 3.1): neither is lost.
	from := jAt(t, 41, jServers2, jAlpha, jBeta)
	record := jAt(t, 42, jServers2, jAlpha, jBeta, jCharlie)
	role := jAt(t, 43, jServers3, jAlpha, jBeta, jCharlie)
	s := newStore(t)
	noteKnown(t, s, storeZone, from)
	enforced(t, s, storeZone)
	noteKnown(t, s, storeZone, record)
	noteKnown(t, s, storeZone, role)
	if got := heldAt(t, s, 43).Refused; len(got) == 0 || got[0].Code != RefusedRoleWithoutRecord {
		t.Fatalf("43 against 41: %v", got)
	}
	if err := s.Activate(storeZone, Thaw{From: sd(from), To: sd(record)}); err != nil {
		t.Fatal(err)
	}
	// a role for a provider with a record: built (S18a)
	wantRefusals(t, "43 against 42", heldAt(t, s, 43).Refused)
}

func TestAnEditWithoutARaisedSerialIsAnOwnerError(t *testing.T) {
	first, second := jAt(t, 42, jServers3, jAlpha, jBeta, jCharlie), jAt(t, 42, jServers3+` suffix="mp"`, jAlpha, jBeta, jCharlie)
	s := newStore(t)
	noteKnown(t, s, storeZone, first)
	noteKnown(t, s, storeZone, second)
	want := fmt.Sprintf("held: owner error: serial 42 with two digests (%s, %s)", first.Digest(), second.Digest())
	if got := status(t, s, storeZone).Line(); got != want {
		t.Errorf("from S7:\n got %q\nwant %q", got, want)
	}
}

func TestTheOwnerErrorEndsAtAHigherSerialOnly(t *testing.T) {
	first := jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie)
	s := newStore(t)
	noteKnown(t, s, storeZone, first)
	enforced(t, s, storeZone)
	noteKnown(t, s, storeZone, jAt(t, 41, jServers3+` suffix="mp"`, jAlpha, jBeta, jCharlie))
	noteKnown(t, s, storeZone, jAt(t, 40, jServers3, jAlpha, jBeta, jCharlie))
	if st := status(t, s, storeZone); st.Phase != PhaseOwnerError {
		t.Fatalf("a lower serial ended the owner error: phase %s", st.Phase)
	}
	// a higher serial ends it, and is judged against the active one
	noteKnown(t, s, storeZone, jAt(t, 42, jServers3, jAlpha, jBeta))
	if st := status(t, s, storeZone); st.OwnerError != "" || st.Phase != PhaseRefused || st.Newest.Serial != 42 {
		t.Errorf("after 42: error %q phase %s newest %s; want none, refused, 42", st.OwnerError, st.Phase, serialOf(st.Newest))
	}
}

func TestRevertedContentsAtTheSameSerialDoNotEndTheOwnerError(t *testing.T) {
	first := jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie)
	s := newStore(t)
	noteKnown(t, s, storeZone, first)
	noteKnown(t, s, storeZone, jAt(t, 41, jServers3+` suffix="mp"`, jAlpha, jBeta, jCharlie))
	noteKnown(t, s, storeZone, first)
	if line := status(t, s, storeZone).Line(); !strings.HasPrefix(line, "held: owner error: serial 41 with two digests") {
		t.Errorf("reverted at 41: %q", line)
	}
}

func TestEveryAgentGivesTheSameReason(t *testing.T) {
	// several reasons; the second agent's copy lists records and roles in
	// another order
	from := jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie)
	to := jAt(t, 42, `servers="alpha,beta" signers="alpha" nsmgmt="agent"`, jAlpha, `3600 IN HSYNC3 ON beta agent.beta.example. charlie`)
	fromRev := jAt(t, 41, `signers="alpha" servers="charlie,beta,alpha"`, jCharlie, jBeta, jAlpha)
	toRev := jAt(t, 42, `nsmgmt="agent" signers="alpha" servers="beta,alpha"`, `3600 IN HSYNC3 ON beta agent.beta.example. charlie`, jAlpha)
	one, other := newStore(t), newStore(t)
	for _, c := range []struct {
		s        *InstructionStore
		from, to *Instructions
	}{{one, from, to}, {other, fromRev, toRev}} {
		noteKnown(t, c.s, storeZone, c.from)
		enforced(t, c.s, storeZone)
		noteKnown(t, c.s, storeZone, c.to)
	}
	a, b := heldAt(t, one, 42).Refused, heldAt(t, other, 42).Refused
	if len(a) < 3 {
		t.Fatalf("refusals %v; want several", a)
	}
	wantRefusals(t, "the other agent", b, a...)
	if la, lb := status(t, one, storeZone).Line(), status(t, other, storeZone).Line(); la != lb {
		t.Errorf("status lines differ:\n%q\n%q", la, lb)
	}
}

// Shown in the status, in mplist and in the auditor's config errors.
func TestARefusalIsShownInTheStatusMplistAndTheAuditor(t *testing.T) {
	const name = "refused.judge.example."
	from := jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie)
	toRecords := []string{jAlpha, jBeta, `3600 IN HSYNCPARAM serial="42" ` + jServers3}
	to := readOf(t, toRecords...)
	mpzd := instrTestZone(t, name, toRecords...)
	s := newStore(t)
	withStore(t, s)
	noteKnown(t, s, name, from)
	enforced(t, s, name)
	noteKnown(t, s, name, to)
	const want = "42 refused: removes the record of agent.charlie.example., which has a role under 41"
	if got, line := s.Status(name).Line(), fmt.Sprintf("%s; active 41 (%s), newest 42 (%s), copy 42", want, from.Digest(), to.Digest()); got != line {
		t.Errorf("status:\n got %q\nwant %q", got, line)
	}
	var info MPZoneInfo
	s.fillMPZoneInfo(name, &info)
	if info.Refused != want {
		t.Errorf("mplist: %q", info.Refused)
	}
	if errs := checkMPZoneHSYNCConfig(mpzd); len(errs) == 0 || errs[0] != want {
		t.Errorf("the auditor's config errors: %q", errs)
	}
}

// From S7 a refused serial is held and shown, and the active serial stays:
// the zone is steady, not frozen (design 3.6).
func TestARefusalIsShownAndEnforced(t *testing.T) {
	from, to := jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie), jAt(t, 42, jServers3, jAlpha, jBeta)
	s := newStore(t)
	noteKnown(t, s, storeZone, from)
	noteKnown(t, s, storeZone, to)
	st := status(t, s, storeZone)
	want := fmt.Sprintf("42 refused: removes the record of agent.charlie.example., which has a role under 41; active 41 (%s), newest 42 (%s), copy 42", from.Digest(), to.Digest())
	if *st.Active != sd(from) || st.Phase != PhaseRefused || st.Line() != want || len(s.frozen(storeZone)) > 0 {
		t.Errorf("active %s phase %s status %q frozen %v; want 41, refused,\n%q", serialOf(st.Active), st.Phase, st.Line(), s.frozen(storeZone), want)
	}
}

func TestARefusalIsLoggedOncePerZoneAndSerial(t *testing.T) {
	logs := captureZonesLog(t)
	from := jAt(t, 41, jServers3, jAlpha, jBeta, jCharlie)
	safe := jAt(t, 42, jServers3+` suffix="mp"`, jAlpha, jBeta, jCharlie)
	refused := jAt(t, 43, jServers3, jAlpha, jBeta)
	s := newStore(t)
	noteKnown(t, s, storeZone, from)
	enforced(t, s, storeZone)
	noteKnown(t, s, storeZone, safe)
	noteKnown(t, s, storeZone, refused)
	noteKnown(t, s, storeZone, refused)
	if err := s.Activate(storeZone, Thaw{From: sd(from), To: sd(safe)}); err != nil { // 43 is judged again
		t.Fatal(err)
	}
	out := logs.String()
	if n := strings.Count(out, "a change of the zone's instructions is refused"); n != 1 {
		t.Fatalf("%d log lines, want 1:\n%s", n, out)
	}
	for _, f := range []string{`"level":"WARN"`, `"zone":"` + storeZone + `"`, `"from":41`, `"to":43`, `"reason":"removes the record of agent.charlie.example., which has a role under 41"`} {
		if !strings.Contains(out, f) {
			t.Errorf("the log line lacks %s:\n%s", f, out)
		}
	}
}
