/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Stamps in beats (plan S5a).
 */
package tdnsmp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

const (
	stampZone  = "stamp.example."
	stampAlpha = "agent.alpha.example."
	stampBeta  = "agent.beta.example."
	stampDelta = "agent.delta.example." // an auditor: a member that does not vote
	stampOmega = "agent.omega.example." // not listed
)

// stampRecords are alpha (a signer and a server), beta (a server) and delta
// (an auditor).
var stampRecords = []string{
	`3600 IN HSYNC3 ON alpha agent.alpha.example. .`,
	`3600 IN HSYNC3 ON beta agent.beta.example. alpha`,
	`3600 IN HSYNC3 ON delta agent.delta.example. .`,
}

// stampAt is the zone's instructions at serial; suffix tells two copies of
// one serial apart, as an edit without a raised serial does.
func stampAt(t *testing.T, serial uint32, suffix string) *Instructions {
	t.Helper()
	return jAt(t, serial, fmt.Sprintf(`servers="alpha,beta" signers="alpha" auditors="delta" suffix="%s"`, suffix), stampRecords...)
}

// stampTableAt is local's stamp table, with a store of its own that holds
// the zone at in.
func stampTableAt(t *testing.T, local string, in *Instructions) *stampTable {
	t.Helper()
	s := newStore(t)
	s.Note(stampZone, in, nil)
	return newStampTable(local, s, 1, true, []string{"ns1." + local})
}

// told is a stamp entry from sender: its own row, with st for the zone.
func told(sender string, epoch, seq uint64, st InstrStamp) *GossipMessage {
	return &GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
		sender: {Identity: sender, Timestamp: time.Now(), Epoch: epoch, Seq: seq, Crypto: true, Instr: map[string]InstrStamp{stampZone: st}}}}
}

// tells is the stamp of a member at active and newest.
func tells(active, newest *Instructions) InstrStamp {
	return InstrStamp{Known: true, Active: active.Serial, ActiveDigest: active.Digest(), Newest: newest.Serial, NewestDigest: newest.Digest()}
}

// rowFor is the status row of id.
func rowFor(t *testing.T, rows []MemberInstructions, id string) MemberInstructions {
	t.Helper()
	for _, r := range rows {
		if r.Identity == id {
			return r
		}
	}
	t.Fatalf("no row for %s in %+v", id, rows)
	return MemberInstructions{}
}

// A beat to a peer tells every zone the two share, and only those.
func TestAStampIsToldForEveryZoneTheTwoShare(t *testing.T) {
	st := stampTableAt(t, stampAlpha, stampAt(t, 7, "a"))
	other := stampAt(t, 3, "a")
	st.store.Note("other.example.", other, nil)
	// a zone alpha has no role in
	st.store.Note("elsewhere.example.", jAt(t, 4, `servers="beta"`, stampRecords[1]), nil)
	e := st.entryFor(stampBeta)
	if e == nil {
		t.Fatal("no stamp entry for beta")
	}
	zones := slices.Sorted(func(yield func(string) bool) {
		for z := range e.Members[stampAlpha].Instr {
			if !yield(z) {
				return
			}
		}
	})
	if want := []string{"other.example.", stampZone}; !slices.Equal(zones, want) {
		t.Errorf("zones told to beta: %v, want %v", zones, want)
	}
	if st.entryFor(stampOmega) != nil {
		t.Error("a stamp entry for an agent that shares no zone")
	}
}

// A zone is shared when both are listed under the active or the newest serial.
func TestAStampIsToldUnderEitherSerial(t *testing.T) {
	seven := stampAt(t, 7, "a")
	st := stampTableAt(t, stampAlpha, seven)
	enforced(t, st.store, stampZone)
	// at 8 omega is listed with a role: alpha tells omega under its newest
	eight := jAt(t, 8, `servers="alpha,beta,omega" signers="alpha" auditors="delta" suffix="a"`,
		append(slices.Clone(stampRecords), `3600 IN HSYNC3 ON omega agent.omega.example. alpha`)...)
	st.store.Note(stampZone, eight, nil)
	e := st.entryFor(stampOmega)
	if e == nil {
		t.Fatal("no stamp for a member under the newest serial only")
	}
	got := e.Members[stampAlpha].Instr[stampZone]
	if got.Active != 7 || got.Newest != 8 || got.ActiveDigest != seven.Digest() || got.NewestDigest != eight.Digest() {
		t.Errorf("the stamp: %+v", got)
	}
}

// The stamp entry has the reserved hash and one row, the sender's, whose sequence rises.
func TestTheStampEntryCarriesOnlyTheSendersRow(t *testing.T) {
	st := stampTableAt(t, stampAlpha, stampAt(t, 7, "a"))
	e := st.entryFor(stampBeta)
	if e.GroupHash != stampGroupHash || len(e.Members) != 1 || e.Members[stampAlpha] == nil {
		t.Fatalf("the stamp entry: %+v", e)
	}
	row := e.Members[stampAlpha]
	if row.Identity != stampAlpha || row.Epoch != 1 || row.Seq == 0 {
		t.Errorf("the row: %+v", row)
	}
	if next := st.entryFor(stampBeta).Members[stampAlpha]; next.Seq <= row.Seq {
		t.Errorf("the sequence did not rise: %d then %d", row.Seq, next.Seq)
	}
}

// The stamp entry is noted where a beat arrives and merged into no group:
// MergeGossip takes nothing for it, and neither does the engine's merge.
func TestTheStampEntryIsNotMergedAsAGroup(t *testing.T) {
	gst := NewGossipStateTable(stampBeta)
	e := stampTableAt(t, stampAlpha, stampAt(t, 7, "a")).entryFor(stampBeta)
	gst.MergeGossip(e, stampAlpha, nil, false)
	gst.mu.RLock()
	defer gst.mu.RUnlock()
	if _, ok := gst.States[stampGroupHash]; ok {
		t.Error("the stamp entry was merged as a group")
	}
}

// A stamp from a beat is noted as its sender's, with the beat's mechanism.
func TestAStampFromABeatIsFirstHand(t *testing.T) {
	seven := stampAt(t, 7, "a")
	bob := stampTableAt(t, stampBeta, seven)
	bob.note(stampTableAt(t, stampAlpha, seven).entryFor(stampBeta), stampAlpha, "DNS")
	m := bob.heard(stampAlpha)
	if m == nil || m.Instr[stampZone].Active != 7 || m.Mechanism != "DNS" || !m.Enveloped {
		t.Fatalf("alice's stamp, heard: %+v", m)
	}
}

// Only the row of the transport's sender is noted, its name in any case.
func TestARowWhoseIdentityIsNotTheSenderIsNotNoted(t *testing.T) {
	seven := stampAt(t, 7, "a")
	bob := stampTableAt(t, stampBeta, seven)
	// alice's entry, as if delta passed it on
	bob.note(stampTableAt(t, stampAlpha, seven).entryFor(stampBeta), stampDelta, "DNS")
	if bob.heard(stampAlpha) != nil || bob.heard(stampDelta) != nil {
		t.Error("a row that is not its sender's was noted")
	}
	// a row under the sender's key that names another identity
	msg := told(stampAlpha, 1, 1, tells(seven, seven))
	msg.Members[stampAlpha].Identity = stampDelta
	bob.note(msg, stampAlpha, "DNS")
	if bob.heard(stampAlpha) != nil {
		t.Error("a row naming another identity was noted")
	}
	// the sender's own row, its name in another case
	bob.note(told("Agent.Alpha.Example.", 1, 1, tells(seven, seven)), stampAlpha, "DNS")
	if bob.heard(stampAlpha) == nil {
		t.Error("the sender's own row in another case was not noted")
	}
}

// Within an epoch only a higher sequence replaces a stamp; an earlier epoch never does.
func TestAnOlderSeqDoesNotReplaceANewerStamp(t *testing.T) {
	seven, eight := stampAt(t, 7, "a"), stampAt(t, 8, "a")
	bob := stampTableAt(t, stampBeta, seven)
	bob.note(told(stampAlpha, 5, 10, tells(eight, eight)), stampAlpha, "DNS")
	bob.note(told(stampAlpha, 5, 9, tells(seven, seven)), stampAlpha, "DNS")
	bob.note(told(stampAlpha, 5, 10, tells(seven, seven)), stampAlpha, "DNS")
	if got := bob.heard(stampAlpha).Instr[stampZone].Active; got != 8 {
		t.Errorf("an older or the same sequence replaced the stamp: active %d", got)
	}
	bob.note(told(stampAlpha, 4, 99, tells(seven, seven)), stampAlpha, "DNS")
	if got := bob.heard(stampAlpha).Instr[stampZone].Active; got != 8 {
		t.Errorf("a stamp from an earlier start replaced the stamp: active %d", got)
	}
}

// A higher epoch, a later start, replaces everything kept of the member.
func TestANewEpochReplacesAPeersStamps(t *testing.T) {
	seven, eight := stampAt(t, 7, "a"), stampAt(t, 8, "a")
	bob := stampTableAt(t, stampBeta, seven)
	two := told(stampAlpha, 5, 40, tells(eight, eight))
	two.Members[stampAlpha].Instr["other.example."] = tells(seven, seven)
	bob.note(two, stampAlpha, "DNS")
	// alice restarted: its first stamp, at sequence 1, tells one zone
	bob.note(told(stampAlpha, 6, 1, tells(seven, seven)), stampAlpha, "API")
	m := bob.heard(stampAlpha)
	if m.Epoch != 6 || m.Instr[stampZone].Active != 7 || len(m.Instr) != 1 || m.Mechanism != "API" || m.Enveloped {
		t.Errorf("after a new epoch: %+v", m)
	}
}

// The epoch rises at every start, whatever the clock does, and starts at the clock after a wipe.
func TestTheEpochIsACounterThatSurvivesARestart(t *testing.T) {
	path, hdb := storeDB(t)
	at := time.Unix(1_000_000, 0)
	first, err := loadStore(t, hdb).RaiseEpoch(at)
	if err != nil || first != 1_000_000_000 {
		t.Fatalf("the first epoch: %d %v, want the clock's milliseconds", first, err)
	}
	// a restart within the millisecond, then one whose clock ran backwards
	for i, now := range []time.Time{at, at.Add(-time.Hour)} {
		e, err := loadStore(t, openStoreDB(t, path)).RaiseEpoch(now)
		if err != nil || e != first+uint64(i)+1 {
			t.Errorf("restart %d: epoch %d %v, want %d", i+1, e, err, first+uint64(i)+1)
		}
	}
	// a wiped database starts at the clock, above what its peers hold, even
	// a second after those restarts
	_, wiped := storeDB(t)
	if e, err := loadStore(t, wiped).RaiseEpoch(at.Add(time.Second)); err != nil || e <= first+2 {
		t.Errorf("after a wipe: epoch %d %v", e, err)
	}
}

// A voting member's other digest for this agent's serial is an owner error, ended by a higher serial.
func TestAVotingPeersOtherDigestAtTheSameSerialIsAnOwnerError(t *testing.T) {
	sevenA, sevenB := stampAt(t, 7, "a"), stampAt(t, 7, "b")
	bob := stampTableAt(t, stampBeta, sevenA)
	bob.note(told(stampAlpha, 1, 1, tells(sevenB, sevenB)), stampAlpha, "DNS")
	st := status(t, bob.store, stampZone)
	want := fmt.Sprintf("serial 7 told with two digests (%s)", strings.Join(slices.Sorted(slices.Values([]string{sevenA.Digest(), sevenB.Digest()})), ", "))
	if st.Phase != PhaseOwnerError || st.OwnerError != want {
		t.Fatalf("phase %s, owner error %q; want %q", st.Phase, st.OwnerError, want)
	}
	// it ends at a higher serial only
	bob.store.Note(stampZone, stampAt(t, 8, "a"), nil)
	if st := status(t, bob.store, stampZone); st.OwnerError != "" {
		t.Errorf("after serial 8: %q", st.OwnerError)
	}
	// alice still tells 7 with its digest: below the highest held, passed
	bob.note(told(stampAlpha, 1, 2, tells(sevenB, sevenB)), stampAlpha, "DNS")
	if st := status(t, bob.store, stampZone); st.OwnerError != "" {
		t.Errorf("a conflict below the highest held was marked again: %q", st.OwnerError)
	}
}

// Two voting members that tell one serial with two digests, a serial this
// agent does not hold yet, are an owner error here too.
func TestTwoVotingPeersTellingOneSerialWithTwoDigestsIsAnOwnerError(t *testing.T) {
	delta := stampTableAt(t, stampDelta, stampAt(t, 7, "a"))
	eightA, eightB := stampAt(t, 8, "a"), stampAt(t, 8, "b")
	delta.note(told(stampAlpha, 1, 1, tells(eightA, eightA)), stampAlpha, "DNS")
	if st := status(t, delta.store, stampZone); st.OwnerError != "" {
		t.Fatalf("one member's newer serial: %q", st.OwnerError)
	}
	delta.note(told(stampBeta, 1, 1, tells(eightB, eightB)), stampBeta, "DNS")
	if st := status(t, delta.store, stampZone); st.Phase != PhaseOwnerError || !strings.HasPrefix(st.OwnerError, "serial 8 told with two digests") {
		t.Errorf("phase %s, owner error %q", st.Phase, st.OwnerError)
	}
}

// An auditor's other digest is shown, and holds nothing.
func TestADigestConflictFromAMemberThatDoesNotVoteHoldsNothing(t *testing.T) {
	sevenA, sevenB := stampAt(t, 7, "a"), stampAt(t, 7, "b")
	bob := stampTableAt(t, stampBeta, sevenA)
	bob.note(told(stampDelta, 1, 1, tells(sevenB, sevenB)), stampDelta, "DNS")
	if st := status(t, bob.store, stampZone); st.Phase != PhaseSteady || st.OwnerError != "" {
		t.Errorf("an auditor's other digest held the zone: phase %s, %q", st.Phase, st.OwnerError)
	}
	row := rowFor(t, bob.members(stampZone), stampDelta)
	if row.OtherDigest == nil || *row.OtherDigest != 7 {
		t.Errorf("the auditor's other digest is not shown: %+v", row)
	}
}

// The stamp tells the judge's refusal of the newest serial, and the serial agreed on.
func TestTheStampCarriesARefusal(t *testing.T) {
	seven := stampAt(t, 7, "a")
	st := stampTableAt(t, stampAlpha, seven)
	enforced(t, st.store, stampZone)
	// beta moved out of servers= with its record kept: taking a role away
	eight := jAt(t, 8, `servers="alpha" signers="alpha" auditors="delta" suffix="a"`, stampRecords...)
	st.store.Note(stampZone, eight, nil)
	got := st.entryFor(stampBeta).Members[stampAlpha].Instr[stampZone]
	if got.Refused != "not-built" || got.Newest != 8 || got.AgreeingDigest != "" {
		t.Errorf("the stamp of a refused newest serial: %+v", got)
	}
	nine := stampAt(t, 9, "z")
	st.store.Note(stampZone, nine, nil)
	got = st.entryFor(stampBeta).Members[stampAlpha].Instr[stampZone]
	if got.Agreeing != 9 || got.AgreeingDigest != nine.Digest() || got.Refused != "" {
		t.Errorf("the stamp with an accepted newest serial: %+v", got)
	}
}

// The status marks the member behind the others.
func TestTheStatusSaysWhichPeerLags(t *testing.T) {
	seven, eight := stampAt(t, 7, "a"), stampAt(t, 8, "a")
	alpha := stampTableAt(t, stampAlpha, eight)
	alpha.note(told(stampBeta, 1, 1, tells(seven, seven)), stampBeta, "DNS")
	alpha.note(told(stampDelta, 1, 1, tells(eight, eight)), stampDelta, "API")
	rows := alpha.members(stampZone)
	if len(rows) != 3 || !rows[0].Self || rows[0].Identity != stampAlpha {
		t.Fatalf("rows: %+v", rows)
	}
	if !rowFor(t, rows, stampBeta).Lags {
		t.Error("beta, at 7, does not lag")
	}
	if rowFor(t, rows, stampAlpha).Lags || rowFor(t, rows, stampDelta).Lags {
		t.Error("a member at 8 lags")
	}
}

// The status names a member whose newest serial no other member holds.
func TestAMemberTellingASerialNobodyHoldsIsNamed(t *testing.T) {
	seven, eight := stampAt(t, 7, "a"), stampAt(t, 8, "a")
	alpha := stampTableAt(t, stampAlpha, seven)
	alpha.note(told(stampBeta, 1, 1, tells(seven, eight)), stampBeta, "DNS")
	alpha.note(told(stampDelta, 1, 1, tells(seven, seven)), stampDelta, "DNS")
	rows := alpha.members(stampZone)
	if r := rowFor(t, rows, stampBeta); !r.Alone || r.Lags {
		t.Errorf("beta tells 8, which nobody else holds: %+v", r)
	}
	if r := rowFor(t, rows, stampDelta); r.Alone || !r.Lags {
		t.Errorf("delta: %+v", r)
	}
}

// A newer serial told is fetched at once, then once a minute while behind.
func TestHearingANewerSerialFetchesOncePerSerialAndMinute(t *testing.T) {
	seven, eight, nine := stampAt(t, 7, "a"), stampAt(t, 8, "a"), stampAt(t, 9, "a")
	bob := stampTableAt(t, stampBeta, seven)
	var fetched []string
	bob.fetch = func(zone string) (string, bool) {
		fetched = append(fetched, zone)
		return zone, true
	}
	seq := uint64(0)
	hear := func(from string, in *Instructions) {
		seq++
		bob.note(told(from, 1, seq, tells(seven, in)), from, "DNS")
	}
	hear(stampAlpha, seven)
	if len(fetched) != 0 {
		t.Fatalf("a serial this agent holds was fetched: %v", fetched)
	}
	hear(stampAlpha, eight)
	hear(stampAlpha, eight)
	hear(stampDelta, eight)
	if !slices.Equal(fetched, []string{stampZone}) {
		t.Fatalf("serial 8 told three times: fetched %v, want once", fetched)
	}
	hear(stampAlpha, nine)
	if len(fetched) != 2 {
		t.Fatalf("a higher serial within the minute: fetched %d times, want 2", len(fetched))
	}
	// a minute on, still behind: fetched again
	bob.mu.Lock()
	f := bob.fetched[stampZone]
	f.at = f.at.Add(-fetchInterval)
	bob.fetched[stampZone] = f
	bob.mu.Unlock()
	hear(stampAlpha, nine)
	if len(fetched) != 3 {
		t.Errorf("a minute later, still behind: fetched %d times, want 3", len(fetched))
	}
	// caught up: no more
	bob.store.Note(stampZone, nine, nil)
	bob.mu.Lock()
	f = bob.fetched[stampZone]
	f.at = f.at.Add(-fetchInterval)
	bob.fetched[stampZone] = f
	bob.mu.Unlock()
	hear(stampAlpha, nine)
	if len(fetched) != 3 {
		t.Errorf("caught up: fetched %d times, want 3", len(fetched))
	}
}

// A refresh the full queue dropped, or one for a zone that is not here yet,
// is asked again at the next telling, not a minute later; and a zone this
// agent holds no active serial for is fetched too (design 3.4).
func TestAFetchTheQueueDroppedIsAskedAgain(t *testing.T) {
	seven, eight := stampAt(t, 7, "a"), stampAt(t, 8, "a")
	bob := stampTableAt(t, stampBeta, seven)
	full := true
	asked := 0
	bob.fetch = func(zone string) (string, bool) {
		asked++
		return zone, !full
	}
	bob.note(told(stampAlpha, 1, 1, tells(seven, eight)), stampAlpha, "DNS")
	full = false
	bob.note(told(stampAlpha, 1, 2, tells(seven, eight)), stampAlpha, "DNS")
	bob.note(told(stampAlpha, 1, 3, tells(seven, eight)), stampAlpha, "DNS")
	if asked != 2 {
		t.Errorf("asked %d times, want 2: once dropped, once queued, then paced", asked)
	}

	// a zone that is not here yet is asked for again at the next telling,
	// and fetched once it is
	later := stampTableAt(t, stampBeta, seven)
	here := false
	var fetchedLater []string
	later.fetch = func(zone string) (string, bool) {
		fetchedLater = append(fetchedLater, zone)
		if !here {
			return "", false
		}
		return zone, true
	}
	later.note(told(stampAlpha, 1, 1, tells(seven, eight)), stampAlpha, "DNS")
	here = true
	later.note(told(stampAlpha, 1, 2, tells(seven, eight)), stampAlpha, "DNS")
	later.note(told(stampAlpha, 1, 3, tells(seven, eight)), stampAlpha, "DNS")
	if len(fetchedLater) != 2 {
		t.Errorf("a zone not here yet: asked %d times, want 2: once not here, once queued, then paced", len(fetchedLater))
	}

	// a store that holds nothing for the zone: a newcomer whose copy has no
	// reading of the instructions yet
	none := newStampTable(stampBeta, newStore(t), 1, true, nil)
	var names []string
	none.fetch = func(zone string) (string, bool) {
		names = append(names, zone)
		return zone, true
	}
	none.note(told(stampAlpha, 1, 1, tells(eight, eight)), stampAlpha, "DNS")
	if !slices.Equal(names, []string{stampZone}) {
		t.Errorf("a zone with no active serial here: fetched %v", names)
	}
}

// One member telling one serial with two digests is no conflict between
// members: rule 2 asks for two.
func TestOneMemberTellingOneSerialWithTwoDigestsIsNoOwnerError(t *testing.T) {
	seven, eightA, eightB := stampAt(t, 7, "a"), stampAt(t, 8, "a"), stampAt(t, 8, "b")
	bob := stampTableAt(t, stampBeta, seven)
	bob.note(told(stampAlpha, 1, 1, tells(eightA, eightB)), stampAlpha, "DNS")
	if st := status(t, bob.store, stampZone); st.OwnerError != "" {
		t.Errorf("one member's two digests: %q", st.OwnerError)
	}
}

// An agent that does not vote compares its active copy (rule 2), and is not
// named among the voting members of the conflict.
func TestAnAuditorIsNotNamedAmongTheVotingMembers(t *testing.T) {
	sevenA, sevenB := stampAt(t, 7, "a"), stampAt(t, 7, "b")
	delta := stampTableAt(t, stampDelta, sevenA)
	delta.note(told(stampAlpha, 1, 1, tells(sevenB, sevenB)), stampAlpha, "DNS")
	if st := status(t, delta.store, stampZone); st.Phase != PhaseOwnerError {
		t.Fatalf("a voting member's other digest for the auditor's active serial: phase %s", st.Phase)
	}
	_, conflicts, _ := delta.toldConflicts(stampZone)
	if len(conflicts) != 1 || !slices.Equal(conflicts[0].members, []string{stampAlpha}) {
		t.Errorf("the conflicts: %+v, want alpha named alone", conflicts)
	}
}

// The stamp row tells whether payload encryption is on.
func TestTheStampTellsPayloadEncryption(t *testing.T) {
	seven := stampAt(t, 7, "a")
	off := newStampTable(stampAlpha, stampTableAt(t, stampAlpha, seven).store, 1, false, nil)
	if off.entryFor(stampBeta).Members[stampAlpha].Crypto {
		t.Error("an agent with payload encryption off tells it on")
	}
	bob := stampTableAt(t, stampBeta, seven)
	bob.note(off.entryFor(stampBeta), stampAlpha, "DNS")
	if r := rowFor(t, bob.members(stampZone), stampAlpha); r.Crypto {
		t.Errorf("alice's row: %+v", r)
	}
	if r := rowFor(t, bob.members(stampZone), stampBeta); !r.Crypto {
		t.Errorf("bob's own row: %+v", r)
	}
}

// The stamp row carries the provider's own nameserver names.
func TestTheStampRowCarriesTheProvidersNameservers(t *testing.T) {
	seven := stampAt(t, 7, "a")
	row := stampTableAt(t, stampAlpha, seven).entryFor(stampBeta).Members[stampAlpha]
	if !slices.Equal(row.Nameservers, []string{"ns1." + stampAlpha}) {
		t.Errorf("nameservers: %v", row.Nameservers)
	}
}

// rolloverUnderWay over each key state and each flag.
func TestTheRolloverPredicateCoversEveryPhase(t *testing.T) {
	yes, no := true, false
	key := func(state string, flags uint16, ds *bool) []tdns.KeyInventoryItem {
		return []tdns.KeyInventoryItem{{KeyTag: 1, State: state, Flags: flags, DS: ds}}
	}
	for _, tc := range []struct {
		what  string
		keys  []tdns.KeyInventoryItem
		flags rolloverFlags
		want  bool
	}{
		{"steady: active and standby", append(key(KeyStateActive, 257, &yes), key(KeyStateStandby, 256, nil)...), rolloverFlags{}, false},
		{"created", key(KeyStateCreated, 256, nil), rolloverFlags{}, false},
		{"mpdist", key(KeyStateMpdist, 256, nil), rolloverFlags{}, true},
		{"published", key(KeyStatePublished, 257, &no), rolloverFlags{}, true},
		{"retired", key(KeyStateRetired, 257, &yes), rolloverFlags{}, true},
		{"mpremove", key(KeyStateMpremove, 256, nil), rolloverFlags{}, true},
		{"removed", key(KeyStateRemoved, 256, nil), rolloverFlags{}, false},
		{"a foreign key", key(KeyStateForeign, 257, nil), rolloverFlags{}, false},
		{"an active KSK whose DS withdrawal started", key(KeyStateActive, 257, &no), rolloverFlags{}, true},
		{"an active KSK with no ds column", key(KeyStateActive, 257, nil), rolloverFlags{}, false},
		{"an active ZSK", key(KeyStateActive, 256, &no), rolloverFlags{}, false},
		{"a requested rollover", nil, rolloverFlags{Requested: true}, true},
		{"an algorithm rollover", nil, rolloverFlags{AlgRoll: true}, true},
		{"a DNSKEY distribution pending", nil, rolloverFlags{PropagationPending: true}, true},
	} {
		if got := rolloverUnderWay(tc.keys, tc.flags); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.what, got, tc.want)
		}
	}
}

// The agent's rollover flag follows its signer's last inventory and its pending distributions.
func TestTheRolloverFlagFollowsTheInventory(t *testing.T) {
	tm := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	zd := &tdns.ZoneData{ZoneName: "rollover.stamp.example."}
	tdns.Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(zd.ZoneName)
		Zones.Invalidate(zd.ZoneName)
	})
	mpzd, _ := Zones.Get(zd.ZoneName)
	if tm.rolloverAt(zd.ZoneName) {
		t.Fatal("a rollover with no inventory")
	}
	mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Inventory: []KeyInventoryItem{{KeyTag: 1, State: KeyStateActive, Flags: 257}, {KeyTag: 2, State: KeyStatePublished, Flags: 256}}})
	if !tm.rolloverAt(zd.ZoneName) {
		t.Error("no rollover with a published key in the inventory")
	}
	mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Inventory: []KeyInventoryItem{{KeyTag: 1, State: KeyStateActive, Flags: 257}}})
	if tm.rolloverAt(zd.ZoneName) {
		t.Error("a rollover with a steady inventory")
	}
	tm.pendingDnskeyPropagations["d1"] = &PendingDnskeyPropagation{Zone: "Rollover.Stamp.Example."}
	if !tm.rolloverAt(zd.ZoneName) {
		t.Error("no rollover with a DNSKEY distribution pending")
	}
}

// The stamp entry on the wire. The goldens of the groups' gossip are
// unchanged: the new fields are omitted from a group's rows.
func TestGoldenGossipWithStamps(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	gossip := []GossipMessage{
		{GroupHash: "0123456789abcdef", Members: map[string]*MemberState{
			stampAlpha: {Identity: stampAlpha, PeerStates: map[string]string{stampBeta: "OPERATIONAL"}, Zones: []string{stampZone}, Timestamp: at}}},
		{GroupHash: stampGroupHash, Members: map[string]*MemberState{
			stampAlpha: {Identity: stampAlpha, Timestamp: at, Epoch: 1767323045, Seq: 42, Crypto: true,
				Nameservers: []string{"ns1.alpha.example."},
				Instr: map[string]InstrStamp{stampZone: {
					Active: 41, ActiveDigest: "5f3a19c2e07b4d11", Newest: 42, NewestDigest: "9c01aa47b2e3f650",
					Agreeing: 42, AgreeingDigest: "9c01aa47b2e3f650", Known: true, Rollover: true,
					Thaw: &Thaw{From: SerialDigest{Serial: 40, Digest: "0aa1"}, To: SerialDigest{Serial: 41, Digest: "5f3a19c2e07b4d11"}}}}}}},
	}
	got, err := json.MarshalIndent(gossip, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "golden-wire", "gossip-with-stamps.json")
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file (run `go test -run TestGoldenGossipWithStamps -update`): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("WIRE DRIFT in the stamp entry:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// The rows of a beat's answer are taken, and no election record or term
// with them (membership decision 35); its stamp entry is not merged either.
func TestGossipRowsInABeatAnswerTakeNoElection(t *testing.T) {
	gst := NewGossipStateTable(stampBeta)
	called := false
	gst.SetOnElectionUpdate(func(string, GroupElectionState) { called = true })
	group := &ProviderGroup{GroupHash: "0123456789abcdef", Members: []string{stampAlpha, stampBeta}, VotingMembers: []string{stampAlpha, stampBeta}}
	gst.MergeGossip(&GossipMessage{GroupHash: group.GroupHash, Members: map[string]*MemberState{
		stampAlpha: {Identity: stampAlpha, Timestamp: time.Now()}},
		Election: GroupElectionState{Leader: stampAlpha, Term: 9}}, stampAlpha, group, true)
	if rowOf(gst, group.GroupHash, stampAlpha) == nil {
		t.Error("the answer's row was not taken")
	}
	if electionOf(gst, group.GroupHash) != nil || called {
		t.Error("the answer's election record was taken")
	}
}
