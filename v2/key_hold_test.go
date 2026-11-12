/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// keyHoldRig is the hold rig on a parent that takes UPDATE, with the zone's
// key made, the zone caught up, and tdns's poll replaced by one that runs
// until released.
type keyHoldRig struct {
	*holdRig
	zone    ZoneName
	key     sig0Row
	entered chan struct{}
	release chan struct{}
}

func newKeyHoldRig(t *testing.T, zone string) *keyHoldRig {
	t.Helper()
	h := newHoldRig(t, zone, "UPDATE", false, repeat(time.Hour, 4)...)
	r := &keyHoldRig{holdRig: h, zone: ZoneName(h.mpzd.ZoneName), entered: make(chan struct{}, 4), release: make(chan struct{})}
	r.key = testSig0Key(t, h.mpzd.KeyDB, h.mpzd.ZoneName)
	trustKey(h.mpzd.KeyDB, h.mpzd.ZoneName, r.key.keyid) // the parent trusts the zone's key
	// released, the poll ends with the parent trusting the key, as tdns's
	// records it
	h.conf.InternalMp.keyPoll = func(ctx context.Context, _ ZoneName, keyName string, keyid uint16, _ uint8) {
		r.entered <- struct{}{}
		select {
		case <-r.release:
			tdns.UpdateParentState(h.mpzd.KeyDB, keyName, keyid, edns0.KeyStateTrusted)
		case <-ctx.Done():
		}
	}
	h.parent.holdsNS("ns1."+h.mpzd.ZoneName, h.oldNS) // the parent has an NS the zone no longer lists
	h.caughtUp()
	return r
}

// pollRuns starts the poll of the zone's key, and waits until it runs.
func (r *keyHoldRig) pollRuns(t *testing.T) {
	t.Helper()
	r.conf.launchKeyPoll(r.ctx, nil, r.zone, string(r.zone), r.key.keyid, r.key.key.Algorithm)
	select {
	case <-r.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("the key poll did not run\n%s", r.log)
	}
}

func (r *keyHoldRig) explicit(t *testing.T) tdns.DelegationSyncStatus {
	t.Helper()
	resp := make(chan tdns.DelegationSyncStatus, 1)
	r.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: string(r.zone), ZoneData: r.mpzd.ZoneData, Response: resp}
	got, ok := recvWithin(resp, 2*time.Second)
	if !ok {
		t.Fatalf("the explicit sync got no answer: the syncher waited\n%s", r.log)
	}
	return got
}

func (r *keyHoldRig) keyOwed() bool {
	r.tr.mu.Lock()
	defer r.tr.mu.Unlock()
	o := r.tr.owed[ZoneName(dns.Fqdn(string(r.zone)))]
	return o != nil && o.key
}

// While a poll of the zone's key runs, the leader's sync waits. An explicit
// sync is answered at once, the key poll's own one after the parent trusts
// the key included: never left waiting until the poll ends. The sync is
// owed for the key; the catch-up does not release it. When the poll ends,
// the sync that waited is asked for, and goes out.
func TestASyncHeldForTheKeyPollIsAnsweredAtOnceAndAskedForAtItsEnd(t *testing.T) {
	r := newKeyHoldRig(t, "polled.key.example.")
	r.pollRuns(t)

	got := r.explicit(t)
	if !strings.Contains(got.Msg, "waits for the zone's SIG(0) key (poll running)") {
		t.Errorf("the explicit sync's answer: %q", got.Msg)
	}
	if !r.keyOwed() {
		t.Fatal("the held sync is not owed for the key")
	}
	r.askOwed() // what the catch-up's places do
	if !r.keyOwed() {
		t.Fatal("the catch-up's ask released the sync held for the key")
	}
	time.Sleep(200 * time.Millisecond)
	if n := r.parent.updatesSeen(); n != 0 {
		t.Fatalf("%d UPDATEs reached the parent while the key's poll ran", n)
	}

	close(r.release)
	waitUntil(t, "the sync that waited for the key went out\n"+r.log.String(), func() bool { return r.parent.updatesSeen() > 0 })
	if r.keyOwed() {
		t.Error("the sync is still owed for the key after the poll ended")
	}
}

// The implicit sync of a refresh is held the same way.
func TestARefreshsSyncIsHeldWhileTheKeyPollRuns(t *testing.T) {
	r := newKeyHoldRig(t, "polled.refresh.example.")
	r.pollRuns(t)
	r.q <- tdns.DelegationSyncRequest{Command: "SYNC-DELEGATION", ZoneName: string(r.zone), ZoneData: r.mpzd.ZoneData,
		SyncStatus: tdns.DelegationSyncStatus{ZoneName: string(r.zone)}}
	waitUntil(t, "the refresh's sync was not owed for the key\n"+r.log.String(), r.keyOwed)
	if n := r.parent.updatesSeen(); n != 0 {
		t.Fatalf("%d UPDATEs reached the parent while the key's poll ran", n)
	}
	close(r.release)
	waitUntil(t, "the sync that waited for the key went out\n"+r.log.String(), func() bool { return r.parent.updatesSeen() > 0 })
}

// The sync waits while the key tdns signs with is not the zone's only active
// key, and goes out once the others are retired.
func TestTheSyncWaitsUntilTheZonesKeyIsTheOnlyActiveOne(t *testing.T) {
	r := newKeyHoldRig(t, "two.keys.example.")
	testSig0Key(t, r.mpzd.KeyDB, string(r.zone))
	trustActiveKeys(t, r.mpzd.KeyDB, string(r.zone)) // whichever is the zone's key, the parent trusts it

	if got := r.explicit(t); !strings.Contains(got.Msg, "(signing key differs)") {
		t.Fatalf("with two active keys the explicit sync's answer: %q", got.Msg)
	}
	zk, err := readZoneKey(r.mpzd.KeyDB, r.zone)
	if err != nil || zk.held == nil {
		t.Fatalf("the zone's key: %+v, %v", zk, err)
	}
	if only, err := retireOtherActiveKeys(r.mpzd.KeyDB, r.zone, zk); !only || err != nil {
		t.Fatalf("retire: %v, %v", only, err)
	}
	r.conf.releaseKeyHold(r.ctx, r.zone)
	waitUntil(t, "the sync that waited for the key went out\n"+r.log.String(), func() bool { return r.parent.updatesSeen() > 0 })
}

// A renewal of the lead in which the zone's key was polled, the key
// published, publishes nothing again and starts no poll. A new lead, another
// key, an unpublished one and a restart (nothing ended here) do.
func TestARenewalKeepsTheZonesKeyAsItIs(t *testing.T) {
	const zone = "renewal.keeps.example."
	kdb := newMPTestKeyDB(t)
	k := testSig0Key(t, kdb, zone)
	other := testSig0Key(t, newMPTestKeyDB(t), zone)
	keyZone(t, zone, k)
	zk, err := readZoneKey(kdb, zone)
	if err != nil || zk.held == nil {
		t.Fatalf("the zone's key: %v", err)
	}
	unpublished := &zoneKey{held: zk.held, active: zk.active}
	// another key active beside the zone's: the renewal's set-up retires it
	twoActive := &zoneKey{held: zk.held, active: append(append([]sig0Row{}, zk.active...), other), published: zk.published}
	for _, c := range []struct {
		name      string
		zk        *zoneKey
		ended     keyPollEnd
		leadStart uint64
		keeps     bool
	}{
		{"a renewal", zk, keyPollEnd{k.keyid, 5}, 5, true},
		{"a new lead", zk, keyPollEnd{k.keyid, 5}, 7, false},
		{"another key polled", zk, keyPollEnd{other.keyid, 5}, 5, false},
		{"after a restart", zk, keyPollEnd{}, 5, false},
		{"not leading", zk, keyPollEnd{k.keyid, 5}, 0, false},
		{"the key not published", unpublished, keyPollEnd{k.keyid, 5}, 5, false},
		{"another key active too", twoActive, keyPollEnd{k.keyid, 5}, 5, false},
	} {
		if got := renewalKeepsKey(c.zk, c.ended, c.leadStart); got != c.keeps {
			t.Errorf("%s: keeps the key %v, want %v", c.name, got, c.keeps)
		}
	}
}

// A lead's number: a renewal keeps it, another agent's lead clears it, a
// lead after another's or after a lapsed lease gets a new one. A lone
// voter's lead at term 0 is a lead, and its renewals keep it.
func TestALeadStartsAtItsFirstTermAndARenewalKeepsIt(t *testing.T) {
	lem := &LeaderElectionManager{localID: "us.example."}
	le := &LeaderElection{}
	lead := func(leader AgentId, term uint64, lease time.Duration) uint64 {
		le.Term = term
		now := time.Now()
		lem.noteLeaderLocked(le, leader, now)
		le.Leader, le.LeaderExpiry = leader, now.Add(lease)
		return le.leadStart
	}
	first := lead("us.example.", 1, time.Hour)
	if first == 0 {
		t.Fatal("a first lead has no number")
	}
	if got := lead("us.example.", 2, time.Hour); got != first {
		t.Errorf("a renewal makes the lead %d, want %d as it was", got, first)
	}
	if got := lead("them.example.", 3, time.Hour); got != 0 {
		t.Errorf("another agent's lead leaves %d, want 0", got)
	}
	after := lead("us.example.", 4, -time.Second)
	if after == 0 || after == first {
		t.Errorf("a lead after another's is %d, want a new number (was %d)", after, first)
	}
	if got := lead("us.example.", 5, time.Hour); got == 0 || got == after {
		t.Errorf("a lead after a lapsed lease is %d, want a new number (was %d)", got, after)
	}

	// a lone voter: its self-election and its renewals stay at term 0
	lone := &LeaderElection{}
	at0 := func() uint64 {
		now := time.Now()
		lem.noteLeaderLocked(lone, "us.example.", now)
		lone.Leader, lone.LeaderExpiry = "us.example.", now.Add(time.Hour)
		return lone.leadStart
	}
	l0 := at0()
	if l0 == 0 {
		t.Fatal("a lead at term 0 reads as no lead")
	}
	if got := at0(); got != l0 {
		t.Errorf("a renewal at term 0 starts the lead anew (%d, was %d): it republishes the key and polls again", got, l0)
	}
}

// Leads in two elections, two groups or a group and a zone's own, never
// share a number, also when each began at the same term: a lead in the
// group a zone moved to is never taken for a renewal of the lead in the
// group it left.
func TestLeadsInTwoElectionsNeverShareANumber(t *testing.T) {
	lem := &LeaderElectionManager{localID: "us.example."}
	g1, g2 := &LeaderElection{Term: 1}, &LeaderElection{Term: 1}
	lem.noteLeaderLocked(g1, "us.example.", time.Now())
	lem.noteLeaderLocked(g2, "us.example.", time.Now())
	if g1.leadStart == 0 || g1.leadStart == g2.leadStart {
		t.Errorf("two leads at term 1 in two elections are %d and %d", g1.leadStart, g2.leadStart)
	}
}

// A poll that returns because the lead moved (the zone left its group, its
// run cancelled) did not run to its end: nothing is noted, and a later lead,
// or the same lead taking the zone up again, publishes and polls anew. A poll
// that ends in the lead it started in is noted.
func TestAPollEndedByAMovedLeadIsNoRenewal(t *testing.T) {
	for _, moved := range []bool{true, false} {
		r := newKeyRoundRig(t, map[bool]string{true: "moved.poll.example.", false: "kept.poll.example."}[moved], "UPDATE")
		release := make(chan struct{})
		started := make(chan struct{}, 1)
		r.conf.InternalMp.keyPoll = func(ctx context.Context, _ ZoneName, _ string, _ uint16, _ uint8) {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		k := testSig0Key(t, r.mpzd.KeyDB, string(r.zone))
		r.conf.launchKeyPoll(r.ctx, nil, r.zone, string(r.zone), k.keyid, k.key.Algorithm)
		if _, ok := recvWithin(started, 5*time.Second); !ok {
			t.Fatal("the poll did not start")
		}
		if moved {
			r.leader(r.them)
		}
		close(release)
		waitUntil(t, "the poll ended", func() bool { n, _, _ := r.conf.InternalMp.keyPolls.state(r.zone); return n == 0 })
		_, _, ended := r.conf.InternalMp.keyPolls.state(r.zone)
		if moved && ended.leadStart != 0 {
			t.Errorf("a poll whose lead moved was noted as ended in lead %d", ended.leadStart)
		}
		if !moved && (ended.leadStart == 0 || ended.keyid != k.keyid) {
			t.Errorf("a poll that ran to its end in its lead was not noted: %+v", ended)
		}
	}
}

// BADKEY with no active key makes no key (1c): tdns's re-bootstrap passes
// algorithm 0, which generation refuses.
func TestABadkeyWithNoActiveKeyMakesNoKey(t *testing.T) {
	const zone = "badkey.nokey.example."
	kdb := newMPTestKeyDB(t)
	zd := &tdns.ZoneData{ZoneName: zone, KeyDB: kdb, Logger: log.New(io.Discard, "", 0), Options: map[tdns.ZoneOption]bool{}}
	zd.SetParent("example.")
	if _, _, err := zd.BootstrapSig0KeyWithParent(context.Background(), 0); err == nil {
		t.Error("the bootstrap with no active key and algorithm 0 did not fail")
	}
	rows, err := kdb.Query(`SELECT count(*) FROM Sig0KeyStore WHERE zonename=?`, zone)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var n int
	if rows.Next() {
		_ = rows.Scan(&n)
	}
	if n != 0 {
		t.Errorf("BADKEY with no active key left %d SIG(0) key(s) in the keystore, want none", n)
	}
}

// LeadStart finds the zone's election as IsLeader does: its provider group's
// when that has a leader, else the zone's own. A group with no leader yet
// leaves the zone's own lead its number, so its renewal keeps the key.
func TestLeadStartFindsTheElectionIsLeaderFinds(t *testing.T) {
	zd := providerZone(t, "leadstart.group.example.", arrivalA, arrivalB)
	zone := ZoneName(zd.ZoneName)
	lem := NewLeaderElectionManager(arrivalA, time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(lem) })
	pgm := NewProviderGroupManager(arrivalA)
	lem.SetProviderGroupManager(pgm)
	pgm.RecomputeGroups()
	inGroup(t, pgm, zd, arrivalA, arrivalB)
	group := pgm.GetGroupForZone(zone).GroupHash

	lead := func(le *LeaderElection) uint64 {
		le.mu.Lock()
		defer le.mu.Unlock()
		le.Term++
		now := time.Now()
		lem.noteLeaderLocked(le, arrivalA, now)
		le.Leader, le.LeaderExpiry = arrivalA, now.Add(time.Hour)
		return le.leadStart
	}
	own := lead(lem.getOrCreate(zone))
	ge := &LeaderElection{Zone: ZoneName(group)}
	lem.mu.Lock()
	lem.groupElections[group] = ge // the group's election, with no leader yet
	lem.mu.Unlock()
	if !lem.IsLeader(zone) {
		t.Fatal("precondition: this agent does not lead the zone by its own election")
	}
	if got := lem.LeadStart(zone); got != own {
		t.Errorf("with the group's election not decided, the lead is %d, want the zone's own %d", got, own)
	}
	if byGroup := lead(ge); lem.LeadStart(zone) != byGroup {
		t.Errorf("with the group led by this agent, the lead is %d, want the group's %d", lem.LeadStart(zone), byGroup)
	}
}

// A parent whose DSYNC records cannot be read (no resolver yet) is not "no
// key": the leader's sync is held as for a parent that takes UPDATE, here
// while an old key the zone does not publish is active too, and the
// leader's set-up runs. Read as "no key", the sync went out signed by the
// old key, and BADKEY uploaded it. The set-up asks the same test.
func TestAnUnreadableParentHoldsTheSync(t *testing.T) {
	r := newKeyHoldRig(t, "unread.hold.example.")
	testSig0Key(t, r.mpzd.KeyDB, string(r.zone)) // an old key, active too
	imr := r.conf.Config.Internal.ImrEngine
	r.conf.Config.Internal.ImrEngine = nil // no resolver yet
	defer func() { r.conf.Config.Internal.ImrEngine = imr }()

	if !r.conf.zoneUsesKey(r.ctx, r.zone) {
		t.Fatal("a parent not read is taken as one that takes no UPDATE")
	}
	if got := r.explicit(t); !strings.Contains(got.Msg, "(signing key differs)") {
		t.Errorf("with the parent not read and two active keys, the explicit sync's answer: %q", got.Msg)
	}
	if !r.keyOwed() {
		t.Error("the sync is not owed for the key")
	}
	if uses, known := r.conf.zoneKeyUse(r.ctx, r.zone); uses || known {
		t.Errorf("the rounds read the parent as uses %v, known %v; want not known", uses, known)
	}
}

// A sync owed for the zone's key waits for the key, not for room in the
// delegation sync queue. A pass that finds the queue full marks the caught-up
// zones after it as waiting for room, but not this one: it is not asked
// until the key's hold ends, so the mark would stay, and the status would
// say the queue is full while the key is what it waits for.
func TestASyncOwedForTheKeyDoesNotWaitForRoom(t *testing.T) {
	r, tr := owedRig(t, "a.room.key.example.", true)
	second := newLeaderSyncRig(t, "b.room.key.example.")
	second.mpzd.Ready = true
	second.mpzd.DelegationSyncQ = r.q
	z1, z2 := ZoneName(r.mpzd.ZoneName), ZoneName(second.mpzd.ZoneName)
	r.lem.mu.Lock()
	r.lem.elections[z2] = &LeaderElection{Zone: z2, Leader: usAgent, LeaderExpiry: time.Now().Add(time.Hour)}
	r.lem.mu.Unlock()
	tr.zdr.markOwnState(z2, true, "")
	for range cap(r.q) {
		r.q <- tdns.DelegationSyncRequest{Command: "SYNC-DNSKEY-RRSET", ZoneName: string(z1)}
	}
	tr.owe(z1)
	tr.oweForKey(z2)
	tr.askAllOwed(r.ctx, false)
	if _, room := tr.owedState(z1); !room {
		t.Fatal("precondition: the zone that found the queue full does not wait for room")
	}
	if owed, room := tr.owedState(z2); !owed || room {
		t.Errorf("the sync owed for the key: owed=%v, waits for room=%v; want owed, not waiting for room", owed, room)
	}
	if !tr.owedForKey(z2) {
		t.Error("the sync is not owed for the key")
	}
	ar := &AgentRegistry{MPTransport: &MPTransportBridge{catchUp: tr}}
	if st := r.lem.GetParentSyncStatus(z2, nil, nil, nil, ar, nil); st.ParentSync != "owed for the zone's SIG(0) key" {
		t.Errorf("the status says %q, want the key", st.ParentSync)
	}
}

// pollEndsWithoutAVerdict runs a poll of the zone's key k to its end in this
// lead and leaves parent_state as it was: a parent that does not answer
// KeyState, whose poll tdns gives up.
func (r *keyHoldRig) pollEndsWithoutAVerdict(t *testing.T, k sig0Row) {
	t.Helper()
	keyPoll := r.conf.InternalMp.keyPoll
	r.conf.InternalMp.keyPoll = func(context.Context, ZoneName, string, uint16, uint8) {}
	defer func() { r.conf.InternalMp.keyPoll = keyPoll }()
	r.conf.launchKeyPoll(r.ctx, nil, r.zone, string(r.zone), k.keyid, k.key.Algorithm)
	waitUntil(t, "the poll did not end\n"+r.log.String(), func() bool {
		n, _, ended := r.conf.InternalMp.keyPolls.state(r.zone)
		return n == 0 && ended.keyid == k.keyid
	})
}

// Whether the leader's sync waits for the zone's key follows the parent's
// verdict on it, as tdns recorded it (#404). A verdict that is not trusted
// holds it, and so does a poll of the key that runs. A key the parent never
// gave a verdict on holds it until a poll of the key has run to its end in
// this lead; after that it does not: the next sync tests the key.
func TestTheHoldFollowsTheParentsVerdict(t *testing.T) {
	r := newKeyHoldRig(t, "verdict.key.example.")
	const notTaken = "the parent has not taken the key"
	cases := []struct {
		state    uint8
		unpolled bool // held before a poll of the key ends in this lead
		polled   bool // held after it
	}{
		{0, true, false},
		{edns0.KeyStateUninitialized, true, false},
		{edns0.KeyStateTrusted, false, false},
		{edns0.KeyStateUnknown, true, true},
		{edns0.KeyStateRefused, true, true},
		{edns0.KeyStateInvalid, true, true},
		{edns0.KeyStateValidationFail, true, true},
		{edns0.KeyStateBootstrapManualRequired, true, true},
	}
	check := func(when string, held func(int) bool) {
		t.Helper()
		for i, tc := range cases {
			tdns.UpdateParentState(r.mpzd.KeyDB, string(r.zone), r.key.keyid, tc.state)
			want := ""
			if held(i) {
				want = notTaken
			}
			if _, why := r.conf.keyHold(r.ctx, r.zone); why != want {
				t.Errorf("parent_state %s, %s: held for %q, want %q", edns0.KeyStateToString(tc.state), when, why, want)
			}
			if got := r.conf.keyPending(r.ctx, r.zone); got != held(i) {
				t.Errorf("parent_state %s, %s: keyPending %v, want %v", edns0.KeyStateToString(tc.state), when, got, held(i))
			}
		}
	}
	check("no poll ended", func(i int) bool { return cases[i].unpolled })
	r.pollEndsWithoutAVerdict(t, r.key)
	check("a poll ended in this lead", func(i int) bool { return cases[i].polled })

	tdns.UpdateParentState(r.mpzd.KeyDB, string(r.zone), r.key.keyid, 0)
	r.pollRuns(t)
	if _, why := r.conf.keyHold(r.ctx, r.zone); why != "poll running" {
		t.Errorf("a key with no verdict and a poll of it running: held for %q, want \"poll running\"", why)
	}
}

// The leader's sync of a zone whose key the parent never gave a verdict on
// waits until a poll of the key has run to its end in this lead, and then
// goes out: it is what tests the key (keys-parent-down K7). tdns records the
// key trusted when the parent answers it NOERROR, and starts its re-bootstrap
// on BADKEY.
func TestASyncTestsAKeyTheParentNeverGaveAVerdictOn(t *testing.T) {
	r := newKeyHoldRig(t, "tested.key.example.")
	tdns.UpdateParentState(r.mpzd.KeyDB, string(r.zone), r.key.keyid, 0) // from before S14, or a parent that does not answer KeyState
	if got := r.explicit(t); !strings.Contains(got.Msg, "the parent has not taken the key") {
		t.Fatalf("before a poll of the key ended the explicit sync's answer: %q", got.Msg)
	}
	time.Sleep(200 * time.Millisecond)
	if n := r.parent.updatesSeen(); n != 0 {
		t.Fatalf("%d UPDATEs reached the parent before a poll of the key ended", n)
	}
	r.pollEndsWithoutAVerdict(t, r.key)
	waitUntil(t, "the sync that waited went out to the parent\n"+r.log.String(), func() bool { return r.parent.updatesSeen() > 0 })
	if got := r.explicit(t); strings.Contains(got.Msg, "the parent has not taken the key") {
		t.Errorf("after a poll of the key ended in this lead the explicit sync's answer: %q", got.Msg)
	}
}

// keys-k3 a: a key just made, or taken up, is published before its poll
// starts (the take-up's poll waits until every recipient has the KEY). The
// parent has not been asked about it yet, and does not trust it: the sync
// waits until a poll of that key ends, even though a poll of the key before
// it ended in this lead. A sync signed with it would get BADKEY.
func TestAFreshKeyPublishedBeforeItsPollHoldsTheSync(t *testing.T) {
	r := newKeyHoldRig(t, "fresh.key.example.")
	r.pollEndsWithoutAVerdict(t, r.key) // the key before it, polled in this lead

	fresh := testSig0Key(t, r.mpzd.KeyDB, string(r.zone)) // parent_state 0: never asked
	zk, err := readZoneKey(r.mpzd.KeyDB, r.zone)
	if err != nil {
		t.Fatal(err)
	}
	for i := range zk.active {
		if zk.active[i].keyid == fresh.keyid {
			zk.held = &zk.active[i]
		}
	}
	if only, err := retireOtherActiveKeys(r.mpzd.KeyDB, r.zone, zk); !only || err != nil {
		t.Fatalf("retiring the key before it: %v, %v", only, err)
	}
	if zk, err := readZoneKey(r.mpzd.KeyDB, r.zone); err != nil || zk.held == nil || zk.held.keyid != fresh.keyid {
		t.Fatalf("the zone's key is not the fresh one: %+v, %v", zk, err)
	}

	if got := r.explicit(t); !strings.Contains(got.Msg, "the parent has not taken the key") {
		t.Fatalf("a fresh key no poll of which has ended: the explicit sync's answer: %q", got.Msg)
	}
	if !r.conf.keyPending(r.ctx, r.zone) {
		t.Error("a fresh key no poll of which has ended is not pending")
	}
	time.Sleep(200 * time.Millisecond)
	if n := r.parent.updatesSeen(); n != 0 {
		t.Fatalf("%d UPDATEs signed with a key the parent was not asked about reached it", n)
	}

	r.pollEndsWithoutAVerdict(t, fresh)
	waitUntil(t, "the sync that waited went out after the fresh key's poll ended\n"+r.log.String(), func() bool { return r.parent.updatesSeen() > 0 })
}

// A new lead has not polled the key: a key the parent gave no verdict on
// holds the sync again until a poll of it ends in that lead.
func TestANewLeadHoldsAKeyWithNoVerdictUntilItsPollEnds(t *testing.T) {
	r := newKeyHoldRig(t, "new.lead.example.")
	tdns.UpdateParentState(r.mpzd.KeyDB, string(r.zone), r.key.keyid, 0)
	r.pollEndsWithoutAVerdict(t, r.key)
	if _, why := r.conf.keyHold(r.ctx, r.zone); why != "" {
		t.Fatalf("after a poll of the key ended in this lead: held for %q", why)
	}

	before := r.lem.LeadStart(r.zone)
	r.leader(AgentId(r.us.Identity)) // a new election that this agent wins
	if after := r.lem.LeadStart(r.zone); after == 0 || after == before {
		t.Fatalf("the new lead is %d, the earlier one %d", after, before)
	}
	if _, why := r.conf.keyHold(r.ctx, r.zone); why != "the parent has not taken the key" {
		t.Errorf("in a new lead before a poll of the key ended: held for %q", why)
	}
	if !r.conf.keyPending(r.ctx, r.zone) {
		t.Error("in a new lead before a poll of the key ended the key is not pending")
	}

	r.pollEndsWithoutAVerdict(t, r.key)
	if _, why := r.conf.keyHold(r.ctx, r.zone); why != "" {
		t.Errorf("after a poll of the key ended in the new lead: held for %q", why)
	}
}
