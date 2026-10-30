/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The leader's roll of the zone's SIG(0) key (plan S17a), on the key
// round's rig: this agent leads, the zone's parent takes UPDATE, and the
// parent is played by rollTestParent.

// rollTestParent trusts the keys it is told to and those an UPDATE it
// accepts adds, and accepts an UPDATE only when a key it trusts signs it.
type rollTestParent struct {
	mu      sync.Mutex
	trusted map[uint16]bool
	initial map[uint16]bool
	// holdTrust: the inquiry says unknown for a key added since the start
	holdTrust bool
	refuse    map[string]int // "add" or "delete": the rcode of the next one
	sent      []rollTestUpdate
}

type rollTestUpdate struct {
	what          string
	keyid, signer uint16
	rcode         int
}

func newRollTestParent(trusted ...uint16) *rollTestParent {
	p := &rollTestParent{trusted: map[uint16]bool{}, initial: map[uint16]bool{}, refuse: map[string]int{}}
	for _, k := range trusted {
		p.trusted[k], p.initial[k] = true, true
	}
	return p
}

func (p *rollTestParent) update(_ context.Context, _ ZoneName, adds, removes []dns.RR, signer *tdns.PrivateKeyCache) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u := rollTestUpdate{what: "add", signer: signer.KeyRR.KeyTag()}
	if len(adds) > 0 {
		u.keyid = adds[0].(*dns.KEY).KeyTag()
	} else {
		u.what, u.keyid = "delete", removes[0].(*dns.KEY).KeyTag()
	}
	switch rc, refused := p.refuse[u.what]; {
	case refused:
		delete(p.refuse, u.what)
		u.rcode = rc
	case !p.trusted[u.signer]:
		u.rcode = dns.RcodeRefused
	default:
		u.rcode = dns.RcodeSuccess
		if u.what == "add" {
			p.trusted[u.keyid] = true
		} else {
			delete(p.trusted, u.keyid)
		}
	}
	p.sent = append(p.sent, u)
	return u.rcode, nil
}

func (p *rollTestParent) keyState(_ context.Context, _ ZoneName, keyid uint16) (uint8, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.trusted[keyid] && (!p.holdTrust || p.initial[keyid]) {
		return edns0.KeyStateTrusted, nil
	}
	return edns0.KeyStateUnknown, nil
}

func (p *rollTestParent) updates() []rollTestUpdate {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.sent)
}

func (p *rollTestParent) trusts() []uint16 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []uint16
	for k := range p.trusted {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

type rollRig struct {
	*keyRoundRig
	parent *rollTestParent
	old    sig0Row
}

// newRollRig: the leader holds the zone's key, which the zone publishes and
// the parent trusts.
func newRollRig(t *testing.T, zone string) *rollRig {
	t.Helper()
	r := newKeyRoundRig(t, zone, "UPDATE")
	k := testSig0Key(t, r.mpzd.KeyDB, string(r.zone))
	r.publish(t, k)
	trustKey(r.mpzd.KeyDB, string(r.zone), k.keyid)
	r.caughtUp()
	p := newRollTestParent(k.keyid)
	r.conf.InternalMp.rollParent = p
	t.Cleanup(r.conf.InternalMp.sig0Rolls.wait)
	return &rollRig{keyRoundRig: r, parent: p, old: k}
}

// start starts the roll and waits for its first pass.
func (r *rollRig) start(t *testing.T) uint16 {
	t.Helper()
	keyid, err := r.conf.startSig0Roll(r.ctx, r.zone, dns.ED25519)
	if err != nil {
		t.Fatalf("the roll did not start: %v", err)
	}
	r.conf.InternalMp.sig0Rolls.wait()
	return keyid
}

// pass runs a pass of the roll, as the ticker does.
func (r *rollRig) pass(t *testing.T, cause syncCause) {
	t.Helper()
	waitUntil(t, "a pass of the roll still runs", func() bool { return r.conf.rollOnce(r.ctx, r.zone, cause) })
}

func (r *rollRig) roll(t *testing.T) *sig0Roll {
	t.Helper()
	ro, err := loadRoll(r.mpzd.KeyDB, r.zone)
	if err != nil {
		t.Fatal(err)
	}
	return ro
}

// due makes a failed phase due again, as time passing would.
func (r *rollRig) due(t *testing.T) {
	t.Helper()
	ro := r.roll(t)
	ro.nextTry = time.Now().Add(-time.Second)
	if err := saveRoll(r.mpzd.KeyDB, ro); err != nil {
		t.Fatal(err)
	}
}

// confirmAll has every recipient of the roll's new KEY take it.
func (r *rollRig) confirmAll(t *testing.T) {
	t.Helper()
	tm := r.conf.InternalMp.MPTransport
	st, ok := tm.rollKEYs.state(r.zone)
	if !ok {
		t.Fatal("no new KEY is booked")
	}
	if len(st.expected) == 0 {
		t.Fatal("the new KEY has no recipients")
	}
	for _, rcpt := range st.expected {
		tm.rollKEYs.heard(st.distID, rcpt, "SUCCESS", "", false)
	}
}

func (r *rollRig) keyState(t *testing.T, keyid uint16) string {
	t.Helper()
	var state string
	if err := r.mpzd.KeyDB.QueryRow(`SELECT state FROM Sig0KeyStore WHERE zonename=? AND keyid=?`, dns.Fqdn(string(r.zone)), keyid).Scan(&state); err != nil {
		t.Fatalf("key %d: %v", keyid, err)
	}
	return state
}

func (r *rollRig) row(t *testing.T, state string, keyid uint16) sig0Row {
	t.Helper()
	k := sig0RowByID(r.mpzd.KeyDB, r.zone, state, keyid)
	if k == nil {
		t.Fatalf("no %s key %d", state, keyid)
	}
	return *k
}

// The add of the new key goes to the parent signed with the old key, and
// the parent's trust in it is asked before anything else.
func TestTheRollAddsTheNewKeySignedWithTheOld(t *testing.T) {
	r := newRollRig(t, "roll.adds.example.")
	k2 := r.start(t)
	u := r.parent.updates()
	if len(u) != 1 || u[0].what != "add" || u[0].keyid != k2 || u[0].signer != r.old.keyid || u[0].rcode != dns.RcodeSuccess {
		t.Fatalf("the parent got %+v, want the add of %d signed with %d", u, k2, r.old.keyid)
	}
	if ro := r.roll(t); ro == nil || ro.phase != rollPublished {
		t.Errorf("the roll after its first pass: %+v, want %s", ro, rollPublished)
	}
	if !strings.Contains(r.alog.String(), "rolling the zone's SIG(0) key") {
		t.Errorf("no line for the roll:\n%s", r.alog)
	}
}

// Until step 5 the leader keeps one active key, the old one, which signs;
// the new key, once the zone publishes it, is the zone's key it hands over,
// and nothing is retired or set up at the leader meanwhile.
func TestTheNewKeyIsNotActiveAtTheLeaderBeforeStepFive(t *testing.T) {
	r := newRollRig(t, "roll.notactive.example.")
	k2 := r.start(t)
	if got := r.active(t); !slices.Equal(got, []uint16{r.old.keyid}) {
		t.Fatalf("active keys during the roll: %v, want %d alone", got, r.old.keyid)
	}
	if st := r.keyState(t, k2); st != tdns.Sig0StatePublished {
		t.Errorf("the new key is %s, want %s", st, tdns.Sig0StatePublished)
	}
	// the zone publishes the new KEY: the leader's zone key is the new one
	r.publish(t, r.row(t, tdns.Sig0StatePublished, k2))
	zk, err := readZoneKey(r.mpzd.KeyDB, r.zone)
	if err != nil || zk.held == nil || zk.held.keyid != k2 || !zk.rolling {
		t.Fatalf("the zone's key at the leader during the roll: %+v (%v), want %d, rolling", zk, err, k2)
	}
	r.conf.wantsZoneKey(r.ctx, r.zone)
	if err := r.conf.leaderKeySetup(r.ctx, r.zone, false); err != nil {
		t.Errorf("the leader's set-up during the roll: %v", err)
	}
	if got := r.active(t); !slices.Equal(got, []uint16{r.old.keyid}) {
		t.Errorf("active keys after the round and the set-up: %v, want %d alone", got, r.old.keyid)
	}
	if why := r.conf.keyHoldReason(r.ctx, r.zone); why != "" {
		t.Errorf("the leader's sync is held during the roll: %s", why)
	}
	r.confirmAll(t)
	r.pass(t, syncOther)
	if got := r.active(t); !slices.Equal(got, []uint16{k2}) {
		t.Errorf("active keys after step 5: %v, want %d alone", got, k2)
	}
	if st := r.keyState(t, r.old.keyid); st != tdns.Sig0StateRetired {
		t.Errorf("the old key after step 5 is %s, want %s", st, tdns.Sig0StateRetired)
	}
}

// The new KEY goes out only once a KeyState inquiry says the parent trusts
// the new key.
func TestTheNewKEYIsPublishedOnlyAfterTheParentHasTakenIt(t *testing.T) {
	r := newRollRig(t, "roll.published.example.")
	r.parent.holdTrust = true
	keyid := r.start(t)
	if ro := r.roll(t); ro == nil || ro.phase != rollAdded || ro.failures != 1 {
		t.Fatalf("the roll while the parent does not trust the new key: %+v", ro)
	}
	if _, booked := r.conf.InternalMp.MPTransport.rollKEYs.state(r.zone); booked {
		t.Fatal("the new KEY went out before the parent trusts the new key")
	}
	r.parent.mu.Lock()
	r.parent.holdTrust = false
	r.parent.mu.Unlock()
	r.due(t)
	r.pass(t, syncOther)
	if ro := r.roll(t); ro.phase != rollPublished {
		t.Fatalf("the roll once the parent trusts the new key: %+v", ro)
	}
	if _, booked := r.conf.InternalMp.MPTransport.rollKEYs.state(r.zone); !booked {
		t.Error("the new KEY did not go out once the parent trusts the new key")
	}
	if k := r.row(t, tdns.Sig0StatePublished, keyid); k.parentState != edns0.KeyStateTrusted {
		t.Errorf("the parent's word on the new key is not recorded: %d", k.parentState)
	}
}

// From when the roll's KEY is sent, the leader's zone key is the new key,
// though its own copy still serves the old KEY: what it hands over is the
// new key, and its set-up does not publish the old KEY over the new one.
func TestTheLeaderNamesTheNewKeyOnceItsKEYIsSent(t *testing.T) {
	r := newRollRig(t, "roll.sent.example.")
	k2 := r.start(t) // the copy still serves the old KEY
	zk, err := readZoneKey(r.mpzd.KeyDB, r.zone)
	if err != nil || zk.held == nil || zk.held.keyid != k2 || !zk.rolling {
		t.Fatalf("the zone's key once the new KEY is sent: %+v (%v), want %d, rolling", zk, err, k2)
	}
	r.alog.Reset()
	if err := r.conf.leaderKeySetup(r.ctx, r.zone, false); err != nil {
		t.Errorf("the leader's set-up: %v", err)
	}
	if strings.Contains(r.alog.String(), "publishing KEY to combiner") {
		t.Errorf("the set-up published a KEY during the roll:\n%s", r.alog)
	}
}

// A recipient that keeps the new KEY and applies it not by its role
// (IGNORED) has taken it; a refusal fails the try, and the KEY goes again.
func TestARefusedKEYIsSentAgainAndAnIgnoredOneIsTaken(t *testing.T) {
	r := newRollRig(t, "roll.ignored.example.")
	r.start(t)
	tm := r.conf.InternalMp.MPTransport
	st, _ := tm.rollKEYs.state(r.zone)
	tm.rollKEYs.heard(st.distID, st.expected[0], "PARTIAL", "not all", false)
	r.pass(t, syncOther)
	if ro := r.roll(t); ro == nil || ro.phase != rollPublished || ro.failures != 1 {
		t.Fatalf("the roll after a KEY taken in part: %+v", ro)
	}
	r.due(t)
	r.pass(t, syncOther)
	again, ok := tm.rollKEYs.state(r.zone)
	if !ok || again.distID == st.distID {
		t.Fatalf("the KEY was not sent again after a refusal: %+v", again)
	}
	for i, rcpt := range again.expected {
		status := "SUCCESS"
		if i == 0 {
			status = "IGNORED"
		}
		tm.rollKEYs.heard(again.distID, rcpt, status, "persisted, not applied", false)
	}
	r.pass(t, syncOther)
	if ro := r.roll(t); ro != nil {
		t.Errorf("the roll with an IGNORED word did not end: %+v", ro)
	}
}

// After step 5 the parent is asked to delete the old key, signed with the
// new one, and then trusts the new key alone. The roll is done.
func TestTheOldKeyIsDeletedWithAnUpdateTheNewKeySigns(t *testing.T) {
	r := newRollRig(t, "roll.deleted.example.")
	k2 := r.start(t)
	r.confirmAll(t)
	r.pass(t, syncOther)
	u := r.parent.updates()
	if len(u) != 2 || u[1].what != "delete" || u[1].keyid != r.old.keyid || u[1].signer != k2 || u[1].rcode != dns.RcodeSuccess {
		t.Fatalf("the parent got %+v, want the delete of %d signed with %d", u, r.old.keyid, k2)
	}
	if got := r.parent.trusts(); !slices.Equal(got, []uint16{k2}) {
		t.Errorf("the parent trusts %v, want %d alone", got, k2)
	}
	if ro := r.roll(t); ro != nil {
		t.Errorf("the roll is still kept: %+v", ro)
	}
	if line := r.conf.zoneKeyLine(r.ctx, r.zone); strings.Contains(line, "roll") {
		t.Errorf("the status after the roll: %q", line)
	}
}

// Between steps 3 and 5 the leader hands over the new key, and a voting
// member that imports it holds it active and the old one retired.
func TestEveryVotingMemberHoldsTheRolledKey(t *testing.T) {
	r := newRollRig(t, "roll.members.example.")
	member := NewHsyncDB(newMPTestKeyDB(t))
	if err := importSig0KeyFromPeer(member, string(r.zone), keyData(r.old)); err != nil {
		t.Fatalf("the member's old key: %v", err)
	}
	k2 := r.start(t)
	r.publish(t, r.row(t, tdns.Sig0StatePublished, k2))
	zk, err := readZoneKey(r.mpzd.KeyDB, r.zone)
	if err != nil || zk.held == nil || zk.held.keyid != k2 {
		t.Fatalf("the key the leader hands over: %+v (%v)", zk, err)
	}
	if err := importSig0KeyFromPeer(member, string(r.zone), keyData(*zk.held)); err != nil {
		t.Fatalf("the member's import of the new key: %v", err)
	}
	active, err := activeSig0Rows(member.KeyDB, r.zone)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyIDs(active); !slices.Equal(got, []uint16{k2}) {
		t.Errorf("the member's active keys: %v, want %d alone", got, k2)
	}
	retired := sig0RowByID(member.KeyDB, r.zone, tdns.Sig0StateRetired, r.old.keyid)
	if retired == nil {
		t.Errorf("the member's old key %d is not retired", r.old.keyid)
	}
}

// The key is handed over to a voting member only: a member with no role is
// refused it, the rolled key as every other.
func TestAMemberWithNoRoleIsNotHandedTheRolledKey(t *testing.T) {
	const zone = "roll.norole.example."
	keyZone(t, zone) // alice serves, bob signs, carol audits, dave has no role
	if !mayHoldZoneSig0Key(zone, "alice.agent.example.") {
		t.Error("a voting member may not hold the zone's key")
	}
	if mayHoldZoneSig0Key(zone, "dave.agent.example.") {
		t.Error("a member with no role may hold the zone's key")
	}
}

// A member that takes the leader's KEY keeps it and no other: a KEY held
// under another name goes from its data, and the combiner is asked to drop
// it.
func TestAMemberKeepsTheLeadersKEYAndNoOther(t *testing.T) {
	const zone ZoneName = "roll.onekey.example."
	zdr, _ := NewZoneDataRepo()
	ar, _ := NewAgentRepo()
	zdr.Repo.Set(zone, ar)
	keyOf := func(origin AgentId, rr string) {
		od := tdns.NewOwnerData(string(zone))
		k, err := dns.NewRR(rr)
		if err != nil {
			t.Fatal(err)
		}
		od.RRtypes.Set(dns.TypeKEY, core.RRset{RRs: []dns.RR{k}})
		ar.Set(origin, od)
	}
	keyOf("agent.leader.example.", string(zone)+" 3600 IN KEY 256 3 15 l+upbn5Hdg/DHyxYVZNmqKpkbfD+PG3sXrqg1ozR6Fs=")
	keyOf("agent.earlier.example.", string(zone)+" 3600 IN KEY 256 3 15 yXLRWnJ7mgKYUMxkKMTQ9wjCzX4jUQyqzzhJAo+AkIk=")
	var purged []AgentId
	saved := purgeKEYsAtCombiner
	purgeKEYsAtCombiner = func(_ *MPTransportBridge, _ ZoneName, origins []AgentId) { purged = append(purged, origins...) }
	t.Cleanup(func() { purgeKEYsAtCombiner = saved })

	(&Config{}).dropOtherKEYs(zdr, zone, "agent.leader.example.")
	if od, _ := ar.Get("agent.leader.example."); od == nil || len(od.RRtypes.GetOnlyRRSet(dns.TypeKEY).RRs) != 1 {
		t.Error("the leader's KEY is gone")
	}
	if od, _ := ar.Get("agent.earlier.example."); od == nil {
		t.Fatal("the earlier origin's data is gone")
	} else if _, has := od.RRtypes.Get(dns.TypeKEY); has {
		t.Error("a KEY under another name than the leader's is kept")
	}
	if !slices.Equal(purged, []AgentId{"agent.earlier.example."}) {
		t.Errorf("the combiner is asked to drop the KEYs of %v", purged)
	}
	// the drop at the combiner is S16's flagged removal in the origin's name
	zu := keyPurge(zone, "agent.earlier.example.")
	if zu.Withdraw == nil || zu.AgentId != "agent.earlier.example." || len(zu.Operations) != 1 ||
		zu.Operations[0].Operation != "replace" || zu.Operations[0].RRtype != "KEY" || len(zu.Operations[0].Records) != 0 {
		t.Errorf("the combiner's drop: %+v", zu)
	}
}

// A refused add leaves the old key in use, and the roll owed: the status
// names its next try, and the line says it is tried again.
func TestAFailedAddLeavesTheOldKeyInUse(t *testing.T) {
	r := newRollRig(t, "roll.failedadd.example.")
	r.parent.refuse["add"] = dns.RcodeRefused
	k2 := r.start(t)
	if got := r.active(t); !slices.Equal(got, []uint16{r.old.keyid}) {
		t.Errorf("active keys after a failed add: %v, want %d alone", got, r.old.keyid)
	}
	if why := r.conf.keyHoldReason(r.ctx, r.zone); why != "" {
		t.Errorf("the leader's sync is held after a failed add: %s", why)
	}
	if got := r.parent.trusts(); !slices.Equal(got, []uint16{r.old.keyid}) {
		t.Errorf("the parent trusts %v after a refused add", got)
	}
	ro := r.roll(t)
	if ro == nil || ro.phase != rollMade || ro.failures != 1 || ro.newKeyid != k2 {
		t.Fatalf("the roll after a failed add: %+v", ro)
	}
	if line := r.conf.zoneKeyLine(r.ctx, r.zone); !strings.HasPrefix(line, "roll owed, next try at ") {
		t.Errorf("the status after a failed add: %q", line)
	}
	if !strings.Contains(r.alog.String(), "the roll of the zone's SIG(0) key failed, trying again") {
		t.Errorf("no line for the failed add:\n%s", r.alog)
	}
}

// A refused delete keeps the roll at step 5, the parent trusting both keys,
// and is tried again.
func TestAFailedDeleteIsRetried(t *testing.T) {
	r := newRollRig(t, "roll.faileddelete.example.")
	k2 := r.start(t)
	r.parent.mu.Lock()
	r.parent.refuse["delete"] = dns.RcodeServerFailure
	r.parent.mu.Unlock()
	r.confirmAll(t)
	r.pass(t, syncOther)
	if ro := r.roll(t); ro == nil || ro.phase != rollActivated || ro.failures != 1 {
		t.Fatalf("the roll after a failed delete: %+v", ro)
	}
	if got := r.parent.trusts(); !slices.Equal(got, []uint16{r.old.keyid, k2}) && !slices.Equal(got, []uint16{k2, r.old.keyid}) {
		t.Errorf("the parent trusts %v after a failed delete, want both", got)
	}
	r.due(t)
	r.pass(t, syncOther)
	if ro := r.roll(t); ro != nil {
		t.Errorf("the roll after the delete went through: %+v", ro)
	}
	if got := r.parent.trusts(); !slices.Equal(got, []uint16{k2}) {
		t.Errorf("the parent trusts %v, want %d alone", got, k2)
	}
}

// A failed phase is tried again after roll-retry, not before; the ticker's
// pass carries it then.
func TestAFailedRollIsRetriedOnItsOwnSchedule(t *testing.T) {
	r := newRollRig(t, "roll.schedule.example.")
	r.parent.refuse["add"] = dns.RcodeRefused
	r.start(t)
	ro := r.roll(t)
	if d := time.Until(ro.nextTry); d < rollRetryDefault-time.Minute || d > rollRetryDefault {
		t.Errorf("the next try in %s, want %s", d, rollRetryDefault)
	}
	r.pass(t, syncOther)
	if n := len(r.parent.updates()); n != 1 {
		t.Fatalf("a pass before the next try sent %d updates, want the first alone", n)
	}
	r.due(t)
	r.pass(t, syncOther)
	if ro := r.roll(t); ro == nil || ro.phase != rollPublished {
		t.Errorf("the roll after its retry: %+v", ro)
	}
	if got := rollRetryFor(&MultiProviderConf{Transitions: struct {
		LeavingTimeout int `yaml:"leaving-timeout" mapstructure:"leaving-timeout"`
		NoRoleTimeout  int `yaml:"no-role-timeout" mapstructure:"no-role-timeout"`
		RollRetry      int `yaml:"roll-retry" mapstructure:"roll-retry"`
	}{RollRetry: 30}}); got != 30*time.Second {
		t.Errorf("roll-retry 30 reads %s", got)
	}
}

// The roll's phase is on disk: after a restart, which loses the book of
// the new KEY, the KEY is published again and the roll goes on to done.
func TestTheRollResumesAfterARestart(t *testing.T) {
	r := newRollRig(t, "roll.restart.example.")
	k2 := r.start(t)
	tm := r.conf.InternalMp.MPTransport
	before, _ := tm.rollKEYs.state(r.zone)
	tm.rollKEYs.forget(r.zone) // the restart
	if ro := r.roll(t); ro == nil || ro.phase != rollPublished || ro.newKeyid != k2 {
		t.Fatalf("the roll on disk: %+v", ro)
	}
	r.pass(t, syncOther)
	after, ok := tm.rollKEYs.state(r.zone)
	if !ok || after.distID == before.distID {
		t.Fatalf("the new KEY was not published again after the restart: %+v", after)
	}
	r.confirmAll(t)
	r.pass(t, syncOther)
	if ro := r.roll(t); ro != nil {
		t.Errorf("the roll did not end after the restart: %+v", ro)
	}
	if got := r.active(t); !slices.Equal(got, []uint16{k2}) {
		t.Errorf("active keys after the roll: %v, want %d alone", got, k2)
	}
}

// While the zone agrees on a change of instructions the roll is owed and
// held, and the status says so; a step of the reconciliation passes.
func TestARollIsHeldWhileTheZoneIsAgreeing(t *testing.T) {
	r := newRollRig(t, "roll.agreeing.example.")
	freezeServed(t, r.conf, r.mpzd)
	r.start(t)
	if u := r.parent.updates(); len(u) != 0 {
		t.Fatalf("the parent got %+v during the freeze", u)
	}
	if line := r.conf.zoneKeyLine(r.ctx, r.zone); line != "roll owed, held until the zone's transition is done" {
		t.Errorf("the status during the freeze: %q", line)
	}
	r.pass(t, syncStep)
	if ro := r.roll(t); ro == nil || ro.phase != rollPublished {
		t.Errorf("the roll as a step: %+v", ro)
	}
}

// `agent zone dsync roll-sig0-key` (roll-key at /zone/parentsync) starts
// this roll for a multi-provider zone, refuses a phase of tdns's roll, and
// leaves any other zone to tdns.
func TestTheRollCommandOnAnMPZoneTakesThisPath(t *testing.T) {
	r := newRollRig(t, "roll.command.example.")
	var passed int
	h := r.conf.apiZoneParentSync(r.ctx, func(w http.ResponseWriter, _ *http.Request) { passed++ })
	post := func(req tdns.ZoneParentSyncPost) tdns.ZoneParentSyncResponse {
		body, _ := json.Marshal(req)
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest("POST", "/api/v1/zone/parentsync", bytes.NewReader(body)))
		var resp tdns.ZoneParentSyncResponse
		if w.Body.Len() > 0 {
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("the answer: %v", err)
			}
		}
		return resp
	}
	if resp := post(tdns.ZoneParentSyncPost{Command: "roll-key", Zone: string(r.zone), Action: "add"}); !resp.Error || passed != 0 {
		t.Errorf("a phase of tdns's roll on an MP zone: %+v, passed on %d", resp, passed)
	}
	resp := post(tdns.ZoneParentSyncPost{Command: "roll-key", Zone: string(r.zone), Action: "complete", Algorithm: dns.ED25519})
	if resp.Error || resp.NewKeyID == 0 || !strings.Contains(resp.Msg, "started") || passed != 0 {
		t.Fatalf("the roll command on an MP zone: %+v, passed on %d", resp, passed)
	}
	r.conf.InternalMp.sig0Rolls.wait()
	if ro := r.roll(t); ro == nil || ro.newKeyid != resp.NewKeyID {
		t.Errorf("the roll the command started: %+v", ro)
	}
	if resp := post(tdns.ZoneParentSyncPost{Command: "roll-key", Zone: string(r.zone)}); !resp.Error || !strings.Contains(resp.ErrorMsg, "under way") {
		t.Errorf("a second roll: %+v", resp)
	}
	post(tdns.ZoneParentSyncPost{Command: "roll-key", Zone: "plain.example."})
	post(tdns.ZoneParentSyncPost{Command: "status", Zone: string(r.zone)})
	if passed != 2 {
		t.Errorf("tdns was asked %d times, want 2: a zone with no HSYNC3, and a status", passed)
	}
}
