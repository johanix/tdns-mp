/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
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

// The roll's KEY publishes the zone's key: the hold of a publication that did
// not go out ends there, since no set-up runs during the roll, and the sync it
// kept waiting is asked for at the next tick.
func TestTheRollsKEYEndsTheHoldForAKEYNotPublished(t *testing.T) {
	r := newRollRig(t, "roll.unpublished.example.")
	r.conf.InternalMp.keyPolls.begin(r.zone).end(true)
	r.conf.InternalMp.CatchUp.oweForKey(r.zone)
	if why := r.conf.keyHoldReason(r.ctx, r.zone); why != "not published" {
		t.Fatalf("the rig's hold: %q", why)
	}
	r.start(t)
	if ro := r.roll(t); ro == nil || ro.phase != rollPublished {
		t.Fatalf("the roll: %+v", ro)
	}
	if why := r.conf.keyHoldReason(r.ctx, r.zone); why != "" {
		t.Errorf("the sync is still held once the roll's KEY is sent: %s", why)
	}
	r.conf.retestKeyHolds(r.ctx)
	if r.conf.InternalMp.CatchUp.releaseKeyOwed(r.zone) {
		t.Error("the sync that waited is still owed after the tick")
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

// underAnotherSerial notes distID as sent to the combiner under a serial this
// agent no longer wants, as the gate does: a word on it other than a success
// is not final, and the update goes again (plan S10). The func returned has
// the combiner hold the serial wanted, and the update go again.
func underAnotherSerial(tm *MPTransportBridge, zone ZoneName, distID string) func() {
	handed, wanted := &ActingHandover{Serial: 1}, &ActingHandover{Serial: 2}
	tr := newHandoverTracker("", func(ZoneName, *ZoneUpdate, string) (string, error) { return "", nil })
	z := &zoneHandover{want: wanted, held: handed}
	tr.zones[handoverKey(string(zone))] = z
	tr.sent[distID] = &sentUpdate{zone: zone, update: &ZoneUpdate{}, under: handed, at: time.Now()}
	tm.handover = tr
	return func() {
		tr.mu.Lock()
		z.held = wanted
		tr.mu.Unlock()
		tr.drain(string(zone))
	}
}

// The combiner's IGNORED on a KEY sent under another serial is no final word:
// the KEY goes again, and the old key is not retired or deleted on it.
func TestAWordNotFinalDoesNotEndTheRoll(t *testing.T) {
	r := newRollRig(t, "roll.notfinal.example.")
	k2 := r.start(t)
	tm := r.conf.InternalMp.MPTransport
	st, _ := tm.rollKEYs.state(r.zone)
	sentAgain := underAnotherSerial(tm, r.zone, st.distID)
	word := func(status transport.ConfirmStatus) {
		tm.ChunkHandler.OnConfirmationReceived(confirmIn(st.distID, rigCombiner, status, string(r.zone), nil, nil, nil, nil, false, ""))
	}
	for _, rcpt := range st.expected {
		if rcpt != canonicalName(rigCombiner) {
			tm.rollKEYs.heard(st.distID, rcpt, "SUCCESS", "", false)
		}
	}
	word(transport.ConfirmIgnored)
	r.pass(t, syncOther)
	if ro := r.roll(t); ro == nil || ro.phase != rollPublished || ro.failures != 0 {
		t.Fatalf("the roll after a word not final: %+v", ro)
	}
	if got := r.parent.trusts(); !slices.Contains(got, r.old.keyid) {
		t.Fatalf("the parent trusts %v, without the old key %d", got, r.old.keyid)
	}
	sentAgain()
	word(transport.ConfirmSuccess)
	r.pass(t, syncOther)
	if ro := r.roll(t); ro != nil {
		t.Errorf("the roll did not end on the final word: %+v", ro)
	}
	if got := r.parent.trusts(); !slices.Equal(got, []uint16{k2}) {
		t.Errorf("the parent trusts %v, want %d alone", got, k2)
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

// keyPurgeRig: a member's data with the KEY of the leader, the other
// provider, and one under an earlier leader's name; the sends to the
// combiner are noted, and fail while failSends is set.
type keyPurgeRig struct {
	*rollRig
	zdr       *ZoneDataRepo
	ar        *AgentRepo
	sends     []string
	failSends bool
}

const earlierLeader AgentId = "agent.earlier.example."

func newKeyPurgeRig(t *testing.T, zone string) *keyPurgeRig {
	t.Helper()
	r := &keyPurgeRig{rollRig: newRollRig(t, zone)}
	r.leader(r.them)
	r.zdr, _ = NewZoneDataRepo()
	r.ar, _ = NewAgentRepo()
	r.zdr.Repo.Set(r.zone, r.ar)
	keyOf := func(origin AgentId, public string) {
		od := tdns.NewOwnerData(string(r.zone))
		k, err := dns.NewRR(string(r.zone) + " 3600 IN KEY 256 3 15 " + public)
		if err != nil {
			t.Fatal(err)
		}
		od.RRtypes.Set(dns.TypeKEY, core.RRset{RRs: []dns.RR{k}})
		r.ar.Set(origin, od)
	}
	keyOf(r.them, "l+upbn5Hdg/DHyxYVZNmqKpkbfD+PG3sXrqg1ozR6Fs=")
	keyOf(earlierLeader, "yXLRWnJ7mgKYUMxkKMTQ9wjCzX4jUQyqzzhJAo+AkIk=")
	saved := sendKEYPurge
	sendKEYPurge = func(_ *MPTransportBridge, _ ZoneName, origin AgentId, distID string) error {
		if origin != earlierLeader {
			t.Errorf("the combiner is asked to drop the KEY of %s", origin)
		}
		r.sends = append(r.sends, distID)
		if r.failSends {
			return errors.New("the queue is full")
		}
		return nil
	}
	t.Cleanup(func() { sendKEYPurge = saved })
	return r
}

func (r *keyPurgeRig) holds(origin AgentId) bool {
	od, ok := r.ar.Get(origin)
	return ok && od != nil && len(od.RRtypes.GetOnlyRRSet(dns.TypeKEY).RRs) > 0
}

// dueAgain makes the request for the earlier leader's drop due, as time
// passing would.
func (r *keyPurgeRig) dueAgain() {
	b := &r.conf.InternalMp.MPTransport.keyPurges
	b.mu.Lock()
	defer b.mu.Unlock()
	if s := b.sent[purgeKey(r.zone, earlierLeader)]; s != nil {
		s.at = time.Time{}
	}
}

// A member that takes the leader's KEY keeps it and no other: the combiner
// is asked to drop a KEY held under another name, by S16's flagged removal,
// and it goes from the data once the combiner has.
func TestAMemberKeepsTheLeadersKEYAndNoOther(t *testing.T) {
	r := newKeyPurgeRig(t, "roll.onekey.example.")
	// nothing is asked before the leader's own KEY is here
	r.conf.dropOtherKEYs(r.zdr, r.zone, "agent.nokey.example.")
	if len(r.sends) != 0 || !r.holds(earlierLeader) {
		t.Fatalf("for a leader whose own KEY is not here: %d sends, earlier KEY held %v", len(r.sends), r.holds(earlierLeader))
	}
	r.conf.dropOtherKEYs(r.zdr, r.zone, r.them)
	if len(r.sends) != 1 {
		t.Fatalf("the combiner was asked %d times", len(r.sends))
	}
	r.conf.InternalMp.MPTransport.keyPurges.heard(r.sends[0], "SUCCESS", "", false)
	r.conf.retryKEYPurges(r.zdr)
	if !r.holds(r.them) {
		t.Error("the leader's KEY is gone")
	}
	if r.holds(earlierLeader) {
		t.Error("a KEY under another name than the leader's is kept after the combiner dropped it")
	}
	// the drop at the combiner is S16's flagged removal in the origin's name
	zu := keyPurge(r.zone, earlierLeader)
	if zu.Withdraw == nil || zu.AgentId != earlierLeader || len(zu.Operations) != 1 ||
		zu.Operations[0].Operation != "replace" || zu.Operations[0].RRtype != "KEY" || len(zu.Operations[0].Records) != 0 {
		t.Errorf("the combiner's drop: %+v", zu)
	}
}

// A KEY under another name is not asked to be dropped while the leader's KEY
// is on its way to this agent's combiner, nor after the combiner ignored it: a
// drop that came first would leave the zone with no KEY. The combiner's final
// word on the leader's KEY has the drop asked for then, not at the next tick.
func TestAKEYPurgeWaitsForTheCombinerToHoldTheLeadersKEY(t *testing.T) {
	r := newKeyPurgeRig(t, "roll.purgewait.example.")
	r.zdr.noteCombinerSend(r.zone, r.them, []uint16{dns.TypeKEY}, time.Now(), "leader-key-1")
	r.conf.dropOtherKEYs(r.zdr, r.zone, r.them)
	if len(r.sends) != 0 {
		t.Fatalf("asked to drop while the leader's KEY is on its way: %d sends", len(r.sends))
	}
	r.zdr.noteCombinerFailed(r.zone, "leader-key-1", true, nil)
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 0 {
		t.Fatalf("asked to drop after the combiner ignored the leader's KEY: %d sends", len(r.sends))
	}
	r.zdr.noteCombinerSend(r.zone, r.them, []uint16{dns.TypeKEY}, time.Now(), "leader-key-2")
	r.zdr.noteCombinerConfirmed(r.zone, "leader-key-2", time.Now())
	r.conf.leaderKEYConfirmed(r.zdr, r.zone, "leader-key-2")
	if len(r.sends) != 1 || !r.holds(earlierLeader) {
		t.Fatalf("on the combiner's word on the leader's KEY: %d sends, earlier KEY held %v", len(r.sends), r.holds(earlierLeader))
	}
}

// A drop the combiner has not made is asked for again until it has: after a
// send that failed, a refusal, and a restart that lost the book. Until then
// the KEY stays in the data, the record of what is owed.
func TestAKEYPurgeIsAskedForAgainUntilTheCombinerHasMadeIt(t *testing.T) {
	r := newKeyPurgeRig(t, "roll.purgeagain.example.")
	book := &r.conf.InternalMp.MPTransport.keyPurges

	r.failSends = true
	r.conf.dropOtherKEYs(r.zdr, r.zone, r.them)
	if len(r.sends) != 1 || !r.holds(earlierLeader) {
		t.Fatalf("after a failed send: %d sends, KEY held %v", len(r.sends), r.holds(earlierLeader))
	}
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 1 {
		t.Errorf("the tick asked again within roll-retry: %d sends", len(r.sends))
	}
	r.failSends = false
	r.dueAgain()
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 2 || r.sends[1] == r.sends[0] {
		t.Fatalf("the tick after the failed send: %v", r.sends)
	}

	book.heard(r.sends[1], "PENDING", "", false)
	book.heard(r.sends[1], "REJECTED", "not now", true) // at another serial: no final word
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 2 || !r.holds(earlierLeader) {
		t.Fatalf("with no final word: %d sends, KEY held %v", len(r.sends), r.holds(earlierLeader))
	}
	book.heard(r.sends[1], "REJECTED", "not now", false)
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 3 || !r.holds(earlierLeader) {
		t.Fatalf("after a refusal: %d sends, KEY held %v", len(r.sends), r.holds(earlierLeader))
	}

	book.forget(r.zone, earlierLeader) // the restart
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 4 {
		t.Fatalf("after a restart: %d sends", len(r.sends))
	}
	book.heard(r.sends[0], "SUCCESS", "", false) // a word on an earlier request
	r.conf.retryKEYPurges(r.zdr)
	if !r.holds(earlierLeader) {
		t.Fatal("a word on an earlier request dropped the KEY")
	}

	book.heard(r.sends[3], "SUCCESS", "", false)
	r.conf.retryKEYPurges(r.zdr)
	if r.holds(earlierLeader) {
		t.Error("the KEY is kept after the combiner dropped it")
	}
	r.dueAgain()
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 4 {
		t.Errorf("asked again once dropped: %d sends", len(r.sends))
	}
}

// The combiner's IGNORED on a drop sent under another serial is no final word:
// the KEY stays in the member's data until the word on the drop sent again.
func TestAWordNotFinalDoesNotDropTheKEY(t *testing.T) {
	r := newKeyPurgeRig(t, "roll.purgenotfinal.example.")
	r.conf.dropOtherKEYs(r.zdr, r.zone, r.them)
	if len(r.sends) != 1 {
		t.Fatalf("the combiner was asked %d times", len(r.sends))
	}
	tm := r.conf.InternalMp.MPTransport
	sentAgain := underAnotherSerial(tm, r.zone, r.sends[0])
	word := func(status transport.ConfirmStatus) {
		tm.ChunkHandler.OnConfirmationReceived(confirmIn(r.sends[0], rigCombiner, status, string(r.zone), nil, nil, nil, nil, false, ""))
	}
	word(transport.ConfirmIgnored)
	r.conf.retryKEYPurges(r.zdr)
	if !r.holds(earlierLeader) {
		t.Fatal("a word not final dropped the KEY")
	}
	sentAgain()
	word(transport.ConfirmSuccess)
	r.conf.retryKEYPurges(r.zdr)
	if r.holds(earlierLeader) {
		t.Error("the KEY is kept after the combiner's final word")
	}
}

// A drop of a KEY is the combiner's word alone: a peer answering under the
// drop's distribution ID changes nothing, whatever it says.
func TestOnlyTheCombinerAnswersAKEYPurge(t *testing.T) {
	r := newKeyPurgeRig(t, "roll.purgeword.example.")
	word := func(from string, status transport.ConfirmStatus) {
		r.conf.InternalMp.MPTransport.ChunkHandler.OnConfirmationReceived(confirmIn(r.sends[0], from, status, string(r.zone), nil, nil, nil, nil, false, ""))
	}
	r.conf.dropOtherKEYs(r.zdr, r.zone, r.them)
	if len(r.sends) != 1 {
		t.Fatalf("the combiner was asked %d times", len(r.sends))
	}
	word(string(r.them), transport.ConfirmSuccess)
	r.conf.retryKEYPurges(r.zdr)
	if !r.holds(earlierLeader) {
		t.Fatal("a peer's word dropped the KEY")
	}
	word(string(r.them), transport.ConfirmRejected)
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 1 {
		t.Errorf("a peer's refusal had the drop asked for again: %d sends", len(r.sends))
	}
	word(rigCombiner, transport.ConfirmSuccess)
	r.conf.retryKEYPurges(r.zdr)
	if r.holds(earlierLeader) {
		t.Error("the KEY is kept after the combiner dropped it")
	}
}

// A stored roll that cannot be read is no proof that none runs: no new roll
// starts over it, and nothing reads which key is the zone's without it.
func TestARollThatCannotBeReadIsNotOverwritten(t *testing.T) {
	r := newRollRig(t, "roll.unreadable.example.")
	r.parent.holdTrust = true
	k2 := r.start(t)
	kdb := r.mpzd.KeyDB
	setNextTry := func(v any) {
		t.Helper()
		if _, err := kdb.DB.Exec(`UPDATE MPSig0Rolls SET nexttry = ?`, v); err != nil {
			t.Fatal(err)
		}
	}
	setNextTry("not a time")
	if _, err := loadRoll(kdb, r.zone); err == nil {
		t.Fatal("the rig's roll can still be read")
	}

	_, err := r.conf.startSig0Roll(r.ctx, r.zone, dns.ED25519)
	r.conf.InternalMp.sig0Rolls.wait()
	if err == nil || !strings.Contains(err.Error(), "the roll of the SIG(0) key") {
		t.Errorf("a roll started over one that cannot be read: %v", err)
	}
	if _, err := readZoneKey(kdb, r.zone); err == nil {
		t.Error("the zone's key was read without its roll")
	}
	if published, err := sig0Rows(kdb, r.zone, tdns.Sig0StatePublished); err != nil || len(published) != 1 {
		t.Errorf("published keys: %d, %v", len(published), err)
	}
	setNextTry(0)
	if ro := r.roll(t); ro == nil || ro.newKeyid != k2 {
		t.Errorf("the roll of key %d was overwritten: %+v", k2, ro)
	}
}

// A restart between step 5 in the keystore and its phase on disk resumes at
// the delete, not wedged on the new key no longer kept published.
func TestARollActivatedInTheKeystoreResumesAtTheDelete(t *testing.T) {
	r := newRollRig(t, "roll.crash.example.")
	k2 := r.start(t)
	if err := activateRolledKey(r.mpzd.KeyDB, r.zone, k2, r.old.keyid); err != nil {
		t.Fatal(err)
	}
	r.conf.InternalMp.MPTransport.rollKEYs.forget(r.zone) // the restart
	r.pass(t, syncOther)
	if ro := r.roll(t); ro != nil {
		t.Errorf("the roll did not end: %+v", ro)
	}
	if got := r.parent.trusts(); !slices.Equal(got, []uint16{k2}) {
		t.Errorf("the parent trusts %v, want %d alone", got, k2)
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
	if line := r.conf.zoneKeyLine(r.ctx, r.zone); !strings.HasPrefix(line, "roll owed since ") || !strings.Contains(line, ", next try at ") {
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

// The ticker's pass finds a roll kept in its zone's own keystore, not only
// in the agent's.
func TestTheTickerFindsARollInTheZonesOwnKeystore(t *testing.T) {
	r := newRollRig(t, "roll.ticker.example.")
	r.parent.refuse["add"] = dns.RcodeRefused
	r.start(t)
	if r.conf.Config != nil && r.conf.Config.Internal.KeyDB == r.mpzd.KeyDB {
		t.Fatal("the rig's zone keeps its key in the agent's keystore")
	}
	r.due(t)
	r.conf.rollsDue(r.ctx)
	r.conf.InternalMp.sig0Rolls.wait()
	if ro := r.roll(t); ro == nil || ro.phase != rollPublished {
		t.Errorf("the roll after the ticker's pass: %+v", ro)
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
	if line := r.conf.zoneKeyLine(r.ctx, r.zone); !strings.HasPrefix(line, "roll owed since ") || !strings.HasSuffix(line, ", held until the zone's transition is done") {
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

// A roll whose agent another one now leads ends there as a member's keys
// would: with the zone publishing the new KEY, the new key is active and the
// old one retired; a new key that never left the agent is deleted.
func TestARollWhoseLeadMovesEndsHere(t *testing.T) {
	t.Run("published", func(t *testing.T) {
		r := newRollRig(t, "roll.leadmoves.example.")
		k2 := r.start(t)
		r.publish(t, r.row(t, tdns.Sig0StatePublished, k2))
		r.leader(r.them)
		r.pass(t, syncOther)
		if ro := r.roll(t); ro != nil {
			t.Fatalf("the roll is kept at an agent that no longer leads: %+v", ro)
		}
		if got := r.active(t); !slices.Equal(got, []uint16{k2}) {
			t.Errorf("active keys: %v, want %d alone", got, k2)
		}
		if st := r.keyState(t, r.old.keyid); st != tdns.Sig0StateRetired {
			t.Errorf("the old key is %s, want %s", st, tdns.Sig0StateRetired)
		}
		if !strings.Contains(r.alog.String(), "the roll of the zone's SIG(0) key ends here") {
			t.Errorf("no line for the end:\n%s", r.alog)
		}
	})
	t.Run("made", func(t *testing.T) {
		r := newRollRig(t, "roll.leadmoves.made.example.")
		r.parent.refuse["add"] = dns.RcodeRefused
		k2 := r.start(t)
		r.leader(r.them)
		r.due(t)
		r.pass(t, syncOther)
		if ro := r.roll(t); ro != nil {
			t.Fatalf("the roll is kept: %+v", ro)
		}
		if k := sig0RowByID(r.mpzd.KeyDB, r.zone, tdns.Sig0StatePublished, k2); k != nil {
			t.Errorf("the new key that never left the agent is kept")
		}
		if got := r.active(t); !slices.Equal(got, []uint16{r.old.keyid}) {
			t.Errorf("active keys: %v, want %d alone", got, r.old.keyid)
		}
	})
}

// A leader that holds the zone's key, trusted, deletes at the parent a
// retired key of the zone the parent still trusts, signed with the zone's
// key, and does not ask about it again (a roll its leader left half done).
func TestTheLeaderDeletesARetiredKeyTheParentStillTrusts(t *testing.T) {
	r := newRollRig(t, "roll.sweep.example.")
	k2 := testSig0Key(t, r.mpzd.KeyDB, string(r.zone))
	if err := sig0KeyChange(r.mpzd.KeyDB, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "setstate",
		Keyname: string(r.zone), Keyid: r.old.keyid, State: tdns.Sig0StateRetired}); err != nil {
		t.Fatal(err)
	}
	r.publish(t, k2)
	trustKey(r.mpzd.KeyDB, string(r.zone), k2.keyid)
	r.parent.trusted[k2.keyid] = true // the parent trusts both

	r.conf.sweepRetiredKeys(r.ctx, r.zone)
	u := r.parent.updates()
	if len(u) != 1 || u[0].what != "delete" || u[0].keyid != r.old.keyid || u[0].signer != k2.keyid || u[0].rcode != dns.RcodeSuccess {
		t.Fatalf("the parent got %+v, want the delete of %d signed with %d", u, r.old.keyid, k2.keyid)
	}
	if got := r.parent.trusts(); !slices.Equal(got, []uint16{k2.keyid}) {
		t.Errorf("the parent trusts %v, want %d alone", got, k2.keyid)
	}
	r.conf.InternalMp.sig0Rolls.mu.Lock()
	r.conf.InternalMp.sig0Rolls.swept = nil
	r.conf.InternalMp.sig0Rolls.mu.Unlock()
	r.conf.sweepRetiredKeys(r.ctx, r.zone)
	if n := len(r.parent.updates()); n != 1 {
		t.Errorf("a second sweep sent %d updates, want none more", n-1)
	}
}

// The roll a removal owes is on disk from the first step. Its passes make the
// key on the roll's own schedule and run as a step while the removal is under
// way (plan S17b).
func TestARollARemovalOwesIsMadeByItsPasses(t *testing.T) {
	r := newRollRig(t, "owed.roll.example.")
	r.conf.oweRoll(r.zone)
	ro := r.roll(t)
	if ro == nil || ro.phase != rollOwed || ro.newKeyid != 0 {
		t.Fatalf("the roll owed: %+v", ro)
	}
	if line := r.conf.rollLine(r.mpzd.KeyDB, r.zone); !strings.HasPrefix(line, "roll owed since ") || !strings.HasSuffix(line, ", the new key is not made yet") {
		t.Errorf("the status: %q", line)
	}
	r.conf.oweRoll(r.zone) // a new leader's turn, or a restart's: no second
	r.pass(t, syncStep)
	ro = r.roll(t)
	if ro == nil || ro.phase == rollOwed || ro.oldKeyid != r.old.keyid || ro.newKeyid == 0 {
		t.Fatalf("the roll after a pass: %+v", ro)
	}
}

// A new key that cannot be made now is tried again, on the roll's schedule:
// the obligation stands. (A key the parent's word on is not recorded for
// waits instead, with no try counted: TestARollOwedWaitsForTheParentsWordOnTheKey.)
func TestARollOwedThatCannotBeMadeIsTriedAgain(t *testing.T) {
	r := newRollRig(t, "owedagain.roll.example.")
	extra := testSig0Key(t, r.mpzd.KeyDB, string(r.zone)) // a second active key: no new key is made
	r.conf.oweRoll(r.zone)
	r.pass(t, syncStep)
	ro := r.roll(t)
	if ro == nil || ro.phase != rollOwed || ro.failures != 1 || ro.nextTry.IsZero() {
		t.Fatalf("the roll after a failed pass: %+v", ro)
	}
	if err := sig0KeyChange(r.mpzd.KeyDB, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "setstate", Keyname: dns.Fqdn(string(r.zone)), Keyid: extra.keyid, State: tdns.Sig0StateRetired}); err != nil {
		t.Fatal(err)
	}
	r.due(t)
	r.pass(t, syncStep)
	if ro = r.roll(t); ro == nil || ro.phase == rollOwed {
		t.Errorf("the roll once it can be made: %+v", ro)
	}
}

// A leader whose key has no recorded word from the parent yet, such as one it
// imported from the leader before it, waits for that word instead of failing.
// No roll-retry is counted: its offers in this lead ask the parent, and the
// ticker's next pass after the word makes the new key (the rig's x2l-update,
// 2026-11-05).
func TestARollOwedWaitsForTheParentsWordOnTheKey(t *testing.T) {
	r := newRollRig(t, "owedwaits.roll.example.")
	tdns.UpdateParentState(r.mpzd.KeyDB, string(r.zone), r.old.keyid, edns0.KeyStateUnknown)
	r.conf.oweRoll(r.zone)
	r.pass(t, syncStep)
	ro := r.roll(t)
	if ro == nil || ro.phase != rollOwed || ro.failures != 0 || !ro.nextTry.IsZero() {
		t.Fatalf("the roll while the parent's word is not recorded: %+v", ro)
	}
	trustKey(r.mpzd.KeyDB, string(r.zone), r.old.keyid)
	r.pass(t, syncStep)
	if ro = r.roll(t); ro == nil || ro.phase == rollOwed || ro.newKeyid == 0 {
		t.Errorf("the roll at the pass after the parent's word: %+v", ro)
	}
}

// debtStore gives the rig an instruction store of its own, which keeps the
// roll owed.
func debtStore(t *testing.T, conf *Config) *InstructionStore {
	t.Helper()
	_, hdb := keptDB(t)
	s := loadStore(t, hdb)
	conf.InternalMp.Instructions = s
	return s
}

// The roll owed is kept with the zone's serials, told in this agent's stamp,
// and ended when the roll is done (here: a zone with no key to roll), whatever
// its phase; the roll done is told too (plan S17b; the project owner,
// 2026-11-05).
func TestARollOwedIsKeptAndToldUntilItIsDone(t *testing.T) {
	r := newKeyRoundRig(t, "debt.nokey.roll.example.", "NOTIFY")
	t.Cleanup(r.conf.InternalMp.sig0Rolls.wait)
	r.caughtUp()
	s := debtStore(t, r.conf)
	r.conf.oweRoll(r.zone)
	owed, _ := s.rollDebt(string(r.zone))
	if owed.IsZero() {
		t.Fatal("the roll owed is not kept with the zone's serials")
	}
	if st, ok := s.stampOf(string(r.zone)); !ok || !st.RollOwed.Equal(owed) {
		t.Errorf("the stamp does not tell the roll owed: %+v", st)
	}
	waitUntil(t, "a pass of the roll still runs", func() bool { return r.conf.rollOnce(r.ctx, r.zone, syncStep) })
	owed, done := s.rollDebt(string(r.zone))
	if !owed.IsZero() || done.IsZero() {
		t.Errorf("after the roll is done: owed %v, done %v", owed, done)
	}
	if st, _ := s.stampOf(string(r.zone)); !st.RollOwed.IsZero() || st.RollDone.IsZero() {
		t.Errorf("the stamp after the roll is done: owed %v, done %v", st.RollOwed, st.RollDone)
	}
}

// A leader with a roll owed and none on its disk owes it itself: the debt it
// heard while a member, or kept from an earlier lead, outlives that lead.
func TestALeaderOwesTheRollOwedThatItHolds(t *testing.T) {
	r := newRollRig(t, "debt.leader.roll.example.")
	s := debtStore(t, r.conf)
	if err := s.noteRollDebt(string(r.zone), time.Now().Add(-time.Minute), time.Time{}); err != nil {
		t.Fatal(err)
	}
	r.conf.rollDebtTurn(string(r.zone))
	if ro := r.roll(t); ro == nil || ro.phase != rollOwed {
		t.Fatalf("the leader did not owe the roll it held: %+v", ro)
	}
	if line := r.conf.rollLine(r.mpzd.KeyDB, r.zone); !strings.Contains(line, "roll owed since "+removalTime(time.Now().Add(-time.Minute))) {
		t.Errorf("the status does not say since when, by the zone's debt: %q", line)
	}
}

// A roll that a pass ends as the leader's turn reads the debt is not owed
// again: the turn looks under the zone's key setup, where the pass notes the
// roll done and forgets it.
func TestARollEndedAsTheTurnLooksIsNotOwedAgain(t *testing.T) {
	r := newRollRig(t, "debt.race.roll.example.")
	s := debtStore(t, r.conf)
	if err := s.noteRollDebt(string(r.zone), time.Now().Add(-time.Minute), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := saveRoll(r.mpzd.KeyDB, &sig0Roll{zone: r.zone, phase: rollActivated, started: time.Now()}); err != nil {
		t.Fatal(err)
	}
	turned := make(chan struct{})
	_ = r.conf.keySetupLocked(r.zone, func() error {
		// the pass's end, the roll forgotten before its done is noted, with
		// the turn under way meanwhile
		if err := deleteRoll(r.mpzd.KeyDB, r.zone); err != nil {
			t.Fatal(err)
		}
		go func() {
			defer close(turned)
			r.conf.rollDebtTurn(string(r.zone))
		}()
		time.Sleep(100 * time.Millisecond)
		if err := s.noteRollDebt(string(r.zone), time.Time{}, time.Now()); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	<-turned
	if ro := r.roll(t); ro != nil {
		t.Errorf("the roll ended was owed again: %+v", ro)
	}
}

// A roll owed for more than twice roll-retry is warned of, once an hour.
func TestARollOwedTooLongIsWarnedOf(t *testing.T) {
	r := newRollRig(t, "debt.warn.roll.example.")
	s := debtStore(t, r.conf)
	if err := s.noteRollDebt(string(r.zone), time.Now().Add(-3*rollRetryFor(r.conf.MpConfig())), time.Time{}); err != nil {
		t.Fatal(err)
	}
	r.conf.rollDebtTurn(string(r.zone))
	r.conf.rollDebtTurn(string(r.zone))
	if n := strings.Count(r.alog.String(), "has been owed for more than twice roll-retry"); n != 1 {
		t.Errorf("%d warnings, want 1:\n%s", n, r.alog)
	}
}

// A roll that a pass finds owed in a zone that uses no key ends: the zone has
// nothing to roll.
func TestARollOwedInAZoneWithNoKeyEnds(t *testing.T) {
	r := newKeyRoundRig(t, "nokey.roll.example.", "NOTIFY")
	t.Cleanup(r.conf.InternalMp.sig0Rolls.wait)
	r.caughtUp()
	r.conf.oweRoll(r.zone)
	waitUntil(t, "a pass of the roll still runs", func() bool { return r.conf.rollOnce(r.ctx, r.zone, syncStep) })
	if ro, err := loadRoll(r.mpzd.KeyDB, r.zone); err != nil || ro != nil {
		t.Errorf("the roll: %+v, %v", ro, err)
	}
}

// formerLeaderRig: this agent led the zone and sent its KEY straight to its
// combiner (sendZoneKEY), so its data holds no KEY of its own. The other
// provider leads now. The drops asked of the combiner are noted by origin.
type formerLeaderRig struct {
	*rollRig
	zdr   *ZoneDataRepo
	ar    *AgentRepo
	sends []AgentId
	dists []string
}

func newFormerLeaderRig(t *testing.T, zone string) *formerLeaderRig {
	t.Helper()
	r := &formerLeaderRig{rollRig: newRollRig(t, zone)}
	r.leader(r.them)
	r.zdr, _ = NewZoneDataRepo()
	r.ar, _ = NewAgentRepo()
	r.zdr.Repo.Set(r.zone, r.ar)
	saved := sendKEYPurge
	sendKEYPurge = func(_ *MPTransportBridge, _ ZoneName, origin AgentId, distID string) error {
		r.sends = append(r.sends, origin)
		r.dists = append(r.dists, distID)
		return nil
	}
	t.Cleanup(func() { sendKEYPurge = saved })
	return r
}

// holdsKEY puts key in this agent's data under origin's name.
func (r *formerLeaderRig) holdsKEY(origin AgentId, key *dns.KEY) {
	od := tdns.NewOwnerData(string(r.zone))
	od.RRtypes.Set(dns.TypeKEY, core.RRset{RRs: []dns.RR{key}})
	r.ar.Set(origin, od)
}

// The lead moves to a provider and the former leader stays. The new leader's
// roll replaces its own KEY only, so the zone publishes the former's beside
// the new one (the rig's x2l-update, where that held every sync of the
// leader). The former leader's combiner is asked to drop the KEY in its own
// name once the zone publishes the two, and not before: the new KEY might
// not be there yet, and the zone would have none. It is asked again if the
// KEY comes back (the combiner's own read).
func TestAFormerLeaderThatStaysDropsItsOwnKEYAfterTheNewLeadersRoll(t *testing.T) {
	r := newFormerLeaderRig(t, "roll.formerstays.example.")
	self := r.conf.localAgentID()
	if self == "" || sameName(string(self), string(r.them)) {
		t.Fatalf("the rig's identities: %q, %q", self, r.them)
	}
	book := &r.conf.InternalMp.MPTransport.keyPurges
	rolled := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.holdsKEY(r.them, rolled.key)

	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 0 {
		t.Fatalf("with the new KEY not published yet the combiner was asked for %v", r.sends)
	}

	r.publish(t, r.old, rolled)
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 1 || r.sends[0] != self {
		t.Fatalf("with the zone publishing both KEYs the combiner was asked for %v, want %s's", r.sends, self)
	}
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 1 {
		t.Errorf("the tick asked again within roll-retry: %v", r.sends)
	}
	book.heard(r.dists[0], "SUCCESS", "", false)
	r.conf.dropOtherKEYs(r.zdr, r.zone, r.them)
	if len(r.sends) != 1 {
		t.Errorf("asked again after the combiner's word, with the zone not refreshed yet: %v", r.sends)
	}

	r.publish(t, rolled)
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 1 {
		t.Errorf("asked again with the zone publishing the leader's KEY alone: %v", r.sends)
	}
	r.publish(t, r.old, rolled)
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 2 || r.sends[1] != self {
		t.Errorf("the KEY came back, and the combiner was asked for %v", r.sends)
	}
}

// After a restart the combiner's own read can put the former leader's KEY in
// its data. It goes by the same rule, and leaves the data once dropped.
func TestAFormerLeadersOwnKEYInItsDataGoesOnceTheCombinerHasDroppedIt(t *testing.T) {
	r := newFormerLeaderRig(t, "roll.formerdata.example.")
	self := r.conf.localAgentID()
	rolled := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.holdsKEY(r.them, rolled.key)
	r.holdsKEY(self, r.old.key)
	r.publish(t, r.old, rolled)
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 1 || r.sends[0] != self {
		t.Fatalf("the combiner was asked for %v", r.sends)
	}
	held := func() int {
		od, ok := r.ar.Get(self)
		if !ok || od == nil {
			return 0
		}
		return len(od.RRtypes.GetOnlyRRSet(dns.TypeKEY).RRs)
	}
	r.conf.retryKEYPurges(r.zdr)
	if held() != 1 {
		t.Error("the KEY left the data before the combiner's word")
	}
	r.conf.InternalMp.MPTransport.keyPurges.heard(r.dists[0], "SUCCESS", "", false)
	r.conf.retryKEYPurges(r.zdr)
	if held() != 0 {
		t.Error("the KEY stayed in the data after the combiner dropped it")
	}
	if len(r.sends) != 1 {
		t.Errorf("the combiner was asked for %v", r.sends)
	}
}

// A leader has no earlier KEY of its own to drop, whatever the zone publishes:
// another KEY beside its own is not one its own name holds.
func TestALeaderDropsNoKEYOfItsOwnName(t *testing.T) {
	r := newFormerLeaderRig(t, "roll.leaderkeeps.example.")
	self := r.conf.localAgentID()
	r.leader(self)
	other := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.holdsKEY(self, r.old.key)
	r.publish(t, r.old, other)
	r.conf.dropOtherKEYs(r.zdr, r.zone, self)
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 0 {
		t.Errorf("the leader asked for the drop of %v", r.sends)
	}
}

// Several KEYs that do not include the leader's are the operator's to sort
// out (decision 98): this agent's own name is not asked to drop anything.
func TestSeveralKEYsWithoutTheLeadersDropNothingOfThisAgents(t *testing.T) {
	r := newFormerLeaderRig(t, "roll.notleaders.example.")
	other := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	third := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.holdsKEY(r.them, third.key)
	r.publish(t, r.old, other)
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 0 {
		t.Errorf("the combiner was asked for %v", r.sends)
	}
}

// A lead move with no roll: the new leader publishes the key the former one
// did, and the zone publishes that one KEY. Nothing is owed, and a leader's
// KEY that reached the combiner without its instruction is there under the
// former's name alone (see the next test), so dropping that name could leave
// the zone with none. It stays, also when the combiner's own read has put it
// in this agent's data after a restart.
func TestALeadMoveWithNoRollKeepsTheOnlyKEYItHas(t *testing.T) {
	r := newFormerLeaderRig(t, "roll.moveonly.example.")
	self := r.conf.localAgentID()
	r.holdsKEY(r.them, r.old.key)
	r.conf.dropOtherKEYs(r.zdr, r.zone, r.them)
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 0 {
		t.Errorf("with its own KEY not in its data the combiner was asked for %v", r.sends)
	}
	r.holdsKEY(self, r.old.key)
	r.conf.dropOtherKEYs(r.zdr, r.zone, r.them)
	r.conf.retryKEYPurges(r.zdr)
	if len(r.sends) != 0 {
		t.Errorf("with its own KEY in its data the combiner was asked for %v", r.sends)
	}
	if od, ok := r.ar.Get(self); !ok || od == nil || len(od.RRtypes.GetOnlyRRSet(dns.TypeKEY).RRs) != 1 {
		t.Error("this agent's data lost the KEY")
	}
}

// The same, at a real combiner. A leader's KEY that the combiner's own agent
// has published too stays under the local name alone, until the instruction
// that comes with it files it under the leader's as well. The next leader's
// roll replaces the leader's name only, so the two stand side by side, which
// is what the agent then sees at the apex. The drop the former leader's agent
// asks for takes its KEY and its instruction, and leaves the leader's.
func TestTheCombinerHoldsAFormerLeadersKEYBesideTheRolledOneUntilItIsDropped(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "roll.formerkey.combiner.example.", true, true)
	zone := mpzd.ZoneName
	local := map[string]bool{csyncOurAgent: true}
	update := func(sender string, key *dns.KEY, instr *core.PublishInstruction) {
		t.Helper()
		resp := CombinerProcessUpdate(&CombinerSyncRequest{SenderID: sender, DeliveredBy: csyncOurAgent, Zone: zone,
			Operations:     []core.RROperation{{Operation: "replace", RRtype: "KEY", Records: []string{key.String()}}},
			Publish:        instr,
			DistributionID: nextDistributionID(), Timestamp: time.Now()}, nil, local, hdb, nil)
		if resp.Status != "ok" {
			t.Fatalf("%s's KEY: %s: %s (%v)", sender, resp.Status, resp.Message, resp.RejectedItems)
		}
	}
	instruction := func(key *dns.KEY) *core.PublishInstruction {
		return &core.PublishInstruction{KEYRRs: []string{key.String()}, Locations: []string{"at-apex"}}
	}
	holds := func(sender string) []dns.RR {
		return mpzd.MP.AgentContributions[sender][zone][dns.TypeKEY].RRs
	}
	first := testSig0Key(t, newMPTestKeyDB(t), zone)
	rolled := testSig0Key(t, newMPTestKeyDB(t), zone)

	update(csyncOurAgent, first.key, instruction(first.key))
	update(csyncLeaderA, first.key, nil)
	if len(holds(csyncOurAgent)) != 1 || len(holds(csyncLeaderA)) != 0 {
		t.Fatalf("the same key with no instruction: %v under the local name, %v under the leader's", holds(csyncOurAgent), holds(csyncLeaderA))
	}
	update(csyncLeaderA, first.key, instruction(first.key))
	if len(holds(csyncOurAgent)) != 1 || len(holds(csyncLeaderA)) != 1 {
		t.Fatalf("the same key with its instruction: %v under the local name, %v under the leader's", holds(csyncOurAgent), holds(csyncLeaderA))
	}

	update(csyncLeaderA, rolled.key, instruction(rolled.key))
	if got := holds(csyncOurAgent); len(got) != 1 || !sameKey(asKEY(got[0]), first.key) {
		t.Fatalf("the local name after the roll: %v", got)
	}
	if got := holds(csyncLeaderA); len(got) != 1 || !sameKey(asKEY(got[0]), rolled.key) {
		t.Fatalf("the leader's name after the roll: %v", got)
	}

	zu := keyPurge(ZoneName(zone), csyncOurAgent)
	resp := CombinerProcessUpdate(&CombinerSyncRequest{SenderID: string(zu.AgentId), DeliveredBy: csyncOurAgent, Zone: zone,
		Operations: zu.Operations, Publish: zu.Publish, Removal: zu.Withdraw != nil,
		DistributionID: nextDistributionID(), Timestamp: time.Now()}, nil, local, hdb, nil)
	if resp.Status != "ok" {
		t.Fatalf("the drop: %s: %s", resp.Status, resp.Message)
	}
	if got := holds(csyncOurAgent); len(got) != 0 {
		t.Errorf("the former leader's KEY after the drop: %v", got)
	}
	if got := holds(csyncLeaderA); len(got) != 1 || !sameKey(asKEY(got[0]), rolled.key) {
		t.Errorf("the leader's KEY after the drop: %v", got)
	}
	if stored, err := GetPublishInstruction(hdb, zone, csyncOurAgent); err != nil || stored != nil {
		t.Errorf("the former leader's instruction after the drop: %+v, %v", stored, err)
	}
	if stored, err := GetPublishInstruction(hdb, zone, csyncLeaderA); err != nil || stored == nil {
		t.Errorf("the leader's instruction after the drop: %+v, %v", stored, err)
	}
}

func asKEY(rr dns.RR) *dns.KEY {
	k, _ := rr.(*dns.KEY)
	return k
}

// A purge older than the origin's last KEY REPLACE takes nothing back: the
// queue can deliver it after that REPLACE, and its empty replace is refused
// as stale, so its retraction must not take the newer KEY and its instruction
// (an agent that lost the lead and quickly had it back). One newer than the
// REPLACE drops both.
func TestAPurgeOlderThanTheLastKEYTakesNothingBack(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "roll.stalepurge.combiner.example.", true, true)
	zone := mpzd.ZoneName
	local := map[string]bool{csyncOurAgent: true}
	key := testSig0Key(t, newMPTestKeyDB(t), zone).key
	at := time.Now()
	resp := CombinerProcessUpdate(&CombinerSyncRequest{SenderID: csyncLeaderA, DeliveredBy: csyncOurAgent, Zone: zone,
		Operations:     []core.RROperation{{Operation: "replace", RRtype: "KEY", Records: []string{key.String()}}},
		Publish:        &core.PublishInstruction{KEYRRs: []string{key.String()}, Locations: []string{"at-apex"}},
		DistributionID: nextDistributionID(), Timestamp: at}, nil, local, hdb, nil)
	if resp.Status != "ok" {
		t.Fatalf("the KEY: %s: %s (%v)", resp.Status, resp.Message, resp.RejectedItems)
	}
	purge := func(when time.Time) *CombinerSyncResponse {
		t.Helper()
		zu := keyPurge(ZoneName(zone), csyncLeaderA)
		return CombinerProcessUpdate(&CombinerSyncRequest{SenderID: string(zu.AgentId), DeliveredBy: csyncOurAgent, Zone: zone,
			Operations: zu.Operations, Publish: zu.Publish, Removal: zu.Withdraw != nil,
			DistributionID: nextDistributionID(), Timestamp: when}, nil, local, hdb, nil)
	}
	holds := func() int { return len(mpzd.MP.AgentContributions[csyncLeaderA][zone][dns.TypeKEY].RRs) }
	stored := func() *StoredPublishInstruction {
		t.Helper()
		s, err := GetPublishInstruction(hdb, zone, csyncLeaderA)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	// the older drop is refused, not told as made: its agent asks again
	// (CodeRabbit at 290cd90)
	if resp := purge(at.Add(-time.Minute)); resp.Status == "ok" || len(resp.RejectedItems) != 1 {
		t.Errorf("the older purge: %s: %s (%v)", resp.Status, resp.Message, resp.RejectedItems)
	}
	if holds() != 1 || stored() == nil {
		t.Errorf("after an older purge: %d KEYs held, instruction %+v", holds(), stored())
	}
	if resp := purge(at.Add(time.Minute)); resp.Status != "ok" {
		t.Fatalf("the newer purge: %s: %s", resp.Status, resp.Message)
	}
	if holds() != 0 || stored() != nil {
		t.Errorf("after a newer purge: %d KEYs held, instruction %+v", holds(), stored())
	}
}

// An older KEY that comes with its instruction after a newer one, as the
// queue can deliver it, does not put the older KEY back: its replace is
// refused as stale, and so is its instruction, which would otherwise apply
// the older KEY and be kept in the newer one's place.
func TestAnOlderKEYWithItsInstructionDoesNotComeBack(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "roll.stalekey.combiner.example.", true, true)
	zone := mpzd.ZoneName
	local := map[string]bool{csyncOurAgent: true}
	newer := testSig0Key(t, newMPTestKeyDB(t), zone).key
	older := testSig0Key(t, newMPTestKeyDB(t), zone).key
	at := time.Now()
	send := func(key *dns.KEY, when time.Time) {
		t.Helper()
		resp := CombinerProcessUpdate(&CombinerSyncRequest{SenderID: csyncLeaderA, DeliveredBy: csyncOurAgent, Zone: zone,
			Operations:     []core.RROperation{{Operation: "replace", RRtype: "KEY", Records: []string{key.String()}}},
			Publish:        &core.PublishInstruction{KEYRRs: []string{key.String()}, Locations: []string{"at-apex"}},
			DistributionID: nextDistributionID(), Timestamp: when}, nil, local, hdb, nil)
		if resp.Status != "ok" {
			t.Fatalf("the KEY: %s: %s (%v)", resp.Status, resp.Message, resp.RejectedItems)
		}
	}
	send(newer, at)
	send(older, at.Add(-time.Minute))
	if got := mpzd.MP.AgentContributions[csyncLeaderA][zone][dns.TypeKEY].RRs; len(got) != 1 || !sameKey(asKEY(got[0]), newer) {
		t.Errorf("the KEY held after an older one came: %v", got)
	}
	stored, err := GetPublishInstruction(hdb, zone, csyncLeaderA)
	if err != nil || stored == nil || len(stored.KEYRRs) != 1 || stored.KEYRRs[0] != newer.String() {
		t.Errorf("the instruction kept after an older one came: %+v, %v", stored, err)
	}
}

// severalRig: this agent leads, holds the zone's key, which the stand-in
// parent trusts, and the apex carries it beside a KEY no agent holds.
func newSeveralRig(t *testing.T, zone string) *rollRig {
	t.Helper()
	r := newRollRig(t, zone)
	other := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.publish(t, r.old, other)
	return r
}

// explicitSync is the answer to an explicit sync, and whether an UPDATE went
// out for it.
func (r *rollRig) explicitSync(t *testing.T) (string, bool) {
	t.Helper()
	before := r.keyRoundRig.parent.updatesSeen()
	resp := make(chan tdns.DelegationSyncStatus, 1)
	r.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: string(r.zone), ZoneData: r.mpzd.ZoneData, Response: resp}
	got, ok := recvWithin(resp, 5*time.Second)
	if !ok {
		t.Fatal("no answer to the sync")
	}
	return got.Msg + got.ErrorMsg, r.keyRoundRig.parent.updatesSeen() > before
}

func (r *rollRig) parentForgets(keyid uint16) {
	r.parent.mu.Lock()
	defer r.parent.mu.Unlock()
	delete(r.parent.trusted, keyid)
}

// The project owner's rule (2026-11-05): several KEYs at the apex do not hold
// a sync signed with this agent's one active key, which the parent trusts: the
// parent is asked in this lead, and several KEYs are a warning.
func TestSeveralKEYsDoNotHoldASyncSignedWithAKeyTheParentTrusts(t *testing.T) {
	r := newSeveralRig(t, "several.signs.example.")
	got, sent := r.explicitSync(t)
	if !sent {
		t.Fatalf("no UPDATE went out: %q", got)
	}
	if !strings.Contains(r.alog.String(), "the sync signs with this agent's key, which the parent trusts") {
		t.Errorf("no warning of several KEYs:\n%s", r.alog)
	}
}

// Without the parent's word in this lead, a recorded parent_state does not
// let the sync sign: the parent is asked, and one that does not trust the key
// holds the sync, and has its word kept.
func TestSeveralKEYsHoldASyncTheParentDoesNotTrustTheKeyFor(t *testing.T) {
	r := newSeveralRig(t, "several.untrusted.example.")
	r.parentForgets(r.old.keyid)
	got, sent := r.explicitSync(t)
	if sent || !strings.Contains(got, "is not heard in this lead") {
		t.Errorf("the sync went out or was held for another reason: sent %v, %q", sent, got)
	}
	if zk, err := readZoneKey(r.mpzd.KeyDB, r.zone); err != nil || len(zk.active) != 1 || zk.active[0].parentState == edns0.KeyStateTrusted {
		t.Error("the parent's word that it does not trust the key is not kept")
	}
}

// The parent's word counts in the lead that heard it only: after the lead has
// moved and come back, an earlier word does not let the sync sign.
func TestAWordFromAnEarlierLeadDoesNotLetSeveralKEYsSign(t *testing.T) {
	r := newSeveralRig(t, "several.earlierlead.example.")
	if _, sent := r.explicitSync(t); !sent {
		t.Fatal("no UPDATE went out in the first lead")
	}
	self := r.conf.localAgentID()
	r.leader(r.them)
	r.leader(self)
	r.parentForgets(r.old.keyid)
	if got, sent := r.explicitSync(t); sent || !strings.Contains(got, "is not heard in this lead") {
		t.Errorf("a word from the earlier lead let the sync sign: sent %v, %q", sent, got)
	}
}

// Right before the send the parent is asked again: a key it no longer trusts
// does not sign, so no BADKEY and no bootstrap of it, whatever this lead heard.
func TestSeveralKEYsSendNothingWithAKeyTheParentNoLongerTrusts(t *testing.T) {
	r := newSeveralRig(t, "several.nolonger.example.")
	if _, sent := r.explicitSync(t); !sent {
		t.Fatal("no UPDATE went out while the parent trusted the key")
	}
	r.parentForgets(r.old.keyid)
	if got, sent := r.explicitSync(t); sent || !strings.Contains(got, "does not trust key") {
		t.Errorf("a key the parent no longer trusts signed: sent %v, %q", sent, got)
	}
	// and that word ends this lead's: the next sync is held for the key, and
	// owed, rather than failing at the send again (CodeRabbit at bba7a10)
	if got, sent := r.explicitSync(t); sent || !strings.Contains(got, "is not heard in this lead") {
		t.Errorf("the sync after the parent's refusal: sent %v, %q", sent, got)
	}
}
