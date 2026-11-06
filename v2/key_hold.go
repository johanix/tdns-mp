/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The leader's sync waits for the zone's SIG(0) key (step 7b, settle point 1).
//
// tdns signs the leader's UPDATE with the first active key row, and on BADKEY
// uploads that key to the parent as a bootstrap, without waiting for the key
// to be served. A sync signed with a key the parent does not trust yet, or
// with a key that is not the zone's, starts that. So the leader's sync of a
// zone that uses a key waits while
//
//   - the key tdns would sign with is not the zone's key (readZoneKey), or
//     there is not exactly one active key; or
//   - a poll of the zone's key with its parent runs in this process
//     (ParentSyncAfterKeyPublication): it bootstraps the key once the key
//     is served, and the sync signed with it waits for that; or
//   - a key this agent made or took was not published; or
//   - the parent does not trust the zone's key yet, by what tdns last
//     recorded of it (keyPending, plan S14): every sync the leader asks for,
//     the election's included, waits until the key is usable, and tdns asks
//     for one when the parent trusts it (ParentSyncAfterKeyPublication).
//
// The held sync is owed, and asked for when the hold ends: when the last
// poll of the zone's key ends (keyPollEnded), when the key is retired to one,
// and from the 30 s ticker (retestKeyHolds).
//
// All of that is for the UPDATE. A NOTIFY needs no key, so a parent that takes
// one is told by it, alone, while the hold stands (sendDelegationSync, decision
// 110).

// trustWord is a key the parent said it trusts, and the lead that heard it.
type trustWord struct {
	keyid uint16
	lead  uint64
}

// keyHoldLogged is the hold last logged for a zone: when, and its reason.
type keyHoldLogged struct {
	at  time.Time
	why string
}

// keyPollBook is the per-zone state of the hold, under its own lock: a leaf,
// taken by nothing that holds another lock of this package's.
type keyPollBook struct {
	mu sync.Mutex
	// running: the polls that run, and the set-ups that are about to start
	// one (a key being made or taken counts from before it is made).
	running map[ZoneName]int
	// unpublished: a key made or taken whose publication failed. The zone
	// stays held until a later set-up publishes the key and starts a poll.
	unpublished map[ZoneName]bool
	// ended: the zone's key whose poll last ended in this process, and the
	// lead it ran in (LeaderElectionManager.LeadStart). A renewal of that
	// lead neither publishes the key again nor starts another poll.
	ended map[ZoneName]keyPollEnd
	// owed: zones held with no catch-up tracker to keep the owed mark.
	owed map[ZoneName]bool
	// offered: when the zone's key was last offered to the parent (a poll
	// launched), which paces the leader's offers again (plan S14).
	offered map[ZoneName]time.Time
	// lost: the zone publishes a KEY that no agent asked holds, by its key
	// id, as the leader's last round found (step 7b); shown as LOST.
	lost map[ZoneName]uint16
	// logged: the hold last logged for the zone (once an hour, and when its
	// reason changes).
	logged map[ZoneName]keyHoldLogged
	// trustHeard: the key this agent last heard the parent say it trusts, by
	// its own poll, roll or inquiry, and the lead it heard it in (LeadStart).
	// With several KEYs at the apex only such a word lets the sync sign.
	trustHeard map[ZoneName]trustWord
	// trustAsked: when keyHold last asked the parent's KeyState itself.
	trustAsked map[ZoneName]time.Time
	// sent: where the zone's KEY last went with its publish instruction,
	// and the lead it went in (noteKeySent). A location the zone has now that
	// it did not name sends the KEY again (sendKeyToNewLocations).
	sent map[ZoneName]keySent
	// retesting: a backstop pass runs (retestKeyHoldsInBackground).
	retesting atomic.Bool
	// goroutines: the polls and the backstop passes, each to its end, the
	// release of the hold after a poll included. Both read the keystore.
	goroutines sync.WaitGroup
}

// wait returns when every poll and backstop pass started has ended: what
// closes the keystore waits for them first.
func (b *keyPollBook) wait() { b.goroutines.Wait() }

type keyPollEnd struct {
	keyid     uint16
	leadStart uint64
}

type keySent struct {
	keyid     uint16
	leadStart uint64
	locations []string
}

func (b *keyPollBook) init() {
	if b.running == nil {
		b.running = map[ZoneName]int{}
		b.unpublished = map[ZoneName]bool{}
		b.ended = map[ZoneName]keyPollEnd{}
		b.owed = map[ZoneName]bool{}
		b.logged = map[ZoneName]keyHoldLogged{}
		b.trustHeard = map[ZoneName]trustWord{}
		b.trustAsked = map[ZoneName]time.Time{}
		b.offered = map[ZoneName]time.Time{}
		b.lost = map[ZoneName]uint16{}
		b.sent = map[ZoneName]keySent{}
	}
}

func canonZone(zone ZoneName) ZoneName { return ZoneName(canonicalName(string(zone))) }

// keyPollToken is one count of a zone in running: taken before a key is made
// or taken, and handed to the poll that the set-up starts, or given back.
type keyPollToken struct {
	b      *keyPollBook
	zone   ZoneName
	once   sync.Once
	handed bool
}

// begin counts a set-up of the zone's key that may start a poll.
func (b *keyPollBook) begin(zone ZoneName) *keyPollToken {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	zone = canonZone(zone)
	b.running[zone]++
	return &keyPollToken{b: b, zone: zone}
}

// end gives the count back, unless a poll took it. With unpublished, the key
// made or taken was not published: the zone stays held.
func (tk *keyPollToken) end(unpublished bool) int {
	if tk == nil {
		return 0
	}
	left := -1
	tk.once.Do(func() {
		if tk.handed {
			return
		}
		b := tk.b
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.running[tk.zone] > 0 {
			b.running[tk.zone]--
		}
		if unpublished {
			b.unpublished[tk.zone] = true
		}
		left = b.running[tk.zone]
	})
	return left
}

// published notes that the zone's key is published: an earlier failure no
// longer holds the zone.
func (b *keyPollBook) published(zone ZoneName) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	delete(b.unpublished, canonZone(zone))
}

// pollEnded ends a poll, and says how many still run. A poll that ran to its
// end in the lead it started in notes the key and that lead (finished): a
// renewal of the lead keeps the key. One that returned because the lead
// moved notes nothing: the poll did not run to its end, and a later lead,
// or the same one taking the zone up again, polls anew.
func (b *keyPollBook) pollEnded(zone ZoneName, keyid uint16, leadStart uint64, finished bool) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	zone = canonZone(zone)
	if b.running[zone] > 0 {
		b.running[zone]--
	}
	if finished {
		b.ended[zone] = keyPollEnd{keyid: keyid, leadStart: leadStart}
	}
	return b.running[zone]
}

// sentTo notes where the zone's KEY keyid went, in the lead leadStart.
func (b *keyPollBook) sentTo(zone ZoneName, keyid uint16, leadStart uint64, locations []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	b.sent[canonZone(zone)] = keySent{keyid: keyid, leadStart: leadStart, locations: slices.Clone(locations)}
}

// lastSent is where the zone's KEY last went, and in which lead.
func (b *keyPollBook) lastSent(zone ZoneName) keySent {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	return b.sent[canonZone(zone)]
}

// lastOffer is when the zone's key was last offered to the parent.
func (b *keyPollBook) lastOffer(zone ZoneName) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	return b.offered[canonZone(zone)]
}

// setLost notes whether the zone's published KEY keyid is lost: no agent
// asked holds it.
func (b *keyPollBook) setLost(zone ZoneName, lost bool, keyid uint16) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	if lost {
		b.lost[canonZone(zone)] = keyid
	} else {
		delete(b.lost, canonZone(zone))
	}
}

// lostKey is the zone's published KEY that no agent asked holds, if the
// leader's last round found one.
func (b *keyPollBook) lostKey(zone ZoneName) (uint16, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	keyid, ok := b.lost[canonZone(zone)]
	return keyid, ok
}

// state is what the hold reads of the zone.
func (b *keyPollBook) state(zone ZoneName) (running int, unpublished bool, ended keyPollEnd) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	zone = canonZone(zone)
	return b.running[zone], b.unpublished[zone], b.ended[zone]
}

// renewalKeepsKey: the lead is the one the zone's key was last polled in, in
// this process, and the key is the zone's, published, and its only active
// key. A renewal then
// neither publishes the key again nor starts a poll, whatever that poll's
// outcome: a parent that has lost trust in the key shows as BADKEY at the
// next sync. A new lead (leadStart differs), a new or taken key, and a
// restart (nothing ended in this process) publish and poll. So does a
// renewal while another key is active: the set-up retires it, and the hold
// waits for that.
func renewalKeepsKey(zk *zoneKey, ended keyPollEnd, leadStart uint64) bool {
	return zk != nil && zk.held != nil && leadStart != 0 && ended.leadStart == leadStart &&
		ended.keyid == zk.held.keyid && len(zk.active) == 1 &&
		len(zk.published) == 1 && sameKey(zk.published[0], zk.held.key)
}

// zoneUsesKey: the zone syncs with its parent through its agents
// (parentsync=agent) and the parent advertises the DSYNC UPDATE scheme, or
// the parent's DSYNC records cannot be read yet (no resolver, a failed
// look-up). For the hold and the leader's set-up a parent not read is one
// that may take UPDATE: the sync waits, and the set-up publishes the key
// and polls, until a read says otherwise. Read as "no key", the set-up was
// skipped and the sync went out on whatever key was active (plan, step 7b).
// A parent known to take NOTIFY only needs no SIG(0) key.
func (conf *Config) zoneUsesKey(ctx context.Context, zone ZoneName) bool {
	uses, known := conf.zoneKeyUse(ctx, zone)
	return uses || !known
}

// zoneKeyUse says whether the parent takes UPDATE (uses), and whether that
// is known. known is false when the parent's DSYNC records could not be
// read (no resolver yet, a failed look-up). The key rounds then go on
// asking, and make no key; the hold and the set-up take the zone as one
// that uses a key (zoneUsesKey).
func (conf *Config) zoneKeyUse(ctx context.Context, zone ZoneName) (uses, known bool) {
	mpzd, ok := Zones.Get(string(zone))
	if !ok || mpzd == nil || mpzd.ZoneData == nil || !mpzd.Options[tdns.OptParentSync] {
		return false, true
	}
	if conf.Config == nil || conf.Config.Internal.ImrEngine == nil {
		return false, false
	}
	imr := &Imr{conf.Config.Internal.ImrEngine}
	res, err := imr.DsyncDiscovery(ctx, string(zone), false)
	if err != nil {
		return false, false
	}
	for _, d := range res.Rdata {
		if d != nil && d.Scheme == core.SchemeUpdate && d.Type == dns.TypeANY && d.Usable() {
			return true, true
		}
	}
	return false, true
}

// keyHoldReason says why the leader's sync of the zone waits for the zone's
// key, or "" when it does not. It reads the keystore and asks the resolver:
// never called under a lock of the catch-up tracker. It does not read tdns's
// cache of the keys it signs with (KeystoreSig0Cache), a map tdns keeps no
// lock around: only the syncher's own goroutine, where tdns signs, reads it
// (signingKeyCached).
func (conf *Config) keyHoldReason(ctx context.Context, zone ZoneName) string {
	_, why := conf.keyHold(ctx, zone)
	return why
}

// keyHold is keyHoldReason, and whether the zone uses a key at all.
func (conf *Config) keyHold(ctx context.Context, zone ZoneName) (uses bool, why string) {
	if !conf.zoneUsesKey(ctx, zone) {
		return false, ""
	}
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return true, "not held"
	}
	zk, err := readZoneKey(kdb, zone)
	if err == nil && zk.several() {
		return true, conf.severalKEYsHold(ctx, kdb, zone, zk)
	}
	if err != nil || zk.held == nil {
		return true, "not held"
	}
	if len(zk.active) != 1 {
		return true, "signing key differs"
	}
	running, unpublished, _ := conf.InternalMp.keyPolls.state(zone)
	if running > 0 {
		return true, "poll running"
	}
	if unpublished {
		return true, "not published"
	}
	if zk.held.parentState != edns0.KeyStateTrusted {
		return true, "the parent has not taken the key"
	}
	return true, ""
}

// severalKEYsHold is keyHold's reason while the apex carries several KEYs, or
// "" when the sync signs all the same. The project owner's rule (2026-11-05):
// "parent trusts a KEY that we hold the private key for, then just sign the
// update and get on with it". This agent's one active key signs when the
// parent's word that it trusts it was heard in this lead, by this agent's own
// poll, roll or inquiry; without that word the parent is asked here, at most
// every keyTrustAskEvery. A recorded parent_state is not enough: it is what
// was heard last, and a roll's delete leaves it stale at a member. Several KEYs
// are then a warning, once an hour.
func (conf *Config) severalKEYsHold(ctx context.Context, kdb *tdns.KeyDB, zone ZoneName, zk *zoneKey) string {
	const several = "the zone publishes several KEYs"
	if len(zk.active) != 1 {
		return several
	}
	keyid := zk.active[0].keyid
	if !conf.trustHeardInLead(zone, keyid) && (!conf.trustAskDue(zone) || !conf.askParentTrust(ctx, kdb, zone, keyid)) {
		return fmt.Sprintf("%s, and the parent's word that it trusts key %d is not heard in this lead", several, keyid)
	}
	if conf.InternalMp.keyLogs.due("several signs " + string(zone)) {
		lgAgent.Warn("the zone publishes several SIG(0) KEYs; the sync signs with this agent's key, which the parent trusts",
			"zone", zone, "keyid", keyid, "keyids", keyTags(zk.published))
	}
	return ""
}

// keyTrustAskEvery paces keyHold's own KeyState inquiries for a zone.
const keyTrustAskEvery = 30 * time.Second

// trustAskDue books a KeyState inquiry of keyHold's for the zone, unless one
// went within keyTrustAskEvery.
func (conf *Config) trustAskDue(zone ZoneName) bool {
	b := &conf.InternalMp.keyPolls
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	if time.Since(b.trustAsked[canonZone(zone)]) < keyTrustAskEvery {
		return false
	}
	b.trustAsked[canonZone(zone)] = time.Now()
	return true
}

// noteTrustHeard records the parent's word that it trusts keyid, heard by this
// agent in its lead lead (LeadStart). Outside a lead nothing is recorded.
func (conf *Config) noteTrustHeard(zone ZoneName, keyid uint16, lead uint64) {
	if lead == 0 {
		return
	}
	b := &conf.InternalMp.keyPolls
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	b.trustHeard[canonZone(zone)] = trustWord{keyid: keyid, lead: lead}
}

// trustHeardInLead: the parent's word that it trusts keyid was heard in this
// agent's present lead of the zone.
func (conf *Config) trustHeardInLead(zone ZoneName, keyid uint16) bool {
	lem := conf.InternalMp.LeaderElectionManager
	if lem == nil {
		return false
	}
	lead := lem.LeadStart(zone)
	b := &conf.InternalMp.keyPolls
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	w, ok := b.trustHeard[canonZone(zone)]
	return ok && lead != 0 && w.lead == lead && w.keyid == keyid
}

// askParentTrust asks the parent's KeyState for keyid now (no bootstrap),
// records the answer as tdns's poll does (parent_state), and reports whether
// the parent trusts the key.
func (conf *Config) askParentTrust(ctx context.Context, kdb *tdns.KeyDB, zone ZoneName, keyid uint16) bool {
	var lead uint64
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
		lead = lem.LeadStart(zone)
	}
	state, err := conf.rollParentOf().keyState(ctx, zone, keyid)
	if err != nil {
		lgAgent.Warn("the parent's KeyState for the zone's SIG(0) key could not be asked", "zone", zone, "keyid", keyid, "err", err)
		return false
	}
	tdns.UpdateParentState(kdb, string(zone), keyid, state)
	if state != edns0.KeyStateTrusted {
		// the word of this lead that it trusts the key is ended by this one
		conf.forgetTrustHeard(zone, keyid)
		return false
	}
	conf.noteTrustHeard(zone, keyid, lead)
	return true
}

// forgetTrustHeard forgets the parent's word that it trusts keyid: the parent
// has since said otherwise.
func (conf *Config) forgetTrustHeard(zone ZoneName, keyid uint16) {
	b := &conf.InternalMp.keyPolls
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	if w, ok := b.trustHeard[canonZone(zone)]; ok && w.keyid == keyid {
		delete(b.trustHeard, canonZone(zone))
	}
}

// trustBeforeSigning asks the parent's KeyState, right before the leader's
// sync is sent, for the key it signs with while the apex carries several KEYs,
// and refuses the sync unless the parent trusts it now. tdns uploads a key the
// parent answers BADKEY for as a bootstrap, and the parent checks that against
// the apex, which may still show a key the parent has deleted (the project
// owner's ruling, 2026-11-05). What is left is the time between the inquiry
// and the send.
func (conf *Config) trustBeforeSigning(ctx context.Context, ds tdns.DelegationSyncRequest) error {
	if !mpLeaderSync(conf, ds) {
		return nil
	}
	zone := ZoneName(ds.ZoneName)
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil || !conf.zoneUsesKey(ctx, zone) {
		return nil
	}
	zk, err := readZoneKey(kdb, zone)
	if err != nil || !zk.several() || len(zk.active) != 1 {
		return nil
	}
	if keyid := zk.active[0].keyid; !conf.askParentTrust(ctx, kdb, zone, keyid) {
		return fmt.Errorf("the zone publishes several KEYs and the parent does not trust key %d now: nothing is sent, so no bootstrap of it starts", keyid)
	}
	return nil
}

// parentTrustsActive: keyid is an active key of the zone's whose recorded
// parent_state is Trusted. It reads the keystore only.
func parentTrustsActive(kdb *tdns.KeyDB, zone ZoneName, keyid uint16) bool {
	active, err := activeSig0Rows(kdb, zone)
	if err != nil {
		return false
	}
	for _, r := range active {
		if r.keyid == keyid {
			return r.parentState == edns0.KeyStateTrusted
		}
	}
	return false
}

// keyPending: this agent leads the zone, the zone uses a key, and this agent
// holds no key, or holds one the parent does not trust yet by what tdns last
// recorded of it (parent_state). While it is true every sync the leader asks
// for is held (keyHold), and the key rounds offer the key again
// (reofferZoneKey). Nothing is pending for a parent known to take no UPDATE
// (plan S14).
func (conf *Config) keyPending(ctx context.Context, zone ZoneName) bool {
	if lem := conf.InternalMp.LeaderElectionManager; lem == nil || !lem.IsLeader(zone) {
		return false
	}
	if !conf.zoneUsesKey(ctx, zone) {
		return false
	}
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return true
	}
	zk, err := readZoneKey(kdb, zone)
	return err != nil || zk.held == nil || zk.held.parentState != edns0.KeyStateTrusted
}

// rolloverInZone: a key rollover is under way in the zone, at this provider
// or by the latest first-hand telling of a voting member, heard within the
// time a telling counts (S5a's predicate, as the thaw reads it).
func (conf *Config) rolloverInZone(zone string) bool {
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		return false
	}
	if tm.rolloverAt(zone) {
		return true
	}
	voting := conf.InternalMp.Instructions.activeVoters(zone)
	timeout := leavingTimeoutFor(conf.MpConfig())
	for _, st := range tm.stamps.firstHand(canonicalName(zone)) {
		if st.Rollover && isAmong(voting, AgentId(st.identity)) && time.Since(st.heard) <= timeout {
			return true
		}
	}
	return false
}

// offerHeld holds the publication of the zone's key and its offers to the
// parent (the poll, and the bootstrap in it) while the zone is frozen, as
// syncHeld holds every other change (plan S6), except while a key rollover
// under way in the zone waits for the parent to trust the key (keyPending):
// the rollover's DS sync waits for the key, so holding its offers would
// leave the rollover and the thaw waiting for each other (design 3.1, 6;
// plan S14). Nor as a step of the reconciliation (design 6): a step's own sync
// waits for the key too (holdForZoneKey comes before the freeze), so a leader
// elected during a removal would wait for the step, and the step for it; so
// would one that holds a key not published during a joiner's DS step; and
// the step that takes the parent sync up publishes and offers it (plan S20).
// Once a hand-over to the owner has come to the delete of the agents' key at
// the parent, the key is offered no more, whatever waits for it.
func (conf *Config) offerHeld(ctx context.Context, zone ZoneName) (held bool, why string) {
	if conf.InternalMp.Instructions.tookStep(string(zone), parentSyncKeyKey) {
		return true, "the parent sync goes to the zone's owner"
	}
	if len(conf.zoneFrozen(string(zone))) > 0 {
		if conf.rolloverInZone(string(zone)) && conf.keyPending(ctx, zone) {
			lgAgent.Info("the zone's SIG(0) key is offered during the transition: a rollover under way waits for the parent to trust it", "zone", zone)
			return false, ""
		}
		if conf.InternalMp.reconciles.asksSync(canonicalName(string(zone))) || conf.parentSyncTakenUp(string(zone)) || conf.joinersDSAsked(string(zone)) {
			lgAgent.Info("the zone's SIG(0) key is published and offered during the transition: a step's own sync waits for it", "zone", zone)
			return false, ""
		}
	}
	return conf.syncHeld(string(zone), syncOther)
}

// keyToPublish: this agent leads the zone, and its key's publication in this
// lead failed or the freeze held it. The key rounds publish it when they may
// (reofferZoneKey), also for a key the parent trusts, which nothing else would.
func (conf *Config) keyToPublish(zone ZoneName) bool {
	if lem := conf.InternalMp.LeaderElectionManager; lem == nil || !lem.IsLeader(zone) {
		return false
	}
	_, unpublished, _ := conf.InternalMp.keyPolls.state(zone)
	return unpublished
}

// zoneKeyLine is the status of the zone's SIG(0) key at the leader, for
// `agent parentsync status`: LOST when its last round found the published
// KEY held by no agent asked, and while the parent does not trust the key
// held, that it was offered and not taken, or that the parent refuses it
// (decision 99). "" otherwise.
func (conf *Config) zoneKeyLine(ctx context.Context, zone ZoneName) string {
	if lem := conf.InternalMp.LeaderElectionManager; lem == nil || !lem.IsLeader(zone) {
		return ""
	}
	// what the hand-over of the parent sync left for the owner (plan S20)
	if line := conf.InternalMp.parentSyncs.ownerTold(string(zone)); line != "" {
		return line
	}
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return ""
	}
	// a roll under way says how far it has come (plan S17a)
	if line := conf.rollLine(kdb, zone); line != "" {
		return line
	}
	zk, err := readZoneKey(kdb, zone)
	if err != nil {
		return ""
	}
	if zk.held == nil {
		if keyid, lost := conf.InternalMp.keyPolls.lostKey(zone); lost && len(zk.published) == 1 && zk.published[0].KeyTag() == keyid {
			return "LOST"
		}
		return ""
	}
	if !conf.keyPending(ctx, zone) {
		return ""
	}
	switch zk.held.parentState {
	case edns0.KeyStateRefused, edns0.KeyStateInvalid:
		return fmt.Sprintf("key %d: the parent refuses it (%s)", zk.held.keyid, edns0.KeyStateToString(zk.held.parentState))
	}
	if zk.held.creator == "leader-election" {
		return fmt.Sprintf("new key %d made and offered; the parent has not taken it yet", zk.held.keyid)
	}
	return fmt.Sprintf("key %d offered; the parent has not taken it yet", zk.held.keyid)
}

// holdForZoneKey holds the leader's sync of a multi-provider zone while the
// zone's key is not held, not the one tdns signs with, or still being
// bootstrapped: it marks the sync owed for the key, logs why (when the reason
// is new, and then once an hour), and reports that nothing is to be sent. The
// syncher calls it after the hold for the catch-up, in both arms; the
// explicit arm answers its caller at once. Never waits. A parent that takes a
// NOTIFY holds nothing: that sync needs no key (sendDelegationSync).
func (conf *Config) holdForZoneKey(ctx context.Context, ds tdns.DelegationSyncRequest) (held bool, why string) {
	if !mpLeaderSync(conf, ds) {
		return false, ""
	}
	zone := ZoneName(ds.ZoneName)
	why = conf.syncKeyHold(ctx, zone)
	if why == "" {
		return false, ""
	}
	if parentNotifyTarget(ctx, conf, ds.ZoneData) != nil {
		if conf.InternalMp.reconciles.sayOnce(canonicalName(string(zone)), "notify passes the key's hold "+why) {
			lgAgent.Info("an UPDATE waits for the zone's SIG(0) key; the sync goes by NOTIFY, which needs no key", "zone", zone, "reason", why)
		}
		return false, ""
	}
	// That look asks the parent, and the hold can end during it. A release then
	// finds nothing owed, so read the hold again before owing the sync.
	if why = conf.syncKeyHold(ctx, zone); why == "" {
		return false, ""
	}
	if t := conf.InternalMp.CatchUp; t != nil {
		t.oweForKey(zone)
	} else {
		b := &conf.InternalMp.keyPolls
		b.mu.Lock()
		b.init()
		b.owed[canonZone(zone)] = true
		b.mu.Unlock()
	}
	b := &conf.InternalMp.keyPolls
	b.mu.Lock()
	b.init()
	last := b.logged[canonZone(zone)]
	now := time.Now()
	logIt := last.why != why || now.Sub(last.at) >= time.Hour
	if logIt {
		b.logged[canonZone(zone)] = keyHoldLogged{at: now, why: why}
	}
	b.mu.Unlock()
	if logIt {
		lgAgent.Info("the sync with the parent waits for the zone's SIG(0) key", "zone", zone, "reason", why)
	}
	return true, why
}

// syncKeyHold says why an UPDATE of the leader's waits for the zone's key, or
// "". Called on the syncher's goroutine only (signingKeyCached).
func (conf *Config) syncKeyHold(ctx context.Context, zone ZoneName) string {
	uses, why := conf.keyHold(ctx, zone)
	if uses && why == "" && !conf.signingKeyCached(zone) {
		why = "signing key differs"
	}
	return why
}

// parentNotifyTarget is where the parent takes a NOTIFY for the zone, in the
// plan tdns's own walk of the schemes reads, so parentsync.schemes has its say:
// nil if it offers none. A test stands in for it.
var parentNotifyTarget = func(ctx context.Context, conf *Config, zd *tdns.ZoneData) *tdns.DsyncTarget {
	if zd == nil || conf.Config == nil || conf.Config.Internal.ImrEngine == nil {
		return nil
	}
	plan, err := zd.BuildParentSyncPlan(ctx, conf.zoneKeyDB(ZoneName(zd.ZoneName)), conf.Config.Internal.ImrEngine, tdns.SyncRoleChild)
	if err != nil {
		return nil
	}
	for _, cand := range plan.Candidates {
		if cand.Scheme == "NOTIFY" {
			return cand.Target
		}
	}
	return nil
}

// sendDelegationSync is tdns's walk of the schemes. While the zone's key holds
// an UPDATE, the only sync that passed the hold is a NOTIFY (holdForZoneKey),
// and it goes alone: the walk would sign an UPDATE with that key first, and a
// BADKEY starts a bootstrap of it. With no target now (the hold came after
// holdForZoneKey, or this look failed) nothing goes: the sync fails, is asked
// again, and holdForZoneKey decides again.
func (conf *Config) sendDelegationSync(ctx context.Context, kdb *tdns.KeyDB, notifyq chan tdns.NotifyRequest, ds tdns.DelegationSyncRequest,
	syncstate tdns.DelegationSyncStatus, imr *tdns.Imr) (string, uint8, tdns.UpdateResult, error) {
	zd := ds.ZoneData
	if !syncstate.InSync && mpLeaderSync(conf, ds) {
		why := conf.syncKeyHold(ctx, ZoneName(ds.ZoneName))
		// with several KEYs at the apex, only a key the parent trusts now
		// signs an UPDATE (trustBeforeSigning); a NOTIFY needs none
		if why == "" {
			if err := conf.trustBeforeSigning(ctx, ds); err != nil {
				why = err.Error()
			}
		}
		if why != "" {
			target := parentNotifyTarget(ctx, conf, zd)
			if target == nil {
				return "", 0, tdns.UpdateResult{}, fmt.Errorf("the zone's SIG(0) key holds an UPDATE (%s) and the parent gave no NOTIFY target", why)
			}
			msg, rcode, err := zd.SyncZoneDelegationViaNotify(ctx, kdb, notifyq, syncstate, target)
			return msg, rcode, tdns.UpdateResult{}, err
		}
	}
	return zd.SyncZoneDelegation(ctx, kdb, notifyq, syncstate, imr)
}

// parentRefusesKey: the parent's last word on the key this agent holds as the
// zone's is a refusal: which key, and the word. It reads the keystore only.
func (conf *Config) parentRefusesKey(zone ZoneName) (uint16, string, bool) {
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return 0, "", false
	}
	zk, err := readZoneKey(kdb, zone)
	if err != nil || zk.held == nil {
		return 0, "", false
	}
	switch zk.held.parentState {
	case edns0.KeyStateRefused, edns0.KeyStateInvalid:
		return zk.held.keyid, edns0.KeyStateToString(zk.held.parentState), true
	}
	return 0, "", false
}

// signingKeyCached: the key tdns signs the zone's UPDATE with, read through
// its cache as tdns reads it (GetSig0Keys), is the zone's only active key. A
// cache that still holds a retired key (tdns #943) is cleared once, and read
// again. Called on the syncher's goroutine only, where tdns signs: the cache
// is a map tdns keeps no lock around.
func (conf *Config) signingKeyCached(zone ZoneName) bool {
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return false
	}
	active, err := activeSig0Rows(kdb, zone)
	if err != nil || len(active) != 1 {
		return false
	}
	for try := 0; try < 2; try++ {
		sak, err := kdb.GetSig0Keys(dns.Fqdn(string(zone)), tdns.Sig0StateActive)
		if err == nil && sak != nil && len(sak.Keys) > 0 && sak.Keys[0].KeyId == active[0].keyid {
			return true
		}
		delete(kdb.KeystoreSig0Cache, dns.Fqdn(string(zone))+"+"+tdns.Sig0StateActive)
	}
	return false
}

// releaseKeyHold asks for the sync held for the zone's key, when the key's
// hold is over. The catch-up's hold, if any, keeps it owed. Called outside
// every lock of the tracker's.
func (conf *Config) releaseKeyHold(ctx context.Context, zone ZoneName) {
	if why := conf.keyHoldReason(ctx, zone); why != "" {
		return
	}
	if t := conf.InternalMp.CatchUp; t != nil {
		if t.releaseKeyOwed(zone) {
			lgAgent.Info("the zone's SIG(0) key is held and bootstrapped, asking for the sync that waited", "zone", zone)
			t.askOwed(ctx, zone)
		}
		return
	}
	b := &conf.InternalMp.keyPolls
	b.mu.Lock()
	b.init()
	owed := b.owed[canonZone(zone)]
	delete(b.owed, canonZone(zone))
	b.mu.Unlock()
	if owed {
		lgAgent.Info("the zone's SIG(0) key is held and bootstrapped, asking for the sync that waited", "zone", zone)
		conf.askOwedDelegationSync(ctx, zone)
	}
}

// retestKeyHolds releases every key hold that is over: the backstop, from
// the 30 s ticker.
func (conf *Config) retestKeyHolds(ctx context.Context) {
	zones := conf.InternalMp.CatchUp.keyOwedZones()
	b := &conf.InternalMp.keyPolls
	b.mu.Lock()
	b.init()
	for zone := range b.owed {
		zones = append(zones, zone)
	}
	b.mu.Unlock()
	for _, zone := range zones {
		conf.releaseKeyHold(ctx, zone)
	}
}

// retestKeyHoldsInBackground runs retestKeyHolds on a goroutine of its own,
// one at a time.
func (conf *Config) retestKeyHoldsInBackground(ctx context.Context) {
	b := &conf.InternalMp.keyPolls
	if !b.retesting.CompareAndSwap(false, true) {
		return
	}
	b.goroutines.Add(1)
	go func() {
		defer b.goroutines.Done()
		defer b.retesting.Store(false)
		conf.retestKeyHolds(ctx)
	}()
}

// launchKeyPoll starts the poll of the zone's key with its parent, counted in
// keyPolls until it returns; a token, when given, is the count the set-up
// took before it made or took the key. The sync of the zone waits while the
// poll runs, and when the last poll of the zone ends the sync that waited is
// asked for. The operator's parentsync-bootstrap starts its poll here too.
func (conf *Config) launchKeyPoll(ctx context.Context, tk *keyPollToken, zone ZoneName, keyName string, keyid uint16, algorithm uint8) {
	b := &conf.InternalMp.keyPolls
	if tk == nil {
		tk = b.begin(zone)
	}
	tk.handed = true
	b.mu.Lock()
	b.init()
	b.offered[canonZone(zone)] = time.Now()
	b.mu.Unlock()
	var leadStart uint64
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
		leadStart = lem.LeadStart(zone)
	}
	b.goroutines.Add(1)
	go func() {
		defer b.goroutines.Done()
		held := false
		defer func() {
			// finished: this agent still leads the zone in the lead the
			// poll started in, and the poll ran: one the freeze held is
			// polled at the take-up (plan S6)
			finished := !held
			if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
				finished = finished && leadStart != 0 && lem.LeadStart(zone) == leadStart
			}
			if left := b.pollEnded(zone, keyid, leadStart, finished); left == 0 {
				conf.releaseKeyHold(ctx, zone)
				// once the parent trusts the zone's key, the retired keys
				// it may still trust are deleted there (S17a)
				conf.sweepRetiredKeys(ctx, zone)
			}
		}()
		held = conf.ParentSyncAfterKeyPublication(ctx, zone, keyName, keyid, algorithm)
		// the parent's word on the key, heard by this poll, in the lead it
		// started in
		if kdb := conf.zoneKeyDB(zone); !held && kdb != nil && parentTrustsActive(kdb, zone, keyid) {
			conf.noteTrustHeard(zone, keyid, leadStart)
		}
	}()
}
