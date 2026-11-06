/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The leader's roll of the zone's SIG(0) key (plan S17a).
//
// tdns's RolloverSig0KeyWithParent makes a new key at each call, so its
// phases cannot be resumed, and it publishes the KEY itself, not through the
// combiner. The roll is built here from tdns's exported pieces instead, one
// phase at a time, each kept on disk (MPSig0Rolls):
//
//  1. made: the new key is made at the leader and kept published, not
//     active. The leader keeps one active key (step 7b), and tdns signs with
//     the first active one.
//  2. added: the parent took an UPDATE adding the new key, signed with the
//     old one.
//  3. published: a KeyState inquiry says the parent trusts the new key; its
//     KEY is published as the leader's replace (S14). From here the
//     leader's zone key is the new one (readZoneKey), which the leader hands
//     over, while the old key still signs.
//  4. The voting members ask for the key (keyCheck) and import it, which
//     retires the old one there. The leader waits for the KEY's
//     confirmations, members with no role with S12's time-out.
//  5. activated: the new key active and the old one retired at the leader;
//     then the parent takes an UPDATE deleting the old key, signed with the
//     new one, and the roll is done.
//
// A failed phase is tried again after multi-provider.transitions.roll-retry,
// and the status says so. A failed add leaves the old key in use; until a
// failed delete goes through, the parent trusts both keys. The roll is held
// while the zone is frozen, except as a step of the reconciliation.
//
// It is finished from what is in place, as S12 plans. A roll whose agent
// another one now leads ends there as a member's keys would (endRollHere),
// and any leader deletes at the parent the zone's retired keys it holds
// that the parent still trusts (sweepRetiredKeys): step 5's delete, by
// whichever leader holds the old key retired.

const (
	rollOwed      = "owed" // a removal owes it (S17b): the new key is not made yet
	rollMade      = "made"
	rollAdded     = "added"
	rollPublished = "published"
	rollActivated = "activated"
	rollDone      = "done"
)

// sig0Roll is one roll, as MPSig0Rolls holds it.
type sig0Roll struct {
	zone     ZoneName
	phase    string
	oldKeyid uint16
	newKeyid uint16
	started  time.Time
	nextTry  time.Time
	failures int
	lastErr  string
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeOrZero(s int64) time.Time {
	if s == 0 {
		return time.Time{}
	}
	return time.Unix(s, 0)
}

// loadRoll is the zone's roll, nil when none runs. A keystore with no table
// of rolls holds none.
func loadRoll(kdb *tdns.KeyDB, zone ZoneName) (*sig0Roll, error) {
	row := kdb.QueryRow(`SELECT phase, oldkeyid, newkeyid, started, nexttry, failures, lasterr FROM MPSig0Rolls WHERE zonename = ?`,
		canonicalName(string(zone)))
	r := &sig0Roll{zone: canonZone(zone)}
	var oldKeyid, newKeyid int
	var started, nextTry int64
	err := row.Scan(&r.phase, &oldKeyid, &newKeyid, &started, &nextTry, &r.failures, &r.lastErr)
	switch {
	case errors.Is(err, sql.ErrNoRows), err != nil && strings.Contains(err.Error(), "no such table"):
		return nil, nil
	case err != nil:
		return nil, err
	}
	r.oldKeyid, r.newKeyid = uint16(oldKeyid), uint16(newKeyid)
	r.started, r.nextTry = timeOrZero(started), timeOrZero(nextTry)
	return r, nil
}

// saveRoll writes the roll, creating the table on first use.
func saveRoll(kdb *tdns.KeyDB, r *sig0Roll) error {
	hdb := NewHsyncDB(kdb)
	hdb.Lock()
	defer hdb.Unlock()
	if _, err := hdb.DB.Exec(HsyncTables["MPSig0Rolls"]); err != nil {
		return fmt.Errorf("the table of SIG(0) key rolls: %w", err)
	}
	_, err := hdb.DB.Exec(`INSERT OR REPLACE INTO MPSig0Rolls (zonename, phase, oldkeyid, newkeyid, started, nexttry, failures, lasterr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		canonicalName(string(r.zone)), r.phase, r.oldKeyid, r.newKeyid, unixOrZero(r.started), unixOrZero(r.nextTry), r.failures, r.lastErr)
	if err != nil {
		return fmt.Errorf("keeping the roll of %s's SIG(0) key: %w", r.zone, err)
	}
	return nil
}

func deleteRoll(kdb *tdns.KeyDB, zone ZoneName) error {
	hdb := NewHsyncDB(kdb)
	hdb.Lock()
	defer hdb.Unlock()
	_, err := hdb.DB.Exec(`DELETE FROM MPSig0Rolls WHERE zonename = ?`, canonicalName(string(zone)))
	return err
}

// rollZones are the zones with a roll in kdb.
func rollZones(kdb *tdns.KeyDB) []ZoneName {
	rows, err := kdb.Query(`SELECT zonename FROM MPSig0Rolls`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []ZoneName
	for rows.Next() {
		var z string
		if rows.Scan(&z) == nil {
			out = append(out, ZoneName(z))
		}
	}
	return out
}

// rollingKey is the new key of the zone's roll, kept published at the
// leader, while the roll is "added" or "published"; sent: its KEY has gone
// out ("published"). In "added" the KEY may have gone out before the phase
// was written, which the zone's copy shows. A roll that cannot be read is an
// error: it says nothing of which key is the zone's.
func rollingKey(kdb *tdns.KeyDB, zone ZoneName) (key *sig0Row, sent bool, err error) {
	r, err := loadRoll(kdb, zone)
	if err != nil || r == nil || (r.phase != rollAdded && r.phase != rollPublished) {
		return nil, false, err
	}
	return sig0RowByID(kdb, zone, tdns.Sig0StatePublished, r.newKeyid), r.phase == rollPublished, nil
}

func sig0RowByID(kdb *tdns.KeyDB, zone ZoneName, state string, keyid uint16) *sig0Row {
	rows, err := sig0Rows(kdb, zone, state)
	if err != nil {
		return nil
	}
	for i := range rows {
		if rows[i].keyid == keyid && rows[i].key != nil {
			return &rows[i]
		}
	}
	return nil
}

// rollBook: the rolls a pass runs for, one at a time per zone, and their
// goroutines. A leaf lock.
type rollBook struct {
	mu         sync.Mutex
	running    map[ZoneName]bool
	swept      map[ZoneName]time.Time // the last sweep of retired keys
	goroutines sync.WaitGroup
}

// sweepDue notes a sweep of the zone's retired keys now, unless one ran
// within every.
func (b *rollBook) sweepDue(zone ZoneName, every time.Duration) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.swept == nil {
		b.swept = map[ZoneName]time.Time{}
	}
	zone = canonZone(zone)
	if last, ok := b.swept[zone]; ok && time.Since(last) < every {
		return false
	}
	b.swept[zone] = time.Now()
	return true
}

func (b *rollBook) claim(zone ZoneName) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.running == nil {
		b.running = map[ZoneName]bool{}
	}
	zone = canonZone(zone)
	if b.running[zone] {
		return false
	}
	b.running[zone] = true
	return true
}

func (b *rollBook) release(zone ZoneName) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.running, canonZone(zone))
}

// wait returns when every pass started has ended.
func (b *rollBook) wait() { b.goroutines.Wait() }

// rollKEYBook: the distribution of each roll's new KEY, and the final word
// of each of its recipients (the transport's confirmations). A leaf lock.
type rollKEYBook struct {
	mu    sync.Mutex
	zones map[ZoneName]*rollKEY
}

type rollKEY struct {
	distID   string
	expected []string
	since    time.Time
	heard    map[string]rollWord
}

type rollWord struct {
	status  string
	message string
}

// expect books a KEY sent to these recipients under distID.
func (b *rollKEYBook) expect(zone ZoneName, distID string, expected []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.zones == nil {
		b.zones = map[ZoneName]*rollKEY{}
	}
	b.zones[canonZone(zone)] = &rollKEY{distID: distID, expected: expected, since: time.Now(), heard: map[string]rollWord{}}
}

// heard notes a recipient's final word on a roll's KEY; a PENDING, and a
// word from a recipient at another active serial (rule 6), are no final
// word.
func (b *rollKEYBook) heard(distID, sender, status, message string, notYet bool) {
	if status == "PENDING" || notYet {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, k := range b.zones {
		if k.distID == distID {
			k.heard[canonicalName(sender)] = rollWord{status: status, message: message}
		}
	}
}

// state is a copy of the zone's booked KEY.
func (b *rollKEYBook) state(zone ZoneName) (rollKEY, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, ok := b.zones[canonZone(zone)]
	if !ok {
		return rollKEY{}, false
	}
	c := *k
	c.heard = map[string]rollWord{}
	for r, w := range k.heard {
		c.heard[r] = w
	}
	return c, true
}

func (b *rollKEYBook) forget(zone ZoneName) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.zones, canonZone(zone))
}

// rollParent is what the roll asks of the zone's parent; a test stands in
// for it (InternalMp.rollParent).
type rollParent interface {
	// update sends an UPDATE of the zone's KEY at the parent, signed with
	// signer, and returns the parent's rcode
	update(ctx context.Context, zone ZoneName, adds, removes []dns.RR, signer *tdns.PrivateKeyCache) (int, error)
	// keyState is the parent's word on the key, by a KeyState inquiry
	keyState(ctx context.Context, zone ZoneName, keyid uint16) (uint8, error)
}

// tdnsParent asks the parent through tdns, under the zone's parent context
// (S7).
type tdnsParent struct{ conf *Config }

func (p tdnsParent) update(ctx context.Context, zone ZoneName, adds, removes []dns.RR, signer *tdns.PrivateKeyCache) (int, error) {
	mpzd, ok := Zones.Get(string(zone))
	if !ok || mpzd == nil || mpzd.ZoneData == nil {
		return 0, fmt.Errorf("zone %s not found", zone)
	}
	if p.conf.Config == nil || p.conf.Config.Internal.ImrEngine == nil {
		return 0, fmt.Errorf("no resolver to find the parent's UPDATE target")
	}
	parent, err := mpzd.ZoneData.ResolveParent()
	if err != nil {
		return 0, err
	}
	runCtx, done := p.conf.delegationSyncRun(ctx, string(zone))
	defer done()
	target, err := p.conf.Config.Internal.ImrEngine.LookupDSYNCTarget(runCtx, string(zone), dns.TypeANY, core.SchemeUpdate)
	if err != nil {
		return 0, fmt.Errorf("the parent's DSYNC UPDATE target: %w", err)
	}
	m, err := tdns.CreateUpdate(parent, adds, removes)
	if err != nil {
		return 0, err
	}
	m, err = tdns.SignMsg(*m, string(zone), &tdns.Sig0ActiveKeys{Keys: []*tdns.PrivateKeyCache{signer}})
	if err != nil {
		return 0, err
	}
	rcode, _, err := tdns.SendUpdate(runCtx, m, parent, target.Addresses)
	return rcode, err
}

func (p tdnsParent) keyState(ctx context.Context, zone ZoneName, keyid uint16) (uint8, error) {
	if p.conf.Config == nil || p.conf.Config.Internal.ImrEngine == nil {
		return 0, fmt.Errorf("no resolver to ask the parent")
	}
	runCtx, done := p.conf.delegationSyncRun(ctx, string(zone))
	defer done()
	state, _, _, err := queryParentKeyStateDetailed(runCtx, NewHsyncDB(p.conf.zoneKeyDB(zone)), &Imr{p.conf.Config.Internal.ImrEngine}, string(zone), keyid)
	return state, err
}

func (conf *Config) rollParentOf() rollParent {
	if p := conf.InternalMp.rollParent; p != nil {
		return p
	}
	return tdnsParent{conf: conf}
}

// keyCache is the row's key, to sign with.
func keyCache(r *sig0Row) (*tdns.PrivateKeyCache, error) {
	if r == nil {
		return nil, fmt.Errorf("no such key")
	}
	return tdns.PrepareKeyCache(r.privatekey, r.keyrr)
}

// addKeyAtParent asks the parent to add newKey, signed with signer.
func (conf *Config) addKeyAtParent(ctx context.Context, zone ZoneName, newKey *dns.KEY, signer *sig0Row) error {
	return conf.keyUpdateAtParent(ctx, zone, []dns.RR{newKey}, nil, signer, "add", newKey.KeyTag())
}

// deleteKeyAtParent asks the parent to delete oldKey, signed with signer: a
// function of its own, which S20 uses too.
func (conf *Config) deleteKeyAtParent(ctx context.Context, zone ZoneName, oldKey *dns.KEY, signer *sig0Row) error {
	return conf.keyUpdateAtParent(ctx, zone, nil, []dns.RR{oldKey}, signer, "delete", oldKey.KeyTag())
}

func (conf *Config) keyUpdateAtParent(ctx context.Context, zone ZoneName, adds, removes []dns.RR, signer *sig0Row, what string, keyid uint16) error {
	pkc, err := keyCache(signer)
	if err != nil {
		return fmt.Errorf("the key to sign the %s of key %d with: %w", what, keyid, err)
	}
	rcode, err := conf.rollParentOf().update(ctx, zone, adds, removes, pkc)
	if err != nil {
		return fmt.Errorf("the %s of key %d at the parent: %w", what, keyid, err)
	}
	if rcode != dns.RcodeSuccess {
		return fmt.Errorf("the parent refused the %s of key %d: %s", what, keyid, dns.RcodeToString[rcode])
	}
	return nil
}

// startSig0Roll starts the roll of the zone's key at this agent, which leads
// the zone and holds the key the parent trusts: the new key is made, and the
// first pass runs in the background. It returns the new key's id.
func (conf *Config) startSig0Roll(ctx context.Context, zone ZoneName, alg uint8) (uint16, error) {
	if !votesIn(instructionsFor(zone), conf.localAgentID()) {
		return 0, fmt.Errorf("this agent does not vote in zone %s", zone)
	}
	if lem := conf.InternalMp.LeaderElectionManager; lem == nil || !lem.IsLeader(zone) {
		return 0, fmt.Errorf("this agent does not lead zone %s", zone)
	}
	if uses, known := conf.zoneKeyUse(ctx, zone); !known {
		return 0, fmt.Errorf("whether the parent of %s takes UPDATE is not known yet", zone)
	} else if !uses {
		return 0, fmt.Errorf("the parent of %s takes no UPDATE: the zone has no SIG(0) key to roll", zone)
	}
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return 0, fmt.Errorf("no keystore for zone %s", zone)
	}
	if alg == 0 {
		alg = parentSyncKeygenAlgorithm()
	}
	var newKeyid, oldKeyid uint16
	err := conf.keySetupLocked(zone, func() error {
		r, err := loadRoll(kdb, zone)
		switch {
		case err != nil:
			return fmt.Errorf("the roll of the SIG(0) key of %s cannot be read: %w", zone, err)
		case r != nil:
			return fmt.Errorf("a roll of the SIG(0) key of %s is under way (%s, new key %d)", zone, r.phase, r.newKeyid)
		}
		if oldKeyid, newKeyid, err = makeRolledKey(kdb, zone, alg); err != nil {
			return err
		}
		return saveRoll(kdb, &sig0Roll{zone: zone, phase: rollMade, oldKeyid: oldKeyid, newKeyid: newKeyid, started: time.Now()})
	})
	if err != nil {
		return 0, err
	}
	lgAgent.Info("rolling the zone's SIG(0) key", "zone", zone, "phase", rollMade, "old", oldKeyid, "new", newKeyid)
	conf.rollInBackground(ctx, zone)
	return newKeyid, nil
}

// makeRolledKey makes the roll's new key at this agent, which must hold the
// zone's one active key, trusted by the parent; under the zone's key-setup
// lock. It returns the old key's id and the new one's.
func makeRolledKey(kdb *tdns.KeyDB, zone ZoneName, alg uint8) (oldKeyid, newKeyid uint16, err error) {
	zk, err := readZoneKey(kdb, zone)
	switch {
	case err != nil:
		return 0, 0, fmt.Errorf("the SIG(0) keys of %s cannot be read: %w", zone, err)
	case zk.several():
		return 0, 0, fmt.Errorf("zone %s publishes several SIG(0) KEYs; an operator has to leave one", zone)
	case zk.held == nil || zk.held.key == nil:
		return 0, 0, fmt.Errorf("this agent does not hold the SIG(0) key of zone %s", zone)
	case len(zk.active) != 1:
		return 0, 0, fmt.Errorf("zone %s has %d active SIG(0) keys", zone, len(zk.active))
	case zk.held.parentState != edns0.KeyStateTrusted:
		return 0, 0, fmt.Errorf("this agent has no record that the parent trusts the SIG(0) key %d of zone %s", zk.held.keyid, zone)
	}
	resp, err := sig0KeyMgmtRetried(kdb, tdns.KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "generate",
		Zone:       string(zone),
		Keyname:    string(zone),
		Algorithm:  alg,
		State:      tdns.Sig0StatePublished,
		Creator:    "sig0-roll",
	})
	if err == nil && resp != nil && resp.Error {
		err = fmt.Errorf("%s", resp.ErrorMsg)
	}
	if err == nil && (resp == nil || resp.GeneratedSig0Key == nil) {
		err = fmt.Errorf("the keystore returned no key")
	}
	if err != nil {
		return 0, 0, fmt.Errorf("the new SIG(0) key of %s: %w", zone, err)
	}
	return zk.held.keyid, resp.GeneratedSig0Key.KeyRR.KeyTag(), nil
}

// oweRoll keeps the roll of the zone's key as owed, on disk, unless a roll is
// under way: a removal's obligation, not a gate (design 5.2, plan S17b). The
// passes make the new key, on the roll's own schedule, and find whether the
// zone uses a key at all. An agent that loses the lead ends it (endRollHere),
// and the new leader owes its own.
func (conf *Config) oweRoll(zone ZoneName) {
	// the debt first: it outlives this agent's lead and its roll
	if err := conf.InternalMp.Instructions.noteRollDebt(string(zone), time.Now(), time.Time{}); err != nil {
		lgAgent.Error("the roll owed could not be kept with the zone's serials", "zone", zone, "err", err)
	}
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return
	}
	err := conf.keySetupLocked(zone, func() error {
		if r, err := loadRoll(kdb, zone); err != nil || r != nil {
			return err
		}
		return saveRoll(kdb, &sig0Roll{zone: zone, phase: rollOwed, started: time.Now()})
	})
	if err != nil {
		lgAgent.Error("the roll a removal owes could not be kept", "zone", zone, "err", err)
		return
	}
	lgAgent.Info("rolling the zone's SIG(0) key", "zone", zone, "phase", rollOwed)
}

// rollDebtTurn is the zone's owed roll at this agent's turn (plan S17b; the
// project owner, 2026-11-05): an owed roll outlives the removal and the lead
// until it is done. Each voting member's first-hand telling of a roll owed or
// done is kept (noteRollDebt); a leader with a roll owed and none on its disk
// owes it itself; and a roll owed for more than twice roll-retry is warned of,
// once an hour.
func (conf *Config) rollDebtTurn(zone string) {
	s := conf.InternalMp.Instructions
	if s == nil {
		return
	}
	if tm := conf.InternalMp.MPTransport; tm != nil && tm.stamps != nil {
		voters := s.activeVoters(zone)
		for _, st := range tm.stamps.firstHand(canonicalName(zone)) {
			if st.RollOwed.IsZero() && st.RollDone.IsZero() || !isAmong(voters, AgentId(st.identity)) {
				continue
			}
			if err := s.noteRollDebt(zone, st.RollOwed, st.RollDone); err != nil {
				lgAgent.Error("a member's roll owed or done could not be kept", "zone", zone, "member", st.identity, "err", err)
			}
		}
	}
	owed, _ := s.rollDebt(zone)
	if owed.IsZero() {
		return
	}
	z := ZoneName(zone)
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil && lem.IsLeader(z) {
		conf.resumeOwedRoll(z)
	}
	if time.Since(owed) > 2*rollRetryFor(conf.MpConfig()) && conf.InternalMp.keyLogs.due("roll owed "+zone) {
		lgAgent.Warn("the roll of the zone's SIG(0) key has been owed for more than twice roll-retry", "zone", zone,
			"since", owed.UTC().Format(time.RFC3339))
	}
}

// resumeOwedRoll has a leader owe the roll that the zone's debt holds, with
// none on its disk. It looks under the zone's key setup, where a pass that
// ends the roll notes it done and forgets it (rollPass): a roll ended as the
// turn looks is not owed again.
func (conf *Config) resumeOwedRoll(zone ZoneName) {
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return
	}
	owes := false
	err := conf.keySetupLocked(zone, func() error {
		if owed, _ := conf.InternalMp.Instructions.rollDebt(string(zone)); owed.IsZero() {
			return nil
		}
		if r, err := loadRoll(kdb, zone); err != nil || r != nil {
			return err
		}
		owes = true
		return saveRoll(kdb, &sig0Roll{zone: zone, phase: rollOwed, started: time.Now()})
	})
	if err != nil {
		lgAgent.Error("the roll owed could not be kept", "zone", zone, "err", err)
		return
	}
	if owes {
		lgAgent.Info("rolling the zone's SIG(0) key", "zone", zone, "phase", rollOwed)
	}
}

// rollCause is why a pass of the zone's roll runs: a step's own while a
// removal is under way (plan S17b), and otherwise held by a freeze.
func (conf *Config) rollCause(zone ZoneName) syncCause {
	if len(conf.InternalMp.Instructions.removalIdentities(string(zone))) > 0 {
		return syncStep
	}
	return syncOther
}

// rollInBackground runs a pass of the zone's roll on a goroutine of its own,
// unless one runs.
func (conf *Config) rollInBackground(ctx context.Context, zone ZoneName) {
	b := &conf.InternalMp.sig0Rolls
	if !b.claim(zone) {
		return
	}
	b.goroutines.Add(1)
	go func() {
		defer b.goroutines.Done()
		defer b.release(zone)
		conf.rollPass(ctx, zone, conf.rollCause(zone))
	}()
}

// rollOnce runs a pass of the zone's roll here, unless one runs: it reports
// whether it ran.
func (conf *Config) rollOnce(ctx context.Context, zone ZoneName, cause syncCause) bool {
	b := &conf.InternalMp.sig0Rolls
	if !b.claim(zone) {
		return false
	}
	defer b.release(zone)
	conf.rollPass(ctx, zone, cause)
	return true
}

// rollsDue runs a pass of every roll in the agent's keystores, its own and
// each zone's (zoneKeyDB): the backstop, from the 30 s ticker, which carries
// a roll waiting for its members and one whose retry is due.
func (conf *Config) rollsDue(ctx context.Context) {
	seen := map[*tdns.KeyDB]bool{}
	var kdbs []*tdns.KeyDB
	add := func(kdb *tdns.KeyDB) {
		if kdb != nil && !seen[kdb] {
			seen[kdb] = true
			kdbs = append(kdbs, kdb)
		}
	}
	if conf.Config != nil {
		add(conf.Config.Internal.KeyDB)
	}
	for _, zd := range tdns.Zones.Items() {
		if zd != nil {
			add(zd.KeyDB)
		}
	}
	for _, kdb := range kdbs {
		for _, zone := range rollZones(kdb) {
			conf.rollInBackground(ctx, zone)
		}
	}
}

// rollPass takes the zone's roll as far as it goes now: phase by phase,
// until one waits or fails. Held while the zone is frozen, unless cause is
// a step of the reconciliation (S17b), and while this agent does not lead
// the zone.
func (conf *Config) rollPass(ctx context.Context, zone ZoneName, cause syncCause) {
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return
	}
	for ctx.Err() == nil {
		r, err := loadRoll(kdb, zone)
		if err != nil || r == nil {
			return
		}
		if lem := conf.InternalMp.LeaderElectionManager; lem == nil || !lem.IsLeader(zone) {
			// another agent leads, by the group's election or the zone's:
			// the roll ends here; with no leader known yet it waits
			if lem != nil {
				if leader, ok := lem.ZoneLeader(zone); ok && !sameName(string(leader), string(conf.localAgentID())) {
					conf.endRollHere(kdb, r, leader)
				}
			}
			return
		}
		if cause != syncStep && len(conf.zoneFrozen(string(zone))) > 0 {
			return
		}
		if time.Now().Before(r.nextTry) {
			return
		}
		var next string
		_ = conf.keySetupLocked(zone, func() error {
			next, err = conf.rollStep(ctx, kdb, r)
			return nil
		})
		if err != nil {
			retry := rollRetryFor(conf.MpConfig())
			r.failures++
			r.lastErr = err.Error()
			r.nextTry = time.Now().Add(retry)
			if serr := saveRoll(kdb, r); serr != nil {
				lgAgent.Error("the roll of the zone's SIG(0) key could not be kept", "zone", zone, "err", serr)
			}
			lgAgent.Warn("the roll of the zone's SIG(0) key failed, trying again", "zone", zone, "phase", r.phase, "in", retry, "err", err)
			return
		}
		switch next {
		case "":
			return // waiting
		case rollDone:
			// under the zone's key setup, as resumeOwedRoll looks: it finds
			// the roll on disk or the debt ended
			var nerr, derr error
			_ = conf.keySetupLocked(zone, func() error {
				nerr = conf.InternalMp.Instructions.noteRollDebt(string(zone), time.Time{}, time.Now())
				derr = deleteRoll(kdb, zone)
				return nil
			})
			if derr != nil {
				lgAgent.Error("the roll of the zone's SIG(0) key is done but could not be forgotten", "zone", zone, "err", derr)
			}
			if nerr != nil {
				lgAgent.Error("the roll done could not be kept with the zone's serials", "zone", zone, "err", nerr)
			}
			lgAgent.Info("rolling the zone's SIG(0) key", "zone", zone, "phase", rollDone, "old", r.oldKeyid, "new", r.newKeyid)
			return
		}
		r.phase, r.failures, r.lastErr, r.nextTry = next, 0, "", time.Time{}
		if err := saveRoll(kdb, r); err != nil {
			lgAgent.Error("the roll of the zone's SIG(0) key could not be kept", "zone", zone, "err", err)
			return
		}
		lgAgent.Info("rolling the zone's SIG(0) key", "zone", zone, "phase", next, "old", r.oldKeyid, "new", r.newKeyid)
	}
}

// rollStep does the roll's next phase, under the zone's key-setup lock. It
// returns the phase reached, "" while it waits, or an error for a retry.
func (conf *Config) rollStep(ctx context.Context, kdb *tdns.KeyDB, r *sig0Roll) (string, error) {
	zone := r.zone
	switch r.phase {
	case rollOwed:
		switch uses, known := conf.zoneKeyUse(ctx, zone); {
		case !known:
			return "", fmt.Errorf("whether the parent of %s takes UPDATE is not known yet", zone)
		case !uses:
			lgAgent.Info("the zone has no SIG(0) key to roll: its parent takes no UPDATE", "zone", zone)
			return rollDone, nil
		}
		// A leader whose key has no recorded word from the parent yet (one it
		// imported, say) waits for it, with no try counted: its offers in this
		// lead ask the parent, and the ticker passes the roll again (rollsDue)
		if conf.keyPending(ctx, zone) {
			return "", nil
		}
		oldKeyid, newKeyid, err := makeRolledKey(kdb, zone, parentSyncKeygenAlgorithm())
		if err != nil {
			return "", err
		}
		r.oldKeyid, r.newKeyid = oldKeyid, newKeyid
		return rollMade, nil

	case rollMade:
		oldKey := sig0RowByID(kdb, zone, tdns.Sig0StateActive, r.oldKeyid)
		newKey := sig0RowByID(kdb, zone, tdns.Sig0StatePublished, r.newKeyid)
		if oldKey == nil || newKey == nil {
			return "", fmt.Errorf("the keystore holds key %d active and key %d published no more", r.oldKeyid, r.newKeyid)
		}
		if err := conf.addKeyAtParent(ctx, zone, newKey.key, oldKey); err != nil {
			return "", err
		}
		return rollAdded, nil

	case rollAdded:
		newKey := sig0RowByID(kdb, zone, tdns.Sig0StatePublished, r.newKeyid)
		if newKey == nil {
			return "", fmt.Errorf("the keystore holds key %d published no more", r.newKeyid)
		}
		state, err := conf.rollParentOf().keyState(ctx, zone, r.newKeyid)
		if err != nil {
			return "", fmt.Errorf("the KeyState inquiry for key %d: %w", r.newKeyid, err)
		}
		tdns.UpdateParentState(kdb, string(zone), r.newKeyid, state)
		if state != edns0.KeyStateTrusted {
			return "", fmt.Errorf("the parent does not trust key %d yet (%s)", r.newKeyid, edns0.KeyStateToString(state))
		}
		if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
			conf.noteTrustHeard(zone, r.newKeyid, lem.LeadStart(zone))
		}
		if err := conf.publishRolledKEY(zone, newKey); err != nil {
			return "", err
		}
		return rollPublished, nil

	case rollPublished:
		// step 5 made in the keystore, its phase not written (a restart
		// between the two)
		if sig0RowByID(kdb, zone, tdns.Sig0StateActive, r.newKeyid) != nil && sig0RowByID(kdb, zone, tdns.Sig0StateRetired, r.oldKeyid) != nil {
			return rollActivated, nil
		}
		return conf.rollMembers(kdb, r)

	case rollActivated:
		newKey := sig0RowByID(kdb, zone, tdns.Sig0StateActive, r.newKeyid)
		oldKey := sig0RowByID(kdb, zone, tdns.Sig0StateRetired, r.oldKeyid)
		if newKey == nil || oldKey == nil {
			return "", fmt.Errorf("the keystore holds key %d active and key %d retired no more", r.newKeyid, r.oldKeyid)
		}
		if err := conf.deleteKeyAtParent(ctx, zone, oldKey.key, newKey); err != nil {
			return "", err
		}
		return rollDone, nil
	}
	return "", fmt.Errorf("unknown phase %q", r.phase)
}

// publishRolledKEY publishes the new key's KEY as the leader's replace, and
// books its recipients: the combiner and the zone's agents.
func (conf *Config) publishRolledKEY(zone ZoneName, newKey *sig0Row) error {
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		return fmt.Errorf("no transport to publish the KEY with")
	}
	// booked before it is sent: a confirmation can come back at once
	agents, _ := tm.getAllAgentsForZone(zone)
	var expected []string
	if tm.combinerID != "" {
		expected = append(expected, canonicalName(string(tm.combinerID)))
	}
	for _, a := range agents {
		expected = append(expected, canonicalName(string(a)))
	}
	distID := transport.GenerateDistributionID()
	tm.rollKEYs.expect(zone, distID, expected)
	// an agent the KEY is not queued for would never answer: the try fails
	_, _, agentsErr, err := sendZoneKEY(tm, zone, newKey.key, distID)
	if err == nil {
		err = agentsErr
	}
	if err != nil {
		tm.rollKEYs.forget(zone)
		return fmt.Errorf("the new KEY could not be sent: %w", err)
	}
	// the zone's key is published: an earlier publication that failed, or
	// was held, no longer holds the zone. No set-up runs during the roll
	conf.InternalMp.keyPolls.published(zone)
	return nil
}

// rollMembers is step 4: once every recipient has confirmed the new KEY
// (members with no role after the time-out), the new key is made active and
// the old one retired at the leader, in one transaction. A recipient that
// applied the KEY (SUCCESS), or keeps it and does not apply it by its role
// (IGNORED: a combiner that signs nothing publishes no KEY), has taken it;
// any other final word has not. A KEY booked in no earlier pass of this process (a restart), or
// refused, is published again.
func (conf *Config) rollMembers(kdb *tdns.KeyDB, r *sig0Roll) (string, error) {
	zone := r.zone
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		return "", fmt.Errorf("no transport to hear the members with")
	}
	st, ok := tm.rollKEYs.state(zone)
	if !ok {
		newKey := sig0RowByID(kdb, zone, tdns.Sig0StatePublished, r.newKeyid)
		if newKey == nil {
			return "", fmt.Errorf("the keystore holds key %d published no more", r.newKeyid)
		}
		return "", conf.publishRolledKEY(zone, newKey)
	}
	var awaited []string
	for _, rcpt := range st.expected {
		w, heard := st.heard[rcpt]
		switch {
		case !heard:
			awaited = append(awaited, rcpt)
		case w.status != "SUCCESS" && w.status != "IGNORED":
			tm.rollKEYs.forget(zone)
			return "", fmt.Errorf("%s did not take the new KEY (%s: %s)", rcpt, w.status, w.message)
		}
	}
	if len(awaited) > 0 {
		only, wait := noRoleOnly(zone, awaited, st.since, time.Now(), noRoleTimeoutFor(conf.MpConfig()))
		if !only || wait > 0 {
			return "", nil
		}
		for _, a := range awaited {
			lgEngine.Warn("a member with no role did not confirm in time, going on", "zone", zone, "member", a, "what", "the zone's new KEY")
		}
	}
	if err := activateRolledKey(kdb, zone, r.newKeyid, r.oldKeyid); err != nil {
		return "", fmt.Errorf("making key %d active and retiring key %d: %w", r.newKeyid, r.oldKeyid, err)
	}
	tm.rollKEYs.forget(zone)
	return rollActivated, nil
}

// activateRolledKey makes the new key active and retires the old one, in one
// transaction of the keystore.
func activateRolledKey(kdb *tdns.KeyDB, zone ZoneName, newKeyid, oldKeyid uint16) error {
	var err error
	for try := 0; try < keystoreRetries; try++ {
		var tx *tdns.Tx
		tx, err = kdb.Begin("sig0-roll")
		if keystoreBusy(err) {
			time.Sleep(time.Duration(try+1) * keystoreRetryStep)
			continue
		}
		if err != nil {
			return err
		}
		for _, kp := range []tdns.KeystorePost{
			{Command: "sig0-mgmt", SubCommand: "setstate", Keyname: dns.Fqdn(string(zone)), Keyid: newKeyid, State: tdns.Sig0StateActive},
			{Command: "sig0-mgmt", SubCommand: "setstate", Keyname: dns.Fqdn(string(zone)), Keyid: oldKeyid, State: tdns.Sig0StateRetired},
		} {
			resp, kerr := kdb.Sig0KeyMgmt(tx, kp)
			if kerr == nil && resp != nil && resp.Error {
				kerr = fmt.Errorf("%s", resp.ErrorMsg)
			}
			if kerr != nil {
				tx.Rollback()
				return kerr
			}
		}
		return tx.Commit()
	}
	return err
}

// endRollHere ends the roll of an agent that another one now leads, as a
// member's keys follow the zone (plan S17a, a reading for the project
// owner): when the zone publishes the new KEY the new key is made active and
// the old one retired, as an import would; otherwise a new key made here
// alone is deleted, and one the parent took is retired: the parent trusts
// it until this agent, leading, deletes it there (sweepRetiredKeys).
func (conf *Config) endRollHere(kdb *tdns.KeyDB, r *sig0Roll, leader AgentId) {
	zone := r.zone
	var err error
	_ = conf.keySetupLocked(zone, func() error {
		newKey := sig0RowByID(kdb, zone, tdns.Sig0StatePublished, r.newKeyid)
		pub := publishedKeys(zone)
		switch {
		case newKey == nil:
		case len(pub) == 1 && sameKey(pub[0], newKey.key):
			err = activateRolledKey(kdb, zone, r.newKeyid, r.oldKeyid)
		case r.phase == rollMade:
			err = sig0KeyChange(kdb, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "delete", Zone: string(zone), Keyname: string(zone), Keyid: r.newKeyid})
		default:
			err = sig0KeyChange(kdb, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "setstate", Keyname: dns.Fqdn(string(zone)), Keyid: r.newKeyid, State: tdns.Sig0StateRetired})
		}
		if err == nil {
			err = deleteRoll(kdb, zone)
		}
		return nil
	})
	if err != nil {
		lgAgent.Error("the roll of the zone's SIG(0) key could not be ended here", "zone", zone, "phase", r.phase, "err", err)
		return
	}
	if tm := conf.InternalMp.MPTransport; tm != nil {
		tm.rollKEYs.forget(zone)
	}
	lgAgent.Info("the roll of the zone's SIG(0) key ends here: another agent leads the zone", "zone", zone, "phase", r.phase,
		"old", r.oldKeyid, "new", r.newKeyid, "leader", leader)
}

func sig0KeyChange(kdb *tdns.KeyDB, kp tdns.KeystorePost) error {
	resp, err := sig0KeyMgmtRetried(kdb, kp)
	if err == nil && resp != nil && resp.Error {
		err = fmt.Errorf("%s", resp.ErrorMsg)
	}
	return err
}

// sweepInBackground runs sweepRetiredKeys on a goroutine of its own, at
// most every roll-retry for a zone.
func (conf *Config) sweepInBackground(ctx context.Context, zone ZoneName) {
	b := &conf.InternalMp.sig0Rolls
	b.goroutines.Add(1)
	go func() {
		defer b.goroutines.Done()
		conf.sweepRetiredKeys(ctx, zone)
	}()
}

// sweepRetiredKeys: at the zone's leader, which holds the zone's key and the
// parent trusts it, and runs no roll, each retired key of the zone it holds
// that the parent may still trust (by what was last recorded of it) is asked
// about, and deleted at the parent, signed with the zone's key. A key the
// parent does not trust is not asked about again. At most every roll-retry
// while one is left to ask about.
func (conf *Config) sweepRetiredKeys(ctx context.Context, zone ZoneName) {
	lem := conf.InternalMp.LeaderElectionManager
	kdb := conf.zoneKeyDB(zone)
	if lem == nil || !lem.IsLeader(zone) || kdb == nil {
		return
	}
	if r, err := loadRoll(kdb, zone); err != nil || r != nil {
		return
	}
	zk, err := readZoneKey(kdb, zone)
	if err != nil || zk.held == nil || zk.rolling || len(zk.active) != 1 || zk.held.parentState != edns0.KeyStateTrusted {
		return
	}
	retired, err := sig0Rows(kdb, zone, tdns.Sig0StateRetired)
	if err != nil {
		return
	}
	retired = slices.DeleteFunc(retired, func(old sig0Row) bool {
		return old.key == nil || old.keyid == zk.held.keyid || (old.parentState != 0 && old.parentState != edns0.KeyStateTrusted)
	})
	if len(retired) == 0 || !conf.InternalMp.sig0Rolls.sweepDue(zone, rollRetryFor(conf.MpConfig())) {
		return
	}
	for _, old := range retired {
		state, err := conf.rollParentOf().keyState(ctx, zone, old.keyid)
		if err != nil {
			lgAgent.Warn("the parent could not be asked about a retired SIG(0) key of the zone", "zone", zone, "keyid", old.keyid, "err", err)
			continue
		}
		if state == edns0.KeyStateTrusted {
			if err := conf.deleteKeyAtParent(ctx, zone, old.key, zk.held); err != nil {
				lgAgent.Warn("the parent still trusts a retired SIG(0) key of the zone, and its delete failed", "zone", zone, "keyid", old.keyid, "err", err)
				continue
			}
			lgAgent.Info("a retired SIG(0) key of the zone the parent still trusted is deleted there", "zone", zone, "keyid", old.keyid, "signer", zk.held.keyid)
			state = edns0.KeyStateUnknown
		}
		tdns.UpdateParentState(kdb, string(zone), old.keyid, state)
	}
}

// rollLine is the zone's roll for `agent parentsync status`, "" when none
// runs.
func (conf *Config) rollLine(kdb *tdns.KeyDB, zone ZoneName) string {
	r, err := loadRoll(kdb, zone)
	if err != nil || r == nil {
		return ""
	}
	// since when it is owed: the zone's debt, which may be older than this
	// agent's roll (an earlier leader's)
	since := r.started
	if owed, _ := conf.InternalMp.Instructions.rollDebt(string(zone)); !owed.IsZero() {
		since = owed
	}
	owed := "roll owed since " + removalTime(since)
	switch {
	case r.failures > 0 && time.Now().Before(r.nextTry):
		return fmt.Sprintf("%s, next try at %s", owed, r.nextTry.UTC().Format("15:04")+" UTC")
	case len(conf.zoneFrozen(string(zone))) > 0 && conf.rollCause(zone) != syncStep:
		return owed + ", held until the zone's transition is done"
	case r.phase == rollOwed:
		return owed + ", the new key is not made yet"
	case r.phase == rollMade:
		return fmt.Sprintf("rolling: new key %d made, not yet added at the parent", r.newKeyid)
	case r.phase == rollActivated:
		return fmt.Sprintf("rolling: new key %d in use, key %d not yet deleted at the parent", r.newKeyid, r.oldKeyid)
	}
	return fmt.Sprintf("rolling: new key %d added at the parent, waiting for the members", r.newKeyid)
}

// dropOtherKEYs is a member's word on taking the leader's KEY: it keeps the
// leader's KEY and no other (plan S17a, the third KEY item of the membership
// plan's step 9). The combiner is asked to drop a KEY held under another
// name, and the KEY leaves this agent's data once it has: until then the data
// is the record of what is owed, and the tick asks again (retryKEYPurges).
// After a restart the combiner's own read gives such a KEY back, so nothing
// else is kept on disk. This agent's own name is dropOwnKEY's. On the engine's
// goroutine, which owns the repo.
func (conf *Config) dropOtherKEYs(zdr *ZoneDataRepo, zone ZoneName, leader AgentId) {
	tm := conf.InternalMp.MPTransport
	if zdr == nil || tm == nil {
		return
	}
	ar, ok := zdr.Repo.Get(zone)
	if !ok || ar == nil {
		return
	}
	// only once the leader's own KEY is here
	theirs, ok := ar.Data.Get(leader)
	if !ok || theirs == nil || theirs.RRtypes == nil || len(theirs.RRtypes.GetOnlyRRSet(dns.TypeKEY).RRs) == 0 {
		return
	}
	every := rollRetryFor(conf.MpConfig())
	self := conf.localAgentID()
	conf.dropOwnKEY(zdr, zone, self, leader, theirs.RRtypes.GetOnlyRRSet(dns.TypeKEY).RRs, every)
	// and a drop is asked for only once this agent's combiner holds the
	// leader's KEY: one that came first would leave the zone with no KEY
	// until it did (leaderKEYConfirmed)
	held := zdr.combinerHoldsSet(zone, leader, dns.TypeKEY)
	for _, id := range ar.Data.Keys() {
		if sameName(string(id), string(leader)) {
			tm.keyPurges.forget(zone, id)
			continue
		}
		if sameName(string(id), string(self)) {
			continue
		}
		od, ok := ar.Data.Get(id)
		if !ok || od == nil || od.RRtypes == nil {
			continue
		}
		if _, has := od.RRtypes.Get(dns.TypeKEY); !has {
			tm.keyPurges.forget(zone, id)
			continue
		}
		if tm.keyPurges.taken(zone, id) {
			od.RRtypes.Delete(dns.TypeKEY)
			zdr.removeTracking(zone, id, dns.TypeKEY)
			tm.keyPurges.forget(zone, id)
			lgEngine.Info("a KEY held under another name than the leader's is dropped", "zone", zone, "origin", id, "leader", leader)
			continue
		}
		if !held {
			continue
		}
		distID, due := tm.keyPurges.due(zone, id, every)
		if !due {
			continue
		}
		if err := sendKEYPurge(tm, zone, id, distID); err != nil {
			lgEngine.Warn("the combiner could not be asked to drop a KEY held under another name, trying again", "zone", zone, "origin", id, "in", every, "err", err)
			continue
		}
		lgEngine.Info("the combiner is asked to drop a KEY held under another name than the leader's", "zone", zone, "origin", id, "leader", leader)
	}
}

// dropOwnKEY is dropOtherKEYs for the KEY under this agent's own name, from
// when it led. That KEY went straight to the combiner (sendZoneKEY), so the
// data need not hold it, and the apex says what is owed: the zone publishes
// the leader's KEY and another. Until the new leader rolls, the zone publishes
// the one KEY, and this agent's name may be all that holds it, so nothing is
// asked. A combiner that publishes no KEY shows nothing to drop here.
func (conf *Config) dropOwnKEY(zdr *ZoneDataRepo, zone ZoneName, self, leader AgentId, leaderKEY []dns.RR, every time.Duration) {
	tm := conf.InternalMp.MPTransport
	if self == "" {
		return
	}
	if sameName(string(self), string(leader)) || !publishesBeside(zone, leaderKEY) {
		tm.keyPurges.forget(zone, self)
		return
	}
	if tm.keyPurges.taken(zone, self) {
		if ar, ok := zdr.Repo.Get(zone); ok && ar != nil {
			if od, ok := ar.Data.Get(self); ok && od != nil && od.RRtypes != nil {
				od.RRtypes.Delete(dns.TypeKEY)
				zdr.removeTracking(zone, self, dns.TypeKEY)
			}
		}
		return
	}
	distID, due := tm.keyPurges.due(zone, self, every)
	if !due {
		return
	}
	if err := sendKEYPurge(tm, zone, self, distID); err != nil {
		lgEngine.Warn("the combiner could not be asked to drop this agent's own KEY, trying again", "zone", zone, "in", every, "err", err)
		return
	}
	lgEngine.Info("the zone publishes the leader's KEY and another: the combiner is asked to drop this agent's own KEY", "zone", zone, "origin", self, "leader", leader)
}

// publishesBeside: the apex of this agent's copy of the zone publishes one of
// keys and another KEY.
func publishesBeside(zone ZoneName, keys []dns.RR) bool {
	published := publishedKeys(zone)
	return len(published) > 1 && slices.ContainsFunc(published, func(k *dns.KEY) bool {
		return slices.ContainsFunc(keys, func(rr dns.RR) bool {
			held, ok := rr.(*dns.KEY)
			return ok && sameKey(held, k)
		})
	})
}

// retryKEYPurges: the tick's word on the KEYs held under another name than
// the zone's leader's: those the combiner has dropped go from the data, and
// the others are asked for again when due. On the engine's goroutine.
func (conf *Config) retryKEYPurges(zdr *ZoneDataRepo) {
	lem := conf.InternalMp.LeaderElectionManager
	if zdr == nil || lem == nil {
		return
	}
	for _, zone := range zdr.Repo.Keys() {
		ar, ok := zdr.Repo.Get(zone)
		if !ok || ar == nil {
			continue
		}
		holders := 0
		for _, od := range ar.Data.Items() {
			if od != nil && od.RRtypes != nil && len(od.RRtypes.GetOnlyRRSet(dns.TypeKEY).RRs) > 0 {
				holders++
			}
		}
		// the leader's alone is enough: this agent's own may be at its
		// combiner and not here (dropOwnKEY)
		if holders == 0 {
			continue
		}
		if leader, ok := lem.ZoneLeader(zone); ok {
			conf.dropOtherKEYs(zdr, zone, leader)
		}
	}
}

// leaderKEYConfirmed is the combiner's final confirmation of distID: when it
// is the hand-over of the zone's leader's KEY, the KEYs held under another
// name are asked to be dropped now, not at the next tick (dropOtherKEYs). On
// the engine's goroutine.
func (conf *Config) leaderKEYConfirmed(zdr *ZoneDataRepo, zone ZoneName, distID string) {
	lem := conf.InternalMp.LeaderElectionManager
	if zdr == nil || lem == nil || distID == "" {
		return
	}
	leader, ok := lem.ZoneLeader(zone)
	if !ok {
		return
	}
	if n := zdr.notes[zone][leader][dns.TypeKEY]; n == nil || n.distID != distID {
		return
	}
	conf.dropOtherKEYs(zdr, zone, leader)
}

// keyPurge is the drop of origin's KEY at this agent's combiner: an empty
// replace of KEY in origin's name with the withdrawal's flag, a removal the
// combiner takes from its own agent only, whether or not origin votes
// (combinerTakesRemoval, S16). An instruction with no location takes origin's
// instruction back with it: stored, it would publish the KEY again at a reapply.
func keyPurge(zone ZoneName, origin AgentId) *ZoneUpdate {
	zu := (&Withdraw{Provider: string(origin), RRtype: "KEY"}).update(zone)
	zu.Publish = &core.PublishInstruction{}
	return zu
}

// sendKEYPurge sends the combiner the drop of origin's KEY under distID; a
// test stands in for it.
var sendKEYPurge = func(tm *MPTransportBridge, zone ZoneName, origin AgentId, distID string) error {
	_, err := tm.EnqueueForCombiner(zone, keyPurge(zone, origin), distID)
	return err
}

// keyPurgeBook: the drops of KEYs held under another name this agent asked
// its combiner for, and whether it has made them. A leaf lock.
type keyPurgeBook struct {
	mu   sync.Mutex
	sent map[keyPurgeKey]*keyPurgeSent
}

type keyPurgeKey struct {
	zone   ZoneName
	origin string
}

type keyPurgeSent struct {
	distID  string
	at      time.Time
	dropped bool
}

func purgeKey(zone ZoneName, origin AgentId) keyPurgeKey {
	return keyPurgeKey{zone: canonZone(zone), origin: canonicalName(string(origin))}
}

// due books a new request for origin's drop, under a new distribution ID,
// unless the combiner has made it or one went within every.
func (b *keyPurgeBook) due(zone ZoneName, origin AgentId, every time.Duration) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sent == nil {
		b.sent = map[keyPurgeKey]*keyPurgeSent{}
	}
	k := purgeKey(zone, origin)
	if s := b.sent[k]; s != nil && (s.dropped || time.Since(s.at) < every) {
		return "", false
	}
	distID := transport.GenerateDistributionID()
	b.sent[k] = &keyPurgeSent{distID: distID, at: time.Now()}
	return distID, true
}

// heard notes the combiner's word on a drop it was asked for. SUCCESS, or
// IGNORED (a combiner that signs nothing publishes no KEY): it is dropped.
// Any other final word makes the request due again at the next tick.
func (b *keyPurgeBook) heard(distID, status, message string, notYet bool) {
	if status == "PENDING" || notYet {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, s := range b.sent {
		if s.distID != distID {
			continue
		}
		if status == "SUCCESS" || status == "IGNORED" {
			s.dropped = true
		} else {
			s.at = time.Time{}
			lgEngine.Warn("the combiner did not drop a KEY held under another name, trying again", "zone", k.zone, "origin", k.origin, "status", status, "msg", message)
		}
	}
}

func (b *keyPurgeBook) taken(zone ZoneName, origin AgentId) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sent[purgeKey(zone, origin)]
	return s != nil && s.dropped
}

func (b *keyPurgeBook) forget(zone ZoneName, origin AgentId) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sent, purgeKey(zone, origin))
}

// apiZoneParentSync is tdns's /zone/parentsync, but its roll-key for a
// multi-provider zone is the leader's roll (plan S17a): `agent zone dsync
// roll-sig0-key` at the agent that leads the zone. The roll runs whole, in
// the background; the answer names the new key.
func (conf *Config) apiZoneParentSync(ctx context.Context, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req tdns.ZoneParentSyncPost
		if json.Unmarshal(body, &req) != nil || req.Command != "roll-key" || !hasHSYNC3(instructionsFor(ZoneName(dns.Fqdn(req.Zone)))) {
			r.Body = io.NopCloser(bytes.NewReader(body))
			next(w, r)
			return
		}
		zone := ZoneName(dns.Fqdn(req.Zone))
		resp := tdns.ZoneParentSyncResponse{AppName: tdns.Globals.App.Name, Time: time.Now(), Zone: string(zone)}
		if req.Action != "" && req.Action != "complete" {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("zone %s is a multi-provider zone: its SIG(0) key is rolled whole by the leader, not by phase (%q)", zone, req.Action)
		} else if keyid, err := conf.startSig0Roll(ctx, zone, req.Algorithm); err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
		} else {
			resp.NewKeyID = keyid
			resp.Msg = fmt.Sprintf("roll of %s's SIG(0) key started: new key %d", zone, keyid)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			lgAgent.Error("json encode failed", "handler", "zoneParentSync", "err", err)
		}
	}
}
