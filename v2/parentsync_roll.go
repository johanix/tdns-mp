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
	"sync"
	"time"

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
// while the zone is frozen, except as a step of the reconciliation. It runs
// only while this agent leads the zone: a roll left at an agent that lost
// the lead goes on if it leads again.

const (
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
	case errors.Is(err, sql.ErrNoRows):
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

// rollingKey is the new key of the zone's roll between its steps 3 and 5,
// kept published at the leader. Nil otherwise. A roll in "added" counts too:
// its KEY may have gone out before the phase was written.
func rollingKey(kdb *tdns.KeyDB, zone ZoneName) *sig0Row {
	r, err := loadRoll(kdb, zone)
	if err != nil || r == nil || (r.phase != rollAdded && r.phase != rollPublished) {
		return nil
	}
	return sig0RowByID(kdb, zone, tdns.Sig0StatePublished, r.newKeyid)
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
	goroutines sync.WaitGroup
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
		if r, err := loadRoll(kdb, zone); err == nil && r != nil {
			return fmt.Errorf("a roll of the SIG(0) key of %s is under way (%s, new key %d)", zone, r.phase, r.newKeyid)
		}
		zk, err := readZoneKey(kdb, zone)
		switch {
		case err != nil:
			return fmt.Errorf("the SIG(0) keys of %s cannot be read: %w", zone, err)
		case zk.several():
			return fmt.Errorf("zone %s publishes several SIG(0) KEYs; an operator has to leave one", zone)
		case zk.held == nil || zk.held.key == nil:
			return fmt.Errorf("this agent does not hold the SIG(0) key of zone %s", zone)
		case len(zk.active) != 1:
			return fmt.Errorf("zone %s has %d active SIG(0) keys", zone, len(zk.active))
		case zk.held.parentState != edns0.KeyStateTrusted:
			return fmt.Errorf("the parent does not trust the SIG(0) key %d of zone %s yet", zk.held.keyid, zone)
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
			return fmt.Errorf("the new SIG(0) key of %s: %w", zone, err)
		}
		oldKeyid, newKeyid = zk.held.keyid, resp.GeneratedSig0Key.KeyRR.KeyTag()
		return saveRoll(kdb, &sig0Roll{zone: zone, phase: rollMade, oldKeyid: oldKeyid, newKeyid: newKeyid, started: time.Now()})
	})
	if err != nil {
		return 0, err
	}
	lgAgent.Info("rolling the zone's SIG(0) key", "zone", zone, "phase", rollMade, "old", oldKeyid, "new", newKeyid)
	conf.rollInBackground(ctx, zone)
	return newKeyid, nil
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
		conf.rollPass(ctx, zone, syncOther)
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

// rollsDue runs a pass of every roll in the agent's keystore: the backstop,
// from the 30 s ticker, which carries a roll waiting for its members and one
// whose retry is due.
func (conf *Config) rollsDue(ctx context.Context) {
	if conf.Config == nil || conf.Config.Internal.KeyDB == nil {
		return
	}
	for _, zone := range rollZones(conf.Config.Internal.KeyDB) {
		conf.rollInBackground(ctx, zone)
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
			if err := deleteRoll(kdb, zone); err != nil {
				lgAgent.Error("the roll of the zone's SIG(0) key is done but could not be forgotten", "zone", zone, "err", err)
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
		if err := conf.publishRolledKEY(zone, newKey); err != nil {
			return "", err
		}
		return rollPublished, nil

	case rollPublished:
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
	distID, agents, err := sendZoneKEY(tm, zone, newKey.key)
	if err != nil {
		return fmt.Errorf("the new KEY could not be sent: %w", err)
	}
	var expected []string
	if tm.combinerID != "" {
		expected = append(expected, canonicalName(string(tm.combinerID)))
	}
	for _, a := range agents {
		expected = append(expected, canonicalName(string(a)))
	}
	tm.rollKEYs.expect(zone, distID, expected)
	return nil
}

// rollMembers is step 4: once every recipient has confirmed the new KEY
// (members with no role after the time-out), the new key is made active and
// the old one retired at the leader, in one transaction. A KEY booked in no
// earlier pass of this process (a restart), or refused, is published again.
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
		case w.status != "SUCCESS" && w.status != "PARTIAL":
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

// rollLine is the zone's roll for `agent parentsync status`, "" when none
// runs.
func (conf *Config) rollLine(kdb *tdns.KeyDB, zone ZoneName) string {
	r, err := loadRoll(kdb, zone)
	if err != nil || r == nil {
		return ""
	}
	switch {
	case r.failures > 0 && time.Now().Before(r.nextTry):
		return fmt.Sprintf("roll owed, next try at %s", r.nextTry.UTC().Format("15:04")+" UTC")
	case len(conf.zoneFrozen(string(zone))) > 0:
		return "roll owed, held until the zone's transition is done"
	case r.phase == rollMade:
		return fmt.Sprintf("rolling: new key %d made, not yet added at the parent", r.newKeyid)
	case r.phase == rollActivated:
		return fmt.Sprintf("rolling: new key %d in use, key %d not yet deleted at the parent", r.newKeyid, r.oldKeyid)
	}
	return fmt.Sprintf("rolling: new key %d added at the parent, waiting for the members", r.newKeyid)
}

// dropOtherKEYs is a member's word on taking the leader's KEY: it keeps the
// leader's KEY and no other (plan S17a, the third KEY item of the membership
// plan's step 9). A KEY held under another name is dropped from its data;
// at its combiner the drop needs S16's flagged purge (purgeKEYsAtCombiner).
// On the engine's goroutine, which owns the repo.
func (conf *Config) dropOtherKEYs(zdr *ZoneDataRepo, zone ZoneName, leader AgentId) {
	if zdr == nil {
		return
	}
	ar, ok := zdr.Repo.Get(zone)
	if !ok || ar == nil {
		return
	}
	var dropped []AgentId
	for _, id := range ar.Data.Keys() {
		if sameName(string(id), string(leader)) {
			continue
		}
		od, ok := ar.Data.Get(id)
		if !ok || od == nil || od.RRtypes == nil {
			continue
		}
		if _, has := od.RRtypes.Get(dns.TypeKEY); !has {
			continue
		}
		od.RRtypes.Delete(dns.TypeKEY)
		zdr.removeTracking(zone, id, dns.TypeKEY)
		dropped = append(dropped, id)
		lgEngine.Info("a KEY held under another name than the leader's is dropped", "zone", zone, "origin", id, "leader", leader)
	}
	if len(dropped) > 0 {
		slices.Sort(dropped)
		purgeKEYsAtCombiner(zone, dropped)
	}
}

// purgeKEYsAtCombiner is the combiner's drop of the KEYs held under these
// origins' names: S16's flagged purge, a removal in any origin's name that
// the combiner takes from its own agent only. Until S16's flag is in, the
// combiner keeps them, and an operator removes them there.
var purgeKEYsAtCombiner = func(zone ZoneName, origins []AgentId) {
	lgEngine.Warn("the combiner keeps the KEYs held under these names: it takes no purge from its agent yet", "zone", zone, "origins", origins)
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
