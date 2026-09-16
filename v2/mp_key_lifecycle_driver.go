/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The driver of the multi-provider key lifecycle: applies the table
 * (mp_key_lifecycle.go) to one zone's rows in tdns's keystore, through the
 * owner's state write, and asks its surroundings -- the Wire -- for what the
 * table's side effects need: a distribution to the peers, the parent's DS,
 * a strip of a key's RRSIGs, a resign. The agent's transport is the Wire
 * in production; the harness is in the tests.
 */
package tdnsmp

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// LifecyclePolicy is the owner's part of a zone's policy (design Q1): the
// algorithms, the standby counts, the lifetimes and the waits.
type LifecyclePolicy struct {
	KSKAlgorithm, ZSKAlgorithm uint8
	StandbyKSK, StandbyZSK     int
	KSKLifetime, ZSKLifetime   time.Duration // 0: forever
	PropagationDelay           time.Duration
	Margin                     time.Duration
	// ResendAfter is how long a distribution may wait for confirmations
	// before it is sent again (E12); 0 never resends.
	ResendAfter time.Duration
}

// Wire is what the driver needs from its surroundings.
type Wire interface {
	// OtherSigners are the zone's signing providers other than this one.
	OtherSigners(zone string) []string
	// Distribute sends the key's DNSKEY to the peers (a REPLACE of this
	// provider's DNSKEYs); DistributeRemoval its removal. Confirmations
	// come back through ZoneKeyLifecycle.Confirm.
	Distribute(zone string, keyid uint16)
	DistributeRemoval(zone string, keyid uint16)
	// ParentServesDS reports whether the parent serves the key's DS; known
	// false when the parent could not be asked.
	ParentServesDS(zone string, keyid uint16) (present, known bool)
	// Strip removes every RRSIG by the key from the served zone.
	Strip(zone string, keyid uint16) error
	// Resign asks tdns to re-sign the zone.
	Resign(zone string)
	// ServedDnskeyTTL is the TTL the DNSKEY RRset is served with.
	ServedDnskeyTTL(zone string) time.Duration
	// Report surfaces something an operator must see: a rejected key.
	Report(zone string, keyid uint16, what string)
}

// distribution is one key's distribution in flight: who must confirm, and
// who has.
type distribution struct {
	Removal  bool
	SentAt   time.Time // when the distribution first went out: what a confirmation must not predate
	LastSent time.Time // the last send (a resend included): what the resend timer runs from
	Expected map[string]bool
	Applied  map[string]bool
	Pending  map[string]bool
	Rejected map[string]bool
	Reason   string
}

// ZoneKeyLifecycle runs the machine for one zone.
type ZoneKeyLifecycle struct {
	Zone   string
	KDB    *tdns.KeyDB
	Clock  Clock
	Policy LifecyclePolicy
	Wire   Wire
	Log    func(msg string, kv ...any)

	mu       sync.Mutex
	dist     map[uint16]*distribution
	dsGone   map[uint16]bool
	rolls    map[string]bool // a rollover requested, by role
	reported map[uint16]bool // retired KSKs reported as waiting on the parent
	initErr  error           // why the driver cannot run (its persistence missing)
	rolling  string          // the role whose promotion is a rollover, while it is applied
	known    map[string]bool // the other signers last seen, for the joiners
}

// NewZoneKeyLifecycle is a driver with nothing in flight; Reload picks up
// what the keystore holds.
func NewZoneKeyLifecycle(zone string, kdb *tdns.KeyDB, clock Clock, pol LifecyclePolicy, wire Wire) *ZoneKeyLifecycle {
	if clock == nil {
		clock = RealClock
	}
	known := map[string]bool{}
	for _, p := range wire.OtherSigners(dns.Fqdn(zone)) {
		known[p] = true
	}
	l := &ZoneKeyLifecycle{Zone: dns.Fqdn(zone), KDB: kdb, Clock: clock, Policy: pol, Wire: wire,
		dist: map[uint16]*distribution{}, dsGone: map[uint16]bool{}, rolls: map[string]bool{}, reported: map[uint16]bool{}, known: known}
	if kdb != nil {
		if _, err := kdb.DB.Exec(HsyncTables["MPKeyDistribution"]); err != nil {
			// without the table nothing in flight would survive a restart:
			// the driver refuses to run until it exists (Ready)
			l.initErr = fmt.Errorf("the MPKeyDistribution table of %s: %w", l.Zone, err)
		} else {
			// a table created before last_sent existed gains the column (the
			// error for a column already there is the expected one)
			kdb.DB.Exec(`ALTER TABLE MPKeyDistribution ADD COLUMN last_sent TEXT DEFAULT ''`)
		}
	}
	return l
}

// Ready reports whether the driver can run: its persistence exists.
func (l *ZoneKeyLifecycle) Ready() error { return l.initErr }

func (l *ZoneKeyLifecycle) logf(msg string, kv ...any) {
	if l.Log != nil {
		l.Log(msg, kv...)
	}
}

func roleOf(flags uint16) string {
	if flags&dns.SEP != 0 {
		return "KSK"
	}
	return "ZSK"
}

// rows are the zone's own keys (foreign rows left out), by key id.
func (l *ZoneKeyLifecycle) rows() (map[uint16]tdns.DnssecKeyWithTimestamps, error) {
	out := map[uint16]tdns.DnssecKeyWithTimestamps{}
	for _, st := range KeyLifecycleStates {
		ks, err := tdns.GetDnssecKeysByState(l.KDB, l.Zone, st)
		if err != nil {
			return nil, fmt.Errorf("list %s keys of %s: %w", st, l.Zone, err)
		}
		for _, k := range ks {
			out[k.KeyTag] = k
		}
	}
	return out, nil
}

// keytagsOf: the zone's keytags in ascending order, the order the driver
// walks them in (the same rows, the same actions, in the same order).
func keytagsOf(all map[uint16]tdns.DnssecKeyWithTimestamps) []uint16 {
	out := make([]uint16, 0, len(all))
	for k := range all {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (l *ZoneKeyLifecycle) columnsOf(keyid uint16) (tdns.KeyRowFlags, error) {
	inv, err := tdns.GetKeyInventory(l.KDB, l.Zone)
	if err != nil {
		return tdns.KeyRowFlags{}, err
	}
	for _, it := range inv {
		if it.KeyTag == keyid {
			f := tdns.KeyRowFlags{Pub: it.Pub, Sign: it.Sign}
			if it.DS != nil {
				f.DS = sql.NullBool{Bool: *it.DS, Valid: true}
			}
			return f, nil
		}
	}
	return tdns.KeyRowFlags{}, fmt.Errorf("key %d of %s not in the inventory", keyid, l.Zone)
}

func (l *ZoneKeyLifecycle) keyView(k tdns.DnssecKeyWithTimestamps, cols tdns.KeyRowFlags) KeyView {
	v := KeyView{State: k.State, SEP: k.Flags&dns.SEP != 0, Algorithm: k.Algorithm, DSGone: l.dsGone[k.KeyTag]}
	if k.PublishedAt != nil {
		v.PublishedAt = *k.PublishedAt
	}
	if k.RetiredAt != nil {
		v.RetiredAt = *k.RetiredAt
	}
	v.Withdrawn = v.SEP && cols.DS.Valid && !cols.DS.Bool
	return v
}

func (l *ZoneKeyLifecycle) zoneView(k tdns.DnssecKeyWithTimestamps, all map[uint16]tdns.DnssecKeyWithTimestamps) ZoneView {
	role := roleOf(k.Flags)
	z := ZoneView{
		OtherSigners:     l.Wire.OtherSigners(l.Zone),
		Applied:          map[string]bool{},
		Pending:          map[string]bool{},
		Rejected:         map[string]bool{},
		PropagationDelay: l.Policy.PropagationDelay,
		ServedDnskeyTTL:  l.Wire.ServedDnskeyTTL(l.Zone),
		Margin:           l.Policy.Margin,
		Now:              l.Clock.Now(),
	}
	if d := l.dist[k.KeyTag]; d != nil {
		z.Applied, z.Pending, z.Rejected = d.Applied, d.Pending, d.Rejected
		// the expected set is the set at distribution time, minus a signer
		// that has left since (transition table O3)
		z.OtherSigners = nil
		for p := range d.Expected {
			z.OtherSigners = append(z.OtherSigners, p)
		}
	} else {
		// no distribution in flight: the key's distribution is done, nothing
		// is outstanding
		for _, p := range z.OtherSigners {
			z.Applied[p] = true
		}
	}
	active := 0
	for _, o := range all {
		if o.State != KeyStateActive || roleOf(o.Flags) != role {
			continue
		}
		active++
		if o.Algorithm == k.Algorithm && o.KeyTag != k.KeyTag {
			z.ActiveOfRoleAndAlg = true
		}
	}
	z.NoActiveOfRole = active == 0
	z.RolloverRequested = l.rolling == role
	z.RolloverPending = l.rolls[role]
	z.AlgRollInFlight = l.algRollInFlight(role, all)
	return z
}

// algRollInFlight: an active key of the role whose algorithm is not the
// policy's, beside a key of the policy's algorithm in the pipeline.
func (l *ZoneKeyLifecycle) algRollInFlight(role string, all map[uint16]tdns.DnssecKeyWithTimestamps) bool {
	want := l.Policy.ZSKAlgorithm
	if role == "KSK" {
		want = l.Policy.KSKAlgorithm
	}
	oldActive, newComing := false, false
	for _, o := range all {
		if roleOf(o.Flags) != role {
			continue
		}
		switch {
		case o.State == KeyStateActive && o.Algorithm != want:
			oldActive = true
		case o.Algorithm == want && o.State != KeyStateActive && o.State != KeyStateRetired && o.State != KeyStateMpremove && o.State != KeyStateRemoved:
			newComing = true
		}
	}
	return oldActive && newComing
}

// Apply feeds one event for one key through the table and carries out the
// row's side effects. Returns the state before and after.
func (l *ZoneKeyLifecycle) Apply(keyid uint16, ev KeyEvent) (from, to string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.initErr != nil {
		return "", "", l.initErr
	}
	return l.applyLocked(keyid, ev)
}

func (l *ZoneKeyLifecycle) applyLocked(keyid uint16, ev KeyEvent) (from, to string, err error) {
	all, err := l.rows()
	if err != nil {
		return "", "", err
	}
	k, ok := all[keyid]
	if !ok {
		return "", "", fmt.Errorf("key %d of %s is not one of the zone's own keys", keyid, l.Zone)
	}
	cols, err := l.columnsOf(keyid)
	if err != nil {
		return "", "", err
	}
	kv := l.keyView(k, cols)
	zv := l.zoneView(k, all)
	next, row := Next(kv, ev, zv)
	if row == nil {
		return k.State, k.State, nil
	}
	l.logf("key lifecycle", "zone", l.Zone, "keyid", keyid, "event", ev, "row", row.ID, "from", k.State, "to", next)
	switch row.ID {
	case "T4":
		return k.State, next, nil
	case "T5":
		d := l.dist[keyid]
		if d == nil {
			return k.State, k.State, fmt.Errorf("key %d of %s has no distribution in flight to be rejected", keyid, l.Zone)
		}
		l.Wire.Report(l.Zone, keyid, "rejected: "+d.Reason)
		return k.State, next, nil
	case "T6":
		// a fresh distribution for the current signers, the rejection gone;
		// on a key already serving it is the record a joiner must confirm;
		// on a key being removed it is the removal sent again
		l.startDistribution(keyid, k.State == KeyStateMpremove)
		return k.State, next, nil
	case "T6'":
		l.resend(keyid)
		return k.State, next, nil
	case "T11":
		l.dsGone[keyid] = true
		return k.State, next, nil
	case "T14a", "T14b", "T15":
		return k.State, next, nil
	}
	if next == k.State {
		return k.State, next, nil
	}
	if next == KeyStateMpremove {
		// the RRSIGs go before the row does: a strip that fails leaves the
		// row where it was, so the next tick tries again (nothing is left
		// in mpremove with no removal in flight)
		if err := l.Wire.Strip(l.Zone, keyid); err != nil {
			return k.State, k.State, fmt.Errorf("strip the RRSIGs of key %d: %w", keyid, err)
		}
	}
	if err := l.write(k, next, kv.SEP); err != nil {
		return k.State, k.State, err
	}
	switch next {
	case KeyStateMpdist:
		l.startDistribution(keyid, false)
		if len(l.dist[keyid].Expected) == 0 {
			// nobody to wait for (T3'): published at once
			if _, _, err := l.applyLocked(keyid, EvDistributed); err != nil {
				return k.State, next, err
			}
			return k.State, KeyStatePublished, nil
		}
	case KeyStatePublished, KeyStateStandby, KeyStateRemoved:
		// the distribution that brought the key here is done; a record a
		// joiner has yet to confirm stays (T9 waits for it)
		if d := l.dist[keyid]; d == nil || next == KeyStateRemoved || !(confirmationsOutstandingFor(d) || len(d.Rejected) > 0) {
			delete(l.dist, keyid)
			l.saveDist(keyid)
		}
	case KeyStateActive:
		l.Wire.Resign(l.Zone)
		// the previous active key of the role retires (T10)
		for _, tag := range keytagsOf(all) {
			o := all[tag]
			if o.State == KeyStateActive && o.KeyTag != keyid && roleOf(o.Flags) == roleOf(k.Flags) {
				if _, _, err := l.applyLocked(o.KeyTag, EvSuccessorActive); err != nil {
					return k.State, next, err
				}
			}
		}
	case KeyStateRetired:
		l.Wire.Resign(l.Zone)
	case KeyStateMpremove:
		delete(l.dsGone, keyid)
		l.startDistribution(keyid, true)
		if len(l.dist[keyid].Expected) == 0 {
			if _, _, err := l.applyLocked(keyid, EvDistributed); err != nil {
				return k.State, next, err
			}
			return k.State, KeyStateRemoved, nil
		}
	}
	return k.State, next, nil
}

// write moves the row to state with the state's columns (a retired KSK
// enters with its DS withdrawal already written: ds=0).
func (l *ZoneKeyLifecycle) write(k tdns.DnssecKeyWithTimestamps, state string, sep bool) error {
	cols, ok := KeyStateColumns(state, sep, state == KeyStateRetired)
	if !ok {
		return fmt.Errorf("no columns for state %s", state)
	}
	if err := tdns.UpdateKeyRowFrom(l.KDB, l.Zone, k.KeyTag, state, k.State, cols); err != nil {
		return fmt.Errorf("key %d of %s %s -> %s: %w", k.KeyTag, l.Zone, k.State, state, err)
	}
	return nil
}

// resend sends a distribution in flight again, keeping the confirmations
// it has.
func (l *ZoneKeyLifecycle) resend(keyid uint16) {
	d := l.dist[keyid]
	if d == nil {
		return
	}
	// the confirmations received stay (T6'), and so does the first send
	// time: the answer a slow signer gives to the first send is not stale
	d.LastSent = l.Clock.Now()
	l.saveDist(keyid)
	if d.Removal {
		l.Wire.DistributeRemoval(l.Zone, keyid)
	} else {
		l.Wire.Distribute(l.Zone, keyid)
	}
}

func (l *ZoneKeyLifecycle) startDistribution(keyid uint16, removal bool) {
	now := l.Clock.Now()
	d := &distribution{Removal: removal, SentAt: now, LastSent: now, Expected: map[string]bool{}, Applied: map[string]bool{}, Pending: map[string]bool{}, Rejected: map[string]bool{}}
	for _, p := range l.Wire.OtherSigners(l.Zone) {
		d.Expected[p] = true
	}
	l.dist[keyid] = d
	l.saveDist(keyid)
	if removal {
		l.Wire.DistributeRemoval(l.Zone, keyid)
	} else {
		l.Wire.Distribute(l.Zone, keyid)
	}
}

// ErrStaleConfirmation: a confirmation of a distribution that is no longer
// the one in flight (an answer to the key's distribution after its removal
// went out, or the other way round).
var ErrStaleConfirmation = errors.New("the confirmation is for a distribution no longer in flight")

// Confirm records a provider's confirmation of the key's distribution in
// flight, whichever kind it is: status applied, pending or rejected (with
// a reason), and feeds the event.
func (l *ZoneKeyLifecycle) Confirm(keyid uint16, provider, status, reason string) (from, to string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.confirmLocked(keyid, provider, status, reason, nil)
}

// ConfirmKind is Confirm for a confirmation known to answer the key's
// distribution (removal false) or its removal (removal true): an answer to
// the other kind is stale and refused with ErrStaleConfirmation.
func (l *ZoneKeyLifecycle) ConfirmKind(keyid uint16, provider, status, reason string, removal bool) (from, to string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.confirmLocked(keyid, provider, status, reason, &removal)
}

// StaleTolerance is how much earlier than the record's first send a
// confirmation's time may be and still count: the agent stamps the time
// it started tracking, on its own clock, after the signer's push; the
// tolerance covers that latency and a modest skew between the two hosts.
// A confirmation earlier than that answers a distribution that went out
// before this record's (the key's own after its removal, say) and is
// refused; a skew beyond it is logged as such.
const StaleTolerance = 2 * time.Minute

func kindName(removal bool) string {
	if removal {
		return "removal"
	}
	return "distribution"
}

func (d *distribution) lastSent() time.Time {
	if d.LastSent.IsZero() {
		return d.SentAt
	}
	return d.LastSent
}

// ConfirmAllAt is the aggregated confirmation the agent sends today (one
// "propagated" once every remote agent applied a distribution, table §6
// O5): it counts for every signer the record in flight expects, not for
// whoever signs now. at is when the agent started tracking the
// distribution it answers, the zero time when the sender does not say; a
// confirmation older than the record's first send by more than
// StaleTolerance is stale and refused (ErrStaleConfirmation). A resend
// keeps the first send time, so the answer to the first send still counts.
// removal says which kind of distribution the confirmation answers when
// the sender names it (nil when it does not): an answer of the other kind
// than the record's is stale too.
func (l *ZoneKeyLifecycle) ConfirmAllAt(keyid uint16, status, reason string, at time.Time, removal *bool) (from, to string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.dist[keyid]
	if d == nil {
		return "", "", fmt.Errorf("key %d of %s has no distribution in flight", keyid, l.Zone)
	}
	if removal != nil && *removal != d.Removal {
		return "", "", fmt.Errorf("key %d of %s: an answer about the key's %s while its %s is in flight: %w", keyid, l.Zone, kindName(*removal), kindName(d.Removal), ErrStaleConfirmation)
	}
	if !at.IsZero() && at.Before(d.SentAt.Add(-StaleTolerance)) {
		return "", "", fmt.Errorf("key %d of %s: a confirmation from %s of a distribution older than the one in flight (sent %s; or the agent's clock is more than %s behind): %w",
			keyid, l.Zone, at.Format(time.RFC3339), d.SentAt.Format(time.RFC3339), StaleTolerance, ErrStaleConfirmation)
	}
	expected := setList(d.Expected)
	if len(expected) == 0 {
		// nobody to wait for (T3', T13')
		return l.applyLocked(keyid, EvDistributed)
	}
	for _, p := range expected {
		if from, to, err = l.confirmLocked(keyid, p, status, reason, nil); err != nil {
			return from, to, err
		}
		if l.dist[keyid] == nil {
			break // the distribution completed on that confirmation
		}
	}
	return from, to, nil
}

func (l *ZoneKeyLifecycle) confirmLocked(keyid uint16, provider, status, reason string, removal *bool) (from, to string, err error) {
	d := l.dist[keyid]
	if d == nil {
		return "", "", fmt.Errorf("key %d of %s has no distribution in flight", keyid, l.Zone)
	}
	if removal != nil && *removal != d.Removal {
		return "", "", fmt.Errorf("key %d of %s: %w", keyid, l.Zone, ErrStaleConfirmation)
	}
	var ev KeyEvent
	switch status {
	case "applied":
		d.Applied[provider] = true
		delete(d.Pending, provider)
		ev = EvApplied
		if d.Removal {
			ev = EvRemovalApplied
		}
	case "pending":
		if !d.Applied[provider] {
			d.Pending[provider] = true
		}
		ev = EvPending
	case "rejected":
		d.Rejected[provider] = true
		if d.Reason == "" {
			d.Reason = reason
		}
		ev = EvRejected
	default:
		return "", "", fmt.Errorf("confirmation status %q", status)
	}
	l.saveDist(keyid)
	from, to, err = l.applyLocked(keyid, ev)
	if err == nil && status == "rejected" && from != KeyStateMpdist {
		// a signer that joined rejects a key already serving: surfaced, not
		// retreated from (no automatic retreat, design §5.6)
		l.Wire.Report(l.Zone, keyid, "rejected by "+provider+" after the key was accepted: "+reason)
	}
	// a served key's record (a joiner's) is done once everyone expected
	// applied; a rejection stays on it, so a standby key with a rejection is
	// not promoted (T9, P1) until the operator retries or withdraws
	if err == nil && !d.Removal && to != KeyStateMpdist && len(d.Rejected) == 0 && !confirmationsOutstandingFor(d) {
		delete(l.dist, keyid)
		l.saveDist(keyid)
	}
	return from, to, err
}

// SignersChanged tells the driver the zone's signing providers changed:
// every distribution in flight expects the current set (O3).
func (l *ZoneKeyLifecycle) SignersChanged() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := map[string]bool{}
	for _, p := range l.Wire.OtherSigners(l.Zone) {
		now[p] = true
	}
	// a signer that joined gets this provider's served keys again (what a
	// REPLACE of the local DNSKEYs carries on every send), with a record it
	// must confirm before a key of ours may sign (P1)
	joiners := map[string]bool{}
	for p := range now {
		if !l.known[p] {
			joiners[p] = true
		}
	}
	l.known = now
	if len(joiners) > 0 {
		all, err := l.rows()
		if err != nil {
			return err
		}
		for _, keyid := range keytagsOf(all) {
			k := all[keyid]
			if l.dist[keyid] != nil {
				continue
			}
			if k.State == KeyStatePublished || k.State == KeyStateStandby || k.State == KeyStateActive || k.State == KeyStateRetired {
				d := &distribution{SentAt: l.Clock.Now(), LastSent: l.Clock.Now(), Expected: map[string]bool{}, Applied: map[string]bool{}, Pending: map[string]bool{}, Rejected: map[string]bool{}}
				for p := range joiners {
					d.Expected[p] = true
				}
				l.dist[keyid] = d
				l.saveDist(keyid)
				l.logf("key lifecycle: a signer joined; the served key must be applied there", "zone", l.Zone, "keyid", keyid, "joiners", joinSet(joiners), "state", k.State)
				l.Wire.Distribute(l.Zone, keyid)
			}
		}
	}
	distKeys := make([]uint16, 0, len(l.dist))
	for keyid := range l.dist {
		distKeys = append(distKeys, keyid)
	}
	sort.Slice(distKeys, func(i, j int) bool { return distKeys[i] < distKeys[j] })
	for _, keyid := range distKeys {
		d := l.dist[keyid]
		for p := range d.Expected {
			if !now[p] {
				delete(d.Expected, p)
			}
		}
		added := false
		for p := range now {
			if !d.Expected[p] && !d.Applied[p] {
				d.Expected[p] = true
				added = true
			}
		}
		l.saveDist(keyid)
		if added {
			// a signer now expected must have the distribution to confirm
			// it: sent again to everyone (the push carries the whole
			// inventory), the first send time kept
			l.resend(keyid)
		}
		ev := EvSignersChanged
		if _, _, err := l.applyLocked(keyid, ev); err != nil {
			return err
		}
		// re-evaluate the confirmation against the new set
		ev = EvApplied
		if d.Removal {
			ev = EvRemovalApplied
		}
		if _, _, err := l.applyLocked(keyid, ev); err != nil {
			return err
		}
	}
	return nil
}

// Mint generates a key of the role in created, with its columns.
func (l *ZoneKeyLifecycle) Mint(role string) (uint16, error) {
	alg := l.Policy.ZSKAlgorithm
	if role == "KSK" {
		alg = l.Policy.KSKAlgorithm
	}
	// one write: the INSERT carries the state and its columns (design §3.2)
	cols, _ := KeyStateColumns(KeyStateCreated, role == "KSK", false)
	pkc, _, err := l.KDB.GenerateKeypairWithColumns(l.Zone, "mp-key-lifecycle", KeyStateCreated, alg, role, cols, nil)
	if err != nil {
		return 0, fmt.Errorf("mint a %s for %s: %w", role, l.Zone, err)
	}
	l.logf("key lifecycle: minted", "zone", l.Zone, "role", role, "keyid", pkc.KeyId)
	return pkc.KeyId, nil
}

// RequestRollover asks for the next standby key of the role to be promoted
// on the next tick; CancelRollover withdraws the request.
func (l *ZoneKeyLifecycle) RequestRollover(role string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rolls[role] = true
}

func (l *ZoneKeyLifecycle) CancelRollover(role string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.rolls, role)
}

// Tick runs the timers, then the policy: distribute created keys, move
// published keys that have propagated, probe the parent for retired KSKs
// and remove after the margin; then mint what the standby counts want and
// promote for a rollover due or requested, or for a role with no active
// key.
func (l *ZoneKeyLifecycle) Tick() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.initErr != nil {
		return l.initErr
	}
	all, err := l.rows()
	if err != nil {
		return err
	}
	// a key whose step fails (a strip the signer refuses, say) is logged and
	// left for the next tick; the others, and the minting below, go on
	var errs []error
	fail := func(keyid uint16, what string, err error) {
		l.logf("key lifecycle: a tick step failed; the key waits for the next tick", "zone", l.Zone, "keyid", keyid, "step", what, "err", err)
		errs = append(errs, err)
	}
	for _, keyid := range keytagsOf(all) {
		k := all[keyid]
		// E12: a distribution in flight that has waited too long, whatever
		// the key's state (a joiner's record on a served key included)
		if d := l.dist[keyid]; d != nil && l.Policy.ResendAfter > 0 && !l.Clock.Now().Before(d.lastSent().Add(l.Policy.ResendAfter)) {
			if _, _, err := l.applyLocked(keyid, EvResend); err != nil {
				fail(keyid, "resend", err)
				continue
			}
		}
		switch k.State {
		case KeyStateCreated:
			if _, _, err := l.applyLocked(keyid, EvDistributed); err != nil {
				fail(keyid, "distribute", err)
			}
		case KeyStatePublished:
			if _, _, err := l.applyLocked(keyid, EvPropagated); err != nil {
				fail(keyid, "propagated", err)
			}
		case KeyStateRetired:
			if k.Flags&dns.SEP != 0 && !l.dsGone[keyid] {
				if present, known := l.Wire.ParentServesDS(l.Zone, keyid); known && !present {
					if _, _, err := l.applyLocked(keyid, EvDSGone); err != nil {
						fail(keyid, "ds gone", err)
					}
				} else if k.RetiredAt != nil && !l.reported[keyid] && !l.Clock.Now().Before(k.RetiredAt.Add(3*l.Policy.Margin)) {
					// E7 has not come: until S5 withdraws the DS at the parent,
					// nothing in S3 does, so the operator hears it (design §5.7)
					l.reported[keyid] = true
					l.Wire.Report(l.Zone, keyid, "retired KSK waits for the parent to drop its DS; the withdrawal towards the parent is S5's (it stays published meanwhile)")
				}
			}
			if _, _, err := l.applyLocked(keyid, EvMargin); err != nil {
				fail(keyid, "margin", err)
			}
		}
	}
	for _, role := range []string{"KSK", "ZSK"} {
		all, err = l.rows()
		if err != nil {
			return err
		}
		pipeline, active, standbys := 0, 0, []tdns.DnssecKeyWithTimestamps{}
		var oldest *tdns.DnssecKeyWithTimestamps
		for _, keyid := range keytagsOf(all) {
			k := all[keyid]
			if roleOf(k.Flags) != role {
				continue
			}
			switch k.State {
			case KeyStateCreated, KeyStateMpdist, KeyStatePublished, KeyStateStandby:
				pipeline++
				if k.State == KeyStateStandby {
					standbys = append(standbys, k)
				}
			case KeyStateActive:
				active++
				kk := k
				// the oldest by active_at; a key with no stamp counts as the
				// oldest, so a missing stamp never hides a due rollover
				if oldest == nil || oldest.ActiveAt != nil && (k.ActiveAt == nil || k.ActiveAt.Before(*oldest.ActiveAt)) {
					oldest = &kk
				}
			}
		}
		want := l.Policy.StandbyZSK
		lifetime := l.Policy.ZSKLifetime
		if role == "KSK" {
			want, lifetime = l.Policy.StandbyKSK, l.Policy.KSKLifetime
		}
		due := lifetime > 0 && oldest != nil && (oldest.ActiveAt == nil || !l.Clock.Now().Before(oldest.ActiveAt.Add(lifetime)))
		// T9: promote for a rollover requested or due, or a role without an active key
		if len(standbys) > 0 && (active == 0 || l.rolls[role] || due) {
			sort.Slice(standbys, func(i, j int) bool { return standbys[i].KeyTag < standbys[j].KeyTag })
			l.rolling = role
			_, to, err := l.applyLocked(standbys[0].KeyTag, EvPromote)
			l.rolling = ""
			if err != nil {
				return err
			} else if to == KeyStateActive {
				delete(l.rolls, role)
				pipeline--
				active++
				due = false
			}
		}
		// T1: mint what is missing, and send it on its way (T2) at once; a
		// rollover requested with nothing in the pipeline (T16 with a standby
		// count of 0, the default for KSKs) mints the key it will promote
		if pipeline < want || (active == 0 && pipeline == 0) || (due && pipeline == 0) || (l.rolls[role] && pipeline == 0) {
			keyid, err := l.Mint(role)
			if err != nil {
				return err
			}
			if _, _, err := l.applyLocked(keyid, EvDistributed); err != nil {
				return err
			}
		}
	}
	return errors.Join(errs...)
}

// Reload is the restart (T15): distributions for keys in mpdist and
// mpremove are sent again; the timers read the row stamps on the next tick.
func (l *ZoneKeyLifecycle) Reload() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.rows()
	if err != nil {
		return err
	}
	l.known = map[string]bool{}
	for _, p := range l.Wire.OtherSigners(l.Zone) {
		l.known[p] = true
	}
	if err := l.loadDists(); err != nil {
		return err
	}
	for _, keyid := range keytagsOf(all) {
		k := all[keyid]
		d := l.dist[keyid]
		switch k.State {
		case KeyStateMpdist, KeyStateMpremove:
			if d == nil {
				l.startDistribution(keyid, k.State == KeyStateMpremove)
				continue
			}
			if len(d.Rejected) > 0 {
				continue // waits for the operator (P8)
			}
			l.resend(keyid)
		}
	}
	return nil
}

// --- the operator's view -----------------------------------------------------

// DistributionStatus is one distribution in flight, as the operator sees it.
type DistributionStatus struct {
	KeyId    uint16    `json:"keyid"`
	Removal  bool      `json:"removal"`
	SentAt   time.Time `json:"sent_at"`
	Expected []string  `json:"expected"`
	Applied  []string  `json:"applied,omitempty"`
	Pending  []string  `json:"pending,omitempty"`
	Rejected []string  `json:"rejected,omitempty"`
	Reason   string    `json:"reason,omitempty"`
}

func setList(m map[string]bool) []string {
	var out []string
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// InFlight lists the distributions in flight, by keytag.
func (l *ZoneKeyLifecycle) InFlight() []DistributionStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []DistributionStatus
	for keyid, d := range l.dist {
		out = append(out, DistributionStatus{KeyId: keyid, Removal: d.Removal, SentAt: d.SentAt, Expected: setList(d.Expected),
			Applied: setList(d.Applied), Pending: setList(d.Pending), Rejected: setList(d.Rejected), Reason: d.Reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyId < out[j].KeyId })
	return out
}

// HasDistribution reports whether the key has a distribution in flight.
func (l *ZoneKeyLifecycle) HasDistribution(keyid uint16) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dist[keyid] != nil
}

// RolloverRequests lists the roles with a rollover requested and not yet fired.
func (l *ZoneKeyLifecycle) RolloverRequests() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return setList(l.rolls)
}

// SetPolicy replaces the policy the driver applies from the next tick on.
func (l *ZoneKeyLifecycle) SetPolicy(p LifecyclePolicy) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Policy = p
}

// --- the distributions in flight, persisted ----------------------------------

func joinSet(m map[string]bool) string {
	var out []string
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func splitSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p != "" {
			out[p] = true
		}
	}
	return out
}

func (l *ZoneKeyLifecycle) saveDist(keyid uint16) {
	d := l.dist[keyid]
	if d == nil {
		l.KDB.DB.Exec(`DELETE FROM MPKeyDistribution WHERE zonename=? AND keyid=?`, l.Zone, int(keyid))
		return
	}
	removal := 0
	if d.Removal {
		removal = 1
	}
	if _, err := l.KDB.DB.Exec(`INSERT INTO MPKeyDistribution (zonename, keyid, removal, sent_at, last_sent, expected, applied, pending, rejected, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(zonename, keyid) DO UPDATE SET removal=excluded.removal, sent_at=excluded.sent_at, last_sent=excluded.last_sent, expected=excluded.expected,
		applied=excluded.applied, pending=excluded.pending, rejected=excluded.rejected, reason=excluded.reason`,
		l.Zone, int(keyid), removal, d.SentAt.UTC().Format(time.RFC3339), d.lastSent().UTC().Format(time.RFC3339), joinSet(d.Expected), joinSet(d.Applied), joinSet(d.Pending), joinSet(d.Rejected), d.Reason); err != nil {
		l.logf("key lifecycle: saving the distribution failed", "zone", l.Zone, "keyid", keyid, "err", err)
	}
}

func (l *ZoneKeyLifecycle) loadDists() error {
	rows, err := l.KDB.DB.Query(`SELECT keyid, removal, sent_at, last_sent, expected, applied, pending, rejected, reason FROM MPKeyDistribution WHERE zonename=?`, l.Zone)
	if err != nil {
		return fmt.Errorf("read the distributions of %s: %w", l.Zone, err)
	}
	defer rows.Close()
	l.dist = map[uint16]*distribution{}
	for rows.Next() {
		var keyid, removal int
		var sentAt, lastSent, expected, applied, pending, rejected, reason string
		if err := rows.Scan(&keyid, &removal, &sentAt, &lastSent, &expected, &applied, &pending, &rejected, &reason); err != nil {
			return err
		}
		d := &distribution{Removal: removal != 0, Expected: splitSet(expected), Applied: splitSet(applied), Pending: splitSet(pending), Rejected: splitSet(rejected), Reason: reason}
		d.SentAt, _ = time.Parse(time.RFC3339, sentAt)
		d.LastSent, _ = time.Parse(time.RFC3339, lastSent)
		l.dist[uint16(keyid)] = d
	}
	return rows.Err()
}

func confirmationsOutstandingFor(d *distribution) bool {
	if len(d.Rejected) > 0 {
		return false
	}
	for p := range d.Expected {
		if !d.Applied[p] {
			return true
		}
	}
	return false
}
