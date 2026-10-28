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
	// SigLifetime is the signature validity the policy signs with: how long
	// a ZSK-only algorithm rollover keeps the old ZSK signing beside its
	// successor before it retires (T19). 0: the default, two weeks.
	SigLifetime time.Duration
}

// defaultSigLifetime is T19's wait for a ZSK-only algorithm rollover when
// the policy names no signature validity.
const defaultSigLifetime = 14 * 24 * time.Hour

// Wire is what the driver needs from its surroundings.
type Wire interface {
	// OtherSigners are the providers other than this one whose
	// confirmations a key's distribution expects (KeyConfirmers, plan S11).
	OtherSigners(zone string) []string
	// DSSigners are the providers other than this one whose KSKs have a DS
	// (plan S11): another provider's key gets ds only while its provider
	// is among them.
	DSSigners(zone string) []string
	// Distribute sends the key's DNSKEY to the peers (a REPLACE of this
	// provider's DNSKEYs); DistributeRemoval its removal. Confirmations
	// come back through ZoneKeyLifecycle.Confirm.
	Distribute(zone string, keyid uint16)
	DistributeRemoval(zone string, keyid uint16)
	// Resend sends a distribution in flight again (E12, T6', or after a
	// restart): the key, or its removal, must reach the peers again even
	// though the signer's key set has not changed (#256).
	Resend(zone string, keyid uint16, removal bool)
	// ParentDS is the parent's DS RRset for the zone as the signer's own
	// resolver sees it: the key tags served, and the RRset's TTL. Known is
	// false when the parent could not be asked (no resolver, one not ready
	// yet, a lookup that failed), which is not "no DS" (table E7, O7): a
	// key that waits on the parent keeps waiting then.
	ParentDS(zone string) (served map[uint16]bool, ttl time.Duration, known bool)
	// Strip removes every RRSIG by the key from the served zone.
	Strip(zone string, keyid uint16) error
	// Resign asks tdns to re-sign the zone.
	Resign(zone string)
	// ServedDnskeyTTL is the TTL the DNSKEY RRset is served with.
	ServedDnskeyTTL(zone string) time.Duration
	// Report surfaces something an operator must see: a rejected key.
	Report(zone string, keyid uint16, what string)
	// KeysChanged tells the surroundings a key row changed (state or any
	// of pub, sign, ds): the signer pushes a fresh inventory to its
	// agents on every change (design §4.1, arrow 2).
	KeysChanged(zone string)
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
	// Inventory reads the zone's key rows with their columns (ds among
	// them); nil means tdns's keystore. A seam for the tests.
	Inventory func(kdb *tdns.KeyDB, zone string) ([]tdns.KeyInventoryItem, error)

	mu     sync.Mutex
	dist   map[uint16]*distribution
	dsGone map[uint16]bool
	// dsGoneAt: for an active KSK whose DS is withdrawn (T10a), when the
	// parent was first seen without the DS and the TTL caches may hold it
	// for (T11a); T10b waits that TTL out. An answer that serves the DS
	// again drops the note, and the wait starts afresh when it goes again,
	// as T9's wait does (T18). Persisted with lastDSTTL in MPParentDS
	// (saveWithdrawal; read back at T15).
	dsGoneAt map[uint16]dsPresence
	// lastDSTTL: the longest TTL a withdrawn KSK's DS was seen served
	// with: the DS RRset's TTL as T18 noted it for the successor whose
	// promotion withdrew the key (the same RRset), then every poll that
	// still saw the DS, the longest kept. A cache that fetched under a
	// longer TTL may hold the DS that long, whatever the parent served
	// last. What T11a's note is made of; an answer without the DS says
	// nothing about the TTL caches hold (an empty answer has none).
	lastDSTTL map[uint16]time.Duration
	// successorDSTTL: while a promotion applies E6 to the keys it replaces,
	// the DS RRset TTL the promoted key's DS was observed with (its T18
	// note), for T10a's note on the key it withdraws.
	successorDSTTL time.Duration
	// kskLeft, by algorithm: a KSK of that algorithm retired on T10b while a
	// ZSK of the same algorithm was still signing with the policy naming
	// another ZSK algorithm: the KSK this combined roll withdrew, which
	// ends the old ZSK's wait (T19's OldAlgKSKLeaving). Cleared when that
	// ZSK retires. In memory: after a restart the old ZSK waits the
	// signature lifetime instead, the safe side (T15).
	kskLeft map[uint8]bool
	// dsPresent: standby SEP keys the parent has been seen serving the DS
	// of, since when and with what TTL (E13, T18; persisted, T15). T9 waits
	// for the TTL to pass (O7). parentEmpty and parentTTL are the parent's
	// last known answer on this tick: no DS for the zone at all (O2), and
	// the DS RRset's TTL for a stamp. promoteWait and promoteTold: a
	// standby SEP key the parent wait refused, since when, and whether the
	// operator has heard (after three margins).
	dsPresent   map[uint16]dsPresence
	parentKnown bool
	parentEmpty bool
	parentTTL   time.Duration
	promoteWait map[uint16]time.Time
	promoteTold map[uint16]bool
	rolls       map[string]bool        // a rollover requested, by role
	reported    map[uint16]bool        // retired KSKs reported as waiting on the parent
	initErr     error                  // why the driver cannot run (its persistence missing)
	rolling     string                 // the role whose promotion is a rollover, while it is applied
	known       map[string]bool        // the other signers last seen, for the joiners
	foreign     map[uint16]foreignSaid // what the other providers said about their keys (#58)
	// another provider's KSK with no ds decided: since when, and whether
	// the operator has been told (R9)
	undecidedSince map[uint16]time.Time
	undecidedTold  map[uint16]bool
	// An algorithm rollover (table §6 O4). algorithms are the owner's
	// algorithms by role, set through the command (design Q1: the
	// algorithm is the owner's field; tdns's policy binding refuses a
	// change of it) and persisted (MPOwnerAlgorithm), so a restart keeps a
	// roll under way; they override the bound policy's in Policy.
	// successor is the algorithm of the key being promoted while the key
	// it replaces is retired (T10's guard).
	algorithms map[string]uint8
	successor  uint8
	// hold: the signer's agent holds the zone (the hand-over's hold, plan S6):
	// the tick starts nothing new (Tick)
	hold bool
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
		dist: map[uint16]*distribution{}, dsGone: map[uint16]bool{}, rolls: map[string]bool{}, reported: map[uint16]bool{}, known: known,
		dsPresent: map[uint16]dsPresence{}, promoteWait: map[uint16]time.Time{}, promoteTold: map[uint16]bool{}, algorithms: map[string]uint8{},
		dsGoneAt: map[uint16]dsPresence{}, lastDSTTL: map[uint16]time.Duration{}, kskLeft: map[uint8]bool{}}
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
		if _, err := kdb.DB.Exec(HsyncTables["MPForeignKeyState"]); err != nil && l.initErr == nil {
			l.initErr = fmt.Errorf("the MPForeignKeyState table of %s: %w", l.Zone, err)
		}
		if _, err := kdb.DB.Exec(HsyncTables["MPParentDS"]); err != nil && l.initErr == nil {
			l.initErr = fmt.Errorf("the MPParentDS table of %s: %w", l.Zone, err)
		}
		if _, err := kdb.DB.Exec(HsyncTables["MPOwnerAlgorithm"]); err != nil && l.initErr == nil {
			l.initErr = fmt.Errorf("the MPOwnerAlgorithm table of %s: %w", l.Zone, err)
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
	if p, ok := l.dsPresent[k.KeyTag]; ok {
		v.DSPresentSince, v.ParentDSTTL = p.Since, p.TTL
	}
	if k.PublishedAt != nil {
		v.PublishedAt = *k.PublishedAt
	}
	if k.RetiredAt != nil {
		v.RetiredAt = *k.RetiredAt
	}
	v.Withdrawn = v.SEP && cols.DS.Valid && !cols.DS.Bool
	if g, ok := l.dsGoneAt[k.KeyTag]; ok && k.State == KeyStateActive && v.Withdrawn {
		v.DSGoneAt, v.ParentDSTTL = g.Since, g.TTL
	}
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
		ParentKnown:      l.parentKnown,
		ParentServesNoDS: l.parentEmpty,
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
	z.SuccessorAlgorithm = l.successor
	z.OldAlgKSKLeaving = l.oldAlgKSKLeaving(k, all)
	// the algorithm rollover's view (O4): the policy's algorithm for the
	// role, whether a key of the role signs with another, the policy's
	// keys on their way or signing, and whether the KSK side is done
	z.PolicyAlgorithm = l.policyAlgorithm(role)
	z.KSKSideDone = true
	z.SigLifetime = l.Policy.SigLifetime
	if z.SigLifetime == 0 {
		z.SigLifetime = defaultSigLifetime
	}
	for _, o := range all {
		if o.State == KeyStateActive && o.Flags&dns.SEP != 0 && o.Algorithm != l.policyAlgorithm("KSK") {
			z.KSKSideDone = false
		}
		if roleOf(o.Flags) != role {
			continue
		}
		if l.signsInThisRoll(k, o, z.PolicyAlgorithm) && (z.PolicyAlgActiveSince.IsZero() || o.ActiveAt.Before(z.PolicyAlgActiveSince)) {
			z.PolicyAlgActiveSince = *o.ActiveAt
		}
		if o.State == KeyStateActive && o.Algorithm != z.PolicyAlgorithm {
			z.AlgRollPending = true
		}
		if o.Algorithm == z.PolicyAlgorithm {
			switch o.State {
			case KeyStateCreated, KeyStateMpdist, KeyStatePublished, KeyStateStandby, KeyStateActive:
				z.PolicyAlgKeys++
				if o.State == KeyStateActive && o.KeyTag != k.KeyTag {
					z.PolicyAlgActive = true
				}
			}
		}
	}
	return z
}

// policyAlgorithm is the policy's algorithm for the role, the owner's
// override included (it is in Policy already).
func (l *ZoneKeyLifecycle) policyAlgorithm(role string) uint8 {
	if role == "KSK" {
		return l.Policy.KSKAlgorithm
	}
	return l.Policy.ZSKAlgorithm
}

// signsInThisRoll: o is a key of the policy's algorithm that began
// signing in the roll that k, a key of another algorithm, is leaving in.
// T19's signature lifetime counts from the first such key, and a later
// rollover of it (requested, or its own lifetime) does not start the wait
// over: the policy's algorithm has signed since the first one. So a key
// that has since retired or left counts too, as long as it began signing
// after k did: a key of the policy's algorithm from before k (the roll
// before this one, back the other way) is not this roll's. Stamps that
// are equal, or no stamp on k, tell the two apart no better, and then
// only a key that still signs counts: the wait is longer, never shorter.
func (l *ZoneKeyLifecycle) signsInThisRoll(k, o tdns.DnssecKeyWithTimestamps, policyAlg uint8) bool {
	if o.Algorithm != policyAlg || o.ActiveAt == nil {
		return false
	}
	if o.State == KeyStateActive {
		return true
	}
	if k.Algorithm == policyAlg || k.ActiveAt == nil {
		return false
	}
	switch o.State {
	case KeyStateRetired, KeyStateMpremove, KeyStateRemoved:
		return o.ActiveAt.After(*k.ActiveAt)
	}
	return false
}

// algRollInFlight: an active key of the role whose algorithm is not the
// policy's, beside a key of the policy's algorithm in the pipeline, and
// none of the policy's algorithm signing yet: the roll's one promotion.
// Once a key of the new algorithm signs, the next standby of it waits as
// any standby does while the old algorithm's key signs on.
func (l *ZoneKeyLifecycle) algRollInFlight(role string, all map[uint16]tdns.DnssecKeyWithTimestamps) bool {
	want := l.Policy.ZSKAlgorithm
	if role == "KSK" {
		want = l.Policy.KSKAlgorithm
	}
	oldActive, newComing, newActive := false, false, false
	for _, o := range all {
		if roleOf(o.Flags) != role {
			continue
		}
		switch {
		case o.State == KeyStateActive && o.Algorithm != want:
			oldActive = true
		case o.State == KeyStateActive && o.Algorithm == want:
			newActive = true
		case o.Algorithm == want && o.State != KeyStateRetired && o.State != KeyStateMpremove && o.State != KeyStateRemoved:
			newComing = true
		}
	}
	return oldActive && newComing && !newActive
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
		// on a key being removed it is the removal sent again. The agent's
		// key set has not changed, so it goes as a resend (#256).
		l.startDistribution(keyid, k.State == KeyStateMpremove, true)
		return k.State, next, nil
	case "T6'":
		l.resend(keyid)
		return k.State, next, nil
	case "T10a":
		// the DS withdrawal written on the active row: ds=0, the DS set
		// shrinks and the parent follows (S5d), the key goes on signing
		cols, _ := KeyStateColumns(KeyStateActive, true, true)
		if err := tdns.UpdateKeyRowFrom(l.KDB, l.Zone, keyid, k.State, k.State, cols); err != nil {
			return k.State, k.State, fmt.Errorf("withdraw the DS of key %d of %s: %w", keyid, l.Zone, err)
		}
		l.Wire.KeysChanged(l.Zone)
		// the DS RRset TTL caches may hold the key's DS for: the TTL the
		// parent served the successor's DS with (its T18 note), the same
		// RRset; noted now, while the parent still serves this DS
		if l.successorDSTTL > l.lastDSTTL[keyid] {
			l.lastDSTTL[keyid] = l.successorDSTTL
		}
		l.saveWithdrawal(keyid)
		l.logf("key lifecycle: the old algorithm's KSK goes on signing with its DS withdrawn; it retires once the parent has not served the DS for the DS TTL", "zone", l.Zone, "keyid", keyid, "algorithm", dns.AlgorithmToString[k.Algorithm], "ds_ttl", l.lastDSTTL[keyid])
		return k.State, next, nil
	case "T11":
		l.dsGone[keyid] = true
		return k.State, next, nil
	case "T11a":
		// the TTL caches may hold the DS for: what the parent was seen
		// serving it with (lastDSTTL); failing that, the TTL of the DS
		// RRset this answer still carries (the other DS); failing that
		// (an empty answer says nothing about it) the withdrawal margin,
		// never zero
		l.dsGone[keyid] = true
		ttl := l.lastDSTTL[keyid]
		if ttl == 0 {
			ttl = l.parentTTL
		}
		if ttl == 0 {
			ttl = l.Policy.Margin
		}
		l.dsGoneAt[keyid] = dsPresence{Since: l.Clock.Now(), TTL: ttl}
		l.saveWithdrawal(keyid)
		l.logf("key lifecycle: the parent no longer serves the old algorithm's DS; the old KSK retires after the DS TTL", "zone", l.Zone, "keyid", keyid, "ds_ttl", ttl)
		return k.State, next, nil
	case "T18":
		l.dsPresent[keyid] = dsPresence{Since: l.Clock.Now(), TTL: l.parentTTL}
		l.savePresence(keyid)
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
	if k.State == KeyStateStandby {
		// the parent wait is standby's: promoted, or withdrawn, it is over;
		// the DS RRset TTL its note carries serves T10a on the key a
		// promotion withdraws (the same RRset at the parent)
		l.successorDSTTL = l.dsPresent[keyid].TTL
		delete(l.dsPresent, keyid)
		delete(l.promoteWait, keyid)
		delete(l.promoteTold, keyid)
		l.savePresence(keyid)
	}
	switch next {
	case KeyStateMpdist:
		l.startDistribution(keyid, false, false)
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
		// the previous active key of the role retires (T10); during an
		// algorithm rollover the old KSK goes on signing with its DS
		// withdrawn (T10a) until the parent has not served the DS for the
		// DS TTL (T10b), and the old ZSK waits for T19
		l.successor = k.Algorithm
		for _, tag := range keytagsOf(all) {
			o := all[tag]
			if o.State == KeyStateActive && o.KeyTag != keyid && roleOf(o.Flags) == roleOf(k.Flags) {
				if _, _, err := l.applyLocked(o.KeyTag, EvSuccessorActive); err != nil {
					l.successor, l.successorDSTTL = 0, 0
					return k.State, next, err
				}
			}
		}
		l.successor, l.successorDSTTL = 0, 0
	case KeyStateRetired:
		switch row.ID {
		case "T10b":
			// the KSK's DS is gone already (noted on T11a): T12's margin runs
			// from here, and the wait's notes are done with. A ZSK of its
			// algorithm still signing with the policy naming another ZSK
			// algorithm is this roll's old ZSK: the mark that lets T19
			// retire it now that the KSK side is over
			delete(l.dsGoneAt, keyid)
			delete(l.lastDSTTL, keyid)
			l.saveWithdrawal(keyid)
			for _, o := range all {
				if o.Flags&dns.SEP == 0 && o.State == KeyStateActive && o.Algorithm == k.Algorithm && o.Algorithm != l.policyAlgorithm("ZSK") {
					l.kskLeft[k.Algorithm] = true
				}
			}
		case "T19":
			delete(l.kskLeft, k.Algorithm)
		}
		l.Wire.Resign(l.Zone)
	case KeyStateMpremove:
		delete(l.dsGone, keyid)
		l.startDistribution(keyid, true, false)
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
	l.Wire.KeysChanged(l.Zone)
	return nil
}

// SetForeignDS writes another provider's key's ds column (design §1 P3:
// its DS belongs at the parent while its provider signs the zone and holds
// it standby, active or retired-not-withdrawn), the row's state and other
// columns untouched, and tells the surroundings like every other write:
// the inventory goes out and the DS engine wakes, with no state change
// (T5.4). The write of one row by hand; what #58 learns from the wire
// goes through SetForeignStates and applyForeignLocked, which write the
// same way.
func (l *ZoneKeyLifecycle) SetForeignDS(keyid uint16, ds bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var state string
	if err := l.KDB.DB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, l.Zone, int(keyid)).Scan(&state); err != nil {
		return fmt.Errorf("foreign key %d of %s: %w", keyid, l.Zone, err)
	}
	if state != DnskeyStateForeign {
		return fmt.Errorf("key %d of %s is %s, not a foreign row", keyid, l.Zone, state)
	}
	cols := tdns.KeyRowFlags{Pub: true, DS: sql.NullBool{Bool: ds, Valid: true}}
	if err := tdns.UpdateKeyRowFrom(l.KDB, l.Zone, keyid, DnskeyStateForeign, DnskeyStateForeign, cols); err != nil {
		return fmt.Errorf("ds of foreign key %d of %s: %w", keyid, l.Zone, err)
	}
	l.Wire.KeysChanged(l.Zone)
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
	l.Wire.Resend(l.Zone, keyid, d.Removal)
}

// startDistribution starts the key's distribution, or its removal's. resend:
// the agent's key set has not changed with it (an operator's retry, a
// restart with no record of the distribution), so it is sent as a resend,
// which the agent distributes anyway (#256). A first distribution goes with
// the key's row change, which changes the agent's set.
func (l *ZoneKeyLifecycle) startDistribution(keyid uint16, removal, resend bool) {
	now := l.Clock.Now()
	d := &distribution{Removal: removal, SentAt: now, LastSent: now, Expected: map[string]bool{}, Applied: map[string]bool{}, Pending: map[string]bool{}, Rejected: map[string]bool{}}
	for _, p := range l.Wire.OtherSigners(l.Zone) {
		d.Expected[p] = true
	}
	l.dist[keyid] = d
	l.saveDist(keyid)
	switch {
	case resend:
		l.Wire.Resend(l.Zone, keyid, removal)
	case removal:
		l.Wire.DistributeRemoval(l.Zone, keyid)
	default:
		l.Wire.Distribute(l.Zone, keyid)
	}
}

// ErrStaleConfirmation: a confirmation of a distribution that is no longer
// the one in flight (an answer to the key's distribution after its removal
// went out, or the other way round).
var ErrStaleConfirmation = errors.New("the confirmation is for a distribution no longer in flight")

// ErrNoDistribution: a confirmation of a key that has no distribution in
// flight here (the key was distributed by someone else, tdns's own key
// state worker before the zone was taken for one, or the answer is a
// late duplicate); nothing to apply it to.
var ErrNoDistribution = errors.New("no distribution in flight")

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
		return "", "", fmt.Errorf("key %d of %s: %w", keyid, l.Zone, ErrNoDistribution)
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
		return "", "", fmt.Errorf("key %d of %s: %w", keyid, l.Zone, ErrNoDistribution)
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

// Expects: the driver's distributions expect these providers' confirmations,
// as SignersChanged, NewZoneKeyLifecycle or Reload last set them.
func (l *ZoneKeyLifecycle) Expects(signers []string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(signers) != len(l.known) {
		return false
	}
	for _, p := range signers {
		if !l.known[p] {
			return false
		}
	}
	return true
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
				// every signer now: the pass below would add the others and
				// send it a second time
				for p := range now {
					d.Expected[p] = true
				}
				l.dist[keyid] = d
				l.saveDist(keyid)
				l.logf("key lifecycle: a signer joined; the served key must be applied there", "zone", l.Zone, "keyid", keyid, "joiners", joinSet(joiners), "state", k.State)
				// the agent serves the key already: only a resend makes it
				// distribute the set again (#256)
				l.Wire.Resend(l.Zone, keyid, false)
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
	// a provider that stopped signing: its keys' DS no longer belongs at
	// the parent (E10); one that started: what it said counts now
	return l.applyForeignLocked()
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

// SetHold holds the machine, or lets it go: under a hold a tick starts no
// new rollover (plan S6).
func (l *ZoneKeyLifecycle) SetHold(on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hold = on
}

// RequestRollover asks for the next standby key of the role to be promoted
// on the next tick; CancelRollover withdraws the request.
func (l *ZoneKeyLifecycle) RequestRollover(role string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rolls[role] = true
}

// CancelRollover withdraws the role's rollover request, and says whether
// there was one.
func (l *ZoneKeyLifecycle) CancelRollover(role string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	had := l.rolls[role]
	delete(l.rolls, role)
	return had
}

// oldAlgKSKLeaving is T19's OldAlgKSKLeaving for k, an old-algorithm ZSK:
// a KSK of k's own algorithm retired on T10b while k's change was pending
// (kskLeft: the KSK this combined roll withdrew), and it is still retired
// or being removed. A KSK of the old algorithm left over from an earlier
// roll carries no mark: the change is then ZSK-only and T19 waits the
// signature lifetime.
func (l *ZoneKeyLifecycle) oldAlgKSKLeaving(k tdns.DnssecKeyWithTimestamps, all map[uint16]tdns.DnssecKeyWithTimestamps) bool {
	if k.Flags&dns.SEP != 0 || !l.kskLeft[k.Algorithm] {
		return false
	}
	for _, o := range all {
		if o.Flags&dns.SEP != 0 && o.Algorithm == k.Algorithm && (o.State == KeyStateRetired || o.State == KeyStateMpremove) {
			return true
		}
	}
	return false
}

// withdrawnActive: the active KSKs whose DS withdrawal has been written
// (ds=0; T10a), from the inventory's columns: the old algorithm's KSK in the
// withdrawal wait of an algorithm rollover.
// An inventory that cannot be read is an error, not an empty set: a
// restart that read it as empty would take every withdrawal-wait note for
// a stale one and delete it.
func (l *ZoneKeyLifecycle) withdrawnActive(all map[uint16]tdns.DnssecKeyWithTimestamps) (map[uint16]bool, error) {
	read := l.Inventory
	if read == nil {
		read = tdns.GetKeyInventory
	}
	inv, err := read(l.KDB, l.Zone)
	if err != nil {
		return nil, fmt.Errorf("the key inventory of %s: %w", l.Zone, err)
	}
	out := map[uint16]bool{}
	for _, it := range inv {
		k, ok := all[it.KeyTag]
		if ok && k.State == KeyStateActive && k.Flags&dns.SEP != 0 && it.DS != nil && !*it.DS {
			out[it.KeyTag] = true
		}
	}
	return out, nil
}

// Tick runs the timers, then the policy: distribute created keys, move
// published keys that have propagated, probe the parent for retired KSKs
// and remove after the margin; then mint what the standby counts want and
// promote for a rollover due or requested, or for a role with no active
// key. Under a hold (plan S6) it starts nothing new: no rollover for a
// key's lifetime, no standby key, no algorithm rollover that has no key of
// its algorithm yet. Every phase of a rollover under way runs, an
// algorithm rollover's included, and so does a rollover the operator asks
// for (the emergency rollover, RequestRollover), and a role with no active
// key gets one.
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
	// another provider's key whose row appeared since its provider's word
	// came gets its ds now (#58)
	if err := l.applyForeignLocked(); err != nil {
		l.logf("key lifecycle: writing ds on the foreign rows failed; next tick", "zone", l.Zone, "err", err)
		errs = append(errs, err)
	}
	// the parent's DS RRset, asked once per tick while a SEP key waits on it:
	// a standby one for its own DS to be there (E13, then T9's wait, O7), a
	// published one about to be standby, a retired one for its DS to go (E7).
	// Not asked: nothing is known of the parent this tick, and a key waits.
	var served map[uint16]bool
	l.parentKnown, l.parentEmpty = false, false
	withdrawn, werr := l.withdrawnActive(all)
	if werr != nil {
		// the withdrawal wait is left where it is this tick: no note
		// taken, none expired
		l.logf("key lifecycle: the key inventory is unreadable; the withdrawal wait is left alone this tick", "zone", l.Zone, "err", werr)
		withdrawn = map[uint16]bool{}
	}
	for _, k := range all {
		if k.Flags&dns.SEP != 0 && (k.State == KeyStatePublished || k.State == KeyStateStandby || k.State == KeyStateRetired && !l.dsGone[k.KeyTag] || withdrawn[k.KeyTag]) {
			served, l.parentTTL, l.parentKnown = l.Wire.ParentDS(l.Zone)
			l.parentEmpty = l.parentKnown && len(served) == 0
			break
		}
	}
	parentKnown := l.parentKnown
	// a withdrawn KSK whose DS the parent serves: the TTL it is served
	// with, noted for T11a; and a DS that is served again after it was
	// seen gone drops the note, the wait starts afresh when it goes again
	// (as T18 does for a standby key's wait)
	if parentKnown {
		for keyid := range withdrawn {
			if !served[keyid] {
				continue
			}
			if l.parentTTL > l.lastDSTTL[keyid] {
				l.lastDSTTL[keyid] = l.parentTTL
			}
			if l.dsGone[keyid] {
				delete(l.dsGone, keyid)
				delete(l.dsGoneAt, keyid)
				l.logf("key lifecycle: the parent serves the old algorithm's DS again; the old KSK's wait starts afresh when it goes", "zone", l.Zone, "keyid", keyid)
			}
			l.saveWithdrawal(keyid)
		}
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
		case KeyStateStandby:
			// E13: the parent serves the key's DS, noted with the TTL for
			// T9; a DS that went away again starts the wait afresh
			if k.Flags&dns.SEP != 0 && parentKnown {
				if _, seen := l.dsPresent[keyid]; served[keyid] && !seen {
					if _, _, err := l.applyLocked(keyid, EvDSPresent); err != nil {
						fail(keyid, "ds present", err)
					}
				} else if !served[keyid] && seen {
					delete(l.dsPresent, keyid)
					l.savePresence(keyid)
				}
			}
		case KeyStateActive:
			// the withdrawal wait of an algorithm rollover (T10a): the old
			// KSK signs on until the parent has dropped its DS (T11a) and
			// the DS TTL has passed (T10b, E15)
			// Both on a tick the parent answered, and answered without
			// the DS: the parent unknown counts as neither (O7), and a DS
			// served again dropped the note above.
			if withdrawn[keyid] && parentKnown && !served[keyid] {
				if !l.dsGone[keyid] {
					if _, _, err := l.applyLocked(keyid, EvDSGone); err != nil {
						fail(keyid, "ds gone", err)
					}
				} else if _, _, err := l.applyLocked(keyid, EvDSExpired); err != nil {
					fail(keyid, "ds expired", err)
				}
			}
		case KeyStateRetired:
			if k.Flags&dns.SEP != 0 && !l.dsGone[keyid] {
				if parentKnown && !served[keyid] {
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
		// a key on its way that signs with an algorithm the policy no
		// longer names is given up on (C2 by the machine, T7 to T7''): it
		// never signed, so nothing depends on it, and the policy's
		// algorithm takes its place in the pipeline (O4). A rejected one
		// goes the same way: its rejection is moot.
		switch k.State {
		case KeyStateMpdist, KeyStatePublished, KeyStateStandby:
			if k.Algorithm != l.policyAlgorithm(roleOf(k.Flags)) {
				l.logf("key lifecycle: a key of an algorithm the policy no longer names is withdrawn", "zone", l.Zone, "keyid", keyid, "role", roleOf(k.Flags), "state", k.State, "algorithm", dns.AlgorithmToString[k.Algorithm], "policy", dns.AlgorithmToString[l.policyAlgorithm(roleOf(k.Flags))])
				if _, _, err := l.applyLocked(keyid, CmdWithdraw); err != nil {
					fail(keyid, "withdraw (algorithm)", err)
				}
			}
		}
	}
	for _, role := range []string{"KSK", "ZSK"} {
		all, err = l.rows()
		if err != nil {
			return err
		}
		// the pipeline and the standbys are the policy's algorithm's: a key
		// of another algorithm on its way is being withdrawn (above) and is
		// never promoted. policyKeys counts the policy's algorithm in
		// created..active, and algPending says the active key signs with
		// another: an algorithm rollover (O4) mints the policy's algorithm
		// when nothing of it is on its way or signing, and promotes it once
		// standby (a KSK once the parent has served its DS for the DS TTL,
		// T9's wait, O7)
		alg := l.policyAlgorithm(role)
		pipeline, policyKeys, active, activeOfAlg, algPending, standbys := 0, 0, 0, 0, false, []tdns.DnssecKeyWithTimestamps{}
		var oldest *tdns.DnssecKeyWithTimestamps
		for _, keyid := range keytagsOf(all) {
			k := all[keyid]
			if roleOf(k.Flags) != role {
				continue
			}
			switch k.State {
			case KeyStateCreated, KeyStateMpdist, KeyStatePublished, KeyStateStandby:
				if k.Algorithm != alg {
					continue
				}
				pipeline++
				policyKeys++
				if k.State == KeyStateStandby {
					standbys = append(standbys, k)
				}
			case KeyStateActive:
				active++
				if k.Algorithm != alg {
					// a key of another algorithm that still signs is waiting
					// out T10b or T19. Its age is not the lifetime's
					// business: promoting on its account rolls the new
					// algorithm's key (T10) and leaves this one signing.
					algPending = true
					continue
				}
				policyKeys++
				activeOfAlg++
				kk := k
				// the oldest of the policy's algorithm by active_at; a key
				// with no stamp counts as the oldest, so a missing stamp
				// never hides a due rollover
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
		// under a hold nothing new starts (plan S6): no lifetime rollover,
		// no standby key, no algorithm rollover not yet begun. A standby of
		// a role the policy keeps none of was minted for a rollover that
		// began before the hold: its promotion is that rollover's next phase.
		algStart := algPending && policyKeys == 0
		promoteDue := due
		if l.hold {
			promoteDue = due && want == 0
			due, algStart = false, false
			want = 0
		}
		// T9: promote for a rollover requested or due, a role without an
		// active key, or an algorithm rollover whose algorithm does not sign
		// yet: the roll promotes once. The standby the count mints after
		// that promotion waits as any standby does while the old
		// algorithm's key signs on (T10a's wait, T19's); promoting it on the
		// old key's account rolled the new algorithm's key once per standby
		// (seen on the testbed). Due is the policy algorithm's own key past
		// its lifetime, for the same reason.
		if len(standbys) > 0 && (active == 0 || l.rolls[role] || promoteDue || (algPending && activeOfAlg == 0)) {
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
			} else if k := standbys[0]; k.Flags&dns.SEP != 0 {
				l.noteParentWait(k, all)
			}
		}
		// T1: mint what is missing, and send it on its way (T2) at once; a
		// rollover requested with nothing in the pipeline (T16 with a standby
		// count of 0, the default for KSKs) mints the key it will promote; an
		// algorithm rollover mints the policy's algorithm when no key of it
		// is on its way or signing (O4)
		if pipeline < want || (active == 0 && pipeline == 0) || (due && pipeline == 0) || (l.rolls[role] && pipeline == 0) || algStart {
			keyid, err := l.Mint(role)
			if err != nil {
				return err
			}
			if _, _, err := l.applyLocked(keyid, EvDistributed); err != nil {
				return err
			}
		}
	}
	// E14, T19: the old algorithm's ZSK leaves last. Once a ZSK of the
	// policy's algorithm signs and no KSK of another algorithm than the
	// policy's does (the old KSK retired on T10b, its DS gone from the
	// parent for the DS TTL), or, in a ZSK-only roll, a signature lifetime
	// after the new ZSK began signing, a ZSK that still signs with another
	// algorithm retires; the guard decides, the event is offered to every
	// active ZSK of another algorithm than the policy's
	all, err = l.rows()
	if err != nil {
		return err
	}
	for _, keyid := range keytagsOf(all) {
		k := all[keyid]
		if k.State == KeyStateActive && k.Flags&dns.SEP == 0 && k.Algorithm != l.policyAlgorithm("ZSK") {
			if _, _, err := l.applyLocked(keyid, EvAlgSuperseded); err != nil {
				fail(keyid, "algorithm superseded", err)
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
	if err := l.loadAlgorithms(); err != nil {
		return err
	}
	if err := l.adopt(all); err != nil {
		return err
	}
	if err := l.loadForeign(); err != nil {
		return err
	}
	if err := l.applyForeignLocked(); err != nil {
		return err
	}
	if err := l.loadDists(); err != nil {
		return err
	}
	if err := l.loadPresences(all); err != nil {
		return err
	}
	for _, keyid := range keytagsOf(all) {
		k := all[keyid]
		d := l.dist[keyid]
		switch k.State {
		case KeyStateMpdist, KeyStateMpremove:
			if d == nil {
				// a key in flight with no record of its distribution: the
				// agent's set has it as it was, so it goes as a resend
				l.startDistribution(keyid, k.State == KeyStateMpremove, true)
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

// adopt gives an own row the store shaped without the design's columns
// (a key tdns minted before the zone was taken: its ds is NULL, so the
// zone's DS intent is unknown and no CDS is served; lab run 2026-09-16,
// finding 3) the columns its state prescribes. A retired KSK is adopted
// as not withdrawn: its DS stays at the parent until the machine
// withdraws it, which is the harmless reading of a DS status nobody
// recorded.
func (l *ZoneKeyLifecycle) adopt(all map[uint16]tdns.DnssecKeyWithTimestamps) error {
	inv, err := tdns.GetKeyInventory(l.KDB, l.Zone)
	if err != nil {
		return fmt.Errorf("inventory of %s: %w", l.Zone, err)
	}
	changed := false
	for _, it := range inv {
		k, own := all[it.KeyTag]
		if !own || it.DS != nil {
			continue
		}
		cols, ok := KeyStateColumns(k.State, k.Flags&dns.SEP != 0, false)
		if !ok {
			continue
		}
		if err := tdns.UpdateKeyRowFrom(l.KDB, l.Zone, k.KeyTag, k.State, k.State, cols); err != nil {
			return fmt.Errorf("adopt key %d of %s (%s): %w", k.KeyTag, l.Zone, k.State, err)
		}
		l.logf("key lifecycle: adopted a key row with no ds column", "keytag", k.KeyTag, "role", roleOf(k.Flags), "state", k.State, "ds", cols.DS.Bool)
		changed = true
	}
	if changed {
		l.Wire.KeysChanged(l.Zone)
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

// RolloverFlags are what the driver knows of the zone beside its key rows,
// for rolloverUnderWay (plan S11): a rollover asked for, an algorithm
// rollover under way, and a distribution that waits for confirmations.
func (l *ZoneKeyLifecycle) RolloverFlags() (rolloverFlags, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.rows()
	if err != nil {
		return rolloverFlags{}, err
	}
	f := rolloverFlags{Requested: len(l.rolls) > 0, AlgRoll: len(l.algRolloversOf(all)) > 0}
	for _, d := range l.dist {
		if confirmationsOutstandingFor(d) {
			f.PropagationPending = true
		}
	}
	return f, nil
}

// WaitsOn is, for each key in mpdist or mpremove, the other signers whose
// "applied" its distribution still misses, sorted (plan S11); a key whose
// distribution misses nobody is not named.
func (l *ZoneKeyLifecycle) WaitsOn() (map[uint16][]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.rows()
	if err != nil {
		return nil, err
	}
	out := map[uint16][]string{}
	for keyid, d := range l.dist {
		if st := all[keyid].State; st != KeyStateMpdist && st != KeyStateMpremove {
			continue
		}
		var missing []string
		for p := range d.Expected {
			if !d.Applied[p] {
				missing = append(missing, p)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			out[keyid] = missing
		}
	}
	return out, nil
}

// ApplyForeign writes ds on the foreign rows again (applyForeignLocked):
// a hand-over that changes DSSigners does it at once (plan S11).
func (l *ZoneKeyLifecycle) ApplyForeign() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.initErr != nil {
		return l.initErr
	}
	return l.applyForeignLocked()
}

// SetPolicy replaces the policy the driver applies from the next tick on.
// The owner's algorithms (SetAlgorithm) stay: they are the owner's field,
// not the bound policy's (design Q1).
func (l *ZoneKeyLifecycle) SetPolicy(p LifecyclePolicy) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Policy = p
	l.applyAlgorithms()
}

// --- the algorithm rollover (transition table §6 O4) ----------------------------

// SetAlgorithm sets the owner's algorithm for the role, persisted, and
// returns the one it replaces. A change starts an algorithm rollover from
// the next tick: a key of the new algorithm is minted, distributed,
// published and standby as any key; a new KSK is promoted once the parent
// has served its DS for the DS TTL (T9's wait, O7) and the old KSK retires
// in that step; the old ZSK keeps signing beside the new one until the KSK
// side is done (T10's guard, T19); the old keys then leave as any retired
// key (ds=0, the parent, the margin, the strip). A key of the old
// algorithm not yet signing is withdrawn. Setting the algorithm back
// before anything of the new one signs cancels the roll (the new keys are
// withdrawn); after that it is a rollover back, through the same steps.
func (l *ZoneKeyLifecycle) SetAlgorithm(role string, alg uint8) (uint8, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if role != "KSK" && role != "ZSK" {
		return 0, fmt.Errorf("role %q: KSK or ZSK", role)
	}
	if alg == 0 {
		return 0, fmt.Errorf("no algorithm")
	}
	old := l.policyAlgorithm(role)
	prev, hadPrev := l.algorithms[role]
	l.algorithms[role] = alg
	l.applyAlgorithms()
	if err := l.saveAlgorithm(role); err != nil {
		l.restoreAlgorithm(role, prev, hadPrev, old)
		return old, err
	}
	l.logf("key lifecycle: the owner's algorithm set", "zone", l.Zone, "role", role, "from", dns.AlgorithmToString[old], "to", dns.AlgorithmToString[alg])
	return old, nil
}

// applyAlgorithms puts the owner's algorithms over the bound policy's.
// restoreAlgorithm puts the role's override and the policy's algorithm
// back as they were before a change whose save failed: what the next tick
// runs is what the database holds. applyAlgorithms writes only non-zero
// overrides, so the policy's value is put back by hand.
func (l *ZoneKeyLifecycle) restoreAlgorithm(role string, prev uint8, hadPrev bool, policyAlg uint8) {
	if hadPrev {
		l.algorithms[role] = prev
	} else {
		delete(l.algorithms, role)
	}
	if role == "KSK" {
		l.Policy.KSKAlgorithm = policyAlg
	} else {
		l.Policy.ZSKAlgorithm = policyAlg
	}
}

func (l *ZoneKeyLifecycle) applyAlgorithms() {
	if a := l.algorithms["KSK"]; a != 0 {
		l.Policy.KSKAlgorithm = a
	}
	if a := l.algorithms["ZSK"]; a != 0 {
		l.Policy.ZSKAlgorithm = a
	}
}

// ErrAlgRollSigns: the algorithm rollover cannot be cancelled, a key of
// the new algorithm already signs.
var ErrAlgRollSigns = errors.New("a key of the new algorithm already signs")

// CancelAlgorithmRollover takes the role's algorithm back to the one its
// active key signs with, which withdraws the new algorithm's keys on the
// next tick (they are keys of an algorithm the policy no longer names).
// The rule: a key that does not sign yet can be withdrawn; once a key of
// the new algorithm signs the roll completes on its own, and the way back
// is a change of the algorithm once it has, a rollover through the same
// steps (ErrAlgRollSigns). Returns the algorithms the roll was from and to.
func (l *ZoneKeyLifecycle) CancelAlgorithmRollover(role string) (from, to uint8, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.rows()
	if err != nil {
		return 0, 0, err
	}
	to = l.policyAlgorithm(role)
	from, _, ok := l.oldAlgorithmKey(role, all)
	if !ok {
		return 0, to, fmt.Errorf("the %s algorithm rollover of %s to %s: no key of another algorithm signs or has signed; nothing to go back to", role, l.Zone, dns.AlgorithmToString[to])
	}
	for _, k := range all {
		if roleOf(k.Flags) == role && k.State == KeyStateActive && k.Algorithm == to {
			return from, to, fmt.Errorf("the %s algorithm rollover of %s to %s: %w", role, l.Zone, dns.AlgorithmToString[to], ErrAlgRollSigns)
		}
	}
	prev, hadPrev := l.algorithms[role]
	l.algorithms[role] = from
	l.applyAlgorithms()
	if err := l.saveAlgorithm(role); err != nil {
		l.restoreAlgorithm(role, prev, hadPrev, to)
		return from, to, err
	}
	l.logf("key lifecycle: the algorithm rollover cancelled; the keys of the new algorithm are withdrawn", "zone", l.Zone, "role", role, "from", dns.AlgorithmToString[from], "to", dns.AlgorithmToString[to])
	return from, to, nil
}

// AlgRolloverStatus is an algorithm rollover of one role as the operator
// sees it: the algorithm the old key signs with, the policy's, and the
// step the roll is at, as a sentence.
type AlgRolloverStatus struct {
	Role string `json:"role"`
	From uint8  `json:"from"`
	To   uint8  `json:"to"`
	Step string `json:"step"`
}

// AlgorithmRollovers lists the algorithm rollovers under way: a role whose
// key signs, or has signed and not yet left, with another algorithm than
// the policy's.
//
// A failed read of the rows is an error, not an empty list: none would
// tell the operator that a rollover still under way is over.
func (l *ZoneKeyLifecycle) AlgorithmRollovers() ([]AlgRolloverStatus, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.rows()
	if err != nil {
		return nil, err
	}
	return l.algRolloversOf(all), nil
}

// algRolloversOf is AlgorithmRollovers from rows already read; the caller
// holds l.mu.
func (l *ZoneKeyLifecycle) algRolloversOf(all map[uint16]tdns.DnssecKeyWithTimestamps) []AlgRolloverStatus {
	var out []AlgRolloverStatus
	for _, role := range []string{"KSK", "ZSK"} {
		if st, ok := l.algRolloverOf(role, all); ok {
			out = append(out, st)
		}
	}
	return out
}

// oldAlgorithmKey is the role's key of another algorithm than the policy's
// that signs or has signed and not yet left: the one an algorithm
// rollover replaces. Its algorithm and state, the furthest along when
// there are several. A key of another algorithm that never signed (one on
// its way, withdrawn at the change) is no such key.
func (l *ZoneKeyLifecycle) oldAlgorithmKey(role string, all map[uint16]tdns.DnssecKeyWithTimestamps) (alg uint8, state string, ok bool) {
	to := l.policyAlgorithm(role)
	rank := map[string]int{KeyStateActive: 3, KeyStateRetired: 2, KeyStateMpremove: 1}
	for _, keyid := range keytagsOf(all) {
		k := all[keyid]
		if roleOf(k.Flags) != role || k.Algorithm == to {
			continue
		}
		if k.State != KeyStateActive && k.ActiveAt == nil {
			continue
		}
		if rank[k.State] > rank[state] {
			alg, state, ok = k.Algorithm, k.State, true
		}
	}
	return alg, state, ok
}

func (l *ZoneKeyLifecycle) algRolloverOf(role string, all map[uint16]tdns.DnssecKeyWithTimestamps) (AlgRolloverStatus, bool) {
	to := l.policyAlgorithm(role)
	st := AlgRolloverStatus{Role: role, To: to}
	from, oldState, ok := l.oldAlgorithmKey(role, all)
	if !ok {
		return st, false
	}
	st.From = from
	var newState string
	order := map[string]int{KeyStateCreated: 1, KeyStateMpdist: 2, KeyStatePublished: 3, KeyStateStandby: 4, KeyStateActive: 5}
	for _, keyid := range keytagsOf(all) {
		k := all[keyid]
		if roleOf(k.Flags) == role && k.Algorithm == to && order[k.State] > order[newState] {
			newState = k.State
		}
	}
	role = strings.ToLower(role)
	switch {
	case oldState == KeyStateActive && newState == KeyStateActive && role == "ksk":
		st.Step = "both KSKs sign: the old one's DS is withdrawn from the DS set; it retires once the parent has not served that DS for the DS TTL"
	case oldState == KeyStateRetired && role == "ksk":
		st.Step = "the old KSK is retired and its DS withdrawn; it leaves once the parent no longer serves the DS and the withdrawal margin has passed"
	case oldState == KeyStateRetired:
		st.Step = "the old ZSK is retired; it leaves once the withdrawal margin has passed"
	case oldState == KeyStateMpremove:
		st.Step = "the old " + strings.ToUpper(role) + " has left the DNSKEY RRset; its removal is being confirmed by the other signing providers"
	case newState == "":
		st.Step = "a " + strings.ToUpper(role) + " of the new algorithm is minted on the next tick"
	case newState == KeyStateCreated || newState == KeyStateMpdist:
		st.Step = "the new " + strings.ToUpper(role) + " is on its way to the other signing providers"
	case newState == KeyStatePublished:
		st.Step = "the new " + strings.ToUpper(role) + " is published; waiting for the DNSKEY RRset to propagate"
	case newState == KeyStateStandby && role == "ksk":
		st.Step = "the new KSK is standby and its DS is in the zone's DS set; it signs once the parent has served the DS for the DS TTL, and the old KSK retires then"
	case newState == KeyStateStandby:
		st.Step = "the new ZSK is standby; it signs from the next tick"
	case newState == KeyStateActive && role == "zsk":
		st.Step = "both ZSKs sign; the old one retires once no KSK of the old algorithm signs, or, with no KSK to wait for, a signature lifetime after the new one began signing"
	default:
		st.Step = "both " + strings.ToUpper(role) + "s sign"
	}
	return st, true
}

func (l *ZoneKeyLifecycle) saveAlgorithm(role string) error {
	if l.KDB == nil {
		return nil
	}
	if _, err := l.KDB.DB.Exec(`INSERT INTO MPOwnerAlgorithm (zonename, role, algorithm) VALUES (?, ?, ?)
		ON CONFLICT(zonename, role) DO UPDATE SET algorithm=excluded.algorithm`, l.Zone, role, int(l.algorithms[role])); err != nil {
		return fmt.Errorf("saving the owner's %s algorithm of %s: %w", role, l.Zone, err)
	}
	return nil
}

// loadAlgorithms reads the owner's algorithms back at a restart (T15) and
// puts them over the bound policy's.
func (l *ZoneKeyLifecycle) loadAlgorithms() error {
	if l.KDB == nil {
		return nil
	}
	rows, err := l.KDB.DB.Query(`SELECT role, algorithm FROM MPOwnerAlgorithm WHERE zonename=?`, l.Zone)
	if err != nil {
		return fmt.Errorf("read the owner's algorithms of %s: %w", l.Zone, err)
	}
	defer rows.Close()
	l.algorithms = map[string]uint8{}
	for rows.Next() {
		var role string
		var alg int
		if err := rows.Scan(&role, &alg); err != nil {
			return err
		}
		if alg > 0 && alg < 256 {
			l.algorithms[role] = uint8(alg)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	l.applyAlgorithms()
	return nil
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

// dsPresence: since when the parent has served a standby SEP key's DS, and
// the DS RRset's TTL then (E13, T18).
type dsPresence struct {
	Since time.Time
	TTL   time.Duration
}

// noteParentWait: a standby SEP key's promotion was refused. When the parent
// wait is what refused it, the first refusal is noted, and the operator
// hears once after three margins: the DS the leader sends the parent has
// not been seen served, or was seen too recently (O7).
func (l *ZoneKeyLifecycle) noteParentWait(k tdns.DnssecKeyWithTimestamps, all map[uint16]tdns.DnssecKeyWithTimestamps) {
	cols, err := l.columnsOf(k.KeyTag)
	if err != nil {
		return
	}
	if parentDSWaitMet(l.keyView(k, cols), l.zoneView(k, all)) {
		return
	}
	first, waiting := l.promoteWait[k.KeyTag]
	if !waiting {
		l.promoteWait[k.KeyTag] = l.Clock.Now()
		l.logf("key lifecycle: a standby KSK waits for the parent to serve its DS before it is promoted", "zone", l.Zone, "keyid", k.KeyTag)
		return
	}
	if !l.promoteTold[k.KeyTag] && l.Policy.Margin > 0 && !l.Clock.Now().Before(first.Add(3*l.Policy.Margin)) {
		l.promoteTold[k.KeyTag] = true
		l.Wire.Report(l.Zone, k.KeyTag, "standby KSK waits for the parent to serve its DS before it is promoted (O7): the leader's delegation sync carries it once the key has ds=1; if the parent has it, the DS TTL has to pass")
	}
}

// savePresence persists the parent's presence note of a key, or its absence.
func (l *ZoneKeyLifecycle) savePresence(keyid uint16) {
	if l.KDB == nil {
		return
	}
	p, ok := l.dsPresent[keyid]
	if !ok {
		l.KDB.DB.Exec(`DELETE FROM MPParentDS WHERE zonename=? AND keyid=?`, l.Zone, int(keyid))
		return
	}
	if _, err := l.KDB.DB.Exec(`INSERT INTO MPParentDS (zonename, keyid, since, ttl_seconds) VALUES (?, ?, ?, ?)
		ON CONFLICT(zonename, keyid) DO UPDATE SET since=excluded.since, ttl_seconds=excluded.ttl_seconds`,
		l.Zone, int(keyid), p.Since.UTC().Format(time.RFC3339), int64(p.TTL/time.Second)); err != nil {
		l.logf("key lifecycle: saving the parent's DS note failed", "zone", l.Zone, "keyid", keyid, "err", err)
	}
}

// loadPresences reads the notes back at a restart (T15); one for a key no
// longer standby is dropped, its wait being over.
// saveWithdrawal persists the withdrawal wait's notes of an active KSK
// whose DS is withdrawn (T10a): the TTL caches may hold its DS for, and,
// once the parent was seen without the DS, since when (T11a). Rows of
// MPParentDS like a standby key's T18 note, with an empty since while the
// DS is still served. No note (the key left active) deletes the row.
func (l *ZoneKeyLifecycle) saveWithdrawal(keyid uint16) {
	if l.KDB == nil {
		return
	}
	ttl, hasTTL := l.lastDSTTL[keyid]
	g, gone := l.dsGoneAt[keyid]
	if !hasTTL && !gone {
		l.KDB.DB.Exec(`DELETE FROM MPParentDS WHERE zonename=? AND keyid=?`, l.Zone, int(keyid))
		return
	}
	since := ""
	if gone {
		since, ttl = g.Since.UTC().Format(time.RFC3339), g.TTL
	}
	if _, err := l.KDB.DB.Exec(`INSERT INTO MPParentDS (zonename, keyid, since, ttl_seconds) VALUES (?, ?, ?, ?)
		ON CONFLICT(zonename, keyid) DO UPDATE SET since=excluded.since, ttl_seconds=excluded.ttl_seconds`,
		l.Zone, int(keyid), since, int64(ttl/time.Second)); err != nil {
		l.logf("key lifecycle: saving the withdrawal wait's note failed", "zone", l.Zone, "keyid", keyid, "err", err)
	}
}

func (l *ZoneKeyLifecycle) loadPresences(all map[uint16]tdns.DnssecKeyWithTimestamps) error {
	withdrawn, err := l.withdrawnActive(all)
	if err != nil {
		return err
	}
	rows, err := l.KDB.DB.Query(`SELECT keyid, since, ttl_seconds FROM MPParentDS WHERE zonename=?`, l.Zone)
	if err != nil {
		return fmt.Errorf("read the parent's DS notes of %s: %w", l.Zone, err)
	}
	defer rows.Close()
	l.dsPresent = map[uint16]dsPresence{}
	var stale []uint16
	for rows.Next() {
		var keyid int
		var since string
		var ttl int64
		if err := rows.Scan(&keyid, &since, &ttl); err != nil {
			return err
		}
		tag := uint16(keyid)
		if withdrawn[tag] {
			// the withdrawal wait's note (T10a, T11a): the TTL, and since
			// when the parent was seen without the DS, if it was
			if ttl > 0 {
				l.lastDSTTL[tag] = time.Duration(ttl) * time.Second
			}
			if since != "" {
				if t, err := time.Parse(time.RFC3339, since); err == nil {
					l.dsGone[tag] = true
					l.dsGoneAt[tag] = dsPresence{Since: t, TTL: time.Duration(ttl) * time.Second}
				} else {
					l.logf("key lifecycle: the withdrawal wait's note of a key is unreadable and is dropped; the next poll notes the DS gone again", "zone", l.Zone, "keyid", tag, "since", since, "err", err)
				}
			}
			continue
		}
		if k, ok := all[tag]; !ok || k.State != KeyStateStandby {
			stale = append(stale, tag)
			continue
		}
		// A note whose time cannot be read is no note: kept, its zero time
		// would hold the key's wait forever (parentDSWaitMet). Dropped, the
		// next tick that sees the DS records a fresh one.
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			l.logf("key lifecycle: the parent's DS note of a key is unreadable and is dropped", "zone", l.Zone, "keyid", tag, "since", since, "err", err)
			stale = append(stale, tag)
			continue
		}
		l.dsPresent[tag] = dsPresence{Since: t, TTL: time.Duration(ttl) * time.Second}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, tag := range stale {
		l.savePresence(tag)
	}
	return nil
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
