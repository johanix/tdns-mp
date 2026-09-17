/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Foreign rows of an owned zone: what the other providers say about
 * their keys (tdns-mp #58; design §5, D4), and the ds column the owner
 * writes on their rows from it (transition table §3, P3). The rows
 * themselves follow the other providers' DNSKEYs as before; only ds is
 * decided here.
 */
package tdnsmp

import (
	"database/sql"
	"fmt"
	"sort"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// foreignStateOmitted stands for a key its provider no longer mentions
// while it still speaks of others: it has stopped serving the key (a
// standby withdrawn, a removal under way), so the key's DS does not belong
// at the parent any more, whatever was said before. The entry stays until
// the row itself is gone.
const foreignStateOmitted = "omitted"

// foreignSaid is what a provider said about one of its keys.
type foreignSaid struct {
	Provider string
	State    string
	DS       *bool // nil: the provider does not say
}

// foreignDSFor is P3: a foreign KSK's DS belongs at the parent only while
// its provider signs the zone and holds the key standby, active or retired
// with its DS not withdrawn, which is what the provider's own ds column
// says. decided is false when the provider does not say (an older
// release, Q9): the row stays undecided, which blocks the zone's DS set
// rather than guessing it.
func foreignDSFor(said foreignSaid, sep bool, signers map[string]bool) (ds bool, decided bool) {
	if said.DS == nil {
		return false, false
	}
	held := said.State == KeyStateStandby || said.State == KeyStateActive || said.State == KeyStateRetired
	return *said.DS && sep && held && signers[said.Provider], true
}

// SetForeignStates records the complete latest set of what the other
// providers said about their keys in the zone (a provider missing from
// the set has said nothing), and writes ds on the foreign rows from it.
func (l *ZoneKeyLifecycle) SetForeignStates(keys []core.ForeignKeyState) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.initErr != nil {
		return l.initErr
	}
	said := map[uint16]foreignSaid{}
	for _, k := range keys {
		if prev, dup := said[k.KeyTag]; dup && prev.Provider != k.Provider {
			l.logf("key lifecycle: two providers name a key with the same key tag; the later one stands", "zone", l.Zone, "keytag", k.KeyTag, "first", prev.Provider, "later", k.Provider)
		}
		said[k.KeyTag] = foreignSaid{Provider: k.Provider, State: k.State, DS: k.DS}
	}
	// the latest word replaces the one before; a key a provider mentioned
	// before and leaves out now, while it still speaks, is omitted: ds=0
	speaking := map[string]bool{}
	for _, s := range said {
		speaking[s.Provider] = true
	}
	no := false
	for kt, old := range l.foreign {
		if _, still := said[kt]; !still && speaking[old.Provider] {
			said[kt] = foreignSaid{Provider: old.Provider, State: foreignStateOmitted, DS: &no}
		}
	}
	if err := l.saveForeign(said); err != nil {
		return err
	}
	l.foreign = said
	return l.applyForeignLocked()
}

// applyForeignLocked writes ds on every foreign row whose provider has
// said, where the row does not have it already. It runs when the
// providers' word arrives, on every tick (a row appears when the zone
// with the provider's DNSKEY has been transferred, which may be after
// the word), on Reload, and when the signers change (a provider that
// stops signing: ds=0, E10).
func (l *ZoneKeyLifecycle) applyForeignLocked() error {
	inv, err := tdns.GetKeyInventory(l.KDB, l.Zone)
	if err != nil {
		return fmt.Errorf("inventory of %s: %w", l.Zone, err)
	}
	signers := map[string]bool{}
	for _, p := range l.Wire.OtherSigners(l.Zone) {
		signers[p] = true
	}
	changed := false
	rows := map[uint16]bool{}
	for _, it := range inv {
		if it.State != DnskeyStateForeign {
			continue
		}
		rows[it.KeyTag] = true
		said, ok := l.foreign[it.KeyTag]
		want, decided := false, false
		if ok {
			want, decided = foreignDSFor(said, it.Flags&dns.SEP != 0, signers)
		}
		if !decided {
			if it.DS == nil && it.Flags&dns.SEP != 0 {
				l.noteUndecided(it.KeyTag, said.Provider)
			}
			continue
		}
		delete(l.undecidedSince, it.KeyTag)
		delete(l.undecidedTold, it.KeyTag)
		if it.DS != nil && *it.DS == want {
			continue
		}
		cols := tdns.KeyRowFlags{Pub: true, DS: sql.NullBool{Bool: want, Valid: true}}
		if err := tdns.UpdateKeyRowFrom(l.KDB, l.Zone, it.KeyTag, DnskeyStateForeign, DnskeyStateForeign, cols); err != nil {
			return fmt.Errorf("ds of foreign key %d of %s: %w", it.KeyTag, l.Zone, err)
		}
		l.logf("key lifecycle: ds written on another provider's key", "zone", l.Zone, "keytag", it.KeyTag, "provider", said.Provider, "its state", said.State, "ds", want)
		changed = true
	}
	// an omitted key whose row is gone has nothing left to decide
	dropped := false
	for kt, s := range l.foreign {
		if s.State == foreignStateOmitted && !rows[kt] {
			delete(l.foreign, kt)
			dropped = true
		}
	}
	for kt := range l.undecidedSince {
		if !rows[kt] {
			delete(l.undecidedSince, kt)
			delete(l.undecidedTold, kt)
		}
	}
	if dropped {
		if err := l.saveForeign(l.foreign); err != nil {
			return err
		}
	}
	if changed {
		l.Wire.KeysChanged(l.Zone)
	}
	return nil
}

// noteUndecided: another provider's KSK nobody has decided the ds of keeps
// the zone's DS set unknown, so no CDS and no DS change reaches the parent
// (design R9: a provider left on an older release blocks every KSK
// change towards the parent). Said once per key, after the word has had
// three margins to arrive, with the provider when it is known.
func (l *ZoneKeyLifecycle) noteUndecided(keyid uint16, provider string) {
	if l.undecidedSince == nil {
		l.undecidedSince, l.undecidedTold = map[uint16]time.Time{}, map[uint16]bool{}
	}
	now := l.Clock.Now()
	since, seen := l.undecidedSince[keyid]
	if !seen {
		l.undecidedSince[keyid] = now
		return
	}
	wait := 3 * l.Policy.Margin
	if wait <= 0 {
		wait = 5 * time.Minute
	}
	if l.undecidedTold[keyid] || now.Before(since.Add(wait)) {
		return
	}
	l.undecidedTold[keyid] = true
	who := "a provider that has not been heard from"
	if provider != "" {
		who = "provider " + provider + ", which does not say"
	}
	l.Wire.Report(l.Zone, keyid, fmt.Sprintf("the KSK of %s whether its DS belongs at the parent: the zone's DS set stays unknown, and no CDS or DS change reaches the parent, until every signing provider runs a release that says", who))
}

// ForeignStates is what the providers said, by key tag, for the operator.
func (l *ZoneKeyLifecycle) ForeignStates() []core.ForeignKeyState {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]core.ForeignKeyState, 0, len(l.foreign))
	for kt, s := range l.foreign {
		out = append(out, core.ForeignKeyState{Provider: s.Provider, KeyState: core.KeyState{KeyTag: kt, State: s.State, DS: s.DS}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyTag < out[j].KeyTag })
	return out
}

func (l *ZoneKeyLifecycle) saveForeign(said map[uint16]foreignSaid) error {
	tx, err := l.KDB.DB.Begin()
	if err != nil {
		return fmt.Errorf("foreign key states of %s: %w", l.Zone, err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM MPForeignKeyState WHERE zonename=?`, l.Zone); err != nil {
		return fmt.Errorf("foreign key states of %s: %w", l.Zone, err)
	}
	for kt, s := range said {
		var ds sql.NullBool
		if s.DS != nil {
			ds = sql.NullBool{Bool: *s.DS, Valid: true}
		}
		if _, err := tx.Exec(`INSERT INTO MPForeignKeyState (zonename, keyid, provider, state, ds) VALUES (?, ?, ?, ?, ?)`,
			l.Zone, int(kt), s.Provider, s.State, ds); err != nil {
			return fmt.Errorf("foreign key state %d of %s: %w", kt, l.Zone, err)
		}
	}
	return tx.Commit()
}

func (l *ZoneKeyLifecycle) loadForeign() error {
	rows, err := l.KDB.DB.Query(`SELECT keyid, provider, state, ds FROM MPForeignKeyState WHERE zonename=?`, l.Zone)
	if err != nil {
		return fmt.Errorf("foreign key states of %s: %w", l.Zone, err)
	}
	defer rows.Close()
	said := map[uint16]foreignSaid{}
	for rows.Next() {
		var keyid int
		var s foreignSaid
		var ds sql.NullBool
		if err := rows.Scan(&keyid, &s.Provider, &s.State, &ds); err != nil {
			return fmt.Errorf("foreign key states of %s: %w", l.Zone, err)
		}
		if ds.Valid {
			v := ds.Bool
			s.DS = &v
		}
		said[uint16(keyid)] = s
	}
	if err := rows.Err(); err != nil {
		return err
	}
	l.foreign = said
	return nil
}
