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

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

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
	if len(l.foreign) == 0 {
		return nil
	}
	inv, err := tdns.GetKeyInventory(l.KDB, l.Zone)
	if err != nil {
		return fmt.Errorf("inventory of %s: %w", l.Zone, err)
	}
	signers := map[string]bool{}
	for _, p := range l.Wire.OtherSigners(l.Zone) {
		signers[p] = true
	}
	changed := false
	for _, it := range inv {
		if it.State != DnskeyStateForeign {
			continue
		}
		said, ok := l.foreign[it.KeyTag]
		if !ok {
			continue
		}
		want, decided := foreignDSFor(said, it.Flags&dns.SEP != 0, signers)
		if !decided || (it.DS != nil && *it.DS == want) {
			continue
		}
		cols := tdns.KeyRowFlags{Pub: true, DS: sql.NullBool{Bool: want, Valid: true}}
		if err := tdns.UpdateKeyRowFrom(l.KDB, l.Zone, it.KeyTag, DnskeyStateForeign, DnskeyStateForeign, cols); err != nil {
			return fmt.Errorf("ds of foreign key %d of %s: %w", it.KeyTag, l.Zone, err)
		}
		l.logf("key lifecycle: ds written on another provider's key", "zone", l.Zone, "keytag", it.KeyTag, "provider", said.Provider, "its state", said.State, "ds", want)
		changed = true
	}
	if changed {
		l.Wire.KeysChanged(l.Zone)
	}
	return nil
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
