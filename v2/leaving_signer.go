/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A signer the zone owner takes out of signers= (tdns-mp #147, the interim
 * rule of #267 item 5). While the zone's HSYNC3 RRset still lists it, it
 * goes on as before: its signer signs with its own keys, its combiner
 * applies what it is sent, and the other providers go on treating it as a
 * signer, so its DNSKEYs stay in their DNSKEY RRsets and its DS in the
 * zone's DS set (#200 items 3 and 4). It starts nothing of its own: it has
 * no role, so it neither votes nor distributes keys. It takes no
 * distribution either, so while it leaves no signer of the zone starts a
 * key rollover: another signer's new key would be missing from the DNSKEY
 * RRset the leaver serves. Everything ends when the owner removes its
 * HSYNC3 record; the owner's order is in guide/provider-changes.md. The
 * transitions design (#211: S11, S13 and S17b) replaces this with a
 * removal in steps.
 */
package tdnsmp

import (
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// signingSet is the providers that sign a zone: those its signers= names,
// and those leaving it. Keyed by HSYNC3 label without the trailing dot,
// each with the identity of its ON HSYNC3 record ("" for a label signers=
// names that no such record carries).
type signingSet map[string]string

// nextSigningSet is the signing set by a copy of the zone whose apex is
// apex, given the set by the copy before it (prev): every label signers=
// names, and every provider of prev that the HSYNC3 RRset still lists ON
// under the same label and identity. So a provider leaves the set only
// when the owner removes its HSYNC3 record, and only a provider that has
// been in signers= is ever in it: a newcomer whose record comes first, or
// a server that does not sign, never starts. A copy with no HSYNCPARAM
// names no signer.
func nextSigningSet(apex *tdns.OwnerData, prev signingSet) signingSet {
	return nextSigningSetOf(readingOf(apex), prev)
}

// nextSigningSetOf is nextSigningSet by a reading of the instructions.
func nextSigningSetOf(in *Instructions, prev signingSet) signingSet {
	out := signingSet{}
	if in == nil || !in.HasParam {
		return out
	}
	for _, s := range in.Signers {
		out[s] = in.identityOf(s)
	}
	for label, id := range prev {
		if _, named := out[label]; !named && id != "" && core.EqualNames(in.identityOf(label), id) {
			out[label] = id
		}
	}
	return out
}

// others are the labels of the set other than self, sorted.
func (s signingSet) others(self string) []string {
	var out []string
	for label := range s {
		if label != trimDot(self) {
			out = append(out, label)
		}
	}
	sort.Strings(out)
	return out
}

// leaving are the labels of the set that the instructions' signers= does
// not name, sorted.
func (s signingSet) leaving(in *Instructions) []string {
	var out []string
	for label := range s {
		if in == nil || !slices.Contains(in.Signers, label) {
			out = append(out, label)
		}
	}
	sort.Strings(out)
	return out
}

// leavers are the providers of the set that the instructions' signers=
// does not name, by identity (by label where the set has none), sorted.
func (s signingSet) leavers(in *Instructions) []string {
	var out []string
	for _, label := range s.leaving(in) {
		if id := s[label]; id != "" {
			out = append(out, id)
		} else {
			out = append(out, label)
		}
	}
	sort.Strings(out)
	return out
}

// signingSet is the zone's signing set as its last refresh left it. Before
// the zone's first copy here, and for a ZoneData that is not the one in
// Zones (an incoming copy wrapped for analysis), it is the signers= alone of
// the instructions mpzd reads: the active ones, or that copy's.
func (mpzd *MPZoneData) signingSet() signingSet {
	if mpzd.MP != nil && mpzd.MP.MPdata != nil && mpzd.MP.MPdata.Signing != nil {
		return mpzd.MP.MPdata.Signing
	}
	return nextSigningSetOf(mpzd.instructions(), nil)
}

// signs: the provider with this HSYNC3 label signs the zone, named in
// signers= or leaving it.
func (mpzd *MPZoneData) signs(label string) bool {
	_, in := mpzd.signingSet()[trimDot(label)]
	return in
}

// signingLabels are the labels of the zone's signing set: those signers=
// names, then those leaving it, each sorted.
func (mpzd *MPZoneData) signingLabels() []string {
	set := mpzd.signingSet()
	apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	in := activeOr(mpzd.ZoneName, apex)
	if in == nil || !in.HasParam {
		return slices.Sorted(maps.Keys(set))
	}
	var out []string
	for _, s := range in.Signers {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}
	return append(out, set.leaving(in)...)
}

// leavingSigner: this provider signs the zone though its signers= no longer
// names it.
func (mpzd *MPZoneData) leavingSigner() bool {
	return mpzd.MP != nil && mpzd.MP.MPdata != nil && mpzd.MP.MPdata.Leaving
}

// advanceSigningSet is the signing set by the incoming copy (apex), from
// the one the zone's last copy gave. At the zone's first copy here that is
// the one the keystore keeps, so that a restart does not forget a provider
// that is leaving; a changed set is kept again. With no keystore (kdb nil)
// nothing is kept, and a restart starts from signers=. changed says that a
// live refresh changed the set: not the first copy here, whose election
// runs the leader's sync anyway (afterSigningSetChange).
func (mpzd *MPZoneData) advanceSigningSet(apex *tdns.OwnerData, kdb *tdns.KeyDB) (next signingSet, changed bool) {
	var prev signingSet
	live := mpzd.MP != nil && mpzd.MP.MPdata != nil && mpzd.MP.MPdata.Signing != nil
	if live {
		prev = mpzd.MP.MPdata.Signing
	} else if kdb != nil {
		var err error
		if prev, err = loadSigningSet(kdb, mpzd.ZoneName); err != nil {
			lg.Error("the zone's signing providers could not be read from the keystore; starting from signers=", "zone", mpzd.ZoneName, "err", err)
		}
	}
	next = nextSigningSet(apex, prev)
	if maps.Equal(prev, next) {
		return next, false
	}
	lg.Info("the providers that sign the zone changed; one out of signers= signs on until the owner removes its HSYNC3 record (#147)",
		"zone", mpzd.ZoneName, "signing", strings.Join(slices.Sorted(maps.Keys(next)), " "),
		"leaving", strings.Join(next.leaving(readingOf(apex)), " "))
	if kdb != nil {
		if err := saveSigningSet(kdb, mpzd.ZoneName, next); err != nil {
			lg.Error("the zone's signing providers could not be kept in the keystore; a restart starts from signers=", "zone", mpzd.ZoneName, "err", err)
		}
	}
	return next, live
}

// afterSigningSetChange runs after a refresh (the post-refresh callback): when
// the refresh changed the zone's signing set (MPState.SigningChanged, which
// it clears), it asks the leader's delegation sync. The DS set follows the
// signing set, and can change with no key and no inventory changing: when
// the owner removes a leaving provider's HSYNC3 record its DS leaves the
// set, and nothing else would ask for the sync (#147). The sync is explicit,
// an update only where the parent differs; an agent that does not lead, and
// a zone whose parent the owner syncs, ask for nothing.
func (conf *Config) afterSigningSetChange(mpzd *MPZoneData) {
	if mpzd == nil || mpzd.MP == nil || !mpzd.MP.SigningChanged {
		return
	}
	mpzd.MP.SigningChanged = false
	conf.requestDelegationSync(nil, mpzd.ZoneName, "the zone's signing set changed: a provider left signers=, or a leaving one's HSYNC3 record went (#147)")
}

// The signing set is kept as one row per zone, "label=identity" pairs
// separated by spaces, so that a write is one statement.

func loadSigningSet(kdb *tdns.KeyDB, zone string) (signingSet, error) {
	if _, err := kdb.DB.Exec(HsyncTables["MPSigningProviders"]); err != nil {
		return nil, fmt.Errorf("the MPSigningProviders table: %w", err)
	}
	var providers string
	err := kdb.DB.QueryRow(`SELECT providers FROM MPSigningProviders WHERE zonename=?`, dns.Fqdn(zone)).Scan(&providers)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the signing providers of %s: %w", zone, err)
	}
	set := signingSet{}
	for _, p := range strings.Fields(providers) {
		label, id, _ := strings.Cut(p, "=")
		set[label] = id
	}
	return set, nil
}

func saveSigningSet(kdb *tdns.KeyDB, zone string, set signingSet) error {
	if _, err := kdb.DB.Exec(HsyncTables["MPSigningProviders"]); err != nil {
		return fmt.Errorf("the MPSigningProviders table: %w", err)
	}
	var pairs []string
	for _, label := range slices.Sorted(maps.Keys(set)) {
		pairs = append(pairs, label+"="+set[label])
	}
	if _, err := kdb.DB.Exec(`INSERT INTO MPSigningProviders (zonename, providers) VALUES (?, ?)
		ON CONFLICT(zonename) DO UPDATE SET providers = excluded.providers`, dns.Fqdn(zone), strings.Join(pairs, " ")); err != nil {
		return fmt.Errorf("keeping the signing providers of %s: %w", zone, err)
	}
	return nil
}
