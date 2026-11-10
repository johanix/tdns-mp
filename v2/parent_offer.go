/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A parent that publishes no DSYNC, or none with a scheme this child can
// use, is the common case, not a fault (Johan, 2026-11-09): the child says
// so once, as a warning, and moves on. Nothing is sent to such a parent, no
// failure is booked and no retry is scheduled. The parent is looked at again
// quietly, at DEBUG: when something asks for a sync anyway, once an hour
// (recheckParentOffers), and from the identity zone's own sync. When a
// usable scheme appears the change is logged at INFO and the sync goes on as
// for any other parent. A failure where a usable scheme exists (the parent
// refuses the UPDATE, the API call fails, a timeout) is not this case and
// is logged as before.

// parentOffer is what one look at the parent's DSYNC records found.
type parentOffer struct {
	parent  string // the parent zone, as the sync plan resolved it
	found   string // what was found: the plan's summary
	usable  bool   // at least one configured scheme this child can use
	update  bool   // the parent advertises a usable UPDATE target (the SIG(0) bootstrap's)
	schemes string // the schemes the parent advertises, for the bootstrap's warning
}

// errNoResolver: the parent's DSYNC records cannot be looked at, because
// the resolver is not running. Callers go on as if nothing were known.
var errNoResolver = errors.New("no resolver to look up the parent's DSYNC records with")

// parentOfferOf looks at what the zone's parent offers: the plan tdns would
// build for the sync (one DSYNC discovery), and whether the parent
// advertises an UPDATE target the SIG(0) bootstrap could use. An error says
// nothing is known (no resolver, a failed lookup); the caller then goes on as
// it would have without the look, and a failed lookup is reported where the
// sync itself runs into it.
//
// The discovery is made twice, once for the plan and once for the UPDATE
// target, which the plan only evaluates when the configuration names the
// UPDATE scheme. The resolver answers the second from its cache.
func (conf *Config) parentOfferOf(ctx context.Context, zd *tdns.ZoneData, kdb *tdns.KeyDB) (parentOffer, error) {
	if hook := conf.InternalMp.parentOffer; hook != nil {
		return hook(ctx, zd)
	}
	if zd == nil {
		return parentOffer{}, errors.New("no zone")
	}
	if conf.Config == nil || conf.Config.Internal.ImrEngine == nil {
		return parentOffer{}, errNoResolver
	}
	imr := conf.Config.Internal.ImrEngine
	plan, err := zd.BuildParentSyncPlan(ctx, kdb, imr, tdns.SyncRoleChild)
	if err != nil {
		return parentOffer{}, err
	}
	res, err := imr.DsyncDiscovery(ctx, zd.ZoneName, false)
	if err != nil {
		return parentOffer{}, err
	}
	off := parentOffer{parent: plan.Parent, found: plan.Summary(), usable: plan.Usable()}
	var names []string
	for _, d := range res.Rdata {
		if d == nil || !d.Usable() {
			continue
		}
		// The test LookupDSYNCTarget applies for the bootstrap's target
		if d.Scheme == core.SchemeUpdate && d.Type == dns.TypeANY {
			off.update = true
		}
		name := core.SchemeToString[d.Scheme]
		if name == "" {
			name = fmt.Sprintf("scheme %d", d.Scheme)
		}
		names = append(names, name)
	}
	off.schemes = schemeList(names)
	return off, nil
}

// schemeList is the advertised schemes, each once, sorted.
func schemeList(names []string) string {
	if len(names) == 0 {
		return "no DSYNC records"
	}
	sort.Strings(names)
	out := names[:0]
	for i, n := range names {
		if i == 0 || n != names[i-1] {
			out = append(out, n)
		}
	}
	return strings.Join(out, ", ")
}

// errNoUsableScheme is syncDelegation's answer when the parent offers no
// scheme this child can use: nothing was sent. Not a failure: the caller
// logs it at DEBUG, books no failure and schedules no retry (the warning
// is noteParentOffer's, once per zone).
type errNoUsableScheme struct{ off parentOffer }

func (e errNoUsableScheme) Error() string {
	return fmt.Sprintf("the parent %s offers no delegation sync scheme this zone can use (%s); nothing was sent", e.off.parent, e.off.found)
}

// parentNotices is what the log has been told about each zone's parent:
// that it offers no usable scheme, or no UPDATE scheme for the SIG(0)
// bootstrap. Keyed by the zone's name, so a reload, which replaces the
// zone's ZoneData, does not warn again.
type parentNotices struct {
	mu       sync.Mutex
	noScheme map[string]*parentNotice
	noUpdate map[string]*parentNotice
}

// parentNotice is one zone's note.
type parentNotice struct {
	parent  string
	since   time.Time
	recheck bool // looked at again by recheckParentOffers
}

// note records that the zone's parent offers nothing (of the kind m
// tracks), and reports whether that is news: the first time, or a new
// parent. recheck puts the zone on the hourly look (recheckParentOffers);
// it is never taken off by a later note without it.
func (n *parentNotices) note(m *map[string]*parentNotice, zone, parent string, recheck bool) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if *m == nil {
		*m = map[string]*parentNotice{}
	}
	zone = string(canonZone(ZoneName(zone)))
	if e := (*m)[zone]; e != nil && sameName(e.parent, parent) {
		e.recheck = e.recheck || recheck
		return false
	}
	(*m)[zone] = &parentNotice{parent: parent, since: time.Now(), recheck: recheck}
	return true
}

// clear forgets the zone's note, and returns it when there was one.
func (n *parentNotices) clear(m *map[string]*parentNotice, zone string) *parentNotice {
	n.mu.Lock()
	defer n.mu.Unlock()
	zone = string(canonZone(ZoneName(zone)))
	e := (*m)[zone]
	delete(*m, zone)
	return e
}

// rechecked lists the zones on the hourly look. It takes the map's address,
// as note and clear do, and reads the field only under n.mu: note makes the
// map on a zone's first note, from the syncher or the identity loop.
func (n *parentNotices) rechecked(m *map[string]*parentNotice) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for zone, e := range *m {
		if e.recheck {
			out = append(out, zone)
		}
	}
	sort.Strings(out)
	return out
}

// noteParentOffer logs what the parent offers for the zone's delegation
// sync, and reports whether there is a scheme to use. No usable scheme: a
// warning the first time (and for a new parent), DEBUG after that. A usable
// scheme after a warning: INFO, once.
func (conf *Config) noteParentOffer(zone string, off parentOffer, recheck bool) bool {
	n := &conf.InternalMp.parentNotices
	if !off.usable {
		if n.note(&n.noScheme, zone, off.parent, recheck) {
			lg.Warn("delegation sync: the parent offers no scheme this zone can use; nothing is sent to it, and it is looked at again quietly",
				"zone", zone, "parent", off.parent, "found", off.found)
		} else {
			lg.Debug("delegation sync: the parent still offers no scheme this zone can use", "zone", zone, "parent", off.parent, "found", off.found)
		}
		return false
	}
	if e := n.clear(&n.noScheme, zone); e != nil {
		lg.Info("delegation sync: the parent now offers a scheme this zone can use", "zone", zone, "parent", off.parent,
			"found", off.found, "none_since", e.since.UTC().Format(time.RFC3339))
	}
	return true
}

// noteUpdateOffer is noteParentOffer for the SIG(0) bootstrap, which needs
// the parent's UPDATE target: it reports whether the parent advertises one.
func (conf *Config) noteUpdateOffer(zone string, off parentOffer, recheck bool) bool {
	n := &conf.InternalMp.parentNotices
	if !off.update {
		if n.note(&n.noUpdate, zone, off.parent, recheck) {
			lg.Warn("delegation sync: the parent offers no UPDATE scheme; the zone's SIG(0) key is not bootstrapped with it",
				"zone", zone, "parent", off.parent, "advertised", off.schemes)
		} else {
			lg.Debug("delegation sync: the parent still offers no UPDATE scheme", "zone", zone, "parent", off.parent, "advertised", off.schemes)
		}
		return false
	}
	if e := n.clear(&n.noUpdate, zone); e != nil {
		lg.Info("delegation sync: the parent now offers the UPDATE scheme; the zone's SIG(0) key is bootstrapped", "zone", zone,
			"parent", off.parent, "none_since", e.since.UTC().Format(time.RFC3339))
	}
	return true
}

// parentRecheckEvery is how often recheckParentOffers looks again at the
// parents that offer nothing. An hour is longer than the negative TTL of
// most zones' DSYNC answers, so each look asks the parent anew. A variable
// so a test need not wait an hour.
var parentRecheckEvery = time.Hour

// recheckParentOffers looks again, once per parentRecheckEvery, at the
// parents that offered no usable scheme (or no UPDATE scheme for the
// bootstrap) when the syncher last asked. A parent that still offers
// nothing is noted at DEBUG, and nothing else happens. One that now offers
// a scheme is noted at INFO, and the zone's explicit sync (or setup) is
// queued, which the syncher runs as for any other parent. A zone gone, or a
// multi-provider zone this agent no longer leads, is forgotten: whoever
// leads it asks for itself. The identity zone's own sync looks at its
// parent by itself and does not put the zone here.
func (conf *Config) recheckParentOffers(ctx context.Context, hdb *HsyncDB, q chan tdns.DelegationSyncRequest) {
	t := time.NewTicker(parentRecheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !conf.recheckParentOffersOnce(ctx, hdb, q) {
			return
		}
	}
}

// recheckParentOffersOnce is one round of recheckParentOffers. It reports
// false when ctx ended.
func (conf *Config) recheckParentOffersOnce(ctx context.Context, hdb *HsyncDB, q chan tdns.DelegationSyncRequest) bool {
	n := &conf.InternalMp.parentNotices
	var kdb *tdns.KeyDB
	if hdb != nil {
		kdb = hdb.KeyDB
	}
	for _, set := range []struct {
		m       *map[string]*parentNotice
		command string
		offered func(zone string, off parentOffer) bool
	}{
		{&n.noScheme, "EXPLICIT-SYNC-DELEGATION", func(zone string, off parentOffer) bool { return conf.noteParentOffer(zone, off, true) }},
		{&n.noUpdate, "DELEGATION-SYNC-SETUP", func(zone string, off parentOffer) bool { return conf.noteUpdateOffer(zone, off, true) }},
	} {
		for _, zone := range n.rechecked(set.m) {
			mpzd, ok := Zones.Get(zone)
			if !ok || mpzd == nil || mpzd.ZoneData == nil || !mpzd.Options[tdns.OptParentSync] ||
				(mpzd.Options[tdns.OptMultiProvider] && !conf.leadsZone(zone)) {
				n.clear(set.m, zone)
				continue
			}
			off, err := conf.parentOfferOf(ctx, mpzd.ZoneData, kdb)
			if err != nil {
				lg.Debug("delegation sync: the parent's DSYNC records could not be looked at again", "zone", zone, "err", err)
				continue
			}
			if !set.offered(zone, off) {
				continue
			}
			select {
			case q <- tdns.DelegationSyncRequest{Command: set.command, ZoneName: mpzd.ZoneName, ZoneData: mpzd.ZoneData}:
			case <-ctx.Done():
				return false
			}
		}
	}
	return ctx.Err() == nil
}

// noUsableScheme looks at what the zone's parent offers before a sync sends
// anything (syncDelegation). It returns errNoUsableScheme when the parent
// offers no scheme this zone can use, and nil when it offers one or when
// nothing is known: the sync then goes on and meets any failure itself.
func (conf *Config) noUsableScheme(ctx context.Context, hdb *HsyncDB, ds tdns.DelegationSyncRequest) error {
	if conf == nil || ds.ZoneData == nil {
		return nil
	}
	var kdb *tdns.KeyDB
	if hdb != nil {
		kdb = hdb.KeyDB
	}
	off, err := conf.parentOfferOf(ctx, ds.ZoneData, kdb)
	if err != nil || conf.noteParentOffer(ds.ZoneName, off, true) {
		return nil
	}
	return errNoUsableScheme{off}
}
