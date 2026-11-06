/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The zone's CDS and CDNSKEY at the _signal names (design 5.6, plan S21):
 * _dsboot.<zone>._signal.<ns>, RFC 9615's names, under the nameservers this
 * provider has a provider zone for (signalNSTargets, the KEY's targets). They
 * go by the sets the combiner was handed, its agent's word for the step, not
 * by the zone's copy, and carry the apex as the combiner serves it: only it
 * holds every signer's CDS, and a name that did not follow the apex would
 * give a parent a DS for a key the zone no longer publishes. The provider
 * zone's own contributions are the ledger of what was published, and what a
 * restart loads.
 */
package tdnsmp

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// dsbootTypes are what a _dsboot name carries.
var dsbootTypes = []uint16{dns.TypeCDS, dns.TypeCDNSKEY}

// dsbootRetryInterval is how often a failed sync of the names goes again.
var dsbootRetryInterval = time.Minute

// dsbootOwnerPrefix is what every _dsboot name of the zone starts with.
func dsbootOwnerPrefix(zone string) string {
	return "_dsboot." + dns.Fqdn(zone) + "_signal."
}

// dsbootOwnerName computes the RFC 9615 owner name of a zone's CDS and
// CDNSKEY under a nameserver: _dsboot.<zone>._signal.<nameserver>.
func dsbootOwnerName(zone, nameserver string) string {
	return dsbootOwnerPrefix(zone) + dns.Fqdn(nameserver)
}

// dsbootWanted is what the zone's _dsboot names should hold, by owner and
// type: the apex's CDS and CDNSKEY as served, under each of signalNSTargets;
// nothing while the sets handed do not say pubcds, or the zone has neither.
// Nothing for a zone with no HSYNC3 either: it is not a multi-provider zone,
// and tdns's use-hsyncparam publishes at its names, each provider on its own
// (the project owner, 2026-11-06).
func (mpzd *MPZoneData) dsbootWanted(by string) map[string]map[uint16][]dns.RR {
	want := map[string]map[uint16][]dns.RR{}
	if !mpzd.hasPubcds() || !hasHSYNC3(mpzd.instructions()) {
		return want
	}
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		return want
	}
	targets := mpzd.signalNSTargets(by, mpzd.ZoneName)
	for _, rrtype := range dsbootTypes {
		rrs := apex.RRtypes.GetOnlyRRSet(rrtype).RRs
		if len(rrs) == 0 {
			continue
		}
		for _, ns := range targets {
			owner := dsbootOwnerName(mpzd.ZoneName, ns)
			if want[owner] == nil {
				want[owner] = map[uint16][]dns.RR{}
			}
			for _, rr := range rrs {
				c := dns.Copy(rr)
				c.Header().Name = owner
				want[owner][rrtype] = append(want[owner][rrtype], c)
			}
		}
	}
	return want
}

// syncDsbootNames brings the zone's _dsboot names in the provider zones to
// what the sets handed and the served apex say: called after whatever can
// change them, a hand-over, an update, a refresh or a first load, and a no-op
// when they are already so. Handed nothing, the combiner leaves them as they
// are (rule 5), and a zone that has not loaded says nothing either way. A
// provider zone that has not loaded waits for its own first load
// (serveDsbootNamesAtFirstLoad). A failure is kept, and the combiner tries
// again every minute (syncOwedDsbootNames): an update's data is held and
// served whatever its names do, so no word of the agent's asks for them
// again, and the next update or hand-over may be long in coming.
func (mpzd *MPZoneData) syncDsbootNames() (err error) {
	defer func() { actingHeld.Load().oweDsboot(mpzd.ZoneName, err != nil) }()
	if GetProviderZoneRRtypes(mpzd.ZoneName) != nil || !mpzd.HasPublishedData() {
		return nil
	}
	held, ok := actingHeld.Load().get(mpzd.ZoneName)
	if !ok {
		return nil
	}
	want := mpzd.dsbootWanted(held.by)
	prefix := dsbootOwnerPrefix(mpzd.ZoneName)
	byProvider := map[string][]string{}
	for owner := range want {
		if pz := findProviderZoneForOwner(owner); pz != "" {
			byProvider[pz] = append(byProvider[pz], owner)
		}
	}
	var errs []error
	published, withdrawn := false, false
	for _, name := range slices.Sorted(maps.Keys(providerZoneRRtypes)) {
		provider, ok := Zones.Get(name)
		if !ok || !provider.contributionsLoaded() {
			continue
		}
		pub, wd, err := provider.settleDsboot(mpzd.ZoneName, prefix, held.by, byProvider[name], want)
		published, withdrawn = published || pub, withdrawn || wd
		if err != nil {
			errs = append(errs, err)
		}
	}
	switch {
	case published:
		lg.Info("the zone's CDS at the _signal names published", "zone", mpzd.ZoneName)
	case withdrawn && len(want) == 0:
		lg.Info("the zone's CDS at the _signal names withdrawn", "zone", mpzd.ZoneName)
	}
	return errors.Join(errs...)
}

// syncOwedDsbootNames tries again the zones whose last sync failed. The
// combiner's message loop runs it, one at a time with the updates and
// hand-overs that sync too: each brings the names to the apex it reads.
func syncOwedDsbootNames() {
	store := actingHeld.Load()
	for _, zone := range store.zonesOwingDsboot() {
		mpzd, ok := Zones.Get(zone)
		if !ok {
			store.oweDsboot(zone, false)
			continue
		}
		if err := mpzd.syncDsbootNames(); err != nil {
			lgCombiner.Error("the zone's _dsboot names still do not follow it; tried again in a minute", "zone", zone, "err", err)
			continue
		}
		lgCombiner.Info("the zone's _dsboot names follow it again", "zone", zone)
	}
}

// settleDsboot brings one provider zone to what want says for its owners:
// whatever the zone holds under prefix that want does not say, or that its
// allowed-rrtypes no longer allow, goes, from every origin, and what want
// says is held in the name of by. It publishes when anything is wanted or has
// gone: a zone whose names are in place publishes nothing, and one that lost
// them to a failed publish gets them now. So does a withdrawal whose publish
// failed: its contributions are already gone and the publish is all that is
// owed, and the combine has kept the cleanup it could not make.
func (provider *MPZoneData) settleDsboot(zone, prefix, by string, owners []string, want map[string]map[uint16][]dns.RR) (published, withdrawn bool, err error) {
	type contribution struct {
		origin, owner string
		rrtype        uint16
	}
	allowed := GetProviderZoneRRtypes(provider.ZoneName)
	var stale []contribution
	provider.Lock()
	for origin, ownerMap := range provider.MP.AgentContributions {
		for owner, rrtypeMap := range ownerMap {
			if !strings.HasPrefix(owner, prefix) {
				continue
			}
			for rrtype := range rrtypeMap {
				if origin != by || want[owner][rrtype] == nil || !allowed[rrtype] {
					stale = append(stale, contribution{origin, owner, rrtype})
				}
			}
		}
	}
	provider.Unlock()

	var errs []error
	for _, c := range stale {
		_, _, changed, rerr := provider.ReplaceCombinerDataByRRtype(c.origin, c.owner, c.rrtype, nil)
		if rerr != nil {
			errs = append(errs, fmt.Errorf("provider zone %s: retracting %s %s: %w", provider.ZoneName, c.owner, dns.TypeToString[c.rrtype], rerr))
		}
		withdrawn = withdrawn || changed
	}
	wanted := false
	for _, owner := range owners {
		for _, rrtype := range dsbootTypes {
			rrs := want[owner][rrtype]
			if len(rrs) == 0 {
				continue
			}
			if !allowed[rrtype] {
				lgCombiner.Warn("the provider zone's allowed-rrtypes lacks a type of the zone's _dsboot names: it is not published", "zone", zone, "providerzone", provider.ZoneName, "rrtype", dns.TypeToString[rrtype])
				continue
			}
			wanted = true
			_, _, changed, rerr := provider.ReplaceCombinerDataByRRtype(by, owner, rrtype, rrs)
			if rerr != nil {
				errs = append(errs, fmt.Errorf("provider zone %s: publishing %s %s: %w", provider.ZoneName, owner, dns.TypeToString[rrtype], rerr))
			}
			published = published || changed
		}
	}
	if wanted || len(stale) > 0 || provider.MP.cleanupPendingUnder(prefix) {
		if _, cerr := provider.CombineWithLocalChanges(); cerr != nil {
			errs = append(errs, fmt.Errorf("provider zone %s: publishing the _dsboot names of %s: %w", provider.ZoneName, zone, cerr))
		}
	}
	return published, withdrawn, errors.Join(errs...)
}

// serveDsbootNamesAtFirstLoad is a provider zone's first load, for the
// _dsboot names: every customer zone the combiner holds a hand-over for acts,
// as it could not while this zone had not loaded, and what the zone holds of
// them goes into the copy it serves. Its file has none of them. A customer
// zone that has not loaded says nothing either way, and its names are served
// as they were before the restart until it has.
func (mpzd *MPZoneData) serveDsbootNamesAtFirstLoad() {
	for _, zone := range actingHeld.Load().zoneNames() {
		child, ok := Zones.Get(zone)
		if !ok {
			continue
		}
		if err := child.syncDsbootNames(); err != nil {
			lgCombiner.Error("the zone's _dsboot names could not follow the provider zone's first load; tried again every minute", "zone", zone, "providerzone", mpzd.ZoneName, "err", err)
		}
	}
	if !mpzd.holdsDsbootNames() {
		return
	}
	if _, err := mpzd.CombineWithLocalChanges(); err != nil {
		lgCombiner.Error("publishing the _dsboot names at the provider zone's first load failed", "zone", mpzd.ZoneName, "err", err)
	}
}

// holdsDsbootNames: some origin contributes a _dsboot name to this zone.
func (mpzd *MPZoneData) holdsDsbootNames() bool {
	mpzd.Lock()
	defer mpzd.Unlock()
	if mpzd.MP == nil {
		return false
	}
	return slices.ContainsFunc(slices.Collect(maps.Values(mpzd.MP.AgentContributions)), func(owners map[string]map[uint16]core.RRset) bool {
		return slices.ContainsFunc(slices.Collect(maps.Keys(owners)), func(owner string) bool { return strings.HasPrefix(owner, "_dsboot.") })
	})
}
