/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"slices"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// HsyncDiff carries the identities whose ON HSYNC3 records entered or left
// a zone's active instructions when they changed (tdns-mp's plan S3, the
// hook at activation): from the two active readings, not from the records.
type HsyncDiff struct {
	Entered []PeerID
	Left    []PeerID
}

// participates reports whether id has standing in the zone that admission
// lets in. Until the switch that standing is a role, as the zone's
// participants have it: an ON record whose label HSYNCPARAM lists in
// servers=, signers= or auditors=, or any ON record in a zone with no
// HSYNCPARAM (decision 31). ReconcileZone and ApplyHsyncDiff's gate ask it
// of the local identity, so an agent reads alike in both. Identities are
// compared as canonical names: the auditor's engine is built before its
// identity gets its trailing dot.
func participates(zv ZoneView, id PeerID) bool {
	if zv == nil || id == "" {
		return false
	}
	return slices.ContainsFunc(zv.Participants(), func(p PeerID) bool { return samePeer(p, id) })
}

// samePeer reports whether two identities name the same peer: equal as
// canonical names (lower case, with the trailing dot).
func samePeer(a, b PeerID) bool {
	return core.EqualNames(dns.Fqdn(string(a)), dns.Fqdn(string(b)))
}

// isLocal: id names the local agent. An engine with no local identity has
// none. Compared as canonical names: a local identity configured without
// the trailing dot, or in another case, is the zone's record of it.
func isLocal(local, id PeerID) bool {
	return local != "" && samePeer(id, local)
}

// ApplyHsyncDiff registers the identities that entered and left one zone,
// and recomputes the provider groups (Host.OnHsync3Changed). The agent checks the zone's
// election after it returns (zoneChanged, step 8).
func (e *Engine) ApplyHsyncDiff(zone ZoneName, diff HsyncDiff) error {
	if e == nil || e.registry == nil {
		return nil
	}
	local := string(e.deps.LocalID)
	updated := make(map[PeerID]bool)
	affected := make(map[PeerID]bool)

	// Membership is role-derived: an identity that entered with no role must
	// not register a member. The participant set comes from
	// the zone view; if the view is unavailable (members==nil) adds fail closed
	// (skipped) — the periodic ReconcileZone remains authoritative.
	var members map[PeerID]struct{}
	var zv ZoneView
	if e.deps.Zones != nil {
		if got, ok := e.deps.Zones.Get(string(zone)); ok && got != nil {
			zv = got
			members = make(map[PeerID]struct{})
			for _, id := range zv.Participants() {
				members[id] = struct{}{}
			}
		}
	}

	// Pre-diff guard: in a zone where the local identity has no standing
	// (participates), skip remote add/remove processing; ReconcileZone
	// expects no peers there either. The local identity among those that left
	// still fires OnLocalRemoved so the one-time teardown hook runs.
	//
	// The provider groups are recomputed on this path too. They are made from
	// the zones' records whoever is in them, and this path used to return
	// before the recompute: an agent whose role and HSYNC3 record the owner
	// removed in one edit kept the zone in the group it had been in, and went
	// on answering that it led the zone if it led that group, until a change
	// in some other zone recomputed the groups (tdns-mp #183).
	if e.deps.GateOnLocalPresence && !participates(zv, PeerID(local)) {
		for _, id := range diff.Left {
			if isLocal(PeerID(local), id) {
				if e.deps.Host.OnLocalRemoved != nil {
					e.deps.Host.OnLocalRemoved(zone)
				}
				break
			}
		}
		if e.deps.Host.OnHsync3Changed != nil {
			e.deps.Host.OnHsync3Changed(zone)
		}
		return nil
	}

	for _, id := range diff.Entered {
		if isLocal(PeerID(local), id) {
			continue
		}
		if members == nil {
			continue // zone view unavailable — fail closed
		}
		if _, isMember := members[id]; !isMember {
			continue // an ON record without a role — not a member
		}
		updated[id] = true
		affected[id] = true
		e.MarkNeeded(id, zone, nil)
	}

	for _, id := range diff.Left {
		affected[id] = true
		if updated[id] {
			continue
		}
		if isLocal(PeerID(local), id) {
			if e.deps.Host.OnLocalRemoved != nil {
				e.deps.Host.OnLocalRemoved(zone)
			}
			continue
		}
		e.registry.RemovePeerFromZone(zone, id)
	}

	for id := range affected {
		if peer, ok := e.registry.S.Get(id); ok {
			e.registry.RecomputeSharedZones(peer)
		}
	}

	if e.deps.Host.OnHsync3Changed != nil {
		e.deps.Host.OnHsync3Changed(zone)
	}
	return nil
}
