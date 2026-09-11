/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// IdentitiesFromRRset returns remote HSYNC3 identities, excluding localIdentity.
func IdentitiesFromRRset(rrs []dns.RR, localIdentity string) map[PeerID]struct{} {
	out := make(map[PeerID]struct{})
	for _, rr := range rrs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok || h3.Identity == "" {
			continue
		}
		if localIdentity != "" && h3.Identity == localIdentity {
			continue
		}
		out[PeerID(h3.Identity)] = struct{}{}
	}
	return out
}

// HsyncDiff carries incremental HSYNC3 changes from zone refresh.
type HsyncDiff struct {
	Adds    []dns.RR
	Removes []dns.RR
}

// hsync3Of extracts the HSYNC3 payload from an RR, if present.
func hsync3Of(rr dns.RR) (*core.HSYNC3, bool) {
	prr, ok := rr.(*dns.PrivateRR)
	if !ok {
		return nil, false
	}
	h3, ok := prr.Data.(*core.HSYNC3)
	return h3, ok
}

// localInHsync3 reports whether local appears in the zone view's current HSYNC3
// RRset (raw co-presence, no role filter — mirrors the legacy weAreInHSYNC check).
func localInHsync3(zv ZoneView, local string) bool {
	if zv == nil || local == "" {
		return false
	}
	for _, rr := range zv.HSYNC3() {
		if h3, ok := hsync3Of(rr); ok && h3.Identity == local {
			return true
		}
	}
	return false
}

// ApplyHsyncDiff registers adds and removes for one zone.
// Symmetric with tdnsmp UpdateAgents HSYNC add/remove passes; the agent re-homes
// the RFI/election side effects via Host.OnHsyncMembersAdded.
func (e *Engine) ApplyHsyncDiff(zone ZoneName, diff HsyncDiff) error {
	if e == nil || e.registry == nil {
		return nil
	}
	local := string(e.deps.LocalID)
	updated := make(map[PeerID]bool)
	affected := make(map[PeerID]bool)

	// Membership is HSYNCPARAM-derived: an HSYNC3 add for an identity with no
	// HSYNCPARAM role must not register a member. The participant set comes from
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

	// Agent-only pre-diff guard: mirror the legacy weAreInHSYNC abort. When the
	// local identity is absent from the zone's current HSYNC3 RRset, skip remote
	// add/remove processing and the group recompute. An explicit local-remove RR
	// still fires OnLocalRemoved so the one-time teardown hook runs.
	if e.deps.GateOnLocalPresence && !localInHsync3(zv, local) {
		for _, rr := range diff.Removes {
			if h3, ok := hsync3Of(rr); ok && h3.Identity == local {
				if e.deps.Host.OnLocalRemoved != nil {
					e.deps.Host.OnLocalRemoved(zone)
				}
				break
			}
		}
		return nil
	}

	localAdded := false
	for _, rr := range diff.Adds {
		h3, ok := hsync3Of(rr)
		if !ok {
			continue
		}
		id := PeerID(h3.Identity)
		if string(id) == local {
			localAdded = true
			continue
		}
		if members == nil {
			continue // zone view unavailable — fail closed
		}
		if _, isMember := members[id]; !isMember {
			continue // HSYNC3 record without a HSYNCPARAM role — not a member
		}
		updated[id] = true
		affected[id] = true
		e.MarkNeeded(id, zone, nil)
	}

	for _, rr := range diff.Removes {
		h3, ok := hsync3Of(rr)
		if !ok {
			continue
		}
		id := PeerID(h3.Identity)
		affected[id] = true
		if updated[id] {
			continue
		}
		if string(id) == local {
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

	if (len(updated) > 0 || localAdded) && e.deps.Host.OnHsyncMembersAdded != nil {
		added := make([]PeerID, 0, len(updated))
		for id := range updated {
			added = append(added, id)
		}
		e.deps.Host.OnHsyncMembersAdded(zone, added, localAdded)
	}
	return nil
}
