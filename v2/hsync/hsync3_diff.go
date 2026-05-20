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

// ApplyHsyncDiff registers adds and removes for one zone.
// Symmetric with tdnsmp UpdateAgents HSYNC add/remove passes (without RFI side effects).
func (e *Engine) ApplyHsyncDiff(zone ZoneName, diff HsyncDiff) error {
	if e == nil || e.registry == nil {
		return nil
	}
	local := string(e.deps.LocalID)
	updated := make(map[PeerID]bool)
	affected := make(map[PeerID]bool)

	for _, rr := range diff.Adds {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok {
			continue
		}
		id := PeerID(h3.Identity)
		if string(id) == local {
			continue
		}
		updated[id] = true
		affected[id] = true
		e.MarkNeeded(id, zone, nil)
	}

	for _, rr := range diff.Removes {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
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
	return nil
}
