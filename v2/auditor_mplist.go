/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * HSYNCPARAM role snapshots for the auditor web (same data as zone mplist).
 */
package tdnsmp

import (
	"slices"
	"time"

	"github.com/miekg/dns"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

// MPZoneInfoFromMPZoneData extracts HSYNCPARAM role lists from a loaded
// multi-provider zone (same fields as /zone/mplist).
func MPZoneInfoFromMPZoneData(mpzd *MPZoneData) MPZoneInfo {
	info := MPZoneInfo{
		NSmgmt:     "owner",
		ParentSync: "owner",
		Servers:    []string{},
		Signers:    []string{},
		Auditors:   []string{},
	}
	if mpzd == nil {
		return info
	}
	seen := make(map[tdns.ZoneOption]bool)
	for opt, val := range mpzd.Options {
		if val {
			info.Options = append(info.Options, opt)
			seen[opt] = true
		}
	}
	if mpzd.MP != nil && mpzd.MP.MPdata != nil {
		for opt, val := range mpzd.MP.MPdata.Options {
			if val && !seen[opt] {
				info.Options = append(info.Options, opt)
			}
		}
	}
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		return info
	}
	hsyncparamRRset, exists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !exists || len(hsyncparamRRset.RRs) == 0 {
		return info
	}
	prr, ok := hsyncparamRRset.RRs[0].(*dns.PrivateRR)
	if !ok {
		return info
	}
	hp, ok := prr.Data.(*core.HSYNCPARAM)
	if !ok {
		return info
	}
	switch hp.GetNSmgmt() {
	case core.HsyncNSmgmtAGENT:
		info.NSmgmt = "agent"
	default:
		info.NSmgmt = "owner"
	}
	switch hp.GetParentSync() {
	case core.HsyncParentSyncAgent:
		info.ParentSync = "agent"
	default:
		info.ParentSync = "owner"
	}
	info.Servers = hp.GetServers()
	info.Signers = hp.GetSigners()
	info.Auditors = hp.GetAuditors()
	info.Suffix = hp.GetSuffix()
	return info
}

// ZoneMemberRoleDTO is one HSYNC3 label with HSYNCPARAM role flags and
// optional live auditor state.
type ZoneMemberRoleDTO struct {
	Label            string    `json:"label"`
	Identity         string    `json:"identity,omitempty"`
	HSYNC3State      string    `json:"hsync3_state,omitempty"`
	Upstream         string    `json:"upstream,omitempty"`
	Server           bool      `json:"server"`
	Signer           bool      `json:"signer"`
	Auditor          bool      `json:"auditor"`
	Local            bool      `json:"local,omitempty"`
	GossipState      string    `json:"gossip_state,omitempty"`
	LastBeat         time.Time `json:"last_beat,omitempty"`
	LastSync         time.Time `json:"last_sync,omitempty"`
	SecondsSinceBeat int64     `json:"seconds_since_beat,omitempty"`
}

// ZoneMPViewDTO is the zone mplist + per-member role table for the web.
type ZoneMPViewDTO struct {
	Zone       string              `json:"zone"`
	NSmgmt     string              `json:"nsmgmt"`
	ParentSync string              `json:"parentsync"`
	Suffix     string              `json:"suffix,omitempty"`
	Servers    []string            `json:"servers"`
	Signers    []string            `json:"signers"`
	Auditors   []string            `json:"auditors"`
	Options    []string            `json:"options,omitempty"`
	Members    []ZoneMemberRoleDTO `json:"members"`
}

func labelInRoleList(list []string, label string) bool {
	label = normalizeHSYNC3Label(label)
	for _, s := range list {
		if normalizeHSYNC3Label(s) == label {
			return true
		}
	}
	return false
}

func (mpzd *MPZoneData) hsync3RecordsByLabel() map[string]core.HSYNC3 {
	out := make(map[string]core.HSYNC3)
	if mpzd == nil {
		return out
	}
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		return out
	}
	hsync3RRset, exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !exists {
		return out
	}
	for _, rr := range hsync3RRset.RRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok {
			continue
		}
		out[normalizeHSYNC3Label(h3.Label)] = *h3
	}
	return out
}

// declaredRoleLabels returns HSYNCPARAM servers/signers/auditors labels only.
func declaredRoleLabels(info MPZoneInfo) []string {
	seen := make(map[string]bool)
	var out []string
	for _, list := range [][]string{info.Servers, info.Signers, info.Auditors} {
		for _, lbl := range list {
			lbl = normalizeHSYNC3Label(lbl)
			if lbl == "" || seen[lbl] {
				continue
			}
			seen[lbl] = true
			out = append(out, lbl)
		}
	}
	slices.Sort(out)
	return out
}

// zoneGossipMemberIdentities returns FQDN identities for this zone's
// declared roles (HSYNCPARAM), not every HSYNC3 in a shared provider group.
func zoneGossipMemberIdentities(zone string) []string {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return nil
	}
	info := MPZoneInfoFromMPZoneData(mpzd)
	byLabel := mpzd.hsync3IdentitiesByLabel()
	seen := make(map[string]bool)
	var out []string
	for _, lbl := range declaredRoleLabels(info) {
		id := byLabel[lbl]
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// SnapshotZoneMPView builds mplist-style HSYNCPARAM data plus a row per
// member label with server/signer/auditor flags.
func SnapshotZoneMPView(zone string, sm *AuditStateManager, ar *AgentRegistry, localIdentity string) *ZoneMPViewDTO {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return nil
	}
	info := MPZoneInfoFromMPZoneData(mpzd)
	hsync3 := mpzd.hsync3RecordsByLabel()
	byIdentity := mpzd.hsync3IdentitiesByLabel()

	view := &ZoneMPViewDTO{
		Zone:       zone,
		NSmgmt:     info.NSmgmt,
		ParentSync: info.ParentSync,
		Suffix:     info.Suffix,
		Servers:    info.Servers,
		Signers:    info.Signers,
		Auditors:   info.Auditors,
	}
	for _, opt := range info.Options {
		if s, ok := tdns.ZoneOptionToString[opt]; ok {
			view.Options = append(view.Options, s)
		}
	}
	slices.Sort(view.Options)

	now := time.Now()
	var zs *AuditZoneState
	if sm != nil {
		zs = sm.GetZone(zone)
	}
	localIdentity = dns.Fqdn(localIdentity)
	seenIdentity := make(map[string]bool)

	for _, label := range declaredRoleLabels(info) {
		row := ZoneMemberRoleDTO{
			Label:   label,
			Server:  labelInRoleList(info.Servers, label),
			Signer:  labelInRoleList(info.Signers, label),
			Auditor: labelInRoleList(info.Auditors, label),
		}
		if id := byIdentity[label]; id != "" {
			if seenIdentity[id] {
				continue
			}
			seenIdentity[id] = true
			row.Identity = id
		}
		if h3, ok := hsync3[label]; ok {
			row.HSYNC3State = core.HsyncStateToString[h3.State]
			up := normalizeHSYNC3Label(h3.Upstream)
			if up != "" && up != "." {
				row.Upstream = up
			}
		}
		if row.Identity != "" && zs != nil {
			zs.mu.RLock()
			if ps, ok := zs.Providers[row.Identity]; ok {
				row.GossipState = ps.GossipState
				row.LastBeat = ps.LastBeat
				row.LastSync = ps.LastSync
				if ps.IsSigner {
					row.Signer = true
				}
			}
			if as, ok := zs.Auditors[row.Identity]; ok {
				if as.GossipState != "" {
					row.GossipState = as.GossipState
				}
				if as.LastBeat.After(row.LastBeat) {
					row.LastBeat = as.LastBeat
				}
			}
			zs.mu.RUnlock()
			if !row.LastBeat.IsZero() {
				row.SecondsSinceBeat = int64(now.Sub(row.LastBeat).Seconds())
			}
		}
		if row.Identity == localIdentity {
			row.Local = true
			if ar != nil && row.GossipState == "" {
				_, gossip, _ := providerBeatMeta(ar, ZoneName(zone), row.Identity)
				row.GossipState = gossip
			}
		}
		view.Members = append(view.Members, row)
	}
	markLocalMembers(localIdentity, view.Members)
	return view
}

func markLocalMembers(localIdentity string, members []ZoneMemberRoleDTO) {
	localIdentity = dns.Fqdn(localIdentity)
	if localIdentity == "" {
		return
	}
	for i := range members {
		if dns.Fqdn(members[i].Identity) == localIdentity {
			members[i].Local = true
		}
	}
}

// zoneMemberIdentities returns apex HSYNC3 identity FQDNs for zone.
func zoneMemberIdentities(zone string) map[string]bool {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return nil
	}
	ids := make(map[string]bool)
	for _, id := range mpzd.hsync3IdentitiesByLabel() {
		ids[id] = true
	}
	return ids
}
