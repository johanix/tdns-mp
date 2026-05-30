/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"slices"
	"strings"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ParticipantsFromHSYNC3 returns membership-conferring identities for a
// zone, mirroring tdnsmp.zoneParticipants: OFF HSYNC3 records are excluded;
// when hsyncparam is nil every ON identity is returned (legacy fallback);
// otherwise only labels with servers/signers/auditors roles resolve.
func ParticipantsFromHSYNC3(hsyncRRs []dns.RR, hsyncparam *core.HSYNCPARAM) []PeerID {
	if len(hsyncRRs) == 0 {
		return nil
	}

	labelToIdentity := map[string]string{}
	var allIdentities []PeerID
	for _, rr := range hsyncRRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok || h3.State == 0 { // skip OFF (decommissioned)
			continue
		}
		labelToIdentity[strings.TrimSuffix(h3.Label, ".")] = h3.Identity
		allIdentities = append(allIdentities, PeerID(h3.Identity))
	}

	if hsyncparam == nil {
		slices.SortFunc(allIdentities, func(a, b PeerID) int {
			return strings.Compare(string(a), string(b))
		})
		return slices.Compact(allIdentities)
	}

	seen := map[PeerID]bool{}
	var participants []PeerID
	addRole := func(labels []string) {
		for _, label := range labels {
			id, ok := labelToIdentity[strings.TrimSuffix(label, ".")]
			if !ok {
				continue
			}
			pid := PeerID(id)
			if !seen[pid] {
				participants = append(participants, pid)
				seen[pid] = true
			}
		}
	}
	addRole(hsyncparam.GetServers())
	addRole(hsyncparam.GetSigners())
	addRole(hsyncparam.GetAuditors())

	slices.SortFunc(participants, func(a, b PeerID) int {
		return strings.Compare(string(a), string(b))
	})
	return participants
}
