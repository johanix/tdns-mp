/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * /gossip endpoint handler — role-agnostic gossip introspection.
 * Registered on all MP roles. Zone-centric: gossip-zone-state
 * resolves the provider group for a zone and returns its matrix.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	tdns "github.com/johanix/tdns/v2"
)

// APIgossip returns the /gossip handler. Role-agnostic: depends only
// on the AgentRegistry and LeaderElectionManager passed in.
func APIgossip(ar *AgentRegistry, lem *LeaderElectionManager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var gp GossipPost
		if err := decoder.Decode(&gp); err != nil {
			lgApi.Warn("error decoding gossip command post", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /gossip request", "cmd", gp.Command, "from", r.RemoteAddr)

		resp := GossipResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := tdns.SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				lgApi.Error("json encoder failed", "handler", "gossip", "err", err)
			}
		}()

		switch gp.Command {
		case "gossip-zone-state":
			if ar == nil || ar.GossipStateTable == nil {
				resp.Error = true
				resp.ErrorMsg = "gossip state table not available"
				return
			}
			zone := dns.Fqdn(gp.Zone)
			if zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}
			pg, groupHash, err := providerGroupForGossipZone(ar, zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}

			states, election, nameProposal := ar.GossipStateTable.GetGroupState(groupHash)
			members := unionGossipMembers(pg.Members, states)
			matrix := buildGossipMatrixRows(members, states)

			result := map[string]interface{}{
				"zone":    zone,
				"members": members,
				"matrix":  matrix,
			}

			electionData := buildGossipElectionData(lem, groupHash, election)
			result["election"] = electionData

			if nameProposal != nil {
				result["name_proposal"] = map[string]interface{}{
					"name":        nameProposal.Name,
					"proposer":    nameProposal.Proposer,
					"proposed_at": nameProposal.ProposedAt.Format(time.RFC3339),
				}
			}

			resp.Data = result
			resp.Msg = fmt.Sprintf("Gossip state for zone %s", zone)

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown gossip command: %s", gp.Command)
		}
	}
}

// providerGroupForGossipZone finds the provider group serving zone.
// Prefer ProviderGroupManager; fall back to gossip state when PGM
// has not been populated yet (common on auditors).
func providerGroupForGossipZone(ar *AgentRegistry, zone string) (*ProviderGroup, string, error) {
	zone = dns.Fqdn(zone)
	zn := ZoneName(zone)
	if ar.ProviderGroupManager != nil {
		if pg := ar.ProviderGroupManager.GetGroupForZone(zn); pg != nil {
			return pg, pg.GroupHash, nil
		}
	}
	if ar.GossipStateTable == nil {
		return nil, "", fmt.Errorf("no provider group for zone %s", zone)
	}
	ar.GossipStateTable.mu.RLock()
	defer ar.GossipStateTable.mu.RUnlock()
	for hash, states := range ar.GossipStateTable.States {
		for _, ms := range states {
			for _, z := range ms.Zones {
				if dns.Fqdn(z) == zone {
					return providerGroupFromGossipState(hash, states, ar.GossipStateTable.Names[hash]), hash, nil
				}
			}
		}
	}
	return nil, "", fmt.Errorf("no provider group for zone %s", zone)
}

func providerGroupFromGossipState(hash string, states map[string]*MemberState, nameProposal *GroupNameProposal) *ProviderGroup {
	members := make([]string, 0, len(states))
	zoneSet := make(map[ZoneName]bool)
	for id, ms := range states {
		members = append(members, id)
		if ms != nil {
			for _, z := range ms.Zones {
				zoneSet[ZoneName(dns.Fqdn(z))] = true
			}
		}
	}
	slices.Sort(members)
	zones := make([]ZoneName, 0, len(zoneSet))
	for z := range zoneSet {
		zones = append(zones, z)
	}
	slices.Sort(zones)
	pg := &ProviderGroup{
		GroupHash: hash,
		Members:   members,
		Zones:     zones,
	}
	if nameProposal != nil {
		pg.Name = nameProposal.Name
		pg.NameProposal = nameProposal
	}
	return pg
}

func buildGossipMatrixRows(members []string, states map[string]*MemberState) []map[string]interface{} {
	reported := make(map[string]bool, len(states))
	var matrix []map[string]interface{}
	for reporter, ms := range states {
		reported[reporter] = true
		matrix = append(matrix, gossipMatrixRow(reporter, ms))
	}
	for _, member := range members {
		if reported[member] {
			continue
		}
		matrix = append(matrix, gossipMatrixRow(member, nil))
	}
	slices.SortFunc(matrix, func(a, b map[string]interface{}) int {
		ra, _ := a["reporter"].(string)
		rb, _ := b["reporter"].(string)
		return strings.Compare(ra, rb)
	})
	return matrix
}

func gossipMatrixRow(reporter string, ms *MemberState) map[string]interface{} {
	row := map[string]interface{}{
		"reporter": reporter,
	}
	if ms == nil {
		row["peer_states"] = map[string]string{}
		row["age"] = "unknown"
		return row
	}
	row["peer_states"] = ms.PeerStates
	row["timestamp"] = ms.Timestamp.Format(time.RFC3339)
	row["age"] = time.Since(ms.Timestamp).Truncate(time.Second).String()
	row["zones"] = len(ms.Zones)
	if ms.BeatInterval > 0 {
		row["beat_interval"] = ms.BeatInterval
	}
	return row
}

func buildGossipElectionData(lem *LeaderElectionManager, groupHash string, gossipElection *GroupElectionState) map[string]interface{} {
	electionData := map[string]interface{}{}
	var es GroupElectionState
	if lem != nil {
		es = lem.GetGroupElectionState(groupHash)
	}
	if es.Term == 0 && gossipElection != nil {
		es = *gossipElection
	}
	if es.Term == 0 {
		electionData["status"] = "no_election"
	} else if es.Leader == "" {
		electionData["status"] = "invalidated"
		electionData["term"] = es.Term
	} else if time.Now().After(es.LeaderExpiry) {
		electionData["status"] = "expired"
		electionData["leader"] = es.Leader
		electionData["term"] = es.Term
	} else {
		electionData["status"] = "active"
		electionData["leader"] = es.Leader
		electionData["term"] = es.Term
		electionData["leader_expiry"] = es.LeaderExpiry.Format(time.RFC3339)
		electionData["expires_in"] = time.Until(es.LeaderExpiry).Truncate(time.Second).String()
	}
	return electionData
}
