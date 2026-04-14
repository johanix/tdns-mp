/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * /gossip endpoint handler — role-agnostic gossip introspection.
 * Registered on all MP roles. Commands operate on whatever
 * AgentRegistry / LeaderElectionManager state exists; a role
 * without a ProviderGroupManager returns an empty list for
 * gossip-group-list and an honest error for gossip-group-state.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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
		case "gossip-group-state":
			if ar == nil || ar.GossipStateTable == nil || ar.ProviderGroupManager == nil {
				resp.Error = true
				resp.ErrorMsg = "gossip state table not available"
				return
			}

			groupName := gp.GroupName
			if groupName == "" {
				resp.Error = true
				resp.ErrorMsg = "group name or hash is required"
				return
			}

			// Look up group by name first, then by hash
			pg := ar.ProviderGroupManager.GetGroupByName(groupName)
			if pg == nil {
				pg = ar.ProviderGroupManager.GetGroup(groupName)
			}
			if pg == nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("provider group %q not found", groupName)
				return
			}

			states, election, nameProposal := ar.GossipStateTable.GetGroupState(pg.GroupHash)

			// Build matrix data
			var matrix []map[string]interface{}
			for _, member := range pg.Members {
				row := map[string]interface{}{
					"reporter": member,
				}
				if ms, ok := states[member]; ok {
					row["peer_states"] = ms.PeerStates
					row["timestamp"] = ms.Timestamp.Format(time.RFC3339)
					row["age"] = time.Since(ms.Timestamp).Truncate(time.Second).String()
					row["zones"] = len(ms.Zones)
				} else {
					row["peer_states"] = map[string]string{}
					row["age"] = "unknown"
				}
				matrix = append(matrix, row)
			}

			result := map[string]interface{}{
				"group_hash": pg.GroupHash,
				"group_name": pg.Name,
				"members":    pg.Members,
				"matrix":     matrix,
			}

			// Always include election block with status.
			// LEM is authoritative; gossip table is fallback.
			electionData := map[string]interface{}{}
			var es GroupElectionState
			if lem != nil {
				es = lem.GetGroupElectionState(pg.GroupHash)
			}
			if es.Term == 0 && election != nil {
				es = *election
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
			result["election"] = electionData

			if nameProposal != nil {
				result["name_proposal"] = map[string]interface{}{
					"name":        nameProposal.Name,
					"proposer":    nameProposal.Proposer,
					"proposed_at": nameProposal.ProposedAt.Format(time.RFC3339),
				}
			}

			resp.Data = result
			resp.Msg = fmt.Sprintf("Gossip state for group %s (%s)", pg.Name, pg.GroupHash[:8])

		case "gossip-group-list":
			if ar == nil || ar.ProviderGroupManager == nil {
				// Role without a ProviderGroupManager — honest empty response.
				resp.Data = []map[string]interface{}{}
				resp.Msg = "Found 0 provider groups"
				return
			}
			groups := ar.ProviderGroupManager.GetGroups()
			var groupData []map[string]interface{}
			for _, pg := range groups {
				// Show first 5 zones as sample
				sampleZones := make([]string, 0)
				for i, z := range pg.Zones {
					if i >= 5 {
						break
					}
					sampleZones = append(sampleZones, string(z))
				}
				entry := map[string]interface{}{
					"group_hash":   pg.GroupHash,
					"name":         pg.Name,
					"members":      pg.Members,
					"zone_count":   len(pg.Zones),
					"sample_zones": sampleZones,
				}
				if pg.NameProposal != nil {
					entry["name_proposal"] = map[string]interface{}{
						"name":        pg.NameProposal.Name,
						"proposer":    pg.NameProposal.Proposer,
						"proposed_at": pg.NameProposal.ProposedAt.Format(time.RFC3339),
					}
				}
				groupData = append(groupData, entry)
			}
			resp.Data = groupData
			resp.Msg = fmt.Sprintf("Found %d provider groups", len(groups))

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown gossip command: %s", gp.Command)
		}
	}
}
