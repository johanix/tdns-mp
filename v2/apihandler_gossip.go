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
// on the config's AgentRegistry and LeaderElectionManager.
//
// It reads them when a request comes in. The routes are set up before the
// role is started, and the election manager is created at that start: a
// handler given the manager at registration held none for the life of the
// process, and reported the election from the gossip table alone (#154).
func APIgossip(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ar := conf.InternalMp.AgentRegistry
		lem := conf.InternalMp.LeaderElectionManager

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
			// dns.Fqdn("") is ".", so validate the raw value first.
			zone := strings.TrimSpace(gp.Zone)
			if zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}
			zone = dns.Fqdn(zone)
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

// providerGroupForGossipZone finds the provider group serving zone, from the
// group manager only: a row of gossip lists no zone (plan S22), so an agent
// or an auditor that has not loaded the zone finds no group for it.
func providerGroupForGossipZone(ar *AgentRegistry, zone string) (*ProviderGroup, string, error) {
	zone = dns.Fqdn(zone)
	if ar.ProviderGroupManager != nil {
		if pg := ar.ProviderGroupManager.GetGroupForZone(ZoneName(zone)); pg != nil {
			return pg, pg.GroupHash, nil
		}
	}
	return nil, "", fmt.Errorf("no provider group for zone %s", zone)
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
	if ms.BeatInterval > 0 {
		row["beat_interval"] = ms.BeatInterval
	}
	if ms.PropagationDelay > 0 {
		row["propagation_delay"] = ms.PropagationDelay
	}
	if ms.DnssecValidationNotEnforced {
		row["dnssec_validation_not_enforced"] = true
	}
	if len(ms.PeerChains) > 0 {
		row["peer_chains"] = ms.PeerChains
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
