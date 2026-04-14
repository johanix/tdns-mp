/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Agent distribution management API endpoints
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// Type aliases: AgentDistribPost, DistributionSummary, AgentDistribResponse, PeerInfo
// are defined as aliases in types.go

func (conf *Config) APIagentDistrib(cache *DistributionCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req AgentDistribPost
		err := decoder.Decode(&req)
		if err != nil {
			lgApi.Warn("error decoding request", "handler", "agentDistrib", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /agent/distrib request", "cmd", req.Command, "from", r.RemoteAddr)

		resp := AgentDistribResponse{
			Time: time.Now(),
		}

		handledManually := false
		defer func() {
			if !handledManually {
				w.Header().Set("Content-Type", "application/json")
				sanitizedResp := tdns.SanitizeForJSON(resp)
				err := json.NewEncoder(w).Encode(sanitizedResp)
				if err != nil {
					lgApi.Error("json encode failed", "handler", "agentDistrib", "err", err)
				}
			}
		}()

		switch req.Command {
		case "peer-zones":
			// List shared zones for each peer agent (doesn't need cache)
			data := listPeerSharedZones(conf)
			resp.Msg = fmt.Sprintf("Found %d peer(s)", len(data))
			resp.Data = data
			return

		case "zone-agents":
			// List agents for a specific zone (doesn't need cache)
			zoneName := req.Zone
			if zoneName == "" {
				resp.Error = true
				resp.ErrorMsg = "zone parameter is required"
				return
			}
			agents := listAgentsForZone(conf, zoneName)

			// Get SOA serial for the zone if available
			var zoneSerial uint32
			if zd, exists := Zones.Get(zoneName); exists {
				if soa, err := zd.GetSOA(); err == nil {
					zoneSerial = soa.Serial
				}
			}

			resp.Msg = fmt.Sprintf("Found %d agent(s) for zone %q (serial: %d)", len(agents), zoneName, zoneSerial)
			resp.Agents = agents
			return
		}

		// Commands below this point require cache
		if cache == nil {
			resp.Error = true
			resp.ErrorMsg = "Distribution cache not configured"
			return
		}

		switch req.Command {
		case "list":
			// List all distributions from this agent
			senderID := string(conf.Config.MultiProvider.Identity)
			infos := cache.List(senderID)

			summaries := make([]*DistributionSummary, 0, len(infos))
			distIDs := make([]string, 0, len(infos))

			for _, info := range infos {
				summary := &DistributionSummary{
					DistributionID: info.DistributionID,
					SenderID:       info.SenderID,
					ReceiverID:     info.ReceiverID,
					Operation:      info.Operation,
					ContentType:    info.ContentType,
					State:          info.State,
					PayloadSize:    info.PayloadSize,
					CreatedAt:      info.CreatedAt.Format(time.RFC3339),
				}
				if info.CompletedAt != nil {
					summary.CompletedAt = info.CompletedAt.Format(time.RFC3339)
				}
				summaries = append(summaries, summary)
				distIDs = append(distIDs, info.DistributionID)
			}

			resp.Summaries = summaries
			resp.Distributions = distIDs
			resp.Msg = fmt.Sprintf("Found %d distribution(s)", len(summaries))

		case "purge":
			// Delete distributions
			var deleted int
			if req.Force {
				deleted = cache.PurgeAll()
				resp.Msg = fmt.Sprintf("Purged %d distribution(s) (force mode)", deleted)
			} else {
				// Purge completed distributions older than 5 minutes
				deleted = cache.PurgeCompleted(5 * time.Minute)
				resp.Msg = fmt.Sprintf("Purged %d completed distribution(s)", deleted)
			}

		case "peer-list":
			// List all known peers with working keys
			peers := ListKnownPeers(conf)
			resp.Msg = fmt.Sprintf("Found %d peer(s) with working keys", len(peers))

			// Convert to generic map for JSON serialization
			peerMaps := make([]map[string]interface{}, len(peers))
			for i, peer := range peers {
				peerMaps[i] = map[string]interface{}{
					"peer_id":      peer.PeerID,
					"peer_type":    peer.PeerType,
					"transport":    peer.Transport,
					"address":      peer.Address,
					"crypto_type":  peer.CryptoType,
					"distrib_sent": peer.DistribSent,
				}

				// Add extended discovery information
				if peer.APIUri != "" {
					peerMaps[i]["api_uri"] = peer.APIUri
				}
				if peer.DNSUri != "" {
					peerMaps[i]["dns_uri"] = peer.DNSUri
				}
				if peer.Port > 0 {
					peerMaps[i]["port"] = peer.Port
				}
				if len(peer.Addresses) > 0 {
					peerMaps[i]["addresses"] = peer.Addresses
				}
				if peer.JWKData != "" {
					peerMaps[i]["jwk_data"] = peer.JWKData
					peerMaps[i]["has_jwk"] = true
				} else {
					peerMaps[i]["has_jwk"] = false
				}
				if peer.KeyAlgorithm != "" {
					peerMaps[i]["key_algorithm"] = peer.KeyAlgorithm
				}
				peerMaps[i]["has_key"] = peer.HasKEY
				peerMaps[i]["has_tlsa"] = peer.HasTLSA
				peerMaps[i]["partial"] = peer.Partial
				if peer.State != "" {
					peerMaps[i]["state"] = peer.State
				}
				if peer.ContactInfo != "" {
					peerMaps[i]["contact_info"] = peer.ContactInfo
				}

				if !peer.LastUsed.IsZero() {
					peerMaps[i]["last_used"] = peer.LastUsed.Format(time.RFC3339)
				}
			}

			// Add to response using a generic field
			respMap := tdns.SanitizeForJSON(resp).(AgentDistribResponse)
			w.Header().Set("Content-Type", "application/json")

			// Add leader election status per zone
			var leaderInfo []map[string]interface{}
			if conf.InternalMp.LeaderElectionManager != nil {
				// Active leaders
				activeLeaderZones := make(map[string]bool)
				for _, ls := range conf.InternalMp.LeaderElectionManager.GetAllLeaders() {
					activeLeaderZones[string(ls.Zone)] = true
					leaderInfo = append(leaderInfo, map[string]interface{}{
						"zone":     string(ls.Zone),
						"leader":   string(ls.Leader),
						"is_self":  ls.IsSelf,
						"term":     ls.Term,
						"ttl_secs": int(time.Until(ls.Expiry).Seconds()),
						"status":   "active",
					})
				}

				// Pending elections (deferred during startup)
				for _, zone := range conf.InternalMp.LeaderElectionManager.GetPendingElections() {
					if !activeLeaderZones[string(zone)] {
						leaderInfo = append(leaderInfo, map[string]interface{}{
							"zone":   string(zone),
							"status": "pending",
						})
					}
				}
			}

			// Zones with OptDelSyncChild (parentsync=agent) — for operator visibility
			var parentsyncZones []string
			for _, zn := range Zones.Keys() {
				if zd, ok := Zones.Get(zn); ok && zd.Options[tdns.OptDelSyncChild] {
					parentsyncZones = append(parentsyncZones, zn)
				}
			}

			// Create response with peers field
			fullResp := map[string]interface{}{
				"time":             respMap.Time,
				"msg":              respMap.Msg,
				"error":            respMap.Error,
				"peers":            peerMaps,
				"leaders":          leaderInfo,
				"parentsync_zones": parentsyncZones,
			}
			if respMap.ErrorMsg != "" {
				fullResp["error_msg"] = respMap.ErrorMsg
			}

			handledManually = true
			json.NewEncoder(w).Encode(fullResp)
			return

		case "op":
			// Run operation toward a peer: distrib op {operation} --to {identity}
			if req.Op == "" || req.To == "" {
				resp.Error = true
				resp.ErrorMsg = "op and to are required (e.g. op=ping, to=combiner)"
				return
			}
			toIdentity := strings.TrimSpace(strings.ToLower(req.To))
			opName := strings.TrimSpace(strings.ToLower(req.Op))

			switch opName {
			case "ping":
				if toIdentity == "combiner" {
					useAPI := strings.TrimSpace(strings.ToLower(req.PingTransport)) == "api"
					pingResp := doPeerPing(conf, dns.Fqdn(req.To), useAPI)
					resp.Error = pingResp.Error
					resp.ErrorMsg = pingResp.ErrorMsg
					resp.Msg = pingResp.Msg
				} else {
					// Ping to peer agent: same mechanism as combiner (SendPing); lookup peer by FQDN identity
					if conf.InternalMp.TransportManager == nil {
						resp.Error = true
						resp.ErrorMsg = "TransportManager not configured"
						return
					}
					toFqdn := dns.Fqdn(req.To)
					peer, ok := conf.InternalMp.TransportManager.PeerRegistry.Get(toFqdn)
					if !ok {
						// DNS-42: Authorization check BEFORE discovery
						authorized, reason := conf.InternalMp.MPTransport.IsPeerAuthorized(toFqdn, "")
						if !authorized {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("peer %q is not authorized", req.To)
							lgApi.Warn("rejected discovery for unauthorized agent", "agent", toFqdn, "reason", reason)
							return
						}

						// Attempt dynamic discovery for authorized but unknown agents
						lgApi.Info("agent not in PeerRegistry, attempting discovery", "agent", toFqdn, "reason", reason)
						discoveryCtx, discoveryCancel := context.WithTimeout(r.Context(), 10*time.Second)
						defer discoveryCancel()

						discErr := conf.InternalMp.MPTransport.DiscoverAndRegisterAgent(discoveryCtx, toFqdn)
						if discErr != nil {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("peer %q not found and discovery failed", req.To)
							lgApi.Warn("peer discovery failed", "peer", toFqdn, "err", discErr)
							return
						}

						// Try to get peer again after discovery
						peer, ok = conf.InternalMp.TransportManager.PeerRegistry.Get(toFqdn)
						if !ok {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("peer %q discovered but not registered properly", req.To)
							return
						}
						lgApi.Info("discovered and registered agent", "agent", toFqdn)
					}
					if peer.CurrentAddress() == nil {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("peer %q has no address configured", req.To)
						return
					}
					ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
					defer cancel()
					pingResp, err := conf.InternalMp.TransportManager.SendPing(ctx, peer)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("ping failed: %v", err)
						return
					}
					if !pingResp.OK {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("peer did not acknowledge (responder: %s)", pingResp.ResponderID)
						return
					}
					resp.Msg = fmt.Sprintf("dnsping ok: %s echoed nonce", pingResp.ResponderID)
				}
			default:
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("unknown operation %q (supported: ping)", req.Op)
			}

		case "discover":
			// Discover agent contact information via DNS
			if req.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "agent_id is required for discover command"
				return
			}
			if conf.InternalMp.TransportManager == nil {
				resp.Error = true
				resp.ErrorMsg = "TransportManager not configured"
				return
			}

			agentId := strings.TrimSpace(req.AgentId)
			agentFqdn := dns.Fqdn(agentId)

			// DNS-42: Authorization check BEFORE discovery
			authorized, reason := conf.InternalMp.MPTransport.IsPeerAuthorized(agentFqdn, "")
			if !authorized {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent %q is not authorized", agentId)
				lgApi.Warn("rejected discovery for unauthorized agent", "agent", agentFqdn, "reason", reason)
				return
			}

			lgApi.Info("starting discovery", "agent", agentId, "reason", reason)

			discoveryCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()

			err := conf.InternalMp.MPTransport.DiscoverAndRegisterAgent(discoveryCtx, agentFqdn)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = "discovery failed"
				lgApi.Warn("agent discovery failed", "agent", agentFqdn, "err", err)
				return
			}

			// Get the peer to return discovery information
			peer, ok := conf.InternalMp.TransportManager.PeerRegistry.Get(dns.Fqdn(agentId))
			if !ok {
				resp.Error = true
				resp.ErrorMsg = "agent discovered but not found in registry"
				return
			}

			// Build discovery result for response
			discoveryInfo := map[string]interface{}{
				"identity": peer.ID,
			}
			if peer.APIEndpoint != "" {
				discoveryInfo["api_uri"] = peer.APIEndpoint
			}
			if addr := peer.CurrentAddress(); addr != nil {
				discoveryInfo["host"] = addr.Host
				discoveryInfo["port"] = addr.Port
				discoveryInfo["transport"] = addr.Transport
			}
			discoveryInfo["state"] = peer.GetState().String()
			discoveryInfo["preferred_transport"] = peer.PreferredTransport

			// Return result through handledManually
			respMap := tdns.SanitizeForJSON(resp).(AgentDistribResponse)
			w.Header().Set("Content-Type", "application/json")

			fullResp := map[string]interface{}{
				"time":      respMap.Time,
				"msg":       fmt.Sprintf("Successfully discovered agent %s", agentId),
				"error":     false,
				"discovery": discoveryInfo,
			}

			handledManually = true
			json.NewEncoder(w).Encode(fullResp)
			return

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", req.Command)
		}
	}
}

// ListKnownPeers returns all peers that have working keys established
func ListKnownPeers(conf *Config) []PeerInfo {
	var peers []PeerInfo
	mp := conf.Config.MultiProvider

	// For combiners: list all configured agents
	if mp != nil && len(mp.Agents) > 0 {
		for _, agent := range mp.Agents {
			peerID := agent.Identity
			if peerID == "" {
				peerID = agent.Address
			}
			peerInfo := PeerInfo{
				PeerID:      peerID,
				PeerType:    "agent",
				Transport:   "DNS",
				Address:     agent.Address,
				CryptoType:  "JOSE",
				DistribSent: 0,
			}
			peers = append(peers, peerInfo)
		}
		return peers
	}

	// For agents: list remote agents from AgentRegistry
	seen := make(map[string]bool)
	for _, p := range peers {
		seen[p.PeerID+":"+p.Transport] = true
	}
	if conf.InternalMp.AgentRegistry != nil {
		ar := conf.InternalMp.AgentRegistry

		ar.S.IterCb(func(agentID AgentId, agent *Agent) {
			agentIDFqdn := dns.Fqdn(string(agent.Identity))

			isCombiner := false
			if mp.Combiner != nil && mp.Combiner.Identity != "" {
				isCombiner = string(agent.Identity) == mp.Combiner.Identity ||
					dns.Fqdn(string(agent.Identity)) == dns.Fqdn(mp.Combiner.Identity)
			} else {
				isCombiner = agent.Identity == "combiner"
			}

			isSigner := false
			if mp.Signer != nil && mp.Signer.Identity != "" {
				isSigner = string(agent.Identity) == mp.Signer.Identity ||
					dns.Fqdn(string(agent.Identity)) == dns.Fqdn(mp.Signer.Identity)
			}

			peerType := "agent"
			if isCombiner {
				peerType = "combiner"
			} else if isSigner {
				peerType = "signer"
			}

			// Add API transport entry if available
			if agent.ApiDetails != nil && agent.ApiDetails.BaseUri != "" {
				key := agentIDFqdn + ":API"
				if !seen[key] {
					seen[key] = true

					effectiveState := agent.ApiDetails.State
					if !isCombiner && !isSigner && len(agent.Zones) == 0 && (effectiveState == AgentStateOperational || effectiveState == AgentStateIntroduced || effectiveState == AgentStateKnown) {
						effectiveState = AgentStateLegacy
					}

					peerInfo := PeerInfo{
						PeerID:      agentIDFqdn,
						PeerType:    peerType,
						Transport:   "API",
						Address:     agent.ApiDetails.BaseUri,
						CryptoType:  "TLS",
						DistribSent: 0,
						APIUri:      agent.ApiDetails.BaseUri,
						Port:        agent.ApiDetails.Port,
						Addresses:   agent.ApiDetails.Addrs,
						HasTLSA:     agent.ApiDetails.TlsaRR != nil,
						State:       AgentStateToString[effectiveState],
						ContactInfo: agent.ApiDetails.ContactInfo,
					}
					if !agent.ApiDetails.HelloTime.IsZero() {
						peerInfo.LastUsed = agent.ApiDetails.HelloTime
					}
					if conf.InternalMp.TransportManager != nil {
						if peer, ok := conf.InternalMp.TransportManager.PeerRegistry.Get(agentIDFqdn); ok {
							s := peer.Stats.GetDetailedStats()
							peerInfo.HelloSent = s.HelloSent
							peerInfo.HelloReceived = s.HelloReceived
							peerInfo.BeatSent = s.BeatSent
							peerInfo.BeatReceived = s.BeatReceived
							peerInfo.SyncSent = s.SyncSent
							peerInfo.SyncReceived = s.SyncReceived
							peerInfo.PingSent = s.PingSent
							peerInfo.PingReceived = s.PingReceived
							peerInfo.TotalSent = s.TotalSent
							peerInfo.TotalReceived = s.TotalReceived
							peerInfo.DistribSent = int(s.TotalReceived)
							if !s.LastUsed.IsZero() {
								peerInfo.LastUsed = s.LastUsed
							}
							lgApi.Debug("peer stats", "peer", agentIDFqdn, "lastUsed", s.LastUsed.Format("15:04:05"), "sent", s.TotalSent, "received", s.TotalReceived)
						} else {
							lgApi.Debug("peer not found in PeerRegistry", "peer", agentIDFqdn)
						}
					}
					peers = append(peers, peerInfo)
				}
			}

			// Add DNS transport entry if available
			if agent.DnsDetails != nil && agent.DnsDetails.BaseUri != "" {
				key := agentIDFqdn + ":DNS"
				if !seen[key] {
					seen[key] = true

					effectiveState := agent.DnsDetails.State
					if !isCombiner && !isSigner && len(agent.Zones) == 0 && (effectiveState == AgentStateOperational || effectiveState == AgentStateIntroduced || effectiveState == AgentStateKnown) {
						effectiveState = AgentStateLegacy
					}

					peerInfo := PeerInfo{
						PeerID:       agentIDFqdn,
						PeerType:     peerType,
						Transport:    "DNS",
						Address:      agent.DnsDetails.BaseUri,
						CryptoType:   "JOSE",
						DistribSent:  0,
						DNSUri:       agent.DnsDetails.BaseUri,
						Port:         agent.DnsDetails.Port,
						Addresses:    agent.DnsDetails.Addrs,
						JWKData:      agent.DnsDetails.JWKData,
						KeyAlgorithm: agent.DnsDetails.KeyAlgorithm,
						HasJWK:       agent.DnsDetails.JWKData != "",
						HasKEY:       agent.DnsDetails.KeyRR != nil,
						State:        AgentStateToString[effectiveState],
						ContactInfo:  agent.DnsDetails.ContactInfo,
					}
					if !agent.DnsDetails.HelloTime.IsZero() {
						peerInfo.LastUsed = agent.DnsDetails.HelloTime
					}
					if conf.InternalMp.TransportManager != nil {
						if peer, ok := conf.InternalMp.TransportManager.PeerRegistry.Get(agentIDFqdn); ok {
							s := peer.Stats.GetDetailedStats()
							peerInfo.HelloSent = s.HelloSent
							peerInfo.HelloReceived = s.HelloReceived
							peerInfo.BeatSent = s.BeatSent
							peerInfo.BeatReceived = s.BeatReceived
							peerInfo.SyncSent = s.SyncSent
							peerInfo.SyncReceived = s.SyncReceived
							peerInfo.PingSent = s.PingSent
							peerInfo.PingReceived = s.PingReceived
							peerInfo.TotalSent = s.TotalSent
							peerInfo.TotalReceived = s.TotalReceived
							peerInfo.DistribSent = int(s.TotalReceived)
							if !s.LastUsed.IsZero() {
								peerInfo.LastUsed = s.LastUsed
							}
							lgApi.Debug("peer stats", "peer", agentIDFqdn, "lastUsed", s.LastUsed.Format("15:04:05"), "sent", s.TotalSent, "received", s.TotalReceived)
						} else {
							lgApi.Debug("peer not found in PeerRegistry", "peer", agentIDFqdn)
						}
					}
					peers = append(peers, peerInfo)
				}
			}
		})
	}

	// Add agents from authorized_peers that haven't been discovered yet
	if mp != nil && len(mp.AuthorizedPeers) > 0 {
		for _, peerID := range mp.AuthorizedPeers {
			peerIDFqdn := dns.Fqdn(peerID)

			alreadyListed := false
			for _, p := range peers {
				if p.PeerID == peerIDFqdn {
					alreadyListed = true
					break
				}
			}

			if !alreadyListed {
				peerInfo := PeerInfo{
					PeerID:      peerIDFqdn,
					PeerType:    "agent",
					Transport:   "-",
					Address:     "-",
					CryptoType:  "-",
					State:       "CONFIG",
					ContactInfo: "config only",
					DistribSent: 0,
				}
				if conf.InternalMp.TransportManager != nil {
					if peer, ok := conf.InternalMp.TransportManager.PeerRegistry.Get(peerIDFqdn); ok {
						s := peer.Stats.GetDetailedStats()
						peerInfo.HelloSent = s.HelloSent
						peerInfo.HelloReceived = s.HelloReceived
						peerInfo.BeatSent = s.BeatSent
						peerInfo.BeatReceived = s.BeatReceived
						peerInfo.SyncSent = s.SyncSent
						peerInfo.SyncReceived = s.SyncReceived
						peerInfo.PingSent = s.PingSent
						peerInfo.PingReceived = s.PingReceived
						peerInfo.TotalSent = s.TotalSent
						peerInfo.TotalReceived = s.TotalReceived
						peerInfo.DistribSent = int(s.TotalReceived)
						if !s.LastUsed.IsZero() {
							peerInfo.LastUsed = s.LastUsed
						}
						lgApi.Debug("config-only peer stats", "peer", peerIDFqdn, "lastUsed", s.LastUsed.Format("15:04:05"), "sent", s.TotalSent, "received", s.TotalReceived)
					}
				}
				peers = append(peers, peerInfo)
			}
		}
	}

	// Add all peers from PeerRegistry that we haven't listed yet
	if conf.InternalMp.TransportManager != nil {
		allPeersFromRegistry := conf.InternalMp.TransportManager.PeerRegistry.All()
		for _, peer := range allPeersFromRegistry {
			peerID := peer.ID

			alreadyListed := false
			for _, p := range peers {
				if p.PeerID == peerID {
					alreadyListed = true
					break
				}
			}

			if !alreadyListed {
				s := peer.Stats.GetDetailedStats()

				state := "UNKNOWN"
				if s.TotalReceived > 0 || s.TotalSent > 0 {
					if s.BeatReceived > 0 || s.BeatSent > 0 {
						state = "CONTACTED"
					} else if s.HelloReceived > 0 || s.HelloSent > 0 {
						state = "HELLO"
					} else {
						state = "CONTACTED"
					}
				}

				peerInfo := PeerInfo{
					PeerID:        peerID,
					PeerType:      "agent",
					Transport:     "-",
					Address:       "-",
					CryptoType:    "-",
					State:         state,
					ContactInfo:   "peer registry only",
					HelloSent:     s.HelloSent,
					HelloReceived: s.HelloReceived,
					BeatSent:      s.BeatSent,
					BeatReceived:  s.BeatReceived,
					SyncSent:      s.SyncSent,
					SyncReceived:  s.SyncReceived,
					PingSent:      s.PingSent,
					PingReceived:  s.PingReceived,
					TotalSent:     s.TotalSent,
					TotalReceived: s.TotalReceived,
					DistribSent:   int(s.TotalReceived),
				}
				if !s.LastUsed.IsZero() {
					peerInfo.LastUsed = s.LastUsed
				}

				peers = append(peers, peerInfo)
				lgApi.Debug("added peer from PeerRegistry only", "peer", peerID, "state", state, "sent", s.TotalSent, "received", s.TotalReceived)
			}
		}
	}

	return peers
}

// listPeerSharedZones returns shared zones for each peer agent
func listPeerSharedZones(conf *Config) []interface{} {
	data := make([]interface{}, 0)
	mp := conf.Config.MultiProvider

	if conf.InternalMp.AgentRegistry == nil {
		return data
	}

	conf.InternalMp.AgentRegistry.S.IterCb(func(agentID AgentId, agent *Agent) {
		agent.Mu.RLock()
		identity := agent.Identity
		state := agent.State

		// Skip combiner
		if mp != nil && mp.Combiner != nil {
			combinerID := mp.Combiner.Identity
			if combinerID == "" {
				combinerID = "combiner"
			}
			if dns.Fqdn(string(identity)) == dns.Fqdn(combinerID) {
				agent.Mu.RUnlock()
				return
			}
		}

		zoneNames := make([]ZoneName, 0, len(agent.Zones))
		for zoneName := range agent.Zones {
			zoneNames = append(zoneNames, zoneName)
		}
		agent.Mu.RUnlock()

		zoneDetails := make([]map[string]interface{}, 0, len(zoneNames))
		for _, zoneName := range zoneNames {
			zoneInfo := map[string]interface{}{
				"name": string(zoneName),
			}

			if zd, exists := Zones.Get(string(zoneName)); exists {
				if soa, err := zd.GetSOA(); err == nil {
					zoneInfo["serial"] = soa.Serial
				}
			}

			zoneDetails = append(zoneDetails, zoneInfo)
		}

		entry := map[string]interface{}{
			"peer_id": string(identity),
			"zones":   zoneDetails,
			"state":   AgentStateToString[state],
		}
		data = append(data, entry)
	})

	return data
}

// listAgentsForZone returns peer agents that share a specific zone
func listAgentsForZone(conf *Config, zoneName string) []string {
	agents := make([]string, 0)
	mp := conf.Config.MultiProvider

	if conf.InternalMp.AgentRegistry == nil {
		return agents
	}

	conf.InternalMp.AgentRegistry.S.IterCb(func(agentID AgentId, agent *Agent) {
		agent.Mu.RLock()
		hasZone := agent.Zones[ZoneName(zoneName)]
		identity := agent.Identity
		agent.Mu.RUnlock()

		// Skip combiner
		if mp != nil && mp.Combiner != nil {
			combinerID := mp.Combiner.Identity
			if combinerID == "" {
				combinerID = "combiner"
			}
			if dns.Fqdn(string(identity)) == dns.Fqdn(combinerID) {
				return
			}
		}

		if hasZone {
			agents = append(agents, string(identity))
		}
	})

	return agents
}
