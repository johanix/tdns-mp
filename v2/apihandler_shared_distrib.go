/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Role-independent distrib commands. peer-list, peer-zones and
 * zone-agents are observation commands that work on any role with
 * a TransportManager / AgentRegistry, so we keep their handling
 * in one place and call it from both APIagentDistrib and
 * APIauditorDistrib (and any future role that needs the same
 * observation surface).
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// handleSharedDistribCommand processes the role-independent distrib
// commands (peer-list, peer-zones, zone-agents). Returns true if it
// recognised and handled the command, false otherwise (so the
// role-specific handler can fall through to its own switch). The
// peer-list case writes the response itself (via the underlying
// handler's response shape) and indicates that to the caller via
// the writeHandled return; the other two cases mutate resp and
// rely on the caller's defer to encode it.
//
// `respTime` is the value to use for the "time" field in the
// peer-list response (typically the caller's resp.Time).
func handleSharedDistribCommand(conf *Config, w http.ResponseWriter, command, zoneArg string, respTime time.Time) (handled, writeHandled bool, msg string, data []interface{}, errMsg string, agents []string) {
	switch command {
	case "peer-zones":
		d := listPeerSharedZones(conf)
		return true, false, fmt.Sprintf("Found %d peer(s)", len(d)), d, "", nil

	case "zone-agents":
		if zoneArg == "" {
			return true, false, "", nil, "zone parameter is required", nil
		}
		a := listAgentsForZone(conf, zoneArg)
		var zoneSerial uint32
		if zd, exists := Zones.Get(zoneArg); exists {
			if soa, err := zd.GetSOA(); err == nil {
				zoneSerial = soa.Serial
			}
		}
		return true, false, fmt.Sprintf("Found %d agent(s) for zone %q (serial: %d)", len(a), zoneArg, zoneSerial), nil, "", a

	case "peer-list":
		writePeerListResponse(conf, w, respTime)
		return true, true, "", nil, "", nil
	}
	return false, false, "", nil, "", nil
}

// writePeerListResponse handles peer-list end-to-end: collects
// peers from ListKnownPeers, attaches leader-election state and
// (for agent) parentsync-zone visibility, and writes the JSON
// response. Called only from handleSharedDistribCommand.
func writePeerListResponse(conf *Config, w http.ResponseWriter, respTime time.Time) {
	peers := ListKnownPeers(conf)
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

	// Leader-election status per zone — both active leaders and
	// pending elections (deferred during startup). Visible on any
	// role that has joined gossip.
	var leaderInfo []map[string]interface{}
	if conf.InternalMp.LeaderElectionManager != nil {
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
		for _, zone := range conf.InternalMp.LeaderElectionManager.GetPendingElections() {
			if !activeLeaderZones[string(zone)] {
				leaderInfo = append(leaderInfo, map[string]interface{}{
					"zone":   string(zone),
					"status": "pending",
				})
			}
		}
	}

	// Zones with OptDelSyncChild (parentsync=agent) — empty on
	// auditor; populated on agent. Worth showing both, with the
	// empty-list-on-auditor case being a legitimate (true) answer.
	var parentsyncZones []string
	for _, zn := range Zones.Keys() {
		if zd, ok := Zones.Get(zn); ok && zd.Options[tdns.OptDelSyncChild] {
			parentsyncZones = append(parentsyncZones, zn)
		}
	}

	fullResp := map[string]interface{}{
		"time":             respTime,
		"msg":              fmt.Sprintf("Found %d peer(s) with working keys", len(peers)),
		"error":            false,
		"peers":            peerMaps,
		"leaders":          leaderInfo,
		"parentsync_zones": parentsyncZones,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fullResp)
}
