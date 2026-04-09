/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Signer API route registration for tdns-mp.
 * Registers /signer and /signer/distrib endpoints.
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// SetupMPSignerRoutes registers signer-specific API routes on
// the existing API router. Called from StartMPSigner.
func (conf *Config) SetupMPSignerRoutes(ctx context.Context, apirouter *mux.Router) {
	kdb := conf.Config.Internal.KeyDB
	sr := apirouter.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/signer", conf.APImpSigner()).Methods("POST")
	sr.HandleFunc("/gossip", APIgossip(conf.InternalMp.AgentRegistry, conf.InternalMp.LeaderElectionManager)).Methods("POST")
	sr.HandleFunc("/router", APIrouter(conf.InternalMp.TransportManager)).Methods("POST")
	sr.HandleFunc("/peer", APIpeer(conf, conf.InternalMp.TransportManager, conf.InternalMp.AgentRegistry)).Methods("POST")
	sr.HandleFunc("/zone/mplist", conf.APImplist()).Methods("POST")
	sr.HandleFunc("/signer/distrib", conf.APIsingerDistrib()).Methods("POST")
	sr.HandleFunc("/keystore", kdb.APIkeystore(conf.Config)).Methods("POST")
	sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
	sr.HandleFunc("/zone/dsync", tdns.APIzoneDsync(ctx, &tdns.Globals.App, conf.Config.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/delegation", tdns.APIdelegation(conf.Config.Internal.DelegationSyncQ)).Methods("POST")
}

// APIsingerDistrib handles /signer/distrib — peer listing for the signer.
func (conf *Config) APIsingerDistrib() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req struct {
			Command string `json:"command"`
		}
		if err := decoder.Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"time":      time.Now(),
				"error":     true,
				"error_msg": fmt.Sprintf("error decoding request: %v", err),
			})
			return
		}

		switch req.Command {
		case "peer-list":
			tm := conf.InternalMp.TransportManager
			if tm == nil {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"time":      time.Now(),
					"error":     true,
					"error_msg": "multi-provider not active",
				})
				return
			}

			allPeers := tm.PeerRegistry.All()
			peerMaps := make([]map[string]interface{}, len(allPeers))
			for i, peer := range allPeers {
				peerMaps[i] = map[string]interface{}{
					"peer_id":     dns.Fqdn(peer.ID),
					"peer_type":   "agent",
					"transport":   "DNS",
					"crypto_type": "JOSE",
					"state":       peer.GetState().String(),
				}
				if addr := peer.CurrentAddress(); addr != nil {
					peerMaps[i]["address"] = fmt.Sprintf("dns://%s:%d/", addr.Host, addr.Port)
					peerMaps[i]["dns_uri"] = fmt.Sprintf("dns://%s:%d/", addr.Host, addr.Port)
					peerMaps[i]["port"] = addr.Port
					peerMaps[i]["addresses"] = []string{addr.Host}
				}
				s := peer.Stats.GetDetailedStats()
				peerMaps[i]["distrib_sent"] = int(s.TotalSent)
				peerMaps[i]["total_sent"] = s.TotalSent
				peerMaps[i]["total_received"] = s.TotalReceived
				if !s.LastUsed.IsZero() {
					peerMaps[i]["last_used"] = s.LastUsed.Format(time.RFC3339)
				}
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"time":  time.Now(),
				"msg":   fmt.Sprintf("Found %d peer(s) with working keys", len(allPeers)),
				"error": false,
				"peers": peerMaps,
			})

		default:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"time":      time.Now(),
				"error":     true,
				"error_msg": fmt.Sprintf("unknown signer distrib command: %q", req.Command),
			})
		}
	}
}
