/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * /peer endpoint handler — role-agnostic peer management.
 * Registered on all MP roles. Peer-ping and peer-apiping work on
 * any role with a TransportManager + peer registry; peer-reset
 * depends on IMR-based dynamic discovery (agent-only in practice)
 * and reports a clean error if no IMR is configured.
 */
package tdnsmp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// APIpeer returns the /peer handler. Role-agnostic: depends on the
// TransportManager (for ping/apiping) and the AgentRegistry (for
// peer-reset). The IMR for cache flush is read from
// tdns.Globals.ImrEngine at handler invocation time (not capture
// time) because the IMR starts asynchronously after route setup.
// peer-reset on a role without an IMR or without an AgentRegistry
// returns a clean error; the CLI gates non-agent roles before
// making the RPC call.
func APIpeer(conf *Config, tm *transport.TransportManager, ar *AgentRegistry) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var pp PeerPost
		if err := decoder.Decode(&pp); err != nil {
			lgApi.Warn("error decoding peer command post", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /peer request", "cmd", pp.Command, "from", r.RemoteAddr)

		resp := PeerResponse{
			Time: time.Now(),
		}
		if tm != nil {
			resp.Identity = AgentId(tm.LocalID)
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := tdns.SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				lgApi.Error("json encoder failed", "handler", "peer", "err", err)
			}
		}()

		switch pp.Command {
		case "peer-ping":
			if pp.PeerID == "" {
				resp.Error = true
				resp.ErrorMsg = "peer_id is required for peer-ping"
				return
			}
			pingResp := doPeerPing(conf, string(pp.PeerID), false)
			resp.Error = pingResp.Error
			resp.ErrorMsg = pingResp.ErrorMsg
			resp.Msg = pingResp.Msg

		case "peer-apiping":
			if pp.PeerID == "" {
				resp.Error = true
				resp.ErrorMsg = "peer_id is required for peer-apiping"
				return
			}
			pingResp := doPeerPing(conf, string(pp.PeerID), true)
			resp.Error = pingResp.Error
			resp.ErrorMsg = pingResp.ErrorMsg
			resp.Msg = pingResp.Msg

		case "peer-reset":
			if pp.PeerID == "" {
				resp.Error = true
				resp.ErrorMsg = "peer_id is required for peer-reset"
				return
			}
			peerID := AgentId(dns.Fqdn(string(pp.PeerID)))

			if ar == nil {
				resp.Error = true
				resp.ErrorMsg = "agent registry not available (peer-reset requires dynamic discovery)"
				return
			}

			// Flush IMR cache for this identity's discovery names.
			// Read Globals.ImrEngine lazily: the IMR starts async after
			// route setup, so a captured reference would be nil.
			imr := tdns.Globals.ImrEngine
			flushed := 0
			if imr != nil && imr.Cache != nil {
				removed, _ := imr.Cache.FlushDomain(string(peerID), false)
				flushed = removed
			}

			// Reset agent to NEEDED state and restart discovery
			agent, exists := ar.S.Get(peerID)
			if !exists {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent %q not found in registry", peerID)
				return
			}

			agent.Mu.Lock()
			if agent.ApiDetails != nil {
				agent.ApiDetails.State = AgentStateNeeded
				agent.ApiDetails.DiscoveryFailures = 0
				agent.ApiDetails.LatestError = ""
			}
			if agent.DnsDetails != nil {
				agent.DnsDetails.State = AgentStateNeeded
				agent.DnsDetails.DiscoveryFailures = 0
				agent.DnsDetails.LatestError = ""
			}
			agent.State = AgentStateNeeded
			agent.Mu.Unlock()

			// Trigger immediate re-discovery
			if imr != nil {
				go ar.attemptDiscovery(agent, imr, agent.ApiMethod, agent.DnsMethod)
			}

			resp.Msg = fmt.Sprintf("Reset agent %s to NEEDED state (flushed %d cache entries), discovery restarted", peerID, flushed)

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown peer command: %s", pp.Command)
		}
	}
}

// doPeerPing pings any known peer via DNS CHUNK or API.
// Role-agnostic: works for agent, combiner, signer, or any role
// with a TransportManager. The peer must be in the PeerRegistry
// or have static config (combiner, signer, multi-provider agent).
// useAPI true = HTTPS API ping; false = CHUNK-based DNS ping.
func doPeerPing(conf *Config, peerID string, useAPI bool) *PeerResponse {
	resp := &PeerResponse{
		Time: time.Now(),
	}
	peerID = dns.Fqdn(peerID)

	tm := conf.InternalMp.TransportManager
	if tm == nil {
		resp.Error = true
		resp.ErrorMsg = "TransportManager not configured"
		return resp
	}
	resp.Identity = AgentId(tm.LocalID)

	peer, ok := tm.PeerRegistry.Get(peerID)
	if !ok {
		// Peer not in registry — try static config fallbacks for all roles
		peer = conf.lookupStaticPeer(peerID)
		if peer == nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("peer %q not found in registry (run discovery first)", peerID)
			return resp
		}
	}

	if useAPI {
		if peer.APIEndpoint == "" {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("peer %q has no API endpoint configured", peerID)
			return resp
		}
		url := strings.TrimSuffix(peer.APIEndpoint, "/") + "/ping"
		body := tdns.PingPost{Msg: fmt.Sprintf("peer ping %s", peerID), Pings: 1}
		data, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("build request: %v", err)
			return resp
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		res, err := client.Do(req)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("apiping to %s failed: %v", peerID, err)
			return resp
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("peer %s API returned %d", peerID, res.StatusCode)
			return resp
		}
		var pr tdns.PingResponse
		if err := json.NewDecoder(res.Body).Decode(&pr); err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("decode ping response from %s: %v", peerID, err)
			return resp
		}
		resp.Msg = fmt.Sprintf("ping ok (api transport): %s responded", peerID)
		return resp
	}

	// DNS CHUNK ping
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pingResp, err := tm.SendPing(ctx, peer)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("ping to %s failed: %v", peerID, err)
		return resp
	}
	if !pingResp.OK {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("peer %s did not acknowledge (responder: %s)", peerID, pingResp.ResponderID)
		return resp
	}
	resp.Msg = fmt.Sprintf("ping ok (dns transport): %s echoed nonce %s rtt=%s", pingResp.ResponderID, pingResp.Nonce, pingResp.RTT.Round(time.Microsecond))
	return resp
}

// lookupStaticPeer checks all static peer configurations (agent-side: combiner, signer;
// signer-side: multi-provider.agent) and returns a temporary Peer if found. Returns nil if not found.
func (conf *Config) lookupStaticPeer(peerID string) *transport.Peer {
	mp := conf.Config.MultiProvider
	// Agent-side: combiner
	if mp != nil && mp.Role == "agent" && mp.Combiner != nil &&
		dns.Fqdn(mp.Combiner.Identity) == peerID && mp.Combiner.Address != "" {
		if peer := peerFromAddress(peerID, mp.Combiner.Address); peer != nil {
			if mp.Combiner.ApiBaseUrl != "" {
				peer.APIEndpoint = mp.Combiner.ApiBaseUrl
			}
			return peer
		}
	}

	// Agent-side: signer
	if mp != nil && mp.Role == "agent" && mp.Signer != nil &&
		dns.Fqdn(mp.Signer.Identity) == peerID && mp.Signer.Address != "" {
		return peerFromAddress(peerID, mp.Signer.Address)
	}

	// Signer-side: multi-provider agents
	if mp != nil {
		for _, agentConf := range mp.Agents {
			if agentConf != nil && dns.Fqdn(agentConf.Identity) == peerID && agentConf.Address != "" {
				return peerFromAddress(peerID, agentConf.Address)
			}
		}
	}

	return nil
}

// peerFromAddress creates a temporary transport.Peer from a host:port address string.
func peerFromAddress(peerID string, address string) *transport.Peer {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		lgApi.Warn("invalid address for static peer", "address", address, "peer", peerID, "err", err)
		return nil
	}
	port, err2 := strconv.Atoi(portStr)
	if err2 != nil {
		lgApi.Warn("invalid port in address for static peer", "address", address, "peer", peerID, "err", err2)
		return nil
	}
	peer := transport.NewPeer(peerID)
	peer.SetDiscoveryAddress(&transport.Address{
		Host:      host,
		Port:      uint16(port),
		Transport: "udp",
	})
	return peer
}
