/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * /agent/hsync handler — HSYNC state-reporting commands.
 * Migrated out of /agent (APIagent) in tdns-mp/v2/apihandler_agent.go.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// APIagentHsync handles /agent/hsync requests. The 6 supported
// commands are: hsync-zonestatus, hsync-peer-status, hsync-sync-ops,
// hsync-confirmations, hsync-transport-events, hsync-metrics.
func (conf *Config) APIagentHsync(hdb *HsyncDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var amp AgentMgmtPost
		err := decoder.Decode(&amp)
		if err != nil {
			lgApi.Warn("error decoding agent/hsync command post", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /agent/hsync request", "cmd", amp.Command, "from", r.RemoteAddr)

		resp := AgentMgmtResponse{
			Time:     time.Now(),
			Identity: AgentId(conf.Config.MultiProvider.Identity),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := tdns.SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				lgApi.Error("json encoder failed", "err", err)
			}
		}()

		switch amp.Command {
		case "hsync-zonestatus":
			amp.Zone = ZoneName(dns.Fqdn(string(amp.Zone)))
			zd, exist := Zones.Get(string(amp.Zone))
			if !exist {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", amp.Zone)
				return
			}

			owner, err := zd.GetOwner(zd.ZoneName)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone %s error: %v", amp.Zone, err)
				return
			}

			hsyncRRset := owner.RRtypes.GetOnlyRRSet(core.TypeHSYNC3)
			if len(hsyncRRset.RRs) == 0 {
				resp.Msg = fmt.Sprintf("Zone %s has no HSYNC3 RRset", amp.Zone)
				return
			}

			hsyncStrs := make([]string, len(hsyncRRset.RRs))
			for i, rr := range hsyncRRset.RRs {
				hsyncStrs[i] = rr.String()
			}
			resp.HsyncRRs = hsyncStrs

			resp.ZoneAgentData, err = conf.InternalMp.AgentRegistry.GetZoneAgentData(amp.Zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error getting remote agents: %v", err)
				return
			}
			resp.Msg = fmt.Sprintf("HSYNC RRset and agents for zone %s", amp.Zone)

		case "hsync-peer-status":
			if hdb == nil {
				resp.Error = true
				resp.ErrorMsg = "HsyncDB not configured"
				return
			}

			state := ""
			if amp.AgentId != "" {
				peer, err := hdb.GetPeer(string(amp.AgentId))
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("error getting peer: %v", err)
					return
				}
				if peer != nil {
					resp.HsyncPeers = []*HsyncPeerInfo{PeerRecordToInfo(peer)}
				}
			} else {
				peers, err := hdb.ListPeers(state)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("error listing peers: %v", err)
					return
				}
				for _, peer := range peers {
					resp.HsyncPeers = append(resp.HsyncPeers, PeerRecordToInfo(peer))
				}
			}
			resp.Msg = fmt.Sprintf("Found %d peers", len(resp.HsyncPeers))

		case "hsync-sync-ops":
			if hdb == nil {
				resp.Error = true
				resp.ErrorMsg = "HsyncDB not configured"
				return
			}

			ops, err := hdb.ListSyncOperations(dns.Fqdn(string(amp.Zone)), 50)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error listing sync operations: %v", err)
				return
			}
			for _, op := range ops {
				resp.HsyncSyncOps = append(resp.HsyncSyncOps, SyncOpRecordToInfo(op))
			}
			resp.Msg = fmt.Sprintf("Found %d sync operations", len(resp.HsyncSyncOps))

		case "hsync-confirmations":
			if hdb == nil {
				resp.Error = true
				resp.ErrorMsg = "HsyncDB not configured"
				return
			}

			confs, err := hdb.ListSyncConfirmations("", 50)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error listing confirmations: %v", err)
				return
			}
			for _, c := range confs {
				resp.HsyncConfirmations = append(resp.HsyncConfirmations, ConfirmRecordToInfo(c))
			}
			resp.Msg = fmt.Sprintf("Found %d confirmations", len(resp.HsyncConfirmations))

		case "hsync-transport-events":
			if hdb == nil {
				resp.Error = true
				resp.ErrorMsg = "HsyncDB not configured"
				return
			}

			limit := 100
			if v, ok := amp.Data["limit"]; ok {
				if f, ok := v.(float64); ok {
					limit = int(f)
				}
			}
			events, err := hdb.ListTransportEvents(string(amp.AgentId), limit)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error listing transport events: %v", err)
				return
			}
			resp.HsyncEvents = events
			resp.Msg = fmt.Sprintf("Found %d transport events", len(resp.HsyncEvents))

		case "hsync-metrics":
			if hdb == nil {
				resp.Error = true
				resp.ErrorMsg = "HsyncDB not configured"
				return
			}

			metrics, err := hdb.GetAggregatedMetrics()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error getting metrics: %v", err)
				return
			}
			resp.HsyncMetrics = metrics
			resp.Msg = "Aggregated metrics"

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("unknown hsync command: %q", amp.Command)
		}
	}
}
