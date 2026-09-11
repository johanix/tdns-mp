/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor distrib endpoint. Dispatches the role-independent commands
 * (peer-list, peer-zones, zone-agents) via the shared helper, plus the
 * cache-backed list/purge commands for inspecting the auditor's own
 * distributions. The auditor sends HELLO/BEAT to its HSYNC3 peers and
 * so maintains a DistributionCache like the agent and combiner. The
 * agent-only op/discover commands are not offered.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

func (conf *Config) APIauditorDistrib(cache *DistributionCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req AgentDistribPost
		if err := decoder.Decode(&req); err != nil {
			lgApi.Warn("error decoding request", "handler", "auditorDistrib", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /auditor/distrib request", "cmd", req.Command, "from", r.RemoteAddr)

		resp := AgentDistribResponse{Time: time.Now()}
		handledManually := false
		defer func() {
			if !handledManually {
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(tdns.SanitizeForJSON(resp)); err != nil {
					lgApi.Error("json encode failed", "handler", "auditorDistrib", "err", err)
				}
			}
		}()

		// Role-independent commands (peer-list, peer-zones,
		// zone-agents) — dispatched via the shared helper, also used
		// by APIagentDistrib.
		if handled, writeHandled, msg, data, errMsg, agents := handleSharedDistribCommand(conf, w, req.Command, req.Zone, resp.Time); handled {
			if writeHandled {
				handledManually = true
				return
			}
			if errMsg != "" {
				resp.Error = true
				resp.ErrorMsg = errMsg
				return
			}
			resp.Msg = msg
			if data != nil {
				resp.Data = data
			}
			if agents != nil {
				resp.Agents = agents
			}
			return
		}

		// Commands below this point require the cache.
		if cache == nil {
			resp.Error = true
			resp.ErrorMsg = "Distribution cache not configured"
			return
		}

		switch req.Command {
		case "list":
			senderID := string(conf.MpConfig().Identity)
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
			var deleted int
			if req.Force {
				deleted = cache.PurgeAll()
				resp.Msg = fmt.Sprintf("Purged %d distribution(s) (force mode)", deleted)
			} else {
				deleted = cache.PurgeCompleted(5 * time.Minute)
				resp.Msg = fmt.Sprintf("Purged %d completed distribution(s)", deleted)
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("unknown auditor distrib command: %q", req.Command)
		}
	}
}
