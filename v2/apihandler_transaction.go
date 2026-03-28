/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Transaction diagnostic API endpoints for agents.
 * Provides visibility into open outgoing/incoming transactions and error history.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// APIagentTransaction handles transaction diagnostic requests for agents
func (conf *Config) APIagentTransaction(cache *DistributionCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req TransactionPost
		err := decoder.Decode(&req)
		if err != nil {
			lgApi.Warn("error decoding request", "handler", "agentTransaction", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /agent/transaction request", "cmd", req.Command, "from", r.RemoteAddr)

		resp := TransactionResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := tdns.SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				lgApi.Error("json encode failed", "handler", "agentTransaction", "err", err)
			}
		}()

		switch req.Command {
		case "open-outgoing":
			if cache == nil {
				resp.Error = true
				resp.ErrorMsg = "Distribution cache not configured"
				return
			}
			senderID := string(conf.Config.MultiProvider.Identity)
			infos := cache.List(senderID)
			now := time.Now()

			var summaries []*TransactionSummary
			for _, info := range infos {
				if info.State == "confirmed" {
					continue // Only show non-confirmed
				}
				age := now.Sub(info.CreatedAt)
				summaries = append(summaries, &TransactionSummary{
					DistributionID: info.DistributionID,
					Peer:           info.ReceiverID,
					Operation:      info.Operation,
					Age:            formatDuration(age),
					CreatedAt:      info.CreatedAt.Format(time.RFC3339),
					State:          info.State,
				})
			}
			resp.Transactions = summaries
			resp.Msg = fmt.Sprintf("Found %d open outgoing transaction(s)", len(summaries))

		case "open-incoming":
			// Query PendingRemoteConfirms on the agent side
			zdr := conf.InternalMp.ZoneDataRepo
			if zdr == nil {
				resp.Error = true
				resp.ErrorMsg = "ZoneDataRepo not configured"
				return
			}
			now := time.Now()

			var summaries []*TransactionSummary
			if zdr.PendingRemoteConfirms != nil {
				for combinerDistID, prc := range zdr.PendingRemoteConfirms {
					summaries = append(summaries, &TransactionSummary{
						DistributionID: combinerDistID,
						Peer:           prc.OriginatingSender,
						Operation:      "remote-sync",
						Zone:           string(prc.Zone),
						Age:            formatDuration(now.Sub(prc.CreatedAt)),
						CreatedAt:      prc.CreatedAt.Format(time.RFC3339),
						State:          "awaiting-combiner",
					})
				}
			}
			resp.Transactions = summaries
			resp.Msg = fmt.Sprintf("Found %d open incoming transaction(s)", len(summaries))

		case "errors":
			resp.Error = true
			resp.ErrorMsg = "Error journal is only available on the combiner. Use 'combiner transaction errors' instead."

		case "error-details":
			resp.Error = true
			resp.ErrorMsg = "Error journal is only available on the combiner. Use 'combiner transaction errors details' instead."

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", req.Command)
		}
	}
}

// formatDuration formats a duration in a human-readable way (e.g. "2m30s", "1h15m")
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) - m*60
		if s > 0 {
			return fmt.Sprintf("%dm%ds", m, s)
		}
		return fmt.Sprintf("%dm", m)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) - h*60
	if m > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dh", h)
}
