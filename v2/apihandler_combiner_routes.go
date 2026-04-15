/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Combiner API route registration for tdns-mp.
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
)

// SetupMPCombinerRoutes registers combiner-specific API routes on
// the existing API router. Called from StartMPCombiner.
func (conf *Config) SetupMPCombinerRoutes(ctx context.Context, apirouter *mux.Router) {
	hdb := NewHsyncDB(conf.Config.Internal.KeyDB)
	sr := apirouter.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/combiner", APIcombiner(&tdns.Globals.App, conf.Config.Internal.RefreshZoneCh, hdb)).Methods("POST")
	sr.HandleFunc("/gossip", APIgossip(conf.InternalMp.AgentRegistry, conf.InternalMp.LeaderElectionManager)).Methods("POST")
	sr.HandleFunc("/router", APIrouter(conf.InternalMp.TransportManager)).Methods("POST")
	sr.HandleFunc("/peer", APIpeer(conf, conf.InternalMp.TransportManager, conf.InternalMp.AgentRegistry)).Methods("POST")
	sr.HandleFunc("/zone/mplist", conf.APImplist()).Methods("POST")
	sr.HandleFunc("/combiner/distrib", conf.APIcombinerDistrib(conf.InternalMp.DistributionCache)).Methods("POST")
	sr.HandleFunc("/combiner/transaction", conf.APIcombinerTransaction()).Methods("POST")
	sr.HandleFunc("/combiner/debug", APIcombinerDebug(conf)).Methods("POST")
	sr.HandleFunc("/combiner/edits", APIcombinerEdits(conf)).Methods("POST")
	sr.HandleFunc("/combiner/mp", conf.APImpCombiner()).Methods("POST")
}

// APIcombinerTransaction handles the /combiner/transaction endpoint.
// Provides error journal queries for combiner CHUNK processing diagnostics.
func (conf *Config) APIcombinerTransaction() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req TransactionPost
		err := decoder.Decode(&req)
		if err != nil {
			lgApi.Warn("error decoding request", "handler", "combinerTransaction", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /combiner/transaction request", "cmd", req.Command, "from", r.RemoteAddr)

		resp := TransactionResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := tdns.SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				lgApi.Error("json encode failed", "handler", "combinerTransaction", "err", err)
			}
		}()

		combinerState := conf.InternalMp.CombinerState
		if combinerState == nil || combinerState.ErrorJournal == nil {
			resp.Error = true
			resp.ErrorMsg = "Combiner state or error journal not configured"
			return
		}

		switch req.Command {
		case "errors":
			duration, err := time.ParseDuration(req.Last)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Invalid duration %q: %v", req.Last, err)
				return
			}

			entries := combinerState.ErrorJournal.ListSince(duration)
			now := time.Now()

			var errors []*TransactionErrorSummary
			for _, e := range entries {
				errors = append(errors, &TransactionErrorSummary{
					DistributionID: e.DistributionID,
					Age:            formatDuration(now.Sub(e.Timestamp)),
					Sender:         e.Sender,
					MessageType:    e.MessageType,
					ErrorMsg:       e.ErrorMsg,
					QNAME:          e.QNAME,
					Timestamp:      e.Timestamp.Format(time.RFC3339),
				})
			}
			resp.Errors = errors
			resp.Msg = fmt.Sprintf("Found %d error(s) in the last %s", len(errors), req.Last)

		case "error-details":
			if req.DistID == "" {
				resp.Error = true
				resp.ErrorMsg = "dist_id is required for error-details command"
				return
			}

			entry, found := combinerState.ErrorJournal.LookupByDistID(req.DistID)
			if !found {
				resp.Msg = fmt.Sprintf("No error record for distID %s", req.DistID)
				return
			}
			now := time.Now()
			resp.ErrorDetail = &TransactionErrorSummary{
				DistributionID: entry.DistributionID,
				Age:            formatDuration(now.Sub(entry.Timestamp)),
				Sender:         entry.Sender,
				MessageType:    entry.MessageType,
				ErrorMsg:       entry.ErrorMsg,
				QNAME:          entry.QNAME,
				Timestamp:      entry.Timestamp.Format(time.RFC3339),
			}
			resp.Msg = fmt.Sprintf("Error details for distID %s", req.DistID)

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", req.Command)
		}
	}
}
