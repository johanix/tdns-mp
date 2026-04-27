/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor management API: a single POST /api/v1/auditor endpoint
 * dispatches commands by req.Command. Wire format uses the DTOs in
 * auditor_dto.go; runtime types in auditor_state.go are never
 * exposed directly.
 *
 * Commands:
 *   zones               — list audited zones with provider summaries
 *   zone                — detail for one zone (req.Zone required)
 *   observations        — recent observations, optionally per zone
 *   eventlog-list       — query event log (zone/since/limit)
 *   eventlog-clear      — clear events (zone, older_than, all)
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// AuditPost is the request body for /api/v1/auditor.
type AuditPost struct {
	Command   string `json:"command"`
	Zone      string `json:"zone,omitempty"`
	Since     string `json:"since,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	OlderThan string `json:"older_than,omitempty"`
	All       bool   `json:"all,omitempty"`
}

// AuditResponse is the response body for /api/v1/auditor.
type AuditResponse struct {
	Status       string                 `json:"status"`
	Msg          string                 `json:"msg,omitempty"`
	Error        bool                   `json:"error,omitempty"`
	ErrorMsg     string                 `json:"error_msg,omitempty"`
	Zones        []AuditZoneSummary     `json:"zones,omitempty"`
	Events       []AuditEvent           `json:"events,omitempty"`
	Observations []AuditObservation     `json:"observations,omitempty"`
	Providers    []AuditProviderSummary `json:"providers,omitempty"`
	Gossip       []GossipMatrixDTO      `json:"gossip,omitempty"`
	Deleted      int64                  `json:"deleted,omitempty"`
}

// APIauditor returns the HTTP handler for /api/v1/auditor.
func (conf *Config) APIauditor() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AuditPost
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAuditError(w, "invalid request body: "+err.Error())
			return
		}
		kdb := conf.Config.Internal.KeyDB
		sm := conf.InternalMp.AuditStateManager

		switch req.Command {
		case "zones":
			resp := AuditResponse{Status: "ok"}
			if sm != nil {
				resp.Zones = sm.SnapshotAllZones()
			}
			writeAuditJSON(w, resp)

		case "zone":
			if req.Zone == "" {
				writeAuditError(w, "zone is required")
				return
			}
			resp := AuditResponse{Status: "ok"}
			if sm != nil {
				if zs := sm.GetZone(req.Zone); zs != nil {
					resp.Zones = []AuditZoneSummary{zs.Snapshot()}
				}
			}
			writeAuditJSON(w, resp)

		case "observations":
			resp := AuditResponse{Status: "ok"}
			if sm != nil {
				resp.Observations = sm.SnapshotAllObservations(req.Zone)
			}
			writeAuditJSON(w, resp)

		case "providers":
			resp := AuditResponse{Status: "ok"}
			if sm != nil {
				resp.Providers = sm.SnapshotAllProviders()
			}
			writeAuditJSON(w, resp)

		case "gossip":
			resp := AuditResponse{Status: "ok"}
			resp.Gossip = SnapshotGossip(conf.InternalMp.AgentRegistry)
			writeAuditJSON(w, resp)

		case "eventlog-list":
			if kdb == nil {
				writeAuditError(w, "no database configured")
				return
			}
			var since time.Time
			if req.Since != "" {
				t, err := time.Parse(time.RFC3339, req.Since)
				if err != nil {
					writeAuditError(w, "invalid since format: "+err.Error())
					return
				}
				since = t
			}
			limit := req.Limit
			if limit == 0 {
				limit = 100
			}
			events, err := QueryAuditEvents(kdb, req.Zone, since, limit)
			if err != nil {
				writeAuditError(w, "query failed: "+err.Error())
				return
			}
			writeAuditJSON(w, AuditResponse{Status: "ok", Events: events})

		case "eventlog-clear":
			if kdb == nil {
				writeAuditError(w, "no database configured")
				return
			}
			var olderThan time.Duration
			if req.OlderThan != "" {
				d, err := time.ParseDuration(req.OlderThan)
				if err != nil {
					writeAuditError(w, "invalid older_than: "+err.Error())
					return
				}
				olderThan = d
			}
			if !req.All && req.Zone == "" && olderThan == 0 {
				writeAuditError(w, "must specify zone, older_than, or all")
				return
			}
			deleted, err := ClearAuditEvents(kdb, req.Zone, olderThan, req.All)
			if err != nil {
				writeAuditError(w, "clear failed: "+err.Error())
				return
			}
			writeAuditJSON(w, AuditResponse{
				Status:  "ok",
				Msg:     fmt.Sprintf("deleted %d events", deleted),
				Deleted: deleted,
			})

		default:
			writeAuditError(w, fmt.Sprintf("unknown command: %q", req.Command))
		}
	}
}

func writeAuditJSON(w http.ResponseWriter, resp AuditResponse) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeAuditError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(AuditResponse{
		Status:   "error",
		Error:    true,
		ErrorMsg: msg,
	})
}
