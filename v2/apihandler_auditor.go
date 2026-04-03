/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor API handler: /audit/* endpoints for querying state,
 * event log, and observations.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// AuditPost is the request body for /audit/* endpoints.
type AuditPost struct {
	Command   string `json:"command"`
	Zone      string `json:"zone,omitempty"`
	Since     string `json:"since,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	OlderThan string `json:"older_than,omitempty"`
	All       bool   `json:"all,omitempty"`
}

// AuditResponse is the response body for /audit/* endpoints.
type AuditResponse struct {
	Status       string             `json:"status"`
	Msg          string             `json:"msg,omitempty"`
	Error        bool               `json:"error,omitempty"`
	ErrorMsg     string             `json:"error_msg,omitempty"`
	Zones        []AuditZoneSummary `json:"zones,omitempty"`
	Events       []AuditEvent       `json:"events,omitempty"`
	Observations []AuditObservation `json:"observations,omitempty"`
	Deleted      int64              `json:"deleted,omitempty"`
}

// AuditZoneSummary is a condensed view of a zone's audit state.
type AuditZoneSummary struct {
	Zone          string                         `json:"zone"`
	ProviderCount int                            `json:"provider_count"`
	LastRefresh   time.Time                      `json:"last_refresh,omitempty"`
	ZoneSerial    uint32                         `json:"zone_serial,omitempty"`
	Providers     map[string]*AuditProviderState `json:"providers,omitempty"`
}

// APIaudit returns an HTTP handler for /audit endpoints.
func (conf *Config) APIaudit() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AuditPost
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAuditError(w, "invalid request body: "+err.Error())
			return
		}

		kdb := conf.Config.Internal.KeyDB
		stateManager := conf.InternalMp.AuditStateManager

		switch req.Command {
		case "zones":
			resp := AuditResponse{Status: "ok"}
			if stateManager != nil {
				allZones := stateManager.GetAllZones()
				for zoneName, zs := range allZones {
					zs.mu.RLock()
					summary := AuditZoneSummary{
						Zone:          zoneName,
						ProviderCount: len(zs.Providers),
						LastRefresh:   zs.LastRefresh,
						ZoneSerial:    zs.ZoneSerial,
					}
					zs.mu.RUnlock()
					resp.Zones = append(resp.Zones, summary)
				}
			}
			writeAuditJSON(w, resp)

		case "zone":
			if req.Zone == "" {
				writeAuditError(w, "zone is required")
				return
			}
			resp := AuditResponse{Status: "ok"}
			if stateManager != nil {
				zs := stateManager.GetZone(req.Zone)
				if zs != nil {
					zs.mu.RLock()
					summary := AuditZoneSummary{
						Zone:          zs.Zone,
						ProviderCount: len(zs.Providers),
						LastRefresh:   zs.LastRefresh,
						ZoneSerial:    zs.ZoneSerial,
						Providers:     zs.Providers,
					}
					zs.mu.RUnlock()
					resp.Zones = []AuditZoneSummary{summary}
				}
			}
			writeAuditJSON(w, resp)

		case "observations":
			resp := AuditResponse{Status: "ok"}
			if stateManager != nil {
				allZones := stateManager.GetAllZones()
				for _, zs := range allZones {
					if req.Zone != "" && zs.Zone != req.Zone {
						continue
					}
					zs.mu.RLock()
					resp.Observations = append(resp.Observations, zs.Observations...)
					zs.mu.RUnlock()
				}
			}
			writeAuditJSON(w, resp)

		case "eventlog-list":
			if kdb == nil {
				writeAuditError(w, "no database configured")
				return
			}
			var since time.Time
			if req.Since != "" {
				var err error
				since, err = time.Parse(time.RFC3339, req.Since)
				if err != nil {
					writeAuditError(w, "invalid since format: "+err.Error())
					return
				}
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
				var err error
				olderThan, err = time.ParseDuration(req.OlderThan)
				if err != nil {
					writeAuditError(w, "invalid older_than: "+err.Error())
					return
				}
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

// SetupMPAuditorRoutes registers auditor-specific API routes.
func (conf *Config) SetupMPAuditorRoutes(apirouter *mux.Router) {
	kdb := conf.Config.Internal.KeyDB
	sr := apirouter.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/audit", conf.APIaudit()).Methods("POST")
	// Reuse agent management endpoint for peer/gossip/debug commands
	sr.HandleFunc("/agent", conf.APIagent(conf.Config.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/agent/distrib", conf.APIagentDistrib(conf.InternalMp.DistributionCache)).Methods("POST")
	sr.HandleFunc("/agent/debug", conf.APIagentDebug()).Methods("POST")
}

func writeAuditJSON(w http.ResponseWriter, resp AuditResponse) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func writeAuditError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuditResponse{
		Status:   "error",
		Error:    true,
		ErrorMsg: msg,
	})
}
