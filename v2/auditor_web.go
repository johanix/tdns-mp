/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor web interface: built-in HTTP dashboard for inspecting
 * current auditor state. Read-only. Uses Go templates + HTMX.
 * All assets embedded via //go:embed.
 */
package tdnsmp

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/viper"
)

//go:embed auditor_web_templates
var webTemplateFS embed.FS

//go:embed auditor_web_static
var webStaticFS embed.FS

// auditorWebServer holds the template set and state manager for
// serving the web interface.
type auditorWebServer struct {
	tmpl    *template.Template
	conf    *Config
	funcMap template.FuncMap
}

// templateData is passed to every full-page template render.
type templateData struct {
	Title        string
	Zone         string
	Zones        []*AuditZoneState
	ZoneDetail   *AuditZoneSummary
	Providers    []*AuditProviderState
	Events       []AuditEvent
	Observations []AuditObservation
	Now          time.Time
	Error        string
}

func newAuditorWebServer(conf *Config) (*auditorWebServer, error) {
	fm := template.FuncMap{
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			d := time.Since(t)
			switch {
			case d < 2*time.Second:
				return "just now"
			case d < time.Minute:
				return fmt.Sprintf("%ds ago", int(d.Seconds()))
			case d < time.Hour:
				return fmt.Sprintf("%dm ago", int(d.Minutes()))
			default:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			}
		},
		"fmtTime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format("2006-01-02 15:04:05")
		},
		"providerCount": func(m map[string]*AuditProviderState) int {
			return len(m)
		},
		"severityClass": func(s string) string {
			switch s {
			case "error":
				return "pico-color-red-500"
			case "warning":
				return "pico-color-yellow-500"
			default:
				return ""
			}
		},
		"lower": strings.ToLower,
		"upper": strings.ToUpper,
		"add":   func(a, b int) int { return a + b },
	}

	// Parse all templates from embedded FS
	tmpl, err := template.New("").Funcs(fm).ParseFS(
		webTemplateFS,
		"auditor_web_templates/*.html",
		"auditor_web_templates/fragments/*.html",
	)
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	return &auditorWebServer{
		tmpl:    tmpl,
		conf:    conf,
		funcMap: fm,
	}, nil
}

func (s *auditorWebServer) render(w http.ResponseWriter, name string, data *templateData) {
	if data.Now.IsZero() {
		data.Now = time.Now()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("web template render error", "template", name, "err", err)
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// isHTMX returns true if the request was triggered by HTMX.
func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// RegisterAuditorWebRoutes attaches /web/* routes to the given mux.
func (s *auditorWebServer) RegisterRoutes(mux *http.ServeMux) {
	// Static assets
	staticSub, _ := fs.Sub(webStaticFS, "auditor_web_static")
	mux.Handle("/web/static/", http.StripPrefix("/web/static/", http.FileServer(http.FS(staticSub))))

	// Pages
	mux.HandleFunc("/web/", s.handleDashboard)
	mux.HandleFunc("/web/zone/", s.handleZoneDetail)
	mux.HandleFunc("/web/eventlog", s.handleEventLog)
	mux.HandleFunc("/web/providers", s.handleProviders)
	mux.HandleFunc("/web/observations", s.handleObservations)

	// HTMX fragments
	mux.HandleFunc("/web/fragment/zone-status", s.fragmentZoneStatus)
	mux.HandleFunc("/web/fragment/provider-detail", s.fragmentProviderDetail)
	mux.HandleFunc("/web/fragment/eventlog-rows", s.fragmentEventLogRows)
	mux.HandleFunc("/web/fragment/observation-list", s.fragmentObservationList)
}

// --- Page handlers ---

func (s *auditorWebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/web/" && r.URL.Path != "/web" {
		http.NotFound(w, r)
		return
	}
	sm := s.conf.InternalMp.AuditStateManager
	data := &templateData{Title: "Auditor Dashboard"}
	if sm != nil {
		for _, zs := range sm.GetAllZones() {
			data.Zones = append(data.Zones, zs)
		}
	}
	s.render(w, "dashboard.html", data)
}

func (s *auditorWebServer) handleZoneDetail(w http.ResponseWriter, r *http.Request) {
	zone := strings.TrimPrefix(r.URL.Path, "/web/zone/")
	if zone == "" {
		http.Redirect(w, r, "/web/", http.StatusSeeOther)
		return
	}
	sm := s.conf.InternalMp.AuditStateManager
	data := &templateData{Title: "Zone: " + zone, Zone: zone}
	if sm != nil {
		zs := sm.GetZone(zone)
		if zs != nil {
			zs.mu.RLock()
			summary := &AuditZoneSummary{
				Zone:          zs.Zone,
				ProviderCount: len(zs.Providers),
				LastRefresh:   zs.LastRefresh,
				ZoneSerial:    zs.ZoneSerial,
				Providers:     zs.Providers,
			}
			zs.mu.RUnlock()
			data.ZoneDetail = summary
			for _, ps := range summary.Providers {
				data.Providers = append(data.Providers, ps)
			}
		}
	}
	s.render(w, "zone_detail.html", data)
}

func (s *auditorWebServer) handleEventLog(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	kdb := s.conf.Config.Internal.KeyDB
	data := &templateData{Title: "Event Log", Zone: zone}
	if kdb != nil {
		var since time.Time
		if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
			since, _ = time.Parse(time.RFC3339, sinceStr)
		}
		limit := 100
		events, err := QueryAuditEvents(kdb, zone, since, limit)
		if err != nil {
			data.Error = "query failed: " + err.Error()
		} else {
			data.Events = events
		}
	}
	s.render(w, "eventlog.html", data)
}

func (s *auditorWebServer) handleProviders(w http.ResponseWriter, r *http.Request) {
	sm := s.conf.InternalMp.AuditStateManager
	data := &templateData{Title: "Providers"}
	if sm != nil {
		seen := map[string]bool{}
		for _, zs := range sm.GetAllZones() {
			zs.mu.RLock()
			for _, ps := range zs.Providers {
				if !seen[ps.Identity] {
					seen[ps.Identity] = true
					data.Providers = append(data.Providers, ps)
				}
			}
			zs.mu.RUnlock()
		}
	}
	s.render(w, "providers.html", data)
}

func (s *auditorWebServer) handleObservations(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	sm := s.conf.InternalMp.AuditStateManager
	data := &templateData{Title: "Observations", Zone: zone}
	if sm != nil {
		for _, zs := range sm.GetAllZones() {
			if zone != "" && zs.Zone != zone {
				continue
			}
			zs.mu.RLock()
			data.Observations = append(data.Observations, zs.Observations...)
			zs.mu.RUnlock()
		}
	}
	s.render(w, "observations.html", data)
}

// --- HTMX fragment handlers ---

func (s *auditorWebServer) fragmentZoneStatus(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	sm := s.conf.InternalMp.AuditStateManager
	data := &templateData{Zone: zone}
	if sm != nil && zone != "" {
		zs := sm.GetZone(zone)
		if zs != nil {
			zs.mu.RLock()
			summary := &AuditZoneSummary{
				Zone:          zs.Zone,
				ProviderCount: len(zs.Providers),
				LastRefresh:   zs.LastRefresh,
				ZoneSerial:    zs.ZoneSerial,
				Providers:     zs.Providers,
			}
			zs.mu.RUnlock()
			data.ZoneDetail = summary
		}
	}
	s.render(w, "zone_status.html", data)
}

func (s *auditorWebServer) fragmentProviderDetail(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	provider := r.URL.Query().Get("provider")
	sm := s.conf.InternalMp.AuditStateManager
	data := &templateData{Zone: zone}
	if sm != nil && zone != "" && provider != "" {
		zs := sm.GetZone(zone)
		if zs != nil {
			zs.mu.RLock()
			ps := zs.Providers[provider]
			zs.mu.RUnlock()
			if ps != nil {
				data.Providers = []*AuditProviderState{ps}
			}
		}
	}
	s.render(w, "provider_detail.html", data)
}

func (s *auditorWebServer) fragmentEventLogRows(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	kdb := s.conf.Config.Internal.KeyDB
	data := &templateData{Zone: zone}
	if kdb != nil {
		events, err := QueryAuditEvents(kdb, zone, time.Time{}, 50)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Events = events
		}
	}
	s.render(w, "eventlog_rows.html", data)
}

func (s *auditorWebServer) fragmentObservationList(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	sm := s.conf.InternalMp.AuditStateManager
	data := &templateData{Zone: zone}
	if sm != nil {
		for _, zs := range sm.GetAllZones() {
			if zone != "" && zs.Zone != zone {
				continue
			}
			zs.mu.RLock()
			data.Observations = append(data.Observations, zs.Observations...)
			zs.mu.RUnlock()
		}
	}
	s.render(w, "observation_list.html", data)
}

// --- Healthcheck / JSON status endpoint ---

func (s *auditorWebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	sm := s.conf.InternalMp.AuditStateManager
	type statusResp struct {
		Status    string   `json:"status"`
		Zones     []string `json:"zones"`
		Timestamp string   `json:"timestamp"`
	}
	resp := statusResp{
		Status:    "ok",
		Timestamp: time.Now().Format(time.RFC3339),
	}
	if sm != nil {
		for zone := range sm.GetAllZones() {
			resp.Zones = append(resp.Zones, zone)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// StartAuditorWebServer starts the web interface HTTP listener.
// Addresses come from audit.web.addresses in config (default 127.0.0.1:8099).
func (conf *Config) StartAuditorWebServer(ctx context.Context) error {
	if !viper.GetBool("audit.web.enabled") {
		return nil
	}

	addrs := viper.GetStringSlice("audit.web.addresses")
	if len(addrs) == 0 {
		addrs = []string{"127.0.0.1:8099"}
	}

	ws, err := newAuditorWebServer(conf)
	if err != nil {
		return fmt.Errorf("init web server: %w", err)
	}

	mux := http.NewServeMux()
	ws.RegisterRoutes(mux)
	mux.HandleFunc("/web/status", ws.handleStatus)

	// Redirect root to /web/
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/web/", http.StatusSeeOther)
			return
		}
		http.NotFound(w, r)
	})

	for _, addr := range addrs {
		a := addr // capture
		srv := &http.Server{
			Addr:    a,
			Handler: mux,
		}
		go func() {
			lgAuditor.Info("starting auditor web interface", "addr", a)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				lgAuditor.Error("auditor web server error", "addr", a, "err", err)
			}
		}()
		go func() {
			<-ctx.Done()
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			srv.Shutdown(shutCtx)
		}()
	}
	return nil
}
