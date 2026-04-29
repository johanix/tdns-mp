/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor web dashboard: read-only HTML interface served on its own
 * HTTPS listener. Templates render plain DTOs (auditor_dto.go) — no
 * runtime *AuditProviderState or *AuditZoneState ever crosses into
 * a template. The adapter functions in this file translate state to
 * the WebData struct the templates expect.
 *
 * Auth: bcrypt-hashed users in YAML, in-memory sessions, signed
 * cookies, sliding idle timeout. See auditor_auth.go.
 *
 * Bind safety: refuse to start if auth is "none" but the listener is
 * non-loopback. The "none" mode is for local-only lab use.
 */
package tdnsmp

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/viper"
)

//go:embed auditor_web_templates
var webTemplateFS embed.FS

//go:embed auditor_web_static
var webStaticFS embed.FS

// auditorWebServer holds the parsed templates, state references, and
// auth context.
type auditorWebServer struct {
	tmpl   *template.Template
	conf   *Config
	auth   *AuditWebAuth
	secure bool // sets the Secure cookie flag (true if listener is HTTPS)
}

// WebData is the single struct passed to every full-page render.
// Pages and fragments use only the subset they need.
type WebData struct {
	Title        string
	User         string
	Now          time.Time
	Error        string
	Zone         string
	Zones        []AuditZoneSummary
	ZoneDetail   *AuditZoneSummary
	Providers    []AuditProviderSummary
	Events       []AuditEvent
	Observations []AuditObservation
	Gossip       []GossipMatrixDTO
}

func newAuditorWebServer(conf *Config, auth *AuditWebAuth, secure bool) (*auditorWebServer, error) {
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
	}
	tmpl, err := template.New("").Funcs(fm).ParseFS(
		webTemplateFS,
		"auditor_web_templates/*.html",
		"auditor_web_templates/fragments/*.html",
	)
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &auditorWebServer{tmpl: tmpl, conf: conf, auth: auth, secure: secure}, nil
}

func (s *auditorWebServer) render(w http.ResponseWriter, name string, data *WebData) {
	if data.Now.IsZero() {
		data.Now = time.Now()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		lgAuditor.Error("web template render error", "template", name, "err", err)
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// requireAuth wraps a handler with session-cookie verification. On
// missing/expired session, redirects to /web/login.
func (s *auditorWebServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookieName)
		if err != nil || c.Value == "" {
			http.Redirect(w, r, "/web/login", http.StatusSeeOther)
			return
		}
		sess := s.auth.LookupAndBump(c.Value)
		if sess == nil {
			ClearSessionCookie(w, s.secure)
			http.Redirect(w, r, "/web/login", http.StatusSeeOther)
			return
		}
		// Refresh cookie expiry.
		SetSessionCookie(w, c.Value, s.auth.IdleTTL(), s.secure)
		ctx := context.WithValue(r.Context(), userContextKey{}, sess.User)
		next(w, r.WithContext(ctx))
	}
}

type userContextKey struct{}

func userFromCtx(r *http.Request) string {
	if v, ok := r.Context().Value(userContextKey{}).(string); ok {
		return v
	}
	return ""
}

// --- Login / logout ---

func (s *auditorWebServer) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", &WebData{Title: "Sign in"})
}

func (s *auditorWebServer) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.render(w, "login.html", &WebData{Title: "Sign in", Error: "bad form data"})
		return
	}
	user := r.PostFormValue("user")
	password := r.PostFormValue("password")
	if err := s.auth.Verify(user, password); err != nil {
		lgAuditor.Warn("login failed", "user", user, "remote", r.RemoteAddr)
		s.render(w, "login.html", &WebData{Title: "Sign in", Error: "Invalid credentials"})
		return
	}
	signed, _, err := s.auth.CreateSession(user)
	if err != nil {
		s.render(w, "login.html", &WebData{Title: "Sign in", Error: "session error"})
		return
	}
	SetSessionCookie(w, signed, s.auth.IdleTTL(), s.secure)
	lgAuditor.Info("login ok", "user", user, "remote", r.RemoteAddr)
	http.Redirect(w, r, "/web/", http.StatusSeeOther)
}

func (s *auditorWebServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		s.auth.Logout(c.Value)
	}
	ClearSessionCookie(w, s.secure)
	http.Redirect(w, r, "/web/login", http.StatusSeeOther)
}

// --- Pages ---

func (s *auditorWebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/web/" && r.URL.Path != "/web" {
		http.NotFound(w, r)
		return
	}
	data := s.buildDashboardData(r)
	s.render(w, "dashboard.html", data)
}

func (s *auditorWebServer) handleZoneDetail(w http.ResponseWriter, r *http.Request) {
	zone := strings.TrimPrefix(r.URL.Path, "/web/zone/")
	if zone == "" {
		http.Redirect(w, r, "/web/", http.StatusSeeOther)
		return
	}
	data := s.buildZoneDetailData(r, zone)
	s.render(w, "zone_detail.html", data)
}

func (s *auditorWebServer) handleEventLog(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	data := s.buildEventLogData(r, zone, 100)
	s.render(w, "eventlog.html", data)
}

func (s *auditorWebServer) handleProviders(w http.ResponseWriter, r *http.Request) {
	data := s.buildProvidersData(r)
	s.render(w, "providers.html", data)
}

func (s *auditorWebServer) handleObservations(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	data := s.buildObservationsData(r, zone)
	s.render(w, "observations.html", data)
}

func (s *auditorWebServer) handleGossip(w http.ResponseWriter, r *http.Request) {
	data := s.buildGossipData(r)
	s.render(w, "gossip.html", data)
}

// --- Fragments ---

func (s *auditorWebServer) fragmentZoneStatus(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	data := s.buildZoneDetailData(r, zone)
	s.render(w, "zone_status.html", data)
}

func (s *auditorWebServer) fragmentProviderDetail(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	provider := r.URL.Query().Get("provider")
	data := &WebData{User: userFromCtx(r), Zone: zone}
	sm := s.conf.InternalMp.AuditStateManager
	if sm != nil && zone != "" && provider != "" {
		if zs := sm.GetZone(zone); zs != nil {
			summary := zs.Snapshot()
			for _, p := range summary.Providers {
				if p.Identity == provider {
					data.Providers = []AuditProviderSummary{p}
					break
				}
			}
		}
	}
	s.render(w, "provider_detail.html", data)
}

func (s *auditorWebServer) fragmentEventLogRows(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	data := s.buildEventLogData(r, zone, 50)
	s.render(w, "eventlog-rows-inner", data)
}

func (s *auditorWebServer) fragmentObservationList(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	data := s.buildObservationsData(r, zone)
	s.render(w, "observation-list-inner", data)
}

func (s *auditorWebServer) fragmentGossipMatrix(w http.ResponseWriter, r *http.Request) {
	data := s.buildGossipData(r)
	s.render(w, "gossip-matrix-inner", data)
}

// --- Adapter functions: state → WebData (DTOs) ---

func (s *auditorWebServer) buildDashboardData(r *http.Request) *WebData {
	d := &WebData{Title: "Auditor Dashboard", User: userFromCtx(r)}
	if sm := s.conf.InternalMp.AuditStateManager; sm != nil {
		d.Zones = sm.SnapshotAllZones()
	}
	return d
}

func (s *auditorWebServer) buildZoneDetailData(r *http.Request, zone string) *WebData {
	d := &WebData{
		Title: "Zone: " + zone,
		User:  userFromCtx(r),
		Zone:  zone,
	}
	if sm := s.conf.InternalMp.AuditStateManager; sm != nil {
		if zs := sm.GetZone(zone); zs != nil {
			snap := zs.Snapshot()
			d.ZoneDetail = &snap
			d.Providers = snap.Providers
		}
	}
	return d
}

func (s *auditorWebServer) buildEventLogData(r *http.Request, zone string, limit int) *WebData {
	d := &WebData{Title: "Event Log", User: userFromCtx(r), Zone: zone}
	if kdb := s.conf.Config.Internal.KeyDB; kdb != nil {
		var since time.Time
		if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
			if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
				since = t
			}
		}
		events, err := QueryAuditEvents(kdb, zone, since, limit)
		if err != nil {
			d.Error = "query failed: " + err.Error()
		} else {
			d.Events = events
		}
	}
	return d
}

func (s *auditorWebServer) buildProvidersData(r *http.Request) *WebData {
	d := &WebData{Title: "Providers", User: userFromCtx(r)}
	if sm := s.conf.InternalMp.AuditStateManager; sm != nil {
		d.Providers = sm.SnapshotAllProviders()
	}
	return d
}

func (s *auditorWebServer) buildObservationsData(r *http.Request, zone string) *WebData {
	d := &WebData{Title: "Observations", User: userFromCtx(r), Zone: zone}
	if sm := s.conf.InternalMp.AuditStateManager; sm != nil {
		d.Observations = sm.SnapshotAllObservations(zone)
	}
	return d
}

func (s *auditorWebServer) buildGossipData(r *http.Request) *WebData {
	d := &WebData{Title: "Gossip", User: userFromCtx(r)}
	d.Gossip = SnapshotGossip(s.conf.InternalMp.AgentRegistry)
	return d
}

// --- JSON status (for healthchecks) ---

func (s *auditorWebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	type statusResp struct {
		Status    string   `json:"status"`
		Zones     []string `json:"zones"`
		Timestamp string   `json:"timestamp"`
	}
	resp := statusResp{Status: "ok", Timestamp: time.Now().Format(time.RFC3339)}
	if sm := s.conf.InternalMp.AuditStateManager; sm != nil {
		for _, z := range sm.SnapshotAllZones() {
			resp.Zones = append(resp.Zones, z.Zone)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// registerRoutes wires all /web/* paths onto mux. wrap is applied
// to every route that requires authentication; routes that must
// stay open (static, /login, /logout, /status, root redirect) are
// always registered raw. Callers choose wrap = s.requireAuth for the
// authenticated mux, or an identity passthrough for no-auth mode.
func (s *auditorWebServer) registerRoutes(mux *http.ServeMux, wrap func(http.HandlerFunc) http.HandlerFunc) {
	staticSub, _ := fs.Sub(webStaticFS, "auditor_web_static")
	mux.Handle("/web/static/", http.StripPrefix("/web/static/", http.FileServer(http.FS(staticSub))))

	mux.HandleFunc("/web/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.handleLoginGet(w, r)
		case http.MethodPost:
			s.handleLoginPost(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/web/logout", s.handleLogout)
	mux.HandleFunc("/web/status", s.handleStatus) // unauthenticated healthcheck

	mux.HandleFunc("/web/", wrap(s.handleDashboard))
	mux.HandleFunc("/web/zone/", wrap(s.handleZoneDetail))
	mux.HandleFunc("/web/eventlog", wrap(s.handleEventLog))
	mux.HandleFunc("/web/providers", wrap(s.handleProviders))
	mux.HandleFunc("/web/observations", wrap(s.handleObservations))
	mux.HandleFunc("/web/gossip", wrap(s.handleGossip))

	mux.HandleFunc("/web/fragment/zone-status", wrap(s.fragmentZoneStatus))
	mux.HandleFunc("/web/fragment/provider-detail", wrap(s.fragmentProviderDetail))
	mux.HandleFunc("/web/fragment/eventlog-rows", wrap(s.fragmentEventLogRows))
	mux.HandleFunc("/web/fragment/observation-list", wrap(s.fragmentObservationList))
	mux.HandleFunc("/web/fragment/gossip-matrix", wrap(s.fragmentGossipMatrix))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/web/", http.StatusSeeOther)
			return
		}
		http.NotFound(w, r)
	})
}

// RegisterRoutes wires the authenticated mux: every /web/* data
// route is wrapped with requireAuth.
func (s *auditorWebServer) RegisterRoutes(mux *http.ServeMux) {
	s.registerRoutes(mux, s.requireAuth)
}

// StartAuditorWebServer starts the dashboard listener(s). Reads:
//
//	audit.web.enabled         (bool, default false)
//	audit.web.addresses       ([]string, default ["127.0.0.1:8099"])
//	audit.web.cert_file       (string)
//	audit.web.key_file        (string)
//	audit.web.auth.mode       ("basic"|"none", default "basic")
//	audit.web.auth.idle_timeout (duration, default 30m)
//	audit.web.auth.users      ([]{name, password_hash})
//
// Bind safety: with auth.mode="none", refuses non-loopback addresses.
// HTTPS is mandatory unless explicitly disabled by setting both
// cert_file and key_file to "" — this is intended for local-only
// lab use behind a TLS-terminating proxy.
func (conf *Config) StartAuditorWebServer(ctx context.Context) error {
	if !viper.GetBool("audit.web.enabled") {
		lgAuditor.Info("auditor web dashboard disabled")
		return nil
	}
	addrs := viper.GetStringSlice("audit.web.addresses")
	if len(addrs) == 0 {
		addrs = []string{"127.0.0.1:8099"}
	}
	mode := viper.GetString("audit.web.auth.mode")
	if mode == "" {
		mode = "basic"
	}
	if mode == "none" {
		for _, a := range addrs {
			if !isLoopbackAddr(a) {
				return fmt.Errorf("audit.web.auth.mode=\"none\" forbidden on non-loopback address %q", a)
			}
		}
	}

	var auth *AuditWebAuth
	if mode == "basic" {
		idleTTL := viper.GetDuration("audit.web.auth.idle_timeout")
		if idleTTL <= 0 {
			idleTTL = defaultIdleTTL
		}
		usersFile := auditWebUsersFile()
		if usersFile == "" {
			return errors.New("audit.web.auth.users_file is required when audit.web.auth.mode=\"basic\"")
		}
		users, err := ReadAuditWebUsersFile(usersFile)
		if err != nil {
			return fmt.Errorf("audit.web.auth.users_file %s: %w", usersFile, err)
		}
		if len(users) == 0 {
			return fmt.Errorf("audit.web.auth.users_file %s has no users (use 'mpcli auditor web user create' to add one)", usersFile)
		}
		auth, err = NewAuditWebAuth(users, idleTTL)
		if err != nil {
			return fmt.Errorf("audit.web auth init: %w", err)
		}
		conf.InternalMp.AuditWebAuth = auth
		// Background pruning of expired sessions.
		go func() {
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					auth.PruneExpired()
				}
			}
		}()
	} else if mode != "none" {
		return fmt.Errorf("audit.web.auth.mode must be \"basic\" or \"none\", got %q", mode)
	}

	certFile := viper.GetString("audit.web.cert_file")
	keyFile := viper.GetString("audit.web.key_file")
	useHTTPS := certFile != "" && keyFile != ""

	// Plain HTTP with basic auth would send the login POST and the
	// session cookie in the clear — even on a loopback bind, anyone
	// on the same host could observe them. Refuse the combination.
	// Loopback no-auth is acceptable because there is nothing to
	// protect.
	if mode == "basic" && !useHTTPS {
		return errors.New("audit.web.auth.mode=\"basic\" requires HTTPS (set audit.web.cert_file and audit.web.key_file)")
	}

	ws, err := newAuditorWebServer(conf, auth, useHTTPS)
	if err != nil {
		return fmt.Errorf("init web server: %w", err)
	}

	for _, addr := range addrs {
		a := addr
		// In "none" mode the require-auth wrapper is bypassed by
		// substituting a passthrough; see noAuthMux.
		var mux *http.ServeMux
		if auth == nil {
			mux = noAuthMux(ws)
		} else {
			mux = http.NewServeMux()
			ws.RegisterRoutes(mux)
		}

		srv := &http.Server{Addr: a, Handler: mux, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		go func() {
			lgAuditor.Info("starting auditor web dashboard",
				"addr", a, "https", useHTTPS, "auth", mode)
			var err error
			if useHTTPS {
				err = srv.ListenAndServeTLS(certFile, keyFile)
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lgAuditor.Error("auditor web server error", "addr", a, "err", err)
			}
		}()
		go func() {
			<-ctx.Done()
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutCtx)
		}()
	}
	return nil
}

// noAuthMux builds the route mux without the requireAuth wrapper.
// Only used when audit.web.auth.mode="none" (loopback-only).
func noAuthMux(s *auditorWebServer) *http.ServeMux {
	mux := http.NewServeMux()
	s.registerRoutes(mux, func(h http.HandlerFunc) http.HandlerFunc { return h })
	return mux
}

// auditWebUsersFile reads audit.web.auth.users_file from viper.
func auditWebUsersFile() string {
	return viper.GetString("audit.web.auth.users_file")
}

// isLoopbackAddr returns true if addr (host:port form) binds to a
// loopback interface. An empty host (e.g. ":8099") means "all
// interfaces" and is therefore NOT loopback.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
