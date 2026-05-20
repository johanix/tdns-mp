package tdnsmp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSnapshotGossip_fromGossipStateTableWhenPGMEmpty(t *testing.T) {
	ar := &AgentRegistry{
		ProviderGroupManager: NewProviderGroupManager("auditor.example."),
		GossipStateTable:     NewGossipStateTable("auditor.example."),
	}
	hash := "abc123"
	ar.GossipStateTable.mu.Lock()
	ar.GossipStateTable.States[hash] = map[string]*MemberState{
		"agent.a.example.": {
			Identity:   "agent.a.example.",
			Timestamp:  time.Now(),
			PeerStates: map[string]string{"agent.b.example.": "OPERATIONAL"},
		},
		"agent.b.example.": {
			Identity:   "agent.b.example.",
			Timestamp:  time.Now(),
			PeerStates: map[string]string{"agent.a.example.": "OPERATIONAL"},
		},
	}
	ar.GossipStateTable.mu.Unlock()

	got := SnapshotGossip(ar)
	if len(got) != 1 {
		t.Fatalf("len(SnapshotGossip) = %d, want 1", len(got))
	}
	if len(got[0].Rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(got[0].Rows))
	}
}

func TestDashboardTemplateRendersZones(t *testing.T) {
	sm := NewAuditStateManager()
	zs := sm.GetOrCreateZone("customer.mptest.")
	zs.UpdateProviderBeat("agent.hare.mp.axfr.net.", "hare", "OPERATIONAL", true)

	conf := &Config{InternalMp: InternalMpConf{AuditStateManager: sm}}
	ws, err := newAuditorWebServer(conf, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	data := ws.buildDashboardData(httptest.NewRequest("GET", "/web/", nil))
	var buf bytes.Buffer
	if err := ws.tmpl.ExecuteTemplate(&buf, "dashboard.html", data); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if !strings.Contains(html, "customer.mptest.") {
		t.Fatalf("dashboard HTML missing zone link, got: %s", html)
	}
	if !strings.Contains(html, "/web/zone?zone=") {
		t.Fatalf("dashboard HTML missing query zone link, got: %s", html)
	}
	if !strings.Contains(html, `audit-zone-bar`) {
		t.Fatalf("dashboard HTML missing zone bar, got: %s", html)
	}
}

func TestGossipTemplateRendersMatrix(t *testing.T) {
	conf := &Config{InternalMp: InternalMpConf{
		AgentRegistry: &AgentRegistry{
			ProviderGroupManager: NewProviderGroupManager("auditor.example."),
			GossipStateTable:     NewGossipStateTable("auditor.example."),
		},
	}}
	ar := conf.InternalMp.AgentRegistry
	hash := "abc123"
	ar.GossipStateTable.mu.Lock()
	ar.GossipStateTable.States[hash] = map[string]*MemberState{
		"agent.hare.mp.axfr.net.": {
			Identity:   "agent.hare.mp.axfr.net.",
			Timestamp:  time.Now(),
			PeerStates: map[string]string{"agent.fox.mp.axfr.net.": "OPERATIONAL"},
		},
	}
	ar.GossipStateTable.mu.Unlock()

	ws, err := newAuditorWebServer(conf, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	data := ws.buildGossipData(httptest.NewRequest("GET", "/web/gossip", nil))
	var buf bytes.Buffer
	if err := ws.tmpl.ExecuteTemplate(&buf, "gossip.html", data); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if !strings.Contains(html, "audit-gossip-matrix") {
		t.Fatalf("gossip HTML missing matrix table, got: %s", html)
	}
	if !strings.Contains(html, "<h2>Gossip</h2>") {
		t.Fatalf("gossip HTML missing page title, got: %s", html)
	}
	if strings.Contains(html, "<h2>Zone:") {
		t.Fatalf("gossip HTML incorrectly rendered zone page content")
	}
}

func TestRequireAuth_htmxUnauthorizedRedirect(t *testing.T) {
	auth, err := NewAuditWebAuth([]AuditWebUser{{Name: "u", PasswordHash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ws := &auditorWebServer{auth: auth, secure: false}
	var gotCode int
	var gotHX string
	h := ws.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	})
	req := httptest.NewRequest("GET", "/web/fragment/x", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h(rec, req)
	gotCode = rec.Code
	gotHX = rec.Header().Get("HX-Redirect")
	if gotCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", gotCode)
	}
	if gotHX != "/web/login" {
		t.Fatalf("HX-Redirect = %q, want /web/login", gotHX)
	}
}
