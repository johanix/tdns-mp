package tdnsmp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSnapshotGossip_includesAllStateReporters(t *testing.T) {
	ar := &AgentRegistry{
		ProviderGroupManager: NewProviderGroupManager("auditor.example."),
		GossipStateTable:     NewGossipStateTable("auditor.example."),
	}
	hash := "abc123"
	ar.ProviderGroupManager.mu.Lock()
	ar.ProviderGroupManager.Groups[hash] = &ProviderGroup{
		GroupHash: hash,
		Members:   []string{"agent.a.example."},
	}
	ar.ProviderGroupManager.mu.Unlock()
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
		t.Fatalf("len = %d, want 1", len(got))
	}
	if len(got[0].Members) != 2 {
		t.Fatalf("members = %v, want both reporters", got[0].Members)
	}
	if len(got[0].Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(got[0].Rows))
	}
}

func TestSnapshotGossipForZone_singleMatrix(t *testing.T) {
	ar := &AgentRegistry{
		ProviderGroupManager: NewProviderGroupManager("auditor.example."),
		GossipStateTable:     NewGossipStateTable("auditor.example."),
	}
	hash := "abc123"
	zone := ZoneName("customer.mptest.")
	ar.ProviderGroupManager.mu.Lock()
	ar.ProviderGroupManager.Groups[hash] = &ProviderGroup{
		GroupHash: hash,
		Members:   []string{"agent.a.example.", "agent.b.example."},
		Zones:     []ZoneName{zone},
	}
	ar.ProviderGroupManager.mu.Unlock()
	ar.GossipStateTable.mu.Lock()
	ar.GossipStateTable.States[hash] = map[string]*MemberState{
		"agent.a.example.": {Identity: "agent.a.example.", Zones: []string{string(zone)}},
	}
	// Unrelated group that shares a member identity must not appear.
	ar.GossipStateTable.States["other"] = map[string]*MemberState{
		"agent.a.example.": {Identity: "agent.a.example.", Zones: []string{"other.zone."}},
		"agent.c.example.": {Identity: "agent.c.example.", Zones: []string{"other.zone."}},
	}
	ar.GossipStateTable.mu.Unlock()

	got := SnapshotGossipForZone(ar, string(zone))
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 matrix for zone", len(got))
	}
	if got[0].GroupHash != hash {
		t.Fatalf("group hash = %q, want %q", got[0].GroupHash, hash)
	}
	// Exactly the group's members as reporters (the silent agent.b gets an
	// empty row), and nothing from the unrelated group agent.a also sits in.
	var reporters []string
	for _, r := range got[0].Rows {
		reporters = append(reporters, r.Reporter)
	}
	if want := []string{"agent.a.example.", "agent.b.example."}; !slices.Equal(reporters, want) {
		t.Fatalf("reporters = %v, want %v (no leakage from the other group)", reporters, want)
	}
}

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

func TestMarkLocalAuditors_withoutInboundBeat(t *testing.T) {
	out := []AuditProviderSummary{
		{Identity: "auditor.skrubb.mp.axfr.net.", Label: "skrubb"},
		{Identity: "auditor.auden.mp.axfr.net.", Label: "auden"},
	}
	markLocalAuditors("auditor.skrubb.mp.axfr.net", out)
	if !out[0].Local {
		t.Fatal("skrubb row should be Local")
	}
	if out[1].Local {
		t.Fatal("auden row should not be Local")
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
