package tdnsmp

import (
	"bytes"
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
}
