/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"net/http"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// The web page lists observations newest first, like the recent events,
// across zones; the API keeps them in time order (#110).
func TestObservationsAreNewestFirstOnThePageOnly(t *testing.T) {
	sm := NewAuditStateManager()
	base := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	a := sm.GetOrCreateZone("a.example.")
	b := sm.GetOrCreateZone("b.example.")
	a.Observations = []AuditObservation{
		{Time: base, Zone: "a.example.", Severity: "info", Message: "first"},
		{Time: base.Add(2 * time.Minute), Zone: "a.example.", Severity: "info", Message: "third"},
	}
	b.Observations = []AuditObservation{
		{Time: base.Add(time.Minute), Zone: "b.example.", Severity: "info", Message: "second"},
	}
	conf := &Config{Config: &tdns.Config{}, InternalMp: InternalMpConf{AuditStateManager: sm}}

	ws, err := newAuditorWebServer(conf, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	ws.registerRoutes(mux, func(h http.HandlerFunc) http.HandlerFunc { return h })
	page := webGet(t, mux, "/web/fragment/observation-list")
	third, second, first := strings.Index(page, "third"), strings.Index(page, "second"), strings.Index(page, "first")
	if third < 0 || second < 0 || first < 0 || !(third < second && second < first) {
		t.Errorf("the page lists the observations at %d (third), %d (second), %d (first); want newest first:\n%s", third, second, first, page)
	}
	zonePage := webGet(t, mux, "/web/fragment/observation-list?zone=a.example.")
	if strings.Index(zonePage, "third") > strings.Index(zonePage, "first") {
		t.Errorf("one zone's observations are not newest first:\n%s", zonePage)
	}

	resp := auditAPI(t, conf, AuditPost{Command: "observations", Zone: "a.example."})
	if len(resp.Observations) != 2 || resp.Observations[0].Message != "first" || resp.Observations[1].Message != "third" {
		t.Errorf("API observations = %+v, want time order: first, third", resp.Observations)
	}
}
