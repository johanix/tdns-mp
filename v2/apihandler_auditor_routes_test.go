/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	tdns "github.com/johanix/tdns/v2"
)

// The auditor serves /imr like the agent does: its resolver cache is what
// to look at when the auditor and the agents disagree about a peer.
func TestAuditorServesImr(t *testing.T) {
	conf := &Config{Config: &tdns.Config{}}
	r := mux.NewRouter()
	conf.SetupMPAuditorRoutes(context.Background(), r)

	var m mux.RouteMatch
	if !r.Match(httptest.NewRequest(http.MethodPost, "/api/v1/imr", nil), &m) {
		t.Fatal("tdns-mpauditor does not route POST /api/v1/imr")
	}
}
