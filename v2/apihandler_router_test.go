/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/johanix/tdns-transport/v2/transport"
)

// The detailed router metrics name each peer's state. The state is a number
// in the transport, and it went out converted with string(): one byte, a
// control character on the terminal of whoever asked.
func TestRouterMetricsNameEachPeersState(t *testing.T) {
	peers := transport.NewPeerRegistry()
	peers.GetOrCreate("agent.bravo.example.").SetState(transport.PeerStateOperational, "test")
	peers.GetOrCreate("agent.charlie.example.") // NEEDED, as every new peer is
	tm := &transport.TransportManager{
		LocalID:      "agent.alpha.example.",
		Router:       transport.NewDNSMessageRouter(),
		PeerRegistry: peers,
	}

	body, err := json.Marshal(RouterPost{Command: "router-metrics", Detailed: true})
	if err != nil {
		t.Fatalf("marshal the request: %v", err)
	}
	rec := httptest.NewRecorder()
	APIrouter(tm)(rec, httptest.NewRequest(http.MethodPost, "/api/v1/router", bytes.NewReader(body)))

	var resp struct {
		Error    bool   `json:"error"`
		ErrorMsg string `json:"error_msg"`
		Data     struct {
			Peers []struct {
				PeerID string `json:"peer_id"`
				State  string `json:"state"`
			} `json:"peers"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("the answer does not parse: %v: %s", err, rec.Body.String())
	}
	if resp.Error {
		t.Fatalf("the handler answered with an error: %s", resp.ErrorMsg)
	}
	got := map[string]string{}
	for _, p := range resp.Data.Peers {
		got[p.PeerID] = p.State
	}
	want := map[string]string{
		"agent.bravo.example.":   "OPERATIONAL",
		"agent.charlie.example.": "NEEDED",
	}
	if !maps.Equal(got, want) {
		t.Errorf("the metrics give the peers' states as %q, want %q", got, want)
	}
}
