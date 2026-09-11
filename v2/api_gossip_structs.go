/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Request/response types for the /gossip endpoint.
 * Lives in tdns-mp for future extraction alongside apihandler_gossip.go.
 */
package tdnsmp

import "time"

// GossipPost is the request body for /gossip.
type GossipPost struct {
	Command string `json:"command"`
	Zone    string `json:"zone,omitempty"`
}

// GossipResponse is the response body for /gossip.
// Data carries the per-command payload (state matrix for one zone);
// the CLI formats it via type assertion.
type GossipResponse struct {
	Time     time.Time   `json:"time"`
	Error    bool        `json:"error"`
	ErrorMsg string      `json:"error_msg,omitempty"`
	Msg      string      `json:"msg,omitempty"`
	Identity AgentId     `json:"identity,omitempty"`
	Data     interface{} `json:"data,omitempty"`
}
