/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Request/response types for the /peer endpoint.
 * Lives in tdns-mp alongside apihandler_peer.go for future
 * extraction into tdns-transport.
 */
package tdnsmp

import "time"

// PeerPost is the request body for /peer.
// The command name carries the API-vs-DNS distinction
// (peer-ping = DNS CHUNK, peer-apiping = HTTPS API), so no
// separate flag is needed.
type PeerPost struct {
	Command string  `json:"command"`
	PeerID  AgentId `json:"peer_id,omitempty"`
}

// PeerResponse is the response body for /peer.
// Ping/reset commands return text-only status; no structured
// payload, so there is no Data field.
type PeerResponse struct {
	Time     time.Time `json:"time"`
	Error    bool      `json:"error"`
	ErrorMsg string    `json:"error_msg,omitempty"`
	Msg      string    `json:"msg,omitempty"`
	Identity AgentId   `json:"identity,omitempty"`
}
