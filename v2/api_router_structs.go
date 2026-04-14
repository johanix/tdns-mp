/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Request/response types for the /router endpoint.
 * Lives in tdns-mp alongside apihandler_router.go for future
 * extraction into tdns-transport.
 */
package tdnsmp

import "time"

// RouterPost is the request body for /router.
type RouterPost struct {
	Command  string `json:"command"`
	Detailed bool   `json:"detailed,omitempty"`
}

// RouterResponse is the response body for /router.
// Data carries the per-command payload (list of handlers / metrics
// map / walk tree / description string); the CLI formats it via
// type assertion because the five commands return very different
// shapes.
type RouterResponse struct {
	Time     time.Time   `json:"time"`
	Error    bool        `json:"error"`
	ErrorMsg string      `json:"error_msg,omitempty"`
	Msg      string      `json:"msg,omitempty"`
	Identity AgentId     `json:"identity,omitempty"`
	Data     interface{} `json:"data,omitempty"`
}
