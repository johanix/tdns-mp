/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * /router endpoint handler — role-agnostic DNS message router
 * introspection. Any process running a TransportManager can have
 * its router introspected by posting to this endpoint.
 * Registered on all MP roles.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
)

// APIrouter returns the /router handler. Role-agnostic: depends only
// on the TransportManager passed in.
func APIrouter(tm *transport.TransportManager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var rp RouterPost
		if err := decoder.Decode(&rp); err != nil {
			lgApi.Warn("error decoding router command post", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /router request", "cmd", rp.Command, "from", r.RemoteAddr)

		resp := RouterResponse{
			Time: time.Now(),
		}
		if tm != nil {
			resp.Identity = AgentId(tm.LocalID)
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := tdns.SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				lgApi.Error("json encoder failed", "handler", "router", "err", err)
			}
		}()

		if tm == nil || tm.Router == nil {
			resp.Error = true
			resp.ErrorMsg = "Router not available (DNS transport not configured)"
			return
		}

		switch rp.Command {
		case "router-list":
			routerResp := handleRouterList(tm.Router)
			mergeRouterResponse(&resp, routerResp)

		case "router-describe":
			routerResp := handleRouterDescribe(tm.Router)
			mergeRouterResponse(&resp, routerResp)

		case "router-metrics":
			routerResp := handleRouterMetrics(tm, rp.Detailed)
			mergeRouterResponse(&resp, routerResp)

		case "router-walk":
			routerResp := handleRouterWalk(tm.Router)
			mergeRouterResponse(&resp, routerResp)

		case "router-reset":
			routerResp := handleRouterReset(tm.Router)
			mergeRouterResponse(&resp, routerResp)

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown router command: %s", rp.Command)
		}
	}
}

// mergeRouterResponse copies the result fields from a helper-produced
// response into the outer RouterResponse while preserving its Time
// and Identity.
func mergeRouterResponse(dst *RouterResponse, src *RouterResponse) {
	dst.Error = src.Error
	dst.ErrorMsg = src.ErrorMsg
	dst.Msg = src.Msg
	dst.Data = src.Data
}

// handleRouterList returns a list of all registered handlers grouped by message type.
func handleRouterList(router *transport.DNSMessageRouter) *RouterResponse {
	resp := &RouterResponse{
		Time: time.Now(),
	}

	if router == nil {
		resp.Error = true
		resp.ErrorMsg = "Router not initialized"
		return resp
	}

	handlers := router.List()
	if len(handlers) == 0 {
		resp.Msg = "No handlers registered"
		return resp
	}

	handlerData := make(map[string][]map[string]interface{})
	for msgType, regs := range handlers {
		handlerList := make([]map[string]interface{}, len(regs))
		for i, reg := range regs {
			calls := reg.CallCount.Load()
			errors := reg.ErrorCount.Load()
			latency := time.Duration(reg.TotalLatency.Load())
			avgLatency := time.Duration(0)
			if calls > 0 {
				avgLatency = latency / time.Duration(calls)
			}

			handlerList[i] = map[string]interface{}{
				"name":          reg.Name,
				"message_type":  string(reg.MessageType),
				"priority":      reg.Priority,
				"description":   reg.Description,
				"registered":    reg.Registered.Format(time.RFC3339),
				"call_count":    calls,
				"error_count":   errors,
				"total_latency": latency.String(),
				"avg_latency":   avgLatency.String(),
			}
		}
		handlerData[string(msgType)] = handlerList
	}

	resp.Data = map[string]interface{}{
		"handlers": handlerData,
	}
	resp.Msg = fmt.Sprintf("Found %d message types with handlers", len(handlers))

	return resp
}

// handleRouterDescribe returns a detailed description of the router state.
func handleRouterDescribe(router *transport.DNSMessageRouter) *RouterResponse {
	resp := &RouterResponse{
		Time: time.Now(),
	}

	if router == nil {
		resp.Error = true
		resp.ErrorMsg = "Router not initialized"
		return resp
	}

	description := router.Describe()
	resp.Data = description
	resp.Msg = "Router description retrieved"

	return resp
}

// handleRouterMetrics returns router-level metrics with per-type sent/received
// breakdown, aggregated from all peers. If detailed is true, per-peer breakdown
// is included.
func handleRouterMetrics(tm *transport.TransportManager, detailed bool) *RouterResponse {
	resp := &RouterResponse{
		Time: time.Now(),
	}

	if tm == nil || tm.Router == nil {
		resp.Error = true
		resp.ErrorMsg = "Router not initialized"
		return resp
	}

	metrics := tm.Router.GetMetrics()

	unhandledTypes := make(map[string]uint64)
	for msgType, count := range metrics.UnhandledTypes {
		unhandledTypes[string(msgType)] = count
	}

	var totalSent, totalReceived uint64
	var helloSent, helloRecv, beatSent, beatRecv uint64
	var syncSent, syncRecv, pingSent, pingRecv uint64
	var confirmSent, confirmRecv, otherSent, otherRecv uint64

	var peerMetrics []map[string]interface{}

	if tm.PeerRegistry != nil {
		for _, peer := range tm.PeerRegistry.All() {
			s := peer.Stats.GetDetailedStats()
			totalSent += s.TotalSent
			totalReceived += s.TotalReceived
			helloSent += s.HelloSent
			helloRecv += s.HelloReceived
			beatSent += s.BeatSent
			beatRecv += s.BeatReceived
			syncSent += s.SyncSent
			syncRecv += s.SyncReceived
			pingSent += s.PingSent
			pingRecv += s.PingReceived
			confirmSent += s.ConfirmSent
			confirmRecv += s.ConfirmReceived
			otherSent += s.OtherSent
			otherRecv += s.OtherReceived

			if detailed {
				peerMetrics = append(peerMetrics, map[string]interface{}{
					"peer_id":          peer.ID,
					"state":            string(peer.State),
					"last_used":        s.LastUsed.Format(time.RFC3339),
					"hello_sent":       s.HelloSent,
					"hello_received":   s.HelloReceived,
					"beat_sent":        s.BeatSent,
					"beat_received":    s.BeatReceived,
					"sync_sent":        s.SyncSent,
					"sync_received":    s.SyncReceived,
					"ping_sent":        s.PingSent,
					"ping_received":    s.PingReceived,
					"confirm_sent":     s.ConfirmSent,
					"confirm_received": s.ConfirmReceived,
					"other_sent":       s.OtherSent,
					"other_received":   s.OtherReceived,
					"total_sent":       s.TotalSent,
					"total_received":   s.TotalReceived,
				})
			}
		}
	}

	data := map[string]interface{}{
		"total_messages":    metrics.TotalMessages,
		"unknown_messages":  metrics.UnknownMessages,
		"middleware_errors": metrics.MiddlewareErrors,
		"handler_errors":    metrics.HandlerErrors,
		"unhandled_types":   unhandledTypes,
		"total_sent":        totalSent,
		"total_received":    totalReceived,
		"hello_sent":        helloSent,
		"hello_received":    helloRecv,
		"beat_sent":         beatSent,
		"beat_received":     beatRecv,
		"sync_sent":         syncSent,
		"sync_received":     syncRecv,
		"ping_sent":         pingSent,
		"ping_received":     pingRecv,
		"confirm_sent":      confirmSent,
		"confirm_received":  confirmRecv,
		"other_sent":        otherSent,
		"other_received":    otherRecv,
	}

	if detailed && len(peerMetrics) > 0 {
		data["peers"] = peerMetrics
	}

	resp.Data = data
	resp.Msg = "Router metrics retrieved"

	return resp
}

// handleRouterWalk walks all handlers and returns them in a list.
func handleRouterWalk(router *transport.DNSMessageRouter) *RouterResponse {
	resp := &RouterResponse{
		Time: time.Now(),
	}

	if router == nil {
		resp.Error = true
		resp.ErrorMsg = "Router not initialized"
		return resp
	}

	var walkResults []map[string]interface{}

	err := router.Walk(func(reg *transport.HandlerRegistration) error {
		calls := reg.CallCount.Load()
		errors := reg.ErrorCount.Load()
		latency := time.Duration(reg.TotalLatency.Load())
		avgLatency := time.Duration(0)
		if calls > 0 {
			avgLatency = latency / time.Duration(calls)
		}

		walkResults = append(walkResults, map[string]interface{}{
			"name":          reg.Name,
			"message_type":  string(reg.MessageType),
			"priority":      reg.Priority,
			"description":   reg.Description,
			"registered":    reg.Registered.Format(time.RFC3339),
			"call_count":    calls,
			"error_count":   errors,
			"total_latency": latency.String(),
			"avg_latency":   avgLatency.String(),
		})
		return nil
	})

	if err != nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("Walk failed: %v", err)
		return resp
	}

	resp.Data = walkResults
	resp.Msg = fmt.Sprintf("Walked %d handlers", len(walkResults))

	return resp
}

// handleRouterReset resets all router metrics.
func handleRouterReset(router *transport.DNSMessageRouter) *RouterResponse {
	resp := &RouterResponse{
		Time: time.Now(),
	}

	if router == nil {
		resp.Error = true
		resp.ErrorMsg = "Router not initialized"
		return resp
	}

	router.Reset()
	lgApi.Info("router metrics reset via API")

	resp.Msg = "Router metrics reset successfully"
	return resp
}
