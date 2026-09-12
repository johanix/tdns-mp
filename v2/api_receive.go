/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The HTTPS mechanism's receive side (cleanup plan, step 5).
 *
 * The sync API endpoints (/hello, /beat, /sync/ping, /msg) hand the request
 * body to the transport's receive pipeline, RouteAPIPayload, which parses
 * it with parseAppPayload, authorizes the sender at all and for the zone,
 * runs the role's verb table and delivers the message to the same queues
 * a NOTIFY(CHUNK) reaches. The reply the pipeline produces (the handler's
 * inline confirmation) is shaped here into the response object each
 * endpoint has always returned, so a sender from before this change reads
 * the same fields.
 *
 * Until step 5 these endpoints had five verb switches of their own and
 * never touched the router; "one verb table per role" was true for DNS
 * only.
 */

package tdnsmp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// apiEndpointKind selects the response object an endpoint returns.
type apiEndpointKind int

const (
	apiEndpointHello apiEndpointKind = iota
	apiEndpointBeat
	apiEndpointPing
	apiEndpointMsg
)

// maxAPIBody bounds a request body; a DNS-carried payload is bounded by
// the message size, an HTTPS-carried one is bounded here.
const maxAPIBody = 1 << 20

// apiSyncEndpoint returns the HTTP handler for one sync API endpoint.
func (conf *Config) apiSyncEndpoint(kind apiEndpointKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sink := &apiReplySink{kind: kind, w: w}
		bridge := conf.InternalMp.MPTransport
		if bridge == nil || bridge.ChunkHandler == nil {
			lgApi.Error("sync API request but no transport handler", "path", r.URL.Path)
			_ = sink.fail("transport not initialized")
			return
		}
		sink.local = AgentId(bridge.LocalID)
		handler := bridge.ChunkHandler

		body, err := io.ReadAll(io.LimitReader(r.Body, maxAPIBody))
		if err != nil {
			lgApi.Warn("error reading sync API body", "path", r.URL.Path, "from", r.RemoteAddr, "err", err)
			_ = sink.fail(fmt.Sprintf("Invalid request: %v", err))
			return
		}
		// The sender the body names, for the reply, before the pipeline
		// decides anything about it.
		if im, perr := parseAppPayload("", body, r.RemoteAddr); perr == nil && im != nil {
			sink.your = AgentId(im.SenderID)
		}
		lgApi.Debug("received sync API request", "path", r.URL.Path, "from", r.RemoteAddr, "sender", sink.your)
		if err := handler.RouteAPIPayload(r.Context(), body, r.RemoteAddr, sink); err != nil {
			lgApi.Warn("sync API request failed", "path", r.URL.Path, "from", r.RemoteAddr, "err", err)
		}
	}
}

// apiReplySink shapes the pipeline's answer into the endpoint's response
// object. HTTP status is always 200 with the Error field set, which is
// what the endpoints returned before and what every sender checks.
type apiReplySink struct {
	kind  apiEndpointKind
	w     http.ResponseWriter
	local AgentId
	your  AgentId
	done  bool
}

// inlineConfirm is what the handlers put in the reply payload: the
// transport's confirm and ping_confirm objects and the application's acks
// all carry these three fields.
type inlineConfirm struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Nonce   string `json:"nonce"`
}

func (s *apiReplySink) Reply(ctx *transport.MessageContext, payload []byte, rcode int) error {
	var inline inlineConfirm
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &inline); err != nil {
			lgApi.Warn("unparseable inline confirmation", "err", err)
		}
	}
	if im, ok := ctx.Incoming(); ok && im.SenderID != "" {
		s.your = AgentId(im.SenderID)
	}
	ok := rcode == dns.RcodeSuccess && (inline.Status == "" || inline.Status == "ok" || inline.Status == "pending")
	if ok {
		return s.write(true, inline.Message, inline.Nonce)
	}
	msg := inline.Message
	if msg == "" {
		msg = dns.RcodeToString[rcode]
	}
	return s.write(false, msg, inline.Nonce)
}

func (s *apiReplySink) Fail(rcode int) error {
	return s.fail(rcodeReason(rcode))
}

func (s *apiReplySink) fail(msg string) error {
	return s.write(false, msg, "")
}

// rcodeReason words a pre-routing refusal the way the endpoints did.
func rcodeReason(rcode int) string {
	switch rcode {
	case dns.RcodeFormatError:
		return "Invalid request format"
	case dns.RcodeRefused:
		return "not authorized"
	}
	return "request failed: " + dns.RcodeToString[rcode]
}

// write encodes the endpoint's response object.
func (s *apiReplySink) write(ok bool, msg, nonce string) error {
	if s.done {
		return nil
	}
	s.done = true
	now := time.Now()
	var resp interface{}
	switch s.kind {
	case apiEndpointHello:
		r := AgentHelloResponse{MyIdentity: s.local, YourIdentity: s.your, Time: now}
		if ok {
			r.Status = "ok"
			r.Msg = msg
		} else {
			r.Error = true
			r.ErrorMsg = msg
		}
		resp = r
	case apiEndpointBeat:
		r := AgentBeatResponse{MyIdentity: s.local, YourIdentity: s.your, Time: now}
		if ok {
			r.Status = "ok"
			r.Msg = msg
		} else {
			r.Error = true
			r.ErrorMsg = msg
		}
		resp = r
	case apiEndpointPing:
		r := AgentPingResponse{MyIdentity: s.local, YourIdentity: s.your, Nonce: nonce, Time: now}
		if ok {
			r.Status = "ok"
		} else {
			r.Error = true
			r.ErrorMsg = msg
		}
		resp = r
	default:
		r := AgentMsgResponse{AgentId: s.local, Time: now}
		if ok {
			r.Status = "ok"
			r.Msg = msg
		} else {
			r.Status = "error"
			r.Error = true
			r.ErrorMsg = msg
		}
		resp = r
	}
	s.w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(s.w).Encode(resp); err != nil {
		lgApi.Error("error encoding sync API response", "err", err)
		return err
	}
	return nil
}
