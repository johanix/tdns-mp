/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The HTTPS mechanism's receive side (cleanup plan, step 5).
 *
 * The sync API endpoints (/hello, /beat, /sync/ping, /msg) hand the request
 * body and the client certificate's identity to the transport's receive
 * pipeline, RouteAPIPayload. That identity is the sender (the body names
 * the originator); the pipeline parses the body with parseAppPayload,
 * authorizes the sender at all and for the zone, runs the role's verb
 * table and delivers the message to the same queues a NOTIFY(CHUNK)
 * reaches. The reply the pipeline produces (the handler's
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
	"slices"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
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

// endpointVerbs are the verbs each endpoint takes, as before the endpoints
// entered the pipeline. Each endpoint has checks of its own (a hello must
// introduce the certificate's agent, a beat's answer carries gossip), so
// the endpoint, not the body, decides what may enter through it. /msg
// takes the sync family the HTTPS sender posts there (including config
// and audit answers to RFI), and the confirmations of it.
var endpointVerbs = map[apiEndpointKind][]string{
	apiEndpointHello: {"hello"},
	apiEndpointBeat:  {"beat"},
	apiEndpointPing:  {"ping"},
	apiEndpointMsg:   {"sync", "update", "rfi", "config", "audit", transport.VerbConfirm},
}

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
		// The verb and the sender the body names, before the pipeline
		// decides anything about it: the sender for the reply when no
		// certificate names one, the verb to hold the body to what this
		// endpoint takes.
		im, perr := parseAppPayload("", body, r.RemoteAddr)
		if perr != nil || im == nil {
			lgApi.Warn("unparseable sync API request", "path", r.URL.Path, "from", r.RemoteAddr, "err", perr)
			_ = sink.fail("Invalid request format")
			return
		}
		// The sender is the identity the connection authenticated: the
		// client certificate, whose CN the TLSA middleware has checked,
		// as a NOTIFY's sender is the identity in its query name. The
		// body names the originator, which for an update an agent
		// forwards to its combiner is the remote agent whose update it
		// is. It goes in canonical form, the form a peer is known by;
		// the certificate may spell the name otherwise.
		var sender string
		if cn, ok := clientIdentity(r); ok {
			sender = core.CanonicalizeName(dns.Fqdn(cn))
		}
		sink.your = AgentId(im.SenderID)
		if sender != "" {
			sink.your = AgentId(sender)
		}
		if !slices.Contains(endpointVerbs[kind], im.Token()) {
			lgApi.Warn("sync API request refused: this endpoint does not take the verb",
				"path", r.URL.Path, "from", r.RemoteAddr, "verb", im.Token(), "sender", im.SenderID)
			_ = sink.fail(fmt.Sprintf("message type %q is not accepted on %s", im.Token(), r.URL.Path))
			return
		}
		// On /hello, /beat and /sync/ping a peer speaks for itself: the
		// sender the body names is the identity of the certificate the
		// connection presented. The answer to a beat carries the gossip
		// built for that sender (plan decision 26), so a peer must not get
		// it by naming another, and a hello introduces only the agent that
		// sent it. A confirmation speaks for its sender too: the confirm
		// handler books it as the named sender's word on a distribution.
		// The rest of /msg is not held to this: an agent forwards a peer's
		// update to its combiner under that peer's name.
		if kind == apiEndpointHello || kind == apiEndpointBeat || kind == apiEndpointPing || im.Token() == transport.VerbConfirm {
			if cn, ok := clientIdentity(r); ok && dns.CanonicalName(cn) != dns.CanonicalName(im.SenderID) {
				lgApi.Warn("sync API request refused: the sender is not the client certificate's identity",
					"path", r.URL.Path, "from", r.RemoteAddr, "sender", im.SenderID, "certificate", cn)
				_ = sink.fail(fmt.Sprintf("sender %q is not the client certificate's identity", im.SenderID))
				return
			}
		}
		// A hello introduces the agent its body names in MyIdentity (the
		// hello handler reads that field), which the check above need not
		// have seen: the parser reads OriginatorID first. So a hello must
		// name the certificate's agent in MyIdentity; one that leaves it
		// empty, or names another, is refused.
		if kind == apiEndpointHello {
			if cn, ok := clientIdentity(r); ok {
				var hello struct{ MyIdentity string }
				_ = json.Unmarshal(body, &hello)
				if hello.MyIdentity == "" || dns.CanonicalName(cn) != dns.CanonicalName(hello.MyIdentity) {
					lgApi.Warn("sync API hello refused: it does not introduce the client certificate's agent",
						"path", r.URL.Path, "from", r.RemoteAddr, "introduces", hello.MyIdentity, "certificate", cn)
					_ = sink.fail(fmt.Sprintf("hello introduces %q, not the client certificate's identity", hello.MyIdentity))
					return
				}
			}
		}
		lgApi.Debug("received sync API request", "path", r.URL.Path, "from", r.RemoteAddr, "sender", sink.your, "originator", im.SenderID)
		if err := handler.RouteAPIPayload(r.Context(), body, r.RemoteAddr, sender, sink); err != nil {
			lgApi.Warn("sync API request failed", "path", r.URL.Path, "from", r.RemoteAddr, "err", err)
		}
	}
}

// clientIdentity is the identity of the client certificate the request
// presented: its common name.
func clientIdentity(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName, true
}

// apiReplySink shapes the pipeline's answer into the endpoint's response
// object. HTTP status is always 200 with the Error field set, which is
// what the endpoints returned before and what every sender checks.
type apiReplySink struct {
	kind   apiEndpointKind
	w      http.ResponseWriter
	local  AgentId
	your   AgentId
	gossip json.RawMessage // the beat handler's gossip for the sender
	done   bool
}

// inlineConfirm is what the handlers put in the reply payload: the
// transport's confirm and ping_confirm objects and the application's acks
// all carry the first three fields. The beat handler's confirm also
// carries the receiver's gossip for the sender, and the beat's answer
// passes it on, as the answer to a DNS beat does (plan decision 26).
type inlineConfirm struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Nonce   string          `json:"nonce"`
	Gossip  json.RawMessage `json:"Gossip"`
}

func (s *apiReplySink) Reply(ctx *transport.MessageContext, payload []byte, rcode int) error {
	var inline inlineConfirm
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &inline); err != nil {
			lgApi.Warn("unparseable inline confirmation", "err", err)
		}
	}
	if im, ok := ctx.Incoming(); ok && im.TransportSender != "" {
		s.your = AgentId(im.TransportSender)
	}
	s.gossip = inline.Gossip
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
		r := AgentBeatResponse{MyIdentity: s.local, YourIdentity: s.your, Time: now, Gossip: s.gossip}
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
