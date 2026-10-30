/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Debug injector for the messages no honest daemon sends: the three
 * sender-rule cases (tdns-mp #261), and hellos at a rate no honest agent
 * sends them (#265). The transport, the keys and this agent's identity stay
 * real. Only the payload lies, or the rate.
 */

package tdnsmp

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// debugSyncRequest is the SYNC send-sync-to sends: one add per RR type, as
// operations. A receiving agent takes what a SYNC carries from its
// operations only (MsgHandler); records grouped by owner are not read, and
// a SYNC that carried only those arrived empty.
func debugSyncRequest(sender, zone string, rrs []string, distID string) (*PeerSyncRequest, error) {
	req := &PeerSyncRequest{
		SenderID:       sender,
		Zone:           zone,
		SyncType:       PeerSyncTypeNS,
		DistributionID: distID,
		MessageType:    "sync",
	}
	if len(rrs) == 0 {
		return req, nil
	}
	ops, err := injectAddOperations(rrs)
	if err != nil {
		return nil, err
	}
	req.Operations = ops
	return req, nil
}

// injectNamedSenderRequest is the SYNC send-sync-to sends, with one
// difference: the payload names named. syncAppMessage puts that name in
// OriginatorID. The transport still sends as this agent.
func injectNamedSenderRequest(zone, named string, rrs []string, distID string) (*PeerSyncRequest, error) {
	return debugSyncRequest(named, zone, rrs, distID)
}

// injectReplaceRequest is a SYNC from sender whose one operation replaces
// sender's set of one RR type with rrs, and whose time is origin. An honest
// agent stamps a REPLACE with the time it enqueued it. The recipient keeps,
// per zone, sending agent and RR type, the origin of the last REPLACE it
// applied, and ignores an older one (#249); this one claims any origin, so
// a test can send one older, or newer, than that.
func injectReplaceRequest(sender, zone string, rrs []string, origin time.Time, distID string) (*PeerSyncRequest, error) {
	if len(rrs) == 0 {
		return nil, fmt.Errorf("at least one RR is required")
	}
	var rrtype uint16
	records := make([]string, 0, len(rrs))
	for _, rrStr := range rrs {
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RR %q: %v", rrStr, err)
		}
		if rr == nil {
			return nil, fmt.Errorf("no RR in %q", rrStr)
		}
		t := rr.Header().Rrtype
		if rrtype != 0 && t != rrtype {
			return nil, fmt.Errorf("a replace carries one RR type, not %s and %s",
				dns.TypeToString[rrtype], dns.TypeToString[t])
		}
		rrtype = t
		records = append(records, rr.String())
	}
	return &PeerSyncRequest{
		SenderID: sender,
		Zone:     zone,
		Operations: []core.RROperation{{
			Operation: "replace",
			RRtype:    dns.TypeToString[rrtype],
			Records:   records,
		}},
		Timestamp:      origin,
		DistributionID: distID,
		MessageType:    "sync",
	}, nil
}

// injectCombinerUpdate is an update for this agent's own combiner whose
// originator is origin. deliverGenericMessage sends an update to the
// combiner with SenderID set from AgentId.
func injectCombinerUpdate(zone, origin string, rrs []string) (*ZoneUpdate, error) {
	ops, err := injectAddOperations(rrs)
	if err != nil {
		return nil, err
	}
	return &ZoneUpdate{
		Zone:       ZoneName(zone),
		AgentId:    AgentId(origin),
		Operations: ops,
	}, nil
}

// injectAddOperations is one add per RR type, in the order the types first
// appear.
func injectAddOperations(rrs []string) ([]core.RROperation, error) {
	if len(rrs) == 0 {
		return nil, fmt.Errorf("at least one RR is required")
	}
	var order []uint16
	records := map[uint16][]string{}
	for _, rrStr := range rrs {
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RR %q: %v", rrStr, err)
		}
		if rr == nil {
			// An empty or comment-only string parses to no record and no error.
			return nil, fmt.Errorf("no RR in %q", rrStr)
		}
		t := rr.Header().Rrtype
		if _, seen := records[t]; !seen {
			order = append(order, t)
		}
		records[t] = append(records[t], rr.String())
	}
	ops := make([]core.RROperation, 0, len(order))
	for _, t := range order {
		ops = append(ops, core.RROperation{
			Operation: "add",
			RRtype:    dns.TypeToString[t],
			Records:   records[t],
		})
	}
	return ops, nil
}

// injectKeystateRequest is an empty KEYSTATE inventory from sender. An
// honest agent never sends one to another provider's agent.
func injectKeystateRequest(sender, zone string) *PeerKeystateRequest {
	return inventoryRequest(sender, zone, nil, false, nil, inventoryMarks{})
}

func debugPostString(data map[string]interface{}, key string) string {
	if data == nil {
		return ""
	}
	s, _ := data[key].(string)
	return s
}

// injectRefused reports that this agent will not forge a payload. The
// management key can already ask for send-sync-to; these three commands
// put words in another identity's mouth, so they stay off unless
// agent-options lists allow-inject.
func (conf *Config) injectRefused(resp *AgentMgmtResponse) bool {
	mp := conf.MpConfig()
	if mp != nil && mp.AgentOptions[AgentOptAllowInject] {
		return false
	}
	resp.Error = true
	resp.ErrorMsg = "inject is refused unless agent-options includes allow-inject"
	return true
}

// sendSyncOnce sends the SYNC on the mechanism SelectTransport picks and
// not on the other one. A NOTIFY answered REFUSED is a retryable error, so
// Send would deliver the same lie again on the fallback. The returned name
// is that mechanism, so the caller can say which receive path was tested.
func (tm *MPTransportBridge) sendSyncOnce(ctx context.Context, peer *transport.Peer, req *PeerSyncRequest) (*PeerSyncResponse, string, error) {
	if tm == nil || tm.TransportManager == nil || peer == nil {
		return nil, "", fmt.Errorf("no transport for peer")
	}
	primary := tm.TransportManager.SelectTransport(peer)
	if primary == nil {
		return nil, "", fmt.Errorf("no usable transport for peer %s", peer.ID)
	}
	msg, err := syncAppMessage(req, peer.ID)
	if err != nil {
		return nil, primary.Name(), err
	}
	resp, err := primary.SendApp(ctx, peer, msg)
	if err != nil {
		return nil, primary.Name(), err
	}
	return syncResponseFromApp(req, resp), primary.Name(), nil
}

// injectSendError puts the error of an inject's send in its receipt. An
// answer of REFUSED is the recipient's verdict, an outcome of the inject as
// much as a SYNC it takes: the receipt says REFUSED and the command
// succeeds. Any other error is a send that did not happen, or that no
// verdict came back for, and the command fails (#277). The receipt goes
// with the failure, so the CLI still prints the distribution and the
// transport before it exits non-zero.
func injectSendError(resp *AgentMgmtResponse, data map[string]interface{}, err error) {
	if answeredRefused(err) {
		data["status"] = "REFUSED"
		return
	}
	data["error"] = err.Error()
	resp.Error = true
	resp.ErrorMsg = "the send failed: " + err.Error()
}

func (conf *Config) debugInjectNamedSender(amp AgentMgmtPost, resp *AgentMgmtResponse) {
	if conf.injectRefused(resp) {
		return
	}
	if amp.AgentId == "" {
		resp.Error = true
		resp.ErrorMsg = "target agent ID (--to) is required"
		return
	}
	if amp.Zone == "" {
		resp.Error = true
		resp.ErrorMsg = "zone is required"
		return
	}
	if conf.InternalMp.TransportManager == nil || conf.InternalMp.MPTransport == nil {
		resp.Error = true
		resp.ErrorMsg = "TransportManager not available (DNS transport not configured)"
		return
	}
	agent, exists := conf.InternalMp.AgentRegistry.S.Get(amp.AgentId)
	if !exists {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("target agent %q not found in registry", amp.AgentId)
		return
	}
	for _, rrStr := range amp.RRs {
		if _, err := dns.NewRR(rrStr); err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("failed to parse RR %q: %v", rrStr, err)
			return
		}
	}
	named := debugPostString(amp.Data, "as")
	if named == "" {
		resp.Error = true
		resp.ErrorMsg = "named sender (--as) is required"
		return
	}

	distID := fmt.Sprintf("debug-inject-named-sender-%d", time.Now().Unix())
	syncReq, err := injectNamedSenderRequest(string(amp.Zone), named, amp.RRs, distID)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = err.Error()
		return
	}
	peer := conf.InternalMp.MPTransport.GetOrCreatePeer(agent)

	syncResp, via, err := conf.InternalMp.MPTransport.sendSyncOnce(context.Background(), peer, syncReq)
	lgApi.Warn("inject: named-sender", "target", amp.AgentId, "zone", amp.Zone, "named", named, "transport", via)

	data := map[string]interface{}{
		"distribution_id": distID,
		"target":          string(amp.AgentId),
		"zone":            string(amp.Zone),
		"named":           named,
		"transport":       via,
	}
	if err != nil {
		injectSendError(resp, data, err)
	} else if syncResp != nil {
		data["status"] = syncResp.Status.String()
		data["message"] = syncResp.Message
	}
	resp.Data = data
	resp.Msg = fmt.Sprintf("inject named-sender to %s for zone %s", amp.AgentId, amp.Zone)
	if !resp.Error {
		resp.Status = "ok"
	}
}

// debugInjectReplace sends the target one REPLACE from this agent that
// claims the origin the operator gave. The sender is this agent, under its
// own identity and keys; only the time lies.
func (conf *Config) debugInjectReplace(parent context.Context, mp *MultiProviderConf, amp AgentMgmtPost, resp *AgentMgmtResponse) {
	if conf.injectRefused(resp) {
		return
	}
	if amp.AgentId == "" {
		resp.Error = true
		resp.ErrorMsg = "target agent ID (--to) is required"
		return
	}
	if amp.Zone == "" {
		resp.Error = true
		resp.ErrorMsg = "zone is required"
		return
	}
	originStr := debugPostString(amp.Data, "origin_time")
	if originStr == "" {
		resp.Error = true
		resp.ErrorMsg = "origin time (--origin-time) is required"
		return
	}
	origin, err := time.Parse(time.RFC3339Nano, originStr)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("origin time %q is not RFC 3339: %v", originStr, err)
		return
	}
	// The recipient judges a REPLACE only when its origin is set: a zero
	// origin (0001-01-01T00:00:00Z) would be applied unjudged.
	if origin.IsZero() {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("origin time %q is the zero time, which the recipient does not judge", originStr)
		return
	}
	distID := fmt.Sprintf("debug-inject-replace-%d", time.Now().UnixNano())
	syncReq, err := injectReplaceRequest(mp.Identity, string(amp.Zone), amp.RRs, origin, distID)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = err.Error()
		return
	}
	if conf.InternalMp.TransportManager == nil || conf.InternalMp.MPTransport == nil {
		resp.Error = true
		resp.ErrorMsg = "TransportManager not available (DNS transport not configured)"
		return
	}
	agent, exists := conf.InternalMp.AgentRegistry.S.Get(amp.AgentId)
	if !exists {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("target agent %q not found in registry", amp.AgentId)
		return
	}
	peer := conf.InternalMp.MPTransport.GetOrCreatePeer(agent)
	rrtype := syncReq.Operations[0].RRtype
	originOut := origin.UTC().Format(time.RFC3339Nano)

	syncResp, via, err := conf.InternalMp.MPTransport.sendSyncOnce(parent, peer, syncReq)
	lgApi.Warn("inject: replace", "target", amp.AgentId, "zone", amp.Zone, "rrtype", rrtype,
		"origin", originOut, "transport", via)

	data := map[string]interface{}{
		"distribution_id": distID,
		"target":          string(amp.AgentId),
		"zone":            string(amp.Zone),
		"rrtype":          rrtype,
		"origin_time":     originOut,
		"transport":       via,
	}
	if err != nil {
		injectSendError(resp, data, err)
	} else if syncResp != nil {
		data["status"] = syncResp.Status.String()
		data["message"] = syncResp.Message
	}
	resp.Data = data
	resp.Msg = fmt.Sprintf("inject replace of %s to %s for zone %s", rrtype, amp.AgentId, amp.Zone)
	if !resp.Error {
		resp.Status = "ok"
	}
}

func (conf *Config) debugInjectCombinerOrigin(amp AgentMgmtPost, resp *AgentMgmtResponse) {
	if conf.injectRefused(resp) {
		return
	}
	if amp.Zone == "" {
		resp.Error = true
		resp.ErrorMsg = "zone is required"
		return
	}
	origin := debugPostString(amp.Data, "origin")
	if origin == "" {
		resp.Error = true
		resp.ErrorMsg = "origin (--origin) is required"
		return
	}
	if conf.InternalMp.MPTransport == nil {
		resp.Error = true
		resp.ErrorMsg = "TransportManager not available (DNS transport not configured)"
		return
	}
	update, err := injectCombinerUpdate(string(amp.Zone), origin, amp.RRs)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = err.Error()
		return
	}
	combinerID, err := conf.InternalMp.MPTransport.getCombinerID()
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = err.Error()
		return
	}

	distID := fmt.Sprintf("debug-inject-combiner-origin-%d", time.Now().Unix())
	lgApi.Warn("inject: combiner-origin", "combiner", combinerID, "zone", amp.Zone, "origin", origin)

	data := map[string]interface{}{
		"distribution_id": distID,
		"combiner":        string(combinerID),
		"zone":            string(amp.Zone),
		"origin":          origin,
	}
	// The combiner's verdict comes later, off the queue; an update that is
	// not queued is never sent, and the command fails (#277).
	if _, err := conf.InternalMp.MPTransport.EnqueueForCombiner(amp.Zone, update, distID); err != nil {
		data["error"] = err.Error()
		resp.Error = true
		resp.ErrorMsg = "the update was not queued for the combiner: " + err.Error()
	}
	resp.Data = data
	resp.Msg = fmt.Sprintf("inject combiner-origin %s for zone %s", origin, amp.Zone)
	if !resp.Error {
		resp.Status = "ok"
	}
}

func (conf *Config) debugInjectPeerKeystate(mp *MultiProviderConf, amp AgentMgmtPost, resp *AgentMgmtResponse) {
	if conf.injectRefused(resp) {
		return
	}
	if amp.AgentId == "" {
		resp.Error = true
		resp.ErrorMsg = "target agent ID (--to) is required"
		return
	}
	if amp.Zone == "" {
		resp.Error = true
		resp.ErrorMsg = "zone is required"
		return
	}
	tm := conf.InternalMp.MPTransport
	if tm == nil || tm.PeerRegistry == nil || tm.DNSTransport == nil {
		resp.Error = true
		resp.ErrorMsg = "TransportManager not available (DNS transport not configured)"
		return
	}
	peer, exists := tm.PeerRegistry.Get(string(amp.AgentId))
	if !exists || peer == nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("agent %q not found in PeerRegistry", amp.AgentId)
		return
	}

	req := injectKeystateRequest(mp.Identity, string(amp.Zone))
	lgApi.Warn("inject: peer-keystate", "target", amp.AgentId, "zone", amp.Zone, "sender", mp.Identity)

	sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ksResp, err := tm.sendKeystate(sendCtx, peer, req)

	data := map[string]interface{}{
		"target": string(amp.AgentId),
		"zone":   string(amp.Zone),
	}
	if err != nil {
		injectSendError(resp, data, err)
	} else if ksResp != nil {
		data["accepted"] = ksResp.Accepted
		data["status"] = "NOT ACCEPTED"
		if ksResp.Accepted {
			data["status"] = "ACCEPTED"
		}
		data["message"] = ksResp.Message
	}
	resp.Data = data
	resp.Msg = fmt.Sprintf("inject peer-keystate to %s for zone %s", amp.AgentId, amp.Zone)
	if !resp.Error {
		resp.Status = "ok"
	}
}

// The bounds of an inject hello: enough hellos to show the bound on the beats
// back they draw (#131), and never a flood.
const (
	injectHelloDefaultCount    = 40
	injectHelloMaxCount        = 200
	injectHelloDefaultInterval = 500 * time.Millisecond
	injectHelloMinInterval     = 100 * time.Millisecond
	injectHelloMaxInterval     = 10 * time.Second
)

// injectHelloParams reads an inject hello's count, interval and mechanism
// from the post's data, with the CLI's defaults, and refuses a value outside
// the bounds. The mechanism is the transport manager's name for it.
func injectHelloParams(data map[string]interface{}) (count int, interval time.Duration, mech string, err error) {
	count, interval, mech = injectHelloDefaultCount, injectHelloDefaultInterval, "DNS"
	if s := debugPostString(data, "count"); s != "" {
		if count, err = strconv.Atoi(s); err != nil {
			return 0, 0, "", fmt.Errorf("count %q: %v", s, err)
		}
	}
	if count < 1 || count > injectHelloMaxCount {
		return 0, 0, "", fmt.Errorf("count %d: must be 1 to %d", count, injectHelloMaxCount)
	}
	if s := debugPostString(data, "interval"); s != "" {
		if interval, err = time.ParseDuration(s); err != nil {
			return 0, 0, "", fmt.Errorf("interval %q: %v", s, err)
		}
	}
	if interval < injectHelloMinInterval || interval > injectHelloMaxInterval {
		return 0, 0, "", fmt.Errorf("interval %s: must be %s to %s", interval, injectHelloMinInterval, injectHelloMaxInterval)
	}
	switch m := strings.ToLower(debugPostString(data, "mechanism")); m { // not-a-name: a transport mechanism
	case "", "dns":
		mech = "DNS"
	case "api":
		mech = "API"
	default:
		return 0, 0, "", fmt.Errorf("mechanism %q: must be dns or api", m)
	}
	return count, interval, mech, nil
}

// injectHelloRequest is the hello SendHelloWithFallback sends: it names this
// agent, not the target, and the zones the two share.
func injectHelloRequest(sender string, shared []ZoneName) *transport.HelloRequest {
	zones := make([]string, 0, len(shared))
	for _, z := range shared {
		zones = append(zones, string(z))
	}
	return &transport.HelloRequest{
		SenderID:     sender,
		Capabilities: []string{"sync", "beat", "relocate"},
		SharedZones:  zones,
		Timestamp:    time.Now(),
	}
}

// debugInjectHello sends the target a hello count times, interval apart, on
// one mechanism, whatever this agent's reading of the target: an honest
// agent sends a hello only on a mechanism that is not introduced yet
// (SendHelloWithFallback), and no faster than hello_fast_interval. The
// target beats back on each hello from a peer it has introduced, and #131
// bounds those beats back. The injector changes nothing in this agent's view
// of the target: no mechanism state, no note of an accepted or refused hello.
// A hello the target refuses is an outcome; one that fails (no answer, or
// another error than REFUSED) did not reach it. The command fails only when
// no hello reached the target (#277), with the counts in its receipt.
// The loop runs under the API request's context: a request that is given up
// stops it.
func (conf *Config) debugInjectHello(parent context.Context, amp AgentMgmtPost, resp *AgentMgmtResponse) {
	if conf.injectRefused(resp) {
		return
	}
	if amp.AgentId == "" {
		resp.Error = true
		resp.ErrorMsg = "target agent ID (--to) is required"
		return
	}
	count, interval, mech, err := injectHelloParams(amp.Data)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = err.Error()
		return
	}
	tm := conf.InternalMp.MPTransport
	// The mechanisms this agent is configured to use (supported_mechanisms)
	// bound the injector too: the API client exists whatever the
	// configuration says. Only the rate lies, not the mechanism.
	if tm != nil && !tm.isTransportSupported(strings.ToLower(mech)) { // not-a-name: a transport mechanism
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("this agent does not use the %s mechanism (supported_mechanisms)", strings.ToLower(mech)) // not-a-name: a transport mechanism
		return
	}
	if conf.InternalMp.TransportManager == nil || tm == nil || tm.TransportManager == nil {
		resp.Error = true
		resp.ErrorMsg = "TransportManager not available (DNS transport not configured)"
		return
	}
	if (mech == "DNS" && tm.DNSTransport == nil) || (mech == "API" && tm.APITransport == nil) {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("this agent has no %s transport", mech)
		return
	}
	ar := conf.InternalMp.AgentRegistry
	if ar == nil {
		resp.Error = true
		resp.ErrorMsg = "agent registry not available"
		return
	}
	agent, exists := ar.S.Get(amp.AgentId)
	if !exists {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("target agent %q not found in registry", amp.AgentId)
		return
	}
	peer := tm.GetOrCreatePeer(agent)
	shared := ar.sharedParticipantZones(amp.AgentId)

	lgApi.Warn("inject: hello", "target", amp.AgentId, "mechanism", mech, "count", count, "interval", interval)
	ctx, cancel := context.WithTimeout(parent, time.Duration(count)*(interval+5*time.Second))
	defer cancel()
	sent, accepted, refused, failed, firstErr := 0, 0, 0, 0, ""
	noteErr := func(e string) {
		if firstErr == "" {
			firstErr = e
		}
	}
	for i := 0; i < count && ctx.Err() == nil; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(interval):
			}
			if ctx.Err() != nil {
				break
			}
		}
		results := tm.TransportManager.SendAll(ctx, peer, []string{mech}, injectHelloRequest(tm.LocalID, shared))
		sent++
		r, err := helloResult(results[mech])
		switch {
		case answeredRefused(err):
			refused++
			noteErr(err.Error())
		case err != nil:
			failed++
			noteErr(err.Error())
		case r == nil:
			failed++
			noteErr("no answer")
		case !r.Accepted:
			refused++
			if r.RejectReason != "" {
				noteErr("not accepted: " + r.RejectReason)
			} else {
				noteErr("not accepted")
			}
		default:
			accepted++
		}
	}
	resp.Data = map[string]interface{}{
		"target":      string(amp.AgentId),
		"mechanism":   mech,
		"count":       strconv.Itoa(count),
		"sent":        strconv.Itoa(sent),
		"accepted":    strconv.Itoa(accepted),
		"refused":     strconv.Itoa(refused),
		"failed":      strconv.Itoa(failed),
		"first_error": firstErr,
	}
	resp.Msg = fmt.Sprintf("inject hello to %s: %d sent", amp.AgentId, sent)
	if accepted+refused == 0 {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("no hello reached %s: %d of %d sent, %d failed", amp.AgentId, sent, count, failed)
		return
	}
	resp.Status = "ok"
}
