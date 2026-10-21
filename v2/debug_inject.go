/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Debug injector for the three sender-rule cases no honest daemon sends
 * (tdns-mp #261). The transport, the keys and this agent's identity stay
 * real. Only the payload lies.
 */

package tdnsmp

import (
	"context"
	"fmt"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// injectNamedSenderRequest is the SYNC send-sync-to sends, with one
// difference: the payload names named. syncAppMessage puts that name in
// OriginatorID. The transport still sends as this agent.
func injectNamedSenderRequest(zone, named string, rrs []string, distID string) *PeerSyncRequest {
	return &PeerSyncRequest{
		SenderID:       named,
		Zone:           zone,
		SyncType:       PeerSyncTypeNS,
		Records:        groupRRStringsByOwner(rrs),
		DistributionID: distID,
		MessageType:    "sync",
	}
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
	return inventoryRequest(sender, zone, nil, false, nil)
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
// Send would deliver the same lie again on the fallback.
func (tm *MPTransportBridge) sendSyncOnce(ctx context.Context, peer *transport.Peer, req *PeerSyncRequest) (*PeerSyncResponse, error) {
	msg, err := syncAppMessage(req, peer.ID)
	if err != nil {
		return nil, err
	}
	if tm == nil || tm.TransportManager == nil || peer == nil {
		return nil, fmt.Errorf("no transport for peer")
	}
	primary := tm.TransportManager.SelectTransport(peer)
	if primary == nil {
		return nil, fmt.Errorf("no usable transport for peer %s", peer.ID)
	}
	resp, err := primary.SendApp(ctx, peer, msg)
	if err != nil {
		return nil, err
	}
	return syncResponseFromApp(req, resp), nil
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
	syncReq := injectNamedSenderRequest(string(amp.Zone), named, amp.RRs, distID)
	peer := conf.InternalMp.MPTransport.GetOrCreatePeer(agent)

	lgApi.Warn("inject: named-sender", "target", amp.AgentId, "zone", amp.Zone, "named", named)

	data := map[string]interface{}{
		"distribution_id": distID,
		"target":          string(amp.AgentId),
		"zone":            string(amp.Zone),
		"named":           named,
	}
	syncResp, err := conf.InternalMp.MPTransport.sendSyncOnce(context.Background(), peer, syncReq)
	if err != nil {
		data["error"] = err.Error()
	} else if syncResp != nil {
		data["status"] = syncResp.Status.String()
		data["message"] = syncResp.Message
	}
	resp.Data = data
	resp.Msg = fmt.Sprintf("inject named-sender to %s for zone %s", amp.AgentId, amp.Zone)
	resp.Status = "ok"
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
	if _, err := conf.InternalMp.MPTransport.EnqueueForCombiner(amp.Zone, update, distID); err != nil {
		data["error"] = err.Error()
	}
	resp.Data = data
	resp.Msg = fmt.Sprintf("inject combiner-origin %s for zone %s", origin, amp.Zone)
	resp.Status = "ok"
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
		data["error"] = err.Error()
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
	resp.Status = "ok"
}
