/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Application-side send path (transport redesign, Stage C2).
 *
 * Before C2 tdns-transport owned one typed send method per verb
 * (DNSTransport.Sync/Keystate/Edits/Config/Audit/SendStatusUpdate) and
 * built the wire payload from core.* structs itself. Since C2 transport
 * carries one opaque AppMessage; the payload builders live here and
 * marshal the SAME core.* structs the typed methods did, so the bytes on
 * the wire are unchanged (locked by golden_send_test.go).
 */

package tdnsmp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
)

// syncAppMessage builds the sync-family carrier ("sync", "update", "rfi")
// exactly as DNSTransport.Sync marshalled it: a core.AgentMsgPost.
func syncAppMessage(req *transport.SyncRequest, peerID string) (*transport.AppMessage, error) {
	messageType := core.AgentMsg(req.MessageType)
	if messageType == "" {
		messageType = core.AgentMsgNotify // default to sync
	}
	payload := &core.AgentMsgPost{
		MessageType:  messageType,
		OriginatorID: req.SenderID,
		YourIdentity: peerID,
		Zone:         req.Zone,
		Records:      req.Records,
		Operations:   req.Operations,
		Time:         req.Timestamp,
		RfiType:      req.RfiType,
		RfiSubtype:   req.RfiSubtype,
		Nonce:        req.Nonce,
		ZoneClass:    req.ZoneClass,
		Publish:      req.Publish,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal %s payload: %w", messageType, err)
	}
	return &transport.AppMessage{
		Scope:          req.Zone,
		TypeToken:      string(messageType),
		Payload:        b,
		DistributionID: req.DistributionID,
	}, nil
}

func syncResponseFromApp(req *transport.SyncRequest, resp *transport.AppResponse) *transport.SyncResponse {
	return &transport.SyncResponse{
		ResponderID:    resp.ResponderID,
		Zone:           req.Zone,
		DistributionID: resp.DistributionID,
		Status:         resp.Status,
		Message:        resp.Message,
		Timestamp:      resp.Timestamp,
		AppliedRecords: resp.AppliedRecords,
		RemovedRecords: resp.RemovedRecords,
		RejectedItems:  resp.RejectedItems,
		Truncated:      resp.Truncated,
	}
}

// keystateAppMessage mirrors DNSTransport.Keystate (core.AgentKeystatePost).
func keystateAppMessage(req *transport.KeystateRequest, peerID string) (*transport.AppMessage, error) {
	var coreInventory []core.KeyInventoryEntry
	for _, e := range req.KeyInventory {
		coreInventory = append(coreInventory, core.KeyInventoryEntry{
			KeyTag:    e.KeyTag,
			Algorithm: e.Algorithm,
			Flags:     e.Flags,
			State:     e.State,
			KeyRR:     e.KeyRR,
		})
	}
	payload := &core.AgentKeystatePost{
		MessageType:  core.AgentMsgKeystate,
		MyIdentity:   req.SenderID,
		YourIdentity: peerID,
		Zone:         req.Zone,
		KeyTag:       req.KeyTag,
		Algorithm:    req.Algorithm,
		Signal:       req.Signal,
		Message:      req.Message,
		KeyInventory: coreInventory,
		Time:         req.Timestamp,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal keystate payload: %w", err)
	}
	return &transport.AppMessage{Scope: req.Zone, TypeToken: "keystate", Payload: b}, nil
}

// editsAppMessage mirrors DNSTransport.Edits (core.AgentEditsPost).
func editsAppMessage(req *transport.EditsRequest, peerID string) (*transport.AppMessage, error) {
	payload := &core.AgentEditsPost{
		MessageType:  core.AgentMsgEdits,
		MyIdentity:   req.SenderID,
		YourIdentity: peerID,
		Zone:         req.Zone,
		AgentRecords: req.AgentRecords,
		Message:      req.Message,
		Time:         req.Timestamp,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal edits payload: %w", err)
	}
	return &transport.AppMessage{Scope: req.Zone, TypeToken: "edits", Payload: b}, nil
}

// configAppMessage mirrors DNSTransport.Config (core.AgentConfigPost).
func configAppMessage(req *transport.ConfigRequest, peerID string) (*transport.AppMessage, error) {
	payload := &core.AgentConfigPost{
		MessageType:  core.AgentMsgConfig,
		MyIdentity:   req.SenderID,
		YourIdentity: peerID,
		Zone:         req.Zone,
		Subtype:      req.Subtype,
		ConfigData:   req.ConfigData,
		Message:      req.Message,
		Time:         req.Timestamp,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal config payload: %w", err)
	}
	return &transport.AppMessage{Scope: req.Zone, TypeToken: "config", Payload: b}, nil
}

// auditAppMessage mirrors DNSTransport.Audit (core.AgentAuditPost).
func auditAppMessage(req *transport.AuditRequest, peerID string) (*transport.AppMessage, error) {
	payload := &core.AgentAuditPost{
		MessageType:  core.AgentMsgAudit,
		MyIdentity:   req.SenderID,
		YourIdentity: peerID,
		Zone:         req.Zone,
		AuditData:    req.AuditData,
		Message:      req.Message,
		Time:         req.Timestamp,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal audit payload: %w", err)
	}
	return &transport.AppMessage{Scope: req.Zone, TypeToken: "audit", Payload: b}, nil
}

// statusUpdateAppMessage mirrors DNSTransport.SendStatusUpdate: it stamps
// the identities on the post and sends fire-and-forget.
func statusUpdateAppMessage(post *core.StatusUpdatePost, localID, peerID string) (*transport.AppMessage, error) {
	post.MessageType = core.AgentMsgStatusUpdate
	post.MyIdentity = localID
	post.YourIdentity = peerID
	b, err := json.Marshal(post)
	if err != nil {
		return nil, fmt.Errorf("marshal status-update payload: %w", err)
	}
	return &transport.AppMessage{Scope: post.Zone, TypeToken: "status-update", Payload: b, FireAndForget: true}, nil
}

// --- wrappers over the DNS mechanism (these verbs were DNS-only before C2) ---

func (tm *MPTransportBridge) sendAppDNS(ctx context.Context, peer *transport.Peer, msg *transport.AppMessage, err error) (*transport.AppResponse, error) {
	if err != nil {
		return nil, err
	}
	if tm.DNSTransport == nil {
		return nil, fmt.Errorf("%s: no DNS transport available", msg.TypeToken)
	}
	return tm.DNSTransport.SendApp(ctx, peer, msg)
}

func (tm *MPTransportBridge) sendKeystate(ctx context.Context, peer *transport.Peer, req *transport.KeystateRequest) (*transport.KeystateResponse, error) {
	msg, err := keystateAppMessage(req, peer.ID)
	resp, err := tm.sendAppDNS(ctx, peer, msg, err)
	if err != nil {
		return nil, err
	}
	return &transport.KeystateResponse{
		ResponderID: peer.ID,
		Zone:        req.Zone,
		KeyTag:      req.KeyTag,
		Signal:      req.Signal,
		Accepted:    resp.Status == transport.ConfirmSuccess,
		Message:     resp.Message,
		Timestamp:   time.Now(),
	}, nil
}

func (tm *MPTransportBridge) sendEdits(ctx context.Context, peer *transport.Peer, req *transport.EditsRequest) (*transport.EditsResponse, error) {
	msg, err := editsAppMessage(req, peer.ID)
	resp, err := tm.sendAppDNS(ctx, peer, msg, err)
	if err != nil {
		return nil, err
	}
	return &transport.EditsResponse{
		ResponderID: peer.ID,
		Zone:        req.Zone,
		Accepted:    resp.Status == transport.ConfirmSuccess,
		Message:     resp.Message,
		Timestamp:   time.Now(),
	}, nil
}

func (tm *MPTransportBridge) sendConfig(ctx context.Context, peer *transport.Peer, req *transport.ConfigRequest) (*transport.ConfigResponse, error) {
	msg, err := configAppMessage(req, peer.ID)
	resp, err := tm.sendAppDNS(ctx, peer, msg, err)
	if err != nil {
		return nil, err
	}
	return &transport.ConfigResponse{
		ResponderID: peer.ID,
		Zone:        req.Zone,
		Accepted:    resp.Status == transport.ConfirmSuccess,
		Message:     resp.Message,
		Timestamp:   time.Now(),
	}, nil
}

func (tm *MPTransportBridge) sendAudit(ctx context.Context, peer *transport.Peer, req *transport.AuditRequest) (*transport.AuditResponse, error) {
	msg, err := auditAppMessage(req, peer.ID)
	resp, err := tm.sendAppDNS(ctx, peer, msg, err)
	if err != nil {
		return nil, err
	}
	return &transport.AuditResponse{
		ResponderID: peer.ID,
		Zone:        req.Zone,
		Accepted:    resp.Status == transport.ConfirmSuccess,
		Message:     resp.Message,
		Timestamp:   time.Now(),
	}, nil
}

// sendStatusUpdate is fire-and-forget: no confirmation is awaited.
func (tm *MPTransportBridge) sendStatusUpdate(ctx context.Context, peer *transport.Peer, post *core.StatusUpdatePost) error {
	if tm.DNSTransport == nil {
		return fmt.Errorf("status-update: no DNS transport available")
	}
	msg, err := statusUpdateAppMessage(post, tm.DNSTransport.LocalID, peer.ID)
	_, err = tm.sendAppDNS(ctx, peer, msg, err)
	return err
}
