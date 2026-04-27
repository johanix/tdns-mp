/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor message handler goroutine.
 * Consumes beat, hello, ping, sync/update/rfi, and confirmation
 * messages from MsgQs. Receives everything, logs at info, and never
 * sends zone data.
 *
 * Phase A scope: this is the minimal observer — it delegates beat/
 * hello processing to AgentRegistry (which drives gossip merging
 * and HSYNC3 authorization) and otherwise just logs. Persistent
 * event log and in-memory AuditZoneState come in Phase B.
 */
package tdnsmp

import (
	"context"

	tdns "github.com/johanix/tdns/v2"
)

var lgAuditor = tdns.Logger("auditor")

// AuditorMsgHandler consumes messages from MsgQs. It is the
// auditor's analogue of HsyncEngine, but without any outbound zone
// data sends.
func AuditorMsgHandler(ctx context.Context, conf *Config, msgQs *MsgQs) {
	if msgQs == nil {
		lgAuditor.Warn("no MsgQs configured, exiting")
		return
	}
	registry := conf.InternalMp.AgentRegistry

	lgAuditor.Info("auditor message handler starting", "registry", registry != nil)

	for {
		select {
		case <-ctx.Done():
			lgAuditor.Info("context cancelled, stopping")
			return

		case report := <-msgQs.Beat:
			if report == nil {
				continue
			}
			lgAuditor.Debug("beat received",
				"sender", report.Identity,
				"interval", report.BeatInterval,
				"transport", report.Transport)
			// Delegate to registry: gossip merge, peer-state update.
			if registry != nil {
				registry.HeartbeatHandler(report)
			}

		case report := <-msgQs.Hello:
			if report == nil {
				continue
			}
			lgAuditor.Info("hello received",
				"sender", report.Identity, "zone", report.Zone)
			if registry != nil {
				registry.HelloHandler(report)
			}

		case report := <-msgQs.Ping:
			if report == nil {
				continue
			}
			lgAuditor.Debug("ping received", "sender", report.Identity)

		case msg := <-msgQs.Msg:
			if msg == nil {
				continue
			}
			senderID := string(msg.OriginatorID)
			deliveredBy := string(msg.DeliveredBy)
			if deliveredBy == "" {
				deliveredBy = senderID
			}

			// RFI from a peer: respond empty to satisfy protocol
			// expectation. Phase A logs only; Phase E's rule 5
			// will wire an actual empty-SYNC response.
			if msg.MessageType == AgentMsgRfi {
				lgAuditor.Info("RFI received (no response sent yet — phase E)",
					"type", msg.RfiType, "sender", senderID, "zone", msg.Zone)
				continue
			}

			lgAuditor.Info("sync/update received",
				"sender", senderID, "deliveredBy", deliveredBy,
				"zone", msg.Zone, "msgType", msg.MessageType,
				"distrib", msg.DistributionID,
				"records", len(msg.Records),
				"operations", len(msg.Operations))

		case confirm := <-msgQs.Confirmation:
			if confirm == nil {
				continue
			}
			lgAuditor.Debug("confirmation received",
				"zone", confirm.Zone,
				"distrib", confirm.DistributionID,
				"status", confirm.Status,
				"source", confirm.Source)

		case statusMsg := <-msgQs.StatusUpdate:
			if statusMsg == nil {
				continue
			}
			lgAuditor.Debug("status-update received",
				"zone", statusMsg.Zone,
				"subtype", statusMsg.SubType,
				"sender", statusMsg.SenderID)
		}
	}
}
