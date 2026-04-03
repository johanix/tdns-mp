/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor message handler goroutine.
 * Consumes beat, hello, ping, and sync messages from MsgQs.
 * Receives everything, logs events, updates state — but never sends zone data.
 */
package tdnsmp

import (
	"context"
	"fmt"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

var lgAuditor = tdns.Logger("auditor")

// AuditorMsgHandler consumes beat, hello, ping, and sync messages from MsgQs.
// It logs all events to the persistent event log and updates in-memory state
// but never sends zone data.
func AuditorMsgHandler(ctx context.Context, conf *Config, msgQs *MsgQs,
	stateManager *AuditStateManager) {
	if msgQs == nil {
		lgAuditor.Warn("no MsgQs configured, exiting")
		return
	}

	registry := conf.InternalMp.AgentRegistry
	kdb := conf.Config.Internal.KeyDB

	lgAuditor.Info("auditor message handler starting",
		"registry", registry != nil)

	for {
		select {
		case <-ctx.Done():
			lgAuditor.Info("context cancelled, stopping")
			return

		case report := <-msgQs.Beat:
			if report == nil {
				continue
			}
			senderID := string(report.Identity)
			lgAuditor.Debug("beat received", "sender", senderID,
				"interval", report.BeatInterval)

			// Delegate to registry for gossip processing
			if registry != nil {
				registry.HeartbeatHandler(report)
			}

			// Update audit state for this sender's zone
			if report.Zone != "" {
				zs := stateManager.GetOrCreateZone(string(report.Zone))
				zs.UpdateProviderBeat(senderID, "", "", false)
			}

		case report := <-msgQs.Hello:
			if report == nil {
				continue
			}
			senderID := string(report.Identity)
			lgAuditor.Info("hello received", "sender", senderID)

			// Delegate to registry for HELLO processing
			if registry != nil {
				registry.HelloHandler(report)
			}

			if kdb != nil {
				InsertAuditEvent(kdb, &AuditEvent{
					Time:       time.Now(),
					Zone:       string(report.Zone),
					Originator: senderID,
					EventType:  "hello",
					Summary:    fmt.Sprintf("HELLO from %s", senderID),
				})
			}

		case report := <-msgQs.Ping:
			if report == nil {
				continue
			}
			lgAuditor.Debug("ping received", "sender", string(report.Identity))

		case msg := <-msgQs.Msg:
			if msg == nil {
				continue
			}
			senderID := string(msg.OriginatorID)
			deliveredBy := string(msg.DeliveredBy)
			if deliveredBy == "" {
				deliveredBy = senderID
			}
			zone := string(msg.Zone)

			// Handle RFI: respond with empty data
			if msg.MessageType == tdns.AgentMsgRfi {
				lgAuditor.Info("RFI received (responding empty)",
					"type", msg.RfiType, "sender", senderID, "zone", zone)
				if kdb != nil {
					InsertAuditEvent(kdb, &AuditEvent{
						Time:       time.Now(),
						Zone:       zone,
						Originator: senderID,
						EventType:  "rfi",
						Summary:    fmt.Sprintf("RFI %s from %s (responded empty)", msg.RfiType, senderID),
					})
				}
				continue
			}

			// Log sync/update events
			lgAuditor.Info("sync/update received",
				"sender", senderID, "deliveredBy", deliveredBy,
				"zone", zone, "distrib", msg.DistributionID,
				"records", len(msg.Records), "operations", len(msg.Operations))

			// Count RRs for audit state
			rrCounts := make(map[string]map[uint16]int)
			added := 0
			removed := 0
			var rrtypeSet []string
			rrtypeSeen := make(map[string]bool)

			for owner, rrs := range msg.Records {
				if rrCounts[owner] == nil {
					rrCounts[owner] = make(map[uint16]int)
				}
				for range rrs {
					added++
				}
			}
			for _, op := range msg.Operations {
				if !rrtypeSeen[op.RRtype] {
					rrtypeSeen[op.RRtype] = true
					rrtypeSet = append(rrtypeSet, op.RRtype)
				}
				switch op.Operation {
				case "add", "replace":
					added += len(op.Records)
				case "delete":
					removed += len(op.Records)
				}
			}

			// Update audit state
			zs := stateManager.GetOrCreateZone(zone)
			zs.UpdateProviderSync(senderID, rrCounts)

			// Log event
			if kdb != nil {
				summary := fmt.Sprintf("%s from %s: +%d/-%d RRs",
					msg.MessageType, senderID, added, removed)
				InsertAuditEvent(kdb, &AuditEvent{
					Time:        time.Now(),
					Zone:        zone,
					Originator:  senderID,
					DeliveredBy: deliveredBy,
					EventType:   string(msg.MessageType),
					Summary:     summary,
					RRsAdded:    added,
					RRsRemoved:  removed,
					RRtypes:     strings.Join(rrtypeSet, ","),
				})
			}

		case confirm := <-msgQs.Confirmation:
			if confirm == nil {
				continue
			}
			lgAuditor.Debug("confirmation received",
				"zone", confirm.Zone, "distrib", confirm.DistributionID,
				"status", confirm.Status)

			if kdb != nil {
				InsertAuditEvent(kdb, &AuditEvent{
					Time:       time.Now(),
					Zone:       string(confirm.Zone),
					Originator: confirm.Source,
					EventType:  "confirm",
					Summary: fmt.Sprintf("CONFIRM %s from %s (distrib %s)",
						confirm.Status, confirm.Source, confirm.DistributionID),
				})
			}

		case statusMsg := <-msgQs.StatusUpdate:
			if statusMsg == nil {
				continue
			}
			lgAuditor.Debug("status-update received",
				"zone", statusMsg.Zone, "subtype", statusMsg.SubType,
				"sender", statusMsg.SenderID)
		}
	}
}
