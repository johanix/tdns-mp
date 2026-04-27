/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor message handler goroutine.
 * Consumes beat, hello, ping, sync/update/rfi, and confirmation
 * messages from MsgQs. Receives everything, persists notable events
 * to the AuditEventLog, updates in-memory AuditZoneState — but never
 * sends zone data.
 *
 * Phase B scope: persistent event log + in-memory zone state +
 * basic observation detection. Phase E will add the empty-SYNC
 * response to RFI required by behavioral rule 5.
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

// AuditorMsgHandler consumes messages from MsgQs. It is the
// auditor's analogue of HsyncEngine, but without any outbound zone
// data sends. Events are persisted to the AuditEventLog table and
// reflected in the in-memory AuditStateManager.
func AuditorMsgHandler(ctx context.Context, conf *Config, msgQs *MsgQs,
	stateManager *AuditStateManager) {
	if msgQs == nil {
		lgAuditor.Warn("no MsgQs configured, exiting")
		return
	}
	registry := conf.InternalMp.AgentRegistry
	kdb := conf.Config.Internal.KeyDB

	lgAuditor.Info("auditor message handler starting",
		"registry", registry != nil, "kdb", kdb != nil,
		"state", stateManager != nil)

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
			zone := string(report.Zone)
			lgAuditor.Debug("beat received",
				"sender", senderID,
				"interval", report.BeatInterval,
				"transport", report.Transport)
			// Delegate to registry: gossip merge, peer-state update.
			if registry != nil {
				registry.HeartbeatHandler(report)
			}
			if stateManager != nil && zone != "" {
				zs := stateManager.GetOrCreateZone(zone)
				zs.UpdateProviderBeat(senderID, "", "", false)
			}

		case report := <-msgQs.Hello:
			if report == nil {
				continue
			}
			senderID := string(report.Identity)
			zone := string(report.Zone)
			lgAuditor.Info("hello received", "sender", senderID, "zone", zone)
			if registry != nil {
				registry.HelloHandler(report)
			}
			logEvent(kdb, &AuditEvent{
				Time:       time.Now(),
				Zone:       zone,
				Originator: senderID,
				EventType:  "hello",
				Summary:    fmt.Sprintf("HELLO from %s", senderID),
			})

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

			// RFI from a peer: log only. Phase E's rule 5 will wire
			// an actual empty-SYNC response.
			if msg.MessageType == AgentMsgRfi {
				lgAuditor.Info("RFI received (no response sent yet — phase E)",
					"type", msg.RfiType, "sender", senderID, "zone", zone)
				logEvent(kdb, &AuditEvent{
					Time:        time.Now(),
					Zone:        zone,
					Originator:  senderID,
					DeliveredBy: deliveredBy,
					EventType:   "rfi",
					Summary: fmt.Sprintf("RFI %s from %s (no response — phase E)",
						msg.RfiType, senderID),
				})
				continue
			}

			added, removed, rrtypes, contributions := summarizeMsgRecords(msg)

			lgAuditor.Info("sync/update received",
				"sender", senderID, "deliveredBy", deliveredBy,
				"zone", zone, "msgType", msg.MessageType,
				"distrib", msg.DistributionID,
				"records", len(msg.Records),
				"operations", len(msg.Operations),
				"added", added, "removed", removed)

			if stateManager != nil && zone != "" {
				zs := stateManager.GetOrCreateZone(zone)
				zs.UpdateProviderSync(senderID, contributions)
				detectMsgObservations(zs, senderID, msg, rrtypes)
			}

			logEvent(kdb, &AuditEvent{
				Time:        time.Now(),
				Zone:        zone,
				Originator:  senderID,
				DeliveredBy: deliveredBy,
				EventType:   string(msg.MessageType),
				Summary: fmt.Sprintf("%s from %s: +%d/-%d RRs",
					msg.MessageType, senderID, added, removed),
				RRsAdded:   added,
				RRsRemoved: removed,
				RRtypes:    strings.Join(rrtypes, ","),
			})

		case confirm := <-msgQs.Confirmation:
			if confirm == nil {
				continue
			}
			lgAuditor.Debug("confirmation received",
				"zone", confirm.Zone,
				"distrib", confirm.DistributionID,
				"status", confirm.Status,
				"source", confirm.Source)
			logEvent(kdb, &AuditEvent{
				Time:       time.Now(),
				Zone:       string(confirm.Zone),
				Originator: confirm.Source,
				EventType:  "confirm",
				Summary: fmt.Sprintf("CONFIRM %s from %s (distrib %s)",
					confirm.Status, confirm.Source, confirm.DistributionID),
			})

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

// logEvent inserts an AuditEvent into the persistent log, ignoring
// errors after logging — failure to record an event must not block
// the message loop.
func logEvent(kdb *tdns.KeyDB, event *AuditEvent) {
	if kdb == nil {
		return
	}
	if err := InsertAuditEvent(kdb, event); err != nil {
		lgAuditor.Warn("failed to insert audit event",
			"zone", event.Zone, "type", event.EventType, "err", err)
	}
}

// summarizeMsgRecords returns counts and contribution map for a
// sync/update message. Contributions are keyed owner → rrtype → count
// (rrtype as numeric DNS type when known, 0 otherwise).
func summarizeMsgRecords(msg *AgentMsgPostPlus) (added, removed int,
	rrtypes []string, contributions map[string]map[uint16]int) {
	contributions = make(map[string]map[uint16]int)
	rrtypeSeen := make(map[string]bool)

	for owner, rrs := range msg.Records {
		if contributions[owner] == nil {
			contributions[owner] = make(map[uint16]int)
		}
		// Class-overloaded legacy path: count as added; rrtype detail
		// is not available without parsing each RR string, which is
		// beyond what the auditor needs at this layer.
		added += len(rrs)
	}
	for _, op := range msg.Operations {
		if !rrtypeSeen[op.RRtype] {
			rrtypeSeen[op.RRtype] = true
			rrtypes = append(rrtypes, op.RRtype)
		}
		switch op.Operation {
		case "add", "replace":
			added += len(op.Records)
		case "delete":
			removed += len(op.Records)
		}
	}
	return added, removed, rrtypes, contributions
}

// detectMsgObservations records anomalies discovered while processing
// a sync/update message. Currently flags: unauthorized DNSKEY
// contributions from non-signers (rule 3 of the design doc).
func detectMsgObservations(zs *AuditZoneState, senderID string,
	msg *AgentMsgPostPlus, rrtypes []string) {
	hasDNSKEY := false
	for _, t := range rrtypes {
		if strings.EqualFold(t, "DNSKEY") || strings.EqualFold(t, "CDS") ||
			strings.EqualFold(t, "CDNSKEY") {
			hasDNSKEY = true
			break
		}
	}
	if !hasDNSKEY {
		return
	}
	zs.mu.RLock()
	ps := zs.Providers[senderID]
	zs.mu.RUnlock()
	if ps != nil && ps.IsSigner {
		return
	}
	zs.AddObservation("warning", senderID,
		fmt.Sprintf("DNSKEY-class contribution from non-signer %s in %s",
			senderID, msg.MessageType))
}
