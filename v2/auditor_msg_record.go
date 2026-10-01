/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * What the auditor records about each inbound message. AuditorEngine
 * (auditor_engine.go) consumes the messages; the helpers here persist
 * its events to the AuditEventLog, count the records a sync/update
 * adds and removes, and flag anomalies as observations in the
 * in-memory AuditZoneState. The auditor never sends zone data.
 */
package tdnsmp

import (
	"fmt"
	"strings"

	tdns "github.com/johanix/tdns/v2"
)

var lgAuditor = tdns.Logger("auditor")

// logEvent inserts an AuditEvent into the persistent log. The insert
// is synchronous (it runs inline, taking kdb.Lock() and one db.Exec
// per call); the calling goroutine (the engine's message loop, its
// hello adapter or runAux) waits for it. At current load this is a
// single-row write of ~1ms and not a problem. If event volume ever
// justifies it, switch to a buffered channel + dedicated writer
// goroutine. Errors are logged and swallowed: a failure to persist
// must never stop the message loop.
func logEvent(kdb *tdns.KeyDB, event *AuditEvent) {
	if kdb == nil {
		return
	}
	if err := InsertAuditEvent(kdb, event); err != nil {
		lgAuditor.Warn("failed to insert audit event",
			"zone", event.Zone, "type", event.EventType, "err", err)
	}
}

// summarizeMsgRecords returns counts and the set of RRtypes touched
// by a sync/update message. Per-owner / per-rrtype attribution is
// not done here: parsing every RR string just to bucket counts adds
// CPU on the hot path for state we don't yet display anywhere. Until
// per-owner attribution is needed, contributions is returned as nil
// so callers can pass it straight to UpdateProviderSync without
// clobbering the existing map.
//
// TODO: when msg.Records is non-empty (legacy class-overloaded
// path), the rrtypes slice will miss any types only carried in
// Records. Today the senders we care about (agent → auditor for
// DNSKEY-class checks) emit Operations, so this is a latent bug
// rather than an active one. Fix when we add per-owner attribution.
func summarizeMsgRecords(msg *AgentMsgPostPlus) (added, removed int,
	rrtypes []string, contributions map[string]map[uint16]int) {
	rrtypeSeen := make(map[string]bool)

	for _, rrs := range msg.Records {
		// Legacy class-overloaded path: count as added without
		// parsing the RR strings.
		added += len(rrs)
	}
	if len(msg.Records) > 0 && len(msg.Operations) == 0 {
		lgAuditor.Warn("sync/update used legacy Records field without Operations; rrtype-based observations may miss this message",
			"zone", msg.Zone, "sender", msg.OriginatorID, "owners", len(msg.Records))
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
	// contributions is intentionally nil — see godoc.
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
	// Read IsSigner under the lock; ps is mutated by
	// UpdateProviderBeat/UpdateProviderSync from other goroutines.
	zs.mu.RLock()
	isSigner := false
	if ps := zs.Providers[senderID]; ps != nil {
		isSigner = ps.IsSigner
	}
	zs.mu.RUnlock()
	if isSigner {
		return
	}
	zs.AddObservation("warning", senderID,
		fmt.Sprintf("DNSKEY-class contribution from non-signer %s in %s",
			senderID, msg.MessageType))
}
