/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The answer to a request for the zone's state (the membership design,
 * 5.4): one SYNC to the asker alone, with this agent's whole state of the
 * zone, marked with the request's name and as complete, or marked as not
 * complete and carrying nothing.
 */

package tdnsmp

import (
	"fmt"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// catchUpAnswer answers target's request for the zone's state. The answer
// is complete when the zone has loaded here, this agent has read its own
// state from its combiner, and, for a provider in signers=, its signer's
// inventory is in. Otherwise it says why, and carries no operation: empty
// sets from an agent that has not read its own state would remove its
// contributions at every peer.
//
// A complete answer has a replace for NS and CDS, and for a provider in
// signers= for DNSKEY, each empty where this agent holds none; and, from
// the agent that leads the zone, for its CSYNC. It names no KEY (decision
// 27). It is enqueued for the asker alone and not tracked: tracking it
// would put another distribution ID on the records the leader's CSYNC is
// tracked under. The asker's confirmation closes its queue entry.
//
// At most one answer per zone and asker waits in the queue: a newer answer
// takes the older one out. The asker counts only the answer to its latest
// request, and it asks again every five minutes while it has none, also
// when the answers cannot reach it; each answer would wait in the queue
// for a day, and a full queue takes nothing more, this agent's own
// updates to its combiner included.
func (conf *Config) catchUpAnswer(zdr *ZoneDataRepo, zone ZoneName, target AgentId, req *CatchUp) (string, error) {
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		return "", fmt.Errorf("TransportManager not available")
	}
	zu := conf.buildCatchUpAnswer(zdr, zone, req)
	complete, why := zu.CatchUp.IsComplete(), zu.CatchUp.Why
	detail := ""
	if why == whyOwnStateNotRead {
		detail = zdr.ownStateWhy(zone) // what an operator can act on
	}
	lgEngine.Info("answering a request for the zone's state", "zone", zone, "peer", target,
		"reason", req.Reason, "request", req.Request, "complete", complete, "why", why, "detail", detail)
	if older := zdr.catchUpAnswers[zone][target]; older != "" && tm.MarkDeliveryConfirmed(older, string(target)) {
		lgEngine.Info("an answer to a request for the zone's state replaces the older one still queued", "zone", zone, "peer", target, "older", older)
	}
	distID := transport.GenerateDistributionID()
	if err := tm.EnqueueForSpecificAgent(zone, target, zu, distID); err != nil {
		return "", err
	}
	// An answer with a DNSKEY operation is remembered: the asker's final
	// confirmation of it is its word on the keys of the distributions it
	// overtook there (creditFromAnswerLocked).
	for _, op := range zu.Operations {
		if op.RRtype == "DNSKEY" {
			tm.noteCatchUpAnswer(distID, zone, target, dnskeyKeyTagsOf(op.Records))
		}
	}
	if zdr.catchUpAnswers == nil {
		zdr.catchUpAnswers = map[ZoneName]map[AgentId]string{}
	}
	if zdr.catchUpAnswers[zone] == nil {
		zdr.catchUpAnswers[zone] = map[AgentId]string{}
	}
	zdr.catchUpAnswers[zone][target] = distID
	if !complete {
		return fmt.Sprintf("answered %s for zone %s: not complete (%s)", target, zone, why), nil
	}
	return fmt.Sprintf("answered %s for zone %s: complete, %d operations", target, zone, len(zu.Operations)), nil
}

// buildCatchUpAnswer is the answer catchUpAnswer sends.
func (conf *Config) buildCatchUpAnswer(zdr *ZoneDataRepo, zone ZoneName, req *CatchUp) *ZoneUpdate {
	self := AgentId(conf.MpConfig().Identity)
	answer := &CatchUp{Request: req.Request}
	zu := &ZoneUpdate{Zone: zone, AgentId: self, CatchUp: answer}
	why := conf.catchUpIncomplete(zdr, zone, self)
	complete := why == ""
	answer.Complete = &complete
	if complete {
		zu.Operations = conf.catchUpOperations(zdr, zone, self)
	} else {
		answer.Why = why
	}
	return zu
}

// catchUpIncomplete says why this agent's answer for the zone cannot be
// complete, or "" when it can.
func (conf *Config) catchUpIncomplete(zdr *ZoneDataRepo, zone ZoneName, self AgentId) string {
	zd, ok := Zones.Get(string(zone))
	if !ok || !zd.loadedForCatchUp() {
		return whyZoneNotLoaded
	}
	if !zdr.OwnStateRead(zone) {
		return whyOwnStateNotRead
	}
	if conf.signsZone(zd) && zd.GetLastKeyInventory() == nil {
		return whyNoInventory
	}
	return ""
}

// signsZone: this agent's provider is in the zone's signers=, by this
// agent's copy of the zone.
func (conf *Config) signsZone(zd *MPZoneData) bool {
	matched, label, err := zd.matchHsyncIdentity(ourHsyncIdentities(conf.MpConfig()))
	return err == nil && matched && zd.isSigner(label)
}

// catchUpOperations are the operations of a complete answer.
//
// NS and CDS come from this agent's own data, as its own read left it. A
// record that its own combiner refused is left out: its state is Rejected
// and its tracking entry shows that combiner's confirmation as rejected
// (decision 43). A refusal by a peer does not leave a record out: leaving
// it out of a replace would remove it at the asker. A record whose removal
// the combiner refused is accepted again, and is named.
//
// DNSKEY, the records and their key states, come from the signer's latest
// inventory, never from the agent's own data, which can lack its own
// DNSKEYs while an inventory is there. A provider not in signers= sends no
// DNSKEY operation: a provider moved from signers= to servers= does not
// withdraw its keys (the membership design, 2.3).
//
// The zone's CSYNC is the leader's alone, and only the agent that leads
// the zone names it.
func (conf *Config) catchUpOperations(zdr *ZoneDataRepo, zone ZoneName, self AgentId) []core.RROperation {
	var nod *OwnerData
	if agentRepo, ok := zdr.Repo.Get(zone); ok {
		nod, _ = agentRepo.Data.Get(self)
	}
	combiner := ""
	if tm := conf.InternalMp.MPTransport; tm != nil {
		combiner = string(tm.combinerID)
	}
	own := func(rrtype uint16) core.RROperation {
		op := core.RROperation{Operation: "replace", RRtype: dns.TypeToString[rrtype], Records: []string{}}
		if nod == nil {
			return op
		}
		rrset, ok := nod.RRtypes.Get(rrtype)
		if !ok {
			return op
		}
		for _, rr := range rrset.RRs {
			c := dns.Copy(rr)
			c.Header().Class = dns.ClassINET
			if zdr.combinerRefused(zone, self, rrtype, c.String(), combiner) {
				continue
			}
			op.Records = append(op.Records, c.String())
		}
		return op
	}
	ops := []core.RROperation{own(dns.TypeNS), own(dns.TypeCDS)}

	if zd, ok := Zones.Get(string(zone)); ok && conf.signsZone(zd) {
		op := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{}}
		if inv := zd.GetLastKeyInventory(); inv != nil {
			keys, states := zd.inventoryKeys(inv)
			for _, k := range keys {
				op.Records = append(op.Records, k.String())
			}
			op.KeyStates = states
		}
		ops = append(ops, op)
	}

	if lem := conf.InternalMp.LeaderElectionManager; lem != nil && lem.IsLeader(zone) {
		ops = append(ops, own(dns.TypeCSYNC))
	}
	return ops
}

// combinerRefused: the latest tracking entry of the record says that the
// agent's own combiner refused it: the record is Rejected, and the
// combiner's confirmation is the refusal.
func (zdr *ZoneDataRepo) combinerRefused(zone ZoneName, agent AgentId, rrtype uint16, rrStr, combiner string) bool {
	if combiner == "" || zdr.Tracking[zone] == nil || zdr.Tracking[zone][agent] == nil {
		return false
	}
	tracked := zdr.Tracking[zone][agent][rrtype]
	if tracked == nil {
		return false
	}
	for i := len(tracked.Tracked) - 1; i >= 0; i-- {
		tr := tracked.Tracked[i]
		if tr.RR == nil {
			continue
		}
		c := dns.Copy(tr.RR)
		c.Header().Class = dns.ClassINET
		if c.String() != rrStr {
			continue
		}
		return tr.State == RRStateRejected && tr.Confirmations[combiner].Status == "rejected"
	}
	return false
}
