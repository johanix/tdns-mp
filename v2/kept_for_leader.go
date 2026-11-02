/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A CSYNC or the leader's KEY that comes before this agent knows the zone's
 * leader (plan S15; the membership plan's step 10). Both are taken from the
 * leader only (refuseCsyncNotFromLeader), and a newcomer with no role knows
 * no leader until a voting member's gossip tells it: a REJECTED from it made
 * the leader drop its held NOTIFY and fail the sync. So the whole update is
 * kept on the zone's kept list, its sender told in a PENDING, and judged
 * once a leader is known here; at an agent that does not vote, once the
 * leader it knows is the sender, or the lease of the leader it knew when
 * the update came has run out. A voting member that knows a leader refuses
 * a CSYNC from another agent at once, as before. An entry kept for the
 * leader does not hold the list: the entries behind it are handled in their
 * order, and only a later CSYNC or KEY waits behind it.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// leaderOnlyOp: an operation refuseCsyncNotFromLeader takes from the zone's
// leader only, a CSYNC or a KEY.
func leaderOnlyOp(op core.RROperation) bool {
	return strings.EqualFold(op.RRtype, dns.TypeToString[dns.TypeCSYNC]) || strings.EqualFold(op.RRtype, dns.TypeToString[dns.TypeKEY]) // not-a-name: an RR type
}

// carriesLeaderOnly: the update carries what refuseCsyncNotFromLeader takes
// from the leader only: a CSYNC, a KEY, or a publish instruction.
func carriesLeaderOnly(ops []core.RROperation, publish *core.PublishInstruction) bool {
	return publish != nil || slices.ContainsFunc(ops, leaderOnlyOp)
}

// leaderWait is why an update with a CSYNC or a KEY from sender waits here
// for the zone's leader; "" when it is judged now: a leader is known, and
// this agent votes in the zone or the leader is the sender. At an agent
// that does not vote and knows another leader, leader is that one and until
// its lease; with no leader known both are empty.
func (conf *Config) leaderWait(zone ZoneName, sender AgentId) (why string, leader AgentId, until time.Time) {
	lem := conf.InternalMp.LeaderElectionManager
	if lem == nil {
		return "", "", time.Time{}
	}
	known, ok := lem.ZoneLeader(zone)
	if !ok {
		return "no leader of the zone is known here yet", "", time.Time{}
	}
	if votesInZone(zone, lem.localID) || sameName(string(known), string(sender)) {
		return "", "", time.Time{}
	}
	// the lease that ZoneLeader found running; a per-zone leader that
	// zoneLease does not see counts as run out
	until = time.Now()
	if l, exp := lem.zoneLease(zone); sameName(string(l), string(known)) {
		until = exp
	}
	return fmt.Sprintf("the leader known here is %s, until its lease runs out at %s", known, until.UTC().Format(time.RFC3339)), known, until
}

// keepForLeader keeps u whole on the zone's kept list when it carries a
// CSYNC or a KEY and waits for the zone's leader here (leaderWait), or when
// an earlier such update of the zone is kept for it: a later CSYNC or KEY
// waits behind it. A catch-up answer is kept whole too. Its sender is told
// in a PENDING, again for every resend. Reports whether u was kept. An
// update released from the kept list is judged, not kept again
// (leaderJudged). The kept list is the zone's while the store keeps its
// serials, as rule 6 has it: a zone whose serials are not kept here, and a
// daemon that keeps no lists, keep nothing.
func (conf *Config) keepForLeader(u *SynchedDataUpdate, msgQs *MsgQs) bool {
	k := conf.InternalMp.Kept
	if u == nil || u.Update == nil || u.leaderJudged || k == nil || !carriesLeaderOnly(u.Update.Operations, u.Update.Publish) {
		return false
	}
	if _, kept := conf.InternalMp.Instructions.activeSerial(string(u.Zone)); !kept {
		return false
	}
	why, leader, until := conf.leaderWait(u.Zone, u.DeliveredBy)
	if why == "" {
		if !k.waitsForLeader(string(u.Zone)) {
			return false
		}
		why = "an earlier CSYNC or KEY of the zone is kept for its leader"
	}
	ku := keptRemoteOf(u)
	ku.ForLeader, ku.Leader, ku.LeaseUntil = true, leader, until
	added, err := k.keepOnce(string(u.Zone), u.OriginatingDistID, ku)
	if err != nil {
		// as keepRemote: no confirmation goes back, so the sender sends it
		// again
		lgEngine.Error("a CSYNC or KEY that waits for the zone's leader could not be kept", "zone", u.Zone, "peer", u.AgentId, "distrib", u.OriginatingDistID, "err", err)
		respond(u, &AgentMsgResponse{Zone: u.Zone, AgentId: u.AgentId, Error: true, ErrorMsg: "the distribution could not be kept: " + err.Error()})
		return true
	}
	if added {
		lgEngine.Info("a CSYNC or KEY is kept until the zone's leader is known here", "zone", u.Zone, "peer", u.AgentId, "sender", u.DeliveredBy, "distrib", u.OriginatingDistID, "why", why)
	} else {
		lgEngine.Debug("a resend of a CSYNC or KEY kept for the zone's leader is kept once", "zone", u.Zone, "peer", u.AgentId, "distrib", u.OriginatingDistID)
	}
	conf.tellKept(u, keptPrefix+" "+why, msgQs)
	return true
}

// leaderHolds: the kept update ku, which carries a CSYNC or a KEY, still
// waits for the zone's leader here. One not noted as waiting for it yet,
// kept for its serial, waits as a new one would (leaderWait), and leader
// and until are what to note on it. One noted is released once the wait
// has ended, once a leader is known when none was when it was noted, or
// once the lease noted has run out.
func (conf *Config) leaderHolds(zone ZoneName, ku keptUpdate, now time.Time) (holds bool, leader AgentId, until time.Time) {
	why, leader, until := conf.leaderWait(zone, ku.DeliveredBy)
	switch {
	case why == "":
		return false, "", time.Time{}
	case !ku.ForLeader:
		return true, leader, until
	case leader == "": // no leader known
		return true, "", time.Time{}
	case ku.Leader == "", !now.Before(ku.LeaseUntil):
		return false, "", time.Time{}
	}
	return true, "", time.Time{}
}

// waitsForLeader: the zone's kept list holds an update kept for the zone's
// leader.
func (k *keptLists) waitsForLeader(zone string) bool {
	if k == nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.ContainsFunc(k.lists[canonicalName(zone)][listKept], func(e keptEntry) bool { return e.Update.ForLeader })
}

// markForLeader notes on the zone's kept entry seq that it waits for the
// zone's leader, the leader known and its lease, on disk first.
func (k *keptLists) markForLeader(zone string, seq int64, leader AgentId, until time.Time) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	entries := k.lists[canonicalName(zone)][listKept]
	i := slices.IndexFunc(entries, func(e keptEntry) bool { return e.Seq == seq })
	if i < 0 {
		return nil
	}
	u := entries[i].Update
	u.ForLeader, u.Leader, u.LeaseUntil = true, leader, until
	if k.hdb != nil {
		b, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("noting entry %d of the kept list of %s: %w", seq, zone, err)
		}
		k.hdb.Lock()
		_, err = k.hdb.DB.Exec(`UPDATE MPKept SET update_json = ? WHERE seq = ?`, string(b), seq)
		k.hdb.Unlock()
		if err != nil {
			return fmt.Errorf("noting entry %d of the kept list of %s: %w", seq, zone, err)
		}
	}
	entries[i].Update = u
	return nil
}

// askLeaderWaits asks the data engine to judge what every zone keeps, once
// an election names a leader (SetOnLeaderNamed): a CSYNC or KEY kept for
// the zone's leader is judged by the leader named. The end of a lease is
// caught by the engine's tick (releaseActivated).
func (conf *Config) askLeaderWaits() {
	for _, z := range conf.InternalMp.Kept.zones(listKept) {
		if conf.InternalMp.Kept.waitsForLeader(z) {
			conf.askActivated(ZoneName(z))
		}
	}
}
