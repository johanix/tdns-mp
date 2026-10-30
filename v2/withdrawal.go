/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The leader's withdrawal of another provider's records (design 5.2, plan
 * S16). The leader takes a leaving provider's NS, DNSKEY or CDS records out
 * of the zone by an operation of its own: an empty replace of the type, in
 * the provider's name, which the sync wrapper's "withdraw" field names. A
 * member takes it from the zone's leader only, when the active instructions
 * do not list the provider for the type; its confirmation goes to the
 * leader. To its combiner an agent sends it in the provider's name, with the
 * same field as the flag the combiner honours from its own agent only.
 */
package tdnsmp

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Withdraw names the provider whose records a withdrawal takes away, and
// their type.
type Withdraw struct {
	Provider string `json:"provider"`
	RRtype   string `json:"rrtype"`
}

// withdrawnFrom is, for each type a withdrawal takes away, the list of the
// active instructions that must not name the provider. Glue is not a
// contribution.
var withdrawnFrom = map[uint16]string{dns.TypeNS: "servers", dns.TypeDNSKEY: "signers", dns.TypeCDS: "signers"}

// sentWithdrawal is a withdrawal this agent sent, as its leader.
type sentWithdrawal struct {
	zone ZoneName
	w    Withdraw
	at   time.Time
}

// withdrawalsKept is how long a sent withdrawal is remembered: its resend
// under rule 6 and the start of its time-out read it.
const withdrawalsKept = 24 * time.Hour

// update is the withdrawal as an update: one empty replace of its type, in
// the provider's name.
func (w *Withdraw) update(zone ZoneName) *ZoneUpdate {
	return &ZoneUpdate{Zone: zone, AgentId: AgentId(w.Provider), Withdraw: w,
		Operations: []core.RROperation{{Operation: "replace", RRtype: w.RRtype}}}
}

// withdrawalRefusal is why the active instructions in do not let provider's
// records of rrtype be withdrawn; "" when they do: the provider is not in
// the list the type depends on.
func withdrawalRefusal(in *Instructions, provider, rrtype string) string {
	list, ok := withdrawnFrom[dns.StringToType[strings.ToUpper(rrtype)]]
	if !ok {
		return fmt.Sprintf("%s records are not withdrawn: only NS, DNSKEY and CDS are", rrtype)
	}
	if in == nil {
		return "the zone's active instructions are not known here"
	}
	label, on := in.labelOf(provider)
	set := in.Servers
	if list == "signers" {
		set = in.Signers
	}
	if on && slices.Contains(set, label) {
		return fmt.Sprintf("the active instructions list %s in %s=", provider, list)
	}
	return ""
}

// answerTo is whom u's answers go to: its sender, or the leader that
// delivered a withdrawal.
func (u *SynchedDataUpdate) answerTo() AgentId {
	if u.Withdraw != nil && u.DeliveredBy != "" {
		return u.DeliveredBy
	}
	return u.AgentId
}

// acceptWithdrawal is why u, a withdrawal, is refused here; "" when it is
// taken. Its deliverer must lead the zone; the active instructions must not
// list the provider for the type; and it must be one empty replace of the
// type it names.
func (conf *Config) acceptWithdrawal(u *SynchedDataUpdate) string {
	w := u.Withdraw
	var leader AgentId
	known := false
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
		leader, known = lem.ZoneLeader(u.Zone)
	}
	switch {
	case !known:
		return "no leader of the zone is known here"
	case !sameName(string(leader), string(u.DeliveredBy)):
		return fmt.Sprintf("the sender %s does not lead the zone, %s does", u.DeliveredBy, leader)
	}
	if why := withdrawalRefusal(conf.InternalMp.Instructions.activeReading(string(u.Zone)), w.Provider, w.RRtype); why != "" {
		return why
	}
	ops := u.Update.Operations
	sameType := len(ops) == 1 && strings.EqualFold(ops[0].RRtype, w.RRtype) // not-a-name: an RR type
	if !sameType || ops[0].Operation != "replace" || len(ops[0].Records) > 0 || len(u.Update.RRsets) > 0 || len(u.Update.RRs) > 0 {
		return "a withdrawal is one empty replace of the type it names"
	}
	return ""
}

// refuseWithdrawal refuses u, a withdrawal, with a final REJECTED to the
// leader that sent it.
func refuseWithdrawal(u *SynchedDataUpdate, why string, msgQs *MsgQs) {
	lgEngine.Info("a withdrawal is refused", "zone", u.Zone, "provider", u.Withdraw.Provider, "rrtype", u.Withdraw.RRtype, "why", why)
	text := "a withdrawal is refused: " + why
	if u.OriginatingDistID != "" && msgQs != nil && msgQs.OnRemoteConfirmationReady != nil {
		msgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
			OriginatingDistID: u.OriginatingDistID,
			OriginatingSender: string(u.answerTo()),
			Mechanism:         u.Mechanism,
			Zone:              u.Zone,
			Status:            "REJECTED",
			Message:           text,
		})
	}
	respond(u, &AgentMsgResponse{Zone: u.Zone, AgentId: u.AgentId, Msg: text})
}

// combinerRemovesOnly: every operation removes what origin holds at the
// combiner: a delete, or a replace whose records are a subset of origin's
// (design 3.5). A replace that adds a record is no removal.
func combinerRemovesOnly(zone, origin string, ops []core.RROperation) bool {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd.MP == nil || len(ops) == 0 {
		return false
	}
	for _, op := range ops {
		switch op.Operation {
		case "delete":
		case "replace":
			rrtype, ok := dns.StringToType[strings.ToUpper(op.RRtype)]
			if !ok {
				return false
			}
			var held []dns.RR
			for sender, owners := range mpzd.MP.AgentContributions {
				if sameName(sender, origin) {
					held = owners[zone][rrtype].RRs
				}
			}
			for _, rec := range op.Records {
				rr, err := dns.NewRR(rec)
				if err != nil || !slices.ContainsFunc(held, func(h dns.RR) bool { return dns.IsDuplicate(h, rr) }) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// combinerTakesRemoval: msg is a removal in any origin's name that this
// combiner's own agent delivered with the withdrawal's flag: applied
// whether or not the origin votes. From anyone else the flag is not
// honoured.
func combinerTakesRemoval(msg *AgentMsgPostPlus, deliveredBy string, localAgents map[string]bool) bool {
	return msg.Withdraw != nil && localAgents[deliveredBy] && combinerRemovesOnly(dns.Fqdn(string(msg.Zone)), string(msg.OriginatorID), msg.Operations)
}

// withdrawalHeldBack is why this agent may not withdraw provider's records
// of rrtype now; "" when it may: it leads the zone, and its active
// instructions do not list the provider for the type.
func (conf *Config) withdrawalHeldBack(zone ZoneName, provider AgentId, rrtype string) string {
	if lem := conf.InternalMp.LeaderElectionManager; lem == nil || !lem.IsLeader(zone) {
		return "this agent does not lead the zone"
	}
	return withdrawalRefusal(conf.InternalMp.Instructions.activeReading(string(zone)), string(provider), rrtype)
}

// heldOf is the records of rrtype this agent's data holds of agent.
func (zdr *ZoneDataRepo) heldOf(zone ZoneName, agent AgentId, rrtype uint16) []dns.RR {
	if ar, ok := zdr.Get(zone); ok {
		if od, ok := ar.Get(agent); ok {
			if rrset, ok := od.RRtypes.Get(rrtype); ok {
				return rrset.RRs
			}
		}
	}
	return nil
}

// sendWithdrawal withdraws provider's records of rrtype from the zone, as
// its leader: the records this agent holds of it are marked pending
// removal, every recipient expected to confirm, and the withdrawal goes to
// this agent's combiner and to every member, the provider's agent among
// them, under one distribution ID. It runs on the data engine.
func (conf *Config) sendWithdrawal(zdr *ZoneDataRepo, zone ZoneName, provider AgentId, rrtype string) (string, error) {
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		return "", errors.New("the transport is not available")
	}
	if why := conf.withdrawalHeldBack(zone, provider, rrtype); why != "" {
		return "", errors.New(why)
	}
	t := dns.StringToType[strings.ToUpper(rrtype)]
	w := &Withdraw{Provider: string(provider), RRtype: dns.TypeToString[t]}
	zu := w.update(zone)
	distID := transport.GenerateDistributionID()
	now := time.Now()
	tracked := zdr.getOrCreateTracking(zone, provider, t)
	for _, rr := range zdr.heldOf(zone, provider, t) {
		if !slices.ContainsFunc(tracked.Tracked, func(tr TrackedRR) bool { return tr.RR.String() == rr.String() }) {
			tracked.Tracked = append(tracked.Tracked, TrackedRR{RR: rr, State: RRStateAccepted, UpdatedAt: now})
		}
		zdr.markDeletePending(tracked, rr, distID, now)
	}
	zdr.MarkRRsPending(zone, provider, zu, distID, tm.GetDistributionRecipients(zone, false))
	zdr.noteWithdrawal(distID, sentWithdrawal{zone: zone, w: *w, at: now})
	lgEngine.Info("withdrawing another provider's records", "zone", zone, "provider", provider, "rrtype", w.RRtype)
	var errs []error
	if _, err := tm.EnqueueForCombiner(zone, zu, distID); err != nil {
		errs = append(errs, err)
	}
	if err := tm.EnqueueForZoneAgents(zone, zu, distID); err != nil {
		errs = append(errs, err)
	}
	return distID, errors.Join(errs...)
}

// withdraw is the plan's call (S12, S17b): a withdrawal of provider's
// records of rrtype goes when what is in place here still calls for one:
// this agent holds some of them, and none is pending removal already. So a
// new leader, planning again, sends again what the leader before it sent,
// while it still holds the records. It runs on the data engine.
func (conf *Config) withdraw(zdr *ZoneDataRepo, zone ZoneName, provider AgentId, rrtype string) (sent bool, err error) {
	t := dns.StringToType[strings.ToUpper(rrtype)]
	if len(zdr.heldOf(zone, provider, t)) == 0 {
		return false, nil
	}
	if tracked := zdr.Tracking[zone][provider][t]; tracked != nil &&
		slices.ContainsFunc(tracked.Tracked, func(tr TrackedRR) bool { return tr.State == RRStatePendingRemoval }) {
		return false, nil
	}
	if _, err := conf.sendWithdrawal(zdr, zone, provider, rrtype); err != nil {
		return false, err
	}
	return true, nil
}

// withdrawalDone: the withdrawal of provider's records of rrtype is done
// here, by this agent's tracking. Every record of it this agent still
// holds is pending removal, and every recipient that has not confirmed it
// is a member with no role, after S12's time-out from the withdrawal's
// start (design 4). A record that every recipient confirmed is gone.
func (conf *Config) withdrawalDone(zdr *ZoneDataRepo, zone ZoneName, provider AgentId, rrtype string) bool {
	t := dns.StringToType[strings.ToUpper(rrtype)]
	held := zdr.heldOf(zone, provider, t)
	if len(held) == 0 {
		return true
	}
	tracked := zdr.Tracking[zone][provider][t]
	if tracked == nil {
		return false
	}
	wait := noRoleTimeoutDefault
	if tm := conf.InternalMp.MPTransport; tm != nil {
		wait = tm.noRoleWait()
	}
	now := time.Now()
	for _, rr := range held {
		i := slices.IndexFunc(tracked.Tracked, func(tr TrackedRR) bool { return tr.RR.String() == rr.String() })
		if i < 0 || tracked.Tracked[i].State != RRStatePendingRemoval {
			return false
		}
		tr := tracked.Tracked[i]
		start := tr.UpdatedAt
		if sw, ok := zdr.withdrawalSent(tr.DistributionID); ok {
			start = sw.at
		}
		for _, r := range tr.ExpectedRecipients {
			if c, ok := tr.Confirmations[r]; ok && c.Status != "pending" {
				continue
			}
			if !noRoleMember(zone, AgentId(r)) || now.Sub(start) < wait {
				return false
			}
		}
	}
	return true
}

// noteWithdrawal remembers a withdrawal this agent sent, and forgets those
// sent longer ago than withdrawalsKept.
func (zdr *ZoneDataRepo) noteWithdrawal(distID string, sw sentWithdrawal) {
	zdr.mu.Lock()
	defer zdr.mu.Unlock()
	if zdr.withdrawals == nil {
		zdr.withdrawals = map[string]sentWithdrawal{}
	}
	maps.DeleteFunc(zdr.withdrawals, func(_ string, o sentWithdrawal) bool { return sw.at.Sub(o.at) > withdrawalsKept })
	zdr.withdrawals[distID] = sw
}

// withdrawalSent is the withdrawal this agent sent under distID.
func (zdr *ZoneDataRepo) withdrawalSent(distID string) (sentWithdrawal, bool) {
	zdr.mu.Lock()
	defer zdr.mu.Unlock()
	sw, ok := zdr.withdrawals[distID]
	return sw, ok
}

// withdrawAgain sends a withdrawal a peer answered "not yet" to that peer
// again, under its own distribution ID, now that the two are in step (rule
// 6), while the active instructions still call for it.
func (conf *Config) withdrawAgain(zone ZoneName, n *notYet, sw sentWithdrawal) {
	tm := conf.InternalMp.MPTransport
	tm.notYets.drop(zone, n.peer, n.distID)
	if why := conf.withdrawalHeldBack(zone, AgentId(sw.w.Provider), sw.w.RRtype); why != "" {
		lgEngine.Info("a withdrawal a peer answered \"not yet\" is no longer called for: not sent again", "zone", zone, "peer", n.peer, "distrib", n.distID, "why", why)
		return
	}
	if err := tm.EnqueueForSpecificAgent(zone, n.peer, sw.w.update(zone), n.distID); err != nil {
		tm.notYets.add(n)
		lgEngine.Warn("sending a withdrawal again to a peer now in step failed; the engine's tick tries again", "zone", zone, "peer", n.peer, "distrib", n.distID, "err", err)
		return
	}
	lgEngine.Info("sent a withdrawal again to a peer now in step", "zone", zone, "peer", n.peer, "distrib", n.distID, "provider", sw.w.Provider, "rrtype", sw.w.RRtype)
}

// debugWithdraw is agent debug withdraw: the leader's withdrawal of a
// provider's records, refused unless this agent leads the zone and the
// acceptance holds here.
func (conf *Config) debugWithdraw(amp *AgentMgmtPost, resp *AgentMgmtResponse) {
	rrtype := dns.TypeToString[amp.RRType]
	if why := conf.withdrawalHeldBack(amp.Zone, amp.AgentId, rrtype); why != "" {
		resp.Error, resp.ErrorMsg = true, fmt.Sprintf("no withdrawal of %s's %s records in zone %s: %s", amp.AgentId, rrtype, amp.Zone, why)
		return
	}
	msgQs := conf.InternalMp.MsgQs
	if msgQs == nil || msgQs.SynchedDataCmd == nil {
		resp.Error, resp.ErrorMsg = true, "the data engine is not running"
		return
	}
	answer := make(chan *SynchedDataCmdResponse, 1)
	msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "withdraw", Zone: amp.Zone, Withdraw: &Withdraw{Provider: string(amp.AgentId), RRtype: rrtype}, Response: answer}
	select {
	case a := <-answer:
		if a.Error {
			resp.Error, resp.ErrorMsg = true, a.Msg
			return
		}
		resp.Msg = a.Msg
	case <-time.After(10 * time.Second):
		resp.Error, resp.ErrorMsg = true, "the data engine did not answer in time"
	}
}
