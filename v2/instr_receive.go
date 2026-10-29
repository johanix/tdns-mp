/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Messages between serials (design rule 6, plan S8). A distribution is
 * stamped with the active serial its sender acted by when it sent it
 * (S5b). Its receiver takes it when its own active serial is the same,
 * keeps it when the stamp is higher or its own active serial is not known,
 * until its active serial catches up, and refuses it as made under older
 * instructions when the stamp is lower. A confirmation reports a fact and
 * is always taken; a request is answered whatever its stamp. At the
 * sender, an answer other than a success from a peer whose stamp tells
 * another active serial than the send it answers is no decision yet: what
 * this agent contributes goes to that peer again once the two are in step.
 */
package tdnsmp

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
)

// staleInstructions names rule 6's final refusal of a distribution made
// under an older active serial than the receiver's (decision 31).
const staleInstructions = "stale-instructions"

// keptPrefix begins the PENDING of a kept distribution (keptText).
const keptPrefix = "kept:"

// receipt is what rule 6 does with a distribution.
type receipt int

const (
	receiptTake  receipt = iota // made under this agent's active serial
	receiptKeep                 // made under a higher one, or this agent's is not known
	receiptStale                // made under a lower one
)

// receiptOf is rule 6 for a distribution made under made, at an agent
// whose active serial is active (nil: not known). While this agent knows no
// active serial every distribution is kept, catch-up answers included
// (design 3.4, plan S9); one whose sender tells no active serial (made nil)
// is taken at its release, by the serial known then, as it is taken when
// one is known. One made under the active serial with another digest is
// kept: the two tell an owner error (rule 2), which holds the zone until a
// higher serial, and that refuses it.
func receiptOf(active, made *SerialDigest) receipt {
	switch {
	case active == nil:
		return receiptKeep
	case made == nil:
		return receiptTake
	case *made == *active:
		return receiptTake
	case CompareSerial(made.Serial, active.Serial) < 0:
		return receiptStale
	default:
		return receiptKeep
	}
}

// madeUnder is the active serial a stamp tells; nil when it tells none.
func madeUnder(ms *MsgStamp) *SerialDigest {
	if ms == nil || !ms.Known {
		return nil
	}
	return &SerialDigest{Serial: ms.Active, Digest: ms.ActiveDigest}
}

// activeSerial is zone's active serial, the zone named in any case: nil
// when the store knows none. kept is false when it keeps no serials of the
// zone.
func (s *InstructionStore) activeSerial(zone string) (active *SerialDigest, kept bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, z := s.zoneLocked(zone)
	if z == nil {
		return nil, false
	}
	if z.Active != nil {
		a := z.Active.SerialDigest
		active = &a
	}
	return active, true
}

// activeUnknown: the store keeps serials of zone, named in any case, and
// knows no active serial among them (design 3.4).
func (s *InstructionStore) activeUnknown(zone string) bool {
	active, kept := s.activeSerial(zone)
	return kept && active == nil
}

// instrReceive judges another agent's update by the active serial it was
// made under (rule 6): taken as it comes when that is this agent's own,
// also while the zone agrees; kept on the zone's kept list when it is
// higher, or while this agent knows no active serial, and its sender told
// so in a PENDING; refused when it is lower, with a final REJECTED that
// names stale-instructions and carries this agent's stamp. The transport's
// acknowledgement went already, ok. A zone whose serials this agent keeps
// none of is not judged. Reports whether the update goes on now.
func (conf *Config) instrReceive(u *SynchedDataUpdate, msgQs *MsgQs) bool {
	active, kept := conf.InternalMp.Instructions.activeSerial(string(u.Zone))
	if !kept {
		return true
	}
	made := madeUnder(u.OriginatingInstr)
	switch receiptOf(active, made) {
	case receiptKeep:
		conf.keepRemote(u, active, made, msgQs)
		return false
	case receiptStale:
		refuseStale(u, active, made, msgQs)
		return false
	}
	return true
}

// keptText is the PENDING of a kept distribution (P2 carries it).
func keptText(active, made *SerialDigest) string {
	switch {
	case active == nil && made == nil:
		return fmt.Sprintf("%s this agent does not know its active serial yet, nor did the sender tell one", keptPrefix)
	case active == nil:
		return fmt.Sprintf("%s this agent does not know its active serial yet, the message was made under %d", keptPrefix, made.Serial)
	}
	return fmt.Sprintf("%s this agent acts by serial %d, the message was made under %d", keptPrefix, active.Serial, made.Serial)
}

// activeName is an active serial for the log.
func activeName(active *SerialDigest) string {
	if active == nil {
		return "not known"
	}
	return fmt.Sprint(active.Serial)
}

// keepRemote keeps u on the zone's kept list, once, and tells its sender in
// a PENDING, again for every resend, so its queue waits on.
func (conf *Config) keepRemote(u *SynchedDataUpdate, active, made *SerialDigest, msgQs *MsgQs) {
	text := keptText(active, made)
	added, err := conf.InternalMp.Kept.keepOnce(string(u.Zone), u.OriginatingDistID, keptRemoteOf(u))
	if err != nil {
		// no confirmation goes back, so the sender's queue sends it again;
		// the answer below is the engine's own, to whoever handed it the
		// update (a message from the wire: MsgHandler, which logs it)
		lgEngine.Error("a distribution made under other instructions could not be kept", "zone", u.Zone, "peer", u.AgentId, "distrib", u.OriginatingDistID, "err", err)
		respond(u, &AgentMsgResponse{Zone: u.Zone, AgentId: u.AgentId, Error: true, ErrorMsg: "the distribution could not be kept: " + err.Error()})
		return
	}
	if u.CatchUp != nil {
		// a catch-up answer kept is not handled yet: its request's answer
		// time stops until the active serial is known (plan S9)
		conf.InternalMp.CatchUp.Arrived(u.Zone, u.AgentId, u.CatchUp)
	}
	if added {
		lgEngine.Info("a distribution made under newer instructions is kept", "zone", u.Zone, "peer", u.AgentId, "distrib", u.OriginatingDistID,
			"made_under", activeName(made), "active", activeName(active))
	} else {
		lgEngine.Debug("a resend of a kept distribution is kept once", "zone", u.Zone, "peer", u.AgentId, "distrib", u.OriginatingDistID)
	}
	if u.OriginatingDistID != "" && msgQs != nil && msgQs.OnRemoteConfirmationReady != nil {
		msgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
			OriginatingDistID: u.OriginatingDistID,
			OriginatingSender: string(u.AgentId),
			Mechanism:         u.Mechanism,
			Zone:              u.Zone,
			Status:            "PENDING",
			Message:           text,
		})
	}
	respond(u, &AgentMsgResponse{Zone: u.Zone, AgentId: u.AgentId, Msg: text})
}

// refuseStale refuses u, made under an older active serial than this
// agent's: nothing is stored or passed on, and its sender gets a final
// REJECTED that names stale-instructions, with this agent's stamp
// (confirmOn), which it reads as "not yet".
func refuseStale(u *SynchedDataUpdate, active, made *SerialDigest, msgQs *MsgQs) {
	text := fmt.Sprintf("%s: made under older instructions: this agent acts by serial %d, the message was made under %d", staleInstructions, active.Serial, made.Serial)
	lgEngine.Info("a distribution made under older instructions is refused", "zone", u.Zone, "peer", u.AgentId, "distrib", u.OriginatingDistID,
		"made_under", made.Serial, "active", active.Serial)
	if u.OriginatingDistID != "" && msgQs != nil && msgQs.OnRemoteConfirmationReady != nil {
		msgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
			OriginatingDistID: u.OriginatingDistID,
			OriginatingSender: string(u.AgentId),
			Mechanism:         u.Mechanism,
			Zone:              u.Zone,
			Status:            "REJECTED",
			Message:           text,
		})
	}
	respond(u, &AgentMsgResponse{Zone: u.Zone, AgentId: u.AgentId, Msg: text})
}

// respond gives the update's answer to whoever waits for it.
func respond(u *SynchedDataUpdate, resp *AgentMsgResponse) {
	if u.Response == nil {
		return
	}
	select {
	case u.Response <- resp:
	default:
		lgEngine.Warn("response channel blocked, skipping response")
	}
}

// askActivated asks the data engine to handle what waits for the zone's
// active serial (instrActivated), when it changes, becomes known or goes.
// A full queue leaves it to the engine's next own-read tick
// (releaseActivated).
func (conf *Config) askActivated(zone ZoneName) {
	msgQs := conf.InternalMp.MsgQs
	if msgQs == nil || msgQs.SynchedDataCmd == nil {
		return
	}
	select {
	case msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "instr-activated", Zone: zone}:
	default:
		lgEngine.Warn("the data engine's queue is full; what waits for the zone's active serial is handled at its next tick", "zone", zone)
	}
}

// releaseActivated is the data engine's tick for rule 6: every zone that
// keeps another agent's distribution, or has something of its own to send
// again, is handled. It catches what a full queue or a restart came
// between.
func (conf *Config) releaseActivated(ctx context.Context, zdr *ZoneDataRepo) {
	zones := map[string]ZoneName{}
	for _, z := range conf.InternalMp.Kept.zones(listKept) {
		zones[z] = ZoneName(z)
	}
	if tm := conf.InternalMp.MPTransport; tm != nil {
		for _, z := range tm.notYets.zones() {
			zones[canonicalName(string(z))] = z
		}
	}
	for _, key := range slices.Sorted(maps.Keys(zones)) {
		conf.instrActivated(ctx, zdr, zones[key])
	}
}

// instrActivated handles what waits for the zone's active serial (design
// 3.3): the distributions of others that the zone keeps, in order, by the
// active serial now (those made under it are taken, judged by the
// instructions active now; those made under a lower one are refused; those
// made under a higher one stay), and then what this agent sends again to
// the peers that answered "not yet" (resendInStep). Run by the data engine,
// which alone takes from the lists. A zone whose serials this agent no
// longer keeps drops what it kept.
func (conf *Config) instrActivated(ctx context.Context, zdr *ZoneDataRepo, zone ZoneName) {
	k := conf.InternalMp.Kept
	if entries := k.entries(string(zone), listKept); len(entries) > 0 {
		active, kept := conf.InternalMp.Instructions.activeSerial(string(zone))
		if !kept {
			lgEngine.Info("the zone's serials are gone: the distributions it kept are dropped", "zone", zone, "kept", len(entries))
		}
		for _, e := range entries {
			if kept && receiptOf(active, madeUnder(e.Update.Instr)) == receiptKeep {
				continue // made under a higher serial: it waits on
			}
			if kept {
				conf.releaseKept(ctx, zdr, zone, e)
			}
			if err := k.remove(string(zone), listKept, e.Seq); err != nil {
				lgEngine.Error("a kept distribution could not be taken off its list", "zone", zone, "err", err)
			}
		}
	}
	conf.resendInStep(zdr, zone)
}

// releaseKept hands a kept distribution to the data engine's remote case
// again, which takes it or refuses it as stale. Its sender is asked again
// whether it may send to this agent for the zone (membership step 6): the
// instructions active now decide, and a refusal is final.
func (conf *Config) releaseKept(ctx context.Context, zdr *ZoneDataRepo, zone ZoneName, e keptEntry) {
	msgQs := conf.InternalMp.MsgQs
	u, err := e.remoteUpdate(zone)
	if err != nil {
		lgEngine.Error("a kept distribution cannot be read; it is dropped", "zone", zone, "distrib", e.Distribution, "err", err)
		return
	}
	sender := u.DeliveredBy
	if sender == "" {
		sender = u.AgentId
	}
	if tm := conf.InternalMp.MPTransport; tm != nil && tm.agentRegistry != nil {
		if ok, why := tm.IsPeerAuthorized(string(sender), string(zone)); !ok {
			lgEngine.Info("a kept distribution is refused at its release: its sender may not send for the zone now", "zone", zone, "peer", u.AgentId, "distrib", u.OriginatingDistID, "why", why)
			if u.OriginatingDistID != "" && msgQs != nil && msgQs.OnRemoteConfirmationReady != nil {
				msgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{OriginatingDistID: u.OriginatingDistID, OriginatingSender: string(u.AgentId),
					Mechanism: u.Mechanism, Zone: zone, Status: "REJECTED", Message: "refused at its release: " + why})
			}
			return
		}
	}
	lgEngine.Info("a kept distribution is released", "zone", zone, "peer", u.AgentId, "distrib", u.OriginatingDistID, "made_under", activeName(madeUnder(u.OriginatingInstr)))
	conf.applyRemoteUpdate(ctx, zdr, u, msgQs)
}

// notYet is a distribution of this agent's that a peer answered "not yet":
// the zone, the peer, the distribution, and the peer's stamp in its
// answer.
type notYet struct {
	zone   ZoneName
	peer   AgentId
	distID string
	answer *MsgStamp
	at     time.Time
}

// notYetBook holds what waits to be sent again once this agent and the
// peer are in step, by zone (folded), then peer (folded) and distribution.
type notYetBook struct {
	mu   sync.Mutex
	open map[string]map[string]*notYet
}

// notYetsKept bounds what the book holds: the oldest go first. A peer that
// never comes into step holds a distribution no longer than that.
const notYetsKept = 2000

func notYetKey(peer AgentId, distID string) string { return canonicalName(string(peer)) + " " + distID }

// add puts n in the book, in the place of what the book held of the same
// distribution and peer.
func (b *notYetBook) add(n *notYet) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open == nil {
		b.open = map[string]map[string]*notYet{}
	}
	z := canonicalName(string(n.zone))
	if b.open[z] == nil {
		b.open[z] = map[string]*notYet{}
	}
	b.open[z][notYetKey(n.peer, n.distID)] = n
	var all []*notYet
	for _, m := range b.open {
		for _, o := range m {
			all = append(all, o)
		}
	}
	if len(all) <= notYetsKept {
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for _, o := range all[:len(all)-notYetsKept] {
		b.dropLocked(o.zone, o.peer, o.distID)
	}
}

// forZone is what the book holds of zone, oldest first.
func (b *notYetBook) forZone(zone ZoneName) []*notYet {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := slices.Collect(maps.Values(b.open[canonicalName(string(zone))]))
	sort.Slice(out, func(i, j int) bool { return out[i].at.Before(out[j].at) })
	return out
}

// drop takes a distribution to a peer out of the book.
func (b *notYetBook) drop(zone ZoneName, peer AgentId, distID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropLocked(zone, peer, distID)
}

func (b *notYetBook) dropLocked(zone ZoneName, peer AgentId, distID string) {
	z := canonicalName(string(zone))
	delete(b.open[z], notYetKey(peer, distID))
	if len(b.open[z]) == 0 {
		delete(b.open, z)
	}
}

// zones are the zones the book holds something of.
func (b *notYetBook) zones() []ZoneName {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []ZoneName
	for _, m := range b.open {
		for _, n := range m {
			out = append(out, n.zone)
			break
		}
	}
	return out
}

// notYetFrom is rule 6 at the sender (decision 76): a final answer other
// than a success, from a peer whose stamp tells another active serial than
// this agent's stamp of the send it answers told, is no decision yet. A
// success and a PENDING report facts and are taken as they come. So is an
// answer when either stamp tells no active serial, as the receiver takes a
// message whose stamp tells none: the combiner's, which tells what it acts
// by apart (confirmActing), and that of a peer that does not know its
// active serial yet. A refusal that names stale-instructions is the
// receiver's own word that the message was made under older instructions
// (decision 31): never a decision, whichever send it answers, though the
// latest send may have been made under the receiver's serial.
func (tm *MPTransportBridge) notYetFrom(distID, peer string, status transport.ConfirmStatus, message string, answer *MsgStamp) bool {
	switch status {
	case transport.ConfirmRejected:
		if strings.HasPrefix(message, staleInstructions+":") {
			return true
		}
	case transport.ConfirmIgnored, transport.ConfirmFailed, transport.ConfirmPartial:
	default:
		return false
	}
	sent, told := madeUnder(tm.stamps.sentStamp(distID, peer)), madeUnder(answer)
	return sent != nil && told != nil && *sent != *told
}

// noteNotYet books an answer that is "not yet", and asks the data engine
// to send the distribution again at once if the two are in step already:
// the trigger, this agent's activation, has then fired (decision 52).
func (tm *MPTransportBridge) noteNotYet(zone ZoneName, peer AgentId, distID string, answer *MsgStamp) {
	lgEngine.Info("an answer from a peer at other instructions is not final; sending again when in step", "zone", zone, "peer", peer, "distrib", distID)
	tm.notYets.add(&notYet{zone: zone, peer: peer, distID: distID, answer: answer, at: time.Now()})
	if tm.msgQs == nil || tm.msgQs.SynchedDataCmd == nil {
		return
	}
	select {
	case tm.msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "instr-activated", Zone: zone}:
	default:
		// the engine's tick sends it (releaseActivated)
	}
}

// resendInStep sends again what this agent contributes to the zone, to each
// peer that answered "not yet", once this agent's active serial has caught
// up with the one the peer answered under: a complete replace per type, as
// a complete answer to a request for the zone's state has it but with no
// catch_up, the leader's KEY with its publish instruction (#206), under the
// distribution's own ID, so that the peer's answer settles what waits for
// it there, a key's propagation included. A peer
// ahead of this agent waits for its activation; past the peer, the peer
// keeps it until it catches up (rule 6). Nothing goes once this agent's
// provider no longer contributes to the zone. A zone whose answer cannot be
// complete yet waits for the engine's next tick.
func (conf *Config) resendInStep(zdr *ZoneDataRepo, zone ZoneName) {
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		return
	}
	open := tm.notYets.forZone(zone)
	if len(open) == 0 {
		return
	}
	active, _ := conf.InternalMp.Instructions.activeSerial(string(zone))
	if active == nil {
		return
	}
	var due []*notYet
	for _, n := range open {
		if peer := madeUnder(n.answer); peer == nil || CompareSerial(active.Serial, peer.Serial) >= 0 {
			due = append(due, n)
		}
	}
	if len(due) == 0 {
		return
	}
	self := AgentId(conf.MpConfig().Identity)
	if !votesInZone(zone, self) {
		lgEngine.Info("this provider no longer contributes to the zone: nothing is sent again", "zone", zone, "dropped", len(due))
		for _, n := range due {
			tm.notYets.drop(zone, n.peer, n.distID)
		}
		return
	}
	if why := conf.catchUpIncomplete(zdr, zone, self); why != "" {
		lgEngine.Debug("what this agent contributes cannot be sent again in full yet", "zone", zone, "why", why)
		return
	}
	ops := conf.catchUpOperations(zdr, zone, self)
	for _, n := range due {
		zu := &ZoneUpdate{Zone: zone, AgentId: self, Operations: ops, Publish: keyPublish(zone, ops)}
		if err := tm.EnqueueForSpecificAgent(zone, n.peer, zu, n.distID); err != nil {
			lgEngine.Warn("sending again to a peer now in step failed; the engine's tick tries again", "zone", zone, "peer", n.peer, "distrib", n.distID, "err", err)
			continue
		}
		tm.notYets.drop(zone, n.peer, n.distID)
		lgEngine.Info("sent again to a peer now in step", "zone", zone, "peer", n.peer, "distrib", n.distID, "active", active.Serial)
	}
}
