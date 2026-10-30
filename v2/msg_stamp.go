/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Stamps on messages and confirmations (design rules 4 and 6, plan S5b).
 * Every sync-family, EDITS, CONFIG and AUDIT message an agent or the
 * auditor sends carries its stamp of the message's zone, set when it is
 * sent, not when it is queued: a resend carries the stamp of the resend.
 * Every confirmation carries the confirmer's, in tdns-transport's
 * application field (P2). A receiver notes each as its sender's telling,
 * first hand, ordered with the sender's beats by epoch and sequence
 * (instr_stamp.go). The transport's inline acknowledgement is an answer and
 * carries none. Each distribution keeps, per recipient, the stamp of its
 * latest send and of the recipient's latest confirmation; S8 judges by
 * them.
 */
package tdnsmp

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// MsgStamp is the stamp a message or a confirmation carries; its wire form
// is package hsync's.
type MsgStamp = hsync.MsgStamp

// confirmApp is what tdns-mp carries in a confirmation's application field.
type confirmApp struct {
	Instr *MsgStamp `json:"instr,omitempty"` // the confirmer's stamp
	// Acting is the combiner's: the serial it acts by (plan S8). It is no
	// member's telling, so never "instr": a combiner acting by an older
	// serial would read as an owner error.
	Acting *ActingStamp `json:"acting,omitempty"`
}

// ActingStamp is the serial a combiner acts by, as its confirmations tell
// it: what its agent last handed it, by serial, digest and step.
type ActingStamp struct {
	Serial uint32 `json:"serial"`
	Digest string `json:"digest"`
	Step   int    `json:"step"`
}

// actingStampOf is the stamp of a hand-over; nil for none.
func actingStampOf(h *ActingHandover) *ActingStamp {
	if h == nil {
		return nil
	}
	return &ActingStamp{Serial: h.Serial, Digest: h.Digest, Step: h.Step}
}

// names: the stamp names the hand-over h, by serial, digest and step.
func (a *ActingStamp) names(h *ActingHandover) bool {
	return h != nil && a.Serial == h.Serial && a.Digest == h.Digest && a.Step == h.Step
}

// actingAppFor is the application field of a combiner's confirmation for
// zone: the serial it acts by; nil while it was handed nothing for it.
func actingAppFor(zone string) json.RawMessage {
	held, ok := actingHeld.Load().get(zone)
	if !ok {
		return nil
	}
	b, err := json.Marshal(confirmApp{Acting: actingStampOf(held.handover)})
	if err != nil {
		return nil
	}
	return b
}

// confirmActing is the serial a combiner's confirmation says it acts by;
// nil with none, or one that does not parse.
func confirmActing(app json.RawMessage) *ActingStamp {
	if len(app) == 0 {
		return nil
	}
	var ca confirmApp
	if err := json.Unmarshal(app, &ca); err != nil {
		return nil
	}
	return ca.Acting
}

// messageStamp is this agent's stamp of zone for a message it sends now:
// nil on a role that tells nothing, and for a zone whose serials it keeps
// none of.
func (t *stampTable) messageStamp(zone string) *MsgStamp {
	if t == nil {
		return nil
	}
	st, ok := t.ownStamp(zone)
	if !ok {
		return nil
	}
	return &MsgStamp{Epoch: t.epoch, Seq: t.seq.Add(1), InstrStamp: st}
}

// confirmAppFor is a confirmation's application field with this agent's
// stamp of zone; nil with none.
func (t *stampTable) confirmAppFor(zone string) json.RawMessage {
	ms := t.messageStamp(zone)
	if ms == nil {
		return nil
	}
	b, err := json.Marshal(confirmApp{Instr: ms})
	if err != nil {
		return nil
	}
	return b
}

// confirmStamp is the confirmer's stamp in a confirmation's application
// field; nil with none, or one that does not parse.
func confirmStamp(app json.RawMessage) *MsgStamp {
	if len(app) == 0 {
		return nil
	}
	var ca confirmApp
	if err := json.Unmarshal(app, &ca); err != nil {
		lgTransport.Debug("a confirmation's application field does not parse", "err", err)
		return nil
	}
	return ca.Instr
}

// noteMessage keeps the stamp of zone that sender told in a message it sent,
// or in its confirmation: first hand, unless what is kept of sender's
// telling of zone is newer. A later epoch replaces all that was kept of
// sender, and has every zone told to it once, as a beat's does (design
// 3.4, plan S22).
func (t *stampTable) noteMessage(sender, zone string, ms *MsgStamp) {
	if t == nil || ms == nil || sender == "" || zone == "" {
		return
	}
	key, z := canonicalName(sender), canonicalName(zone)
	now := time.Now()
	t.mu.Lock()
	old := t.kept[key]
	switch {
	case old == nil || ms.Epoch > old.Epoch:
		t.kept[key] = &memberStamp{Identity: dns.Fqdn(sender), Epoch: ms.Epoch, Heard: now,
			Instr: map[string]InstrStamp{z: ms.InstrStamp}, ZoneSeq: map[string]uint64{z: ms.Seq}, ZoneHeard: map[string]time.Time{z: now}}
		t.tellOnceLocked(key)
	case ms.Epoch < old.Epoch || ms.Seq <= old.ZoneSeq[z]:
		t.mu.Unlock()
		return
	default:
		if old.ZoneHeard == nil {
			old.ZoneHeard = map[string]time.Time{}
		}
		old.Instr[z], old.ZoneSeq[z], old.ZoneHeard[z], old.Heard = ms.InstrStamp, ms.Seq, now, now
	}
	t.mu.Unlock()
	lgGossip.Debug("a member's stamp noted from its message", "zone", zone, "member", sender, "seq", ms.Seq)
	t.judgeTold(z)
	t.fetchIfNewer(z, &memberStamp{Identity: dns.Fqdn(sender), Instr: map[string]InstrStamp{z: ms.InstrStamp}})
	if t.onTold != nil {
		t.onTold(z)
	}
}

// stampedVerbs are the messages that carry their sender's stamp in an
// "instr" field. A confirmation carries it in its application field
// (OnConfirmationReceived), and a beat in its stamp entry.
var stampedVerbs = map[string]bool{"sync": true, "update": true, "rfi": true, "edits": true, "config": true, "audit": true}

// noteMessageStamp is the router middleware of the agent and the auditor,
// after every refusal (routerMiddleware): the stamp a message carries is
// noted as its sender's telling, the sender being the one the transport
// established and refuseNamedSender held the payload to.
func (tm *MPTransportBridge) noteMessageStamp(ctx *transport.MessageContext, next transport.MessageHandlerFunc) error {
	if msg, ok := ctx.Incoming(); ok && tm.stamps != nil && stampedVerbs[msg.Token()] {
		sender := ctx.PeerID
		if sender == "" {
			sender = msg.TransportSender
		}
		var carried struct {
			Instr *MsgStamp `json:"instr"`
		}
		if sender != "" && json.Unmarshal(msg.Payload, &carried) == nil && carried.Instr != nil {
			tm.stamps.noteMessage(sender, msg.Zone, carried.Instr)
		}
	}
	return next(ctx)
}

// distStamp is what a distribution keeps of one recipient's stamps: this
// agent's at its latest send, the recipient's at its latest confirmation.
type distStamp struct {
	Distribution string
	Recipient    string
	Zone         string
	Sent         *MsgStamp
	SentAt       time.Time
	Confirmed    *MsgStamp
	Status       string
	ConfirmedAt  time.Time
}

// distStampsKept bounds the distributions kept: the oldest sends go first.
const distStampsKept = 2000

func distKey(distID, recipient string) string { return distID + " " + canonicalName(recipient) }

// sent records the stamp of a send of distribution distID to recipient.
// A send without a distribution ID is not recorded.
func (t *stampTable) sent(distID, recipient, zone string, ms *MsgStamp) {
	if t == nil || distID == "" || recipient == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dists == nil {
		t.dists = map[string]*distStamp{}
	}
	key := distKey(distID, recipient)
	d := t.dists[key]
	if d == nil {
		d = &distStamp{Distribution: distID, Recipient: dns.Fqdn(recipient), Zone: zone}
		t.dists[key] = d
	}
	d.Sent, d.SentAt = ms, time.Now()
	if len(t.dists) > distStampsKept {
		t.pruneDistsLocked()
	}
}

// sentStamp is this agent's stamp at its latest send of distribution
// distID to recipient; nil when none is recorded.
func (t *stampTable) sentStamp(distID, recipient string) *MsgStamp {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if d := t.dists[distKey(distID, recipient)]; d != nil {
		return d.Sent
	}
	return nil
}

// laterStamp reports whether a member stamped a after b: in a later start,
// or later in the same one.
func laterStamp(a, b *MsgStamp) bool {
	return a.Epoch > b.Epoch || (a.Epoch == b.Epoch && a.Seq > b.Seq)
}

// replacesConfirmation reports whether a confirmation, with its stamp and
// status, takes the place of the one kept: the later by their stamps when
// both carry one, and otherwise anything but a PENDING after a final word.
// A confirmer sends its PENDING and its final word apart
// (sendImmediateConfirmation, sendRemoteConfirmation), so the PENDING can
// arrive last.
func replacesConfirmation(kept *MsgStamp, keptStatus string, ms *MsgStamp, status string) bool {
	if kept != nil && ms != nil {
		return laterStamp(ms, kept)
	}
	pending := transport.ConfirmPending.String()
	return status != pending || keptStatus == "" || keptStatus == pending
}

// confirmed records the confirmer's stamp of distribution distID, and its
// status, unless the confirmation kept is the later (replacesConfirmation).
// A confirmation of a distribution this agent sent no recorded send of
// starts a row of its own; the rows are bounded as sent's are.
func (t *stampTable) confirmed(distID, confirmer, zone string, ms *MsgStamp, status string) {
	if t == nil || distID == "" || confirmer == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dists == nil {
		t.dists = map[string]*distStamp{}
	}
	key := distKey(distID, confirmer)
	d := t.dists[key]
	if d == nil {
		d = &distStamp{Distribution: distID, Recipient: dns.Fqdn(confirmer), Zone: zone}
		t.dists[key] = d
	}
	if !replacesConfirmation(d.Confirmed, d.Status, ms, status) {
		return
	}
	d.Confirmed, d.Status, d.ConfirmedAt = ms, status, time.Now()
	if len(t.dists) > distStampsKept {
		t.pruneDistsLocked()
	}
}

// pruneDistsLocked drops the rows of the oldest sends, down to three
// quarters of what is kept. Called with t.mu held.
func (t *stampTable) pruneDistsLocked() {
	rows := make([]*distStamp, 0, len(t.dists))
	for _, d := range t.dists {
		rows = append(rows, d)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].lastAt().Before(rows[j].lastAt()) })
	for _, d := range rows[:len(rows)-distStampsKept*3/4] {
		delete(t.dists, distKey(d.Distribution, d.Recipient))
	}
}

func (d *distStamp) lastAt() time.Time {
	if d.ConfirmedAt.After(d.SentAt) {
		return d.ConfirmedAt
	}
	return d.SentAt
}

// DistributionStamps is one row of `agent distrib stamps`: a distribution
// and a recipient, with this agent's stamp at its latest send and the
// recipient's at its latest confirmation.
type DistributionStamps struct {
	DistributionID string        `json:"distribution_id"`
	Recipient      string        `json:"recipient"`
	Zone           string        `json:"zone,omitempty"`
	Sent           *SerialDigest `json:"sent,omitempty"` // this agent's active serial at the send
	SentNewest     *SerialDigest `json:"sent_newest,omitempty"`
	SentAt         time.Time     `json:"sent_at,omitzero"`
	Confirmed      *SerialDigest `json:"confirmed,omitempty"` // the recipient's active serial at its confirmation
	ConfirmedNew   *SerialDigest `json:"confirmed_newest,omitempty"`
	Status         string        `json:"status,omitempty"`
	ConfirmedAt    time.Time     `json:"confirmed_at,omitzero"`
}

// distributionStamps are the rows kept, newest first; with zone, those of
// that zone only.
func (t *stampTable) distributionStamps(zone string) []DistributionStamps {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	rows := make([]*distStamp, 0, len(t.dists))
	for _, d := range t.dists {
		if zone == "" || canonicalName(d.Zone) == canonicalName(zone) {
			c := *d
			rows = append(rows, &c)
		}
	}
	t.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].lastAt().After(rows[j].lastAt()) })
	out := make([]DistributionStamps, 0, len(rows))
	for _, d := range rows {
		r := DistributionStamps{DistributionID: d.Distribution, Recipient: d.Recipient, Zone: d.Zone,
			SentAt: d.SentAt, Status: d.Status, ConfirmedAt: d.ConfirmedAt}
		r.Sent, r.SentNewest = stampSerials(d.Sent)
		r.Confirmed, r.ConfirmedNew = stampSerials(d.Confirmed)
		out = append(out, r)
	}
	return out
}

// stampSerials are a stamp's active and newest serials; nil for what it
// does not tell.
func stampSerials(ms *MsgStamp) (active, newest *SerialDigest) {
	if ms == nil {
		return nil, nil
	}
	if ms.Known && ms.ActiveDigest != "" {
		active = &SerialDigest{Serial: ms.Active, Digest: ms.ActiveDigest}
	}
	if ms.NewestDigest != "" {
		newest = &SerialDigest{Serial: ms.Newest, Digest: ms.NewestDigest}
	}
	return active, newest
}

// noteConfirmation is what a confirmation's stamp does at the bridge: it is
// the confirmer's telling, first hand (the confirmation is a message the
// confirmer sent, its sender held to the transport's by refuseNamedSender);
// and the distribution keeps it for the confirmer. A DNSKEY propagation
// keeps it with each result the answer gives (processDnskeyConfirmation).
func (tm *MPTransportBridge) noteConfirmation(c *transport.IncomingConfirmation, ms *MsgStamp) {
	tm.stamps.confirmed(c.DistributionID, c.PeerID, c.Zone, ms, c.Status.String())
	if ms == nil {
		return
	}
	tm.stamps.noteMessage(c.PeerID, c.Zone, ms)
}

// stampResultLocked keeps ms as the stamp of agent's result for key kt: the
// stamp of the answer that gave the result, which no later confirmation
// replaces, as no later answer replaces the result. Under dnskeyPropMu.
func (prop *PendingDnskeyPropagation) stampResultLocked(agent AgentId, kt uint16, ms *MsgStamp) {
	if ms == nil {
		return
	}
	if prop.Stamps == nil {
		prop.Stamps = map[AgentId]map[uint16]*MsgStamp{}
	}
	if prop.Stamps[agent] == nil {
		prop.Stamps[agent] = map[uint16]*MsgStamp{}
	}
	prop.Stamps[agent][kt] = ms
}
