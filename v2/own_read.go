/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The agent's own state of a zone (the membership design, 5.4): what its
 * combiner holds of the zone's contributions, and its signer's key
 * inventory. An agent answers a request for the zone's state as complete
 * only once it has read both: empty sets from an agent that has not read
 * its own state would remove its contributions at every peer.
 */

package tdnsmp

import (
	"context"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// ownReadInterval: how often a zone whose own read is not done is read
// again. A variable for the tests.
var ownReadInterval = 30 * time.Second

// ownReadsAtOnce: the re-reads that may wait for their answers at once.
const ownReadsAtOnce = 8

// noteMaxAge: how long the reliable queue keeps a message before it gives
// it up; a note older than that, unconfirmed, is confirmed by nobody.
const noteMaxAge = 24 * time.Hour

// Why an answer to a request for the zone's state is not complete (the
// catch-up object's "why").
const (
	whyZoneNotLoaded   = "zone-not-loaded"
	whyOwnStateNotRead = "own-state-not-read"
	whyNoInventory     = "no-inventory"
)

// setNote is what the data engine notes of the last change it stored of one
// agent's set of one type in a zone, and passed to its combiner: when it
// stored it, the distribution under which it went to the combiner (empty
// when the send failed), and when the combiner's final confirmation of
// that distribution arrived (zero until then). A late answer to a request
// for the combiner's contributions must not undo what the engine did while
// the request was out (mayApplyOwnRead). Engine only, as Tracking is.
type setNote struct {
	changed   time.Time
	distID    string
	confirmed time.Time
}

// noteCombinerSend notes that the engine stored a change of agent's sets of
// these types at changed, and passed it to its combiner under distID ("" when
// the send failed).
func (zdr *ZoneDataRepo) noteCombinerSend(zone ZoneName, agent AgentId, rrtypes []uint16, changed time.Time, distID string) {
	if zdr.notes == nil {
		zdr.notes = map[ZoneName]map[AgentId]map[uint16]*setNote{}
	}
	if zdr.notes[zone] == nil {
		zdr.notes[zone] = map[AgentId]map[uint16]*setNote{}
	}
	if zdr.notes[zone][agent] == nil {
		zdr.notes[zone][agent] = map[uint16]*setNote{}
	}
	for _, t := range rrtypes {
		zdr.notes[zone][agent][t] = &setNote{changed: changed, distID: distID}
	}
}

// noteCombinerConfirmed notes the combiner's final confirmation of distID.
// For a set that an empty replace emptied no record carries the ID, so the
// note is found by the ID, not through the records.
func (zdr *ZoneDataRepo) noteCombinerConfirmed(zone ZoneName, distID string, at time.Time) {
	if distID == "" {
		return
	}
	for _, byType := range zdr.notes[zone] {
		for _, n := range byType {
			if n.distID == distID && n.confirmed.IsZero() {
				n.confirmed = at
			}
		}
	}
}

// setsNotHandedOver are those of types whose last change here, of agent's
// set, this agent's combiner may not have. With failedOnly, only a set whose
// hand-over failed (no distribution); else also one the combiner has not
// confirmed yet. The repo has the set either way, so the repo alone does not
// say the combiner does; the set note is the trace, for a set an omission or
// an empty replace changed as much as for one with records.
func (zdr *ZoneDataRepo) setsNotHandedOver(zone ZoneName, agent AgentId, types []uint16, failedOnly bool) map[uint16]bool {
	var out map[uint16]bool
	for _, t := range types {
		n := zdr.notes[zone][agent][t]
		if n == nil || (n.distID != "" && (failedOnly || !n.confirmed.IsZero())) {
			continue
		}
		if out == nil {
			out = map[uint16]bool{}
		}
		out[t] = true
	}
	return out
}

// recordsNotOfTypes are those of records whose type is not among types.
func recordsNotOfTypes(records []string, types map[uint16]bool) []string {
	if len(types) == 0 {
		return records
	}
	var out []string
	for _, s := range records {
		if rr, err := dns.NewRR(s); err == nil && types[rr.Header().Rrtype] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// mayApplyOwnRead: the combiner's answer to a request sent at sentAt may set
// agent's set of rrtype. A set with no note, which no update has changed
// since the agent started, may. A set whose last change the combiner had
// confirmed before sentAt may: the answer holds it. A set changed after
// sentAt, one whose last change the combiner confirmed after sentAt or not
// at all, and one whose send to the combiner failed, may not: the answer
// can predate what the engine holds.
//
// A change the combiner has not confirmed a day after it was stored never
// will be: the queue has given its message up by then (noteMaxAge). The
// combiner's answer is the truth for that set again.
func (zdr *ZoneDataRepo) mayApplyOwnRead(zone ZoneName, agent AgentId, rrtype uint16, sentAt time.Time) bool {
	n := zdr.notes[zone][agent][rrtype]
	if n == nil {
		return true
	}
	if n.distID != "" && n.confirmed.IsZero() && sentAt.Sub(n.changed) > noteMaxAge {
		return true
	}
	if n.distID == "" || n.changed.After(sentAt) || n.confirmed.IsZero() || n.confirmed.After(sentAt) {
		return false
	}
	return true
}

// updateRRtypes are the types of the sets an update changes.
func updateRRtypes(u *ZoneUpdate) []uint16 {
	if u == nil {
		return nil
	}
	seen := map[uint16]bool{}
	var out []uint16
	add := func(t uint16) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, op := range u.Operations {
		if t, ok := dns.StringToType[op.RRtype]; ok {
			add(t)
		}
	}
	for t := range u.RRsets {
		add(t)
	}
	for _, rr := range u.RRs {
		add(rr.Header().Rrtype)
	}
	return out
}

// OwnStateRead: the agent has read its own state of the zone from its
// combiner, with the combiner's word that its stored contributions were
// loaded.
func (zdr *ZoneDataRepo) OwnStateRead(zone ZoneName) bool {
	zdr.mu.Lock()
	defer zdr.mu.Unlock()
	return !zdr.ownState[zone].IsZero()
}

// ownStateWhy is why the zone's own read is not done, for the log and the
// status. Empty when it is done.
func (zdr *ZoneDataRepo) ownStateWhy(zone ZoneName) string {
	zdr.mu.Lock()
	defer zdr.mu.Unlock()
	if !zdr.ownState[zone].IsZero() {
		return ""
	}
	if why := zdr.ownStateNote[zone]; why != "" {
		return why
	}
	return "the combiner has not been asked yet"
}

// markOwnState records the outcome of an own read of the zone from the
// combiner: read, or not and why.
func (zdr *ZoneDataRepo) markOwnState(zone ZoneName, read bool, why string) {
	zdr.mu.Lock()
	defer zdr.mu.Unlock()
	if zdr.ownState == nil {
		zdr.ownState = map[ZoneName]time.Time{}
		zdr.ownStateNote = map[ZoneName]string{}
	}
	if read {
		zdr.ownState[zone] = time.Now()
		delete(zdr.ownStateNote, zone)
		return
	}
	if zdr.ownState[zone].IsZero() {
		zdr.ownStateNote[zone] = why
	}
}

// ownReadAnswer is what a re-read brought: when the combiner was asked
// (asked), its answer and when the request was sent (sentAt), or why there
// is none.
type ownReadAnswer struct {
	zone   ZoneName
	asked  bool
	resp   *EditsResponseMsg
	sentAt time.Time
	err    error
	reread bool // the re-read's (ownReader), not the start-up read's or a resync's
}

// applyOwnRead applies an answer of the combiner to the agent's data and
// says whether it counts as the agent's own read. Only the combiner's word
// editsLoaded counts. editsNotLoaded is applied to nothing. Any other word
// is from a combiner older than the agent, and does not count: its answer
// is applied once for the zone, at its first read, as such answers always
// were, and again at a resync; and only when it carries records. An empty
// one is what such a combiner sends after a failed read of its store, and
// would drop records this agent holds. The re-read, which runs every
// ownReadInterval while the own read is not done, applies no such answer
// after the first: it would apply it again and again. self is this agent:
// its own DNSKEY set is never applied (applyEditsToSDE). The apply makes no
// note.
func applyOwnRead(zd *MPZoneData, a *ownReadAnswer, zdr *ZoneDataRepo, self AgentId) {
	if !a.asked {
		return
	}
	if a.err != nil {
		zdr.markOwnState(a.zone, false, a.err.Error())
		return
	}
	switch a.resp.Message {
	case editsNotLoaded:
		zdr.markOwnState(a.zone, false, "the combiner has not loaded the zone's stored contributions")
		lgEngine.Info("the combiner has not loaded the zone's stored contributions; this agent's own state is not read", "zone", a.zone)
		return
	case editsLoaded:
		applyEditsToSDE(zd.ZoneData, a.resp.AgentRecords, zdr, self, a.sentAt)
		zdr.markOwnState(a.zone, true, "")
	default:
		applied := editsRecordCount(a.resp.AgentRecords) > 0 && !(a.reread && zdr.olderApplied[a.zone])
		if applied {
			applyEditsToSDE(zd.ZoneData, a.resp.AgentRecords, zdr, self, a.sentAt)
			if zdr.olderApplied == nil {
				zdr.olderApplied = map[ZoneName]bool{}
			}
			zdr.olderApplied[a.zone] = true
		}
		why := "the combiner answered without the loaded token: is it older than the agent?"
		zdr.markOwnState(a.zone, false, why)
		lgEngine.Warn("the combiner's answer does not say that its stored contributions are loaded; this agent's own state is not read", "zone", a.zone, "why", why, "applied", applied)
	}
}

// ownReader re-reads the own state of the zones whose own read is not done,
// every ownReadInterval, without blocking the data engine: each read waits
// for its answer on a goroutine of its own, at most ownReadsAtOnce at a time,
// and hands the answer back to the engine, which applies it. The engine
// owns inFlight.
type ownReader struct {
	conf     *Config
	msgQs    *MsgQs
	zdr      *ZoneDataRepo
	slots    chan struct{}
	inFlight map[ZoneName]bool
	noneSaid bool
}

func newOwnReader(conf *Config, msgQs *MsgQs, zdr *ZoneDataRepo) *ownReader {
	return &ownReader{conf: conf, msgQs: msgQs, zdr: zdr, slots: make(chan struct{}, ownReadsAtOnce), inFlight: map[ZoneName]bool{}}
}

// tick starts a re-read of each multi-provider zone that has loaded and
// whose own read is not done, unless one is in flight for it.
func (r *ownReader) tick(ctx context.Context) {
	tm := r.conf.InternalMp.MPTransport
	if tm == nil {
		return
	}
	for _, name := range Zones.Keys() {
		zd, ok := Zones.Get(name)
		if !ok || !zd.Options[tdns.OptMultiProvider] {
			continue
		}
		zone := ZoneName(zd.ZoneName)
		if r.inFlight[zone] || !zd.loadedForCatchUp() {
			continue
		}
		needCombiner := !r.zdr.OwnStateRead(zone)
		needSigner := zd.signsWithoutInventory() && tm.signerID != ""
		if needCombiner && !r.conf.namesCombiner() {
			needCombiner = false
			if !r.noneSaid {
				r.noneSaid = true
				lgEngine.Warn("this agent's configuration names no combiner: it cannot read its own state, and answers no request for a zone's state as complete")
			}
			r.zdr.markOwnState(zone, false, "this agent's configuration names no combiner")
		}
		if !needCombiner && !needSigner {
			continue
		}
		r.inFlight[zone] = true
		r.conf.InternalMp.ownReads.Add(1)
		go func() {
			defer r.conf.InternalMp.ownReads.Done()
			select {
			case r.slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-r.slots }()
			r.read(ctx, zd, needCombiner, needSigner)
		}()
	}
}

// read is one re-read of the zone, on its own goroutine: the combiner's
// contributions, and the signer's inventory for a provider that signs and
// has none. The inventory is handed on as a pushed one, which the hsync
// data engine records (handleKeystateInventory); the answer from the
// combiner goes back to the data engine, which applies it.
func (r *ownReader) read(ctx context.Context, zd *MPZoneData, combiner, signer bool) {
	zone := ZoneName(zd.ZoneName)
	tm := r.conf.InternalMp.MPTransport
	if signer {
		if inv := zd.requestKeyInventory(ctx, tm); inv != nil && r.msgQs.KeystateInventory != nil {
			select {
			case r.msgQs.KeystateInventory <- inv:
			case <-ctx.Done():
			}
		}
	}
	a := &ownReadAnswer{zone: zone}
	if combiner {
		resp, sentAt, err := r.conf.editsRequester()(ctx, zd.ZoneData, tm, r.msgQs)
		a = &ownReadAnswer{zone: zone, asked: true, resp: resp, sentAt: sentAt, err: err, reread: true}
	}
	select {
	case r.msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "own-read", Zone: zone, ownRead: a}:
	case <-ctx.Done():
	}
}

// done is the engine's word that the zone's re-read has ended, with an
// answer or without one.
func (r *ownReader) done(zone ZoneName) {
	delete(r.inFlight, zone)
}

// namesCombiner: this agent's configuration names its combiner. The bridge
// cannot tell: without one it uses a default identity.
func (conf *Config) namesCombiner() bool {
	mp := conf.MpConfig()
	return mp != nil && mp.Combiner != nil && mp.Combiner.Identity != ""
}

// loadedForCatchUp: the zone has loaded here, and its multi-provider data
// is the first load's, not the stub main_init puts in place, which reads as
// no provider (MPPreRefresh replaces it at the first load).
func (mpzd *MPZoneData) loadedForCatchUp() bool {
	if !mpzd.Ready {
		return false
	}
	mpzd.Lock()
	defer mpzd.Unlock()
	return mpzd.MP != nil && mpzd.MP.MPdata != nil && mpzd.MP.MPdata.WeAreProvider
}

// hasProviderData: the load gave the zone provider data (populateMPdata):
// it is a multi-provider zone that names this agent. Before the first load
// that is main_init's stub.
func (mpzd *MPZoneData) hasProviderData() bool {
	mpzd.Lock()
	defer mpzd.Unlock()
	return mpzd.MP != nil && mpzd.MP.MPdata != nil
}

// signsWithoutInventory: this provider signs the zone, and its signer's
// inventory has not been received.
func (mpzd *MPZoneData) signsWithoutInventory() bool {
	mpzd.Lock()
	signs := mpzd.MP != nil && mpzd.MP.MPdata != nil && mpzd.MP.MPdata.ZoneSigned && mpzd.MP.MPdata.WeAreSigner
	mpzd.Unlock()
	return signs && mpzd.GetLastKeyInventory() == nil
}

// editsRecordCount is the number of records in an EDITS answer.
func editsRecordCount(recs map[string]map[string][]string) int {
	n := 0
	for _, owners := range recs {
		for _, rrs := range owners {
			n += len(rrs)
		}
	}
	return n
}
