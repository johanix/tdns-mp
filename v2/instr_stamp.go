/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Stamps in beats (design rule 4, plan S5a). What an agent tells of its
 * zones' instructions rides in each of its beats, in a gossip entry of its
 * own outside the groups (decision 30), whose one row is the sender's. A
 * receiver keeps each member's latest stamp, per zone, first hand only: from
 * a beat the member sent, as the row of the sender the transport
 * established. The answer to a beat counts for nothing (rule 4): no stamp
 * rides in one, and one that does is not noted. From the stamps come the
 * owner errors between agents (rule 2), the fetch of a newer serial (design
 * 3.1) and the status per member.
 */
package tdnsmp

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	transport "github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// InstrStamp is what an agent tells of one zone's instructions (design rule
// 4); its wire form is package hsync's.
type InstrStamp = hsync.InstrStamp

// stampGroupHash is the stamp entry's group hash, which no group has.
const stampGroupHash = hsync.StampGroupHash

// fetchInterval paces the fetch of a serial a member tells (design 3.1): an
// upstream that keeps serving an old copy causes no fetch at every beat.
const fetchInterval = time.Minute

// stampEntryBudget bounds the zones a stamp entry tells, in bytes of their
// JSON (plan S22, amended 2026-10-30): with the rest of a beat and the
// transport's envelope, a beat stays well under what one carries inline
// (tdns #987), however many zones something is going on in. What does not
// fit is told in the beats that follow, in turn (fillEntry): with K zones
// a beat, a change of n zones is told within ceil(2n/K) beats, ceil(n/K)
// while none is due, and a zone something is going on in at least every
// refresh plus ceil(2n/K) beats. A zone left out is heard no more until it
// is told again, so the leaving and the no-role time-outs, which read how
// fresh a telling is, must be well above that.
const stampEntryBudget = 16 << 10

// stampTable is what this agent tells in its beats and what its members
// have told it. Nil on the roles that tell nothing (the combiner, the
// signer): every method is a no-op on it.
type stampTable struct {
	localID     string
	store       *InstructionStore
	epoch       uint64
	crypto      bool     // payload encryption is on at this agent
	nameservers []string // this provider's own (multi-provider.local.nameservers)
	// rollover is rolloverUnderWay at this provider; nil: none known (the
	// auditor, which runs no key machine). waitsOn is whom it waits on.
	rollover func(zone string) bool
	waitsOn  func(zone string) []string
	// hold: this agent's signer has confirmed the zone's hold since this
	// agent came to hold the serial it agrees on (holdConfirmed, plan S6); nil on
	// the auditor, which has no signer.
	hold func(zone string) bool
	// stepHeld: this agent holds the zone's step at its active serial, its
	// combiner and its signer included (holdsStep, plan S12); nil on the
	// auditor, which has no parts.
	stepHeld func(zone string, sd SerialDigest, step InstrStep) bool
	// fetch asks a refresh of the zone's own copy, the zone named in any
	// case: the zone's name here ("" when this agent has no such zone), and
	// whether the refresh was queued. Nil: none.
	fetch func(zone string) (name string, queued bool)
	// onTold is asked of a zone after a member's first-hand stamp of it is
	// kept: the thaw's turn (plan S7). Nil: none.
	onTold func(zone string)
	// work is the zones, folded, this agent has work owed, kept or under
	// way for with peer (plan S22): its owed or its kept list, a catch-up
	// with peer, a message to peer not yet confirmed. Nil: none (the
	// auditor).
	work func(peer string) map[string]bool
	seq  atomic.Uint64

	mu      sync.Mutex
	kept    map[string]*memberStamp // by identity, folded (canonicalName)
	fetched map[string]fetchMark    // by zone, folded
	said    map[string]bool         // the lines logged once
	dists   map[string]*distStamp   // by distribution and recipient (msg_stamp.go)
	// once is, by peer folded, the zones, folded, still to be told once
	// since its new epoch (plan S22); a nil set: every zone the two share,
	// not yet counted.
	once map[string]map[string]bool
	// cursor is, by peer folded, the last zone, folded, of each rank told
	// in an acknowledged beat to it (acknowledged): the next beat goes on
	// after it. pending is the latest beat made to it, until it is
	// acknowledged; gen counts the peer's new epochs (tellOnceLocked), and a
	// beat made before one counts for nothing when it is acknowledged.
	cursor  map[string]*[4]string
	pending map[string]*pendingBeat
	gen     map[string]uint64
	// acked is, by peer folded, each zone's stamp (folded) as a beat to it
	// that was acknowledged told it: by a hash, a stamp that differs has
	// changed since, and goes first; by when, one that something is going
	// on in and that was told longer ago than refresh is due again.
	acked map[string]map[string]ackMark
	// refresh is how long a zone that something is going on in may go
	// untold to a peer before it is due again (entryFor): a quarter of the
	// shorter of the leaving and the no-role time-outs, which read how fresh
	// a telling is (wireStamps). Zero: refreshDefault.
	refresh time.Duration
}

// ackMark is a zone's stamp as an acknowledged beat told it: its hash, and
// when. A beat made and not yet acknowledged leaves the hash unknown (0), so
// that the zone is told again, as changed, until a beat that told it is.
type ackMark struct {
	hash uint64
	at   time.Time
}

// pendingBeat is the latest beat made to a peer: its sequence, where it
// leaves the turn of each rank, and the peer's new epochs then.
type pendingBeat struct {
	seq    uint64
	cursor [4]string
	gen    uint64
}

// refreshDefault is refresh where nothing sets it.
const refreshDefault = time.Minute

// memberStamp is a member's latest stamp, as it was heard. Instr is keyed
// by the zone's name, folded, and ZoneSeq is the sequence each zone's stamp
// was told at, ZoneHeard when: a message tells one zone, a beat every zone
// the two share. Seq is the latest beat's.
type memberStamp struct {
	Identity    string
	Epoch, Seq  uint64
	Heard       time.Time // the latest telling, a beat's or a message's
	Mechanism   string    // the latest beat's
	Enveloped   bool      // the latest beat came in the payload envelope
	Crypto      bool      // the member tells payload encryption on
	Nameservers []string
	Instr       map[string]InstrStamp
	ZoneSeq     map[string]uint64
	ZoneHeard   map[string]time.Time
	Partial     bool // the latest beat left out zones something is going on in
}

// encrypted: the member tells payload encryption on, and its latest beat
// came in the payload envelope, or over HTTPS, whose two ends each check the
// other's certificate against its TLSA record (tdns-mp #242, #246). Either
// way the telling is the member's own (design 3.7; plan S7 decides that an
// HTTPS beat counts).
func (m *memberStamp) encrypted() bool {
	return m.Crypto && (m.Enveloped || m.Mechanism == transport.MechanismAPI)
}

type fetchMark struct {
	serial uint32
	at     time.Time
}

// newStampTable is the stamp table of localID, whose serials store keeps,
// for the start that epoch numbers.
func newStampTable(localID string, store *InstructionStore, epoch uint64, crypto bool, nameservers []string) *stampTable {
	return &stampTable{
		localID:     dns.Fqdn(localID),
		store:       store,
		epoch:       epoch,
		crypto:      crypto,
		nameservers: slices.Clone(nameservers),
		kept:        map[string]*memberStamp{},
		fetched:     map[string]fetchMark{},
		said:        map[string]bool{},
		once:        map[string]map[string]bool{},
		cursor:      map[string]*[4]string{},
		pending:     map[string]*pendingBeat{},
		gen:         map[string]uint64{},
		acked:       map[string]map[string]ackMark{},
	}
}

// entryFor is the stamp entry of a beat to peer: one row, this agent's own,
// with a stamp of each zone the two share (sharedWith) that something is
// going on in (design rule 4, plan S22): its stamp here is not at rest, or
// this agent has work for it with peer (work), or peer's latest first-hand
// stamp of it is not at rest or tells other serials; and, since peer's new
// epoch, every zone once (onceFor). At rest the row tells no zone, and
// goes all the same: a receiver reads the sender's epoch from it, and drops
// what it holds of a zone a newer beat no longer tells, but a stamp at rest
// (keep). Nil when the two share no zone.
//
// The zones told fit stampEntryBudget (fillEntry, plan S22 amended
// 2026-10-30), in four ranks. First the zones whose stamp changed since an
// acknowledged beat to peer told it (acked): one told for the first time,
// one that starts or takes a step, whose parts come to hold it, that is
// done or comes to rest. Then those something is going on in that are due:
// told longer ago than refresh. Then the other zones something is going on
// in. Last those of peer's new epoch alone. A beat that leaves out a zone
// of the first three ranks says so (Partial), and its receiver keeps what
// it holds of the zones it does not tell, as it was.
func (t *stampTable) entryFor(peer string) *GossipMessage {
	if t == nil {
		return nil
	}
	zones := t.store.sharedWith(t.localID, peer)
	if len(zones) == 0 {
		return nil
	}
	// the sequence first: a message whose stamp is read after this beat's
	// stamps carries a later one (keep)
	seq := t.seq.Add(1)
	var work map[string]bool
	if t.work != nil {
		work = t.work(peer)
	}
	once := t.onceFor(peer, zones)
	var theirs map[string]InstrStamp
	if m := t.heard(peer); m != nil {
		theirs = m.Instr
	}
	acked := t.ackedFor(peer, zones)
	refresh := t.refresh
	if refresh <= 0 {
		refresh = refreshDefault
	}
	now := time.Now()
	var ranked [4][]toTell
	for _, zone := range zones {
		st, ok := t.ownStamp(zone)
		if !ok {
			continue
		}
		z := newToTell(zone, st)
		z.own, z.busy = !atRest(st), work[z.key]
		their, heard := theirs[z.key]
		z.theirs = heard && (!atRest(their) || !sameSerials(st, their))
		mark, told := acked[z.key]
		going := z.own || z.busy || z.theirs
		z.changed = told && mark.hash != z.hash || !told && going
		switch {
		case z.changed:
			ranked[0] = append(ranked[0], z)
		case going && now.Sub(mark.at) >= refresh:
			z.due = true
			ranked[1] = append(ranked[1], z)
		case going:
			ranked[2] = append(ranked[2], z)
		case once[z.key]:
			ranked[3] = append(ranked[3], z)
		}
	}
	t.mu.Lock()
	cursor := [4]string{}
	if c := t.cursor[canonicalName(peer)]; c != nil {
		cursor = *c
	}
	told, size, partial := fillEntry(ranked, &cursor)
	key := canonicalName(peer)
	if t.pending == nil {
		t.pending = map[string]*pendingBeat{}
	}
	t.pending[key] = &pendingBeat{seq: seq, cursor: cursor, gen: t.gen[key]}
	// what peer holds of the zones told is not known until the beat is
	// acknowledged: a change it tells, if lost, is told again (S2 of the
	// external review)
	if len(told) > 0 {
		if t.acked == nil {
			t.acked = map[string]map[string]ackMark{}
		}
		if t.acked[key] == nil {
			t.acked[key] = map[string]ackMark{}
		}
	}
	for _, z := range told {
		mark := t.acked[key][z.key]
		mark.hash = 0
		t.acked[key][z.key] = mark
	}
	t.mu.Unlock()

	instr := make(map[string]InstrStamp, len(told))
	// for the log: the zones told for each reason, and the first few told
	// for something going on rather than for peer's new epoch alone
	var onceTold, changedTold, dueTold, ownTold, workTold, theirsTold int
	var named []string
	for _, z := range told {
		instr[z.zone] = z.st
		onceTold += boolToInt(once[z.key])
		changedTold += boolToInt(z.changed)
		dueTold += boolToInt(z.due)
		ownTold += boolToInt(z.own)
		workTold += boolToInt(z.busy)
		theirsTold += boolToInt(z.theirs)
		if (z.changed || z.own || z.busy || z.theirs) && len(named) < 8 {
			named = append(named, z.zone)
		}
	}
	slices.Sort(named)
	lgGossip.Debug("the stamp entry of a beat", "peer", peer, "zones", len(instr), "once", onceTold, "shared", len(zones),
		"own", ownTold, "work", workTold, "theirs", theirsTold, "named", named, "partial", partial, "bytes", size,
		"changed", changedTold, "due", dueTold)
	row := &MemberState{
		Identity:    t.localID,
		Timestamp:   time.Now(),
		Instr:       instr,
		Epoch:       t.epoch,
		Seq:         seq,
		Nameservers: slices.Clone(t.nameservers),
		Crypto:      t.crypto,
		Partial:     partial,
	}
	return &GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{t.localID: row}}
}

// toTell is a zone a stamp entry may tell, folded in key, with the size its
// stamp adds to the entry and a hash of the stamp, and why: the stamp
// changed since it was last told to the peer (changed), it is due again
// (due), it is not at rest (own), this agent has work for the zone with the
// peer (busy), the peer's stamp of it is not at rest or differs (theirs).
type toTell struct {
	zone, key                       string
	st                              InstrStamp
	size                            int
	hash                            uint64
	changed, due, own, busy, theirs bool
}

// newToTell is zone's stamp st, sized and hashed: the size is the name, the
// stamp's JSON, and the quotes, colon and comma around them.
func newToTell(zone string, st InstrStamp) toTell {
	z := toTell{zone: zone, key: canonicalName(zone), st: st, size: stampEntryBudget}
	if b, err := json.Marshal(st); err == nil {
		z.size, z.hash = len(zone)+len(b)+4, stampHash(b)
	}
	return z
}

// stampHash is a hash of a stamp's JSON.
func stampHash(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64()
}

// fillEntry takes, of the zones ranked by what goes on in them, as many as
// stampEntryBudget holds, and their size: rank by rank, each rank from the
// zone after the last one told of it before (cursor, which it moves), so
// that what does not fit now is told in the beats that follow. The zones
// whose stamp changed leave room for the zones that are due, up to half the
// budget, so that changes hold them back for no more than that; a zone of
// peer's new epoch alone waits until all those something is going on in
// fit. One zone is told whatever its size. partial: a zone of the first
// three ranks was left out.
func fillEntry(ranked [4][]toTell, cursor *[4]string) (told []toTell, size int, partial bool) {
	due := 0
	for _, z := range ranked[1] {
		due += z.size
	}
	for r, list := range ranked {
		if r == 3 && partial {
			break
		}
		limit := stampEntryBudget
		if r == 0 {
			limit -= min(due, stampEntryBudget/2)
		}
		slices.SortFunc(list, func(a, b toTell) int { return strings.Compare(a.key, b.key) })
		start, _ := slices.BinarySearchFunc(list, cursor[r], func(z toTell, key string) int {
			if z.key <= key {
				return -1
			}
			return 1
		})
		for i := range list {
			z := list[(start+i)%len(list)]
			if size+z.size > limit && len(told) > 0 {
				if r > 0 {
					return told, size, partial || r < 3
				}
				partial = true
				break
			}
			told, size = append(told, z), size+z.size
			cursor[r] = z.key
		}
	}
	return told, size, partial
}

// ackedFor is a copy of what was told to peer in acknowledged beats, of the
// zones (shared with peer); what is noted of a zone no longer shared is
// dropped.
func (t *stampTable) ackedFor(peer string, zones []string) map[string]ackMark {
	key := canonicalName(peer)
	t.mu.Lock()
	defer t.mu.Unlock()
	acked := t.acked[key]
	if len(acked) == 0 {
		return nil
	}
	shared := make(map[string]bool, len(zones))
	for _, zone := range zones {
		shared[canonicalName(zone)] = true
	}
	for zone := range acked {
		if !shared[zone] {
			delete(acked, zone)
		}
	}
	return maps.Clone(acked)
}

// atRest: nothing is going on in a zone by its stamp (plan S22). The active
// serial is known and is the newest, with no owner error, no refusal, no
// serial agreed on, no transition, step or removal under way, and no key
// rollover.
func atRest(st InstrStamp) bool {
	return st.Known && st.Error == "" && st.Refused == "" && st.Agreeing == 0 &&
		!st.Reconciling && st.Step == nil && len(st.Removals) == 0 && !st.Rollover &&
		st.Newest == st.Active && st.NewestDigest == st.ActiveDigest
}

// sameSerials: two stamps tell the same active and newest serials.
func sameSerials(a, b InstrStamp) bool {
	return a.Active == b.Active && a.ActiveDigest == b.ActiveDigest &&
		a.Newest == b.Newest && a.NewestDigest == b.NewestDigest
}

// onceFor is the zones (shared with peer), folded, still to be told to it
// once since its new epoch; the entry's budget bounds how many a beat
// tells. A zone no longer shared is no longer owed.
func (t *stampTable) onceFor(peer string, zones []string) map[string]bool {
	key := canonicalName(peer)
	t.mu.Lock()
	defer t.mu.Unlock()
	left, ok := t.once[key]
	if !ok {
		return nil
	}
	shared := make(map[string]bool, len(zones))
	for _, zone := range zones {
		shared[canonicalName(zone)] = true
	}
	if left == nil {
		left = shared
	}
	for zone := range left {
		if !shared[zone] {
			delete(left, zone)
		}
	}
	if len(left) == 0 {
		delete(t.once, key)
		return nil
	}
	t.once[key] = left
	return maps.Clone(left)
}

// tellOnceLocked has every zone shared with the member key (folded) told to
// it once: its first stamp since this agent's start, or one of its new
// epoch, has come. Called with t.mu held.
func (t *stampTable) tellOnceLocked(key string) {
	if t.once == nil {
		t.once = map[string]map[string]bool{}
	}
	t.once[key] = nil
	delete(t.acked, key)
	if t.gen == nil {
		t.gen = map[string]uint64{}
	}
	t.gen[key]++
}

// acknowledged notes that the beat that carried e, a stamp entry to peer,
// was acknowledged: the zones it told are told to peer once, each stamp is
// the one peer was last told (acked), and the next beat goes on from where
// e left off (cursor). Only the latest beat made to peer counts, and not
// one made before a new epoch of peer's that has put every zone back to be
// told once.
func (t *stampTable) acknowledged(peer string, e *GossipMessage) {
	if t == nil || e == nil || e.Members[t.localID] == nil {
		return
	}
	key := canonicalName(peer)
	now := time.Now()
	marks := map[string]ackMark{}
	for zone, st := range e.Members[t.localID].Instr {
		if b, err := json.Marshal(st); err == nil {
			marks[canonicalName(zone)] = ackMark{hash: stampHash(b), at: now}
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// only the latest beat made to peer, and not one made before a new
	// epoch of peer's that was heard since (S2 of the external review)
	p := t.pending[key]
	if p == nil || p.seq != e.Members[t.localID].Seq || p.gen != t.gen[key] {
		return
	}
	delete(t.pending, key)
	if t.cursor == nil {
		t.cursor = map[string]*[4]string{}
	}
	cursor := p.cursor
	t.cursor[key] = &cursor
	if t.acked == nil {
		t.acked = map[string]map[string]ackMark{}
	}
	if t.acked[key] == nil {
		t.acked[key] = map[string]ackMark{}
	}
	maps.Copy(t.acked[key], marks)
	left := t.once[key]
	if left == nil {
		return
	}
	for zone := range marks {
		delete(left, zone)
	}
	if len(left) == 0 {
		delete(t.once, key)
	}
}

// ownStamp is what this agent tells of zone: the serials its store keeps,
// with its provider's rollover flag, whom a rollover under way waits on,
// its signer's hold, and whether its parts hold the step it holds.
func (t *stampTable) ownStamp(zone string) (InstrStamp, bool) {
	st, ok := t.store.stampOf(zone)
	if !ok {
		return st, false
	}
	if st.Step != nil && t.stepHeld != nil {
		st.StepHeld = t.stepHeld(zone, SerialDigest{Serial: st.Active, Digest: st.ActiveDigest}, *st.Step)
	}
	if t.rollover != nil {
		st.Rollover = t.rollover(zone)
	}
	if st.Rollover && t.waitsOn != nil {
		st.WaitsOn = t.waitsOn(zone)
	}
	if t.hold != nil {
		st.Hold = t.hold(zone)
	}
	return st, true
}

// note keeps the stamp entry of a beat that sender sent, first hand: its row
// of sender's own identity and nothing else, unless the stamp kept of sender
// is newer (keep). mechanism is the beat's.
func (t *stampTable) note(msg *GossipMessage, sender, mechanism string) {
	if t == nil || msg == nil {
		return
	}
	var row *MemberState
	for id, ms := range msg.Members {
		if ms != nil && core.EqualNames(id, sender) && core.EqualNames(ms.Identity, sender) {
			row = ms
			break
		}
	}
	if row == nil {
		lgGossip.Debug("a stamp entry without its sender's own row is not noted", "sender", sender)
		return
	}
	m := &memberStamp{
		Identity: dns.Fqdn(sender),
		Epoch:    row.Epoch,
		Seq:      row.Seq,
		Heard:    time.Now(),
		// Over DNS a receiver with payload encryption on refuses a payload
		// outside the envelope, so a beat that reached it came in one; the
		// HTTPS mechanism carries no payload encryption (tdns-transport's
		// route). S7 decides what counts.
		Mechanism:   mechanism,
		Enveloped:   t.crypto && mechanism == transport.MechanismDNS,
		Crypto:      row.Crypto,
		Nameservers: slices.Clone(row.Nameservers),
		Instr:       make(map[string]InstrStamp, len(row.Instr)),
		Partial:     row.Partial,
	}
	for zone, st := range row.Instr {
		m.Instr[canonicalName(zone)] = st
	}
	var shared map[string]bool
	if t.store != nil {
		shared = map[string]bool{}
		for _, zone := range t.store.sharedWith(t.localID, sender) {
			shared[canonicalName(zone)] = true
		}
	}
	if !t.keep(m, shared) {
		return
	}
	lgGossip.Debug("a member's stamp noted from its beat", "member", m.Identity, "zones", len(row.Instr), "partial", row.Partial)
	// the zones this beat told; those kept from before were noted when told
	for _, zone := range slices.Sorted(maps.Keys(row.Instr)) {
		zone = canonicalName(zone)
		t.judgeTold(zone)
		t.fetchIfNewer(zone, m)
		if t.onTold != nil {
			t.onTold(zone)
		}
	}
}

// keep keeps m, a beat's stamp, as its member's latest, unless the one kept
// is newer. Epochs and sequences are compared only within one member's own:
// a higher epoch is a later start of the member, whose stamp replaces all
// that was kept of it (design 3.4); a lower one is from before that start;
// within one epoch a higher sequence is newer. A beat tells the zones that
// something is going on in (entryFor): of a newer one each zone is taken
// unless a message told it later (noteMessage). Of a zone, still shared
// (shared; nil: every zone), that it does not tell, what was kept stays
// as told and heard when the beat is partial or what was kept is at rest:
// a sender tells a stamp of its that changes, so one at rest still holds
// (plan S22, amended 2026-10-30). Any other goes, as nothing is going on in
// it at the member. A member's first
// stamp since this agent's start, or one of a new epoch, has every zone the
// two share told to it once (plan S22).
func (t *stampTable) keep(m *memberStamp, shared map[string]bool) bool {
	key := canonicalName(m.Identity)
	m.ZoneSeq = make(map[string]uint64, len(m.Instr))
	m.ZoneHeard = make(map[string]time.Time, len(m.Instr))
	for zone := range m.Instr {
		m.ZoneSeq[zone], m.ZoneHeard[zone] = m.Seq, m.Heard
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	old := t.kept[key]
	switch {
	case old == nil || m.Epoch > old.Epoch:
		t.kept[key] = m
		t.tellOnceLocked(key)
		return true
	case m.Epoch < old.Epoch || m.Seq <= old.Seq:
		return false
	}
	for zone, seq := range old.ZoneSeq {
		_, told := m.Instr[zone]
		stays := !told && (shared == nil || shared[zone]) && (m.Partial || atRest(old.Instr[zone]))
		if seq > m.Seq || stays {
			m.Instr[zone], m.ZoneSeq[zone], m.ZoneHeard[zone] = old.Instr[zone], seq, old.ZoneHeard[zone]
		} else if !told {
			delete(m.Instr, zone)
			delete(m.ZoneHeard, zone)
		}
	}
	t.kept[key] = m
	return true
}

// heard is the latest stamp kept of identity, a copy; nil with none.
func (t *stampTable) heard(identity string) *memberStamp {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.kept[canonicalName(identity)]
	if m == nil {
		return nil
	}
	c := *m
	c.Instr, c.ZoneSeq, c.ZoneHeard = maps.Clone(m.Instr), maps.Clone(m.ZoneSeq), maps.Clone(m.ZoneHeard)
	return &c
}

// toldStamp is a member's latest first-hand stamp of one zone, as the thaw
// reads it (plan S7): when it was heard, and whether the member's beats are
// encrypted (memberStamp.encrypted).
type toldStamp struct {
	InstrStamp
	identity  string
	heard     time.Time
	encrypted bool
}

// firstHand is what each member this agent has heard tells of zone (folded),
// by its identity folded, with when each was heard.
func (t *stampTable) firstHand(zone string) map[string]toldStamp {
	out := map[string]toldStamp{}
	if t == nil {
		return out
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, m := range t.kept {
		if st, ok := m.Instr[zone]; ok {
			heard := m.ZoneHeard[zone]
			if heard.IsZero() {
				heard = m.Heard
			}
			out[canonicalName(m.Identity)] = toldStamp{InstrStamp: st, identity: m.Identity, heard: heard, encrypted: m.encrypted()}
		}
	}
	return out
}

// told is what each member that this agent has heard tells of zone (folded),
// by identity.
func (t *stampTable) told(zone string) map[string]InstrStamp {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]InstrStamp{}
	for _, m := range t.kept {
		if st, ok := m.Instr[zone]; ok {
			out[m.Identity] = st
		}
	}
	return out
}

// tellings are the serials a stamp tells, each with its digest: the active,
// the newest and the one agreed on.
func tellings(st InstrStamp) []SerialDigest {
	var out []SerialDigest
	for _, sd := range []SerialDigest{{Serial: st.Active, Digest: st.ActiveDigest}, {Serial: st.Newest, Digest: st.NewestDigest}, {Serial: st.Agreeing, Digest: st.AgreeingDigest}} {
		if sd.Digest != "" && !slices.Contains(out, sd) {
			out = append(out, sd)
		}
	}
	return out
}

// toldConflict is an owner error between agents at one serial: its
// digests, and the voting members named for it.
type toldConflict struct {
	serial  uint32
	digests []string
	members []string
}

// toldConflicts are the owner errors between agents in what the members
// tell of zone (rule 2): two voting members that tell one serial with two
// digests, this agent among them when it votes; or a voting member whose
// digest for this agent's active serial is another than this agent's own.
// One member telling one serial with two digests is no conflict between
// members. Who votes is read from this agent's active and newest serials,
// and an agent that does not vote is not named among them. A serial below
// the highest this agent holds is not looked at: the owner has passed it.
// The serials told with another digest by members that do not vote come
// back apart, by member: they are shown and hold nothing.
func (t *stampTable) toldConflicts(zone string) (name string, conflicts []toldConflict, others map[string][]uint32) {
	own, ok := t.store.ownView(zone)
	if !ok {
		return "", nil, nil
	}
	digests := map[uint32]map[string][]string{} // serial -> digest -> tellers; "" is this agent when it does not vote
	add := func(sd SerialDigest, who string) {
		if CompareSerial(sd.Serial, own.highest) < 0 {
			return
		}
		if digests[sd.Serial] == nil {
			digests[sd.Serial] = map[string][]string{}
		}
		digests[sd.Serial][sd.Digest] = append(digests[sd.Serial][sd.Digest], who)
	}
	localVotes := own.voting.has(t.localID)
	for _, sd := range own.held {
		switch {
		case localVotes:
			add(sd, t.localID)
		case sd == own.active:
			add(sd, "")
		}
	}
	told := t.told(zone)
	var notVoting []string
	for _, id := range slices.Sorted(maps.Keys(told)) {
		if own.voting.has(id) {
			for _, sd := range tellings(told[id]) {
				add(sd, id)
			}
		} else {
			notVoting = append(notVoting, id)
		}
	}
	for _, serial := range slices.Sorted(maps.Keys(digests)) {
		byDigest := digests[serial]
		var tellers []string
		for _, who := range byDigest {
			tellers = append(tellers, who...)
		}
		tellers = sortedUnique(tellers)
		// with two digests and two tellers, two of the tellers differ
		if len(byDigest) < 2 || len(tellers) < 2 {
			continue
		}
		members := slices.DeleteFunc(tellers, func(who string) bool { return who == "" })
		conflicts = append(conflicts, toldConflict{serial: serial, digests: slices.Sorted(maps.Keys(byDigest)), members: members})
	}
	for _, id := range notVoting {
		for _, sd := range tellings(told[id]) {
			if byDigest := digests[sd.Serial]; len(byDigest) > 0 && byDigest[sd.Digest] == nil {
				if others == nil {
					others = map[string][]uint32{}
				}
				others[id] = append(others[id], sd.Serial)
			}
		}
	}
	return own.name, conflicts, others
}

// judgeTold marks the owner errors between agents in what the members tell
// of zone (toldConflicts), and logs what a member that does not vote tells
// with another digest once.
func (t *stampTable) judgeTold(zone string) {
	name, conflicts, others := t.toldConflicts(zone)
	for _, c := range conflicts {
		if t.store.noteToldConflict(name, c.serial, c.digests) {
			lgGossip.Warn("owner error: two voting members tell one serial with two digests", "zone", name, "serial", c.serial, "members", strings.Join(c.members, ", "))
		}
	}
	for _, id := range slices.Sorted(maps.Keys(others)) {
		for _, serial := range others[id] {
			if t.sayOnce(fmt.Sprintf("%s %d %s", zone, serial, canonicalName(id))) {
				lgGossip.Info("a member that does not vote tells another digest", "zone", name, "serial", serial, "member", id)
			}
		}
	}
}

// sayOnce reports whether the line keyed by key is logged for the first
// time.
func (t *stampTable) sayOnce(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.said[key] {
		return false
	}
	t.said[key] = true
	return true
}

// fetchIfNewer asks a refresh of this agent's own copy of zone when m tells
// a newest serial above the highest this agent holds, or when it holds no
// serial for the zone (design 3.1, 3.4): at once for a serial above
// the last one fetched, and again once a minute while this agent lags. Only
// a refresh that was queued counts: one the full queue dropped, or one for a
// zone that is not here yet, is asked again at the next telling. S10 and S11
// add the provider's chain.
func (t *stampTable) fetchIfNewer(zone string, m *memberStamp) {
	st := m.Instr[zone]
	if st.NewestDigest == "" || t.fetch == nil {
		return
	}
	if own, ok := t.store.ownView(zone); ok && CompareSerial(st.Newest, own.highest) <= 0 {
		return
	}
	now := time.Now()
	t.mu.Lock()
	f, seen := t.fetched[zone]
	due := !seen || CompareSerial(st.Newest, f.serial) > 0 || now.Sub(f.at) >= fetchInterval
	if due {
		t.fetched[zone] = fetchMark{serial: st.Newest, at: now}
	}
	t.mu.Unlock()
	if !due {
		return
	}
	name, queued := t.fetch(zone)
	switch {
	case queued:
		lgGossip.Info("a member tells newer instructions, fetching the zone", "zone", name, "member", m.Identity, "serial", st.Newest)
	default:
		// not fetched (the queue was full, or the zone is not here, yet or
		// any more), so the next telling asks again
		t.mu.Lock()
		if t.fetched[zone] == (fetchMark{serial: st.Newest, at: now}) {
			if seen {
				t.fetched[zone] = f
			} else {
				delete(t.fetched, zone)
			}
		}
		t.mu.Unlock()
	}
}

// MemberInstructions is a member's latest stamp of a zone, as the agent's
// status shows it (plan S5a), this agent's own first.
type MemberInstructions struct {
	Identity  string        `json:"identity"`
	Self      bool          `json:"self,omitempty"`
	Active    *SerialDigest `json:"active,omitempty"`
	Newest    *SerialDigest `json:"newest,omitempty"`
	Agreeing  *SerialDigest `json:"agreeing,omitempty"`
	Refused   string        `json:"refused,omitempty"`
	Error     string        `json:"error,omitempty"`
	Rollover  bool          `json:"rollover,omitempty"`
	Hold      bool          `json:"hold,omitempty"` // its signer has confirmed the hold (plan S6)
	Crypto    bool          `json:"crypto"`
	Mechanism string        `json:"mechanism,omitempty"`
	Enveloped bool          `json:"enveloped,omitempty"`
	Heard     time.Time     `json:"heard,omitzero"`
	// Lags: its active or newest serial is below one another member tells.
	Lags bool `json:"lags,omitempty"`
	// Alone: no other member holds its newest serial (design 3.1).
	Alone bool `json:"alone,omitempty"`
	// OtherDigest is a serial it tells with another digest than this
	// agent's; nil with none.
	OtherDigest *uint32 `json:"other_digest,omitempty"`
}

// members is what each member tells of zone, this agent first and then by
// identity, with the members that lag marked; nil when this agent keeps no
// serials for zone.
func (t *stampTable) members(zone string) []MemberInstructions {
	if t == nil {
		return nil
	}
	own, ok := t.ownStamp(zone)
	if !ok {
		return nil
	}
	rows := []MemberInstructions{memberRow(t.localID, own)}
	rows[0].Self, rows[0].Crypto = true, t.crypto
	t.mu.Lock()
	for _, m := range t.kept {
		if st, ok := m.Instr[canonicalName(zone)]; ok {
			r := memberRow(m.Identity, st)
			r.Crypto, r.Mechanism, r.Enveloped, r.Heard = m.Crypto, m.Mechanism, m.Enveloped, m.Heard
			rows = append(rows, r)
		}
	}
	t.mu.Unlock()
	heardRows := rows[1:]
	sort.SliceStable(heardRows, func(i, j int) bool { return heardRows[i].Identity < heardRows[j].Identity })

	var topActive, topNewest *uint32
	for _, r := range rows {
		topActive, topNewest = higher(topActive, r.Active), higher(topNewest, r.Newest)
	}
	ownTold := tellings(own)
	for i := range rows {
		r := &rows[i]
		r.Lags = r.Active != nil && CompareSerial(r.Active.Serial, *topActive) < 0 || r.Newest != nil && CompareSerial(r.Newest.Serial, *topNewest) < 0
		if r.Newest != nil && len(rows) > 1 {
			r.Alone = !slices.ContainsFunc(rows, func(o MemberInstructions) bool {
				return o.Identity != r.Identity && slices.ContainsFunc(rowTellings(o), func(sd SerialDigest) bool { return sd == *r.Newest })
			})
		}
		if r.Self {
			continue
		}
		for _, sd := range rowTellings(*r) {
			if slices.ContainsFunc(ownTold, func(o SerialDigest) bool { return o.Serial == sd.Serial && o.Digest != sd.Digest }) {
				s := sd.Serial
				r.OtherDigest = &s
				break
			}
		}
	}
	return rows
}

// memberRow is the status row of what identity tells in st.
func memberRow(identity string, st InstrStamp) MemberInstructions {
	r := MemberInstructions{Identity: identity, Refused: st.Refused, Error: st.Error, Rollover: st.Rollover, Hold: st.Hold}
	if st.Known && st.ActiveDigest != "" {
		r.Active = &SerialDigest{Serial: st.Active, Digest: st.ActiveDigest}
	}
	if st.NewestDigest != "" {
		r.Newest = &SerialDigest{Serial: st.Newest, Digest: st.NewestDigest}
	}
	if st.AgreeingDigest != "" {
		r.Agreeing = &SerialDigest{Serial: st.Agreeing, Digest: st.AgreeingDigest}
	}
	return r
}

// rowTellings are the serials a status row tells, as tellings has them.
func rowTellings(r MemberInstructions) []SerialDigest {
	var out []SerialDigest
	for _, p := range []*SerialDigest{r.Active, r.Newest, r.Agreeing} {
		if p != nil {
			out = append(out, *p)
		}
	}
	return out
}

// higher is the higher of top and sd's serial (RFC 1982).
func higher(top *uint32, sd *SerialDigest) *uint32 {
	if sd == nil || top != nil && CompareSerial(sd.Serial, *top) <= 0 {
		return top
	}
	s := sd.Serial
	return &s
}

// ownView is what judgeTold and fetchIfNewer read of this agent's own
// serials of zone: the store's name for it, its active serial, every serial
// held, the highest, and the zone's voting members under the active and the
// newest serial.
type ownView struct {
	name    string
	active  SerialDigest
	held    []SerialDigest
	highest uint32
	voting  memberSet
}

// zoneLocked is zone's serials, the zone named in any case, with the
// store's name for it. Called with s.mu held.
func (s *InstructionStore) zoneLocked(zone string) (string, *zoneSerials) {
	if z := s.zones[zone]; z != nil {
		return zone, z
	}
	for name, z := range s.zones {
		if core.EqualNames(name, zone) {
			return name, z
		}
	}
	return "", nil
}

// ownView is what this agent holds of zone, the zone named in any case;
// false when it holds no serial for it. With no active serial known (S9)
// active is zero and the voting members are the newest serial's.
func (s *InstructionStore) ownView(zone string) (ownView, bool) {
	if s == nil {
		return ownView{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, z := s.zoneLocked(zone)
	if z == nil || z.highest() == nil {
		return ownView{}, false
	}
	v := ownView{name: name, highest: z.highest().Serial, voting: memberSet{}}
	if z.Active != nil {
		v.active = z.Active.SerialDigest
		v.held = append(v.held, z.Active.SerialDigest)
	}
	for _, h := range z.Held {
		v.held = append(v.held, h.SerialDigest)
	}
	for _, h := range []*heldSerial{z.Active, z.highest()} {
		if h == nil {
			continue
		}
		_, voting := participantsOf(h.Reading)
		for _, id := range voting {
			v.voting[canonicalName(id)] = true
		}
	}
	return v, true
}

// sharedWith is every zone the two agents share, both with a role under
// this agent's active or newest serial, and every zone with a removal under
// way of peer's (plan S5a): more than rule 4's zones with something to do,
// which S22 brings it to. Sorted.
func (s *InstructionStore) sharedWith(local, peer string) []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for zone, z := range s.zones {
		if z.shares(local, peer) {
			out = append(out, zone)
		}
	}
	sort.Strings(out)
	return out
}

// shares: local and peer both have a role under the active or the newest
// serial, or peer's removal is under way.
func (z *zoneSerials) shares(local, peer string) bool {
	for _, h := range []*heldSerial{z.Active, z.highest()} {
		if h == nil {
			continue
		}
		if set := participantFQDNSet(h.Reading); set.has(local) && set.has(peer) {
			return true
		}
	}
	return slices.ContainsFunc(z.Removals, func(r Removal) bool { return core.EqualNames(r.Identity, dns.Fqdn(peer)) })
}

// stampOf is what this agent tells of zone (rule 4), from the serials it
// keeps, its reconciliation's step and removals included (plan S12); the
// rollover flag and whether its parts hold the step are the caller's.
func (s *InstructionStore) stampOf(zone string) (InstrStamp, bool) {
	if s == nil {
		return InstrStamp{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, z := s.zoneLocked(zone)
	if z == nil {
		return InstrStamp{}, false
	}
	var st InstrStamp
	if z.Active != nil {
		st.Active, st.ActiveDigest, st.Known = z.Active.Serial, z.Active.Digest, true
	}
	if h := z.highest(); h != nil {
		st.Newest, st.NewestDigest = h.Serial, h.Digest
		if len(h.Refused) > 0 {
			st.Refused = h.Refused[0].Code
		}
	}
	if a := z.agreeing(); a != nil {
		st.Agreeing, st.AgreeingDigest = a.Serial, a.Digest
	}
	st.Error = z.OwnerError
	if z.LastThaw != nil {
		th := *z.LastThaw
		st.Thaw = &th
	}
	z.stampStepLocked(&st)
	return st, true
}

var errToldUnchanged = errors.New("nothing told changes the zone's serials")

// noteToldConflict notes rule 2's owner error between agents: voting
// members tell serial with the digests. It holds the zone as the store's
// own conflict does, until a copy above serial is noted; an owner error
// noted at another serial stands. It reports whether it changed what the
// store keeps.
func (s *InstructionStore) noteToldConflict(zone string, serial uint32, digests []string) bool {
	if s == nil {
		return false
	}
	changed := false
	err := s.update(zone, func(z *zoneSerials) error {
		if z.Active == nil || z.OwnerError != "" && (z.ErrorAt == nil || *z.ErrorAt != serial) {
			return errToldUnchanged
		}
		var conflict []string
		if z.ErrorAt != nil && *z.ErrorAt == serial {
			conflict = slices.Clone(z.Conflict)
		}
		for _, d := range digests {
			if !slices.Contains(conflict, d) {
				conflict = append(conflict, d)
			}
		}
		count := fmt.Sprintf("%d digests", len(conflict))
		if len(conflict) == 2 {
			count = "two digests"
		}
		msg := fmt.Sprintf("serial %d told with %s (%s)", serial, count, strings.Join(conflict, ", "))
		if z.OwnerError == msg && slices.Equal(z.Conflict, conflict) {
			return errToldUnchanged
		}
		at := serial
		z.ErrorAt, z.Conflict = &at, conflict
		z.ownerError(zone, msg)
		changed = true
		return nil
	})
	if err != nil && !errors.Is(err, errToldUnchanged) {
		lg.Error("an owner error told between agents could not be kept", "zone", zone, "serial", serial, "err", err)
		return false
	}
	return changed
}

// RaiseEpoch raises the epoch of this agent's stamps at its start, on disk,
// and returns it. It is a counter, raised to the clock's milliseconds when
// they are ahead: a clock that runs backwards across a restart still raises
// it, and a database that is wiped still starts above the epochs its peers
// hold, since no two starts come within a millisecond. Without a database
// it is the clock's.
func (s *InstructionStore) RaiseEpoch(now time.Time) (uint64, error) {
	clock := uint64(max(now.UnixMilli(), 1))
	if s == nil || s.hdb == nil {
		return clock, nil
	}
	s.hdb.Lock()
	defer s.hdb.Unlock()
	tx, err := s.hdb.DB.Begin()
	if err != nil {
		return 0, fmt.Errorf("raising the stamps' epoch: %w", err)
	}
	defer tx.Rollback()
	var stored uint64
	if err := tx.QueryRow(`SELECT epoch FROM MPStampEpoch WHERE id = 1`).Scan(&stored); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("reading the stamps' epoch: %w", err)
	}
	epoch := max(stored+1, clock)
	if _, err := tx.Exec(`INSERT INTO MPStampEpoch (id, epoch) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET epoch = excluded.epoch`, epoch); err != nil {
		return 0, fmt.Errorf("keeping the stamps' epoch: %w", err)
	}
	return epoch, tx.Commit()
}

// wireStamps gives the agent's or the auditor's bridge its stamp table: the
// epoch raised for this start, the provider's nameserver names, whether
// payload encryption is on; on the agent its key rollovers, its parts'
// hold of a step, the fetch and its work with each peer. The bridge takes
// the time-out for members with no role too (plan S12).
func (conf *Config) wireStamps(tm *MPTransportBridge, mp *MultiProviderConf, crypto, agent bool) error {
	epoch, err := conf.InternalMp.Instructions.RaiseEpoch(time.Now())
	if err != nil {
		return err
	}
	t := newStampTable(tm.LocalID, conf.InternalMp.Instructions, epoch, crypto, mp.Local.Nameservers)
	t.onTold = conf.askThaw
	t.refresh = min(leavingTimeoutFor(mp), noRoleTimeoutFor(mp)) / 4
	if agent {
		t.rollover, t.waitsOn = tm.rolloverAt, waitsOnAt
		t.hold = conf.holdConfirmed
		t.stepHeld = conf.holdsStep
		t.fetch = conf.fetchZone
		t.work = func(peer string) map[string]bool { return conf.workWith(tm, peer) }
		if !crypto {
			lgGossip.Warn("payload encryption is off: no transition of a zone this agent votes for is thawed")
		}
	}
	tm.stamps = t
	tm.noRoleTimeout = noRoleTimeoutFor(mp)
	return nil
}

// workWith is the zones, folded, the agent has work owed, kept or under way
// for with peer (plan S22): the zone's owed or kept list is not empty, its
// catch-up with peer is not done, or the reliable queue holds a message to
// peer for it.
func (conf *Config) workWith(tm *MPTransportBridge, peer string) map[string]bool {
	out := map[string]bool{}
	for _, list := range []string{listOwed, listKept} {
		for _, zone := range conf.InternalMp.Kept.zones(list) {
			out[zone] = true
		}
	}
	for _, zone := range conf.InternalMp.CatchUp.openWith(AgentId(peer)) {
		out[canonicalName(string(zone))] = true
	}
	if tm.ReliableQueue != nil {
		for _, m := range tm.ReliableQueue.GetPendingMessages() {
			if m.Zone != "" && core.EqualNames(m.RecipientID, peer) {
				out[canonicalName(m.Zone)] = true
			}
		}
	}
	return out
}

// fetchZone asks a refresh of the zone's own copy, as a NOTIFY does: the
// fetch of a serial a member tells (design 3.1). The zone is named in any
// case. Only a multi-provider zone tdns holds, with its type set, is
// fetched: tdns's zones, not the wrappers Zones keeps, which outlive a zone
// that left the configuration; and the refresh engine makes a zone of a
// refresh for a name it does not hold. A full refresh queue drops it, and
// the next telling asks again.
func (conf *Config) fetchZone(zone string) (string, bool) {
	zd, ok := tdns.Zones.Get(zone)
	if !ok {
		for _, name := range tdns.Zones.Keys() {
			if core.EqualNames(name, zone) {
				zd, ok = tdns.Zones.Get(name)
				break
			}
		}
	}
	if !ok || zd == nil || zd.ZoneType == 0 || !zd.Options[tdns.OptMultiProvider] {
		return "", false
	}
	select {
	case conf.Config.Internal.RefreshZoneCh <- tdns.ZoneRefresher{Name: zd.ZoneName, ZoneStore: zd.ZoneStore}:
		return zd.ZoneName, true
	default:
		lgGossip.Warn("the refresh queue is full; the zone is fetched at a later telling", "zone", zd.ZoneName)
		return zd.ZoneName, false
	}
}

// rolloverAt is rolloverUnderWay at this provider as the agent knows it:
// what its signer's last inventory says, the signer judging on its own
// state (plan S11), or a DNSKEY distribution of this agent's that waits for
// the other agents.
func (tm *MPTransportBridge) rolloverAt(zone string) bool {
	if mpzd, ok := Zones.Get(zone); ok && mpzd != nil {
		if inv := mpzd.GetLastKeyInventory(); inv != nil && inv.Rollover {
			return true
		}
	}
	return tm.dnskeyPropagationPending(zone)
}

// waitsOnAt are the other signers whose "applied" any key of this
// provider's waiting in mpdist or mpremove misses, by its signer's last
// inventory (plan S11), sorted; S7 counts a rollover that waits only on
// excused members as paused.
func waitsOnAt(zone string) []string {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return nil
	}
	inv := mpzd.GetLastKeyInventory()
	if inv == nil {
		return nil
	}
	var out []string
	for _, ps := range inv.WaitsOn {
		for _, p := range ps {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out
}

// dnskeyPropagationPending: a DNSKEY distribution of the zone waits for the
// other agents' confirmations.
func (tm *MPTransportBridge) dnskeyPropagationPending(zone string) bool {
	tm.dnskeyPropMu.Lock()
	defer tm.dnskeyPropMu.Unlock()
	for _, p := range tm.pendingDnskeyPropagations {
		if core.EqualNames(string(p.Zone), zone) {
			return true
		}
	}
	return false
}
