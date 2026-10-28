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
	"errors"
	"fmt"
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
	// auditor, which runs no key machine).
	rollover func(zone string) bool
	// fetch asks a refresh of the zone's own copy, the zone named in any
	// case: the zone's name here ("" when this agent has no such zone), and
	// whether the refresh was queued. Nil: none.
	fetch func(zone string) (name string, queued bool)
	seq   atomic.Uint64

	mu      sync.Mutex
	kept    map[string]*memberStamp // by identity, folded (canonicalName)
	fetched map[string]fetchMark    // by zone, folded
	said    map[string]bool         // the lines logged once
	dists   map[string]*distStamp   // by distribution and recipient (msg_stamp.go)
}

// memberStamp is a member's latest stamp, as it was heard. Instr is keyed
// by the zone's name, folded, and ZoneSeq is the sequence each zone's stamp
// was told at: a message tells one zone, a beat every zone the two share.
// Seq is the latest beat's.
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
	}
}

// entryFor is the stamp entry of a beat to peer: one row, this agent's own,
// with a stamp of every zone the two share (sharedWith). Nil with none.
func (t *stampTable) entryFor(peer string) *GossipMessage {
	if t == nil {
		return nil
	}
	zones := t.store.sharedWith(t.localID, peer)
	if len(zones) == 0 {
		return nil
	}
	instr := make(map[string]InstrStamp, len(zones))
	for _, zone := range zones {
		st, ok := t.store.stampOf(zone)
		if !ok {
			continue
		}
		if t.rollover != nil {
			st.Rollover = t.rollover(zone)
		}
		instr[zone] = st
	}
	row := &MemberState{
		Identity:    t.localID,
		Timestamp:   time.Now(),
		Instr:       instr,
		Epoch:       t.epoch,
		Seq:         t.seq.Add(1),
		Nameservers: slices.Clone(t.nameservers),
		Crypto:      t.crypto,
	}
	return &GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{t.localID: row}}
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
	}
	for zone, st := range row.Instr {
		m.Instr[canonicalName(zone)] = st
	}
	if !t.keep(m) {
		return
	}
	for _, zone := range slices.Sorted(maps.Keys(m.Instr)) {
		t.judgeTold(zone)
		t.fetchIfNewer(zone, m)
	}
}

// keep keeps m, a beat's stamp, as its member's latest, unless the one kept
// is newer. Epochs and sequences are compared only within one member's own:
// a higher epoch is a later start of the member, whose stamp replaces all
// that was kept of it (design 3.4); a lower one is from before that start;
// within one epoch a higher sequence is newer. A beat tells every zone the
// two share: of a newer one each zone is taken unless a message told it
// later (noteMessage), and a zone it no longer tells goes.
func (t *stampTable) keep(m *memberStamp) bool {
	key := canonicalName(m.Identity)
	m.ZoneSeq = make(map[string]uint64, len(m.Instr))
	for zone := range m.Instr {
		m.ZoneSeq[zone] = m.Seq
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	old := t.kept[key]
	switch {
	case old == nil || m.Epoch > old.Epoch:
		t.kept[key] = m
		return true
	case m.Epoch < old.Epoch || m.Seq <= old.Seq:
		return false
	}
	for zone, seq := range old.ZoneSeq {
		if _, told := m.Instr[zone]; seq > m.Seq {
			m.Instr[zone], m.ZoneSeq[zone] = old.Instr[zone], seq
		} else if !told {
			delete(m.Instr, zone)
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
	c.Instr, c.ZoneSeq = maps.Clone(m.Instr), maps.Clone(m.ZoneSeq)
	return &c
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
// active serial for the zone (design 3.1, 3.4): at once for a serial above
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
		// not fetched (the queue was full, or the zone is not here yet), so
		// the next telling asks again
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
	own, ok := t.store.stampOf(zone)
	if !ok {
		return nil
	}
	if t.rollover != nil {
		own.Rollover = t.rollover(zone)
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
	r := MemberInstructions{Identity: identity, Refused: st.Refused, Error: st.Error, Rollover: st.Rollover}
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
// false when it holds no active serial for it.
func (s *InstructionStore) ownView(zone string) (ownView, bool) {
	if s == nil {
		return ownView{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, z := s.zoneLocked(zone)
	if z == nil || z.Active == nil {
		return ownView{}, false
	}
	v := ownView{name: name, active: z.Active.SerialDigest, highest: z.highest().Serial, voting: memberSet{}}
	v.held = append(v.held, z.Active.SerialDigest)
	for _, h := range z.Held {
		v.held = append(v.held, h.SerialDigest)
	}
	for _, h := range []*heldSerial{z.Active, z.highest()} {
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
// keeps; the rollover flag is the caller's.
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
// payload encryption is on; on the agent its key rollovers and the fetch.
func (conf *Config) wireStamps(tm *MPTransportBridge, mp *MultiProviderConf, crypto, agent bool) error {
	epoch, err := conf.InternalMp.Instructions.RaiseEpoch(time.Now())
	if err != nil {
		return err
	}
	t := newStampTable(tm.LocalID, conf.InternalMp.Instructions, epoch, crypto, mp.Local.Nameservers)
	if agent {
		t.rollover = tm.rolloverAt
		t.fetch = conf.fetchZone
		if !crypto {
			lgGossip.Warn("payload encryption is off: no transition of a zone this agent votes for is thawed")
		}
	}
	tm.stamps = t
	return nil
}

// fetchZone asks a refresh of the zone's own copy, as a NOTIFY does: the
// fetch of a serial a member tells (design 3.1). The zone is named in any
// case. A full refresh queue drops it, and the next telling asks again.
func (conf *Config) fetchZone(zone string) (string, bool) {
	mpzd, ok := Zones.Get(zone)
	if !ok {
		for _, name := range Zones.Keys() {
			if core.EqualNames(name, zone) {
				mpzd, ok = Zones.Get(name)
				break
			}
		}
	}
	if !ok || mpzd == nil || mpzd.ZoneData == nil {
		return "", false
	}
	select {
	case conf.Config.Internal.RefreshZoneCh <- tdns.ZoneRefresher{Name: mpzd.ZoneName, ZoneStore: mpzd.ZoneStore}:
		return mpzd.ZoneName, true
	default:
		lgGossip.Warn("the refresh queue is full; the zone is fetched at a later telling", "zone", mpzd.ZoneName)
		return mpzd.ZoneName, false
	}
}

// rolloverAt is rolloverUnderWay at this provider as the agent knows it
// until S11 has the signer report its own: the signer's last inventory, and
// a DNSKEY distribution of this agent's that waits for the other agents.
func (tm *MPTransportBridge) rolloverAt(zone string) bool {
	var keys []tdns.KeyInventoryItem
	if mpzd, ok := Zones.Get(zone); ok && mpzd != nil {
		if inv := mpzd.GetLastKeyInventory(); inv != nil {
			keys = inv.Inventory
		}
	}
	return rolloverUnderWay(keys, rolloverFlags{PropagationPending: tm.dnskeyPropagationPending(zone)})
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
