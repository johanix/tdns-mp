/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The restart rule (design 3.4, plan S9). An agent starts with the serials
 * it stored. A zone with its own enforced record knows its active serial
 * from that record. A zone with none (a record kept before S7 counts as
 * none) knows no active serial: it is placed in its group by its newest
 * serial and talks from it, but it is frozen, keeps what it receives (S8)
 * and hands its parts nothing new until the active serial is known. A
 * member, and the auditor, take the leader's first-hand word; the leader
 * takes what every voting member with a record tells, or, with no record
 * anywhere, the newest serial every voting member tells.
 */
package tdnsmp

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Where a zone's active serial became known from, as the log names it.
const (
	knownFromRecord  = "own record"
	knownFromLeader  = "leader"
	knownFromRecords = "the voting members with a record"
	knownFromNewest  = "common newest"
)

// reading is the zone's instructions as the readers act by them: the active
// serial's, or, with none known, the newest serial's, for talking (design
// 3.4); nil when the store keeps none.
func (s *InstructionStore) reading(zone string) *Instructions {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	z := s.zones[zone]
	switch {
	case z == nil:
		return nil
	case z.Active != nil:
		return z.Active.Reading
	case z.highest() != nil:
		return z.highest().Reading
	}
	return nil
}

// newestReading is the store's name for zone, named in any case, the newest
// serial held of it and its owner error, for a zone the store knows no
// active serial of; a nil serial otherwise.
func (s *InstructionStore) newestReading(zone string) (string, *heldSerial, string) {
	if s == nil {
		return "", nil, ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, z := s.zoneLocked(zone)
	if z == nil || z.Active != nil || z.highest() == nil {
		return "", nil, ""
	}
	h := *z.highest()
	return name, &h, z.OwnerError
}

// restartView is what the restart rule makes of a zone whose active serial
// this agent does not know: the serial it takes, with the thaw told with it
// and who told it, or what it waits for; and the serials it fetches first.
type restartView struct {
	zone   string // the store's name for it
	leads  bool   // this agent leads the zone's group by its newest serial
	take   *SerialDigest
	thaw   *Thaw
	by     string // who told the serial taken
	from   string // the rule that took it (knownFrom*)
	fetch  []restartFetch
	waits  []string // whom the leader waits for
	differ []string // the voting members with a record, and what each tells
	// reconciling: those it is taken from tell a transition to it under
	// way (plan S12)
	reconciling bool
}

// restartFetch is a serial to fetch from a member before the rule can take
// it.
type restartFetch struct {
	sd     SerialDigest
	member string
	why    string
}

// line is the view as the status shows it.
func (v restartView) line() string {
	switch {
	case len(v.differ) > 0:
		return "no record; the voting members with a record differ (" + strings.Join(v.differ, ", ") +
			"); to start over, run `agent zone instructions forget` at the agents that hold a record"
	case len(v.waits) > 0:
		return "active not known since the start; waiting for " + strings.Join(v.waits, ", ")
	case len(v.fetch) > 0:
		return fmt.Sprintf("active not known since the start; fetching serial %d from %s", v.fetch[0].sd.Serial, v.fetch[0].member)
	case !v.leads:
		return "active not known since the start; waiting for the leader's word"
	}
	return "active not known since the start"
}

// restartView is the restart rule for zone at now (design 3.4); false when
// this agent knows the zone's active serial, or keeps no serials of it.
func (conf *Config) restartView(zone string, now time.Time) (restartView, bool) {
	s := conf.InternalMp.Instructions
	name, newest, ownerError := s.newestReading(zone)
	mp := conf.MpConfig()
	if newest == nil || mp == nil {
		return restartView{}, false
	}
	local := dns.Fqdn(mp.Identity)
	v := restartView{zone: name}
	_, voters := participantsOf(newest.Reading)
	var t *stampTable
	if tm := conf.InternalMp.MPTransport; tm != nil {
		t = tm.stamps
	}
	told := t.firstHand(canonicalName(name))
	switch {
	case tdns.Globals.App.Type == AppTypeMPAuditor || !isAmong(voters, AgentId(local)):
	case len(voters) == 1:
		v.leads = true // the zone's only voting member, in no group
	case conf.InternalMp.LeaderElectionManager != nil:
		v.leads = conf.InternalMp.LeaderElectionManager.IsLeader(ZoneName(name))
	}
	if !v.leads {
		conf.leadersWord(&v, newest, told)
		return v, true
	}

	// The leader: every other voting member, heard first hand and fresh,
	// tells its active serial or that it knows none (no objection).
	timeout := leavingTimeoutFor(mp)
	records := map[SerialDigest][]string{}
	var thaws []Thaw
	for _, id := range voters {
		if core.EqualNames(id, local) {
			continue
		}
		st, ok := told[canonicalName(id)]
		switch {
		case !ok:
			v.waits = append(v.waits, id+" (not heard)")
			continue
		case now.Sub(st.heard) > timeout:
			v.waits = append(v.waits, id+" (not heard since "+st.heard.Format(time.TimeOnly)+")")
			continue
		}
		if st.Thaw != nil {
			thaws = append(thaws, *st.Thaw)
		}
		if st.Known && st.ActiveDigest != "" {
			sd := SerialDigest{Serial: st.Active, Digest: st.ActiveDigest}
			records[sd] = append(records[sd], id)
		}
	}
	if len(v.waits) > 0 {
		return v, true
	}
	if len(records) == 0 {
		commonNewest(&v, newest.SerialDigest, ownerError, voters, local, told, t.encrypts())
		return v, true
	}
	take, ok := agreedRecord(records, thaws)
	if !ok {
		for _, sd := range slices.SortedFunc(maps.Keys(records), func(a, b SerialDigest) int { return CompareSerial(a.Serial, b.Serial) }) {
			for _, id := range records[sd] {
				v.differ = append(v.differ, fmt.Sprintf("%s tells %d", id, sd.Serial))
			}
		}
		return v, true
	}
	if s.readingAt(name, take) == nil {
		v.fetch = append(v.fetch, restartFetch{sd: take, member: records[take][0], why: "the voting members with a record tell it active"})
		return v, true
	}
	v.take, v.by, v.from = &take, records[take][0], knownFromRecords
	for _, id := range records[take] {
		v.reconciling = v.reconciling || told[canonicalName(id)].Reconciling
	}
	for i := range thaws {
		if thaws[i].To == take {
			v.thaw = &thaws[i]
			break
		}
	}
	return v, true
}

// leadersWord is the rule of a member with no record, and of the auditor:
// the leader's word only, first hand: a stamp that tells a known active
// serial from the agent that leads the zone's group under that serial, by
// the election records heard first hand (plan 7.2). A serial told that this
// agent does not hold is fetched from the zone's leader or a voting member
// under its newest serial.
func (conf *Config) leadersWord(v *restartView, newest *heldSerial, told map[string]toldStamp) {
	s := conf.InternalMp.Instructions
	var leader string
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
		l, _ := lem.ZoneLeader(ZoneName(v.zone))
		leader = string(l)
	}
	for _, key := range slices.Sorted(maps.Keys(told)) {
		st := told[key]
		id := st.identity
		if !st.Known || st.ActiveDigest == "" {
			continue
		}
		sd := SerialDigest{Serial: st.Active, Digest: st.ActiveDigest}
		reading := s.readingAt(v.zone, sd)
		if reading == nil {
			if core.EqualNames(id, leader) || votesIn(newest.Reading, AgentId(id)) {
				v.fetch = append(v.fetch, restartFetch{sd: sd, member: id, why: "a member tells it active"})
			}
			continue
		}
		if !conf.leadsUnder(reading, id) {
			continue
		}
		v.take, v.by, v.from, v.reconciling = &sd, id, knownFromLeader, st.Reconciling
		if st.Thaw != nil && st.Thaw.To == sd {
			v.thaw = st.Thaw // the thaw to the serial taken, as the leader's own rule keeps it
		}
		v.fetch = nil
		return
	}
}

// leadsUnder: id leads the zone's group under the instructions in, by the
// election records this agent holds; a zone with one voting member is led
// by it.
func (conf *Config) leadsUnder(in *Instructions, id string) bool {
	_, voters := participantsOf(in)
	if !isAmong(voters, AgentId(id)) {
		return false
	}
	if len(voters) == 1 {
		return true
	}
	m := zoneMakeUp(in)
	leader, ok := conf.groupLeader(ComputeGroupHash(m.voting, m.auditors, m.noRole))
	return ok && core.EqualNames(leader, id)
}

// groupLeader is the group's leader by the election records this daemon
// holds: the agent's election manager, or on the auditor, which has none,
// the gossip table's records, while the lease runs.
func (conf *Config) groupLeader(groupHash string) (string, bool) {
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
		leader, ok := lem.GetGroupLeader(groupHash)
		return string(leader), ok
	}
	if ar := conf.InternalMp.AgentRegistry; ar != nil && ar.GossipStateTable != nil {
		if _, el, _ := ar.GossipStateTable.GetGroupState(groupHash); el != nil && el.Leader != "" && time.Now().Before(el.LeaderExpiry) {
			return el.Leader, true
		}
	}
	return "", false
}

// commonNewest is the first start after the upgrade, or a fleet that lost
// every record: no voting member has a record, and the leader takes the
// newest serial every voting member tells, by the thaw's check with no
// rollover and no parent condition (plan S9): each tells it first hand and
// fresh, with no owner error and with payload encryption on, and so does
// this agent.
func commonNewest(v *restartView, newest SerialDigest, ownerError string, voters []string, local string, told map[string]toldStamp, encrypts bool) {
	if ownerError != "" {
		v.waits = append(v.waits, local+" (owner error)")
	}
	if !encrypts {
		v.waits = append(v.waits, local+" (payload encryption off)")
	}
	for _, id := range voters {
		if core.EqualNames(id, local) {
			continue
		}
		st := told[canonicalName(id)]
		switch {
		case st.Newest != newest.Serial || st.NewestDigest != newest.Digest:
			v.waits = append(v.waits, fmt.Sprintf("%s (newest %d)", id, st.Newest))
		case st.Error != "":
			v.waits = append(v.waits, id+" (owner error)")
		case !st.encrypted:
			v.waits = append(v.waits, id+" (payload encryption off)")
		}
	}
	if len(v.waits) == 0 {
		v.take, v.by, v.from = &newest, local, knownFromNewest
	}
}

// agreedRecord is the active serial every voting member with a record
// tells; of two, the last thaw told breaks the tie between a from-serial and
// its target. False when they differ otherwise.
func agreedRecord(records map[SerialDigest][]string, thaws []Thaw) (SerialDigest, bool) {
	sds := slices.Collect(maps.Keys(records))
	switch len(sds) {
	case 1:
		return sds[0], true
	case 2:
		for _, th := range thaws {
			if th.From == sds[0] && th.To == sds[1] {
				return sds[1], true
			}
			if th.From == sds[1] && th.To == sds[0] {
				return sds[0], true
			}
		}
	}
	return SerialDigest{}, false
}

// knowActive is the zone's turn while this agent does not know its active
// serial: it fetches what the rule needs, and makes known what it takes.
func (conf *Config) knowActive(zone string) {
	v, ok := conf.restartView(zone, time.Now())
	if !ok {
		return
	}
	for _, f := range v.fetch {
		conf.fetchInstructions(v.zone, f.sd, f.member, f.why)
	}
	if v.take != nil {
		conf.know(v.zone, *v.take, v.thaw, v.reconciling, v.by, v.from)
	}
}

// know makes sd the zone's active serial (Know), and runs what follows: the
// catch-up's answer time runs again (activeChanged); the readers moved from
// the newest serial to the active one (onActiveChanged),
// the sets handed to the parts (onSetsChanged), and the zone's turn asked
// again, for a newer serial it may agree on now. The end of the freeze
// releases what was owed (onFreeze), and S8 what was kept.
func (conf *Config) know(zone string, sd SerialDigest, th *Thaw, reconciling bool, by, from string) {
	s := conf.InternalMp.Instructions
	before := s.reading(zone)
	if err := s.Know(zone, sd, th, reconciling); err != nil {
		lg.Warn("the zone's active serial could not be made known", "zone", zone, "serial", sd.Serial, "from", from, "err", err)
		return
	}
	lg.Info("the zone's active instructions are known", "zone", zone, "serial", sd.Serial, "from", from, "by", by)
	conf.InternalMp.CatchUp.activeChanged(ZoneName(zone))
	if mpzd, ok := Zones.Get(zone); ok && mpzd != nil && mpzd.Ready {
		if after := s.activeReading(zone); !sameInstructions(before, after) {
			mpzd.onActiveChanged(conf.InternalMp.MPTransport, before, after)
		}
		conf.onSetsChanged(mpzd, true)
	}
	conf.askThaw(zone)
}

// placeGroupsAtStart places the zones in their groups before their first
// load (design 3.4): by the stored active readings, and for a zone with
// none known by its newest serial held, so that the zone talks, and its
// first activation after the upgrade has its group's leader.
func (conf *Config) placeGroupsAtStart() {
	ar := conf.InternalMp.AgentRegistry
	if ar == nil || ar.ProviderGroupManager == nil || conf.InternalMp.Instructions == nil {
		return
	}
	ar.ProviderGroupManager.RecomputeGroups()
	lg.Info("the zones are placed in their groups by their stored serials", "groups", len(ar.ProviderGroupManager.GetGroups()))
}
