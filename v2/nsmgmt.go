/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * NS management (design 5.4, plan S19). A change of nsmgmt has one step of
 * its own, which hands the new role; until then the parts and the agents'
 * readers keep the role they hold (S3, S12). Each combiner acts by the role
 * its agent hands it and drops the NS it stores of every origin when that
 * role changes. Each agent drops the NS from its data: under nsmgmt=owner no
 * agent contributes any, and nothing stored from an earlier time comes back
 * by itself when the role goes to the agents. Under nsmgmt=owner every agent
 * reports an owner's NS RRset that names the servers of a provider whose
 * role is not done (design 3.7).
 */
package tdnsmp

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// nsmgmtStepKey is the key of the step that hands a new nsmgmt.
const nsmgmtStepKey = "nsmgmt"

func init() {
	registerStepRunner(stepRunner{name: nsmgmtStepKey, kind: stepRoleChange, steps: nsmgmtSteps})
}

// nsmgmtSteps is the step of a change of nsmgmt: planned while the sets held
// name another role than the active serial, and kept in the plan once taken.
func nsmgmtSteps(p planView) []plannedStep {
	if p.held.NSmgmt == p.to.NSmgmt && !slices.Contains(p.taken, nsmgmtStepKey) {
		return nil
	}
	to := p.to.NSmgmt
	what := "NS management to the owner"
	if to == core.HsyncNSmgmtAGENT {
		what = "NS management to the agents"
	}
	return []plannedStep{{
		key:  nsmgmtStepKey,
		what: what,
		sets: func(held Roles) Roles {
			held.NSmgmt = to
			return held
		},
	}}
}

// nsLeftToOwner: the sets the zone's parts hold leave its NS to the owner. A
// zone whose instructions are not known here is no such zone: rolesFor reads
// nothing as the default, and no data goes on a default.
func nsLeftToOwner(zone ZoneName) bool {
	return instructionsFor(zone) != nil && rolesForZone(zone).NSmgmt != core.HsyncNSmgmtAGENT
}

// --- The combiner ---

// changesNSmgmt: h, which take would not refuse as older, hands another
// nsmgmt than the hand-over held. Nothing handed before is no change: what
// the combiner holds was not made under another handed role.
func (s *actingStore) changesNSmgmt(h *ActingHandover) bool {
	if s == nil {
		return false
	}
	if in, err := h.read(); err != nil || in == nil {
		return false
	}
	held, ok := s.get(h.Zone)
	return ok && !h.olderThan(held.handover) && held.handover.Sets.NSmgmt != h.Sets.NSmgmt
}

// dropStoredNS drops the NS that every origin has stored for the zone, and
// persists that: nothing stored is applied by itself when the handed role
// next lets the combiner apply NS (design 5.4). The next combine serves the
// upstream's NS. An origin whose drop could not be persisted keeps its NS,
// as the store does, and the error has the hand-over tried again. So does a
// store not read yet: the NS in it are not here to drop, and its read would
// bring them back.
func (mpzd *MPZoneData) dropStoredNS() (int, error) {
	mpzd.Lock()
	defer mpzd.Unlock()
	if mpzd.MP == nil {
		return 0, nil
	}
	if mpzd.MP.PersistContributions != nil && !mpzd.MP.ContributionsRead {
		return 0, errors.New("the zone's stored contributions are not read")
	}
	dropped := 0
	for _, sender := range slices.Sorted(maps.Keys(mpzd.MP.AgentContributions)) {
		for _, owner := range slices.Sorted(maps.Keys(mpzd.MP.AgentContributions[sender])) {
			prior, ok := mpzd.MP.AgentContributions[sender][owner][dns.TypeNS]
			if !ok {
				continue
			}
			rrs := slices.Clone(prior.RRs)
			_, gone, _, err := mpzd.replaceCombinerDataByRRtypeLocked(sender, owner, dns.TypeNS, nil)
			if err != nil {
				mpzd.replaceCombinerDataByRRtypeLocked(sender, owner, dns.TypeNS, rrs)
				return dropped, fmt.Errorf("the NS of %s: %w", sender, err)
			}
			dropped += len(gone)
		}
	}
	return dropped, nil
}

// --- The agent ---

// nsDropOwed: the zone's nsmgmt is another than the last look saw, or a change
// an earlier look saw has not had the agent's data dropped yet (dropNS). The
// first look is no change: a start reads this agent's data from its combiner
// by the role held then.
func (mpzd *MPZoneData) nsDropOwed() bool {
	if mpzd.instructions() == nil {
		return false
	}
	now := mpzd.roles().NSmgmt
	mpzd.Lock()
	defer mpzd.Unlock()
	mpzd.EnsureMP()
	if mpzd.MP.nsmgmtKnown && mpzd.MP.nsmgmtSeen != now {
		mpzd.MP.nsDropIsOwed = true
	}
	mpzd.MP.nsmgmtSeen, mpzd.MP.nsmgmtKnown = now, true
	return mpzd.MP.nsDropIsOwed
}

// followNSmgmt asks the data engine, which owns the agent's data, to drop
// the zone's NS when its nsmgmt changed, either way, or when the owner has
// it and the data holds some. A request a full queue does not take stays
// owed: the engine's round drops the zone's NS (nsmgmtRound).
func (conf *Config) followNSmgmt(mpzd *MPZoneData) {
	zdr, msgQs := conf.InternalMp.ZoneDataRepo, conf.InternalMp.MsgQs
	if zdr == nil || msgQs == nil || msgQs.SynchedDataCmd == nil {
		return
	}
	zone := ZoneName(mpzd.ZoneName)
	if !mpzd.nsDropOwed() && !(nsLeftToOwner(zone) && zdr.holdsNS(zone)) {
		return
	}
	select {
	case msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "drop-ns", Zone: zone}:
	default:
		lgEngine.Warn("the data engine's queue is full; the zone's NS is dropped from this agent's data in the engine's next round", "zone", zone)
	}
}

// holdsNS: the agent's data holds NS of some origin for the zone.
func (zdr *ZoneDataRepo) holdsNS(zone ZoneName) bool {
	repo, ok := zdr.Get(zone)
	if !ok {
		return false
	}
	for _, od := range repo.Data.Items() {
		if od == nil {
			continue
		}
		if rrset, ok := od.RRtypes.Get(dns.TypeNS); ok && len(rrset.RRs) > 0 {
			return true
		}
	}
	return false
}

// dropNS drops the NS of every origin from the agent's data for the zone,
// with its tracking: its own, which it contributes no more, and the others',
// which a resync would otherwise hand its combiner again. Called from the
// data engine, which owns the tracking. What a change owed is settled first,
// so that a change after it is owed again.
func (zdr *ZoneDataRepo) dropNS(zone ZoneName) {
	if mpzd, ok := Zones.Get(string(zone)); ok && mpzd != nil {
		mpzd.Lock()
		if mpzd.MP != nil {
			mpzd.MP.nsDropIsOwed = false
		}
		mpzd.Unlock()
	}
	repo, ok := zdr.Get(zone)
	if !ok {
		return
	}
	dropped := 0
	for agent, od := range repo.Data.Items() {
		if od == nil {
			continue
		}
		if rrset, ok := od.RRtypes.Get(dns.TypeNS); ok {
			dropped += len(rrset.RRs)
			od.RRtypes.Delete(dns.TypeNS)
		}
		zdr.removeTracking(zone, agent, dns.TypeNS)
		if od.RRtypes.Count() == 0 {
			repo.Data.Remove(agent)
		}
	}
	if dropped > 0 {
		lgEngine.Info("the zone's NS is dropped from this agent's data: its nsmgmt changed, or the owner has it", "zone", zone, "records", dropped)
	}
}

// nsmgmtRound is the data engine's look at every multi-provider zone: a drop a
// change of nsmgmt owes, a request the full queue did not take; what the data
// holds under nsmgmt=owner, a message that arrived late; and the report of the
// owner's NS RRset.
func (conf *Config) nsmgmtRound(zdr *ZoneDataRepo, now time.Time) {
	for _, name := range Zones.Keys() {
		mpzd, ok := Zones.Get(name)
		if !ok || mpzd == nil || !mpzd.Options[tdns.OptMultiProvider] {
			continue
		}
		zone := ZoneName(mpzd.ZoneName)
		if mpzd.nsDropOwed() || nsLeftToOwner(zone) && zdr.holdsNS(zone) {
			zdr.dropNS(zone)
		}
		conf.logOwnersNS(mpzd, now)
	}
}

// --- The report of design 3.7 ---

// ownersNSLogEvery: how often a report of the owner's NS RRset is logged.
const ownersNSLogEvery = time.Hour

// ownersNSReport is, under nsmgmt=owner, a line for each provider of the zone
// whose servers the owner's NS RRset names while its server role is not
// done: a provider the sets held do not name as a server, or that the active
// serial does not. A provider's names are those it tells in its stamp row,
// and for a removal under way those the removal keeps; one that tells none is
// not checked, and an auditor has no such role.
func (conf *Config) ownersNSReport(mpzd *MPZoneData) []string {
	tm := conf.InternalMp.MPTransport
	zone := ZoneName(mpzd.ZoneName)
	if tm == nil || !nsLeftToOwner(zone) {
		return nil
	}
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		return nil
	}
	var named []string
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs {
		if ns, ok := rr.(*dns.NS); ok {
			named = append(named, ns.Ns)
		}
	}
	in, r := mpzd.instructions(), mpzd.roles()
	if in == nil {
		return nil
	}
	among := func(set []Provider, id string) bool {
		return slices.ContainsFunc(set, func(p Provider) bool { return core.EqualNames(p.Identity, id) })
	}
	serving := in.providers(in.Servers)
	names := map[string][]string{} // by identity, folded
	for _, rec := range in.Records {
		names[canonicalName(rec.Identity)] = nil
	}
	for _, p := range r.Servers {
		if p.Identity != "" {
			names[canonicalName(p.Identity)] = nil
		}
	}
	if kept, ok := conf.InternalMp.Instructions.reconcileInputs(string(zone)); ok {
		for _, rm := range kept.removals {
			names[canonicalName(rm.Identity)] = rm.NSNames
		}
	}
	var lines []string
	for _, id := range slices.Sorted(maps.Keys(names)) {
		if among(r.Servers, id) && among(serving, id) || zoneStanding(in, id) == standingAuditor {
			continue
		}
		told := append(slices.Clone(names[id]), tm.stamps.nameserversOf(id)...)
		if slices.ContainsFunc(told, func(name string) bool {
			return slices.ContainsFunc(named, func(ns string) bool { return core.EqualNames(ns, name) })
		}) {
			lines = append(lines, fmt.Sprintf("the owner's NS RRset names the servers of %s, whose role is not done", id))
		}
	}
	return lines
}

// logOwnersNS logs the zone's report, each line once an hour. Called from
// the data engine only.
func (conf *Config) logOwnersNS(mpzd *MPZoneData, now time.Time) {
	for _, line := range conf.ownersNSReport(mpzd) {
		key := canonicalName(mpzd.ZoneName) + " " + line
		if last, ok := conf.InternalMp.ownersNSLogged[key]; ok && now.Sub(last) < ownersNSLogEvery {
			continue
		}
		if conf.InternalMp.ownersNSLogged == nil {
			conf.InternalMp.ownersNSLogged = map[string]time.Time{}
		}
		conf.InternalMp.ownersNSLogged[key] = now
		lg.Warn(line, "zone", mpzd.ZoneName)
	}
}
