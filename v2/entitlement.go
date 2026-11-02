/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The sweep (design 3.3, plan S17b). When a transition is done, each agent
 * drops from its data, and from its own combiner, every contribution the
 * active instructions do not entitle its origin to. Nothing goes to peers. It
 * catches a withdrawal lost to a restart: catch-up asks voting members only,
 * so nobody answers for a provider that left.
 */
package tdnsmp

import (
	"errors"
	"maps"
	"slices"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// sweptTypes are the types of contribution the sweep looks at.
var sweptTypes = []uint16{dns.TypeNS, dns.TypeDNSKEY, dns.TypeCDS, dns.TypeKEY, dns.TypeCSYNC}

// sweepWait is how long the end of a transition waits for the data engine's
// sweep: the newer serial that waited is agreed only after it.
var sweepWait = 10 * time.Second

// entitled: the instructions in entitle origin to contributions of rrtype. NS
// needs nsmgmt=agent and the origin in servers=; DNSKEY and CDS the origin in
// signers=. KEY and CSYNC are the leader's, once the leader's own is there:
// until then any origin's stands (leaderHolds). CDS, KEY and CSYNC need
// parentsync=agent too: a combiner under parentsync=owner does not apply them,
// and one kept would come back at a later take-up (plan S20), a CDS from before
// a key roll with it.
func entitled(in *Instructions, origin AgentId, rrtype uint16, leader AgentId, leaderHolds bool) bool {
	label, on := in.labelOf(string(origin))
	switch rrtype {
	case dns.TypeCDS, dns.TypeKEY, dns.TypeCSYNC:
		if in.ParentSync != core.HsyncParentSyncAgent {
			return false
		}
	}
	switch rrtype {
	case dns.TypeNS:
		return in.NSmgmt == core.HsyncNSmgmtAGENT && on && slices.Contains(in.Servers, label)
	case dns.TypeDNSKEY, dns.TypeCDS:
		return on && slices.Contains(in.Signers, label)
	case dns.TypeKEY, dns.TypeCSYNC:
		return !leaderHolds || sameName(string(origin), string(leader))
	}
	return true
}

// holdsContribution: the repo's origin holds records of rrtype.
func holdsContribution(ar *AgentRepo, origin AgentId, rrtype uint16) bool {
	od, ok := ar.Data.Get(origin)
	if !ok || od == nil || od.RRtypes == nil {
		return false
	}
	rrset, ok := od.RRtypes.Get(rrtype)
	return ok && len(rrset.RRs) > 0
}

// sweep drops what the instructions in, the active serial's at the zone's
// "done", do not entitle an origin to, here and at this agent's combiner. It
// runs on the data engine, whose repo it changes. It does not run while the
// zone reconciles, or once another serial is active: the sweep is V's, and it
// runs at V's "done" also when a newer serial waits to be agreed on, before
// that agreement starts (7.2). One serial does not stop it: one the not-built
// fallback followed at that "done" (followNotBuilt). It is unenforced, so what
// only it takes away stays and what it gives is not swept: the sweep drops what
// neither serial entitles.
func (conf *Config) sweep(zdr *ZoneDataRepo, zone ZoneName, in *Instructions) {
	if zdr == nil || in == nil {
		return
	}
	cur, ok := conf.InternalMp.Instructions.reconcileInputs(string(zone))
	if !ok || cur.reconciling {
		return // a sweep owed stays owed; that transition's "done" sweeps too
	}
	// This sweep answers for any owed: it marks the zone again if it must. If
	// it stops below, the serial now active had its own sweep at its "done".
	delete(zdr.sweepsOwed, zone)
	by := []*Instructions{in}
	if cur.active.Serial != in.Serial || cur.active.Digest != in.Digest() {
		if cur.follows == "" || cur.active.Reading == nil {
			return
		}
		by = append(by, cur.active.Reading)
	}
	ar, ok := zdr.Repo.Get(zone)
	if !ok || ar == nil {
		return
	}
	var leader AgentId
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
		leader, _ = lem.ZoneLeader(zone)
	}
	for _, origin := range ar.Data.Keys() {
		od, ok := ar.Data.Get(origin)
		if !ok || od == nil || od.RRtypes == nil {
			continue
		}
		for _, t := range sweptTypes {
			if _, has := od.RRtypes.Get(t); !has {
				continue
			}
			leaderHolds := leader != "" && holdsContribution(ar, leader, t)
			if slices.ContainsFunc(by, func(i *Instructions) bool { return entitled(i, origin, t, leader, leaderHolds) }) {
				continue
			}
			// The combiner is asked first: what it could not be asked to drop
			// stays here, the record of what is owed, and the tick runs this
			// sweep again (retrySweeps).
			if err := purgeAtCombiner(conf.InternalMp.MPTransport, zone, origin, t); err != nil {
				lgEngine.Warn("the combiner could not be asked to drop a contribution its origin is not entitled to; it stays, and is asked for again", "zone", zone, "origin", origin, "rrtype", dns.TypeToString[t], "err", err)
				if zdr.sweepsOwed == nil {
					zdr.sweepsOwed = map[ZoneName]sweepOwed{}
				}
				zdr.sweepsOwed[zone] = sweepOwed{in: in, at: time.Now()}
				continue
			}
			od.RRtypes.Delete(t)
			zdr.removeTracking(zone, origin, t)
			lgEngine.Info("swept a contribution its origin is not entitled to", "zone", zone, "origin", origin, "rrtype", dns.TypeToString[t])
		}
	}
}

// sweepOwed is a sweep to run again: a purge of it could not be queued. It runs
// by the serial it ran by, so a followed serial still does not widen it.
type sweepOwed struct {
	in *Instructions
	at time.Time
}

// retrySweeps: the tick's word on the sweeps owed: each runs again once
// roll-retry has passed since it last ran. What has left since is not asked
// for twice. On the engine's goroutine, which alone reads sweepsOwed.
func (conf *Config) retrySweeps(zdr *ZoneDataRepo) {
	every := rollRetryFor(conf.MpConfig())
	for zone, owed := range maps.Clone(zdr.sweepsOwed) {
		if time.Since(owed.at) >= every {
			conf.sweep(zdr, zone, owed.in)
		}
	}
}

// purgeAtCombiner is the sweep's flagged purge: an empty replace of the type
// in the origin's name with the withdrawal's flag, a removal the combiner
// takes from its own agent only, whether or not the origin votes
// (combinerTakesRemoval, S16). It goes to this agent's combiner and no
// further. A test stands in for it.
var purgeAtCombiner = func(tm *MPTransportBridge, zone ZoneName, origin AgentId, rrtype uint16) error {
	if tm == nil {
		return errors.New("the transport is not available")
	}
	purge := (&Withdraw{Provider: string(origin), RRtype: dns.TypeToString[rrtype]}).update(zone)
	_, err := tm.EnqueueForCombiner(zone, purge, "")
	return err
}

// askSweep has the data engine sweep the zone by the instructions in, and
// waits for it, up to sweepWait. A test stands in for it.
var askSweep = func(conf *Config, zone string, in *Instructions) {
	msgQs := conf.InternalMp.MsgQs
	if msgQs == nil || msgQs.SynchedDataCmd == nil {
		return
	}
	answer := make(chan *SynchedDataCmdResponse, 1)
	deadline := time.After(sweepWait)
	select {
	case msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "sweep", Zone: ZoneName(zone), Sweep: in, Response: answer}:
	case <-deadline:
		lgEngine.Warn("the data engine did not take the sweep in time; not swept", "zone", zone)
		return
	}
	select {
	case <-answer:
	case <-deadline:
		lgEngine.Warn("the data engine has not swept the zone yet; going on", "zone", zone)
	}
}
