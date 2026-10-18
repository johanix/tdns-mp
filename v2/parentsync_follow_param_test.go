/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// servedParentSync puts the zone's HSYNCPARAM in place as a refresh brings
// it: the roles it had, with parentsync="agent" or "owner", or with no
// parentsync at all (nil). Without an HSYNCPARAM to start from the record
// has the parentsync alone; gone removes the record.
func servedParentSync(t *testing.T, mpzd *MPZoneData, parentsync *uint8, gone bool) {
	t.Helper()
	zone := mpzd.ZoneName
	apex, ok := mpzd.Data.Get(zone)
	if !ok {
		t.Fatalf("the zone %s has no apex", zone)
	}
	if gone {
		apex.RRtypes.Delete(core.TypeHSYNCPARAM)
	} else {
		var roles []core.HSYNCPARAMKeyValue
		if old, ok := apex.RRtypes.Get(core.TypeHSYNCPARAM); ok && len(old.RRs) > 0 {
			for _, kv := range old.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM).Value {
				if _, ps := kv.(*core.HSYNCPARAMParentSync); !ps {
					roles = append(roles, kv)
				}
			}
		}
		if parentsync != nil {
			roles = append(roles, &core.HSYNCPARAMParentSync{Value: *parentsync})
		}
		hdr := dns.RR_Header{Name: zone, Rrtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, Ttl: 3600}
		apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr, Data: &core.HSYNCPARAM{Value: roles}}}})
	}
	mpzd.Data.Set(zone, apex)
	mpzd.InstallInitialSnapshot() // the analysis reads the zone as it is served
}

// refreshed runs the post-refresh callbacks that the daemon registers for a
// multi-provider zone (RegisterMPRefreshCallbacks), as a refresh does that
// found the HSYNC records changed.
func refreshed(t *testing.T, conf *Config, mpzd *MPZoneData) {
	t.Helper()
	if !slices.Contains(conf.InternalMp.MPZoneNames, mpzd.ZoneName) {
		conf.InternalMp.MPZoneNames = append(conf.InternalMp.MPZoneNames, mpzd.ZoneName)
		conf.RegisterMPRefreshCallbacks()
	}
	mpzd.EnsureMP()
	mpzd.MP.RefreshAnalysis = &ZoneRefreshAnalysis{HsyncChanged: true}
	for _, cb := range mpzd.OnZonePostRefresh {
		cb(mpzd.ZoneData)
	}
}

var (
	parentSyncAgent = core.HsyncParentSyncAgent
	parentSyncOwner = core.HsyncParentSyncOwner
)

// The agent's delegation sync of a multi-provider zone follows the zone's
// HSYNCPARAM in both directions. It was turned on when HSYNCPARAM said
// parentsync=agent and never off (tdns-mp #200): once the owner had taken
// the sync over, the leader went on syncing the parent at every lease
// renewal, and could put back what the owner had removed there.
func TestTheDelegationSyncFollowsHSYNCPARAM(t *testing.T) {
	asMPAgent(t)
	r := newLeaderSyncRig(t, "follow.parentsync.example.")
	r.leader("agent.us.example.")
	z := r.mpzd.ZoneName
	r.mpzd.SetOption(tdns.OptParentSync, false)

	steps := []struct {
		what       string
		parentsync *uint8
		gone       bool
		want       bool
	}{
		{"parentsync=agent", &parentSyncAgent, false, true},
		{"the owner takes the sync over", &parentSyncOwner, false, false},
		{"the agents again", &parentSyncAgent, false, true},
		{"no parentsync key: the owner's", nil, false, false},
		{"the agents once more", &parentSyncAgent, false, true},
		{"no HSYNCPARAM", nil, true, false},
	}
	for _, s := range steps {
		servedParentSync(t, r.mpzd, s.parentsync, s.gone)
		refreshed(t, r.conf, r.mpzd)
		if got := r.mpzd.Options[tdns.OptParentSync]; got != s.want {
			t.Fatalf("%s: the delegation sync is %v, want %v", s.what, got, s.want)
		}
		// what an election, a lease renewal included, asks for
		asked := r.conf.requestDelegationSync(r.ctx, z, "this agent was elected the zone's delegation sync leader")
		if n := r.requests(t); asked != s.want || n != map[bool]int{true: 1, false: 0}[s.want] {
			t.Errorf("%s: a renewal asked=%v and queued %d syncs", s.what, asked, n)
		}
	}
}

// A parentsync option in the agent's own configuration does not outweigh
// the owner's HSYNCPARAM: the owner syncs a zone whose HSYNCPARAM does not
// say parentsync=agent, whatever the agent's configuration says.
func TestTheOwnersHSYNCPARAMOutweighsTheAgentsConfig(t *testing.T) {
	asMPAgent(t)
	r := newLeaderSyncRig(t, "static.parentsync.example.")
	r.leader("agent.us.example.")
	// the rig's zone has the option on, as from the agent's configuration
	servedParentSync(t, r.mpzd, &parentSyncOwner, false)
	refreshed(t, r.conf, r.mpzd)
	if r.mpzd.Options[tdns.OptParentSync] {
		t.Fatal("an agent configured with parentsync syncs a zone whose owner syncs it")
	}
}

// Another role leaves the option alone: only an agent syncs a zone's
// delegation through the agents.
func TestOnlyAnAgentFollowsHSYNCPARAM(t *testing.T) {
	old := tdns.Globals.App.Type
	tdns.Globals.App.Type = AppTypeMPCombiner
	t.Cleanup(func() { tdns.Globals.App.Type = old })
	r := newLeaderSyncRig(t, "combiner.parentsync.example.")
	servedParentSync(t, r.mpzd, &parentSyncOwner, false)
	refreshed(t, r.conf, r.mpzd)
	if !r.mpzd.Options[tdns.OptParentSync] {
		t.Error("a combiner's refresh changed the delegation sync option")
	}
}

const logDroppedOwner = `msg="the held NOTIFY is dropped: the zone's owner syncs its delegation"`

// The owner takes the sync over while a NOTIFY is held: the refresh that
// brings the HSYNCPARAM drops the NOTIFY and ends the chain, and nothing
// asks again, a lease renewal included. When HSYNCPARAM gives the sync back
// to the agents, the next change is synced.
func TestTheOwnerTakingTheSyncOverDropsAHeldNotify(t *testing.T) {
	asMPAgent(t)
	const wait = time.Second
	r := newNotifyRig(t, "owner.notify.example.", "NOTIFY", repeat(50*time.Millisecond, 400)...)
	servedParentSync(t, r.mpzd, &parentSyncAgent, false)
	r.propagation(wait)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.hint()
	r.logged(t, 1, logHeld)

	servedParentSync(t, r.mpzd, &parentSyncOwner, false) // before the wait is over
	refreshed(t, r.conf, r.mpzd)
	if l := r.log.String(); !strings.Contains(l, logDroppedOwner+" zone="+z+" notify=CSYNC") {
		t.Errorf("the refresh did not drop the held NOTIFY:\n%s", l)
	}
	if n := r.chains(); n != 0 {
		t.Errorf("%d chains left after the held NOTIFY was dropped", n)
	}
	if r.conf.requestDelegationSync(r.ctx, z, "this agent was elected the zone's delegation sync leader") {
		t.Error("a lease renewal asked for a sync of a zone whose owner syncs it")
	}
	r.hint()
	r.quiet(t, wait+300*time.Millisecond, "for a zone whose owner syncs it")
	r.untold(t, 0, "for a zone whose owner syncs it")
	if r.chains() != 0 {
		t.Error("a chain was started for a zone whose owner syncs it")
	}
	if l := r.log.String(); strings.Contains(l, logLeft) || strings.Contains(l, logCheckAgain) {
		t.Errorf("a NOTIFY that was dropped left, or was checked:\n%s", l)
	}

	servedParentSync(t, r.mpzd, &parentSyncAgent, false)
	refreshed(t, r.conf, r.mpzd)
	r.propagation(0)
	r.hint()
	r.notified(t, "the agents sync the zone again", dns.TypeCSYNC)
}

// A request that was on the syncher's queue when the owner took the sync
// over is not sent: the syncher asks the option again, as it asks whether
// this agent is still the leader.
func TestASyncQueuedBeforeTheOwnerTookOverIsNotSent(t *testing.T) {
	asMPAgent(t)
	r := newNotifyRig(t, "queued.notify.example.", "NOTIFY", time.Hour)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)
	// what a refresh that found a delegation change queued, while the
	// agents still synced the zone
	changed, dss, err := implicitDelegationChange(r.mpzd, refreshedZone(t, r.mpzd, fmt.Sprintf("%s 3600 IN NS ns2.provider.example.", z)))
	if err != nil || !changed {
		t.Fatalf("the refresh: changed=%v err=%v", changed, err)
	}
	servedParentSync(t, r.mpzd, &parentSyncOwner, false)
	refreshed(t, r.conf, r.mpzd)
	if r.mpzd.Options[tdns.OptParentSync] {
		t.Fatal("the owner took the sync over, and the agent still syncs the zone")
	}

	r.q <- tdns.DelegationSyncRequest{Command: "SYNC-DELEGATION", ZoneName: z, ZoneData: r.mpzd.ZoneData, SyncStatus: dss}
	resp := make(chan tdns.DelegationSyncStatus, 1)
	r.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: z, ZoneData: r.mpzd.ZoneData, Response: resp}
	select {
	case st := <-resp:
		if want := "the zone's owner syncs its delegation, skipping DDNS"; st.Msg != want {
			t.Errorf("the explicit sync answered %q, want %q", st.Msg, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the explicit sync did not answer")
	}
	r.quiet(t, 300*time.Millisecond, "for a request queued before the owner took over")
	r.untold(t, 0, "for a request queued before the owner took over")
}
