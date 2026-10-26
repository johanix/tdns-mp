/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

const logLeadLostStop = `msg="the delegation sync under way is stopped: another agent leads the zone now"`

// leadMovesTo names who the zone's leader on the election the rig holds, as
// an election that this agent loses does: under the election's lock.
func (r *leaderSyncRig) leadMovesTo(who AgentId) {
	r.lem.mu.RLock()
	le := r.lem.elections[ZoneName(r.mpzd.ZoneName)]
	r.lem.mu.RUnlock()
	le.mu.Lock()
	r.lem.noteLeaderLocked(le, who, time.Now())
	le.Leader, le.LeaderExpiry = who, time.Now().Add(time.Hour)
	le.mu.Unlock()
}

// The election tells of a lead this agent lost only when another agent is
// named: with the hold it lost, the lead that began it, also when an
// invalidation or a lapsed lease gave this agent a new lead in between. A
// renewal, a re-election, and an invalidation alone tell nothing.
func TestALeadIsLostOnlyToAnotherAgent(t *testing.T) {
	lem := NewLeaderElectionManager("agent.us.example.", time.Minute, func(ZoneName, string, map[string][]string) error { return nil })
	lost := make(chan uint64, 8)
	lem.SetOnLeadLost(func(lead uint64) { lost <- lead })
	le := &LeaderElection{Zone: "lost.example."}
	name := func(who AgentId) {
		le.mu.Lock()
		lem.noteLeaderLocked(le, who, time.Now())
		le.Leader, le.LeaderExpiry = who, time.Now().Add(time.Hour)
		le.mu.Unlock()
	}
	told := func(want uint64, what string) {
		t.Helper()
		select {
		case got := <-lost:
			if want == 0 {
				t.Errorf("%s told of a lost lead %d", what, got)
			} else if got != want {
				t.Errorf("%s told of lead %d lost, want %d", what, got, want)
			}
		case <-time.After(200 * time.Millisecond):
			if want != 0 {
				t.Errorf("%s did not tell of lead %d lost", what, want)
			}
		}
	}

	name("agent.us.example.")
	first := le.leadStart
	told(0, "this agent's election")
	name("agent.us.example.")
	if le.leadStart != first {
		t.Errorf("a renewal gave the lead a new number: %d, was %d", le.leadStart, first)
	}
	told(0, "a renewal")
	name("agent.them.example.")
	told(first, "another agent's election")

	name("agent.us.example.")
	second := le.leadStart
	name("")
	told(0, "an invalidation")
	name("agent.us.example.")
	told(0, "a re-election after an invalidation")
	if le.leadStart == second {
		t.Errorf("the lead after an invalidation kept the number of the one before")
	}
	if le.holdStart != second {
		t.Errorf("the re-election after an invalidation is hold %d, want the hold it continues, %d", le.holdStart, second)
	}
	name("")
	name("agent.them.example.")
	told(second, "another agent named after an invalidation and a re-election")
	name("agent.them.example.")
	told(0, "another agent's renewal")

	name("agent.us.example.")
	fourth := le.leadStart
	le.mu.Lock()
	le.LeaderExpiry = time.Now().Add(-time.Second)
	le.mu.Unlock()
	name("agent.us.example.")
	told(0, "a re-election after a lapsed lease")
	if le.leadStart == fourth || le.holdStart != fourth {
		t.Errorf("after a lapsed lease the lead is %d in hold %d, want a new lead in hold %d", le.leadStart, le.holdStart, fourth)
	}
	name("agent.them.example.")
	told(fourth, "another agent named after a lapsed lease")
}

// A former leader does not send an UPDATE on that tdns is still retrying: the
// lead it was sent in is lost to another agent, and the new leader's sync is
// the one that counts. It sent it on: a DS change the new leader had
// overtaken could reach the parent after the new leader's own.
func TestALeadLostToAnotherAgentStopsAnUpdateBeingRetried(t *testing.T) {
	r, underWay := updateBeingRetried(t, "leadlost.update.example.")
	z := r.mpzd.ZoneName

	r.leadMovesTo(AgentId(r.peer.Identity)) // before the retry's wait is over
	for deadline := time.Now().Add(10 * time.Second); underWay() > 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the sync went on after another agent took the lead")
		}
	}
	if l := r.log.String(); !strings.Contains(l, logLeadLostStop+" zone="+z+" syncs=1") {
		t.Errorf("the lost lead did not stop the sync under way:\n%s", l)
	}
	if n := r.parent.updatesSeen(); n != 1 {
		t.Errorf("the parent got %d UPDATEs, want the one sent before the lead moved", n)
	}
}

// An UPDATE begun in one lead is stopped when another agent takes the lead,
// though this agent took a new lead in between: elected again after an
// invalidation, or after its lease lapsed. The run belongs to the hold, not
// to the lead's number. It went on: the loss named only the new number.
func TestALeadLostAfterThisAgentLedAgainStopsAnUpdateBegunBefore(t *testing.T) {
	for _, c := range []struct {
		name  string
		again func(r *notifyRig)
	}{
		{"after an invalidation", func(r *notifyRig) {
			r.leadMovesTo("")
			r.leadMovesTo(r.lem.localID)
		}},
		{"after a lapsed lease", func(r *notifyRig) {
			r.lem.mu.RLock()
			le := r.lem.elections[ZoneName(r.mpzd.ZoneName)]
			r.lem.mu.RUnlock()
			le.mu.Lock()
			le.LeaderExpiry = time.Now().Add(-time.Second)
			le.mu.Unlock()
			r.leadMovesTo(r.lem.localID)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, underWay := updateBeingRetried(t, "leadagain.update.example.")
			z := r.mpzd.ZoneName
			first := r.lem.LeadStart(ZoneName(z))
			c.again(r)
			if r.lem.LeadStart(ZoneName(z)) == first {
				t.Fatalf("this agent leads with the same number %d: the case is not a new lead", first)
			}
			if h := r.conf.holdOf(z); h != first {
				t.Errorf("a run begun now belongs to %d, want the hold begun in lead %d", h, first)
			}
			time.Sleep(100 * time.Millisecond)
			if underWay() != 1 {
				t.Fatal("this agent's own new lead stopped the sync under way")
			}

			r.leadMovesTo(AgentId(r.peer.Identity))
			for deadline := time.Now().Add(10 * time.Second); underWay() > 0; time.Sleep(10 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatal("the sync begun before this agent led again went on after another agent took the lead")
				}
			}
			if l := r.log.String(); !strings.Contains(l, logLeadLostStop+" zone="+z+" syncs=1") {
				t.Errorf("the lost lead did not stop the sync under way:\n%s", l)
			}
		})
	}
}

// updateBeingRetried is a leader sync of zone whose UPDATE the parent has
// refused once and tdns is retrying, with the lead lost to another agent
// stopping what began in it; underWay counts the zone's runs.
func updateBeingRetried(t *testing.T, zone string) (r *notifyRig, underWay func() int) {
	t.Helper()
	asMPAgent(t)
	r = newNotifyRig(t, zone, "UPDATE", repeat(30*time.Millisecond, 400)...)
	r.lem.SetOnLeadLost(r.conf.stopRunsOfLostLead)
	servedParentSync(t, r.mpzd, &parentSyncAgent, false)
	r.propagation(time.Hour)
	z := r.mpzd.ZoneName
	if _, err := r.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	r.parent.refuses()
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.ask()
	underWay = func() int {
		c := &r.conf.InternalMp.delegationSyncChains
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.runs[z])
	}
	for deadline := time.Now().Add(10 * time.Second); r.parent.updatesSeen() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no UPDATE reached the parent")
		}
	}
	if underWay() != 1 {
		t.Fatal("the refused UPDATE is not being retried")
	}
	return r, underWay
}

// A former leader does not bootstrap the zone's SIG(0) key with the parent:
// the poll it started in its lead ends when another agent takes the lead, in
// the poll's wait, and is not started again. It went on to bootstrap the key
// after the new leader had (the rig's K3, run 59t).
func TestALeadLostToAnotherAgentEndsTheKeyPoll(t *testing.T) {
	r := newKeyHoldRig(t, "leadlost.keypoll.example.")
	r.lem.SetOnLeadLost(r.conf.stopRunsOfLostLead)
	var polls, bootstrapped atomic.Int32
	ended := make(chan struct{}, 4)
	r.conf.InternalMp.keyPoll = func(ctx context.Context, _ ZoneName, _ string, _ uint16, _ uint8) {
		polls.Add(1)
		r.entered <- struct{}{}
		select {
		case <-r.release:
			bootstrapped.Add(1)
		case <-ctx.Done():
		}
		ended <- struct{}{}
	}
	r.pollRuns(t)

	r.leadMovesTo(AgentId(r.peer.Identity))
	if _, ok := recvWithin(ended, 5*time.Second); !ok {
		t.Fatalf("the key poll went on after another agent took the lead\n%s", r.log)
	}
	close(r.release)
	time.Sleep(100 * time.Millisecond)
	if n := bootstrapped.Load(); n != 0 {
		t.Errorf("the former leader bootstrapped the key %d times", n)
	}
	if n := polls.Load(); n != 1 {
		t.Errorf("the key poll ran %d times, want once: a former leader started it again", n)
	}
	if l := r.log.String(); !strings.Contains(l, logLeadLostStop+" zone="+string(r.zone)+" syncs=1") {
		t.Errorf("the lost lead did not stop the key poll:\n%s", l)
	}
}

// Every zone that enters a provider group is told of, whoever leads the group
// or none: a group led by another agent, or not led yet, ends or moves this
// agent's lead of the zone as much as one this agent leads.
func TestEveryZoneThatEntersAGroupIsToldOf(t *testing.T) {
	lem := NewLeaderElectionManager("agent.us.example.", time.Minute, func(ZoneName, string, map[string][]string) error { return nil })
	var told []ZoneName
	lem.SetOnZoneRegrouped(func(zone ZoneName) { told = append(told, zone) })
	lem.zoneJoinedGroup("unled.example.", "", "group-without-leader")
	lem.SetOnZoneJoined(func(ZoneName) error { return nil })
	lem.zoneJoinedGroup("moved.example.", "group-before", "group-without-leader")
	if len(told) != 2 || told[0] != "unled.example." || told[1] != "moved.example." {
		t.Errorf("the zones told of are %v, want both that entered a group", told)
	}
}

// groupLeadMovesTo names who the leader of the group's election, as an
// election or the gossip of one does: under the election's lock.
func (r *leaderSyncRig) groupLeadMovesTo(group string, who AgentId) {
	r.lem.mu.Lock()
	le, ok := r.lem.groupElections[group]
	if !ok {
		le = &LeaderElection{Zone: ZoneName(group), Votes: map[AgentId]uint32{}, Confirms: map[AgentId]AgentId{}}
		r.lem.groupElections[group] = le
	}
	r.lem.mu.Unlock()
	le.mu.Lock()
	r.lem.noteLeaderLocked(le, who, time.Now())
	le.Leader, le.LeaderExpiry = who, time.Now().Add(time.Hour)
	le.mu.Unlock()
}

// A zone enters a provider group that has no leader yet, with an UPDATE
// begun under the zone's own election still being retried. The group's
// election that follows moves the zone's lead without a loss of the hold
// the UPDATE began in. When another agent wins the group, the UPDATE stops.
// When this agent wins it, the UPDATE is tied to the group's hold, and stops
// when another agent takes the group's lead later. It went on in both.
func TestARunFollowsItsZoneIntoAGroupWithNoLeaderYet(t *testing.T) {
	for _, c := range []struct {
		name string
		wins bool
	}{
		{"another agent wins the group", false},
		{"this agent wins the group, then loses it", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, underWay := updateBeingRetried(t, "unled.group.example.")
			z := r.mpzd.ZoneName
			const group = "group-not-yet-led"
			pgm := NewProviderGroupManager(string(r.lem.localID))
			pgm.Groups = map[string]*ProviderGroup{group: {GroupHash: group, Zones: []ZoneName{ZoneName(z)}}}
			r.lem.SetProviderGroupManager(pgm)
			r.lem.SetOnZoneRegrouped(r.conf.retieRuns)
			r.lem.SetOnLeaderNamed(r.conf.retieAllRuns)
			began := r.conf.holdOf(z)

			r.lem.zoneJoinedGroup(ZoneName(z), "", group)
			if underWay() != 1 {
				t.Fatal("the run stopped as its zone entered a group with no leader")
			}
			if c.wins {
				r.groupLeadMovesTo(group, r.lem.localID)
				won := r.lem.LeadHold(ZoneName(z))
				if won == 0 || won == began {
					t.Fatalf("this agent's lead of the zone in the group is hold %d, want the group's own, not %d", won, began)
				}
				for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
					c := &r.conf.InternalMp.delegationSyncChains
					c.mu.Lock()
					var held uint64
					for _, run := range c.runs[z] {
						held = run.hold
					}
					c.mu.Unlock()
					if held == won {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("the run is tied to hold %d after this agent won the group, want the group's %d", held, won)
					}
				}
				if underWay() != 1 {
					t.Fatal("this agent's own win of the group stopped the run")
				}
			}
			r.groupLeadMovesTo(group, AgentId(r.peer.Identity))
			for deadline := time.Now().Add(10 * time.Second); underWay() > 0; time.Sleep(10 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatal("the run went on after another agent took the lead of the group its zone entered")
				}
			}
		})
	}
}

// A retie that read the zone's lead before the lead moved records a hold
// that is lost by the time it lands, after the loss went by the run. The
// election that moved the lead asks for a retie of its own, which runs after
// the stale one and reads the lead as it is: it stops the run.
func TestALateRetieIsSetRightByTheRetieOfTheChangeItMissed(t *testing.T) {
	r, underWay := updateBeingRetried(t, "stale.retie.example.")
	z := r.mpzd.ZoneName
	const group = "group-taken-over"
	pgm := NewProviderGroupManager(string(r.lem.localID))
	pgm.Groups = map[string]*ProviderGroup{group: {GroupHash: group, Zones: []ZoneName{ZoneName(z)}}}
	r.lem.SetProviderGroupManager(pgm)
	r.groupLeadMovesTo(group, AgentId(r.peer.Identity)) // no retie wired: this one is missed

	r.conf.retieRunsTo(z, 9, false) // a retie that read this agent's lead of the group before the move
	if underWay() != 1 {
		t.Fatal("the stale retie stopped the run itself")
	}
	r.conf.retieAllRuns() // the retie the election that moved the lead asks for
	for deadline := time.Now().Add(10 * time.Second); underWay() > 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the retie after the move left the run going on a lead that another agent holds")
		}
	}
}

// A run follows its zone into a provider group: tied to the new group's hold
// from then on, so that the loss of the group's lead stops it, and the loss
// of the hold it began in does not. A zone whose new group another agent
// leads has its runs stopped. A run begun with no lead is left alone.
func TestARunFollowsItsZoneIntoAGroup(t *testing.T) {
	const zone = "regroup.example."
	conf := &Config{Config: &tdns.Config{}}
	c := &conf.InternalMp.delegationSyncChains
	run := func(hold uint64) context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		c.mu.Lock()
		if c.runs == nil {
			c.runs = map[string]map[uint64]delegationRun{}
		}
		if c.runs[zone] == nil {
			c.runs[zone] = map[uint64]delegationRun{}
		}
		c.runID++
		c.runs[zone][c.runID] = delegationRun{cancel: cancel, hold: hold}
		c.mu.Unlock()
		return ctx
	}

	moved, untied := run(7), run(0)
	conf.retieRunsTo(zone, 9, false)
	conf.stopRunsOfLostLead(7)
	if moved.Err() != nil {
		t.Fatal("the loss of the hold the run began in stopped it after its zone moved to another group's lead")
	}
	conf.stopRunsOfLostLead(9)
	if moved.Err() == nil {
		t.Error("the loss of the new group's lead did not stop the run that moved with its zone")
	}
	if untied.Err() != nil {
		t.Error("a run begun with no lead was stopped")
	}

	led := run(11)
	conf.retieRunsTo(zone, 0, false)
	if led.Err() != nil {
		t.Error("a run was stopped while nobody leads its zone: an invalidation, or a group not yet led")
	}
	conf.retieRunsTo(zone, 0, true)
	if led.Err() == nil {
		t.Error("a zone that another agent leads now kept its run")
	}
	if untied.Err() != nil {
		t.Error("a run begun with no lead was stopped when its zone's new group is another agent's")
	}
}
