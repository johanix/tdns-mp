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
// named: with the number of the lead it lost, also when an invalidation came
// in between. A renewal, a re-election, and an invalidation alone tell
// nothing.
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
	third := le.leadStart
	if third == second {
		t.Errorf("the lead after an invalidation kept the number of the one before")
	}
	name("")
	name("agent.them.example.")
	told(third, "another agent named after an invalidation")
	name("agent.them.example.")
	told(0, "another agent's renewal")
}

// A former leader does not send an UPDATE on that tdns is still retrying: the
// lead it was sent in is lost to another agent, and the new leader's sync is
// the one that counts. It sent it on: a DS change the new leader had
// overtaken could reach the parent after the new leader's own.
func TestALeadLostToAnotherAgentStopsAnUpdateBeingRetried(t *testing.T) {
	asMPAgent(t)
	r := newNotifyRig(t, "leadlost.update.example.", "UPDATE", repeat(30*time.Millisecond, 400)...)
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
	r.hint()
	underWay := func() int {
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
