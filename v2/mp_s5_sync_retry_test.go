/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Arrow 2 on a testbed: the leader's first sync met a parent that knew
 * the SIG(0) key and had not finished verifying it, was refused, and was
 * dropped; and a leader that restarted inside its term learnt from its
 * peers that it leads and asked for nothing. Both left the parent
 * without the DS set until the keys changed again.
 */
package tdnsmp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// waitRequests: the retries come from timers; wait for n requests.
func (r *leaderSyncRig) waitRequests(t *testing.T, n int, within time.Duration) int {
	t.Helper()
	got, end := 0, time.Now().Add(within)
	for got < n && time.Now().Before(end) {
		got += r.requests(t)
		time.Sleep(5 * time.Millisecond)
	}
	return got
}

func TestAFailedDelegationSyncIsAskedAgain(t *testing.T) {
	r := newLeaderSyncRig(t, "refused.sync.example.")
	z := r.mpzd.ZoneName
	r.leader("agent.us.example.")
	refused := errors.New("parent REFUSED the delegation UPDATE (SIG(0) key known, but not yet trusted)")
	delays := []time.Duration{20 * time.Millisecond, 20 * time.Millisecond}
	ctx := context.Background()

	// a failure asks again after the first delay; a second report while that
	// retry waits adds none
	r.conf.delegationSyncFailedWith(ctx, z, refused, delays)
	r.conf.delegationSyncFailedWith(ctx, z, refused, delays)
	if n := r.waitRequests(t, 1, time.Second); n != 1 {
		t.Fatalf("after one failure: %d sync requests, want 1", n)
	}
	time.Sleep(60 * time.Millisecond)
	if n := r.requests(t); n != 0 {
		t.Errorf("the second report while a retry waited asked for %d more syncs", n)
	}
	// the retried sync fails too: asked once more, and that is the bound
	r.conf.delegationSyncFailedWith(ctx, z, refused, delays)
	if n := r.waitRequests(t, 1, time.Second); n != 1 {
		t.Fatalf("after the second failure: %d sync requests, want 1", n)
	}
	r.conf.delegationSyncFailedWith(ctx, z, refused, delays)
	time.Sleep(60 * time.Millisecond)
	if n := r.requests(t); n != 0 {
		t.Errorf("past the bound: %d sync requests, want none", n)
	}
	// given up means forgotten: the next failure starts a new chain
	r.conf.delegationSyncFailedWith(ctx, z, refused, delays)
	if n := r.waitRequests(t, 1, time.Second); n != 1 {
		t.Errorf("a failure after the chain was given up: %d sync requests, want 1", n)
	}
}

func TestASyncThatSucceedsEndsTheRetries(t *testing.T) {
	r := newLeaderSyncRig(t, "healed.sync.example.")
	z := r.mpzd.ZoneName
	r.leader("agent.us.example.")
	delays := []time.Duration{10 * time.Millisecond}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		// with one delay in the list, a second failure in one chain would be
		// past the bound; a success between them makes each the first
		r.conf.delegationSyncFailedWith(ctx, z, errors.New("refused"), delays)
		if n := r.waitRequests(t, 1, time.Second); n != 1 {
			t.Fatalf("round %d: %d sync requests, want 1", i+1, n)
		}
		r.conf.delegationSyncSucceeded(z)
	}
}

func TestARetryAsksNothingOnceTheLeadershipIsLost(t *testing.T) {
	r := newLeaderSyncRig(t, "lost.sync.example.")
	z := r.mpzd.ZoneName
	r.leader("agent.us.example.")
	delays := []time.Duration{30 * time.Millisecond, 30 * time.Millisecond}
	r.conf.delegationSyncFailedWith(context.Background(), z, errors.New("refused"), delays)
	r.leader("agent.p2.example.") // before the retry comes due
	time.Sleep(100 * time.Millisecond)
	if n := r.requests(t); n != 0 {
		t.Errorf("a peer that lost the leadership asked for %d syncs", n)
	}
	// and its chain ended with that: leading again, a failure is the first
	r.leader("agent.us.example.")
	r.conf.delegationSyncFailedWith(context.Background(), z, errors.New("refused"), delays)
	if n := r.waitRequests(t, 1, time.Second); n != 1 {
		t.Errorf("leading again: %d sync requests after a failure, want 1", n)
	}
}

// A leader that restarts inside its term holds no election: its peers tell
// it that it leads. It asks what an election's winner asks.
func TestLeadershipLearntFromGossipAsksLikeAnElectionWon(t *testing.T) {
	lem := NewLeaderElectionManager("agent.us.example.", time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	pgm := NewProviderGroupManager("agent.us.example.")
	lem.SetProviderGroupManager(pgm)
	asked := make(chan ZoneName, 4)
	lem.SetOnLeaderElected(func(z ZoneName) error { asked <- z; return nil })
	const hash = "0123456789abcdef"
	pgm.mu.Lock()
	pgm.Groups[hash] = &ProviderGroup{GroupHash: hash, Zones: []ZoneName{"cell.example."}}
	pgm.mu.Unlock()
	expiry := time.Now().Add(time.Hour)

	// a peer leads: nothing to ask
	lem.ApplyGossipElection(hash, GroupElectionState{Leader: "agent.p2.example.", Term: 1, LeaderExpiry: expiry})
	select {
	case z := <-asked:
		t.Fatalf("a peer's leadership made this agent ask for %s", z)
	case <-time.After(50 * time.Millisecond):
	}
	// we lead, says the gossip, in a term we know nothing of: asked once
	lem.ApplyGossipElection(hash, GroupElectionState{Leader: "agent.us.example.", Term: 2, LeaderExpiry: expiry})
	select {
	case z := <-asked:
		if z != "cell.example." {
			t.Errorf("asked for %s", z)
		}
	case <-time.After(time.Second):
		t.Fatal("leadership learnt from gossip asked for nothing")
	}
	// the same word again is no news
	lem.ApplyGossipElection(hash, GroupElectionState{Leader: "agent.us.example.", Term: 2, LeaderExpiry: expiry})
	select {
	case z := <-asked:
		t.Errorf("the same term again asked for %s once more", z)
	case <-time.After(50 * time.Millisecond):
	}
}

// An agent that has just started asks its signer for the inventory, and the
// answer comes back on the request's own channel, not the engine's. It must
// feed the same things a pushed inventory feeds: before, the agent had no DS
// set after a restart, and the sync an election asks for then found no
// opinion about the DS and called the parent in sync.
func TestAnInventoryTheAgentAskedForFeedsTheDSSetToo(t *testing.T) {
	yes, no := true, false
	r := newLeaderSyncRig(t, "asked.sync.example.")
	z := r.mpzd.ZoneName
	r.leader("agent.us.example.")
	tm := &MPTransportBridge{onKeyInventory: r.conf.noteKeyInventory} // as initMPAgent wires it
	owner := r.conf.InternalMp.KeyLifecycleOwner
	if in, _ := owner.DSIntent(r.mpzd.ZoneData, dns.SHA256); in.Known {
		t.Fatal("the DS set is known before any inventory came")
	}
	inv := &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: z, Owned: true,
		Inventory: []KeyInventoryItem{invItem(t, z, 257, KeyStateActive, &yes), invItem(t, z, 256, KeyStateActive, &no)}}
	r.mpzd.recordRequestedInventory(context.Background(), tm, inv)

	if in, err := owner.DSIntent(r.mpzd.ZoneData, dns.SHA256); err != nil || !in.Known || len(in.Set) != 1 {
		t.Errorf("the DS set after the requested inventory: known=%v set=%d err=%v, want the one KSK", in.Known, len(in.Set), err)
	}
	if snap := r.mpzd.GetLastKeyInventory(); snap == nil || !snap.Owned {
		t.Errorf("the snapshot lost its Owned mark: %+v", snap)
	}
	if n := r.requests(t); n != 1 {
		t.Errorf("the first inventory after a start: %d sync requests, want 1", n)
	}
	// the same inventory again, as at the next refresh: nothing to ask
	r.mpzd.recordRequestedInventory(context.Background(), tm, inv)
	if n := r.requests(t); n != 0 {
		t.Errorf("an unchanged DS set asked for %d syncs", n)
	}
	// a role with no owner keeps the snapshot, with the mark
	other := signerTestZone(t, "plain.sync.example.", newMPTestKeyDB(t))
	other.recordRequestedInventory(context.Background(), &MPTransportBridge{}, &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: other.ZoneName, Owned: true})
	if snap := other.GetLastKeyInventory(); snap == nil || !snap.Owned {
		t.Errorf("without the hook the snapshot is %+v, want it kept with its Owned mark", snap)
	}
}
