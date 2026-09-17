package tdnsmp

import (
	"context"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// Arrow 2's trigger (T5.4's leader half, T5.8): a DS set that changes with
// nothing else changing reaches the parent through the leader's explicit
// delegation sync; a non-leader asks for nothing; a new leader asks once
// when it is elected.

type leaderSyncRig struct {
	conf *Config
	e    *HsyncDataEngine
	mpzd *MPZoneData
	q    chan tdns.DelegationSyncRequest
	lem  *LeaderElectionManager
	sdq  chan *SynchedDataUpdate
}

func newLeaderSyncRig(t *testing.T, zone string) *leaderSyncRig {
	t.Helper()
	mpzd := signerTestZone(t, zone, newMPTestKeyDB(t))
	q := make(chan tdns.DelegationSyncRequest, 8)
	mpzd.DelegationSyncQ = q
	mpzd.Options[tdns.OptParentSync] = true
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: "agent.us.example."})
	conf.InternalMp.KeyLifecycleOwner = NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return nil })
	conf.InternalMp.AgentRegistry = &AgentRegistry{}
	lem := NewLeaderElectionManager("agent.us.example.", time.Minute, func(ZoneName, string, map[string][]string) error { return nil })
	conf.InternalMp.LeaderElectionManager = lem
	return &leaderSyncRig{conf: conf, e: &HsyncDataEngine{conf: conf}, mpzd: mpzd, q: q, lem: lem, sdq: make(chan *SynchedDataUpdate, 8)}
}

func (r *leaderSyncRig) leader(who AgentId) {
	r.lem.mu.Lock()
	r.lem.elections[ZoneName(r.mpzd.ZoneName)] = &LeaderElection{Zone: ZoneName(r.mpzd.ZoneName), Leader: who, LeaderExpiry: time.Now().Add(time.Hour)}
	r.lem.mu.Unlock()
}

func (r *leaderSyncRig) inventory(items ...KeyInventoryItem) {
	r.e.handleKeystateInventory(context.Background(), "agent.us.example.", &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: r.mpzd.ZoneName, Inventory: items, Owned: true}, r.sdq, nil)
}

func (r *leaderSyncRig) requests(t *testing.T) int {
	t.Helper()
	n := 0
	for {
		select {
		case req := <-r.q:
			if req.Command != "EXPLICIT-SYNC-DELEGATION" || req.ZoneName != r.mpzd.ZoneName || req.ZoneData != r.mpzd.ZoneData {
				t.Errorf("an unexpected request on the delegation sync queue: %+v", req)
			}
			n++
		default:
			return n
		}
	}
}

func TestADSSetChangeAsksTheLeaderToSyncTheParent(t *testing.T) {
	yes, no := true, false
	r := newLeaderSyncRig(t, "dsset.sync.example.")
	z := r.mpzd.ZoneName
	ksk := invItem(t, z, 257, KeyStateActive, &yes)
	zsk := invItem(t, z, 256, KeyStateActive, &no)
	next := invItem(t, z, 257, KeyStatePublished, &no)
	theirs := invItem(t, z, 257, DnskeyStateForeign, nil)

	// we lead. The first inventory with a known DS set asks for a sync:
	// unknown before (nothing heard from the signer), known now
	r.leader("agent.us.example.")
	r.inventory(ksk, zsk, next)
	if n := r.requests(t); n != 1 {
		t.Fatalf("the first known DS set: %d sync requests, want 1", n)
	}
	// the same inventory again: nothing changed, nothing asked
	r.inventory(ksk, zsk, next)
	if n := r.requests(t); n != 0 {
		t.Errorf("an unchanged DS set asked for %d syncs", n)
	}
	// the published KSK becomes standby: ds 0 -> 1 with the DNSKEY set as
	// it was. This is the change that reached no UPDATE before.
	next.State, next.DS = KeyStateStandby, &yes
	r.inventory(ksk, zsk, next)
	if n := r.requests(t); n != 1 {
		t.Errorf("a ds-only change: %d sync requests, want 1", n)
	}
	// a ZSK's state changes: not the DS set's business
	zsk.State = KeyStateRetired
	r.inventory(ksk, zsk, next)
	if n := r.requests(t); n != 0 {
		t.Errorf("a ZSK's change asked for %d syncs", n)
	}
	// another provider's KSK appears with its ds undecided: the DS set is
	// unknown, and an unknown set asks for nothing (the sync would leave
	// the parent alone anyway)
	r.inventory(ksk, zsk, next, theirs)
	if n := r.requests(t); n != 0 {
		t.Errorf("an unknown DS set asked for %d syncs", n)
	}
	// its provider says: the set is known again, and larger
	theirs.DS = &yes
	r.inventory(ksk, zsk, next, theirs)
	if n := r.requests(t); n != 1 {
		t.Errorf("the other provider's word arriving: %d sync requests, want 1", n)
	}
	// a DS withdrawn (the retired KSK's ds 1 -> 0)
	ksk.State, ksk.DS = KeyStateRetired, &no
	r.inventory(ksk, zsk, next, theirs)
	if n := r.requests(t); n != 1 {
		t.Errorf("a withdrawn DS: %d sync requests, want 1", n)
	}
}

// Only the leader sends (T5.4), and a hand-over neither loses an update
// nor repeats one (T5.8): the peer that does not lead asks for nothing
// when the DS set changes, and asks once when it becomes the leader; the
// explicit sync it asks for sends only a difference.
func TestOnlyTheLeaderAsksAndANewLeaderAsksOnce(t *testing.T) {
	yes, no := true, false
	r := newLeaderSyncRig(t, "handover.sync.example.")
	z := r.mpzd.ZoneName
	ksk := invItem(t, z, 257, KeyStateActive, &yes)
	next := invItem(t, z, 257, KeyStatePublished, &no)

	// nobody elected yet, then somebody else: we ask for nothing
	r.inventory(ksk, next)
	r.leader("agent.p2.example.")
	next.State, next.DS = KeyStateStandby, &yes
	r.inventory(ksk, next)
	if n := r.requests(t); n != 0 {
		t.Fatalf("a peer that does not lead asked for %d syncs", n)
	}
	if r.conf.requestDelegationSync(z, "test") {
		t.Error("a request was queued by a peer that does not lead")
	}
	// the leadership comes to us: what the election callback asks for
	r.leader("agent.us.example.")
	if !r.conf.requestDelegationSync(z, "this agent was elected the zone's delegation sync leader") {
		t.Fatal("the new leader's request was not queued")
	}
	if n := r.requests(t); n != 1 {
		t.Errorf("the new leader: %d sync requests, want 1", n)
	}
	// a zone with no queue, or one that is not here, asks for nothing and
	// does not block
	r.mpzd.DelegationSyncQ = nil
	if r.conf.requestDelegationSync(z, "test") || r.conf.requestDelegationSync("absent.sync.example.", "test") {
		t.Error("a request was reported queued with nowhere to queue it")
	}
}

// The queue is the syncher's; a full one must not stop the engine's loop.
func TestAFullSyncQueueDoesNotBlockTheEngine(t *testing.T) {
	r := newLeaderSyncRig(t, "full.sync.example.")
	r.leader("agent.us.example.")
	r.mpzd.DelegationSyncQ = make(chan tdns.DelegationSyncRequest) // nobody reads
	done := make(chan bool, 1)
	go func() { done <- r.conf.requestDelegationSync(r.mpzd.ZoneName, "test") }()
	select {
	case queued := <-done:
		if queued {
			t.Error("a request was reported queued on a queue nobody reads")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request blocked on a full queue")
	}
}
