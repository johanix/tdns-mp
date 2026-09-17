package tdnsmp

import (
	"context"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
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

// shortRetries makes the full-queue retry quick for a test, and restores it.
func shortRetries(t *testing.T, delay time.Duration, retries int) {
	t.Helper()
	d, n := delegationSyncRetryDelay, delegationSyncRetries
	delegationSyncRetryDelay, delegationSyncRetries = delay, retries
	t.Cleanup(func() { delegationSyncRetryDelay, delegationSyncRetries = d, n })
}

// The queue is the syncher's; a full one must not stop the engine's loop.
func TestAFullSyncQueueDoesNotBlockTheEngine(t *testing.T) {
	shortRetries(t, time.Millisecond, 1)
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

// The review's C2: a request that found the queue full is asked again
// shortly, a bounded number of times, so the last change in a burst is
// not left waiting for the next one.
func TestARequestThatFoundTheQueueFullIsAskedAgain(t *testing.T) {
	shortRetries(t, 20*time.Millisecond, 5)
	r := newLeaderSyncRig(t, "retry.sync.example.")
	r.leader("agent.us.example.")
	q := make(chan tdns.DelegationSyncRequest) // no room, and nobody reading yet
	r.mpzd.DelegationSyncQ = q
	if r.conf.requestDelegationSync(r.mpzd.ZoneName, "test") {
		t.Fatal("a request was reported queued on a queue with no room")
	}
	select {
	case req := <-q: // the syncher gets to it
		if req.Command != "EXPLICIT-SYNC-DELEGATION" || req.ZoneName != r.mpzd.ZoneName {
			t.Errorf("the retried request: %+v", req)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request was not asked again")
	}
	// the leadership moves away before the retry: nothing is asked for a
	// zone this agent no longer leads
	if r.conf.requestDelegationSync(r.mpzd.ZoneName, "test") {
		t.Fatal("queued with no room")
	}
	r.leader("agent.p2.example.")
	select {
	case req := <-q:
		t.Errorf("a retry asked for a zone this agent no longer leads: %+v", req)
	case <-time.After(200 * time.Millisecond):
	}
}

// The review's C1: both callers go through one gate. A zone that does not
// sync with its parent through its agents asks for nothing, from an
// inventory or at an election; nor does an inventory from a signer that
// does not run the zone's key lifecycle, whose DS set is not the syncher's.
func TestOnlyAParentsyncZoneWithAnOwningSignerAsks(t *testing.T) {
	yes := true
	r := newLeaderSyncRig(t, "gate.sync.example.")
	r.leader("agent.us.example.")
	ksk := invItem(t, r.mpzd.ZoneName, 257, KeyStateActive, &yes)

	r.mpzd.Options[tdns.OptParentSync] = false
	r.inventory(ksk)
	if r.conf.requestDelegationSync(r.mpzd.ZoneName, "this agent was elected") {
		t.Error("an election asked for a zone that does not sync with its parent through its agents")
	}
	if n := r.requests(t); n != 0 {
		t.Errorf("a zone without parentsync=agent asked for %d syncs", n)
	}

	r.mpzd.Options[tdns.OptParentSync] = true
	next := invItem(t, r.mpzd.ZoneName, 257, KeyStateStandby, &yes)
	r.e.handleKeystateInventory(context.Background(), "agent.us.example.", &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: r.mpzd.ZoneName, Inventory: []KeyInventoryItem{ksk, next}, Owned: false}, r.sdq, nil)
	if n := r.requests(t); n != 0 {
		t.Errorf("an inventory from a signer that does not own the zone's keys asked for %d syncs", n)
	}
	// the zone is taken: the same keys, now from an owning signer. The DS
	// set is the syncher's from here on, so this asks, with no key changed.
	r.inventory(ksk, next)
	if n := r.requests(t); n != 1 {
		t.Errorf("the take, every key as it was: %d sync requests, want 1", n)
	}
}

// The review's N1 and N2: the combiner's hint does not wait for room on
// the queue either; and a DS set is the same set whatever its TTLs say.
func TestCombinerHintDoesNotBlockAndTTLsAreNotTheDSSet(t *testing.T) {
	r := newLeaderSyncRig(t, "hint.sync.example.")
	r.leader("agent.us.example.")
	r.mpzd.DelegationSyncQ = make(chan tdns.DelegationSyncRequest) // nobody reads
	done := make(chan struct{})
	go func() {
		r.e.handleStatusUpdate(&StatusUpdateMsg{Zone: r.mpzd.ZoneName, SubType: "ksk-changed"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the combiner's hint blocked on a full queue")
	}

	k := testDnskey(t, r.mpzd.ZoneName, 257)
	a, b := k.ToDS(dns.SHA256), k.ToDS(dns.SHA256)
	b.Hdr.Ttl = a.Hdr.Ttl + 300
	if !sameDSIntent(tdns.DSIntent{Known: true, Set: []dns.RR{a}}, tdns.DSIntent{Known: true, Set: []dns.RR{b}}) {
		t.Error("a TTL alone made the DS set another set")
	}
	other := testDnskey(t, r.mpzd.ZoneName, 257).ToDS(dns.SHA256)
	if sameDSIntent(tdns.DSIntent{Known: true, Set: []dns.RR{a}}, tdns.DSIntent{Known: true, Set: []dns.RR{other}}) {
		t.Error("another key's DS is the same set")
	}
	if sameDSIntent(tdns.DSIntent{}, tdns.DSIntent{Known: true}) {
		t.Error("unknown and known-empty are the same")
	}
}
