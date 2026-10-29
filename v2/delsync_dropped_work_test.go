package tdnsmp

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// tdns-mp #267 item 3: delegation-sync work that was dropped. A request that
// found the syncher's queue full was given up after five tries (#220), a
// failed sync of a refresh was dropped (#247), a KEYSTATE inventory that
// found the data engine's queue full was dropped (#210), and the combiner's
// ns-changed hint could sync before the agent's copy had the change (#248).

// fillSyncQueue fills the rig's delegation sync queue, which nobody reads.
func fillSyncQueue(r *leaderSyncRig) {
	for range cap(r.q) - len(r.q) {
		r.q <- tdns.DelegationSyncRequest{Command: "SYNC-DNSKEY-RRSET", ZoneName: r.mpzd.ZoneName}
	}
}

// #220: a request that finds the queue full is owed, and is not given up:
// the room ticker's pass brings it once there is room, however long the
// queue stayed full.
func TestARequestThatFindsTheQueueFullIsOwedNotGivenUp(t *testing.T) {
	shortRetries(t, time.Millisecond, 1) // the old bound, quick: it must not apply
	r, tr := owedRig(t, "owed.full.example.", true)
	z := ZoneName(r.mpzd.ZoneName)
	fillSyncQueue(r)
	if !r.conf.requestDelegationSync(r.ctx, string(z), "test") {
		t.Fatal("a request that found the queue full is neither queued nor owed")
	}
	time.Sleep(50 * time.Millisecond) // well past the old bound
	if owed, room := tr.owedState(z); !owed || !room {
		t.Fatalf("after the old bound: owed=%v room=%v, want both", owed, room)
	}
	for len(r.q) > 0 {
		<-r.q
	}
	tr.askAllOwed(r.ctx, true)
	if owed, _ := tr.owedState(z); owed {
		t.Error("the sync is still owed after there was room")
	}
	if n := r.requests(t); n != 1 {
		t.Errorf("%d explicit syncs once there was room, want 1", n)
	}
}

// #220: the chain's own ask that finds the queue full keeps the chain, so
// that the sync it brings counts on from the chain's failures.
func TestAChainsAskThatFindsTheQueueFullKeepsTheChain(t *testing.T) {
	shortRetries(t, time.Millisecond, 1)
	r, tr := owedRig(t, "owed.chain.example.", true)
	z := r.mpzd.ZoneName
	fillSyncQueue(r)
	r.conf.delegationSyncFailedWith(r.ctx, z, errors.New("refused"), []time.Duration{10 * time.Millisecond, time.Hour})
	waitUntil(t, "the chain's ask is not owed", func() bool {
		owed, room := tr.owedState(ZoneName(z))
		return owed && room
	})
	c := &r.conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	ch := c.zones[z]
	failures := -1
	if ch != nil {
		failures = ch.failures
	}
	c.mu.Unlock()
	if failures != 1 {
		t.Errorf("the chain after its ask found the queue full: failures=%d, want 1 (no chain is -1)", failures)
	}
}

// #255 and #220: an election over more zones than the queue has room for.
// Every zone's sync goes out, once each, with no zone given up, and the
// zones that wait for room are told in one warning a pass, not one each.
func TestAnElectionBurstLargerThanTheQueueSyncsEveryZone(t *testing.T) {
	shortRetries(t, time.Hour, 5) // the old retry would not come within the test
	var buf lockedBuffer
	savedLg, savedEngine := lg, lgEngine
	lg, lgEngine = slog.New(slog.NewTextHandler(&buf, nil)), slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { lg, lgEngine = savedLg, savedEngine })

	r, tr := owedRig(t, "z00.burst.example.", true)
	zones := []string{r.mpzd.ZoneName}
	for i := 1; i < 12; i++ {
		zr := newLeaderSyncRig(t, fmt.Sprintf("z%02d.burst.example.", i))
		zr.mpzd.Ready = true
		zr.mpzd.DelegationSyncQ = r.q // one queue for every zone of the agent
		z := ZoneName(zr.mpzd.ZoneName)
		r.lem.mu.Lock()
		r.lem.elections[z] = &LeaderElection{Zone: z, Leader: usAgent, LeaderExpiry: time.Now().Add(time.Hour)}
		r.lem.mu.Unlock()
		tr.zdr.markOwnState(z, true, "")
		zones = append(zones, zr.mpzd.ZoneName)
	}
	for _, z := range zones {
		r.conf.requestDelegationSync(r.ctx, z, "this agent was elected the zone's delegation sync leader")
	}
	// the syncher takes three a pass, and the room ticker asks after each
	got := map[string]int{}
	take := func(n int) {
		for ; n > 0 && len(r.q) > 0; n-- {
			got[(<-r.q).ZoneName]++
		}
	}
	for pass := 0; pass < 10 && len(got) < len(zones); pass++ {
		take(3)
		tr.askAllOwed(r.ctx, true)
	}
	take(cap(r.q))
	for _, z := range zones {
		if got[z] != 1 {
			t.Errorf("%s: %d syncs, want 1", z, got[z])
		}
	}
	if n := strings.Count(buf.String(), "asking again shortly"); n != 0 {
		t.Errorf("%d warnings of a retry per zone, want none", n)
	}
	if n := strings.Count(buf.String(), "owed syncs wait for room"); n != 1 {
		t.Errorf("%d warnings of zones waiting for room, want 1 (the one pass that found the queue full)\n%s", n, buf.String())
	}
}

// refreshSync queues the sync that a refresh of the leader's copy asks for:
// the copy gained ns.
func refreshSync(t *testing.T, r *notifyRig, ns string) {
	t.Helper()
	z := r.mpzd.ZoneName
	changed, dss, err := implicitDelegationChange(r.mpzd, refreshedZone(t, r.mpzd, fmt.Sprintf("%s 3600 IN NS %s", z, ns)))
	if err != nil || !changed {
		t.Fatalf("the refresh: changed=%v err=%v", changed, err)
	}
	r.mpzd.EnsureMP()
	r.mpzd.MP.RefreshAnalysis = &ZoneRefreshAnalysis{DelegationChanged: changed, DelegationStatus: dss}
	r.mpzd.PostRefresh(nil, nil)
}

// failureDelays makes the failure backoff quick for a test, and restores
// it. Called before the rig, so that it is put back after the rig's engines
// have stopped.
func failureDelays(t *testing.T, d time.Duration) {
	t.Helper()
	saved := delegationSyncFailureDelays
	delegationSyncFailureDelays = repeat(d, 8)
	t.Cleanup(func() { delegationSyncFailureDelays = saved })
}

// updateRig is the notify rig for a zone whose parent takes UPDATEs, with
// the zone's SIG(0) key.
func updateRig(t *testing.T, zone string) *notifyRig {
	t.Helper()
	r := newNotifyRig(t, zone, "UPDATE", repeat(30*time.Millisecond, 400)...)
	if _, err := r.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: zone,
		Keyname: zone, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	trustActiveKeys(t, r.mpzd.KeyDB, zone)
	return r
}

// #247: the sync a refresh asks for, failed, is asked for again as the
// explicit arm's is, and reaches the parent once the parent takes it.
func TestAFailedSyncOfARefreshIsAskedAgain(t *testing.T) {
	failureDelays(t, 100*time.Millisecond)
	r := updateRig(t, "refresh.fails.example.")
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.parent.fails(dns.RcodeNotAuth)

	refreshSync(t, r, "ns2.provider.example.")
	r.logged(t, 1, "the delegation sync failed; asking again")
	r.parent.fails(0)
	if m := r.told(t, "the retry's UPDATE answered"); !strings.Contains(m.Msg, "SendUpdate(") {
		t.Errorf("the peer was told %+v", *m)
	}
	if n := r.parent.updatesSeen(); n < 2 {
		t.Errorf("the parent got %d UPDATEs, want the refresh's and the retry's", n)
	}
}

// #247: a zone that is not multi-provider, whose agents do not sync its
// delegation, is not asked for again: it has no leader's chain.
func TestAFailedRefreshSyncOfAZoneThatIsNotMultiProviderIsNotAskedAgain(t *testing.T) {
	failureDelays(t, 50*time.Millisecond)
	r := updateRig(t, "refresh.single.example.")
	r.mpzd.Options[tdns.OptMultiProvider] = false
	r.parent.fails(dns.RcodeNotAuth)
	refreshSync(t, r, "ns2.provider.example.")
	waitUntil(t, "the refresh's UPDATE did not reach the parent", func() bool { return r.parent.updatesSeen() > 0 })
	time.Sleep(300 * time.Millisecond) // six times the first delay
	if strings.Contains(r.log.String(), "asking again") {
		t.Error("the failed sync of a zone that is not multi-provider was asked for again")
	}
	if n := r.parent.updatesSeen(); n != 1 {
		t.Errorf("the parent got %d UPDATEs, want the one", n)
	}
}

// servedNS has the leader's copy serve the zone's NS set as ns, as a
// refresh that brought it leaves the copy.
func servedNS(t *testing.T, r *notifyRig, ns ...string) {
	t.Helper()
	z := r.mpzd.ZoneName
	apex, err := r.mpzd.OwnerForAnalysis(z)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	var rrs []dns.RR
	for _, n := range ns {
		rrs = append(rrs, &dns.NS{Hdr: dns.RR_Header{Name: z, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: n})
	}
	apex.RRtypes.Set(dns.TypeNS, core_RRset(rrs...))
	r.mpzd.ZoneData.InstallInitialSnapshot()
}

// #248: the combiner's ns-changed hint asks for nothing. The NS change that
// another provider's agent contributed (nsmgmt=agent) reaches this agent
// through its own copy, as the signer serves it: the refresh that brings it
// asks for the sync, and the parent follows.
func TestTheNSChangedHintAsksNothingAndTheRefreshSyncs(t *testing.T) {
	r := newNotifyRigWith(t, "hint.refresh.example.", "NOTIFY", false, func(r *notifyRig) {
		apex, err := r.mpzd.OwnerForAnalysis(r.mpzd.ZoneName)
		if err != nil || apex == nil {
			t.Fatalf("apex: %v", err)
		}
		rrset := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNCPARAM)
		hp := rrset.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM)
		hp.Value = append(hp.Value, &core.HSYNCPARAMNSmgmt{Value: core.HsyncNSmgmtAGENT})
		r.mpzd.ZoneData.InstallInitialSnapshot()
	}, repeat(50*time.Millisecond, 400)...)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1." + z) // in step with the copy as it is

	// the hint comes first, before the copy has the other provider's NS
	r.e.handleStatusUpdate(r.ctx, &StatusUpdateMsg{Zone: z, SubType: "ns-changed"})
	r.quiet(t, 200*time.Millisecond, "after the ns-changed hint")
	if strings.Contains(r.log.String(), "delegation sync requested") {
		t.Error("the ns-changed hint asked for a sync")
	}

	theirs := "ns." + shortLabel(r.peer.Identity) + ".example."
	refreshSync(t, r, theirs)
	servedNS(t, r, "ns1."+z, theirs)
	r.notified(t, "the refresh's sync", dns.TypeCSYNC)
	r.parent.holdsNS("ns1."+z, theirs)
	if m := r.told(t, "the parent in sync"); !strings.Contains(m.Msg, "after NOTIFY(CSYNC)") {
		t.Errorf("the peer was told %+v", *m)
	}
}

// keystateMsg is a signer's KEYSTATE inventory of zone, as it reaches the
// agent's transport.
func keystateMsg(t *testing.T, zone string, items []KeyInventoryItem, resend []uint16) *transport.IncomingMessage {
	t.Helper()
	msg, err := keystateAppMessage(inventoryRequest("signer.us.example.", zone, inventoryEntriesOf(items), true, resend, inventoryMarks{}), "agent.us.example.")
	if err != nil {
		t.Fatal(err)
	}
	return &transport.IncomingMessage{TypeToken: "keystate", Zone: zone, Payload: msg.Payload}
}

// engineReads is the data engine's reading of its inventory queue, until it
// is empty: an inventory from the queue, then what found the queue full.
func engineReads(q *MsgQs) []*KeystateInventoryMsg {
	var out []*KeystateInventoryMsg
	for {
		select {
		case m := <-q.KeystateInventory:
			out = append(out, m)
			out = append(out, q.takeWaitingInventories()...)
		default:
			return out
		}
	}
}

// #210: a burst of inventories larger than the queue loses none. What found
// the queue full is the newest inventory of each zone, with the keys that
// the replaced ones sent again, and each zone's inventories are handled in
// the order they came.
func TestABurstOfInventoriesLosesNone(t *testing.T) {
	agent := &MPTransportBridge{msgQs: &MsgQs{KeystateInventory: make(chan *KeystateInventoryMsg, 10)}}
	zone := func(i int) string { return fmt.Sprintf("z%02d.inventory.example.", i%12) }
	newest := map[string]uint16{}   // the key of each zone's newest inventory
	resent := map[string][]uint16{} // the keys sent again with the zone's inventories that found the queue full
	for i := range 25 {
		z := zone(i)
		k := invItem(t, z, 256, KeyStateActive, nil)
		newest[z] = k.KeyTag
		resend := []uint16{uint16(1000 + i)}
		if i >= 10 {
			resent[z] = append(resent[z], resend...)
		}
		agent.routeKeystateMessage(keystateMsg(t, z, []KeyInventoryItem{k}, resend))
	}
	got := engineReads(agent.msgQs)
	if len(got) != 22 { // 25, less the three that a newer one of the zone replaced
		t.Fatalf("%d inventories handled, want 22", len(got))
	}
	last := map[string]*KeystateInventoryMsg{}
	seen := map[string][]uint16{} // each zone's Resend tags, in the order handled
	for _, m := range got {
		last[m.Zone] = m
		seen[m.Zone] = append(seen[m.Zone], m.Resend...)
	}
	for i := range 12 {
		z := zone(i)
		m := last[z]
		if m == nil || len(m.Inventory) != 1 || m.Inventory[0].KeyTag != newest[z] {
			t.Errorf("%s: the last inventory handled is not the newest", z)
			continue
		}
		if !slices.Equal(m.Resend, resent[z]) {
			t.Errorf("%s: the inventory that waited sends again %v, want %v", z, m.Resend, resent[z])
		}
		if !slices.IsSorted(seen[z]) {
			t.Errorf("%s: handled out of order: %v", z, seen[z])
		}
	}
}

// #210: the DNSKEY half. The inventory that waited goes through the same
// handler, so the other providers get this provider's newest key set.
func TestTheNewestInventoryCarriesTheDnskeysToThePeers(t *testing.T) {
	r := newLeaderSyncRig(t, "dnskeys.inventory.example.")
	z := r.mpzd.ZoneName
	q := &MsgQs{KeystateInventory: make(chan *KeystateInventoryMsg, 1)}
	agent := &MPTransportBridge{msgQs: q}
	k1, k2, k3 := invItem(t, z, 256, KeyStateActive, nil), invItem(t, z, 256, KeyStateActive, nil), invItem(t, z, 256, KeyStateActive, nil)
	agent.routeKeystateMessage(keystateMsg(t, z, []KeyInventoryItem{k1}, nil))         // queued
	agent.routeKeystateMessage(keystateMsg(t, z, []KeyInventoryItem{k1, k2}, nil))     // waits
	agent.routeKeystateMessage(keystateMsg(t, z, []KeyInventoryItem{k1, k2, k3}, nil)) // replaces it
	for _, m := range engineReads(q) {
		r.e.handleKeystateInventory(r.ctx, "agent.us.example.", m, r.sdq, q)
	}
	var sent []string
	for len(r.sdq) > 0 {
		u := <-r.sdq
		for _, op := range u.Update.Operations {
			if op.RRtype == "DNSKEY" && op.Operation == "replace" {
				sent = op.Records
			}
		}
	}
	tags := map[uint16]bool{}
	for _, s := range sent {
		if rr, err := dns.NewRR(s); err == nil {
			tags[rr.(*dns.DNSKEY).KeyTag()] = true
		}
	}
	if len(tags) != 3 || !tags[k1.KeyTag] || !tags[k2.KeyTag] || !tags[k3.KeyTag] {
		t.Errorf("the last key set sent to the peers: %v, want the newest inventory's three keys", sent)
	}
}

// #210: an RFI requester that has its answer already does not drop a newer
// inventory: it goes to the agent's handler.
func TestAFullRFIWaiterDoesNotDropTheNewerInventory(t *testing.T) {
	const zone = "rfi.inventory.example."
	agent := &MPTransportBridge{msgQs: &MsgQs{KeystateInventory: make(chan *KeystateInventoryMsg, 1)}}
	waiter := make(chan *KeystateInventoryMsg, 1)
	agent.setKeystateRfi(zone, waiter)
	older, newer := invItem(t, zone, 256, KeyStateActive, nil), invItem(t, zone, 256, KeyStateActive, nil)
	agent.routeKeystateMessage(keystateMsg(t, zone, []KeyInventoryItem{older}, nil))
	agent.routeKeystateMessage(keystateMsg(t, zone, []KeyInventoryItem{newer}, nil))
	if m, ok := recvWithin(waiter, time.Second); !ok || m.Inventory[0].KeyTag != older.KeyTag {
		t.Error("the RFI waiter did not get the first inventory")
	}
	if m, ok := recvWithin(agent.msgQs.KeystateInventory, time.Second); !ok || m.Inventory[0].KeyTag != newer.KeyTag {
		t.Error("the newer inventory did not reach the agent's handler")
	}
}

// #210, CodeRabbit on #274: an RFI requester that has its answer holds an
// older inventory while a newer push goes to the engine. The own read hands
// the older one on afterwards: it is not recorded over the newer one, and
// the peers are not sent its key set.
func TestAnRFIAnswerOlderThanAPushIsNotRecordedOverIt(t *testing.T) {
	r := newLeaderSyncRig(t, "rfi.order.example.")
	z := r.mpzd.ZoneName
	q := &MsgQs{KeystateInventory: make(chan *KeystateInventoryMsg, 4)}
	agent := &MPTransportBridge{msgQs: q}
	waiter := make(chan *KeystateInventoryMsg, 1)
	agent.setKeystateRfi(z, waiter)
	k1, k2 := invItem(t, z, 256, KeyStateActive, nil), invItem(t, z, 256, KeyStateActive, nil)
	agent.routeKeystateMessage(keystateMsg(t, z, []KeyInventoryItem{k1}, nil))     // the RFI's answer
	agent.routeKeystateMessage(keystateMsg(t, z, []KeyInventoryItem{k1, k2}, nil)) // a newer push
	older, ok := recvWithin(waiter, time.Second)
	if !ok {
		t.Fatal("the RFI waiter got no answer")
	}
	for _, m := range engineReads(q) {
		r.e.handleKeystateInventory(r.ctx, "agent.us.example.", m, r.sdq, q)
	}
	for len(r.sdq) > 0 {
		<-r.sdq
	}
	r.e.handleKeystateInventory(r.ctx, "agent.us.example.", older, r.sdq, q) // as the own read hands it on
	if snap := r.mpzd.GetLastKeyInventory(); snap == nil || len(snap.Inventory) != 2 {
		t.Errorf("the recorded inventory after the older answer: %+v, want the newer push's two keys", snap)
	}
	if n := len(r.sdq); n != 0 {
		t.Errorf("the older answer sent %d updates to the peers, want none", n)
	}
}

// #274's review, S1: a failed sync that syncDelegation has asked again for
// itself (a NOTIFY it did not send on) is not asked again by the syncher's
// arm. The failures run to the bound, and the zone stays given up: asked
// twice, the failure that gives the zone up ends its chain, and the second
// ask starts a new one at the first failure.
func TestAGiveUpHoldsWhenTheSyncAskedAgainItself(t *testing.T) {
	failureDelays(t, 10*time.Millisecond)
	r := newLeaderSyncRig(t, "giveup.holds.example.")
	r.leader(usAgent)
	z := r.mpzd.ZoneName
	ds := tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: z, ZoneData: r.mpzd.ZoneData}
	cause := errors.New("a provider rejected the zone's CSYNC")
	chained := func() bool {
		c := &r.conf.InternalMp.delegationSyncChains
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.zones[z] != nil
	}
	for i := 0; ; i++ {
		// what syncDelegation does when the NOTIFY is not sent on, and then
		// what the arm does with the error it returns
		r.conf.delegationSyncFailed(r.ctx, z, cause)
		r.conf.leaderSyncFailed(r.ctx, ds, syncAskedAgain{cause})
		if i == len(delegationSyncFailureDelays) {
			break // the failure that reaches the bound
		}
		select {
		case <-r.q: // the chain's ask, taken as the syncher takes it
		case <-time.After(2 * time.Second):
			t.Fatalf("failure %d: the chain asked for nothing", i+1)
		}
	}
	if chained() {
		t.Error("the zone has a chain after its give-up")
	}
	select {
	case req := <-r.q:
		t.Errorf("asked again after the give-up: %+v", req)
	case <-time.After(200 * time.Millisecond):
	}
	// an UPDATE that failed is the arm's to ask again for: a new chain
	r.conf.leaderSyncFailed(r.ctx, ds, cause)
	if !chained() {
		t.Error("a failure syncDelegation did not ask again for started no chain")
	}
}

// CodeRabbit on #274 (6907110): two inventories of a zone recorded at once,
// by the engine and by a refresh-keys RFI. The older one, between its
// snapshot and the owner's copy, does not leave the owner its inventory
// once the newer one has been recorded.
func TestTwoInventoriesRecordedAtOnceLeaveTheOwnerTheNewer(t *testing.T) {
	r := newLeaderSyncRig(t, "inventory.race.example.")
	z := r.mpzd.ZoneName
	k1, k2 := invItem(t, z, 256, KeyStateActive, nil), invItem(t, z, 256, KeyStateActive, nil)
	older := &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: z, Inventory: []KeyInventoryItem{k1}, Owned: true, seq: 1}
	newer := &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: z, Inventory: []KeyInventoryItem{k1, k2}, Owned: true, seq: 2}
	inWindow, release := make(chan struct{}), make(chan struct{})
	inventoryRecordedHook = func(msg *KeystateInventoryMsg) {
		if msg == older {
			close(inWindow)
			<-release
		}
	}
	t.Cleanup(func() { inventoryRecordedHook = nil })
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() { r.conf.noteKeyInventory(r.ctx, r.mpzd, older); close(doneA) }()
	<-inWindow
	go func() { r.conf.noteKeyInventory(r.ctx, r.mpzd, newer); close(doneB) }()
	select {
	case <-doneB:
	case <-time.After(200 * time.Millisecond): // the newer one waits for the older
	}
	close(release)
	<-doneA
	<-doneB
	if inv := r.conf.InternalMp.KeyLifecycleOwner.inventoryOf(z); inv == nil || len(inv.Inventory) != 2 {
		t.Errorf("the owner's inventory: %+v, want the newer one's two keys", inv)
	}
	if snap := r.mpzd.GetLastKeyInventory(); snap == nil || len(snap.Inventory) != 2 {
		t.Errorf("the zone's snapshot: %+v, want the newer one's two keys", snap)
	}
}
