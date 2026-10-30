/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A CSYNC or the leader's KEY that comes before this agent knows the zone's
 * leader (plan S15), on the receiving rig: the peer sends over the wire to
 * the agent under test, which keeps the update whole and answers PENDING,
 * and judges it once it knows the leader.
 */
package tdnsmp

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const keptNoLeader = keptPrefix + " no leader of the zone is known here yet"

// leaderRig is the receiving rig whose agent keeps lists and knows no
// leader of the zone. As an observer it is a member with no role: the
// store's active reading lists the peer alone in servers= and signers=.
func leaderRig(t *testing.T, zone string, observer bool) *notifyRig {
	t.Helper()
	r, in := serialsRig(t, zone, false)
	if observer {
		c := *in[41]
		label := shortLabel(r.peer.Identity)
		c.Servers, c.Signers = []string{label}, []string{label}
		activeAs(t, r.conf.InternalMp.Instructions, zone, &c)
		withStore(t, r.conf.InternalMp.Instructions)
		if votesInZone(ZoneName(zone), AgentId(r.us.Identity)) {
			t.Fatal("setup: the observer votes")
		}
	}
	r.leaderUntil("", time.Time{})
	return r
}

// leaderUntil has the agent know who as the zone's leader, its lease until;
// with who empty, no leader.
func (r *notifyRig) leaderUntil(who AgentId, until time.Time) {
	zone := ZoneName(r.mpzd.ZoneName)
	r.lem.mu.Lock()
	defer r.lem.mu.Unlock()
	if who == "" {
		delete(r.lem.elections, zone)
		return
	}
	r.lem.elections[zone] = &LeaderElection{Zone: zone, Leader: who, LeaderExpiry: until}
}

// learns has the agent know who as the zone's leader, and judge what it
// keeps for it, as an election that names a leader has it do.
func (r *notifyRig) learns(who AgentId) {
	r.leaderUntil(who, time.Now().Add(time.Hour))
	r.conf.askLeaderWaits()
}

// keptForLeader waits until the zone's kept list holds n entries kept for
// the zone's leader, and returns them.
func (r *notifyRig) keptForLeader(t *testing.T, n int) []keptEntry {
	t.Helper()
	var got []keptEntry
	waitUntil(t, "the entries kept for the leader", func() bool {
		got = nil
		for _, e := range r.conf.InternalMp.Kept.entries(r.mpzd.ZoneName, listKept) {
			if e.Update.ForLeader {
				got = append(got, e)
			}
		}
		return len(got) == n
	})
	return got
}

// heldCsync waits until the agent's repo holds the peer's CSYNC rec.
func (r *notifyRig) heldCsync(t *testing.T, rec string) TrackedRRInfo {
	t.Helper()
	var held TrackedRRInfo
	waitUntil(t, "the peer's CSYNC "+rec+" in the agent's repo", func() bool {
		got := r.repo(t)[AgentId(r.peer.Identity)][dns.TypeCSYNC]
		if len(got) == 1 && got[0].RR == rec {
			held = got[0]
			return true
		}
		return false
	})
	return held
}

// The agent knows no leader of the zone yet: a CSYNC is kept, whole, and
// its sender told in a PENDING. Nothing of it reaches the repo.
func TestAMemberThatKnowsNoLeaderYetKeepsTheCSYNC(t *testing.T) {
	r := leaderRig(t, "noleader.csync.kept.example.", false)
	op, _ := csyncOp(r.mpzd.ZoneName, 1000)
	distID := r.receives(t, r.peer.Identity, r.peer.Identity, op)
	r.pendingSays(t, distID, keptNoLeader)
	if e := r.keptForLeader(t, 1); e[0].Distribution != distID || e[0].Update.Leader != "" {
		t.Errorf("the entry kept: %+v", e[0])
	}
	if got := r.repo(t)[AgentId(r.peer.Identity)][dns.TypeCSYNC]; len(got) != 0 {
		t.Errorf("a kept CSYNC reached the repo: %+v", got)
	}
}

// The kept CSYNC is judged once the agent learns the leader: from the
// sender, it is taken, handed to the combiner, and the sender gets the
// final confirmation.
func TestTheKeptCSYNCIsJudgedWhenTheLeaderIsLearned(t *testing.T) {
	r := leaderRig(t, "learned.csync.kept.example.", false)
	op, rec := csyncOp(r.mpzd.ZoneName, 1000)
	distID := r.receives(t, r.peer.Identity, r.peer.Identity, op)
	r.pendingSays(t, distID, keptNoLeader)
	r.learns(AgentId(r.peer.Identity))
	held := r.heldCsync(t, rec)
	r.confirms(rigCombiner, held.DistributionID, rec)
	if c := r.answered(t, distID); c.Status != "SUCCESS" || !slices.Equal(c.AppliedRecords, []string{rec}) {
		t.Errorf("the leader got the final confirmation %+v", *c)
	}
	r.keptForLeader(t, 0)
}

// The leader's KEY, with its publish instruction, is kept the same way, and
// taken once the agent learns that the sender leads.
func TestAMemberThatKnowsNoLeaderYetKeepsTheLeadersKEY(t *testing.T) {
	r := leaderRig(t, "noleader.key.kept.example.", false)
	combiner := toCombiner(t)
	z := r.mpzd.ZoneName
	k := testSig0Key(t, newMPTestKeyDB(t), z)
	op := core.RROperation{Operation: "replace", RRtype: "KEY", Records: []string{k.key.String()}}
	publish := &core.PublishInstruction{KEYRRs: []string{k.key.String()}, Locations: []string{"at-apex"}}
	distID := r.receivesPublish(t, r.peer.Identity, r.peer.Identity, publish, op)
	r.pendingSays(t, distID, keptNoLeader)
	if e := r.keptForLeader(t, 1); e[0].Update.Publish == nil {
		t.Errorf("the KEY was kept without its publish instruction: %+v", e[0].Update)
	}
	r.learns(AgentId(r.peer.Identity))
	waitUntil(t, "the leader's KEY in the agent's repo", func() bool {
		return len(r.repo(t)[AgentId(r.peer.Identity)][dns.TypeKEY]) == 1
	})
	if got, ok := recvWithin(combiner, 5*time.Second); !ok || got == nil || !slices.Equal(got.Locations, publish.Locations) {
		t.Errorf("the leader's KEY went to the combiner with %+v (handed over %v)", got, ok)
	}
}

// An observer, a member with no role, keeps the leader it knows until that
// lease has run out: the new leader's CSYNC waits for that, also while the
// lease it knows is renewed, and is judged then. Here the leader it knows
// is still the old one, and the CSYNC is refused.
func TestAnObserverKeepsTheNewLeadersCSYNCUntilTheEarlierLeaseRunsOut(t *testing.T) {
	r := leaderRig(t, "observer.csync.kept.example.", true)
	const old = AgentId("old.leader.example.")
	lease := time.Now().Add(time.Second)
	r.leaderUntil(old, lease)
	op, rec := csyncOp(r.mpzd.ZoneName, 1000)
	distID := r.receives(t, r.peer.Identity, r.peer.Identity, op)
	if e := r.keptForLeader(t, 1); e[0].Update.Leader != old || !e[0].Update.LeaseUntil.Equal(lease) {
		t.Fatalf("the entry kept: %+v", e[0].Update)
	}
	r.leaderUntil(old, time.Now().Add(time.Hour)) // the lease known is renewed
	r.conf.askLeaderWaits()
	time.Sleep(200 * time.Millisecond)
	if n := len(r.keptForLeader(t, 1)); n != 1 || len(r.repo(t)[AgentId(r.peer.Identity)][dns.TypeCSYNC]) != 0 {
		t.Fatal("the CSYNC was judged before the earlier lease ran out")
	}
	time.Sleep(time.Until(lease) + 50*time.Millisecond)
	r.conf.askLeaderWaits()
	c := r.answered(t, distID)
	want := "a CSYNC is taken only from the zone's delegation sync leader: the sender is " + r.peer.Identity + ", the leader is " + string(old)
	if c.Status != "REJECTED" || len(c.RejectedItems) != 1 || c.RejectedItems[0].Record != rec || c.RejectedItems[0].Reason != want {
		t.Errorf("the sender got %+v, want the CSYNC refused for %q", *c, want)
	}
	r.keptForLeader(t, 0)
}

// An observer keeps the new leader's KEY as it keeps its CSYNC, and takes it
// once the leader it knows is the sender.
func TestAnObserverKeepsTheNewLeadersKEY(t *testing.T) {
	r := leaderRig(t, "observer.key.kept.example.", true)
	r.leaderUntil("old.leader.example.", time.Now().Add(time.Hour))
	z := r.mpzd.ZoneName
	k := testSig0Key(t, newMPTestKeyDB(t), z)
	op := core.RROperation{Operation: "replace", RRtype: "KEY", Records: []string{k.key.String()}}
	distID := r.receives(t, r.peer.Identity, r.peer.Identity, op)
	r.keptForLeader(t, 1)
	if !strings.Contains(r.log.String(), "distrib="+distID) {
		t.Errorf("the keeping of %s was not logged", distID)
	}
	r.learns(AgentId(r.peer.Identity))
	waitUntil(t, "the new leader's KEY in the observer's repo", func() bool {
		return len(r.repo(t)[AgentId(r.peer.Identity)][dns.TypeKEY]) == 1
	})
}

// An entry kept for the leader does not hold the zone's list: the peer's NS
// record that comes after it is taken at once. A later CSYNC waits behind
// it, also once a leader is known, and both are judged in their order.
func TestAnEntryKeptForTheLeaderDoesNotHoldTheZonesOtherDistributions(t *testing.T) {
	r := leaderRig(t, "behind.kept.example.", false)
	z := r.mpzd.ZoneName
	peer := AgentId(r.peer.Identity)
	first, _ := csyncOp(z, 1000)
	r.pendingSays(t, r.receives(t, string(peer), string(peer), first), keptNoLeader)

	ns := z + "\t3600\tIN\tNS\tns9.provider.example."
	r.receives(t, string(peer), string(peer), core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{ns}})
	waitUntil(t, "the NS record after the kept CSYNC in the repo", func() bool {
		got := r.repo(t)[peer][dns.TypeNS]
		return len(got) == 1 && got[0].RR == ns
	})

	r.leaderUntil(peer, time.Now().Add(time.Hour)) // known, not yet judged
	second, rec := csyncOp(z, 1001)
	r.pendingSays(t, r.receives(t, string(peer), string(peer), second), keptPrefix+" an earlier CSYNC or KEY of the zone is kept for its leader")
	r.keptForLeader(t, 2)
	r.conf.askLeaderWaits()
	r.heldCsync(t, rec)
	r.keptForLeader(t, 0)
}

// A catch-up answer that carries the leader's CSYNC is kept whole while no
// leader is known: its NS records wait with it, and both are taken once the
// leader is learned.
func TestACatchUpAnswerWithTheLeadersCSYNCIsKeptWhole(t *testing.T) {
	r := leaderRig(t, "catchup.kept.example.", false)
	z := r.mpzd.ZoneName
	peer := r.peer.Identity
	op, rec := csyncOp(z, 1000)
	ns := z + "\t3600\tIN\tNS\tns9.provider.example."
	yes := true
	distID := nextDistributionID()
	body, err := json.Marshal(DnsSyncPayload{MessageType: "sync", OriginatorID: peer, YourIdentity: r.us.Identity, Zone: z,
		Operations: []core.RROperation{{Operation: "replace", RRtype: "NS", Records: []string{ns}}, op},
		CatchUp:    &CatchUp{Request: "q-kept", Complete: &yes},
		Time:       time.Now().Format(time.RFC3339Nano), Timestamp: time.Now().Unix(), DistributionID: distID})
	if err != nil {
		t.Fatal(err)
	}
	r.us.Bridge.routeIncomingMessage(&transport.IncomingMessage{TypeToken: "sync", DistributionID: distID, SenderID: peer,
		TransportSender: peer, Mechanism: transport.MechanismDNS, Zone: z, Payload: body, ReceivedAt: time.Now(), SourceAddr: "127.0.0.1:0"})
	amp, ok := recvMsgWithin(t, r.us.MsgQs.Msg, 10*time.Second)
	if !ok {
		t.Fatal("the transport did not queue the answer")
	}
	r.us.Registry.MsgHandler(amp, r.us.MsgQs.SynchedDataUpdate, r.us.MsgQs.SynchedDataCmd)
	r.pendingSays(t, distID, keptNoLeader)
	if e := r.keptForLeader(t, 1); e[0].Update.CatchUp == nil || len(e[0].Update.Operations) != 2 {
		t.Errorf("the answer was not kept whole: %+v", e[0].Update)
	}
	if got := r.repo(t)[AgentId(peer)][dns.TypeNS]; len(got) != 0 {
		t.Errorf("the NS record of a kept answer reached the repo: %+v", got)
	}
	r.learns(AgentId(peer))
	r.heldCsync(t, rec)
	waitUntil(t, "the answer's NS record in the repo", func() bool {
		got := r.repo(t)[AgentId(peer)][dns.TypeNS]
		return len(got) == 1 && got[0].RR == ns
	})
}
