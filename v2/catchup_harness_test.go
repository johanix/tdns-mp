/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"io"
	"log"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// catchUpNet is two agents on the loopback, each listening for the other
// over DNS with its message router running: alice, the real agent with its
// data engine, its message handler and its reliable queue's worker, and bob,
// a stand-in whose queue's worker runs too. alice serves the zone as a
// server, bob as its signer.
type catchUpNet struct {
	env   *integEnv
	conf  *Config
	zone  ZoneName
	alice string
	bob   string
	wg    sync.WaitGroup
}

func newCatchUpNet(t *testing.T, zone string) *catchUpNet {
	t.Helper()
	return newCatchUpNetAs(t, zone, false)
}

// newCatchUpNetAs is newCatchUpNet, or with noRole the rig in which alice is
// a member with no role: the zone's HSYNCPARAM names bob alone, and no peer
// is authorized by configuration, so each side admits the other by the
// zone's records (isInHSYNC).
func newCatchUpNetAs(t *testing.T, zone string, noRole bool) *catchUpNet {
	t.Helper()
	asMPAgent(t)
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: !noRole, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	n := &catchUpNet{env: env, zone: ZoneName(zone), alice: dns.Fqdn(env.Alice.Identity), bob: dns.Fqdn(env.Bob.Identity)}

	zd := seedZoneWithHSYNC3(t, zone, n.alice, n.bob)
	zd.Logger = log.New(io.Discard, "", 0)
	zd.Options[tdns.OptMultiProvider] = true
	apex, _ := zd.GetOwner(zd.ZoneName)
	servers := []string{shortLabel(n.alice), shortLabel(n.bob)}
	if noRole {
		servers = []string{shortLabel(n.bob)}
	}
	hp := numbered(&core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{
		&core.HSYNCPARAMServers{Servers: servers},
		&core.HSYNCPARAMSigners{Signers: []string{shortLabel(n.bob)}},
	}})
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{
		Hdr: dns.RR_Header{Name: zone, Rrtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, Ttl: 3600}, Data: hp}}})
	zd.Data.Set(zone, *apex)
	zd.InstallInitialSnapshot()
	Zones.Invalidate(zone)
	mpzd, _ := Zones.Get(zone)
	mpzd.EnsureMP()
	mpzd.MP.MPdata = &MPdata{WeAreProvider: true, OurLabel: shortLabel(n.alice)}

	// each listens, and knows the other: in its registry, with an address,
	// its DNS mechanism handshaked (the queue's worker sends only then)
	ctx, stop := context.WithCancel(env.ctx)
	for _, p := range []struct{ me, them *peerEnv }{{env.Alice, env.Bob}, {env.Bob, env.Alice}} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p.me.Bridge.StartIncomingMessageRouter(ctx)
		serveDNS(t, ctx, ln, p.me)
		p.them.Registry.S.Set(AgentId(dns.Fqdn(p.me.Identity)), NewAgent(AgentId(dns.Fqdn(p.me.Identity))))
		peer := peerFromAddress(dns.Fqdn(p.me.Identity), ln.Addr().String())
		peer.SetMechanismState(transport.MechanismDNS, transport.PeerStateOperational, "test: as after a completed handshake")
		if err := p.them.Bridge.PeerRegistry.Add(peer); err != nil {
			t.Fatal(err)
		}
	}

	// the reliable queues' workers: started on a context that has ended,
	// which only sets the send function, and run here in the wait group
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	for _, p := range []*peerEnv{env.Alice, env.Bob} {
		p.Bridge.StartReliableQueue(done)
		q := p.Bridge.ReliableQueue
		n.wg.Add(1)
		go func() { defer n.wg.Done(); q.Start(ctx) }()
	}

	// alice: the data engine, with its own state read from a combiner that
	// says its contributions are loaded, and the message handler's loop
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: n.alice, Combiner: &PeerConf{Identity: "combiner.alice.example."}})
	conf.InternalMp.MPTransport = env.Alice.Bridge
	conf.InternalMp.AgentRegistry = env.Alice.Registry
	conf.InternalMp.MPZoneNames = []string{zone}
	env.Alice.Bridge.combinerID = "combiner.alice.example."
	conf.InternalMp.editsRequest = func(context.Context, *tdns.ZoneData, *MPTransportBridge, *MsgQs) (*EditsResponseMsg, time.Time, error) {
		return &EditsResponseMsg{SenderID: "combiner.alice.example.", Zone: zone, Message: editsLoaded}, time.Now(), nil
	}
	msgQs := env.Alice.MsgQs
	msgQs.SynchedDataUpdate = make(chan *SynchedDataUpdate, 16)
	msgQs.SynchedDataCmd = make(chan *SynchedDataCmd, 16)
	conf.InternalMp.MsgQs = msgQs
	n.conf = conf
	n.wg.Add(2)
	go func() { defer n.wg.Done(); conf.SynchedDataEngine(ctx, msgQs) }()
	go func() {
		defer n.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-msgQs.Msg:
				env.Alice.Registry.MsgHandler(m, msgQs.SynchedDataUpdate, msgQs.SynchedDataCmd)
			}
		}
	}()
	t.Cleanup(func() {
		stop()
		ended := make(chan struct{})
		go func() { n.wg.Wait(); conf.InternalMp.ownReads.Wait(); close(ended) }()
		select {
		case <-ended:
		case <-time.After(10 * time.Second):
			t.Error("the harness's goroutines did not end with the test")
		}
	})
	return n
}

// queued is the distribution IDs a peer's queue holds for recipient.
func queued(p *peerEnv, recipient string) []string {
	var ids []string
	for _, m := range p.Bridge.ReliableQueue.GetPendingMessages() {
		if m.RecipientID == recipient {
			ids = append(ids, m.DistributionID)
		}
	}
	return ids
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
	}
}

// A request for the zone's state and its answer, over the wire, both ways.
//
// alice asks: bob's complete answer, which names bob's keys, reaches alice's
// data engine as a SYNC, makes bob speak, and alice's confirmation, over
// the wire, closes the entry in bob's queue.
//
// alice answers: a request from bob, over the wire, through alice's message
// handler, gets alice's complete answer, marked
// with the request's name, as a SYNC to bob alone, and bob's confirmation
// closes the entry in alice's queue.
func TestTransportBoundary_CatchUpRequestAndAnswer(t *testing.T) {
	n := newCatchUpNet(t, "catchup.harness.example.")
	yes := true

	// alice asks; bob answers
	key := testDnskey(t, string(n.zone), 257)
	zu := &ZoneUpdate{Zone: n.zone, AgentId: AgentId(n.bob), CatchUp: &CatchUp{Request: "q-alice", Complete: &yes},
		Operations: []core.RROperation{
			{Operation: "replace", RRtype: "NS", Records: []string{}},
			{Operation: "replace", RRtype: "CDS", Records: []string{}},
			{Operation: "replace", RRtype: "DNSKEY", Records: []string{key.String()},
				KeyStates: []core.KeyState{{KeyTag: key.KeyTag(), State: KeyStateActive, DS: &yes}}},
		}}
	distID := transport.GenerateDistributionID()
	if err := n.env.Bob.Bridge.EnqueueForSpecificAgent(n.zone, AgentId(n.alice), zu, distID); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "bob's answer did not make bob speak at alice", func() bool {
		tm := n.env.Alice.Bridge
		tm.foreignKeyStatesMu.Lock()
		defer tm.foreignKeyStatesMu.Unlock()
		return len(tm.foreignKeyStates[n.zone][AgentId(n.bob)]) == 1
	})
	// alice passes bob's answer on to its combiner, and confirms it to bob
	// once its combiner has: here the combiner's confirmation is handed to
	// alice's data engine, as the transport hands it
	var toCombiner []string
	waitUntil(t, "alice did not pass bob's answer on to its combiner", func() bool {
		toCombiner = queued(n.env.Alice, "combiner.alice.example.")
		return len(toCombiner) == 1
	})
	n.conf.InternalMp.MsgQs.Confirmation <- &ConfirmationDetail{DistributionID: toCombiner[0], Zone: n.zone,
		Source: "combiner.alice.example.", Status: "ok", Timestamp: time.Now()}
	waitUntil(t, "alice's confirmation did not close the entry in bob's queue", func() bool {
		return len(queued(n.env.Bob, n.alice)) == 0
	})

	// bob asks, over the wire; alice answers
	agent, _ := n.env.Bob.Registry.S.Get(AgentId(n.alice))
	if _, err := n.env.Bob.Registry.sendRfiToAgent(agent, &AgentMsgPost{MessageType: AgentMsgRfi, OriginatorID: AgentId(n.bob),
		YourIdentity: AgentId(n.alice), Zone: n.zone, RfiType: "SYNC", CatchUp: &CatchUp{Request: "q-bob", Reason: "start"}}); err != nil {
		t.Fatalf("bob's request: %v", err)
	}
	m, ok := recvMsgWithin(t, n.env.Bob.MsgQs.Msg, 10*time.Second)
	if !ok {
		t.Fatal("alice's answer did not reach bob")
	}
	if m.CatchUp == nil || m.CatchUp.Request != "q-bob" || !m.CatchUp.IsComplete() {
		t.Fatalf("bob got %+v as the answer's marker, want complete for q-bob", m.CatchUp)
	}
	var types []string
	for _, op := range m.Operations {
		types = append(types, op.RRtype)
	}
	if len(types) != 2 {
		t.Errorf("alice, a server, answered with %v, want NS and CDS", types)
	}
	ids := queued(n.env.Alice, n.bob)
	if len(ids) != 1 {
		t.Fatalf("alice's queue holds %v for bob, want the answer", ids)
	}
	n.env.Alice.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(ids[0], n.bob, transport.ConfirmSuccess, string(n.zone), nil, nil, nil, nil, false, ""))
	waitUntil(t, "bob's confirmation did not close the answer's entry in alice's queue", func() bool {
		return len(queued(n.env.Alice, n.bob)) == 0
	})
}

// The member with no role catches up (plan S15): alice, the real agent, has
// a record and no role, and bob, the stand-in, leads the zone. Each admits
// the other by the zone's records: alice's hello is accepted, where before
// the switch it was refused; bob's beats and gossip name the zone to alice,
// a member of its group with no role; and alice's request for the zone's
// state reaches bob, whose complete answer alice takes.
func TestTransportBoundary_MemberWithNoRoleCatchesUp(t *testing.T) {
	n := newCatchUpNetAs(t, "norole.catchup.harness.example.", true)
	if resp := postAPIHello(t, n.env.Bob, n.alice, string(n.zone)); resp.Error || resp.Status != "ok" {
		t.Fatalf("bob refuses the hello of alice, a member with no role: %+v", resp)
	}
	if zones := n.env.Bob.Registry.sharedParticipantZones(AgentId(n.alice)); !slices.Contains(zones, n.zone) {
		t.Errorf("bob's beats to alice name %v, not the zone", zones)
	}
	pgm := NewProviderGroupManager(n.bob)
	pgm.RecomputeGroups()
	if pg := pgm.GetGroupForZone(n.zone); pg == nil || !slices.Equal(pg.NoRole, []string{n.alice}) || !slices.Contains(pg.Members, n.alice) {
		t.Errorf("bob's group of the zone, whose gossip goes to its members: %+v", pg)
	}

	// alice asks, over the wire, and the request reaches bob
	agent, _ := n.env.Alice.Registry.S.Get(AgentId(n.bob))
	if _, err := n.env.Alice.Registry.sendRfiToAgent(agent, &AgentMsgPost{MessageType: AgentMsgRfi, OriginatorID: AgentId(n.alice),
		YourIdentity: AgentId(n.bob), Zone: n.zone, RfiType: "SYNC", CatchUp: &CatchUp{Request: "q-alice", Reason: catchUpJoin}}); err != nil {
		t.Fatalf("alice's request: %v", err)
	}
	m, ok := recvMsgWithin(t, n.env.Bob.MsgQs.Msg, 10*time.Second)
	if !ok || m.CatchUp == nil || m.CatchUp.Request != "q-alice" {
		t.Fatalf("alice's request did not reach bob: %+v", m)
	}

	// bob answers complete, and alice takes the answer
	yes := true
	key := testDnskey(t, string(n.zone), 257)
	zu := &ZoneUpdate{Zone: n.zone, AgentId: AgentId(n.bob), CatchUp: &CatchUp{Request: "q-alice", Complete: &yes},
		Operations: []core.RROperation{
			{Operation: "replace", RRtype: "NS", Records: []string{}},
			{Operation: "replace", RRtype: "CDS", Records: []string{}},
			{Operation: "replace", RRtype: "DNSKEY", Records: []string{key.String()},
				KeyStates: []core.KeyState{{KeyTag: key.KeyTag(), State: KeyStateActive, DS: &yes}}},
		}}
	if err := n.env.Bob.Bridge.EnqueueForSpecificAgent(n.zone, AgentId(n.alice), zu, transport.GenerateDistributionID()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "bob's answer did not make bob speak at alice", func() bool {
		tm := n.env.Alice.Bridge
		tm.foreignKeyStatesMu.Lock()
		defer tm.foreignKeyStatesMu.Unlock()
		return len(tm.foreignKeyStates[n.zone][AgentId(n.bob)]) == 1
	})
	var toCombiner []string
	waitUntil(t, "alice did not pass bob's answer on to its combiner", func() bool {
		toCombiner = queued(n.env.Alice, "combiner.alice.example.")
		return len(toCombiner) == 1
	})
	n.conf.InternalMp.MsgQs.Confirmation <- &ConfirmationDetail{DistributionID: toCombiner[0], Zone: n.zone,
		Source: "combiner.alice.example.", Status: "ok", Timestamp: time.Now()}
	waitUntil(t, "alice's confirmation did not close the entry in bob's queue", func() bool {
		return len(queued(n.env.Bob, n.alice)) == 0
	})
}
