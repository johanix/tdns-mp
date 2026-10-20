/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// restartNet is three agents on the loopback: alice, the real agent that
// restarts, with its data engine, its message handler, its reliable queue's
// worker and its catch-up tracker, and two stand-ins, bob and carol, each
// listening with its router and its queue's worker. All three serve the
// zone.
type restartNet struct {
	alice, bob, carol *peerEnv
	conf              *Config
	zone              ZoneName
	wg                sync.WaitGroup
}

func newRestartNet(t *testing.T, zone string) *restartNet {
	t.Helper()
	asMPAgent(t)
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	// the third peer, with its own authorization: the environment makes two
	carol := newPeer(t, "carol.agent.example.", "edns0", &integEnvConfig{ControlZoneIsIdentity: true,
		AuthorizedPeers: []string{env.Alice.Identity, env.Bob.Identity, "carol.agent.example."}})
	n := &restartNet{alice: env.Alice, bob: env.Bob, carol: carol, zone: ZoneName(zone)}

	zd := seedZoneWithHSYNC3(t, zone, n.alice.Identity, n.bob.Identity, carol.Identity)
	zd.Logger = log.New(io.Discard, "", 0)
	zd.Options[tdns.OptMultiProvider] = true
	addHSYNCPARAMServers(t, zd, shortLabel(n.alice.Identity), shortLabel(n.bob.Identity), shortLabel(carol.Identity))
	Zones.Invalidate(zone)
	mpzd, _ := Zones.Get(zone)
	mpzd.EnsureMP()
	mpzd.MP.MPdata = &MPdata{WeAreProvider: true, OurLabel: shortLabel(n.alice.Identity)}

	ctx, stop := context.WithCancel(env.ctx)
	// alice and each stand-in listen, and know each other
	for _, other := range []*peerEnv{n.bob, carol} {
		for _, p := range []struct{ me, them *peerEnv }{{n.alice, other}, {other, n.alice}} {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			serveDNS(t, ctx, ln, p.me)
			agent := NewAgent(AgentId(dns.Fqdn(p.me.Identity)))
			agent.DnsMethod = true
			p.them.Registry.S.Set(agent.ID, agent)
			peer := peerFromAddress(dns.Fqdn(p.me.Identity), ln.Addr().String())
			// alice has just restarted: she has said hello to each, and her
			// first beat makes it OPERATIONAL to her
			if p.them == n.alice {
				peer.SetMechanismState(transport.MechanismDNS, transport.PeerStateIntroducing, "test: said hello")
			} else {
				peer.SetMechanismState(transport.MechanismDNS, transport.PeerStateOperational, "test: as after a completed handshake")
			}
			if err := p.them.Bridge.PeerRegistry.Add(peer); err != nil {
				t.Fatal(err)
			}
		}
	}
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	for _, p := range []*peerEnv{n.alice, n.bob, carol} {
		p.Bridge.StartIncomingMessageRouter(ctx)
		p.Bridge.StartReliableQueue(done)
		q := p.Bridge.ReliableQueue
		n.wg.Add(1)
		go func() { defer n.wg.Done(); q.Start(ctx) }()
	}

	// alice: the data engine, its own state read from a combiner whose
	// contributions are loaded, the message handler, and the tracker
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: n.alice.Identity, Combiner: &PeerConf{Identity: "combiner.alice.example."}})
	conf.InternalMp.MPTransport = n.alice.Bridge
	conf.InternalMp.AgentRegistry = n.alice.Registry
	conf.InternalMp.MPZoneNames = []string{zone}
	n.alice.Bridge.combinerID = "combiner.alice.example."
	conf.InternalMp.editsRequest = func(context.Context, *tdns.ZoneData, *MPTransportBridge, *MsgQs) (*EditsResponseMsg, time.Time, error) {
		return &EditsResponseMsg{SenderID: "combiner.alice.example.", Zone: zone, Message: editsLoaded}, time.Now(), nil
	}
	catchUp := newCatchUpTracker(AgentId(n.alice.Identity), conf.InternalMp.MPZoneNames, time.Hour)
	catchUp.wire(conf, n.alice.Bridge, n.alice.Registry)
	conf.InternalMp.CatchUp, n.alice.Bridge.catchUp = catchUp, catchUp
	msgQs := n.alice.MsgQs
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
				n.alice.Registry.MsgHandler(m, msgQs.SynchedDataUpdate, msgQs.SynchedDataCmd)
			}
		}
	}()
	t.Cleanup(func() {
		stop()
		ended := make(chan struct{})
		go func() { n.wg.Wait(); catchUp.wait(); conf.InternalMp.ownReads.Wait(); close(ended) }()
		select {
		case <-ended:
		case <-time.After(10 * time.Second):
			t.Error("the rig's goroutines did not end with the test")
		}
	})
	return n
}

// A restarted agent catches up with two peers. Its zone's first load asks
// both, with start; the requests wait until its first beat to each, which
// sends them. Each peer
// answers, complete, and asks it back (peer-start), and gets its complete
// answer. The agent asks each once, and ends caught up.
func TestARestartedAgentCatchesUpWithTwoPeers(t *testing.T) {
	n := newRestartNet(t, "restart.catchup.example.")
	alice := AgentId(dns.Fqdn(n.alice.Identity))
	tr := n.conf.InternalMp.CatchUp
	waitUntil(t, "alice's own read was not done", func() bool { _, w := tr.CaughtUp(n.zone); return w.OwnRead })

	// the restart: the zone's first load, whose requests wait for the
	// peers, then the first round of beats, which sends them
	tr.afterRefresh(n.zone, &ZoneRefreshAnalysis{FirstLoad: true})
	for _, p := range []*peerEnv{n.bob, n.carol} {
		select {
		case m := <-p.MsgQs.Msg:
			t.Fatalf("%s was asked before alice's first beat to it: %+v", p.Identity, m.CatchUp)
		case <-time.After(30 * time.Millisecond):
		}
	}
	for _, p := range []*peerEnv{n.bob, n.carol} {
		agent, _ := n.alice.Registry.S.Get(AgentId(dns.Fqdn(p.Identity)))
		if _, err := n.alice.Bridge.SendBeatWithFallback(context.Background(), agent, 1); err != nil {
			t.Fatalf("the beat to %s: %v", p.Identity, err)
		}
	}

	yes := true
	for _, p := range []*peerEnv{n.bob, n.carol} {
		me := AgentId(dns.Fqdn(p.Identity))
		req, ok := recvMsgWithin(t, p.MsgQs.Msg, 10*time.Second)
		if !ok {
			t.Fatalf("%s got no request", me)
		}
		if req.CatchUp == nil || req.CatchUp.Reason != catchUpStart || req.OriginatorID != alice {
			t.Fatalf("%s got %+v, want alice's request with start", me, req.CatchUp)
		}
		// its complete answer, which names no key: a server's
		zu := &ZoneUpdate{Zone: n.zone, AgentId: me, CatchUp: &CatchUp{Request: req.CatchUp.Request, Complete: &yes},
			Operations: []core.RROperation{{Operation: "replace", RRtype: "NS", Records: []string{}}, {Operation: "replace", RRtype: "CDS", Records: []string{}}}}
		if err := p.Bridge.EnqueueForSpecificAgent(n.zone, alice, zu, transport.GenerateDistributionID()); err != nil {
			t.Fatal(err)
		}
		// and it asks back
		agent, _ := p.Registry.S.Get(alice)
		if _, err := p.Registry.sendRfiToAgent(agent, &AgentMsgPost{MessageType: AgentMsgRfi, OriginatorID: me, YourIdentity: alice,
			Zone: n.zone, RfiType: "SYNC", CatchUp: &CatchUp{Request: "back-" + string(me), Reason: catchUpPeerStart}}); err != nil {
			t.Fatalf("%s's request: %v", me, err)
		}
		ans, ok := recvMsgWithin(t, p.MsgQs.Msg, 10*time.Second)
		if !ok || ans.CatchUp == nil || ans.CatchUp.Request != "back-"+string(me) || !ans.CatchUp.IsComplete() {
			t.Fatalf("%s got %+v as alice's answer, want complete for its request", me, ans)
		}
	}
	waitUntil(t, "alice did not catch up", func() bool { ok, _ := tr.CaughtUp(n.zone); return ok })
	time.Sleep(50 * time.Millisecond)
	for _, p := range []*peerEnv{n.bob, n.carol} {
		select {
		case m := <-p.MsgQs.Msg:
			t.Errorf("%s got another message from alice: %+v", p.Identity, m.CatchUp)
		default:
		}
	}
	if s := tr.Status(n.zone); !s.CaughtUp || len(s.Peers) != 2 || s.Peers[0].Answer != "complete" || s.Peers[1].Answer != "complete" {
		t.Errorf("alice's status: %+v", s)
	}
}

// A peer that starts asks the agent, which answers and asks it back, with
// peer-start; a peer that asks for another reason is not asked back.
func TestAPeerThatStartsIsAskedBack(t *testing.T) {
	n := newRestartNet(t, "askedback.catchup.example.")
	alice := AgentId(dns.Fqdn(n.alice.Identity))
	tr := n.conf.InternalMp.CatchUp
	waitUntil(t, "alice's own read was not done", func() bool { _, w := tr.CaughtUp(n.zone); return w.OwnRead })
	for _, tc := range []struct {
		p      *peerEnv
		reason string
	}{{n.carol, catchUpStart}, {n.bob, catchUpManual}} {
		me := AgentId(dns.Fqdn(tc.p.Identity))
		agent, _ := tc.p.Registry.S.Get(alice)
		if _, err := tc.p.Registry.sendRfiToAgent(agent, &AgentMsgPost{MessageType: AgentMsgRfi, OriginatorID: me, YourIdentity: alice,
			Zone: n.zone, RfiType: "SYNC", CatchUp: &CatchUp{Request: "q-" + string(me), Reason: tc.reason}}); err != nil {
			t.Fatalf("%s's request: %v", me, err)
		}
		ans, ok := recvMsgWithin(t, tc.p.MsgQs.Msg, 10*time.Second)
		if !ok || ans.CatchUp == nil || ans.CatchUp.Request != "q-"+string(me) {
			t.Fatalf("%s got %+v, want alice's answer", me, ans)
		}
	}
	// alice's first beats send what waits for them
	for _, p := range []*peerEnv{n.bob, n.carol} {
		agent, _ := n.alice.Registry.S.Get(AgentId(dns.Fqdn(p.Identity)))
		if _, err := n.alice.Bridge.SendBeatWithFallback(context.Background(), agent, 1); err != nil {
			t.Fatalf("the beat to %s: %v", p.Identity, err)
		}
	}
	req, ok := recvMsgWithin(t, n.carol.MsgQs.Msg, 10*time.Second)
	if !ok || req.CatchUp == nil || req.CatchUp.Reason != catchUpPeerStart {
		t.Fatalf("carol, which started, got %+v, want alice's request with peer-start", req)
	}
	// bob is asked too, at alice's first beat to it: with start, and not
	// for its manual request
	req, ok = recvMsgWithin(t, n.bob.MsgQs.Msg, 10*time.Second)
	if !ok || req.CatchUp == nil || req.CatchUp.Reason != catchUpStart {
		t.Fatalf("bob got %+v, want alice's request with start", req)
	}
}

// A peer that answers complete, makes a change, and restarts within the
// minute, losing the change from its queue, is asked back when it asks at
// its start: the minute does not hold peer-start. The agent gets the change.
func TestAPeerThatRestartsWithinTheMinuteIsAskedBack(t *testing.T) {
	n := newRestartNet(t, "restart.minute.example.")
	alice, bob := AgentId(dns.Fqdn(n.alice.Identity)), AgentId(dns.Fqdn(n.bob.Identity))
	tr := n.conf.InternalMp.CatchUp
	waitUntil(t, "alice's own read was not done", func() bool { _, w := tr.CaughtUp(n.zone); return w.OwnRead })
	yes := true
	answer := func(req *AgentMsgPostPlus, ns string) {
		t.Helper()
		zu := &ZoneUpdate{Zone: n.zone, AgentId: bob, CatchUp: &CatchUp{Request: req.CatchUp.Request, Complete: &yes},
			Operations: []core.RROperation{{Operation: "replace", RRtype: "NS", Records: []string{string(n.zone) + " 3600 IN NS " + ns}},
				{Operation: "replace", RRtype: "CDS", Records: []string{}}}}
		if err := n.bob.Bridge.EnqueueForSpecificAgent(n.zone, alice, zu, transport.GenerateDistributionID()); err != nil {
			t.Fatal(err)
		}
	}
	bobsNS := func() []string {
		resp := make(chan *SynchedDataCmdResponse, 1)
		n.conf.InternalMp.MsgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "dump-zonedatarepo", Zone: n.zone, Response: resp}
		got, ok := recvWithin(resp, 5*time.Second)
		if !ok {
			return nil
		}
		var out []string
		for _, rr := range got.ZDR[n.zone][bob][dns.TypeNS] {
			out = append(out, rr.RR)
		}
		return out
	}

	// alice asks bob at its zone's first load and its first beat; bob answers
	tr.afterRefresh(n.zone, &ZoneRefreshAnalysis{FirstLoad: true})
	agent, _ := n.alice.Registry.S.Get(bob)
	if _, err := n.alice.Bridge.SendBeatWithFallback(context.Background(), agent, 1); err != nil {
		t.Fatalf("the beat: %v", err)
	}
	req, ok := recvMsgWithin(t, n.bob.MsgQs.Msg, 10*time.Second)
	if !ok || req.CatchUp == nil {
		t.Fatalf("bob got %+v", req)
	}
	answer(req, "ns1.bob.agent.example.")
	waitUntil(t, "bob's answer was not taken", func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		e := tr.peers[n.zone][bob]
		return e != nil && e.Complete
	})

	// bob changes its NS, loses the change in a restart, and asks at its start
	back, _ := n.bob.Registry.S.Get(alice)
	if _, err := n.bob.Registry.sendRfiToAgent(back, &AgentMsgPost{MessageType: AgentMsgRfi, OriginatorID: bob, YourIdentity: alice,
		Zone: n.zone, RfiType: "SYNC", CatchUp: &CatchUp{Request: "bob-restarted", Reason: catchUpStart}}); err != nil {
		t.Fatalf("bob's request: %v", err)
	}
	var askedBack *AgentMsgPostPlus
	for askedBack == nil {
		m, ok := recvMsgWithin(t, n.bob.MsgQs.Msg, 10*time.Second)
		if !ok {
			t.Fatal("alice did not ask bob back within the minute of its answer")
		}
		if m.CatchUp != nil && m.CatchUp.Reason == catchUpPeerStart {
			askedBack = m
		}
	}
	answer(askedBack, "ns2.bob.agent.example.")
	waitUntil(t, "alice did not get bob's change", func() bool {
		got := bobsNS()
		return len(got) == 1 && strings.Contains(got[0], "ns2.bob.agent.example.")
	})
}
