/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
)

// roundTimes records when an engine's beat rounds ran.
type roundTimes struct {
	mu sync.Mutex
	at []time.Time
}

func (r *roundTimes) tick() {
	r.mu.Lock()
	r.at = append(r.at, time.Now())
	r.mu.Unlock()
}

func (r *roundTimes) waitFor(t *testing.T, n int, d time.Duration) []time.Time {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		r.mu.Lock()
		got := append([]time.Time(nil), r.at...)
		r.mu.Unlock()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d round(s) within %v, want %d", len(got), d, n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// An inbound hello brings the engine's next beat round forward when it moves
// the sender's mechanism to INTRODUCING, so that this side beats back and
// reaches OPERATIONAL too. A hello that finds the mechanism already there
// leaves the pace alone: a peer whose hello arrives but that never gets our
// accept repeats it every helloretry, and kicking on each repeat would hold
// the beats to the whole group off the beat interval for as long as it did.
func TestAnInboundHelloKicksTheBeatRoundsOnlyWhenItMovesThePeer(t *testing.T) {
	const fast, steady = 20 * time.Millisecond, 300 * time.Millisecond
	const local, remote = "local.example.", "remote.example."

	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent]()}
	tm := &MPTransportBridge{
		TransportManager: &transport.TransportManager{PeerRegistry: transport.NewPeerRegistry()},
		agentRegistry:    ar,
	}
	// The sender is an agent we know and have an address for, so the hello
	// introduces its mechanism and starts no discovery.
	ar.S.Set(AgentId(remote), newAgentView(hsync.NewPeer(remote)))
	tm.PeerRegistry.GetOrCreate(remote).SetMechanismAddress(transport.MechanismDNS,
		&transport.Address{Host: "192.0.2.1", Port: 53, Transport: "udp"})

	rounds := &roundTimes{}
	cfg := hsync.DefaultConfig()
	cfg.BeatIntervalMin, cfg.BeatInterval = fast, steady
	cfg.RetryInterval, cfg.ReconcileInterval = time.Hour, time.Hour
	engine := hsync.NewEngine(hsync.Deps{
		LocalID:   local,
		Transport: &mpHsyncBridge{ar: ar, tm: tm},
		Host:      hsync.HostCallbacks{BeforeHeartbeats: rounds.tick},
	}, cfg)
	ar.HsyncEngine = engine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Run(ctx, hsync.MsgChannels{
		Hello: make(chan *hsync.InboundReport),
		Beat:  make(chan *hsync.InboundReport),
		Msg:   make(chan *hsync.InboundMsg),
	})

	payload, err := json.Marshal(map[string]any{"type": "hello", "sender_id": remote, "MyIdentity": remote})
	if err != nil {
		t.Fatal(err)
	}
	hello := &transport.IncomingMessage{
		TypeToken: "hello", SenderID: remote, Payload: payload, Mechanism: transport.MechanismDNS,
	}

	// The first hello moves the mechanism: the next round comes at the fast
	// interval, though the pace had backed off.
	n := len(rounds.waitFor(t, 7, 4*time.Second))
	sent := time.Now()
	tm.routeHelloMessage(hello)
	peer, _ := tm.PeerRegistry.Get(remote)
	if st, ok := peer.MechanismRawState(transport.MechanismDNS); !ok || st != transport.PeerStateIntroducing {
		t.Fatalf("after the hello the DNS mechanism is %v (present %v), want INTRODUCING", st, ok)
	}
	after := rounds.waitFor(t, n+1, 4*time.Second)
	if got := after[n].Sub(sent); got > steady/2 {
		t.Errorf("the round after a hello that moved the peer came %v later, want about %v", got, fast)
	}

	// The same hello again, once the pace is steady: nothing moved, and the
	// rounds stay a beat interval apart.
	m := len(rounds.waitFor(t, n+7, 4*time.Second))
	tm.routeHelloMessage(hello)
	after = rounds.waitFor(t, m+2, 4*time.Second)
	if gap := after[m+1].Sub(after[m]); gap < steady*3/4 {
		t.Errorf("after a repeated hello the rounds are %v apart, want the steady %v", gap, steady)
	}
}

// beatRecorder is the hsync bridge with its beats acknowledged and noted.
type beatRecorder struct {
	*mpHsyncBridge
	mu sync.Mutex
	at []time.Time
}

func (b *beatRecorder) SendBeat(ctx context.Context, peer *hsync.Peer, sequence uint64) (bool, string, error) {
	b.mu.Lock()
	b.at = append(b.at, time.Now())
	b.mu.Unlock()
	return true, hsync.TransportDNS, nil
}

func (b *beatRecorder) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.at)
}

// A peer that restarts introduces itself again, and its hello finds our
// mechanism where it was: OPERATIONAL, from before the restart. That hello
// gets one beat back at once, to that peer, so that a beat that failed while
// the peer was away is not left two intervals behind the last success (#123).
// It is not a kick: the rounds keep their pace.
func TestAHelloFromAnIntroducedPeerGetsOneBeatBack(t *testing.T) {
	const fast, steady = 20 * time.Millisecond, 300 * time.Millisecond
	const local, remote = "local.example.", "remote.example."

	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent]()}
	tm := &MPTransportBridge{
		TransportManager: &transport.TransportManager{PeerRegistry: transport.NewPeerRegistry()},
		agentRegistry:    ar,
	}
	ar.S.Set(AgentId(remote), newAgentView(hsync.NewPeer(remote)))
	held := tm.PeerRegistry.GetOrCreate(remote)
	held.SetMechanismState(transport.MechanismDNS, transport.PeerStateOperational, "from before the restart")
	held.SetMechanismLastBeatSent(transport.MechanismDNS, time.Now())

	rec := &beatRecorder{mpHsyncBridge: &mpHsyncBridge{ar: ar, tm: tm}}
	rounds := &roundTimes{}
	cfg := hsync.DefaultConfig()
	cfg.BeatIntervalMin, cfg.BeatInterval = fast, steady
	cfg.RetryInterval, cfg.ReconcileInterval = time.Hour, time.Hour
	engine := hsync.NewEngine(hsync.Deps{
		LocalID:   local,
		Transport: rec,
		Host:      hsync.HostCallbacks{BeforeHeartbeats: rounds.tick},
	}, cfg)
	ar.HsyncEngine = engine
	peer := hsync.NewPeer(remote)
	peer.DnsMethod = true
	engine.Registry().S.Set(peer.ID, peer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Run(ctx, hsync.MsgChannels{
		Hello: make(chan *hsync.InboundReport),
		Beat:  make(chan *hsync.InboundReport),
		Msg:   make(chan *hsync.InboundMsg),
	})

	payload, err := json.Marshal(map[string]any{"type": "hello", "sender_id": remote, "MyIdentity": remote})
	if err != nil {
		t.Fatal(err)
	}
	hello := &transport.IncomingMessage{
		TypeToken: "hello", SenderID: remote, Payload: payload, Mechanism: transport.MechanismDNS,
	}

	// At the steady pace, shortly after a round and its beat.
	n := len(rounds.waitFor(t, 8, 5*time.Second))
	time.Sleep(steady / 10)
	before := rec.count()
	sent := time.Now()
	tm.routeHelloMessage(hello)

	deadline := time.Now().Add(steady / 2)
	for rec.count() == before && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if rec.count() != before+1 {
		t.Fatalf("%d beat(s) within %v of the hello, want one beat back", rec.count()-before, steady/2)
	}
	t.Logf("beat back %v after the hello", time.Since(sent))

	// The rounds keep their pace.
	after := rounds.waitFor(t, n+2, 5*time.Second)
	if gap := after[n+1].Sub(after[n]); gap < steady*3/4 {
		t.Errorf("after the beat back the rounds are %v apart, want the steady %v", gap, steady)
	}
	if st, _ := held.MechanismRawState(transport.MechanismDNS); st != transport.PeerStateOperational {
		t.Errorf("the hello left the mechanism at %v, want OPERATIONAL as it was", st)
	}
}
