/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A send that does not reach a peer is not a peer that is gone, and a group
 * with no leader says what holds it (tdns-mp #337).
 */
package tdnsmp

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// dropsMsgServer is apiEndpointsServer for receiver, whose /msg, while drops
// is set, reads the body and goes without an answer: a message that is not
// delivered, on a mechanism whose beats succeed.
func dropsMsgServer(t *testing.T, receiver *peerEnv, drops *atomic.Bool) *httptest.Server {
	t.Helper()
	conf := &Config{}
	conf.InternalMp.MPTransport = receiver.Bridge
	msg := conf.apiSyncEndpoint(apiEndpointMsg)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/beat", conf.apiSyncEndpoint(apiEndpointBeat))
	mux.HandleFunc("/api/v1/msg", func(w http.ResponseWriter, r *http.Request) {
		if !drops.Load() {
			msg(w, r)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
			}
		}
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// A pair with one mechanism, whose group has a leader. One confirmation does
// not reach the peer, and every beat succeeds. The group stays mutually
// OPERATIONAL and keeps its leader, from the real send through the real row
// and gate to the election; the mechanism's own reading shows the failure.
func TestAFailedSendOnAPairWithOneMechanismKeepsTheGroupsLeader(t *testing.T) {
	const zone = "failed-send.leader.example."
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	alice, bob := dns.Fqdn(env.Alice.Identity), dns.Fqdn(env.Bob.Identity)
	zd := seedZoneWithHSYNC3(t, zone, alice, bob)
	addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob))

	var drops atomic.Bool
	srv := dropsMsgServer(t, env.Bob, &drops)
	tr := apiSender(srv, alice)
	env.Alice.Bridge.APITransport = tr
	env.Alice.Bridge.TransportManager.APITransport = tr
	peer := transport.NewPeer(bob)
	peer.APIEndpoint = srv.URL + "/api/v1"
	setTLSA(peer, srv.Certificate())
	peer.SetMechanismState("API", transport.PeerStateIntroducing, "said hello")
	if err := env.Alice.Bridge.PeerRegistry.Add(peer); err != nil {
		t.Fatalf("the peer: %v", err)
	}
	agent := NewAgent(AgentId(bob))
	agent.ApiMethod = true // and no DNS: this pair has the one mechanism

	ar := env.Alice.Registry
	ar.S.Set(AgentId(bob), agent)
	pgm := ar.ProviderGroupManager
	pgm.RecomputeGroups()
	pg := pgm.GetGroupForZone(ZoneName(zone))
	if pg == nil {
		t.Fatal("no provider group for the zone")
	}
	group := pg.GroupHash

	conf := &Config{}
	conf.InternalMp.AgentRegistry = ar
	conf.InternalMp.MPTransport = env.Alice.Bridge
	lem := NewLeaderElectionManager(AgentId(alice), time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(lem) })
	lem.SetProviderGroupManager(pgm)
	conf.InternalMp.LeaderElectionManager = lem
	ar.LeaderElectionManager = lem
	wireAgentGossipCallbacks(conf, ar)
	gst := ar.GossipStateTable
	degraded := 0
	gst.mu.Lock()
	wired := gst.onGroupDegraded
	gst.mu.Unlock()
	gst.SetOnGroupDegraded(func(h string) {
		degraded++
		wired(h)
	})

	// bob reads alice OPERATIONAL, as his own beats to her have it
	env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
	atBob := env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
	atBob.SetMechanismState("API", transport.PeerStateOperational, "test: bob's beat")
	atBob.SetMechanismLastBeatSent("API", time.Now())
	env.Bob.Registry.ProviderGroupManager.RecomputeGroups()
	env.Bob.Registry.GossipStateTable.RefreshLocalStates(env.Bob.Registry, env.Bob.Registry.ProviderGroupManager)
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)

	beat := func(what string) {
		t.Helper()
		resp, err := env.Alice.Bridge.SendBeatWithFallback(env.ctx, agent, 1)
		if err != nil || resp == nil || !resp.Ack {
			t.Fatalf("%s: the beat: %+v %v", what, resp, err)
		}
	}
	round := func() {
		gst.RefreshLocalStates(ar, pgm)
		gst.CheckGroupState(group, pg.VotingMembers)
	}

	lem.ApplyGossipElection(group, GroupElectionState{Leader: bob, Term: 1, LeaderExpiry: time.Now().Add(time.Hour)})
	beat("before the failed send")
	round()
	if cells := gst.notOperational(group, pg.VotingMembers); len(cells) > 0 {
		t.Fatalf("before the failed send the group is not mutually OPERATIONAL: %v", cells)
	}
	if leader, ok := lem.GetGroupLeader(group); !ok || string(leader) != bob {
		t.Fatalf("before the failed send the group's leader is %q, %v, want %s", leader, ok, bob)
	}

	drops.Store(true)
	ctx, cancel := context.WithTimeout(env.ctx, 5*time.Second)
	defer cancel()
	err := env.Alice.Bridge.confirmOn(ctx, transport.MechanismAPI, peer, &transport.ConfirmRequest{
		SenderID: alice, Zone: zone, DistributionID: "failed-send", Status: transport.ConfirmPending, Timestamp: time.Now()})
	if err == nil {
		t.Fatal("the confirmation was delivered")
	}
	if n := peer.MechanismConsecutiveFails("API"); n != 1 {
		t.Fatalf("%d failures counted on the mechanism, want 1", n)
	}
	drops.Store(false)

	for range 3 {
		beat("after the failed send")
		round()
	}
	if st := ar.effectiveAgentState(AgentId(bob)); st != AgentStateOperational {
		t.Errorf("alice reads bob %s, with every beat acknowledged", AgentStateToString[st])
	}
	if degraded != 0 {
		t.Errorf("the failed send took the group out of mutual OPERATIONAL %d time(s)", degraded)
	}
	if leader, ok := lem.GetGroupLeader(group); !ok || string(leader) != bob {
		t.Errorf("the group's leader is %q, %v after the failed send, want %s", leader, ok, bob)
	}
	if st, _ := peer.MechanismEffectiveState("API"); st != transport.PeerStateDegraded {
		t.Errorf("the mechanism reads %v, want DEGRADED: the one-way pair shows there (#236)", st)
	}
}

// thawRigInAGroup is a thaw rig whose zone is in a provider group, at step 0
// of its reconciliation, with roleB its leader.
func thawRigInAGroup(t *testing.T, zone string) (*thawRig, *ProviderGroup) {
	t.Helper()
	r := newThawRig(t, zone, roleB)
	ar := r.conf.InternalMp.AgentRegistry
	ar.ProviderGroupManager = NewProviderGroupManager(roleA)
	ar.GossipStateTable = NewGossipStateTable(roleA)
	ar.ProviderGroupManager.RecomputeGroups()
	r.lem.SetProviderGroupManager(ar.ProviderGroupManager)
	pg := ar.ProviderGroupManager.GetGroupForZone(ZoneName(zone))
	if pg == nil {
		t.Fatal("no provider group for the zone")
	}
	r.agree()
	st := tells(r.v, r.v)
	st.Thaw, st.Reconciling = &Thaw{From: sd(r.n), To: sd(r.v)}, true
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if r.active() != 42 {
		t.Fatal("not activated on the leader's thaw")
	}
	return r, pg
}

// With no leader the status says so, and names the cells that hold the group,
// by the gate's own rule; it does not read as a wait for a leader's step.
func TestAReconcilingZoneWithNoLeaderSaysWhatHoldsItsGroup(t *testing.T) {
	r, pg := thawRigInAGroup(t, "says.noleader.example.")
	const head = "reconciling 41->42: step 0 (the sets held), "
	if line := r.conf.thawLine(r.zone); line != head+"waiting for the leader's first step" {
		t.Errorf("with a leader: %q", line)
	}

	r.lead("", time.Now())
	op, degraded := AgentStateToString[AgentStateOperational], AgentStateToString[AgentStateDegraded]
	gst := r.conf.InternalMp.AgentRegistry.GossipStateTable
	if line := r.conf.thawLine(r.zone); !strings.HasPrefix(line, head+"no leader: ") || !strings.Contains(line, " has no row here") {
		t.Errorf("no rows held: %q", line)
	}
	gst.mergeGossip(&GossipMessage{GroupHash: pg.GroupHash, Members: map[string]*MemberState{
		roleA: {Identity: roleA, PeerStates: map[string]string{roleB: degraded}, Timestamp: time.Now()},
		roleB: {Identity: roleB, PeerStates: map[string]string{roleA: op}, Timestamp: time.Now()},
	}})
	want := head + "no leader: " + dns.Fqdn(roleA) + " reads " + dns.Fqdn(roleB) + " " + degraded
	if line := r.conf.thawLine(r.zone); line != want {
		t.Errorf("one cell down: %q, want %q", line, want)
	}
	gst.mergeGossip(&GossipMessage{GroupHash: pg.GroupHash, Members: map[string]*MemberState{
		roleA: {Identity: roleA, PeerStates: map[string]string{roleB: op}, Timestamp: time.Now().Add(time.Second)},
	}})
	if line := r.conf.thawLine(r.zone); line != head+"no leader" {
		t.Errorf("mutually OPERATIONAL, its election to come: %q", line)
	}

	r.lead(roleB, time.Now().Add(time.Hour))
	if line := r.conf.thawLine(r.zone); line != head+"waiting for the leader's first step" {
		t.Errorf("with a leader again: %q", line)
	}
}

// The warning comes once a stretch, at the leaving time-out, and a leader
// ends the stretch.
func TestAReconcilingZoneWithNoLeaderWarnsOnceAtTheLeavingTimeout(t *testing.T) {
	r, _ := thawRigInAGroup(t, "warns.noleader.example.")
	mp := &MultiProviderConf{Role: "agent", Identity: roleA}
	mp.Transitions.LeavingTimeout = 600
	r.conf.SetMpConfig(mp)
	logged := captureLog(t)
	warnings := func() int {
		return strings.Count(logged.String(), "a reconciling zone has had no leader for the leaving time-out")
	}
	start := time.Now()
	turn := func(after time.Duration) { r.conf.reconcileTurn(r.zone, start.Add(after)) }

	turn(0)
	turn(time.Hour)
	if n := warnings(); n != 0 {
		t.Errorf("%d warnings with a leader", n)
	}

	r.lead("", time.Now())
	turn(0)
	turn(9 * time.Minute)
	if n := warnings(); n != 0 {
		t.Errorf("%d warnings before the leaving time-out", n)
	}
	turn(10 * time.Minute)
	if n := warnings(); n != 1 {
		t.Errorf("%d warnings at the leaving time-out, want 1", n)
	}
	turn(time.Hour)
	if n := warnings(); n != 1 {
		t.Errorf("%d warnings in one stretch, want 1", n)
	}

	r.lead(roleB, time.Now().Add(time.Hour))
	turn(time.Hour)
	r.lead("", time.Now())
	turn(2 * time.Hour)
	turn(2*time.Hour + 9*time.Minute)
	if n := warnings(); n != 1 {
		t.Errorf("%d warnings: a new stretch warned before the leaving time-out", n)
	}
	turn(2*time.Hour + 10*time.Minute)
	if n := warnings(); n != 2 {
		t.Errorf("%d warnings, want a new stretch to warn again", n)
	}
}
