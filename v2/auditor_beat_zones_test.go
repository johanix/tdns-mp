/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
)

// observationsAbout is the messages of zs's observations about provider that
// contain what.
func observationsAbout(zs *AuditZoneState, provider, what string) []string {
	var out []string
	for _, o := range zs.SnapshotObservations() {
		if o.Provider == provider && strings.Contains(o.Message, what) {
			out = append(out, o.Message)
		}
	}
	return out
}

// tdns-mp #153: a beat names every zone its sender shares with the auditor,
// in an order the sender leaves to chance, and it counts for all of them.
// Booked for the first zone alone, a provider whose beats arrived read "has
// not beaten" in the zones that did not come first, "never seen" in a zone
// that never did, and a provider that stopped was not told from either.
//
// The beats travel the real receive path: the sync API endpoint, the
// pipeline's authorization, the router, routeBeatMessage and the auditor's
// own consumer of MsgQs.Beat. Five zones shared by three providers; the
// order of the zones differs from beat to beat, and one zone is never first.
func TestABeatCountsForEveryZoneItNames(t *testing.T) {
	const (
		auditor   = "aud.agent.example."
		threshold = 90 * time.Second
	)
	providers := []string{"p1.agent.example.", "p2.agent.example.", "p3.agent.example."}
	zones := []string{"z1.beats.example.", "z2.beats.example.", "z3.beats.example.", "z4.beats.example.", "z5.beats.example."}
	// The zone orders of the beats. Every beat names all five zones; z5 is
	// first in none, and the zones that come first while all three beat
	// (z1, z2) are not the ones that come first afterwards (z3, z4).
	atFirst := [][]int{{0, 1, 2, 3, 4}, {1, 4, 0, 2, 3}}
	later := [][]int{{2, 3, 4, 1, 0}, {3, 0, 4, 2, 1}, {2, 4, 1, 0, 3}}

	cfg := &integEnvConfig{Role: roleAuditor}
	aud := newPeer(t, auditor, "edns0", cfg)
	for _, z := range zones {
		seedAuditedZone(t, z, auditor, providers...)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	aud.Bridge.StartIncomingMessageRouter(ctx)
	srv := apiEndpointsServer(t, aud)
	sm := NewAuditStateManager()
	booked := adaptBeatReports(ctx, aud.MsgQs.Beat, sm, aud.Registry)

	beat := func(sender string, order []int) {
		t.Helper()
		named := make([]string, len(order))
		for i, n := range order {
			named[i] = zones[n]
		}
		peer := transport.NewPeer(auditor)
		peer.APIEndpoint = srv.URL + "/api/v1"
		setTLSA(peer, srv.Certificate())
		sctx, scancel := context.WithTimeout(ctx, integTestTimeout)
		defer scancel()
		resp, err := apiSender(srv, sender).Beat(sctx, peer, &transport.BeatRequest{SenderID: sender, Zones: named, Timestamp: time.Now()})
		if err != nil || !resp.Ack {
			t.Fatalf("beat from %s naming %v: %+v %v", sender, named, resp, err)
		}
		// the auditor's consumer hands the beat on once it is booked
		if _, ok := recvWithin(booked, integTestTimeout); !ok {
			t.Fatalf("the beat from %s was not consumed", sender)
		}
	}
	detect := func(state *detectorRunState, now time.Time) {
		runDetectorsOnce(sm, state, now, threshold)
	}

	// Every provider beats twice.
	for _, order := range atFirst {
		for _, p := range providers {
			beat(p, order)
		}
	}
	state := newDetectorRunState()
	detect(state, time.Now())
	for _, z := range zones {
		zs := sm.GetZone(z)
		if zs == nil {
			t.Errorf("zone %s: no state, though every beat named it", z)
			continue
		}
		for _, p := range providers {
			zs.mu.RLock()
			ps := zs.Providers[p]
			zs.mu.RUnlock()
			if ps == nil || ps.LastBeat.IsZero() || ps.Label != shortLabel(p) {
				t.Errorf("zone %s: provider %s after its beats = %+v, want it listed with a beat", z, p, ps)
			}
		}
		zs.mu.RLock()
		_, audAsProvider := zs.Providers[auditor]
		zs.mu.RUnlock()
		if audAsProvider {
			t.Errorf("zone %s lists the auditor as a provider", z)
		}
		if obs := zs.SnapshotObservations(); len(obs) != 0 {
			t.Errorf("zone %s: observations with every provider beating: %+v", z, obs)
		}
	}

	// p3 stops. The others go on beating, each beat in another zone order.
	stopped := time.Now()
	time.Sleep(5 * time.Millisecond)
	for _, order := range later {
		beat(providers[0], order)
		beat(providers[1], order)
	}
	// Just past the threshold after p3's last beat: p3 is silent in every
	// zone, and the two that beat are silent in none.
	detect(state, stopped.Add(threshold+time.Millisecond))
	for _, z := range zones {
		zs := sm.GetOrCreateZone(z)
		for _, p := range providers[:2] {
			if got := observationsAbout(zs, p, "has not beaten"); len(got) != 0 {
				t.Errorf("zone %s: %s beats and is reported silent: %v", z, p, got)
			}
		}
		if got := observationsAbout(zs, providers[2], "has not beaten"); len(got) != 1 {
			t.Errorf("zone %s: %d \"has not beaten\" for the stopped %s, want 1: %v", z, len(got), providers[2], zs.SnapshotObservations())
		}
		for _, p := range providers {
			if got := observationsAbout(zs, p, "never seen"); len(got) != 0 {
				t.Errorf("zone %s: %s reported as never seen: %v", z, p, got)
			}
		}
	}

	// p3 returns: one beat, and it has recovered in every zone.
	beat(providers[2], later[1])
	detect(state, time.Now())
	for _, z := range zones {
		if got := observationsAbout(sm.GetOrCreateZone(z), providers[2], "recovered"); len(got) != 1 {
			t.Errorf("zone %s: %d \"recovered\" for %s after its beat, want 1", z, len(got), providers[2])
		}
	}
}

// A beat is booked only for the zones its sender would have been accepted
// for, had each come first: naming a zone it is no member of, after one it
// belongs to, books it nothing there.
func TestABeatIsNotBookedForAZoneItsSenderIsNoMemberOf(t *testing.T) {
	const auditor = "aud.agent.example."
	const member, stranger = "p1.agent.example.", "p9.agent.example."
	const shared, closed = "shared.beats.example.", "closed.beats.example."

	aud := newPeer(t, auditor, "edns0", &integEnvConfig{Role: roleAuditor})
	seedAuditedZone(t, shared, auditor, member, stranger)
	seedAuditedZone(t, closed, auditor, member)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	aud.Bridge.StartIncomingMessageRouter(ctx)
	srv := apiEndpointsServer(t, aud)
	sm := NewAuditStateManager()
	booked := adaptBeatReports(ctx, aud.MsgQs.Beat, sm, aud.Registry)

	peer := transport.NewPeer(auditor)
	peer.APIEndpoint = srv.URL + "/api/v1"
	setTLSA(peer, srv.Certificate())
	sctx, scancel := context.WithTimeout(ctx, integTestTimeout)
	defer scancel()
	resp, err := apiSender(srv, stranger).Beat(sctx, peer, &transport.BeatRequest{SenderID: stranger, Zones: []string{shared, closed, "absent.beats.example."}, Timestamp: time.Now()})
	if err != nil || !resp.Ack {
		t.Fatalf("beat: %+v %v", resp, err)
	}
	if _, ok := recvWithin(booked, integTestTimeout); !ok {
		t.Fatal("the beat was not consumed")
	}

	zs := sm.GetZone(shared)
	if zs == nil {
		t.Fatalf("no state for %s, the zone the beat was authorized for", shared)
	}
	zs.mu.RLock()
	ps := zs.Providers[stranger]
	zs.mu.RUnlock()
	if ps == nil || ps.LastBeat.IsZero() {
		t.Errorf("%s: the sender's beat was not booked: %+v", shared, ps)
	}
	if zs := sm.GetZone(closed); zs != nil {
		t.Errorf("%s: state created by a beat from %s, which is no member of it", closed, stranger)
	}
	if zs := sm.GetZone("absent.beats.example."); zs != nil {
		t.Errorf("a beat created state for a zone the auditor does not have")
	}
}
