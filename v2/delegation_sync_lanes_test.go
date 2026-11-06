/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// silentParent is a parent server that takes every question and answers
// none, as a parent whose servers are down: a query to it waits out its i/o
// timeout. It returns the server's address.
func silentParent(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("the silent parent's listener: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().String()
}

// A parent that does not answer holds only the zones under it in the agent's
// syncher (tdns #1002). Zone a's parent takes its questions and answers none,
// so a's explicit sync waits out the query's timeout; zone b, under another
// parent, is answered meanwhile. With one loop b waited for a.
func TestTheAgentsSyncherRunsEachParentOnItsOwnQueue(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	plain := func(name string) *tdns.ZoneData {
		zd := signerTestZone(t, name, kdb).ZoneData
		zd.Options[tdns.OptMultiProvider] = false // a zone this agent syncs on its own
		return zd
	}
	down := plain("a.down.example.")
	down.SetParent("down.example.")
	down.ParentNS = []string{"ns.down.example."}
	down.ParentServers = []string{silentParent(t)}
	up := plain("b.up.example.") // no parent known and no resolver: its analysis fails at once

	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: "agent.us.example."})
	q := make(chan tdns.DelegationSyncRequest, 10)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = (&HsyncDB{KeyDB: kdb}).DelegationSyncher(ctx, q, make(chan tdns.NotifyRequest, 8), conf)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Error("the syncher did not stop")
		}
	})

	downAnswer := make(chan tdns.DelegationSyncStatus, 1)
	upAnswer := make(chan tdns.DelegationSyncStatus, 1)
	q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: down.ZoneName, ZoneData: down, Response: downAnswer}
	waitUntil(t, "a's sync to ask its parent", func() bool {
		pos, ok := tdns.DelegationSyncWaiting(down.ZoneName)
		return ok && pos.Running
	})
	q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: up.ZoneName, ZoneData: up, Response: upAnswer}

	select {
	case st := <-upAnswer:
		if !st.Error {
			t.Errorf("b answered %+v, want its analysis error (no resolver)", st)
		}
	case st := <-downAnswer:
		t.Fatalf("a was answered (%+v) before b: b waited for a's parent", st)
	case <-time.After(5 * time.Second):
		t.Fatal("b was not answered while a's parent did not answer")
	}
	if pos, ok := tdns.DelegationSyncWaiting(down.ZoneName); !ok || !pos.Running || pos.Parent != "down.example." {
		t.Errorf("after b's answer a stands at %+v (found %v), want still running in down.example.", pos, ok)
	}
	select {
	case st := <-downAnswer:
		if !st.Error {
			t.Errorf("a answered %+v, want the failed analysis", st)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a's analysis never gave up on its silent parent")
	}
}

// With the syncher on per-parent queues the delegation sync queue does not
// fill behind a parent that does not answer, so the catch-up tracker's owed
// sync is queued, not left waiting for room: the mark goes when the sync is
// queued, nothing waits for room, and no "queue is full" warning is logged.
// The status says where the sync waits instead, and says nothing once it has
// run.
func TestAnOwedSyncIsQueuedBehindAStuckParentNotOwedForRoom(t *testing.T) {
	r, tr := owedRig(t, "owed.down.example.", true)
	z := ZoneName(r.mpzd.ZoneName)
	r.mpzd.ZoneData.SetParent("down.example.")
	var buf lockedBuffer
	logTo(t, lg, slog.NewTextHandler(&buf, nil))

	release := make(chan struct{})
	ran := make(chan string, 64)
	ctx, cancel := context.WithCancel(r.ctx)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = tdns.RunDelegationSyncLanes(ctx, r.q, func(ctx context.Context, ds tdns.DelegationSyncRequest) {
			select {
			case <-release:
			case <-ctx.Done():
				return
			}
			ran <- ds.ZoneName
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})

	// three times the queue's room, for zones under the parent that does
	// not answer: all taken, the first running, the rest in its queue
	siblings := 3 * cap(r.q)
	for i := range siblings {
		zd := &tdns.ZoneData{ZoneName: string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".down.example."}
		zd.SetParent("down.example.")
		select {
		case r.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: zd.ZoneName, ZoneData: zd}:
		case <-time.After(2 * time.Second):
			t.Fatalf("request %d was not taken: the queue filled behind the stuck parent", i+1)
		}
	}

	tr.owe(z)
	tr.askAllOwed(r.ctx, false)
	if owed, room := tr.owedState(z); owed || room {
		t.Errorf("after the pass: owed=%v room=%v, want the mark gone with the sync queued", owed, room)
	}
	if tr.roomWaits() {
		t.Error("an owed sync waits for room")
	}
	if strings.Contains(buf.String(), "the delegation sync queue is full") {
		t.Errorf("the pass found the queue full:\n%s", buf.String())
	}

	waitUntil(t, "the owed sync in its parent's queue", func() bool {
		pos, ok := tdns.DelegationSyncWaiting(string(z))
		return ok && pos.Ahead == siblings
	})
	ar := &AgentRegistry{MPTransport: &MPTransportBridge{catchUp: tr}}
	status := func() string { return r.lem.GetParentSyncStatus(z, nil, nil, nil, ar, nil).ParentSync }
	if got, want := status(), fmt.Sprintf("queued: %d ahead for parent down.example.", siblings); got != want {
		t.Errorf("the status says %q, want %q", got, want)
	}

	close(release)
	for range siblings + 1 {
		select {
		case <-ran:
		case <-time.After(5 * time.Second):
			t.Fatal("the queued syncs did not all run once the parent answered")
		}
	}
	waitUntil(t, "the zone's queue to empty", func() bool {
		_, ok := tdns.DelegationSyncWaiting(string(z))
		return !ok
	})
	if got := status(); got != "" {
		t.Errorf("with nothing owed or queued the status says %q", got)
	}
}

// The queued line names the parent and how many syncs are ahead, says so
// when the zone's own sync is the one running, and carries the parent's
// failed analyses when the tracker has seen them.
func TestTheQueuedStatusLine(t *testing.T) {
	z := ZoneName("line.down.example.")
	queued := tdns.DelegationSyncPosition{Parent: "down.example.", Ahead: 3, Waiting: 1}
	if got, want := queuedSyncLine(queued, nil, z), "queued: 3 ahead for parent down.example."; got != want {
		t.Errorf("queued: %q, want %q", got, want)
	}
	running := tdns.DelegationSyncPosition{Parent: "down.example.", Running: true, Waiting: 1}
	if got, want := queuedSyncLine(running, nil, z), "syncing with parent down.example."; got != want {
		t.Errorf("running: %q, want %q", got, want)
	}
	tr := newCatchUpTracker(usAgent, nil, time.Hour)
	tr.oweAfterFailedAnalysis(z, errTestParentDown)
	got := queuedSyncLine(queued, tr, z)
	if !strings.HasPrefix(got, "queued: 3 ahead for parent down.example.; the parent's analysis fails since ") ||
		!strings.HasSuffix(got, "("+errTestParentDown.Error()+")") {
		t.Errorf("with the parent down: %q", got)
	}
}
