/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A SYNC over HTTPS, the whole round trip: alice's own sender posts it,
 * bob's receive pipeline takes it with alice's distribution ID (plan
 * decision 41, PR #224), and both of bob's confirmations come back over
 * HTTPS, none by NOTIFY. Needs #224 and #229 together; on main without
 * #224 bob confirms under an ID of his own and alice's entry stays.
 */

package tdnsmp

import (
	"context"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
)

func TestConfirm_HTTPSSyncRoundTrip(t *testing.T) {
	me := newMechanismEnv(t, "confirm-https-round-trip.example.", httpsServes)
	me.Bob.Bridge.StartIncomingMessageRouter(me.ctx)
	srvB := apiEndpointsServer(t, me.Bob)
	me.Alice.Bridge.APITransport = apiSender(srvB, me.alice, clientCert(t, me.alice))
	bobAtAlice := transport.NewPeer(me.bob)
	bobAtAlice.APIEndpoint = srvB.URL + "/api/v1"

	id := queueSync(t, me.integEnv, me.zone)
	records := map[string][]string{me.zone: {me.zone + " 3600 IN TXT \"sync over https\""}}
	ctx, cancel := context.WithTimeout(context.Background(), confirmWait)
	defer cancel()
	if _, err := me.Alice.Bridge.SendSyncWithFallback(ctx, bobAtAlice, &PeerSyncRequest{
		SenderID: me.alice, Zone: me.zone, MessageType: "sync", DistributionID: id, Records: records, Timestamp: time.Now()}); err != nil {
		t.Fatalf("the SYNC over HTTPS: %v", err)
	}
	m, ok := recvMsgWithin(t, me.Bob.MsgQs.Msg, integTestTimeout)
	if !ok {
		t.Fatal("the sync did not reach bob")
	}
	if m.Mechanism != transport.MechanismAPI || m.DistributionID != id {
		t.Fatalf("bob has the sync as %q over %q, want %q over API", m.DistributionID, m.Mechanism, id)
	}

	me.confirmed(t, id, transport.ConfirmPending)
	me.finalFrom(m)
	me.confirmed(t, id, transport.ConfirmSuccess)
	if got := queueState(me.Alice.Bridge.ReliableQueue, id); got != "gone" {
		t.Errorf("after the final confirmation alice's entry is %s, want it closed", got)
	}
	if n := me.notifies.Load(); n != 0 {
		t.Errorf("a SYNC over HTTPS was confirmed by NOTIFY: %d NOTIFYs to alice", n)
	}
	if n := me.posts.Load(); n != 2 {
		t.Errorf("alice got %d POSTs, want the PENDING and the final word", n)
	}
}
