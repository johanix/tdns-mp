/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Over HTTPS the sender of a message is the identity of the client
 * certificate, as over DNS it is the identity in the NOTIFY's query name
 * (review M1 of plan decision 26). The body names the originator, which
 * for a forwarded update is somebody else.
 */

package tdnsmp

import (
	"context"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// An agent forwards a remote agent's update to its combiner under the
// remote agent's name, as deliverGenericMessage does. The combiner sends
// its confirmations to DeliveredBy, so over HTTPS DeliveredBy must be the
// agent whose certificate the connection presented, not the originator
// the body names. Whether the combiner knows the originator does not
// matter: it authorizes the agent that delivered the update, as it does
// for a NOTIFY.
func TestAPIReceive_ForwardedUpdateIsDeliveredByTheForwarder(t *testing.T) {
	const (
		alice    = "alice.agent.example." // the agent that forwards
		carol    = "carol.agent.example." // the remote agent whose update it is
		combiner = "combiner.example."
		zone     = "api-forward.example."
	)
	for _, tc := range []struct {
		name   string
		agents []string // the combiner's configured agents
	}{
		{"originator known to the combiner", []string{alice, carol}},
		{"originator not known to the combiner", []string{alice}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
			defer cancel()

			comb := newPeer(t, combiner, "query", &integEnvConfig{Role: roleCombiner, AuthorizedPeers: tc.agents})
			comb.Bridge.StartIncomingMessageRouter(ctx)
			srv := apiEndpointsServer(t, comb)

			agent := newPeer(t, alice, "query", &integEnvConfig{CombinerID: combiner})
			tr := apiSender(srv, alice, clientCert(t, alice))
			agent.Bridge.APITransport = tr
			agent.Bridge.TransportManager.APITransport = tr
			agent.Registry.S.Set(AgentId(combiner), NewAgent(AgentId(combiner)))
			agent.Bridge.PeerRegistry.GetOrCreate(combiner).APIEndpoint = srv.URL + "/api/v1"

			err := agent.Bridge.deliverGenericMessage(ctx, &transport.OutgoingMessage{
				DistributionID: "api-forward-1",
				RecipientID:    combiner,
				Zone:           zone,
				CreatedAt:      time.Now(),
				Nonce:          "n-forward",
				Payload: &ZoneUpdate{Zone: zone, AgentId: carol, Operations: []core.RROperation{
					{Operation: "add", RRtype: "TXT", Records: []string{zone + " 3600 IN TXT \"from carol\""}},
				}},
			})
			if err != nil {
				t.Errorf("forwarding the update: %v", err)
			}
			m, ok := recvMsgWithin(t, comb.MsgQs.Msg, integTestTimeout)
			if !ok {
				t.Fatal("the forwarded update did not reach the combiner")
			}
			if string(m.OriginatorID) != carol {
				t.Errorf("OriginatorID %q, want the remote agent %q", m.OriginatorID, carol)
			}
			if string(m.DeliveredBy) != alice {
				t.Errorf("DeliveredBy %q, want the forwarding agent %q", m.DeliveredBy, alice)
			}
		})
	}
}

// With the certificate as the sender, authorization looks at the
// certificate and no longer at the name in the body, and a beat or a ping
// is still booked under the body's name. So a member whose certificate
// gets in must not file a beat or a ping as another member: the refusal
// on /beat and /sync/ping of a body sender that is not the certificate
// (PR 201) is what stops it (review M1 on PR 204). Dave is a member, and
// his own beat is taken; under his certificate a beat or a ping naming
// alice is refused and reaches no queue.
func TestAPIReceive_MemberCannotBeatAsAnother(t *testing.T) {
	const (
		zone = "api-member.example."
		dave = "dave.agent.example."
	)
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	alice := dns.Fqdn(env.Alice.Identity)
	bob := dns.Fqdn(env.Bob.Identity)
	zd := seedZoneWithHSYNC3(t, zone, alice, bob, dave)
	addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob), shortLabel(dave))
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	srv := apiEndpointsServer(t, env.Bob)
	peer := transport.NewPeer(bob)
	peer.APIEndpoint = srv.URL + "/api/v1"
	ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
	defer cancel()
	tr := apiSender(srv, dave, clientCert(t, dave))

	own, err := tr.Beat(ctx, peer, &transport.BeatRequest{SenderID: dave, Zones: []string{zone}, Timestamp: time.Now()})
	if err != nil || !own.Ack {
		t.Fatalf("dave's own beat: %+v %v", own, err)
	}
	if b, ok := recvWithin(env.Bob.MsgQs.Beat, integTestTimeout); !ok || string(b.Identity) != dave {
		t.Fatalf("dave's own beat was not booked as dave: %+v", b)
	}

	beat, err := tr.Beat(ctx, peer, &transport.BeatRequest{SenderID: alice, Zones: []string{zone}, Timestamp: time.Now()})
	if err != nil || beat.Ack {
		t.Fatalf("a beat naming alice under dave's certificate was taken: %+v %v", beat, err)
	}
	if b, ok := recvWithin(env.Bob.MsgQs.Beat, 100*time.Millisecond); ok {
		t.Errorf("a beat naming alice under dave's certificate was booked as %s", b.Identity)
	}
	ping, err := tr.Ping(ctx, peer, &transport.PingRequest{SenderID: alice, Nonce: "n-dave", Timestamp: time.Now()})
	if err != nil || ping.OK {
		t.Fatalf("a ping naming alice under dave's certificate was answered: %+v %v", ping, err)
	}
	if p, ok := recvWithin(env.Bob.MsgQs.Ping, 100*time.Millisecond); ok {
		t.Errorf("a ping naming alice under dave's certificate was booked as %s", p.Identity)
	}
}
