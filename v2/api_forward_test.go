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
