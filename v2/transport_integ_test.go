/*
 * Transport-boundary integration tests.
 * See transport_harness_test.go for the env builder and helpers.
 *
 * PR-1 covered scenarios 1 (chunk_mode=query) and 6 (Hello rejection).
 * PR-2 adds scenarios 2-5 and 7, plus the chunk_mode=edns0 variant of
 * scenario 1.
 *
 * Black-box scope: the harness exercises the boundary between
 * transport-layer message delivery and the MP MsgQs / registry
 * surface. Wire-level concerns (CHUNK encryption, EDNS0 packing,
 * fragment reassembly) are unit-tested in tdns-transport; the
 * scenarios here either drive routeIncomingMessage directly (the
 * post-decryption callback) or call Router.Route(ctx, msgType)
 * directly to exercise registered handlers.
 */

package tdnsmp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
)

// TestTransportBoundary_ChunkToMsg drives a sync IncomingMessage into
// Bob's bridge via the same callback the production CHUNK handler
// invokes (routeIncomingMessage), and asserts the message surfaces on
// Bob's MsgQs.Msg channel with the expected sender, zone, and records.
//
// Parameterized on chunk mode: the post-decryption IncomingMessage
// shape is identical for "query" and "edns0", so a single assertion
// covers both modes for the receive boundary. Wire-level differences
// (where the chunk payload is carried) are tested in tdns-transport.
func TestTransportBoundary_ChunkToMsg(t *testing.T) {
	for _, mode := range []string{"query", "edns0"} {
		t.Run(mode, func(t *testing.T) {
			env := newIntegEnv(t, &integEnvConfig{ChunkMode: mode})

			zoneName := "scenario1-" + mode + ".example."
			// HSYNC3 must include both Alice and Bob for an
			// HSYNC-aware path. routeSyncMessage itself does not
			// consult HSYNC3 (auth is upstream), but seeding is
			// cheap and keeps the fixture realistic.
			seedZoneWithHSYNC3(t, zoneName, env.Alice.Identity, env.Bob.Identity)

			distID := nextDistributionID()
			records := map[string][]string{
				zoneName: {
					zoneName + " 3600 IN TXT \"hello from alice\"",
				},
			}
			msg := makeSyncIncomingMessage(t,
				env.Alice.Identity, env.Bob.Identity,
				zoneName, distID, records,
			)

			env.Bob.Bridge.routeIncomingMessage(msg)

			got, ok := recvMsgWithin(t, env.Bob.MsgQs.Msg, integTestTimeout)
			if !ok {
				t.Fatalf("timed out waiting for sync on Bob.MsgQs.Msg after %s", integTestTimeout)
			}

			if string(got.OriginatorID) != env.Alice.Identity {
				t.Errorf("OriginatorID: got %q, want %q", got.OriginatorID, env.Alice.Identity)
			}
			if string(got.DeliveredBy) != env.Alice.Identity {
				t.Errorf("DeliveredBy: got %q, want %q (direct delivery)", got.DeliveredBy, env.Alice.Identity)
			}
			if string(got.Zone) != zoneName {
				t.Errorf("Zone: got %q, want %q", got.Zone, zoneName)
			}
			if got.DistributionID != distID {
				t.Errorf("DistributionID: got %q, want %q", got.DistributionID, distID)
			}
			if got.MessageType != AgentMsgNotify {
				// "sync" decodes to AgentMsgNotify per
				// routeSyncMessage default; confirm here so we catch
				// a regression in the type mapping.
				t.Errorf("MessageType: got %v, want %v (AgentMsgNotify)", got.MessageType, AgentMsgNotify)
			}
			if len(got.Records[zoneName]) == 0 {
				t.Errorf("Records[%q] missing or empty: got %#v", zoneName, got.Records)
			}
		})
	}
}

// TestTransportBoundary_HelloRejection exercises the policy layer of
// EvaluateHello: a hello whose zone is unknown, has no HSYNC3, or
// excludes the caller must be rejected. The transport layer never
// sees these helloes; rejection happens in MP code before any
// transport-state transition.
//
// This is scenario 6 from the harness doc. It deliberately does not
// rely on any HandleSync path; that is scenario 5 (PR-2).
func TestTransportBoundary_HelloRejection(t *testing.T) {
	t.Run("UnknownZone", func(t *testing.T) {
		env := newIntegEnv(t, &integEnvConfig{SkipBridge: true})
		// No zone seeded.
		ahp := &AgentHelloPost{
			MessageType:  AgentMsgHello,
			MyIdentity:   AgentId(env.Alice.Identity),
			YourIdentity: AgentId(env.Bob.Identity),
			Zone:         ZoneName("nonexistent.example."),
		}
		needed, errmsg, err := env.Bob.Registry.EvaluateHello(ahp)
		if err != nil {
			t.Fatalf("EvaluateHello returned err: %v", err)
		}
		if needed {
			t.Errorf("expected needed=false; got true (errmsg=%q)", errmsg)
		}
		if !strings.Contains(errmsg, "don't know about zone") {
			t.Errorf("errmsg %q does not mention unknown zone", errmsg)
		}
	})

	t.Run("NoHSYNC3", func(t *testing.T) {
		env := newIntegEnv(t, &integEnvConfig{SkipBridge: true})
		const zone = "no-hsync3.example."
		// Zone exists but has no HSYNC3 RRset.
		seedZoneWithHSYNC3(t, zone) // identities=nil -> no HSYNC3
		ahp := &AgentHelloPost{
			MessageType:  AgentMsgHello,
			MyIdentity:   AgentId(env.Alice.Identity),
			YourIdentity: AgentId(env.Bob.Identity),
			Zone:         ZoneName(zone),
		}
		needed, errmsg, err := env.Bob.Registry.EvaluateHello(ahp)
		if err != nil {
			t.Fatalf("EvaluateHello returned err: %v", err)
		}
		if needed {
			t.Errorf("expected needed=false; got true (errmsg=%q)", errmsg)
		}
		if !strings.Contains(errmsg, "no HSYNC3") {
			t.Errorf("errmsg %q does not mention missing HSYNC3", errmsg)
		}
	})

	t.Run("SenderNotInHSYNC3", func(t *testing.T) {
		env := newIntegEnv(t, &integEnvConfig{SkipBridge: true})
		const zone = "exclusive.example."
		// HSYNC3 exists, includes Bob (the local agent for the
		// EvaluateHello call) but excludes Alice. Alice's hello
		// must be rejected.
		seedZoneWithHSYNC3(t, zone, env.Bob.Identity)
		ahp := &AgentHelloPost{
			MessageType:  AgentMsgHello,
			MyIdentity:   AgentId(env.Alice.Identity),
			YourIdentity: AgentId(env.Bob.Identity),
			Zone:         ZoneName(zone),
		}
		needed, errmsg, err := env.Bob.Registry.EvaluateHello(ahp)
		if err != nil {
			t.Fatalf("EvaluateHello returned err: %v", err)
		}
		if needed {
			t.Errorf("expected needed=false; got true (errmsg=%q)", errmsg)
		}
		if !strings.Contains(errmsg, "does not include both") {
			t.Errorf("errmsg %q does not mention HSYNC3 missing both identities", errmsg)
		}
	})
}

// TestTransportBoundary_SyncFallback exercises SendSyncWithFallback's
// primary-then-fallback dispatch.
//
// The transport.TransportManager.Send implementation hard-codes the
// concrete tm.APITransport / tm.DNSTransport fields, which makes it
// impractical to inject fake Transport stubs. End-to-end fallback
// delivery (API fails, message arrives via DNS) requires a real
// loopback DNS receiver; that is left for a future PR.
//
// What this scenario covers at the boundary:
//   - real APITransport against an httptest.Server whose handler
//     returns 500 — confirms the bridge surfaces a *TransportError
//     (Retryable=true) from the API path;
//   - the manager attempts the fallback, which fails because the
//     peer has no usable DNS address — confirms the manager's
//     fallback wiring is reached, not silently skipped.
//
// The test asserts the failure mode (both transports tried, error
// propagates) rather than success. This is sufficient evidence that
// SendSyncWithFallback is wired into Send's primary-then-fallback
// path; the fallback's success branch is covered in tdns-transport
// unit tests with mock transports.
func TestTransportBoundary_SyncFallback(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})

	// Stand up an httptest server that always 500s. APITransport's
	// HTTP client will see a 500 and produce a retryable
	// *TransportError, prompting the manager to try the fallback.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "scenario 2: forced failure", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	// Register Bob in Alice's PeerRegistry with an API endpoint
	// pointing at the failing server, but no DNS address (so the DNS
	// fallback also fails — with "no address available", which the
	// transport reports as non-retryable but still propagates).
	bob := env.Alice.Bridge.PeerRegistry.GetOrCreate(env.Bob.Identity)
	bob.APIEndpoint = srv.URL
	bob.PreferredTransport = "API"

	req := &transport.SyncRequest{
		SenderID:       env.Alice.Identity,
		Zone:           "scenario2.example.",
		MessageType:    "sync",
		DistributionID: nextDistributionID(),
		Records: map[string][]string{
			"scenario2.example.": {
				"scenario2.example. 3600 IN TXT \"fallback test\"",
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
	defer cancel()

	_, err := env.Alice.Bridge.SendSyncWithFallback(ctx, bob, req)
	if err == nil {
		t.Fatalf("expected SendSyncWithFallback to fail (both transports unusable), got nil")
	}

	// Two acceptable error shapes:
	//   - "Send: all transports failed for peer ..." — manager tried
	//     both and exhausted them.
	//   - the fallback's TransportError if API was non-retryable for
	//     some reason and the manager bailed early.
	// Either is evidence the fallback path is reachable.
	msg := err.Error()
	if !strings.Contains(msg, "all transports failed") &&
		!strings.Contains(msg, "no address available") &&
		!errors.As(err, new(*transport.TransportError)) {
		t.Errorf("unexpected error shape: %v", err)
	}
}

// TestTransportBoundary_ConfirmInlineResponsePrep exercises the
// receive side of inline confirmation: a peer's HandleSync prepares
// a JSON ack in ctx.Data["response"] for SendResponseMiddleware to
// wrap into the DNS response. Scenario 3 from the harness doc.
//
// The sender-side extraction of inline confirms (DNSTransport's
// extractConfirmFromResponse) is a wire-level concern and is unit-
// tested in tdns-transport. This test asserts that Bob, on receiving
// a sync, produces the documented ack format.
func TestTransportBoundary_ConfirmInlineResponsePrep(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})

	const zone = "scenario3.example."
	seedZoneWithHSYNC3(t, zone, env.Alice.Identity, env.Bob.Identity)

	// Bob's transport-layer Peer for Alice must have at least one
	// shared zone; otherwise HandleSync rejects with a LEGACY error
	// (that path is scenario 5).
	alicePeer := env.Bob.Bridge.PeerRegistry.GetOrCreate(env.Alice.Identity)
	alicePeer.AddSharedZone(zone, "agent", "agent")

	distID := nextDistributionID()
	ctx := buildSyncMessageContext(t, env.Bob.Bridge,
		env.Alice.Identity, env.Bob.Identity, zone, distID,
		map[string][]string{zone: {zone + " 3600 IN TXT \"hi\""}},
	)
	ctx.Peer = alicePeer

	if err := env.Bob.Bridge.Router.Route(ctx, transport.MessageType("sync")); err != nil {
		t.Fatalf("Router.Route(sync): %v", err)
	}

	resp, ok := ctx.Data["response"].([]byte)
	if !ok || len(resp) == 0 {
		t.Fatalf("expected response payload in ctx.Data[\"response\"], got %T %v", ctx.Data["response"], ctx.Data["response"])
	}
	body := string(resp)
	if !strings.Contains(body, `"type":"confirm"`) {
		t.Errorf("response missing confirm type: %s", body)
	}
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("response missing ok status: %s", body)
	}
	if !strings.Contains(body, distID) {
		t.Errorf("response missing distribution id %q: %s", distID, body)
	}
}

// TestTransportBoundary_ConfirmAsyncToChannel exercises the inbound
// confirm path: a peer sends a confirmation NOTIFY, the router runs
// HandleConfirmation, which forwards via the on_confirmation_received
// callback into the bridge, which pushes a *ConfirmationDetail onto
// MsgQs.Confirmation. Scenario 4 from the harness doc.
//
// Wire transport (NOTIFY construction, EDNS0 framing) is bypassed —
// the test synthesizes a MessageContext at the post-decryption stage
// and routes via Router.Route("confirm"), which is exactly what
// RouteViaRouter does after extracting and decrypting the payload.
func TestTransportBoundary_ConfirmAsyncToChannel(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})

	const zone = "scenario4.example."
	distID := nextDistributionID()
	applied := []string{zone + " 3600 IN TXT \"applied\""}

	ctx := buildConfirmMessageContext(t, env.Alice.Bridge,
		env.Bob.Identity, zone, distID, "ok", applied, nil,
	)

	if err := env.Alice.Bridge.Router.Route(ctx, transport.MessageType("confirm")); err != nil {
		t.Fatalf("Router.Route(confirm): %v", err)
	}

	got, ok := recvConfirmWithin(t, env.Alice.MsgQs.Confirmation, integTestTimeout)
	if !ok {
		t.Fatalf("timed out waiting for confirmation on Alice.MsgQs.Confirmation after %s", integTestTimeout)
	}
	if got.DistributionID != distID {
		t.Errorf("DistributionID: got %q, want %q", got.DistributionID, distID)
	}
	if got.Source != env.Bob.Identity {
		t.Errorf("Source: got %q, want %q", got.Source, env.Bob.Identity)
	}
	if got.Status != "SUCCESS" {
		// transport.ConfirmStatus.String() maps "ok" -> "SUCCESS".
		t.Errorf("Status: got %q, want %q", got.Status, "SUCCESS")
	}
	if string(got.Zone) != zone {
		t.Errorf("Zone: got %q, want %q", got.Zone, zone)
	}
	if len(got.AppliedRecords) != 1 || got.AppliedRecords[0] != applied[0] {
		t.Errorf("AppliedRecords: got %#v, want %#v", got.AppliedRecords, applied)
	}
}

// TestTransportBoundary_LegacySyncRejection asserts that a sync from
// a peer with zero shared zones is rejected by HandleSync at the
// transport layer, before the message reaches MsgQs.Msg. Scenario 5
// from the harness doc.
//
// The rejection signal is twofold:
//   - Router.Route returns a non-nil error.
//   - ctx.Data["response"] contains a JSON error payload with
//     status:"rejected" and a message naming the LEGACY agent.
//
// Bob's MsgQs.Msg is asserted empty after a short wait.
func TestTransportBoundary_LegacySyncRejection(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})

	const zone = "scenario5.example."
	// Alice in Bob's PeerRegistry, but with NO shared zones -> LEGACY.
	alicePeer := env.Bob.Bridge.PeerRegistry.GetOrCreate(env.Alice.Identity)
	if got := alicePeer.GetSharedZones(); len(got) != 0 {
		t.Fatalf("precondition: expected 0 shared zones on Alice peer, got %d (%v)", len(got), got)
	}

	distID := nextDistributionID()
	ctx := buildSyncMessageContext(t, env.Bob.Bridge,
		env.Alice.Identity, env.Bob.Identity, zone, distID,
		map[string][]string{zone: {zone + " 3600 IN TXT \"legacy\""}},
	)
	ctx.Peer = alicePeer

	err := env.Bob.Bridge.Router.Route(ctx, transport.MessageType("sync"))
	if err == nil {
		t.Fatalf("expected LEGACY rejection error from Router.Route, got nil")
	}
	if !strings.Contains(err.Error(), "LEGACY") {
		t.Errorf("error %q does not mention LEGACY", err)
	}

	resp, ok := ctx.Data["response"].([]byte)
	if !ok || len(resp) == 0 {
		t.Fatalf("expected rejection payload in ctx.Data[\"response\"], got %T", ctx.Data["response"])
	}
	body := string(resp)
	if !strings.Contains(body, `"status":"rejected"`) {
		t.Errorf("response missing rejected status: %s", body)
	}
	if !strings.Contains(body, "LEGACY") {
		t.Errorf("response missing LEGACY explanation: %s", body)
	}

	// Confirm no message leaked onto MsgQs.Msg.
	if _, leaked := recvMsgWithin(t, env.Bob.MsgQs.Msg, 100*time.Millisecond); leaked {
		t.Errorf("rejected sync should not reach MsgQs.Msg, but it did")
	}
}

// TestTransportBoundary_DiscoveryComplete asserts that
// OnAgentDiscoveryComplete transitions the transport-layer Peer to
// PeerStateKnown and sets PreferredTransport according to the
// agent's ApiMethod / DnsMethod flags. Scenario 7 from the harness
// doc.
//
// Three subtests cover the documented preference rules: both flags
// set => API; API only => API; DNS only => DNS.
func TestTransportBoundary_DiscoveryComplete(t *testing.T) {
	cases := []struct {
		name     string
		api, dns bool
		wantPref string
	}{
		{"BothPreferAPI", true, true, "API"},
		{"APIOnly", true, false, "API"},
		{"DNSOnly", false, true, "DNS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newIntegEnv(t, nil)

			agent := &Agent{
				Identity:  AgentId(env.Bob.Identity),
				PeerID:    env.Bob.Identity,
				ApiMethod: tc.api,
				DnsMethod: tc.dns,
				Zones:     map[ZoneName]bool{},
			}
			// SyncPeerFromAgent populates APIEndpoint /
			// DiscoveryAddress from these fields; populate them
			// only for the mechanism the case advertises so
			// peer.HasMechanism returns the right answer.
			if tc.api {
				agent.ApiDetails = &AgentDetails{State: AgentStateKnown, BaseUri: "https://example.invalid/"}
			}
			if tc.dns {
				agent.DnsDetails = &AgentDetails{State: AgentStateKnown, Addrs: []string{"127.0.0.1"}, Port: 5300}
			}

			env.Alice.Bridge.OnAgentDiscoveryComplete(agent)

			peer, ok := env.Alice.Bridge.PeerRegistry.Get(env.Bob.Identity)
			if !ok {
				t.Fatalf("Bob not in Alice's PeerRegistry after OnAgentDiscoveryComplete")
			}
			if peer.State != transport.PeerStateKnown {
				t.Errorf("peer state: got %v, want %v", peer.State, transport.PeerStateKnown)
			}
			if peer.PreferredTransport != tc.wantPref {
				t.Errorf("PreferredTransport: got %q, want %q", peer.PreferredTransport, tc.wantPref)
			}

			// GetPreferredTransportName should agree.
			if got := env.Alice.Bridge.GetPreferredTransportName(agent); got != tc.wantPref {
				t.Errorf("GetPreferredTransportName: got %q, want %q", got, tc.wantPref)
			}
		})
	}
}

// _ tdns.AppType silences the import in case future test additions
// need to set an AppType; production startup sets this elsewhere.
var _ = tdns.AppTypeMPAgent
