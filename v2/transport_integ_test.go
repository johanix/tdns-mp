/*
 * Transport-boundary integration tests.
 * See transport_harness_test.go for the env builder and helpers.
 *
 * PR-1 covers:
 *   - Scenario 1: CHUNK NOTIFY -> Msg channel (chunk_mode=query)
 *   - Scenario 6: Hello rejection (3 subtests: UnknownZone, NoHSYNC3,
 *                 SenderNotInHSYNC3)
 *
 * The other five scenarios, plus the chunk_mode=edns0 variant of
 * scenario 1, land in PR-2.
 */

package tdnsmp

import (
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// TestTransportBoundary_ChunkToMsg drives a sync IncomingMessage into
// Bob's bridge via the same callback the production CHUNK handler
// invokes (routeIncomingMessage), and asserts the message surfaces on
// Bob's MsgQs.Msg channel with the expected sender, zone, and records.
//
// Scope: this test exercises the boundary between transport-layer
// message delivery (where IncomingMessage is constructed) and the MP
// MsgQs surface. The CHUNK fetch / decryption / authorization layers
// are intentionally out of scope here — they are exercised by their
// own unit tests in tdns-transport.
func TestTransportBoundary_ChunkToMsg(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{ChunkMode: "query"})

	const zoneName = "scenario1.example."
	// HSYNC3 must include both Alice and Bob for an HSYNC-aware path.
	// routeSyncMessage itself does not consult HSYNC3 (auth is upstream),
	// but seeding is cheap and keeps the fixture realistic.
	seedZoneWithHSYNC3(t, zoneName, env.Alice.Identity, env.Bob.Identity)

	distID := nextDistributionID()
	records := map[string][]string{
		zoneName: {
			"scenario1.example. 3600 IN TXT \"hello from alice\"",
		},
	}
	msg := makeSyncIncomingMessage(t,
		env.Alice.Identity, env.Bob.Identity,
		zoneName, distID, records,
	)

	// Drive the production callback. This is what
	// MPTransportBridge.StartIncomingMessageRouter wires up via
	// transport.RouteToCallback, with auth and decryption already
	// performed upstream of the callback.
	env.Bob.Bridge.routeIncomingMessage(msg)

	got, ok := recvMsgWithin(t, env.Bob.MsgQs.Msg, integTestTimeout)
	if !ok {
		t.Fatalf("scenario 1: timed out waiting for sync on Bob.MsgQs.Msg after %s", integTestTimeout)
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
		// "sync" decodes to AgentMsgNotify per routeSyncMessage default;
		// confirm here so we catch a regression in the type mapping.
		t.Errorf("MessageType: got %v, want %v (AgentMsgNotify)", got.MessageType, AgentMsgNotify)
	}
	if len(got.Records[zoneName]) == 0 {
		t.Errorf("Records[%q] missing or empty: got %#v", zoneName, got.Records)
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

// _ tdns.AppType silences the import in case future test additions
// need to set an AppType; production startup sets this elsewhere.
var _ = tdns.AppTypeMPAgent
