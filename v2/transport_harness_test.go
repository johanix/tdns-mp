/*
 * Transport-boundary integration test harness for tdns-mp.
 *
 * Scope: scenarios 1-7 of docs/2026-04-23-transport-boundary-test-harness.md.
 * PR-1 covers the harness skeleton plus scenarios 1 and 6; remaining
 * scenarios (and the EDNS(0) chunk-mode variant of scenario 1) follow
 * in PR-2.
 *
 * Package choice: same-package (`package tdnsmp`) so tests can call
 * unexported helpers like routeIncomingMessage and look at
 * msgQs/agentRegistry without exporting them. The harness doc allows
 * both same-package and `_test` package; same-package wins on access.
 *
 * Globals: tdns.Zones is process-global. Each helper that seeds a zone
 * registers a t.Cleanup to drop the zone when the test ends.
 */

package tdnsmp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// integTestTimeout is the default channel-receive timeout. Scenarios 1
// and 6 in PR-1 are local and synchronous-after-callback; 2s is plenty.
// PR-2 may add scenarios that need longer; gate behind an env var then.
const integTestTimeout = 2 * time.Second

// integControlZone is the shared HSYNC control zone used by all
// scenarios. Must be FQDN.
const integControlZone = "mp-control.example."

// peerEnv is the per-peer fixture: identity plus the production objects
// the harness has wired together.
type peerEnv struct {
	Identity string // FQDN, trailing dot

	Registry *AgentRegistry
	Bridge   *MPTransportBridge
	MsgQs    *MsgQs
}

// integEnv is the two-peer fixture returned by newIntegEnv. Both peers
// share integControlZone.
type integEnv struct {
	t *testing.T

	Alice *peerEnv
	Bob   *peerEnv

	ctx    context.Context
	cancel context.CancelFunc
}

// integEnvConfig configures the harness. Most knobs are scenario-specific
// and default to "scenario 1 / scenario 6 friendly" if zero.
type integEnvConfig struct {
	// ChunkMode selects the bridge's outbound chunk mode. Empty defaults
	// to "query" for PR-1; "edns0" is exercised by PR-2.
	ChunkMode string

	// SkipBridge, when true, builds Registry+MsgQs but no MPTransportBridge.
	// Used by scenario 6, which only needs EvaluateHello on the registry.
	SkipBridge bool
}

// newIntegEnv builds two in-process peers, "Alice" and "Bob", each
// with its own AgentRegistry, MsgQs, and (unless SkipBridge) an
// MPTransportBridge pointing at the shared control zone. No real
// network is started; scenarios drive bridges via the production
// callbacks (e.g. routeIncomingMessage) directly.
func newIntegEnv(t *testing.T, cfg *integEnvConfig) *integEnv {
	t.Helper()
	if cfg == nil {
		cfg = &integEnvConfig{}
	}
	chunkMode := cfg.ChunkMode
	if chunkMode == "" {
		chunkMode = "query"
	}

	ctx, cancel := context.WithCancel(context.Background())

	env := &integEnv{
		t:      t,
		ctx:    ctx,
		cancel: cancel,
	}

	env.Alice = newPeer(t, "alice.agent.example.", chunkMode, cfg.SkipBridge)
	env.Bob = newPeer(t, "bob.agent.example.", chunkMode, cfg.SkipBridge)

	t.Cleanup(func() {
		cancel()
	})

	return env
}

// newPeer constructs a single peer's Registry, MsgQs and (optionally)
// MPTransportBridge. The bridge is configured for "scenario 1" needs:
// dns transport on, control zone set, no payload crypto, no chunk
// payload store (scenario 1 calls routeIncomingMessage directly so
// the chunk fetch path is not exercised).
func newPeer(t *testing.T, identity, chunkMode string, skipBridge bool) *peerEnv {
	t.Helper()

	mp := &tdns.MultiProviderConf{Identity: identity}
	registry := &AgentRegistry{
		S:                    core.NewStringer[AgentId, *Agent](),
		RemoteAgents:         make(map[ZoneName][]AgentId),
		LocalAgent:           mp,
		LocateInterval:       30,
		helloContexts:        make(map[AgentId]context.CancelFunc),
		ProviderGroupManager: NewProviderGroupManager(identity),
		GossipStateTable:     NewGossipStateTable(identity),
	}

	msgQs := &MsgQs{
		// Scenario 1 receives on Msg.
		Msg: make(chan *AgentMsgPostPlus, 4),
		// Scenario 6 doesn't push to channels, but Hello/Beat are cheap.
		Hello: make(chan *AgentMsgReport, 4),
		Beat:  make(chan *AgentMsgReport, 4),
		// PR-2 scenarios use these:
		Confirmation: make(chan *ConfirmationDetail, 4),
	}

	pe := &peerEnv{
		Identity: identity,
		Registry: registry,
		MsgQs:    msgQs,
	}
	if skipBridge {
		return pe
	}

	cfg := &MPTransportBridgeConfig{
		LocalID:             identity,
		ControlZone:         integControlZone,
		APITimeout:          2 * time.Second,
		DNSTimeout:          2 * time.Second,
		AgentRegistry:       registry,
		MsgQs:               msgQs,
		ChunkMode:           chunkMode,
		SupportedMechanisms: []string{"api", "dns"},
		// AuthorizedPeers is consulted at chunk-handler entry. Tests
		// drive routeIncomingMessage directly, so authorization is
		// not exercised; a permissive callback keeps any indirect
		// path happy without coupling tests to authorization rules.
		AuthorizedPeers: func() []string { return nil },
	}
	pe.Bridge = NewMPTransportBridge(cfg)
	registry.MPTransport = pe.Bridge
	registry.TransportManager = pe.Bridge.TransportManager

	return pe
}

// seedZoneWithHSYNC3 inserts a Ready MapZone into tdns.Zones with the
// given identities present in an HSYNC3 RRset at the apex. Each
// identity becomes one HSYNC3 record with State=ON, Label=<short>,
// Identity=<fqdn>, Upstream=".". Registers a t.Cleanup that removes
// the zone from tdns.Zones.
//
// Pass identities as the FQDNs that should appear in HSYNC3. The
// harness derives a short label by stripping the first DNS label.
//
// To create a zone with NO HSYNC3, pass identities=nil. To create a
// zone where HSYNC3 exists but excludes some identity, just omit it
// from identities.
func seedZoneWithHSYNC3(t *testing.T, zoneName string, identities ...string) *tdns.ZoneData {
	t.Helper()
	zoneName = dns.Fqdn(zoneName)

	zd := &tdns.ZoneData{
		ZoneName:  zoneName,
		ZoneStore: tdns.MapZone,
		ZoneType:  tdns.Primary,
		Data:      core.NewCmap[tdns.OwnerData](),
		Options:   make(map[tdns.ZoneOption]bool),
		Ready:     true,
	}

	apex := tdns.NewOwnerData(zoneName)
	if len(identities) > 0 {
		rrset := core.RRset{}
		for _, ident := range identities {
			ident = dns.Fqdn(ident)
			label := shortLabel(ident)
			h3 := &core.HSYNC3{
				State:    1, // ON
				Label:    label,
				Identity: ident,
				Upstream: ".",
			}
			prr := &dns.PrivateRR{
				Hdr: dns.RR_Header{
					Name:   zoneName,
					Rrtype: core.TypeHSYNC3,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Data: h3,
			}
			rrset.RRs = append(rrset.RRs, prr)
		}
		apex.RRtypes.Set(core.TypeHSYNC3, rrset)
	}
	zd.Data.Set(zoneName, *apex)

	tdns.Zones.Set(zoneName, zd)

	t.Cleanup(func() {
		tdns.Zones.Remove(zoneName)
		// Also drop the MP wrapper cache entry so a follow-up test
		// that reuses the same zone name does not see a stale wrapper.
		Zones.Invalidate(zoneName)
	})

	return zd
}

// shortLabel takes an FQDN and returns its first label, used as a
// human-readable HSYNC3 Label.
func shortLabel(fqdn string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	if i := strings.Index(fqdn, "."); i >= 0 {
		return fqdn[:i]
	}
	return fqdn
}

// recvMsgWithin reads one *AgentMsgPostPlus from ch with a timeout. It
// returns the message and true on success, nil and false on timeout.
// The caller should t.Fatalf on false; this helper does not so the
// caller can produce a richer error message.
func recvMsgWithin(t *testing.T, ch <-chan *AgentMsgPostPlus, d time.Duration) (*AgentMsgPostPlus, bool) {
	t.Helper()
	select {
	case msg := <-ch:
		return msg, true
	case <-time.After(d):
		return nil, false
	}
}

// makeSyncIncomingMessage builds a *transport.IncomingMessage carrying
// a sync payload from senderID to receiverID for the given zone, with
// the supplied records. The harness does NOT exercise the chunk
// authorization or decryption layers; it constructs the message that
// would emerge from those layers and hands it to routeIncomingMessage.
func makeSyncIncomingMessage(t *testing.T, senderID, receiverID, zone, distributionID string, records map[string][]string) *transport.IncomingMessage {
	t.Helper()
	payload := transport.DnsSyncPayload{
		MessageType:    "sync",
		OriginatorID:   senderID,
		YourIdentity:   receiverID,
		Zone:           zone,
		Records:        records,
		Time:           time.Now().Format(time.RFC3339),
		Timestamp:      time.Now().Unix(),
		DistributionID: distributionID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal sync payload: %v", err)
	}
	return &transport.IncomingMessage{
		Type:            "sync",
		DistributionID:  distributionID,
		SenderID:        senderID,
		TransportSender: senderID, // direct delivery, no relay
		Zone:            zone,
		Payload:         body,
		ReceivedAt:      time.Now(),
		SourceAddr:      "127.0.0.1:0",
	}
}

// nonceCounter ensures unique distribution IDs across parallel tests.
var nonceCounter = struct {
	mu sync.Mutex
	n  uint64
}{}

// nextDistributionID returns a unique distribution-id-like string for
// use in scenario payloads. Format mirrors production loosely; only
// uniqueness matters for the assertions.
func nextDistributionID() string {
	nonceCounter.mu.Lock()
	defer nonceCounter.mu.Unlock()
	nonceCounter.n++
	return fmt.Sprintf("d%d-%d", time.Now().UnixNano(), nonceCounter.n)
}
