/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Transport integration for HsyncEngine.
 * Bridges the transport abstraction package with the existing hsyncengine.
 */

package tdnsmp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

var lgTransport = tdns.Logger("transport")
var lgConnRetry = tdns.Logger("conn-retry")

// MPTransportBridge manages multiple transports for agent communication.
// MPTransportBridge aggregates MP-specific transport state and methods.
// It holds a reference to the generic transport.TransportManager and
// adds multi-provider functionality (message routing, authorization,
// agent discovery, DNSKEY propagation, reliable delivery wrappers).
type MPTransportBridge struct {
	role                        string // agent|auditor|signer|combiner (D3: selects the startup wiring)
	beatInterval                uint32 // D2: LivenessInterval stamped on discovered agent peers
	*transport.TransportManager        // generic (fields promoted via embedding)

	agentRegistry *AgentRegistry
	msgQs         *MsgQs

	// SupportedMechanisms lists active transports ("api", "dns")
	SupportedMechanisms []string

	// combinerID is the AgentId of the combiner (from config), used by EnqueueForCombiner.
	combinerID AgentId

	// signerID is the identity of the local signer (tdns-auth) for KEYSTATE signaling.
	signerID string
	// signerAddress is the DNS address (host:port) of the local signer.
	signerAddress string

	// pendingDnskeyPropagations tracks DNSKEY distributions awaiting confirmation from all remote agents.
	// Key: distributionID. When all expected agents confirm, KEYSTATE "propagated" is sent to signer.
	pendingDnskeyPropagations map[string]*PendingDnskeyPropagation
	dnskeyPropMu              sync.Mutex

	// authorizedPeers returns the list of peer identities authorized via config.
	// Injected at config time; role-specific (each role provides its own list).
	authorizedPeers func() []string

	// messageRetention returns retention seconds for a given message type.
	// Used by distribution cache for expiration. If nil, default retention is used.
	messageRetention func(operation string) int

	// getImrEngine returns the IMR resolver for DNS-based agent discovery (optional).
	// Uses a closure because ImrEngine starts asynchronously after TM creation.
	getImrEngine func() *Imr

	// getZone returns zone data by name. Injected to avoid coupling to global Zones.
	// Used by HSYNC3-based authorization in agent_authorization.go.
	getZone func(name string) (*tdns.ZoneData, bool)
	// getZoneNames returns all known zone names. Same purpose as getZone.
	getZoneNames func() []string

	keystateRfiMu    sync.Mutex
	keystateRfiState map[string]chan *KeystateInventoryMsg // key: zone name
}

func (tm *MPTransportBridge) setKeystateRfi(zone string, ch chan *KeystateInventoryMsg) {
	tm.keystateRfiMu.Lock()
	defer tm.keystateRfiMu.Unlock()
	if tm.keystateRfiState == nil {
		tm.keystateRfiState = make(map[string]chan *KeystateInventoryMsg)
	}
	tm.keystateRfiState[zone] = ch
}

func (tm *MPTransportBridge) deleteKeystateRfi(zone string) {
	tm.keystateRfiMu.Lock()
	defer tm.keystateRfiMu.Unlock()
	delete(tm.keystateRfiState, zone)
}

// isTransportReady reports whether the named mechanism on the canonical
// transport.Peer is in a state where the peer can receive app messages — the
// same handshaked-state OR as the beat send gates. Reads the RAW (non-decayed)
// mechanism state via mechStateForGate: readiness is "have we handshaked", not
// liveness — the ReliableMessageQueue's own retry/backoff owns delivery
// failures, so DEGRADED/INTERRUPTED stay eligible. LEGACY needs no case here:
// it is the MP display overlay; at mechanism level such a peer reads
// OPERATIONAL.
func isTransportReady(peer *transport.Peer, mech string) bool {
	st, ok := mechStateForGate(peer, mech)
	if !ok {
		return false
	}
	switch st {
	case AgentStateOperational, AgentStateIntroduced,
		AgentStateDegraded, AgentStateInterrupted:
		return true
	default:
		return false
	}
}

// recipientTransportReady is the ReliableMessageQueue's IsRecipientReady
// predicate: the recipient must be a known agent AND have at least one
// handshaked mechanism on the canonical transport.Peer store. It must NOT
// read agent.{Api,Dns}Details.State — that sidecar stopped being written at
// END.0/D2.5, so gating on it deferred every queued message to an agent
// recipient until the 24h expiry (a reader the END.0 census missed).
func recipientTransportReady(ar *AgentRegistry, peers *transport.PeerRegistry, recipientID string) bool {
	if ar == nil {
		// Roles constructed without an AgentRegistry (combiner/signer) keep
		// the pre-existing always-ready behavior.
		return true
	}
	if _, exists := ar.S.Get(AgentId(recipientID)); !exists {
		return false
	}
	peer, ok := peers.Get(recipientID)
	if !ok {
		return false
	}
	return isTransportReady(peer, "DNS") || isTransportReady(peer, "API")
}

func (tm *MPTransportBridge) getKeystateRfi(zone string) (chan *KeystateInventoryMsg, bool) {
	tm.keystateRfiMu.Lock()
	defer tm.keystateRfiMu.Unlock()
	ch, ok := tm.keystateRfiState[zone]
	return ch, ok
}

// MPTransportBridgeConfig holds configuration for creating a MPTransportBridge.
type MPTransportBridgeConfig struct {
	// Role selects the application verb set registered on the router
	// (C3): "agent", "auditor", "signer" or "combiner". Empty means agent.
	Role          string
	LocalID       string
	ControlZone   string
	APITimeout    time.Duration
	DNSTimeout    time.Duration
	AgentRegistry *AgentRegistry
	MsgQs         *MsgQs
	// BeatInterval is our beat interval towards agent peers (seconds); it
	// is stamped as LivenessInterval on every discovered agent peer (D2).
	// Zero keeps transport's default.
	BeatInterval uint32
	// ChunkMode: "edns0" or "query"; when "query", agent stores payload and sends NOTIFY without EDNS0; receiver fetches via CHUNK query
	ChunkMode         string
	ChunkPayloadStore ChunkPayloadStore
	// ChunkQueryEndpoint: for query mode, address (host:port) where agent answers CHUNK queries
	ChunkQueryEndpoint string
	// ChunkQueryEndpointInNotify: when true, include endpoint in NOTIFY (EDNS0 option 65005); when false, receiver uses static config (e.g. combiner.agents[].address)
	ChunkQueryEndpointInNotify bool
	// ChunkMaxSize: maximum data chunk size in bytes for PrepareDistributionChunks.
	// 0 = default (60000). Set small (e.g. 500) for fragmentation testing.
	ChunkMaxSize int

	// PayloadCrypto enables JWS/JWE encryption for CHUNK payloads (optional)
	// If set and Enabled, all outgoing CHUNK payloads will be encrypted and signed
	PayloadCrypto *transport.PayloadCrypto

	// DistributionCache: when set, outgoing CHUNK operations (ping, hello, etc.) are registered for "agent distrib list"
	DistributionCache *DistributionCache

	// SupportedMechanisms lists active transports ("api", "dns"); default: both if configured
	SupportedMechanisms []string

	// CombinerID is the identity of the combiner for this agent (from config).
	// Used by EnqueueForCombiner to know which AgentRegistry entry is the combiner.
	CombinerID string

	// SignerID is the identity of the local signer for KEYSTATE signaling (Phase 6).
	SignerID string
	// SignerAddress is the DNS address (host:port) of the local signer.
	SignerAddress string

	// AuthorizedPeers returns the list of peer identities authorized via config.
	// Called at runtime during authorization. Each role provides its own implementation.
	// If nil, only HSYNC-based and LEGACY-based authorization is used.
	AuthorizedPeers func() []string

	// MessageRetention returns retention seconds for a given message type (operation).
	// Used by distribution cache for expiration. If nil, default retention is used.
	MessageRetention func(operation string) int

	// GetImrEngine returns the IMR resolver for DNS-based agent discovery (optional).
	// Uses a closure because ImrEngine starts asynchronously after TM creation.
	// Only the agent needs this; combiner/signer/external apps pass nil.
	GetImrEngine func() *Imr

	// GetZone returns zone data by name. Injected to decouple from global Zones.
	// Only needed by roles that use HSYNC3-based authorization (agent).
	GetZone func(name string) (*tdns.ZoneData, bool)
	// GetZoneNames returns all known zone names.
	GetZoneNames func() []string

	// ClientCertFile and ClientKeyFile are the TLS client certificate presented when
	// connecting to peers' sync API servers. Required when peers enforce mutual TLS
	// (e.g. combiner/signer sync routers verify client cert against agent's TLSA record).
	ClientCertFile string
	ClientKeyFile  string
}

// NewTransportManager creates a new MPTransportBridge with both API and DNS transports.
func NewMPTransportBridge(cfg *MPTransportBridgeConfig) (*MPTransportBridge, error) {
	// Default to both transports if not specified (backward compatibility for tests)
	// Production configs MUST specify supported_mechanisms explicitly (validated at config load)
	supportedMechanisms := cfg.SupportedMechanisms
	if len(supportedMechanisms) == 0 {
		lgTransport.Warn("created without supported_mechanisms, defaulting to [api, dns]")
		supportedMechanisms = []string{"api", "dns"}
	}

	// Hoisted so the IsRecipientReady predicate can read the canonical
	// per-mechanism peer state (the literal below has no name to close over).
	peerRegistry := transport.NewPeerRegistry()

	tm := &MPTransportBridge{
		role:         cfg.Role,
		beatInterval: cfg.BeatInterval,
		TransportManager: &transport.TransportManager{
			PeerRegistry: peerRegistry,
			Router:       transport.NewDNSMessageRouter(),
			ReliableQueue: transport.NewReliableMessageQueue(&transport.ReliableMessageQueueConfig{
				IsRecipientReady: func(recipientID string) bool {
					return recipientTransportReady(cfg.AgentRegistry, peerRegistry, recipientID)
				},
			}),
			LocalID:     cfg.LocalID,
			ControlZone: cfg.ControlZone,
		},
		agentRegistry:             cfg.AgentRegistry,
		msgQs:                     cfg.MsgQs,
		SupportedMechanisms:       supportedMechanisms,
		combinerID:                AgentId(cfg.CombinerID),
		signerID:                  cfg.SignerID,
		signerAddress:             cfg.SignerAddress,
		pendingDnskeyPropagations: make(map[string]*PendingDnskeyPropagation),
		authorizedPeers:           cfg.AuthorizedPeers,
		messageRetention:          cfg.MessageRetention,
		getImrEngine:              cfg.GetImrEngine,
		getZone:                   cfg.GetZone,
		getZoneNames:              cfg.GetZoneNames,
	}

	// Always create API client transport — it's a pure HTTP client with no server-side
	// implications. An agent that only serves DNS can still act as an API client to
	// remote agents that serve API. supported_mechanisms controls the server role, not
	// the client role.
	apiTLSConfig := &tls.Config{
		// Peer certificates are validated against TLSA records (discovered via DNS),
		// not against the system CA store. Self-signed certs are the norm here.
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS13,
	}
	if cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		clientCert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			lgTransport.Error("failed to load API client certificate, outbound mTLS will not work",
				"certFile", cfg.ClientCertFile, "keyFile", cfg.ClientKeyFile, "err", err)
		} else {
			apiTLSConfig.Certificates = []tls.Certificate{clientCert}
			lgTransport.Info("API client certificate loaded", "certFile", cfg.ClientCertFile)
		}
	}
	tm.APITransport = transport.NewAPITransport(&transport.APITransportConfig{
		LocalID:        cfg.LocalID,
		DefaultTimeout: cfg.APITimeout,
		TLSConfig:      apiTLSConfig,
	})
	lgTransport.Info("API client transport enabled")

	// Create DNS transport if control zone is configured AND supported
	if cfg.ControlZone != "" && tm.isTransportSupported("dns") {
		dnsCfg := &transport.DNSTransportConfig{
			LocalID:                    cfg.LocalID,
			ControlZone:                cfg.ControlZone,
			Timeout:                    cfg.DNSTimeout,
			ChunkMode:                  cfg.ChunkMode,
			ChunkQueryEndpoint:         cfg.ChunkQueryEndpoint,
			ChunkQueryEndpointInNotify: cfg.ChunkQueryEndpointInNotify,
			ChunkMaxSize:               cfg.ChunkMaxSize,
			PayloadCrypto:              cfg.PayloadCrypto,
		}
		if cfg.ChunkPayloadStore != nil {
			store := cfg.ChunkPayloadStore
			dnsCfg.ChunkPayloadGet = func(qname string) ([]byte, uint8, bool) { return store.Get(qname) }
			dnsCfg.ChunkPayloadSet = func(qname string, payload []byte, format uint8) { store.Set(qname, payload, format) }
			dnsCfg.ChunkPayloadSetChunks = func(qname string, chunks []*core.CHUNK) { store.SetChunks(qname, chunks) }
		}
		if cfg.DistributionCache != nil {
			cache := cfg.DistributionCache
			dnsCfg.DistributionAdd = func(qname string, senderID string, receiverID string, operation string, distributionID string, payloadSize int) {
				now := time.Now()

				// Calculate expiration time based on message type (operation)
				// Use config retention times with sensible defaults
				var retentionSecs int
				if tm.messageRetention != nil {
					retentionSecs = tm.messageRetention(operation)
				} else {
					var m MessageRetentionConf
					retentionSecs = m.GetRetentionForMessageType(operation)
				}
				expiresAt := now.Add(time.Duration(retentionSecs) * time.Second)

				cache.Add(qname, &DistributionInfo{
					DistributionID: distributionID,
					SenderID:       senderID,
					ReceiverID:     receiverID,
					Operation:      operation,
					ContentType:    "",
					State:          "pending",
					PayloadSize:    payloadSize,
					CreatedAt:      now,
					CompletedAt:    nil,
					ExpiresAt:      &expiresAt,
					QNAME:          qname,
				})
			}
			dnsCfg.DistributionMarkCompleted = func(qname string) { cache.MarkCompleted(qname) }
		}
		tm.DNSTransport = transport.NewDNSTransport(dnsCfg)

		// Create CHUNK NOTIFY handler
		tm.ChunkHandler = transport.NewChunkNotifyHandler(
			cfg.ControlZone,
			cfg.LocalID,
			tm.DNSTransport,
		)
		tm.ChunkHandler.ParseApp = parseAppPayload // C5: the application parses its own payloads
		// Attach router to handler for new routing path
		tm.ChunkHandler.Router = tm.Router

		// In chunk_mode=query without EDNS0 CHUNK_QUERY_ENDPOINT, use configured peer address (e.g. agent.peers)
		tm.ChunkHandler.GetPeerAddress = func(senderID string) (string, bool) {
			peer, ok := tm.PeerRegistry.Get(senderID)
			if !ok || peer.CurrentAddress() == nil {
				return "", false
			}
			addr := peer.CurrentAddress()
			return fmt.Sprintf("%s:%d", addr.Host, addr.Port), true
		}

		// DoS mitigation: Check authorization BEFORE expensive operations (decryption, query fetch)
		tm.ChunkHandler.IsPeerAuthorized = func(senderID string, zone string) (bool, string) {
			return tm.IsPeerAuthorized(senderID, zone)
		}

		// Wire confirmation callback for reliable message queue and per-RR tracking
		tm.ChunkHandler.OnConfirmationReceived = func(distributionID string, senderID string, status transport.ConfirmStatus,
			zone string, applied []string, removed []string, rejected []transport.RejectedItemDTO, ignored []string, truncated bool, nonce string) {
			lgTransport.Debug("confirmation received", "distributionID", distributionID, "sender", senderID, "nonce", nonce)

			// Stop retrying on any definitive answer (success, failure, rejected, or ignored).
			// Only keep retrying for transient states (pending, partial).
			if tm.ReliableQueue != nil && (status == transport.ConfirmSuccess || status == transport.ConfirmFailed || status == transport.ConfirmRejected || status == transport.ConfirmIgnored) {
				tm.ReliableQueue.MarkConfirmed(distributionID, senderID)
			}

			// Phase 6: Check if this confirmation is for a pending DNSKEY propagation
			var rejItems []RejectedItemInfo
			for _, ri := range rejected {
				rejItems = append(rejItems, RejectedItemInfo{Record: ri.Record, Reason: ri.Reason})
			}
			tm.ProcessDnskeyConfirmation(distributionID, senderID, status.String(), rejItems)

			// Forward per-RR detail to SynchedDataEngine
			if tm.msgQs != nil && tm.msgQs.Confirmation != nil {
				detail := &ConfirmationDetail{
					DistributionID: distributionID,
					Zone:           ZoneName(zone),
					Source:         senderID,
					Status:         status.String(),
					AppliedRecords: applied,
					RemovedRecords: removed,
					RejectedItems:  rejItems,
					IgnoredRecords: ignored,
					Truncated:      truncated,
					Timestamp:      time.Now(),
				}
				select {
				case tm.msgQs.Confirmation <- detail:
				default:
					lgTransport.Warn("confirmation channel full, dropping detail", "distributionID", distributionID)
				}
			}
		}

		// Wire remote confirmation callback (two-phase protocol: Phase 7).
		// When this agent's combiner confirms a sync that originated from another agent,
		// send the final confirmation NOTIFY back to the originating agent.
		if tm.msgQs != nil {
			tm.msgQs.OnRemoteConfirmationReady = func(detail *RemoteConfirmationDetail) {
				go tm.sendRemoteConfirmation(detail)
			}
		}

		// Trigger discovery when we receive messages from authorized but undiscovered peers.
		// This is the "discovery kick" (Phase 4 gossip): when a beat arrives from a sender
		// whose verification key we don't have, flush IMR cache for that identity's discovery
		// names and retry. This unsticks the UNKNOWN→KNOWN transition when cached NXDOMAIN
		// is blocking discovery.
		tm.ChunkHandler.OnPeerDiscoveryNeeded = func(peerID string) {
			lgTransport.Info("discovery kick: flushing IMR cache and triggering discovery", "peer", peerID)

			// Flush IMR cache for this peer's discovery names before re-discovery
			if tm.getImrEngine != nil {
				if removed := flushDiscoveryCache(tm.getImrEngine(), peerID); removed > 0 {
					lgTransport.Info("flushed IMR cache for peer discovery", "peer", peerID, "removed", removed)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := tm.DiscoverAndRegisterAgent(ctx, peerID)
			if err != nil {
				lgTransport.Warn("discovery incomplete for peer", "peer", peerID, "err", err)
			} else {
				lgTransport.Info("successfully discovered peer, verification key now available", "peer", peerID)
			}
		}

		// Provide gossip for beat responses: when we receive a beat,
		// include our gossip state in the response so peers get
		// bidirectional state exchange on every beat round-trip.
		tm.ChunkHandler.GossipForPeer = func(peerID string) json.RawMessage {
			if tm.agentRegistry == nil || tm.agentRegistry.GossipStateTable == nil || tm.agentRegistry.ProviderGroupManager == nil {
				return nil
			}
			gossipMsgs := tm.agentRegistry.GossipStateTable.BuildGossipForPeer(
				peerID, tm.agentRegistry.ProviderGroupManager, tm.agentRegistry.LeaderElectionManager)
			if len(gossipMsgs) == 0 {
				return nil
			}
			data, _ := json.Marshal(gossipMsgs)
			return data
		}

		// Initialize router with handlers and middleware
		routerCfg := &transport.RouterConfig{
			TransportManager:             tm,
			PeerRegistry:                 tm.PeerRegistry,
			PayloadCrypto:                cfg.PayloadCrypto,
			TriggerDiscoveryOnMissingKey: true,
			AllowUnencrypted:             false,
			VerboseStats:                 false, // Set to true for verbose statistics logging
			Confirmations:                true,
		}
		lgTransport.Debug("router config", "peerRegistry", routerCfg.PeerRegistry, "peerRegistryNil", routerCfg.PeerRegistry == nil)
		if err := transport.InitializeRouter(tm.Router, routerCfg); err != nil {
			return nil, fmt.Errorf("router initialization: %w", err)
		}
		if tm.role == "" {
			tm.role = roleAgent
		}
		// A half-registered verb table would look like a live process with
		// no application receive path; refuse to construct instead (the
		// signer and combiner already fail main_init on the same errors).
		if err := tm.RegisterAppVerbs(tm.Router, tm.role); err != nil {
			return nil, fmt.Errorf("application verb registration (%s): %w", tm.role, err)
		}

		lgTransport.Info("DNS transport enabled")
	} else if cfg.ControlZone == "" {
		lgTransport.Info("DNS transport not configured (no control zone)")
	} else {
		lgTransport.Info("DNS transport disabled by configuration")
	}

	// Phase 2.6: the discovery-completion callback is now LIVE — transport's
	// RegisterDiscoveredPeer fires it after the process completes (it was
	// installed-but-never-invoked before; the ar-work happened inline in the
	// deleted RegisterDiscoveredAgent). MP's residue: materialize the *Agent
	// view and derive its capability flags from the per-mechanism discovery
	// outcome recorded on the peer (ContactInfo: "complete"/"partial" ⇒
	// mechanism offered, absent ⇒ not offered/not probed). The guarded KNOWN
	// promotions and preferred-transport derivation are kept here too —
	// idempotent after transport's own writes, and they keep the callback
	// self-sufficient for tests that drive it directly.
	tm.TransportManager.OnPeerDiscovered = func(peer *transport.Peer) {
		if tm.agentRegistry == nil {
			return
		}
		agent := tm.agentRegistry.agentViewForIdentity(AgentId(peer.ID),
			tm.isTransportSupported("api"), tm.isTransportSupported("dns"))
		if agent == nil {
			return
		}
		apiOffered := peer.MechanismContactInfo("API") != ""
		dnsOffered := peer.MechanismContactInfo("DNS") != ""
		agent.Mu.Lock()
		agent.ApiMethod = apiOffered
		agent.DnsMethod = dnsOffered
		agent.Mu.Unlock()
		// D2: stamp our beat interval as the peer's liveness interval so
		// decay-on-read uses the real cadence, not transport's default.
		if tm.beatInterval > 0 {
			peer.SetLivenessInterval(tm.beatInterval)
		}

		// Promote each usable ("complete") mechanism to KNOWN, but never
		// regress one already past KNOWN (a re-discovery must not knock an
		// OPERATIONAL/INTRODUCED transport back down).
		anyUsable := false
		for _, name := range []string{"API", "DNS"} {
			if peer.MechanismContactInfo(name) != "complete" {
				continue
			}
			anyUsable = true
			if s, present := peer.MechanismRawState(name); !present || s < transport.PeerStateKnown {
				peer.SetMechanismState(name, transport.PeerStateKnown, "discovery complete")
			}
		}

		// Set preferred transport based on what's offered
		switch {
		case apiOffered && dnsOffered:
			peer.PreferredTransport = "API"
			lgTransport.Info("agent has both API and DNS, preferring API", "agent", agent.ID)
		case apiOffered:
			peer.PreferredTransport = "API"
		case dnsOffered:
			peer.PreferredTransport = "DNS"
		}

		// Top-level State must agree with the per-mechanism truth:
		// EffectiveState() falls back to p.State when no mechanism is yet
		// OPERATIONAL+, so an unconditional SetState(KNOWN) here would make
		// gossip report KNOWN for a peer whose only mechanism never resolved
		// an address (the KNOWN/NEEDED contradiction, Fix C). Only declare
		// KNOWN if a mechanism actually became usable, never regressing.
		if anyUsable && peer.GetState() < transport.PeerStateKnown {
			peer.SetState(transport.PeerStateKnown, "discovery complete")
		}

		lgTransport.Info("agent discovery complete, view materialized", "agent", agent.ID, "anyUsable", anyUsable, "preferredTransport", peer.PreferredTransport)
	}

	// Symmetric failure-side seam (Bite D). Fired by MP's
	// attemptDiscovery when a discovery round fails; the loop
	// retries on the next tick, so this can fire repeatedly for
	// the same peer. Body mirrors the existing failure logging in
	// agent_utils.go so behaviour stays unchanged.
	tm.TransportManager.OnDiscoveryFailed = func(peer *transport.Peer, err error) {
		// Do NOT regress a peer that is already established. Discovery
		// attempts race: a chunk-notify "missing key" kick triggers a
		// discovery while a startup/retry discovery is still in flight, so
		// a STALE failing leg (e.g. a resolver i/o timeout) can fire
		// OnDiscoveryFailed AFTER a concurrent attempt already succeeded
		// and registered the peer's address. Slamming ERROR here then
		// clobbers a peer that is demonstrably reachable (EffectiveState
		// falls back to this top-level State, so the bogus ERROR surfaces
		// in the gossip matrix). A failure only means "not established" for
		// a peer that was never established — same truth-model principle as
		// Fix A/C: a failure on one path must not assert state over a peer
		// another path just proved good.
		if peer.GetState() >= transport.PeerStateKnown || peer.CurrentAddress() != nil {
			lgTransport.Warn("peer discovery failed but peer already established; not regressing to ERROR",
				"peer", peer.ID, "state", peer.GetState(), "err", err)
			return
		}
		peer.SetState(transport.PeerStateError, err.Error())
		lgTransport.Warn("peer discovery failed", "peer", peer.ID, "err", err)
	}

	// Phase 2.6: the transport-owned discovery process needs the local
	// mechanism set (Fix E — only supported transports are probed; the TM
	// literal above cannot set the unexported field) and a late-bound IMR
	// accessor (the resolver starts asynchronously). The TEMPORARY
	// DiscoveryDriver seam and MP's RunDiscovery are gone.
	tm.TransportManager.SetSupportedMechanisms(supportedMechanisms)
	if cfg.GetImrEngine != nil {
		getImr := cfg.GetImrEngine
		tm.TransportManager.GetImr = func() *transport.Imr {
			mpImr := getImr()
			if mpImr == nil || mpImr.Imr == nil {
				return nil
			}
			return &transport.Imr{Imr: mpImr.Imr}
		}
	}

	return tm, nil
}

// isTransportSupported checks if a transport mechanism is enabled in configuration.
func (tm *MPTransportBridge) isTransportSupported(mechanism string) bool {
	if len(tm.SupportedMechanisms) == 0 {
		return true // Default: all transports supported
	}
	for _, m := range tm.SupportedMechanisms {
		if m == mechanism {
			return true
		}
	}
	return false
}

// RegisterChunkNotifyHandler registers the CHUNK NOTIFY handler with tdns.
// This should be called during agent initialization.
func (tm *MPTransportBridge) RegisterChunkNotifyHandler() error {
	if tm.ChunkHandler == nil {
		return fmt.Errorf("DNS transport not configured (no control zone)")
	}

	// Register the handler for CHUNK type NOTIFYs
	// RouteViaRouter routes through the DNSMessageRouter with middleware
	err := tdns.RegisterNotifyHandler(core.TypeCHUNK, func(ctx context.Context, req *tdns.DnsNotifyRequest) error {
		return tm.ChunkHandler.RouteViaRouter(ctx, req.Qname, req.Msg, req.ResponseWriter)
	})
	if err != nil {
		return fmt.Errorf("failed to register CHUNK NOTIFY handler: %w", err)
	}

	lgTransport.Info("registered CHUNK NOTIFY handler", "controlZone", tm.ControlZone)
	return nil
}

// StartIncomingMessageRouter starts a goroutine that routes incoming DNS messages
// to the appropriate hsyncengine channels.
// ctx is intentionally unused: kept in the signature for API stability and future use.
func (tm *MPTransportBridge) StartIncomingMessageRouter(ctx context.Context) {
	if tm.ChunkHandler == nil {
		lgTransport.Info("DNS transport not configured, skipping incoming message router")
		return
	}

	// Register RouteToCallback middleware on the Router.
	// When a message arrives via CHUNK NOTIFY, the Router runs the handler
	// chain (auth, crypto, parse) and then calls our callback with the
	// parsed IncomingMessage. The callback dispatches to typed MsgQs
	// channels based on message type.
	//
	// Each message type fans out directly to its own MsgQs channel; the
	// single IncomingChan this replaced was deleted (C3.0).
	tm.Router.Use(transport.RouteToCallback(func(msg *transport.IncomingMessage) {
		tm.routeIncomingMessage(msg)
	}))

	lgTransport.Info("incoming message router registered via RouteToCallback")
}

// routeHelloMessage routes a hello message to the hello channel.
func (tm *MPTransportBridge) routeHelloMessage(msg *transport.IncomingMessage) {
	payload, err := transport.ParseHelloPayload(msg.Payload)
	if err != nil {
		lgTransport.Error("failed to parse hello payload", "err", err)
		return
	}

	// Authorization already verified by AuthorizationMiddleware in the router.
	// Messages reaching routeHelloMessage have passed middleware auth.
	senderID := payload.GetSenderID()
	lgTransport.Debug("processing authorized DNS hello", "sender", senderID)

	// DNS-37: inbound DNS hello accepted → INTRODUCING on the canonical
	// transport.Peer per-mechanism store. END.0: the top-level SetState is NOT
	// written on inbound receipt — top-level peer.State is the discovery-phase
	// marker (NEEDED/KNOWN/ERROR), set only by the discovery paths; INTRODUCING
	// is a per-mechanism fact. (Marker model; mirrors the truth-fix rule that
	// inbound receipt must not assert top-level state.)
	peer := tm.PeerRegistry.GetOrCreate(senderID)
	peer.LastHelloReceived = time.Now()
	if raw, ok := peer.MechanismRawState("DNS"); !ok || raw < transport.PeerStateIntroducing {
		peer.SetMechanismState("DNS", transport.PeerStateIntroducing, "DNS hello accepted and authorized")
	}
	peer.SetMechanismLastHelloRecv("DNS", peer.LastHelloReceived)

	// For an unknown (but authorized) sender, trigger discovery so we can beat
	// back. Contact timestamps live on transport.Peer above — the AgentDetails
	// telemetry mirror is gone (Phase 2).
	if tm.agentRegistry != nil {
		if _, exists := tm.agentRegistry.S.Get(AgentId(senderID)); !exists {
			// DNS-56: Agent not in registry but authorized - trigger discovery
			// This ensures receiver can send beats back to sender
			lgTransport.Info("authorized Hello from unknown agent, triggering discovery", "agent", senderID)
			go func(peerID string) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				err := tm.DiscoverAndRegisterAgent(ctx, peerID)
				if err != nil {
					lgTransport.Error("discovery failed for agent", "agent", peerID, "err", err)
				} else {
					lgTransport.Info("successfully discovered agent, now in registry", "agent", peerID)
				}
			}(senderID)
		}
	}

	// Convert to AgentMsgReport for the existing hsyncengine.
	// Use the first shared zone from the payload as the report's
	// Zone — downstream consumers (e.g. AuditorMsgHandler's
	// StateManager.GetOrCreateZone) gate on zone != "", and without
	// it the auditor never records a per-zone provider entry.
	report := &AgentMsgReport{
		MessageType:    AgentMsgHello,
		Identity:       AgentId(senderID),
		DistributionID: msg.DistributionID,
	}
	if zones := payload.GetSharedZones(); len(zones) > 0 {
		report.Zone = ZoneName(zones[0])
	}

	if tm.msgQs == nil {
		lgTransport.Debug("hello authorized but no agent queues (signer mode), ignoring", "sender", senderID)
		return
	}

	select {
	case tm.msgQs.Hello <- report:
		lgTransport.Debug("routed DNS hello to hsyncengine", "sender", senderID, "state", "INTRODUCING", "distributionID", msg.DistributionID)
	default:
		lgTransport.Warn("hello channel full, dropping message", "sender", senderID)
	}
}

// routeBeatMessage routes a beat message to the heartbeat channel.
func (tm *MPTransportBridge) routeBeatMessage(msg *transport.IncomingMessage) {
	payload, err := transport.ParseBeatPayload(msg.Payload)
	if err != nil {
		lgTransport.Error("failed to parse beat payload", "err", err)
		return
	}

	senderID := payload.GetSenderID() // Use helper method to get sender ID from either format

	// DNS-51: Authorization check for Beat messages
	// Beat includes Zones field (list of zones sender believes are shared)
	// Authorization already verified by AuthorizationMiddleware in the router.
	// Messages reaching routeBeatMessage have passed middleware auth.
	lgTransport.Debug("processing authorized DNS beat", "sender", senderID, "zones", payload.Zones)

	// Record inbound liveness ONLY. Receiving a beat proves the peer can
	// reach us — it does NOT prove we can reach them, which is what
	// OPERATIONAL means (a successful OUTBOUND beat round-trip; set in
	// SendBeatWithFallback). So we update LastBeatRecv evidence but do
	// not touch the connection state. The election trigger likewise
	// lives on the outbound success edge, not here.
	peer := tm.PeerRegistry.GetOrCreate(senderID)
	peer.LastBeatReceived = time.Now()
	peer.SetMechanismLastBeatRecv("DNS", peer.LastBeatReceived)

	// Inbound-liveness evidence lives on transport.Peer above (Phase 2: the
	// AgentDetails telemetry mirror is gone; the NG beat-age scanner it once
	// fed was already retired in D2.5).

	// Process gossip data if present
	if len(payload.Gossip) > 0 && tm.agentRegistry != nil && tm.agentRegistry.GossipStateTable != nil {
		var gossipMsgs []GossipMessage
		if err := json.Unmarshal(payload.Gossip, &gossipMsgs); err == nil {
			for i := range gossipMsgs {
				tm.agentRegistry.GossipStateTable.MergeGossip(&gossipMsgs[i])
			}
			lgTransport.Debug("merged gossip from incoming DNS beat", "sender", senderID, "groups", len(gossipMsgs))

			// Check group operational state after merge
			if tm.agentRegistry.ProviderGroupManager != nil {
				for i := range gossipMsgs {
					pg := tm.agentRegistry.ProviderGroupManager.GetGroup(gossipMsgs[i].GroupHash)
					if pg != nil {
						tm.agentRegistry.GossipStateTable.CheckGroupState(pg.GroupHash, pg.Members)
					}
				}
			}
		}
	}

	beatInterval := payload.MyBeatInterval
	if beatInterval == 0 {
		beatInterval = 30 // Default if not provided
	}

	// Propagate distribution ID from CHUNK qname into the report
	// (same pattern as DNS-87 fix for sync messages).
	distributionID := msg.DistributionID

	// Set Zone from the payload's Zones list so downstream consumers
	// (notably AuditorMsgHandler, which gates StateManager updates on
	// zone != "") can attribute the beat to its zone. Without this,
	// the auditor dashboard's provider list stays empty even though
	// beats are flowing — only HELLO-initiated state entries survive,
	// and HELLOs happen once per handshake while beats happen
	// continuously.
	report := &AgentMsgReport{
		Transport:      "DNS",
		MessageType:    AgentMsgBeat,
		Identity:       AgentId(senderID),
		BeatInterval:   beatInterval,
		DistributionID: distributionID,
	}
	if len(payload.Zones) > 0 {
		report.Zone = ZoneName(payload.Zones[0])
	}

	if tm.msgQs == nil {
		lgTransport.Debug("beat authorized but no agent queues (signer mode), ignoring", "sender", senderID)
		return
	}

	select {
	case tm.msgQs.Beat <- report:
		lgTransport.Debug("routed DNS beat to hsyncengine", "sender", senderID, "state", "OPERATIONAL", "distributionID", distributionID)
	default:
		lgTransport.Warn("beat channel full, dropping message", "sender", senderID)
	}
}

// routePingMessage updates peer liveness and routes to MsgQs.Ping.
// The DNS response was already sent synchronously by SendResponseMiddleware;
// this routing is for peer liveness tracking and counting.
func (tm *MPTransportBridge) routePingMessage(msg *transport.IncomingMessage) {
	senderID := msg.SenderID
	lgTransport.Debug("processing ping", "sender", senderID)

	// Record inbound liveness ONLY (a received ping proves they can reach
	// us, not that we can reach them). State is set by the outbound beat
	// path, not here.
	peer := tm.PeerRegistry.GetOrCreate(senderID)
	peer.LastBeatReceived = time.Now()
	peer.SetMechanismLastBeatRecv("DNS", peer.LastBeatReceived)

	report := &AgentMsgReport{
		MessageType:    AgentMsgPing,
		Identity:       AgentId(senderID),
		DistributionID: msg.DistributionID,
	}

	if tm.msgQs == nil {
		return
	}

	select {
	case tm.msgQs.Ping <- report:
		lgTransport.Debug("routed ping to MsgQs", "sender", senderID)
	default:
		lgTransport.Warn("ping channel full, dropping message", "sender", senderID)
	}
}

// routeSyncMessage routes a sync message to the message channel.
func (tm *MPTransportBridge) routeSyncMessage(msg *transport.IncomingMessage) {
	payload, err := ParseSyncPayload(msg.Payload)
	if err != nil {
		lgTransport.Error("failed to parse sync payload", "err", err)
		return
	}

	// The distribution ID is extracted from the CHUNK qname, not the JSON payload.
	// Propagate it into the parsed payload so downstream code (AgentMsgPost,
	// sendImmediateConfirmation) can access it uniformly.
	if msg.DistributionID != "" && payload.DistributionID == "" {
		payload.DistributionID = msg.DistributionID
	}

	senderID := payload.GetSenderID() // Use helper method to get sender ID from either format
	if senderID == "" && msg.TransportSender != "" {
		senderID = msg.TransportSender // Fallback to transport-level sender (from QNAME)
		lgTransport.Debug("payload had empty sender, using transport sender", "sender", senderID)
	}
	records := payload.GetRecords() // Use helper method to get records from either format
	zone := payload.Zone

	// Determine message type (sync, update, rfi, or status)
	messageType := AgentMsgNotify // Default to sync
	if payload.MessageType != "" {
		messageType = AgentMsg(payload.MessageType)
	}
	msgTypeStr := core.AgentMsgToString[core.AgentMsg(messageType)]

	// Authorization already verified by AuthorizationMiddleware in the router.
	// Messages reaching routeSyncMessage have passed middleware auth.
	lgTransport.Debug("processing authorized DNS message", "msgType", msgTypeStr, "sender", senderID, "zone", zone, "transportSender", msg.TransportSender)

	// Record inbound liveness ONLY — receiving a message proves they can
	// reach us, not that we can reach them. State is set by the outbound
	// beat path (SendBeatWithFallback), never on inbound receipt.
	peer := tm.PeerRegistry.GetOrCreate(senderID)
	peer.LastBeatReceived = time.Now()

	// DeliveredBy is the transport-level sender (from QNAME), which may differ from
	// the originator for forwarded messages. The combiner needs this to send confirmations
	// back to the agent that actually delivered the message, not the original author.
	deliveredBy := msg.TransportSender
	if deliveredBy == "" {
		deliveredBy = senderID // Fallback for direct delivery
	}

	// Ensure the transport sender (deliverer) has a PeerRegistry entry with an address.
	// For forwarded messages, the deliverer may be a remote agent not pre-registered in this
	// combiner's config. Trigger async discovery so the address is available for confirmation.
	if deliveredBy != senderID {
		deliverPeer := tm.PeerRegistry.GetOrCreate(deliveredBy)
		// Inbound liveness only — do not assert OPERATIONAL on a delivery.
		deliverPeer.LastBeatReceived = time.Now()
		if deliverPeer.CurrentAddress() == nil {
			lgTransport.Info("transport sender has no address, triggering async discovery", "sender", deliveredBy)
			go func(peerID string) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := tm.DiscoverAndRegisterAgent(ctx, peerID); err != nil {
					lgTransport.Error("discovery failed for transport sender", "sender", peerID, "err", err)
				} else {
					lgTransport.Info("discovered transport sender", "sender", peerID)
				}
			}(deliveredBy)
		}
	}

	msgPost := &AgentMsgPostPlus{
		AgentMsgPost: AgentMsgPost{
			MessageType:    messageType,
			OriginatorID:   AgentId(senderID),
			DeliveredBy:    AgentId(deliveredBy),
			Zone:           ZoneName(zone),
			Records:        records,
			Operations:     payload.GetOperations(),
			Time:           time.Unix(payload.Timestamp, 0),
			RfiType:        payload.RfiType,        // Include RfiType for RFI messages
			RfiSubtype:     payload.RfiSubtype,     // Include RfiSubtype for CONFIG RFI messages
			DistributionID: payload.DistributionID, // Originating distID from sending agent
			Nonce:          msg.Nonce,              // Echo nonce from incoming message for confirmation
			ZoneClass:      payload.ZoneClass,
			Publish:        payload.GetPublish(),
		},
	}

	if tm.msgQs == nil {
		lgTransport.Debug("message authorized but no agent queues (signer mode), ignoring", "msgType", msgTypeStr, "sender", senderID)
		return
	}

	select {
	case tm.msgQs.Msg <- msgPost:
		lgTransport.Debug("routed DNS message to hsyncengine", "msgType", msgTypeStr, "sender", senderID, "zone", zone)

		// Send immediate "pending" confirmation back to originating agent (two-phase protocol).
		// This tells the originator "I received your sync" so it doesn't need to resend.
		// Only agents acting as relay (with an agentRegistry) send this — the combiner already
		// returned a "pending" ACK inline in the DNS response.
		if tm.agentRegistry != nil {
			go tm.sendImmediateConfirmation(payload)
		}
	default:
		lgTransport.Warn("message channel full, dropping message", "msgType", msgTypeStr, "sender", senderID)
	}
}

// routeKeystateMessage routes an incoming KEYSTATE message.
// For "inventory" signals, delivers the full key inventory to MsgQs.KeystateInventory
// so RequestAndWaitForKeyInventory can pick it up.
func (tm *MPTransportBridge) routeKeystateMessage(msg *transport.IncomingMessage) {
	var payload DnsKeystatePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		lgTransport.Error("failed to parse keystate payload", "err", err)
		return
	}

	senderID := payload.GetSenderID()
	lgTransport.Debug("processing KEYSTATE", "signal", payload.Signal, "sender", senderID, "zone", payload.Zone)

	if payload.Signal != "inventory" {
		// Per-key signals (propagated/rejected/removed) go to the dedicated KeystateSignal channel
		// so the SignerMsgHandler can process them. Falls back to routeSyncMessage if the channel
		// is not available (e.g. on an agent where this signal doesn't apply).
		if tm.msgQs != nil && tm.msgQs.KeystateSignal != nil {
			sigMsg := &KeystateSignalMsg{
				SenderID: senderID,
				Zone:     payload.Zone,
				KeyTag:   payload.KeyTag,
				Signal:   payload.Signal,
				Message:  payload.Message,
			}
			select {
			case tm.msgQs.KeystateSignal <- sigMsg:
				lgTransport.Info("routed KEYSTATE signal", "signal", payload.Signal, "sender", senderID, "zone", payload.Zone, "keyTag", payload.KeyTag)
			default:
				lgTransport.Warn("KeystateSignal channel full, dropping", "signal", payload.Signal, "sender", senderID)
			}
		} else {
			lgTransport.Debug("non-inventory KEYSTATE, no KeystateSignal channel, routing to Msg queue", "signal", payload.Signal, "sender", senderID)
			tm.routeSyncMessage(msg)
		}
		return
	}

	if tm.msgQs == nil {
		lgTransport.Debug("KEYSTATE inventory but no MsgQs, ignoring", "sender", senderID)
		return
	}

	// Convert KeyInventoryEntry → KeyInventoryItem for the channel
	items := make([]KeyInventoryItem, len(payload.KeyInventory))
	for i, e := range payload.KeyInventory {
		items[i] = KeyInventoryItem{
			KeyTag:    e.KeyTag,
			Algorithm: e.Algorithm,
			Flags:     e.Flags,
			State:     e.State,
			KeyRR:     e.KeyRR,
		}
	}

	inventoryMsg := &KeystateInventoryMsg{
		SenderID:  senderID,
		Zone:      payload.Zone,
		Inventory: items,
	}

	// If there's a pending RFI request waiting for this zone's inventory,
	// route there. Zone mismatches fall through to the shared channel.
	if ch, ok := tm.getKeystateRfi(payload.Zone); ok {
		select {
		case ch <- inventoryMsg:
			lgTransport.Info("routed KEYSTATE inventory to RFI requester", "sender", senderID, "zone", payload.Zone, "keys", len(items))
		default:
			lgTransport.Warn("keystateRfiChan full, dropping inventory", "sender", senderID)
		}
		return
	}

	select {
	case tm.msgQs.KeystateInventory <- inventoryMsg:
		lgTransport.Info("routed KEYSTATE inventory to agent", "sender", senderID, "zone", payload.Zone, "keys", len(items))
	default:
		lgTransport.Warn("KeystateInventory channel full, dropping inventory", "sender", senderID)
	}
}

// routeEditsMessage routes an incoming EDITS message from the combiner.
// Delivers the contributions to MsgQs.EditsResponse so RequestAndWaitForEdits can pick it up.
// Modeled on routeKeystateMessage.
func (tm *MPTransportBridge) routeEditsMessage(msg *transport.IncomingMessage) {
	var payload DnsEditsPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		lgTransport.Error("failed to parse edits payload", "err", err)
		return
	}

	senderID := payload.GetSenderID()
	lgTransport.Debug("processing EDITS", "sender", senderID, "zone", payload.Zone)

	if tm.msgQs == nil {
		lgTransport.Debug("EDITS received but no MsgQs, ignoring", "sender", senderID)
		return
	}

	editsMsg := &EditsResponseMsg{
		SenderID:     senderID,
		Zone:         payload.Zone,
		AgentRecords: payload.AgentRecords,
	}

	select {
	case tm.msgQs.EditsResponse <- editsMsg:
		lgTransport.Info("routed EDITS response to agent", "sender", senderID, "zone", payload.Zone, "agents", len(payload.AgentRecords))
	default:
		lgTransport.Warn("EditsResponse channel full, dropping edits", "sender", senderID)
	}
}

// routeConfigMessage routes an incoming CONFIG response message from a peer agent.
// Delivers the config data to MsgQs.ConfigResponse so RequestAndWaitForConfig can pick it up.
func (tm *MPTransportBridge) routeConfigMessage(msg *transport.IncomingMessage) {
	var payload DnsConfigPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		lgTransport.Error("failed to parse config payload", "err", err)
		return
	}

	senderID := payload.GetSenderID()
	lgTransport.Debug("processing CONFIG response", "sender", senderID, "zone", payload.Zone, "subtype", payload.Subtype)

	if tm.msgQs == nil {
		lgTransport.Debug("CONFIG received but no MsgQs, ignoring", "sender", senderID)
		return
	}

	configMsg := &ConfigResponseMsg{
		SenderID:   senderID,
		Zone:       payload.Zone,
		Subtype:    payload.Subtype,
		ConfigData: payload.ConfigData,
	}

	select {
	case tm.msgQs.ConfigResponse <- configMsg:
		lgTransport.Info("routed CONFIG response to agent", "sender", senderID, "zone", payload.Zone, "subtype", payload.Subtype)
	default:
		lgTransport.Warn("ConfigResponse channel full, dropping config", "sender", senderID)
	}
}

// sendConfigToAgent gathers config data for the given subtype and sends it as a separate
// CONFIG message back to the requesting agent. Called asynchronously from MsgHandler when
// an RFI CONFIG is received.
func sendConfigToAgent(tm *MPTransportBridge, ar *AgentRegistry, requesterID string, zone string, subtype string, configData map[string]string) {
	if tm == nil || tm.DNSTransport == nil {
		lgTransport.Warn("sendConfigToAgent: no DNSTransport available", "requester", requesterID)
		return
	}

	peer, peerExists := tm.PeerRegistry.Get(requesterID)
	if !peerExists || peer == nil {
		lgTransport.Warn("sendConfigToAgent: requester not in PeerRegistry", "requester", requesterID)
		return
	}

	req := &PeerConfigRequest{
		SenderID:   ar.LocalAgent.Identity,
		Zone:       zone,
		Subtype:    subtype,
		ConfigData: configData,
		Timestamp:  time.Now(),
	}

	sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := tm.sendConfig(sendCtx, peer, req)
	if err != nil {
		lgTransport.Error("sendConfigToAgent: failed to send", "requester", requesterID, "zone", zone, "subtype", subtype, "err", err)
		return
	}

	if !resp.Accepted {
		lgTransport.Error("sendConfigToAgent: config not accepted", "requester", requesterID, "zone", zone, "subtype", subtype, "accepted", resp.Accepted)
		return
	}
	lgTransport.Info("sendConfigToAgent: sent config to requester", "requester", requesterID, "zone", zone, "subtype", subtype)
}

// routeAuditMessage routes an incoming AUDIT response message from a peer agent.
// Delivers the audit data to MsgQs.AuditResponse so RequestAndWaitForAudit can pick it up.
func (tm *MPTransportBridge) routeAuditMessage(msg *transport.IncomingMessage) {
	var payload DnsAuditPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		lgTransport.Error("failed to parse audit payload", "err", err)
		return
	}

	senderID := payload.GetSenderID()
	lgTransport.Debug("processing AUDIT response", "sender", senderID, "zone", payload.Zone)

	if tm.msgQs == nil {
		lgTransport.Debug("AUDIT received but no MsgQs, ignoring", "sender", senderID)
		return
	}

	auditMsg := &AuditResponseMsg{
		SenderID:  senderID,
		Zone:      payload.Zone,
		AuditData: payload.AuditData,
	}

	select {
	case tm.msgQs.AuditResponse <- auditMsg:
		lgTransport.Info("routed AUDIT response to agent", "sender", senderID, "zone", payload.Zone)
	default:
		lgTransport.Warn("AuditResponse channel full, dropping audit", "sender", senderID)
	}
}

// routeStatusUpdateMessage routes an incoming STATUS-UPDATE notification.
// Delivers to MsgQs.StatusUpdate for processing by the role-specific message handler.
func (tm *MPTransportBridge) routeStatusUpdateMessage(msg *transport.IncomingMessage) {
	var payload DnsStatusUpdatePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		lgTransport.Error("failed to parse status-update payload", "err", err)
		return
	}

	senderID := payload.GetSenderID()
	lgTransport.Debug("processing STATUS-UPDATE", "sender", senderID, "zone", payload.Zone, "subtype", payload.SubType)

	if tm.msgQs == nil {
		lgTransport.Debug("STATUS-UPDATE received but no MsgQs, ignoring", "sender", senderID)
		return
	}

	statusMsg := &StatusUpdateMsg{
		SenderID:  senderID,
		Zone:      payload.Zone,
		SubType:   payload.SubType,
		NSRecords: payload.NSRecords,
		DSRecords: payload.DSRecords,
		Result:    payload.Result,
		Msg:       payload.Msg,
	}

	select {
	case tm.msgQs.StatusUpdate <- statusMsg:
		lgTransport.Info("routed STATUS-UPDATE to handler", "sender", senderID, "zone", payload.Zone, "subtype", payload.SubType)
	default:
		lgTransport.Warn("StatusUpdate channel full, dropping status-update", "sender", senderID)
	}
}

// sendAuditToAgent gathers audit data and sends it as a separate AUDIT message
// back to the requesting agent. Called asynchronously from MsgHandler when
// an RFI AUDIT is received.
func sendAuditToAgent(tm *MPTransportBridge, ar *AgentRegistry, requesterID string, zone string, auditData interface{}) {
	if tm == nil || tm.DNSTransport == nil {
		lgTransport.Warn("sendAuditToAgent: no DNSTransport available", "requester", requesterID)
		return
	}

	peer, peerExists := tm.PeerRegistry.Get(requesterID)
	if !peerExists || peer == nil {
		lgTransport.Warn("sendAuditToAgent: requester not in PeerRegistry", "requester", requesterID)
		return
	}

	req := &PeerAuditRequest{
		SenderID:  ar.LocalAgent.Identity,
		Zone:      zone,
		AuditData: auditData,
		Timestamp: time.Now(),
	}

	sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := tm.sendAudit(sendCtx, peer, req)
	if err != nil {
		lgTransport.Error("sendAuditToAgent: failed to send", "requester", requesterID, "zone", zone, "err", err)
		return
	}

	if !resp.Accepted {
		lgTransport.Error("sendAuditToAgent: audit not accepted", "requester", requesterID, "zone", zone, "accepted", resp.Accepted)
		return
	}
	lgTransport.Info("sendAuditToAgent: sent audit to requester", "requester", requesterID, "zone", zone)
}

// routeRelocateMessage handles a relocate request.
func (tm *MPTransportBridge) routeRelocateMessage(msg *transport.IncomingMessage) {
	payload, err := ParseRelocatePayload(msg.Payload)
	if err != nil {
		lgTransport.Error("failed to parse relocate payload", "err", err)
		return
	}

	// Authorization already verified by AuthorizationMiddleware in the router.
	// Messages reaching routeRelocateMessage have passed middleware auth.
	lgTransport.Debug("processing authorized DNS relocate", "sender", payload.SenderID)

	// Update peer's operational address
	peer, exists := tm.PeerRegistry.Get(payload.SenderID)
	if !exists {
		peer = tm.PeerRegistry.GetOrCreate(payload.SenderID)
	}

	peer.SetOperationalAddress(&transport.Address{
		Host:      payload.NewAddress.Host,
		Port:      payload.NewAddress.Port,
		Transport: payload.NewAddress.Transport,
		Path:      payload.NewAddress.Path,
	})

	lgTransport.Info("updated operational address", "peer", payload.SenderID, "host", payload.NewAddress.Host, "port", payload.NewAddress.Port, "reason", payload.Reason)
}

// sendImmediateConfirmation sends a "pending" confirmation back to the originating agent
// to indicate that the sync was received and is being processed. This is the first of two
// NOTIFYs in the two-phase remote confirmation protocol (Phase 5).
func (tm *MPTransportBridge) sendImmediateConfirmation(payload *DnsSyncPayload) {
	if tm.DNSTransport == nil {
		return
	}

	senderID := payload.GetSenderID()
	if payload.DistributionID == "" {
		lgTransport.Warn("cannot send immediate confirmation, no distribution ID", "sender", senderID)
		return
	}

	peer, exists := tm.PeerRegistry.Get(senderID)
	if !exists {
		lgTransport.Warn("cannot send immediate confirmation, peer not in registry", "peer", senderID)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tm.DNSTransport.Confirm(ctx, peer, &transport.ConfirmRequest{
		SenderID:       tm.LocalID,
		Zone:           payload.Zone,
		DistributionID: payload.DistributionID,
		Nonce:          payload.Nonce,
		Status:         transport.ConfirmPending,
		Message:        "Sync received, forwarding to combiner",
		Timestamp:      time.Now(),
	})

	if err != nil {
		lgTransport.Error("failed to send immediate confirmation", "distributionID", payload.DistributionID, "peer", senderID, "err", err)
	} else {
		lgTransport.Debug("sent immediate (pending) confirmation", "distributionID", payload.DistributionID, "peer", senderID)
	}
}

// sendRemoteConfirmation sends the final confirmation NOTIFY back to the originating agent
// after the remote agent's combiner has confirmed the sync. This is the second of two
// NOTIFYs in the two-phase remote confirmation protocol (Phase 7).
func (tm *MPTransportBridge) sendRemoteConfirmation(detail *RemoteConfirmationDetail) {
	if tm.DNSTransport == nil {
		return
	}

	peer, exists := tm.PeerRegistry.Get(detail.OriginatingSender)
	if !exists {
		lgTransport.Warn("cannot send remote confirmation, peer not in registry", "peer", detail.OriginatingSender)
		return
	}

	var rejItems []transport.RejectedItemDTO
	for _, ri := range detail.RejectedItems {
		rejItems = append(rejItems, transport.RejectedItemDTO{Record: ri.Record, Reason: ri.Reason})
	}

	// Map status string back to ConfirmStatus
	status := transport.ConfirmFailed
	switch detail.Status {
	case "SUCCESS", "ok":
		status = transport.ConfirmSuccess
	case "PARTIAL":
		status = transport.ConfirmPartial
	case "FAILED":
		status = transport.ConfirmFailed
	case "REJECTED":
		status = transport.ConfirmRejected
	case "IGNORED":
		status = transport.ConfirmIgnored
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tm.DNSTransport.Confirm(ctx, peer, &transport.ConfirmRequest{
		SenderID:       tm.LocalID,
		Zone:           string(detail.Zone),
		DistributionID: detail.OriginatingDistID, // Use the originating agent's distID
		Status:         status,
		Message:        detail.Message,
		AppliedRecords: detail.AppliedRecords,
		RemovedRecords: detail.RemovedRecords,
		RejectedItems:  rejItems,
		IgnoredRecords: detail.IgnoredRecords,
		Truncated:      detail.Truncated,
		Timestamp:      time.Now(),
	})

	if err != nil {
		lgTransport.Error("failed to send remote confirmation", "distributionID", detail.OriginatingDistID, "peer", detail.OriginatingSender, "err", err)
	} else {
		lgTransport.Info("sent remote confirmation", "distributionID", detail.OriginatingDistID, "peer", detail.OriginatingSender,
			"applied", len(detail.AppliedRecords), "removed", len(detail.RemovedRecords), "rejected", len(detail.RejectedItems))
	}
}

// SelectTransport selects the appropriate transport for communicating with a peer.
func (tm *MPTransportBridge) SelectTransport(peer *transport.Peer) transport.Transport {
	// Check peer's preferred transport
	switch peer.PreferredTransport {
	case "DNS":
		if tm.DNSTransport != nil && peer.CurrentAddress() != nil {
			return tm.DNSTransport
		}
	case "API":
		if tm.APITransport != nil && peer.APIEndpoint != "" {
			return tm.APITransport
		}
	}

	// Default: try API first (more reliable), then DNS
	if tm.APITransport != nil && peer.APIEndpoint != "" {
		return tm.APITransport
	}
	if tm.DNSTransport != nil && peer.CurrentAddress() != nil {
		return tm.DNSTransport
	}

	return nil
}

// SendWithFallback sends a message using the preferred transport, falling back if it fails.
func (tm *MPTransportBridge) SendSyncWithFallback(ctx context.Context, peer *transport.Peer, req *PeerSyncRequest) (*PeerSyncResponse, error) {
	// Bite 3: delegate to the generic primary-then-fallback path on
	// transport.TransportManager. Hello and Beat are NOT migrated to
	// tm.Send because their wrappers send on all transports in
	// parallel rather than primary-then-fallback, with extensive
	// MP-side state mutation; that is Phase 5 of the main refactor.
	//
	// C2: the wire payload is built here (syncAppMessage, the same
	// core.AgentMsgPost the typed DNSTransport.Sync marshalled) and
	// travels as one opaque AppMessage; the manager picks the mechanism.
	msg, err := syncAppMessage(req, peer.ID)
	if err != nil {
		return nil, err
	}
	resp, err := tm.TransportManager.Send(ctx, peer, msg)
	if err != nil {
		return nil, err
	}
	appResp, ok := resp.(*transport.AppResponse)
	if !ok {
		return nil, fmt.Errorf("SendSyncWithFallback: unexpected response type %T", resp)
	}
	return syncResponseFromApp(req, appResp), nil
}

// GetOrCreatePeer returns the transport.Peer keyed by agent.ID,
// creating it (in PeerStateNeeded) if it does not already exist.
//
// transport.Peer is the canonical per-mechanism state store: receipt
// and send sites write it directly, so there is no Agent->Peer state
// pull. (S4 removed the SyncPeerFromAgent snapshot path; discovery
// completion writes the peer directly in the OnPeerDiscovered closure.)
func (tm *MPTransportBridge) GetOrCreatePeer(agent *Agent) *transport.Peer {
	peer := tm.PeerRegistry.GetOrCreate(string(agent.ID))
	// S2: the AgentDetails->transport address restore is removed.
	// transport.Peer is the sole address source: discovered peers write
	// it during registration (RegisterDiscoveredAgent), config-infra
	// peers (combiner/signer/config-listed agents) write it at startup
	// (Initialize*AsPeer / main_init / apihandler_peer). No peer reaches a
	// send path without its transport address already populated.
	return peer
}

// SendHelloWithFallback sends a Hello handshake to a peer with transport fallback (legacy name).
// UPDATED: Now sends Hello on ALL supported transports independently when both are configured.
// Returns success if ANY transport succeeds. Updates per-transport state in Agent struct.
func (tm *MPTransportBridge) SendHelloWithFallback(ctx context.Context, agent *Agent, sharedZones []string) (*transport.HelloResponse, error) {
	peer := tm.GetOrCreatePeer(agent)
	// The mechanism flags are written under agent.Mu by discovery; read
	// them once under the same lock instead of racing the writer.
	agent.Mu.RLock()
	apiMethod, dnsMethod := agent.ApiMethod, agent.DnsMethod
	agent.Mu.RUnlock()

	req := &transport.HelloRequest{
		SenderID:     tm.LocalID,
		Capabilities: []string{"sync", "beat", "relocate"},
		SharedZones:  sharedZones,
		Timestamp:    time.Now(),
	}

	var apiResp *transport.HelloResponse
	var dnsResp *transport.HelloResponse
	var apiErr error
	var dnsErr error

	// Try API transport if locally supported, available, has valid endpoint, and actually needs Hello (state == KNOWN).
	// Skip if already INTRODUCED or OPERATIONAL — no point sending Hello to an already-established transport.
	// State gate reads the canonical transport.Peer mechanism state (raw).
	// D1: eligibility (the gates) is decided here; the fan-out itself is
	// transport's SendAll — every eligible mechanism is tried, in order,
	// and each outcome is applied below exactly as before.
	apiGate, _ := mechStateForGate(peer, "API")
	apiEligible := tm.APITransport != nil && tm.isTransportSupported("api") && apiMethod && peer.APIEndpoint != "" && apiGate == AgentStateKnown
	dnsGate, _ := mechStateForGate(peer, "DNS")
	dnsEligible := tm.DNSTransport != nil && dnsMethod && tm.isTransportSupported("dns") && dnsGate == AgentStateKnown
	results := tm.TransportManager.SendAll(ctx, peer, eligibleMechanisms(apiEligible, dnsEligible), req)
	if apiEligible {
		apiResp, apiErr = helloResult(results["API"])
		if apiErr != nil {
			lgConnRetry.Warn("API Hello failed", "peer", peer.ID, "err", apiErr)
		} else if apiResp != nil && !apiResp.Accepted {
			lgTransport.Warn("API Hello not accepted", "peer", peer.ID, "reason", apiResp.RejectReason)
		} else {
			lgTransport.Info("API Hello succeeded", "peer", peer.ID)
		}
		if apiErr == nil && apiResp != nil && apiResp.Accepted {
			if raw, ok := peer.MechanismRawState("API"); !ok || raw < transport.PeerStateIntroducing {
				peer.SetMechanismState("API", transport.PeerStateIntroducing, "API hello accepted")
				lgTransport.Info("updated API mechanism state to INTRODUCING after successful Hello", "agent", peer.ID)
			}
		}
	}
	if dnsEligible {
		dnsResp, dnsErr = helloResult(results["DNS"])
		if dnsErr != nil {
			lgConnRetry.Warn("DNS Hello failed", "peer", peer.ID, "err", dnsErr)
		} else if dnsResp != nil && !dnsResp.Accepted {
			lgTransport.Warn("DNS Hello not accepted", "peer", peer.ID, "reason", dnsResp.RejectReason)
		} else {
			lgTransport.Info("DNS Hello succeeded", "peer", peer.ID)
		}
		if dnsErr == nil && dnsResp != nil && dnsResp.Accepted {
			if raw, ok := peer.MechanismRawState("DNS"); !ok || raw < transport.PeerStateIntroducing {
				peer.SetMechanismState("DNS", transport.PeerStateIntroducing, "DNS hello accepted")
				lgTransport.Info("updated DNS mechanism state to INTRODUCING after successful Hello", "agent", peer.ID)
			}
		}
	}
	if apiErr == nil && apiResp != nil && apiResp.Accepted {
		return apiResp, nil
	}
	if dnsErr == nil && dnsResp != nil && dnsResp.Accepted {
		return dnsResp, nil
	}

	// If a transport was skipped (already past KNOWN) and no transport actively
	// failed, treat that as success — the peer is already introduced on that
	// transport. Read the canonical transport.Peer mechanism state (raw).
	dnsMech, _ := mechStateForGate(peer, "DNS")
	apiMech, _ := mechStateForGate(peer, "API")
	if dnsMech >= AgentStateIntroduced && dnsErr == nil {
		return nil, nil
	}
	if apiMech >= AgentStateIntroduced && apiErr == nil {
		return nil, nil
	}

	// Both failed or skipped with nothing established
	apiState := AgentStateToString[apiMech]
	dnsState := AgentStateToString[dnsMech]
	if apiResp == nil && dnsResp == nil && apiErr == nil && dnsErr == nil {
		// No transport was in KNOWN state — nothing to do
		return nil, fmt.Errorf("no transports in KNOWN state for Hello to peer %s (API: %s, DNS: %s)",
			peer.ID, apiState, dnsState)
	}
	return nil, fmt.Errorf("all transports failed for Hello to peer %s (API: %v, DNS: %v)", peer.ID, apiErr, dnsErr)
}

// SendBeatWithFallback sends a heartbeat to a peer with transport fallback.
// SendBeatWithFallback sends a Beat heartbeat to a peer (legacy name).
// UPDATED: Now sends Beat on ALL supported transports independently when both are configured.
// Returns success if ANY transport succeeds. Updates per-transport LastContactTime in Agent struct.
func (tm *MPTransportBridge) SendBeatWithFallback(ctx context.Context, agent *Agent, sequence uint64) (*transport.BeatResponse, error) {
	peer := tm.GetOrCreatePeer(agent)
	// The mechanism flags are written under agent.Mu by discovery; read
	// them once under the same lock instead of racing the writer.
	agent.Mu.RLock()
	apiMethod, dnsMethod := agent.ApiMethod, agent.DnsMethod
	agent.Mu.RUnlock()

	// Build gossip for this peer
	var gossipData json.RawMessage
	if tm.agentRegistry != nil && tm.agentRegistry.GossipStateTable != nil && tm.agentRegistry.ProviderGroupManager != nil {
		gossipMsgs := tm.agentRegistry.GossipStateTable.BuildGossipForPeer(
			string(agent.ID), tm.agentRegistry.ProviderGroupManager, tm.agentRegistry.LeaderElectionManager)
		if len(gossipMsgs) > 0 {
			gossipData, _ = json.Marshal(gossipMsgs)
		}
	}

	// Read the canonical transport.Peer store rather than the Agent.State
	// shadow. The shadow is written under agent.Mu by GetZoneAgentData and by
	// the display surfaces (peer zones / hsync-agentstatus / hsync-locate),
	// while this send path holds no lock on agent at all — a torn-read hazard
	// on a string field, and one that `peer zones` on a converged fleet would
	// provoke (2026-08-25 review, finding 3). The nil-registry branch is
	// harness-only: no display surface exists to race with, and agent.Mu is
	// the embedded peer mutex, so RLocking it here would risk recursive-RLock
	// writer starvation.
	var beatState AgentState
	if tm.agentRegistry != nil {
		beatState = tm.agentRegistry.effectiveAgentState(agent.ID)
	} else {
		beatState = agent.State
	}

	req := &transport.BeatRequest{
		SenderID:  tm.LocalID,
		Timestamp: time.Now(),
		Sequence:  sequence,
		State:     string(beatState),
		Zones:     tm.beatZones(agent.ID),
		Gossip:    gossipData,
	}

	var apiResp *transport.BeatResponse
	var dnsResp *transport.BeatResponse
	var apiErr error
	var dnsErr error

	// Try API transport if locally supported, available, and has valid endpoint.
	// Send on any active state including DEGRADED/INTERRUPTED — beats are how we recover.
	// State gate reads the canonical transport.Peer mechanism state (raw).
	// D1: eligibility (the gates) is decided here; the fan-out itself is
	// transport's SendAll — every eligible mechanism is beaten, in order,
	// and each outcome is applied below exactly as before.
	beatable := func(st AgentState) bool {
		return st == AgentStateOperational || st == AgentStateIntroduced || st == AgentStateLegacy || st == AgentStateDegraded || st == AgentStateInterrupted
	}
	apiBeatGate, _ := mechStateForGate(peer, "API")
	apiBeatEligible := tm.APITransport != nil && tm.isTransportSupported("api") && apiMethod && peer.APIEndpoint != "" && beatable(apiBeatGate)
	dnsBeatGate, _ := mechStateForGate(peer, "DNS")
	dnsBeatEligible := tm.DNSTransport != nil && dnsMethod && tm.isTransportSupported("dns") && beatable(dnsBeatGate)
	apiRaw, _ := peer.MechanismRawState("API")
	apiWasOperational := apiRaw == transport.PeerStateOperational
	dnsRaw, _ := peer.MechanismRawState("DNS")
	dnsWasOperational := dnsRaw == transport.PeerStateOperational
	results := tm.TransportManager.SendAll(ctx, peer, eligibleMechanisms(apiBeatEligible, dnsBeatEligible), req)
	if apiBeatEligible {
		apiResp, apiErr = beatResult(results["API"])
		if apiErr != nil {
			lgConnRetry.Debug("API Beat failed", "peer", peer.ID, "err", apiErr)
		} else if apiResp != nil && !apiResp.Ack {
			lgTransport.Debug("API Beat no confirmation (Ack=false)", "peer", peer.ID)
		} else {
			lgTransport.Debug("API Beat succeeded", "peer", peer.ID)
			peer.SetMechanismState("API", transport.PeerStateOperational, "API beat round-trip succeeded")
			peer.SetMechanismLastBeatSent("API", time.Now())
			if !apiWasOperational && tm.agentRegistry != nil && tm.agentRegistry.LeaderElectionManager != nil {
				tm.agentRegistry.LeaderElectionManager.NotifyPeerOperational(
					tm.agentRegistry.sharedParticipantZones(agent.ID))
			}
		}
	}
	if dnsBeatEligible {
		dnsResp, dnsErr = beatResult(results["DNS"])
		if dnsErr != nil {
			lgConnRetry.Debug("DNS Beat failed", "peer", peer.ID, "err", dnsErr)
		} else if dnsResp != nil && !dnsResp.Ack {
			lgTransport.Debug("DNS Beat no confirmation (Ack=false)", "peer", peer.ID)
		} else {
			lgTransport.Debug("DNS Beat succeeded", "peer", peer.ID)
			peer.SetMechanismState("DNS", transport.PeerStateOperational, "DNS beat round-trip succeeded")
			peer.SetMechanismLastBeatSent("DNS", time.Now())
			if !dnsWasOperational && tm.agentRegistry != nil && tm.agentRegistry.LeaderElectionManager != nil {
				tm.agentRegistry.LeaderElectionManager.NotifyPeerOperational(
					tm.agentRegistry.sharedParticipantZones(agent.ID))
			}
		}
	}
	if tm.agentRegistry != nil && tm.agentRegistry.GossipStateTable != nil && tm.agentRegistry.ProviderGroupManager != nil {
		for _, resp := range []*transport.BeatResponse{apiResp, dnsResp} {
			if resp == nil || len(resp.Gossip) == 0 {
				continue
			}
			var gossipMsgs []GossipMessage
			if err := json.Unmarshal(resp.Gossip, &gossipMsgs); err == nil {
				for i := range gossipMsgs {
					tm.agentRegistry.GossipStateTable.MergeGossip(&gossipMsgs[i])
					// Re-evaluate group state after merge (may trigger elections)
					pg := tm.agentRegistry.ProviderGroupManager.GetGroup(gossipMsgs[i].GroupHash)
					if pg != nil {
						tm.agentRegistry.GossipStateTable.CheckGroupState(gossipMsgs[i].GroupHash, pg.Members)
					}
				}
				lgTransport.Debug("merged gossip from beat response EDNS(0) CHUNK", "peer", peer.ID, "groups", len(gossipMsgs))
			}
		}
	}

	// Return success if ANY transport succeeded
	if apiErr == nil && apiResp != nil {
		return apiResp, nil
	}
	if dnsErr == nil && dnsResp != nil {
		return dnsResp, nil
	}

	// Both failed
	return nil, fmt.Errorf("all transports failed for Beat to peer %s (API: %v, DNS: %v)", peer.ID, apiErr, dnsErr)
}

// GetPreferredTransportName returns the preferred transport name for an agent.
//
// Bite 7 (inherited from Bite 1 step 5): delegates to
// peer.PreferredMechanism() when the peer is in the registry, with a
// fallback to the agent.ApiMethod / agent.DnsMethod flags for peers
// not yet in the registry (e.g. during early startup). Returns "none"
// for the no-mechanism case to preserve the original contract.
func (tm *MPTransportBridge) GetPreferredTransportName(agent *Agent) string {
	if peer, ok := tm.PeerRegistry.Get(string(agent.ID)); ok {
		if pref := peer.PreferredMechanism(); pref != "" {
			return pref
		}
	}
	// Fallback for peers not yet in the registry. API is preferred
	// when both are available, otherwise pick whichever is set.
	if agent.ApiMethod {
		return "API"
	}
	if agent.DnsMethod {
		return "DNS"
	}
	return "none"
}

// HasDNSTransport returns true if DNS transport is available for an agent.
//
// Bite 7: delegates to peer.HasMechanism("DNS") when the peer is in
// the registry; falls back to the agent flag for peers not yet
// synced. The local-side check (tm.DNSTransport != nil) is preserved
// — both ends must be configured for the transport to be usable.
func (tm *MPTransportBridge) HasDNSTransport(agent *Agent) bool {
	if tm.DNSTransport == nil {
		return false
	}
	if peer, ok := tm.PeerRegistry.Get(string(agent.ID)); ok {
		return peer.HasMechanism("DNS")
	}
	return agent.DnsMethod
}

// HasAPITransport returns true if API transport is available for an agent.
//
// Bite 7: delegates to peer.HasMechanism("API") when the peer is in
// the registry; falls back to the agent flag for peers not yet
// synced.
func (tm *MPTransportBridge) HasAPITransport(agent *Agent) bool {
	if tm.APITransport == nil {
		return false
	}
	if peer, ok := tm.PeerRegistry.Get(string(agent.ID)); ok {
		return peer.HasMechanism("API")
	}
	return agent.ApiMethod
}

// --- Reliable message queue integration ---

// StartReliableQueue wires up the sendFunc and starts the queue's background worker.
// Must be called after MPTransportBridge is fully initialized (transports, combiner peer, etc.).
func (tm *MPTransportBridge) StartReliableQueue(ctx context.Context) {
	if tm.ReliableQueue == nil {
		lgTransport.Info("no reliable queue configured, skipping")
		return
	}

	// Wire sendFunc: adapts generic transport.OutgoingMessage to MP delivery logic.
	tm.TransportManager.StartReliableQueue(ctx, func(ctx context.Context, msg *transport.OutgoingMessage) error {
		return tm.deliverGenericMessage(ctx, msg)
	})
}

// deliverGenericMessage is the sendFunc for the generic RMQ.
// It adapts a transport.OutgoingMessage to the existing MP delivery logic.
func (tm *MPTransportBridge) deliverGenericMessage(ctx context.Context, msg *transport.OutgoingMessage) error {
	update, ok := msg.Payload.(*ZoneUpdate)
	if !ok {
		return fmt.Errorf("deliverGenericMessage: payload is not *ZoneUpdate (recipient=%q, payloadType=%T)", msg.RecipientID, msg.Payload)
	}

	if tm.agentRegistry == nil {
		return fmt.Errorf("no agent registry")
	}

	agent, exists := tm.agentRegistry.S.Get(AgentId(msg.RecipientID))
	if !exists {
		return fmt.Errorf("recipient %q not found in AgentRegistry", msg.RecipientID)
	}

	peer := tm.GetOrCreatePeer(agent)
	isCombiner := AgentId(msg.RecipientID) == tm.combinerID

	// Build sync request
	senderID := tm.LocalID
	messageType := "sync"
	if isCombiner {
		messageType = "update"
		if update != nil && update.AgentId != "" {
			senderID = string(update.AgentId)
		}
	}

	syncReq := &PeerSyncRequest{
		SenderID:       senderID,
		Zone:           msg.Zone,
		Timestamp:      msg.CreatedAt,
		DistributionID: msg.DistributionID,
		Nonce:          msg.Nonce,
		MessageType:    messageType,
	}
	if update != nil {
		syncReq.Operations = update.Operations
		if isCombiner {
			syncReq.ZoneClass = update.ZoneClass
			if update.Publish != nil {
				syncReq.Publish = update.Publish
			}
		}
	}

	syncResp, err := tm.SendSyncWithFallback(ctx, peer, syncReq)

	// Forward per-RR detail from inline confirmation to SynchedDataEngine (combiner only)
	if isCombiner && syncResp != nil && tm.msgQs != nil && tm.msgQs.Confirmation != nil {
		var rejItems []RejectedItemInfo
		for _, ri := range syncResp.RejectedItems {
			rejItems = append(rejItems, RejectedItemInfo{Record: ri.Record, Reason: ri.Reason})
		}
		detail := &ConfirmationDetail{
			DistributionID: msg.DistributionID,
			Zone:           ZoneName(msg.Zone),
			Source:         msg.RecipientID,
			Status:         syncResp.Status.String(),
			Message:        syncResp.Message,
			AppliedRecords: syncResp.AppliedRecords,
			RemovedRecords: syncResp.RemovedRecords,
			RejectedItems:  rejItems,
			Truncated:      syncResp.Truncated,
			Timestamp:      time.Now(),
		}
		select {
		case tm.msgQs.Confirmation <- detail:
		default:
			lgTransport.Warn("confirmation channel full, dropping inline detail", "distributionID", msg.DistributionID)
		}
	}

	return err
}

// EnqueueForCombiner enqueues a zone update for reliable delivery to the combiner.
// Called by SynchedDataEngine when a zone update needs to reach the combiner.
// If distID is non-empty, it is used as the distribution ID; otherwise a new one is generated.
// Returns the distributionID for tracking and any error.
func (tm *MPTransportBridge) EnqueueForCombiner(zone ZoneName, update *ZoneUpdate, distID string) (string, error) {
	combinerID, err := tm.getCombinerID()
	if err != nil {
		return "", fmt.Errorf("EnqueueForCombiner: %w", err)
	}

	if distID == "" {
		distID = transport.GenerateDistributionID()
	}
	msg := &transport.OutgoingMessage{
		DistributionID: distID,
		RecipientID:    string(combinerID),
		Zone:           string(zone),
		Payload:        update,
		Priority:       transport.PriorityHigh,
	}

	return distID, tm.ReliableQueue.Enqueue(msg)
}

// EnqueueForZoneAgents enqueues a zone update for reliable delivery to all
// remote agents involved with this zone (as determined by AgentRegistry).
// Called by SynchedDataEngine when a locally-originated update needs to
// reach all peer agents. Uses the same distID for all agents so the
// originating agent can correlate confirmations from combiner and agents.
func (tm *MPTransportBridge) EnqueueForZoneAgents(zone ZoneName, update *ZoneUpdate, distID string) error {
	agents, err := tm.getAllAgentsForZone(zone)
	if err != nil {
		return fmt.Errorf("EnqueueForZoneAgents: %w", err)
	}

	if len(agents) == 0 {
		lgTransport.Debug("no remote agents for zone, nothing to enqueue", "zone", zone)
		return nil
	}

	var enqueueErrors []string
	for _, agentID := range agents {
		msg := &transport.OutgoingMessage{
			DistributionID: distID,
			RecipientID:    string(agentID),
			Zone:           string(zone),
			Payload:        update,
			Priority:       transport.PriorityNormal,
		}

		if err := tm.ReliableQueue.Enqueue(msg); err != nil {
			enqueueErrors = append(enqueueErrors, fmt.Sprintf("%s: %v", agentID, err))
		}
	}

	if len(enqueueErrors) > 0 {
		return fmt.Errorf("failed to enqueue for some agents: %v", enqueueErrors)
	}

	lgTransport.Info("enqueued zone update for agents", "count", len(agents), "zone", zone, "distributionID", distID)
	return nil
}

// EnqueueForSpecificAgent enqueues a zone update for a single agent.
// Used by "resync-targeted" to respond only to the requesting agent.
func (tm *MPTransportBridge) EnqueueForSpecificAgent(zone ZoneName, agentID AgentId, update *ZoneUpdate, distID string) error {
	if tm.ReliableQueue == nil {
		return fmt.Errorf("EnqueueForSpecificAgent: reliable queue not configured")
	}

	msg := &transport.OutgoingMessage{
		DistributionID: distID,
		RecipientID:    string(agentID),
		Zone:           string(zone),
		Payload:        update,
		Priority:       transport.PriorityNormal,
	}

	if err := tm.ReliableQueue.Enqueue(msg); err != nil {
		return fmt.Errorf("EnqueueForSpecificAgent: %s: %w", agentID, err)
	}

	lgTransport.Info("enqueued zone update for specific agent", "agent", agentID, "zone", zone, "distributionID", distID)
	return nil
}

// GetQueueStats returns statistics from the reliable message queue.
func (tm *MPTransportBridge) GetQueueStats() transport.QueueStats {
	if tm.ReliableQueue == nil {
		return transport.QueueStats{}
	}
	return tm.ReliableQueue.GetStats()
}

// GetQueuePendingMessages returns a snapshot of all pending messages in the queue.
func (tm *MPTransportBridge) GetQueuePendingMessages() []transport.PendingMessageInfo {
	if tm.ReliableQueue == nil {
		return nil
	}
	return tm.ReliableQueue.GetPendingMessages()
}

// MarkDeliveryConfirmed marks a queued message as confirmed by the recipient.
// senderID is the identity of the confirming party (= the original message recipient).
func (tm *MPTransportBridge) MarkDeliveryConfirmed(distributionID string, senderID string) bool {
	if tm.ReliableQueue == nil {
		return false
	}
	return tm.ReliableQueue.MarkConfirmed(distributionID, senderID)
}

// --- Helper methods ---

// getCombinerID returns the combiner's AgentId, set at construction time from config.
func (tm *MPTransportBridge) getCombinerID() (AgentId, error) {
	if tm.combinerID != "" {
		return tm.combinerID, nil
	}
	return "", fmt.Errorf("combiner ID not configured")
}

// getAllAgentsForZone returns the AgentIds of all remote agents for a zone.
// Uses AgentRegistry.GetZoneAgentData() which reads the HSYNC RRset.
func (tm *MPTransportBridge) getAllAgentsForZone(zone ZoneName) ([]AgentId, error) {
	if tm.agentRegistry == nil {
		return nil, fmt.Errorf("no agent registry")
	}

	zad, err := tm.agentRegistry.GetZoneAgentData(zone)
	if err != nil {
		return nil, err
	}

	var agents []AgentId
	for _, agent := range zad.Agents {
		agents = append(agents, agent.ID)
	}

	return agents, nil
}

// GetDistributionRecipients returns the list of recipient identities that will
// receive an update for the given zone. This is used by the SynchedDataEngine to
// populate TrackedRR.ExpectedRecipients so that ProcessConfirmation knows who
// must confirm before transitioning Pending → Accepted.
// If skipCombiner is true, the combiner is excluded from the list.
func (tm *MPTransportBridge) GetDistributionRecipients(zone ZoneName, skipCombiner bool) []string {
	var recipients []string

	// Add combiner unless skipped
	if !skipCombiner && tm.combinerID != "" {
		recipients = append(recipients, string(tm.combinerID))
	}

	// Add all remote agents for this zone
	agents, err := tm.getAllAgentsForZone(zone)
	if err != nil {
		lgTransport.Error("failed to get zone agents", "zone", zone, "err", err)
	} else {
		for _, a := range agents {
			recipients = append(recipients, string(a))
		}
	}

	return recipients
}

// groupRRStringsByOwner converts a flat list of RR strings to records grouped by owner name.
// Used when converting from management commands (AgentMgmtPost.RRs []string) to the
// grouped format used by AgentMsgPost.Records and SyncRequest.Records.
func groupRRStringsByOwner(rrStrings []string) map[string][]string {
	records := make(map[string][]string)
	for _, rrStr := range rrStrings {
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			lgTransport.Warn("skipping unparseable RR", "rr", rrStr, "err", err)
			continue
		}
		owner := rr.Header().Name
		records[owner] = append(records[owner], rrStr)
	}
	return records
}

// --- Phase 6: DNSKEY Propagation Tracking and KEYSTATE Signaling ---

// PendingDnskeyPropagation tracks a DNSKEY distribution awaiting confirmation from all remote agents.
type PendingDnskeyPropagation struct {
	Zone           ZoneName
	DistributionID string
	KeyTags        []uint16         // DNSKEY key tags being propagated
	ExpectedAgents map[AgentId]bool // Agents we're waiting for (true = confirmed)
	Rejected       bool             // True if any agent rejected
	RejectionMsg   string           // First rejection reason
	CreatedAt      time.Time
}

// TrackDnskeyPropagation registers a DNSKEY distribution for confirmation tracking.
// Called by SynchedDataEngine after enqueueing DNSKEY changes for remote agents.
func (tm *MPTransportBridge) TrackDnskeyPropagation(zone ZoneName, distID string, keyTags []uint16, agents []AgentId) {
	tm.dnskeyPropMu.Lock()
	defer tm.dnskeyPropMu.Unlock()

	expected := make(map[AgentId]bool, len(agents))
	for _, a := range agents {
		expected[a] = false // false = not yet confirmed
	}

	tm.pendingDnskeyPropagations[distID] = &PendingDnskeyPropagation{
		Zone:           zone,
		DistributionID: distID,
		KeyTags:        keyTags,
		ExpectedAgents: expected,
		CreatedAt:      time.Now(),
	}

	lgTransport.Info("tracking DNSKEY propagation", "zone", zone, "distributionID", distID, "agents", len(agents), "keyTags", len(keyTags))
}

// ProcessDnskeyConfirmation checks if a confirmation is for a pending DNSKEY propagation.
// If so, marks the agent as confirmed. When all agents have confirmed, sends KEYSTATE
// "propagated" to the signer. If any agent rejects, sends KEYSTATE "rejected".
// Returns true if this confirmation was for a DNSKEY propagation (handled here).
func (tm *MPTransportBridge) ProcessDnskeyConfirmation(distID string, source string, status string, rejectedItems []RejectedItemInfo) bool {
	tm.dnskeyPropMu.Lock()
	defer tm.dnskeyPropMu.Unlock()

	prop, exists := tm.pendingDnskeyPropagations[distID]
	if !exists {
		return false // Not a DNSKEY propagation confirmation
	}

	agentID := AgentId(source)

	// Check for rejection
	if len(rejectedItems) > 0 {
		prop.Rejected = true
		if prop.RejectionMsg == "" {
			prop.RejectionMsg = rejectedItems[0].Reason
		}
		lgTransport.Warn("DNSKEY confirmation rejected", "zone", prop.Zone, "distributionID", distID, "agent", source, "reason", prop.RejectionMsg)
	}

	// Mark this agent as confirmed
	if _, expected := prop.ExpectedAgents[agentID]; expected {
		prop.ExpectedAgents[agentID] = true
		lgTransport.Info("DNSKEY confirmation received", "zone", prop.Zone, "distributionID", distID, "agent", source, "status", status)
	}

	// Check if all agents have confirmed
	allConfirmed := true
	for _, confirmed := range prop.ExpectedAgents {
		if !confirmed {
			allConfirmed = false
			break
		}
	}

	if !allConfirmed {
		return true // Still waiting for more confirmations
	}

	// All agents confirmed — send KEYSTATE to signer
	lgTransport.Info("all agents confirmed DNSKEY propagation", "zone", prop.Zone, "distributionID", distID, "agents", len(prop.ExpectedAgents), "rejected", prop.Rejected)

	// Send KEYSTATE asynchronously (don't hold the mutex)
	zone := prop.Zone
	keyTags := prop.KeyTags
	rejected := prop.Rejected
	rejectionMsg := prop.RejectionMsg
	delete(tm.pendingDnskeyPropagations, distID)

	go func() {
		if rejected {
			tm.sendKeystateToSigner(zone, keyTags, "rejected", rejectionMsg)
		} else {
			tm.sendKeystateToSigner(zone, keyTags, "propagated", "all remote agents confirmed")
		}
	}()

	return true
}

// sendKeystateToSigner sends a KEYSTATE message to the local signer.
// signal is "propagated", "rejected", or "removed".
func (tm *MPTransportBridge) sendKeystateToSigner(zone ZoneName, keyTags []uint16, signal string, message string) {
	if tm.signerID == "" || tm.signerAddress == "" {
		lgTransport.Warn("no signer configured, cannot send KEYSTATE", "zone", zone, "signerID", tm.signerID, "signerAddress", tm.signerAddress, "signal", signal)
		return
	}

	if tm.DNSTransport == nil {
		lgTransport.Warn("no DNS transport available, cannot send KEYSTATE", "zone", zone, "signal", signal)
		return
	}

	// Get or create signer peer
	peer := tm.PeerRegistry.GetOrCreate(tm.signerID)
	// Parse address into host:port
	host, port := parseHostPort(tm.signerAddress, 53)
	peer.SetDiscoveryAddress(&transport.Address{
		Host:      host,
		Port:      port,
		Transport: "udp",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Send one KEYSTATE per key tag
	for _, keyTag := range keyTags {
		req := &PeerKeystateRequest{
			SenderID:  tm.LocalID,
			Zone:      string(zone),
			KeyTag:    keyTag,
			Signal:    signal,
			Message:   message,
			Timestamp: time.Now(),
		}

		resp, err := tm.sendKeystate(ctx, peer, req)
		if err != nil {
			lgTransport.Error("KEYSTATE send to signer failed", "zone", zone, "keyTag", keyTag, "signal", signal, "err", err)
			continue
		}

		lgTransport.Info("KEYSTATE sent to signer", "zone", zone, "keyTag", keyTag, "signal", signal, "signer", tm.signerID, "accepted", resp.Accepted, "msg", resp.Message)
	}
}

// parseHostPort splits an address into host and port, defaulting to
// defaultPort. Uses net.SplitHostPort so bracketed IPv6 literals
// ("[::1]:53") parse correctly; bare IPv6 literals without a port
// ("::1") fall back to defaultPort.
func parseHostPort(addr string, defaultPort uint16) (string, uint16) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// No port supplied (or bare IPv6): treat the whole string
		// as a host and apply the default port.
		return addr, defaultPort
	}
	if port, convErr := strconv.ParseUint(portStr, 10, 16); convErr == nil {
		return host, uint16(port)
	}
	return host, defaultPort
}

// sendRfiToSigner sends an RFI message to the signer (e.g. RFI KEYSTATE to request inventory).
// Returns the ACK from the signer. The actual data comes back as a separate KEYSTATE message.
func (tm *MPTransportBridge) sendRfiToSigner(zone string, rfiType string) error {
	if tm.signerID == "" || tm.signerAddress == "" {
		return fmt.Errorf("no signer configured (signerID=%q, signerAddress=%q)", tm.signerID, tm.signerAddress)
	}

	// Get or create signer peer with address
	peer := tm.PeerRegistry.GetOrCreate(tm.signerID)
	host, port := parseHostPort(tm.signerAddress, 53)
	peer.SetDiscoveryAddress(&transport.Address{
		Host:      host,
		Port:      port,
		Transport: "udp",
	})

	syncReq := &PeerSyncRequest{
		SenderID:    tm.LocalID,
		Zone:        zone,
		Timestamp:   time.Now(),
		MessageType: "rfi",
		RfiType:     rfiType,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := tm.SendSyncWithFallback(ctx, peer, syncReq)
	if err != nil {
		return fmt.Errorf("RFI %s to signer %s failed: %w", rfiType, tm.signerID, err)
	}

	lgTransport.Info("RFI sent to signer", "rfiType", rfiType, "zone", zone, "signer", tm.signerID, "status", resp.Status)
	return nil
}

// sendRfiToCombiner sends an RFI message to the combiner (e.g. RFI EDITS to request contributions).
// Modeled on sendRfiToSigner. Uses agentRegistry for peer lookup (same as deliverToCombiner).
func (tm *MPTransportBridge) sendRfiToCombiner(zone string, rfiType string) error {
	if tm.agentRegistry == nil {
		return fmt.Errorf("no agent registry")
	}

	combinerID, err := tm.getCombinerID()
	if err != nil {
		return fmt.Errorf("RFI %s: %w", rfiType, err)
	}

	combiner, exists := tm.agentRegistry.S.Get(combinerID)
	if !exists {
		return fmt.Errorf("combiner %q not found in AgentRegistry", combinerID)
	}

	peer := tm.GetOrCreatePeer(combiner)

	syncReq := &PeerSyncRequest{
		SenderID:    tm.LocalID,
		Zone:        zone,
		Timestamp:   time.Now(),
		MessageType: "rfi",
		RfiType:     rfiType,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := tm.SendSyncWithFallback(ctx, peer, syncReq)
	if err != nil {
		return fmt.Errorf("RFI %s to combiner %s failed: %w", rfiType, combinerID, err)
	}

	lgTransport.Info("RFI sent to combiner", "rfiType", rfiType, "zone", zone, "combiner", combinerID, "status", resp.Status)
	return nil
}

// beatZones is the zone list a beat to the given peer carries: the zones in
// which both we and the peer are participants (C7: derived here, no longer
// stored on transport.Peer). The receiver uses the first one as the
// authorization scope.
func (tm *MPTransportBridge) beatZones(id AgentId) []string {
	if tm.agentRegistry == nil {
		return nil
	}
	shared := tm.agentRegistry.sharedParticipantZones(id)
	if len(shared) == 0 {
		return nil
	}
	// Order is deliberately unspecified (map iteration), exactly as the
	// pre-C7 transport.Peer.GetSharedZones was: the receiver authorizes
	// the beat on Zones[0], and a fixed order would turn one zone the
	// receiver does not list us for into a permanent refusal instead of
	// an intermittent one.
	set := make(map[string]struct{}, len(shared))
	for _, z := range shared {
		set[string(z)] = struct{}{}
	}
	zones := make([]string, 0, len(set))
	for z := range set {
		zones = append(zones, z)
	}
	return zones
}

// Start wires this role's receive path at daemon start (D3): the CHUNK
// NOTIFY handler for the roles whose handler the bridge owns (agent,
// auditor — the signer and combiner register theirs at init), then the
// RouteToCallback dispatch. It replaces the per-role snippets that lived
// in start_*.go and must run before tdns's NotifyHandler starts. The
// reliable queue is started separately (StartReliableQueue) because the
// agent needs its infra peers initialised first.
func (tm *MPTransportBridge) Start(ctx context.Context) error {
	if tm == nil || tm.TransportManager == nil {
		return nil
	}
	switch tm.role {
	case roleSigner, roleCombiner:
		// Chunk handler and router were built and registered at init.
	default:
		// Without the CHUNK NOTIFY handler the process has no DNS receive
		// path; the callers (StartMPAgent, StartMPAuditor) fail startup.
		if err := tm.RegisterChunkNotifyHandler(); err != nil {
			return fmt.Errorf("CHUNK NOTIFY handler (%s): %w", tm.role, err)
		}
	}
	tm.StartIncomingMessageRouter(ctx)
	return nil
}

// flushDiscoveryCache flushes the IMR cache at and below the peer identity
// AND its parent zone, returning the number of entries removed. A lookup
// that fails while the peer restarts (its identity zone is republished at
// startup) leaves an unusable cached entry one label up — the delegation
// the URI/SVCB/JWK names live under — which a flush of the identity alone
// never reaches, so every later discovery attempt failed with "no
// auth-server attempts made" until the entry expired (2026-09-09 fleet
// observation; `imr flush <parent>` + `peer reset` recovered it at once).
func flushDiscoveryCache(imr *Imr, peerID string) int {
	if imr == nil || imr.Imr == nil || imr.Cache == nil {
		return 0
	}
	total := 0
	if n, err := imr.Cache.FlushDomain(peerID, false); err == nil {
		total += n
	} else {
		lgTransport.Warn("discovery cache flush failed; a negative entry may persist until its TTL", "domain", peerID, "err", err)
	}
	if parent := parentDomain(peerID); parent != "" {
		if n, err := imr.Cache.FlushDomain(parent, false); err == nil {
			total += n
		} else {
			lgTransport.Warn("discovery cache flush failed; a negative entry may persist until its TTL", "domain", parent, "err", err)
		}
	}
	return total
}

// parentDomain returns the name one label up ("agent.x.example." ->
// "x.example."), or "" at the top.
func parentDomain(name string) string {
	labels := dns.SplitDomainName(dns.Fqdn(name))
	if len(labels) < 2 {
		return ""
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

// eligibleMechanisms lists the mechanisms a hello/beat fan-out tries, in
// the order the pre-D1 senders used (API, then DNS).
func eligibleMechanisms(api, dns bool) []string {
	var out []string
	if api {
		out = append(out, "API")
	}
	if dns {
		out = append(out, "DNS")
	}
	return out
}

func helloResult(r transport.MechanismResult) (*transport.HelloResponse, error) {
	if r.Err != nil {
		return nil, r.Err
	}
	resp, _ := r.Response.(*transport.HelloResponse)
	return resp, nil
}

func beatResult(r transport.MechanismResult) (*transport.BeatResponse, error) {
	if r.Err != nil {
		return nil, r.Err
	}
	resp, _ := r.Response.(*transport.BeatResponse)
	return resp, nil
}
