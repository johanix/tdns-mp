/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP startup orchestration: MainInit calls tdns.MainInit for
 * DNS infrastructure, then adds MP components on top.
 */
package tdnsmp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// MainInit initializes an MP role (signer or combiner). It delegates
// DNS infrastructure setup to tdns.MainInit, then adds MP components
// (TransportManager, crypto, CHUNK handler, peer registration).
func (conf *Config) MainInit(ctx context.Context, defaultcfg string) error {
	// DNS infrastructure (zones, KeyDB, handlers, channels)
	if err := conf.Config.MainInit(ctx, defaultcfg); err != nil {
		return err
	}

	mp := conf.Config.MultiProvider
	if mp == nil {
		return nil
	}

	switch mp.Role {
	case "signer":
		if !mp.Active {
			return nil // signer requires explicit activation
		}
		return conf.initMPSigner(mp)
	case "combiner":
		return conf.initMPCombiner(mp)
	default:
		return fmt.Errorf("unsupported multi-provider.role: %q", mp.Role)
	}
}

// initMPSigner performs signer-specific MP initialization.
func (conf *Config) initMPSigner(mp *tdns.MultiProviderConf) error {

	if mp.Identity == "" {
		return fmt.Errorf("multi-provider.identity is required when multi-provider.active is true")
	}
	if len(mp.Agents) == 0 {
		return fmt.Errorf("multi-provider.agents is required when multi-provider.active is true")
	}

	// Initialize PayloadCrypto for secure CHUNK transport (optional)
	var signerPayloadCrypto *transport.PayloadCrypto
	if strings.TrimSpace(mp.LongTermJosePrivKey) != "" {
		pc, err := initSignerCrypto(conf.Config)
		if err != nil {
			return fmt.Errorf("failed to initialize signer crypto: %w", err)
		}
		signerPayloadCrypto = pc
	}

	// Initialize distribution cache for outbound tracking
	if conf.Config.Internal.DistributionCache == nil {
		conf.Config.Internal.DistributionCache = tdns.NewDistributionCache()
		tdns.StartDistributionGC(conf.Config.Internal.DistributionCache, 1*time.Minute, conf.Config.Internal.StopCh)
	}

	// Create TransportManager for signer<->agent communication
	chunkMode := strings.TrimSpace(mp.ChunkMode)
	if chunkMode == "" {
		chunkMode = "edns0"
	}
	controlZone := dns.Fqdn(mp.Identity)
	tm := tdns.NewMPTransportBridge(&tdns.MPTransportBridgeConfig{
		LocalID:             dns.Fqdn(mp.Identity),
		ControlZone:         controlZone,
		APITimeout:          10 * time.Second,
		DNSTimeout:          5 * time.Second,
		ChunkMode:           chunkMode,
		ChunkMaxSize:        mp.ChunkMaxSize,
		PayloadCrypto:       signerPayloadCrypto,
		DistributionCache:   conf.Config.Internal.DistributionCache,
		SupportedMechanisms: []string{"dns"},
		MsgQs:               conf.Config.Internal.MsgQs,
		AuthorizedPeers: func() []string {
			var peers []string
			for _, a := range mp.Agents {
				if a != nil && a.Identity != "" {
					peers = append(peers, dns.Fqdn(a.Identity))
				}
			}
			return peers
		},
	})
	conf.Config.Internal.TransportManager = tm.TransportManager
	conf.Config.Internal.MPTransport = tm

	// Create SecurePayloadWrapper for decrypting incoming CHUNK payloads
	var signerSecureWrapper *transport.SecurePayloadWrapper
	if signerPayloadCrypto != nil {
		signerSecureWrapper = transport.NewSecurePayloadWrapper(signerPayloadCrypto)
	}

	// Register CHUNK handler
	signerState, err := RegisterSignerChunkHandler(dns.Fqdn(mp.Identity), signerSecureWrapper)
	if err != nil {
		return fmt.Errorf("RegisterSignerChunkHandler: %w", err)
	}
	conf.Config.Internal.CombinerState = signerState

	// Wire chunk handler into TM
	tm.ChunkHandler = signerState.ChunkHandler()

	// Initialize signer router
	signerRouter := transport.NewDNSMessageRouter()
	signerRouterCfg := &transport.SignerRouterConfig{
		Authorizer:       tm,
		PeerRegistry:     tm.PeerRegistry,
		AllowUnencrypted: true,
		IncomingChan:     nil, // routing via RouteToCallback
	}
	if signerPayloadCrypto != nil {
		signerRouterCfg.PayloadCrypto = signerPayloadCrypto
		signerRouterCfg.AllowUnencrypted = false
	}
	if err := transport.InitializeSignerRouter(signerRouter, signerRouterCfg); err != nil {
		return fmt.Errorf("InitializeSignerRouter: %w", err)
	}
	signerState.SetRouter(signerRouter)
	tm.Router = signerRouter

	// Register agent peers
	for _, agentConf := range mp.Agents {
		if agentConf.Identity == "" {
			return fmt.Errorf("multi-provider.agents: entry missing identity")
		}
		peerID := dns.Fqdn(agentConf.Identity)
		agentPeer := transport.NewPeer(peerID)
		agentPeer.SetState(transport.PeerStateKnown, "configured")
		if agentConf.Address != "" {
			host, portStr, err := net.SplitHostPort(agentConf.Address)
			if err != nil {
				return fmt.Errorf("invalid address %q for %s: %w", agentConf.Address, peerID, err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return fmt.Errorf("invalid port in %q for %s: %w", agentConf.Address, peerID, err)
			}
			agentPeer.SetDiscoveryAddress(&transport.Address{
				Host:      host,
				Port:      uint16(port),
				Transport: "udp",
			})
		}
		if agentConf.ApiBaseUrl != "" {
			agentPeer.APIEndpoint = agentConf.ApiBaseUrl
		}
		if err := tm.PeerRegistry.Add(agentPeer); err != nil {
			return fmt.Errorf("failed to register agent peer %s: %w", peerID, err)
		}
	}

	return nil
}

// initMPCombiner performs combiner-specific MP initialization.
func (conf *Config) initMPCombiner(mp *tdns.MultiProviderConf) error {
	if mp.Identity == "" {
		return fmt.Errorf("multi-provider.identity is required in config")
	}

	// Initialize combiner edit tables
	kdb := conf.Config.Internal.KeyDB
	if kdb != nil {
		if err := kdb.InitCombinerEditTables(); err != nil {
			return fmt.Errorf("InitCombinerEditTables: %w", err)
		}
	}

	chunkMode := strings.TrimSpace(mp.ChunkMode)
	if chunkMode == "query" {
		cep := strings.TrimSpace(mp.ChunkQueryEndpoint)
		if cep != "include" && cep != "none" {
			return fmt.Errorf("multi-provider.chunk_mode=query requires chunk_query_endpoint \"include\" or \"none\" (got %q)", cep)
		}
	}

	// Initialize combiner crypto for decrypting agent payloads
	var secureWrapper *transport.SecurePayloadWrapper
	if strings.TrimSpace(mp.LongTermJosePrivKey) != "" {
		var err error
		secureWrapper, err = tdns.InitCombinerCrypto(conf.Config)
		if err != nil {
			return fmt.Errorf("failed to initialize combiner crypto: %w", err)
		}
	}

	// Register CHUNK handler
	combinerState, err := RegisterCombinerChunkHandler(dns.Fqdn(mp.Identity), secureWrapper)
	if err != nil {
		return fmt.Errorf("RegisterCombinerChunkHandler: %w", err)
	}
	combinerState.ProtectedNamespaces = mp.ProtectedNamespaces
	conf.Config.Internal.CombinerState = combinerState

	// Initialize distribution cache
	if conf.Config.Internal.DistributionCache == nil {
		conf.Config.Internal.DistributionCache = tdns.NewDistributionCache()
		tdns.StartDistributionGC(conf.Config.Internal.DistributionCache, 1*time.Minute, conf.Config.Internal.StopCh)
	}

	// Create TransportManager
	var combinerPayloadCrypto *transport.PayloadCrypto
	if secureWrapper != nil {
		combinerPayloadCrypto = secureWrapper.GetCrypto()
	}
	if chunkMode == "" {
		chunkMode = "edns0"
	}
	tm := tdns.NewMPTransportBridge(&tdns.MPTransportBridgeConfig{
		LocalID:             dns.Fqdn(mp.Identity),
		ControlZone:         dns.Fqdn(mp.Identity),
		DNSTimeout:          5 * time.Second,
		APITimeout:          10 * time.Second,
		ChunkMode:           chunkMode,
		ChunkMaxSize:        mp.ChunkMaxSize,
		PayloadCrypto:       combinerPayloadCrypto,
		DistributionCache:   conf.Config.Internal.DistributionCache,
		SupportedMechanisms: []string{"dns"},
		MsgQs:               conf.Config.Internal.MsgQs,
		AuthorizedPeers: func() []string {
			var peers []string
			for _, a := range mp.Agents {
				if a != nil && a.Identity != "" {
					peers = append(peers, dns.Fqdn(a.Identity))
				}
			}
			return peers
		},
	})
	conf.Config.Internal.TransportManager = tm.TransportManager
	conf.Config.Internal.MPTransport = tm

	// Register agent peers
	for _, agentConf := range mp.Agents {
		if agentConf.Identity == "" {
			return fmt.Errorf("multi-provider.agents: entry missing identity")
		}
		peerID := dns.Fqdn(agentConf.Identity)
		agentPeer := transport.NewPeer(peerID)
		agentPeer.SetState(transport.PeerStateKnown, "configured")
		if agentConf.Address != "" {
			host, portStr, err := net.SplitHostPort(agentConf.Address)
			if err != nil {
				return fmt.Errorf("invalid address %q for %s: %w", agentConf.Address, peerID, err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return fmt.Errorf("invalid port in %q for %s: %w", agentConf.Address, peerID, err)
			}
			agentPeer.SetDiscoveryAddress(&transport.Address{
				Host:      host,
				Port:      uint16(port),
				Transport: "udp",
			})
		}
		if agentConf.ApiBaseUrl != "" {
			agentPeer.APIEndpoint = agentConf.ApiBaseUrl
			agentPeer.PreferredTransport = "API"
		} else {
			agentPeer.PreferredTransport = "DNS"
		}
		if err := tm.PeerRegistry.Add(agentPeer); err != nil {
			return fmt.Errorf("failed to register combiner agent peer %s: %w", peerID, err)
		}
	}

	// Wire GetPeerAddress callback for chunk_mode=query fallback
	combinerState.SetGetPeerAddress(func(senderID string) (string, bool) {
		peer, ok := tm.PeerRegistry.Get(senderID)
		if !ok || peer.CurrentAddress() == nil {
			return "", false
		}
		addr := peer.CurrentAddress()
		return fmt.Sprintf("%s:%d", addr.Host, addr.Port), true
	})

	// Wire chunk handler into TM
	tm.ChunkHandler = combinerState.ChunkHandler()

	// Initialize combiner router
	combinerRouter := transport.NewDNSMessageRouter()
	combinerRouterCfg := &transport.CombinerRouterConfig{
		Authorizer:   tm,
		PeerRegistry: tm.PeerRegistry,
		HandleUpdate: NewCombinerSyncHandler(),
		IncomingChan: nil,
	}
	if combinerPayloadCrypto != nil {
		combinerRouterCfg.PayloadCrypto = combinerPayloadCrypto
	}
	if err := transport.InitializeCombinerRouter(combinerRouter, combinerRouterCfg); err != nil {
		return fmt.Errorf("InitializeCombinerRouter: %w", err)
	}
	combinerState.SetRouter(combinerRouter)
	tm.Router = combinerRouter

	return nil
}
