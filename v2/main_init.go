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

// MainInit initializes the MP signer. It delegates DNS
// infrastructure setup to tdns.MainInit, then adds MP
// components (TransportManager, crypto, CHUNK handler,
// peer registration).
func (conf *Config) MainInit(ctx context.Context, defaultcfg string) error {
	// DNS infrastructure (zones, KeyDB, handlers, channels)
	if err := conf.Config.MainInit(ctx, defaultcfg); err != nil {
		return err
	}

	// MP signer initialization
	mp := conf.Config.MultiProvider
	if mp == nil || !mp.Active {
		return nil // not an MP signer
	}

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
	tm := tdns.NewTransportManager(&tdns.TransportManagerConfig{
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
	conf.Config.Internal.TransportManager = tm

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
