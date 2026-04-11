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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/crypto/jose"
	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// MainInit initializes an MP role (signer or combiner). It delegates
// DNS infrastructure setup to tdns.MainInit, then adds MP components
// (TransportManager, crypto, CHUNK handler, peer registration).
func (conf *Config) MainInit(ctx context.Context, defaultcfg string) error {
	// Register MP zone option handler before ParseZones runs inside MainInit.
	tdns.RegisterZoneOptionHandler(tdns.OptMultiProvider, func(zname string, options map[tdns.ZoneOption]bool) {
		conf.Config.Internal.MPZoneNames = append(conf.Config.Internal.MPZoneNames, zname)
	})

	// Register MP zone option validators before ParseZones runs.
	// These replace the hardcoded validation in tdns's parseZoneOptions.
	tdns.RegisterZoneOptionValidator(tdns.OptMPManualApproval,
		func(c *tdns.Config, zname string, zd *tdns.ZoneData, options map[tdns.ZoneOption]bool) bool {
			if tdns.Globals.App.Type != tdns.AppTypeMPCombiner {
				lg.Error("mp-manual-approval is only valid on the combiner, ignoring", "zone", zname)
				if zd != nil {
					zd.SetError(tdns.ConfigError, "mp-manual-approval is only valid on combiner zones")
				}
				return false
			}
			return true
		})

	tdns.RegisterZoneOptionValidator(tdns.OptMultiProvider,
		func(c *tdns.Config, zname string, zd *tdns.ZoneData, options map[tdns.ZoneOption]bool) bool {
			// On the signer (AppTypeAuth), require server-level multi-provider config.
			// On agents, the zone option alone is sufficient — the HSYNC RRset is the authority.
			if tdns.Globals.App.Type == tdns.AppTypeAuth && (c.MultiProvider == nil || !c.MultiProvider.Active) {
				lg.Error("option requires multi-provider.active in server config", "zone", zname,
					"option", tdns.ZoneOptionToString[tdns.OptMultiProvider])
				if zd != nil {
					zd.SetError(tdns.ConfigError,
						"option %s requires multi-provider.active: true in server config",
						tdns.ZoneOptionToString[tdns.OptMultiProvider])
				}
				return false
			}
			return true
		})

	// Register MP config validators to run during tdns's ValidateConfig.
	conf.Config.Internal.PostValidateConfigHook = ValidateMPConfig

	// DNS infrastructure (zones, KeyDB, handlers, channels)
	if err := conf.Config.MainInit(ctx, defaultcfg); err != nil {
		return err
	}

	// Second pass: populate MPdata on MP zones and attach OnFirstLoad
	// callbacks. Safe because OnFirstLoad fires later in RefreshEngine,
	// not during ParseZones.
	resignQ := conf.Config.Internal.ResignQ
	conf.ForEachMPZone(func(zd *tdns.ZoneData) {
		zd.EnsureMP()
		zd.Lock()
		if zd.MP.MPdata != nil {
			cp := *zd.MP.MPdata
			zd.MP.MPdata = &cp
			zd.MP.MPdata.Options = map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}
		} else {
			zd.MP.MPdata = &tdns.MPdata{
				Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
			}
		}
		zd.Unlock()

		// MP signing OnFirstLoad: after zone load, if HSYNC analysis
		// has dynamically enabled OptInlineSigning, set up signing.
		// This was previously in tdns ParseZones gated on
		// (AppTypeAuth || AppTypeMPSigner).
		if zd.FirstZoneLoad {
			zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *tdns.ZoneData) {
				if zd.Options[tdns.OptInlineSigning] {
					if err := zd.SetupZoneSigning(resignQ); err != nil {
						lg.Error("SetupZoneSigning failed in MP OnFirstLoad",
							"zone", zd.ZoneName, "error", err)
					}
				}
			})
		}
	})

	conf.Config.ParseAuthOptions()

	if err := tdns.ValidateDatabaseFile(conf.Config); err != nil {
		return fmt.Errorf("database validation failed: %v", err)
	}

	if err := conf.Config.InitializeKeyDB(); err != nil {
		return fmt.Errorf("error initializing KeyDB: %v", err)
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
	case "agent":
		return conf.initMPAgent(mp)
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

	// Create MsgQs locally
	conf.InternalMp.MsgQs = NewMsgQs()
	// Initialize distribution cache for outbound tracking
	conf.InternalMp.DistributionCache = NewDistributionCache()
	StartDistributionGC(conf.InternalMp.DistributionCache, 1*time.Minute, conf.Config.Internal.StopCh)
	conf.Config.Internal.DistributionCache = conf.InternalMp.DistributionCache // dual-write

	// Create TransportManager for signer<->agent communication
	chunkMode := strings.TrimSpace(mp.ChunkMode)
	if chunkMode == "" {
		chunkMode = "edns0"
	}
	controlZone := dns.Fqdn(mp.Identity)
	tm := NewMPTransportBridge(&MPTransportBridgeConfig{
		LocalID:             dns.Fqdn(mp.Identity),
		ControlZone:         controlZone,
		APITimeout:          10 * time.Second,
		DNSTimeout:          5 * time.Second,
		ChunkMode:           chunkMode,
		ChunkMaxSize:        mp.ChunkMaxSize,
		PayloadCrypto:       signerPayloadCrypto,
		DistributionCache:   conf.InternalMp.DistributionCache,
		SupportedMechanisms: []string{"dns"},
		MsgQs:               conf.InternalMp.MsgQs,
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
	conf.InternalMp.MPTransport = tm
	conf.InternalMp.TransportManager = tm.TransportManager

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
	conf.InternalMp.CombinerState = signerState
	conf.Config.Internal.CombinerState = signerState // dual-write

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

	// Initialize HsyncDB and combiner edit tables
	kdb := conf.Config.Internal.KeyDB
	if kdb != nil {
		conf.InternalMp.HsyncDB = NewHsyncDB(kdb)
		if err := conf.InternalMp.HsyncDB.InitCombinerEditTables(); err != nil {
			return fmt.Errorf("InitCombinerEditTables: %w", err)
		}
	}

	// Register provider zone RR types from config
	for i := range mp.ProviderZones {
		mp.ProviderZones[i].Zone = dns.Fqdn(mp.ProviderZones[i].Zone)
		RegisterProviderZoneRRtypes(mp.ProviderZones[i])
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
		secureWrapper, err = InitCombinerCrypto(conf.Config)
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
	conf.InternalMp.CombinerState = combinerState
	conf.Config.Internal.CombinerState = combinerState // dual-write

	// Create MsgQs locally
	conf.InternalMp.MsgQs = NewMsgQs()

	// Initialize distribution cache
	conf.InternalMp.DistributionCache = NewDistributionCache()
	StartDistributionGC(conf.InternalMp.DistributionCache, 1*time.Minute, conf.Config.Internal.StopCh)
	conf.Config.Internal.DistributionCache = conf.InternalMp.DistributionCache // dual-write

	// Create TransportManager
	var combinerPayloadCrypto *transport.PayloadCrypto
	if secureWrapper != nil {
		combinerPayloadCrypto = secureWrapper.GetCrypto()
	}
	if chunkMode == "" {
		chunkMode = "edns0"
	}
	tm := NewMPTransportBridge(&MPTransportBridgeConfig{
		LocalID:             dns.Fqdn(mp.Identity),
		ControlZone:         dns.Fqdn(mp.Identity),
		DNSTimeout:          5 * time.Second,
		APITimeout:          10 * time.Second,
		ChunkMode:           chunkMode,
		ChunkMaxSize:        mp.ChunkMaxSize,
		PayloadCrypto:       combinerPayloadCrypto,
		DistributionCache:   conf.InternalMp.DistributionCache,
		SupportedMechanisms: []string{"dns"},
		MsgQs:               conf.InternalMp.MsgQs,
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
	conf.InternalMp.MPTransport = tm
	conf.InternalMp.TransportManager = tm.TransportManager

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

// initMPAgent performs agent-specific MP initialization.
// Note: SetupAgent (which creates the agent identity zone and publishes
// transport records) runs from StartMPAgent, after ZoneUpdaterEngine is
// running — PublishUriRR/PublishAddrRR/etc. send on KeyDB.UpdateQ and
// require a live consumer.
func (conf *Config) initMPAgent(mp *tdns.MultiProviderConf) error {
	if mp.Identity == "" {
		return fmt.Errorf("multi-provider.identity is required for agent role")
	}

	// Initialize AgentRegistry
	conf.InternalMp.AgentRegistry = conf.NewAgentRegistry()

	// Wire shared channels and data from tdns: these are created in tdns
	// MainInit/ParseZones and must be shared so that tdns refresh callbacks
	// and HsyncEngine/SDE operate on the same state.
	conf.InternalMp.SyncQ = conf.Config.Internal.SyncQ
	conf.InternalMp.MPZoneNames = conf.Config.Internal.MPZoneNames

	// Initialize CombinerState (agent-side: just an ErrorJournal, no chunk handler)
	combinerID := "combiner"
	if mp.Combiner != nil && mp.Combiner.Identity != "" {
		combinerID = dns.Fqdn(mp.Combiner.Identity)
	}
	conf.InternalMp.CombinerState = &tdns.CombinerState{
		ErrorJournal: tdns.NewErrorJournal(1000, 24*time.Hour),
	}
	conf.Config.Internal.CombinerState = conf.InternalMp.CombinerState // dual-write

	// Initialize HsyncDB and HSYNC database tables
	kdb := conf.Config.Internal.KeyDB
	if kdb != nil {
		conf.InternalMp.HsyncDB = NewHsyncDB(kdb)
		if err := conf.InternalMp.HsyncDB.InitHsyncTables(); err != nil {
			return fmt.Errorf("InitHsyncTables: %w", err)
		}
	}

	// Create MsgQs locally
	conf.InternalMp.MsgQs = NewMsgQs()

	// Initialize distribution cache
	conf.InternalMp.DistributionCache = NewDistributionCache()
	StartDistributionGC(conf.InternalMp.DistributionCache, 1*time.Minute, conf.Config.Internal.StopCh)
	conf.Config.Internal.DistributionCache = conf.InternalMp.DistributionCache // dual-write

	// Chunk mode configuration
	controlZone := mp.Dns.ControlZone
	if controlZone == "" {
		controlZone = mp.Identity
	}
	chunkMode := mp.Dns.ChunkMode
	if chunkMode == "" {
		chunkMode = "edns0"
	}

	var chunkStore tdns.ChunkPayloadStore
	var chunkQueryEndpoint string
	var chunkQueryEndpointInNotify bool
	if chunkMode == "query" {
		cep := strings.TrimSpace(mp.Dns.ChunkQueryEndpoint)
		if cep != "include" && cep != "none" {
			return fmt.Errorf("agent.dns.chunk_mode=query requires chunk_query_endpoint \"include\" or \"none\" (got %q)", mp.Dns.ChunkQueryEndpoint)
		}
		chunkQueryEndpointInNotify = (cep == "include")
		chunkStore = tdns.NewMemChunkPayloadStore(5 * time.Minute)
		conf.InternalMp.ChunkPayloadStore = chunkStore
		if err := tdns.RegisterChunkQueryHandler(chunkStore); err != nil {
			return fmt.Errorf("RegisterChunkQueryHandler: %w", err)
		}
		chunkQueryEndpoint = buildAgentChunkQueryEndpoint(mp)
	}

	// Initialize PayloadCrypto for secure CHUNK transport (optional)
	var payloadCrypto *transport.PayloadCrypto
	if strings.TrimSpace(mp.LongTermJosePrivKey) != "" {
		pc, err := initAgentCrypto(conf.Config)
		if err != nil {
			return fmt.Errorf("failed to initialize agent crypto: %w", err)
		}
		payloadCrypto = pc
	}

	// Extract signer peer config for KEYSTATE signaling
	var signerID, signerAddress string
	if mp.Signer != nil {
		if mp.Signer.Identity != "" {
			signerID = dns.Fqdn(mp.Signer.Identity)
		}
		signerAddress = mp.Signer.Address
	}

	// Create MPTransportBridge
	tm := NewMPTransportBridge(&MPTransportBridgeConfig{
		LocalID:                    dns.Fqdn(mp.Identity),
		ControlZone:                dns.Fqdn(controlZone),
		APITimeout:                 10 * time.Second,
		DNSTimeout:                 5 * time.Second,
		AgentRegistry:              conf.InternalMp.AgentRegistry,
		MsgQs:                      conf.InternalMp.MsgQs,
		ChunkMode:                  chunkMode,
		ChunkPayloadStore:          chunkStore,
		ChunkQueryEndpoint:         chunkQueryEndpoint,
		ChunkQueryEndpointInNotify: chunkQueryEndpointInNotify,
		ChunkMaxSize:               mp.Dns.ChunkMaxSize,
		PayloadCrypto:              payloadCrypto,
		DistributionCache:          conf.InternalMp.DistributionCache,
		SupportedMechanisms:        mp.SupportedMechanisms,
		CombinerID:                 combinerID,
		SignerID:                   signerID,
		SignerAddress:              signerAddress,
		AuthorizedPeers: func() []string {
			var peers []string
			for _, p := range mp.AuthorizedPeers {
				peers = append(peers, dns.Fqdn(p))
			}
			if mp.Combiner != nil && mp.Combiner.Identity != "" {
				peers = append(peers, dns.Fqdn(mp.Combiner.Identity))
			}
			if mp.Signer != nil && mp.Signer.Identity != "" {
				peers = append(peers, dns.Fqdn(mp.Signer.Identity))
			}
			return peers
		},
		MessageRetention: func(operation string) int {
			return mp.Dns.MessageRetention.GetRetentionForMessageType(operation)
		},
		GetImrEngine:   func() *tdns.Imr { return conf.Config.Internal.ImrEngine },
		GetZone:        tdns.Zones.Get,
		GetZoneNames:   tdns.Zones.Keys,
		ClientCertFile: mp.Api.CertFile,
		ClientKeyFile:  mp.Api.KeyFile,
	})
	conf.InternalMp.MPTransport = tm
	conf.InternalMp.TransportManager = tm.TransportManager
	conf.Config.Internal.TransportManager = tm.TransportManager // dual-write
	conf.InternalMp.AgentRegistry.TransportManager = tm.TransportManager
	conf.InternalMp.AgentRegistry.MPTransport = tm

	return nil
}

// buildAgentChunkQueryEndpoint builds the CHUNK query endpoint (host:port) from agent DNS config.
func buildAgentChunkQueryEndpoint(mp *tdns.MultiProviderConf) string {
	if mp == nil {
		return ""
	}
	dnsConf := &mp.Dns
	port := dnsConf.Port
	if port == 0 {
		port = 53
	}
	var host string
	if len(dnsConf.Addresses.Publish) > 0 {
		host = strings.TrimSpace(dnsConf.Addresses.Publish[0])
	}
	if host == "" && len(dnsConf.Addresses.Listen) > 0 {
		host = strings.TrimSpace(dnsConf.Addresses.Listen[0])
	}
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// initAgentCrypto initializes PayloadCrypto for the agent from MultiProviderConf.
// Loads the agent's JOSE private key and the combiner's public key (if configured).
func initAgentCrypto(conf *tdns.Config) (*transport.PayloadCrypto, error) {
	mp := conf.MultiProvider
	if mp == nil {
		return nil, fmt.Errorf("multi-provider config is not set")
	}

	backend := jose.NewBackend()

	privKeyPath := strings.TrimSpace(mp.LongTermJosePrivKey)
	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("private key file not found: %q: %w", privKeyPath, err)
		}
		return nil, fmt.Errorf("read private key %q: %w", privKeyPath, err)
	}
	privKeyData = StripKeyFileComments(privKeyData)

	privKey, err := backend.ParsePrivateKey(privKeyData)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	joseBackend, ok := backend.(*jose.Backend)
	if !ok {
		return nil, fmt.Errorf("backend is not JOSE")
	}
	pubKey, err := joseBackend.PublicFromPrivate(privKey)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	pc, err := transport.NewPayloadCrypto(&transport.PayloadCryptoConfig{
		Backend: backend,
		Enabled: true,
	})
	if err != nil {
		return nil, fmt.Errorf("create PayloadCrypto: %w", err)
	}

	pc.SetLocalKeys(privKey, pubKey)

	// Load combiner's public key if configured
	if mp.Combiner != nil && strings.TrimSpace(mp.Combiner.LongTermJosePubKey) != "" {
		combinerPubKeyPath := strings.TrimSpace(mp.Combiner.LongTermJosePubKey)
		combinerPubKeyData, err := os.ReadFile(combinerPubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("initAgentCrypto: failed to read combiner public key %q: %w", combinerPubKeyPath, err)
		}
		combinerPubKeyData = StripKeyFileComments(combinerPubKeyData)
		combinerPubKey, err := backend.ParsePublicKey(combinerPubKeyData)
		if err != nil {
			return nil, fmt.Errorf("initAgentCrypto: failed to parse combiner public key: %w", err)
		}
		combinerPeerID := dns.Fqdn(mp.Combiner.Identity)
		pc.AddPeerKey(combinerPeerID, combinerPubKey)
		pc.AddPeerVerificationKey(combinerPeerID, combinerPubKey)
	}

	return pc, nil
}
