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
	// The key lifecycle hooks, before tdns's MainInit: they must be in place
	// before any zone's first refresh, and they are what makes tdns's
	// keystore and key-state worker run the multi-provider key protocol for
	// zones that carry the option (signer_keydb.go).
	RegisterMPKeyLifecycleHooks(conf)

	// Register MP zone option handler before ParseZones runs inside MainInit.
	tdns.RegisterZoneOptionHandler(tdns.OptMultiProvider, func(zname string, options map[tdns.ZoneOption]bool) {
		conf.InternalMp.MPZoneNames = append(conf.InternalMp.MPZoneNames, zname)
	})

	// Register MP zone option validators before ParseZones runs.
	// These replace the hardcoded validation in tdns's parseZoneOptions.
	tdns.RegisterZoneOptionValidator(OptMPManualApproval,
		func(c *tdns.Config, zname string, zd *tdns.ZoneData, options map[tdns.ZoneOption]bool) bool {
			if tdns.Globals.App.Type != AppTypeMPCombiner {
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
			// On the signer, require server-level multi-provider config.
			// On agents, the zone option alone is sufficient — the HSYNC RRset is the authority.
			//
			// Zone-option validators fire during ParseZones, which
			// runs after ParseConfig — by which time
			// RegisterMpConfigParser's hook has populated
			// wiredMpConfig. So WiredMpConfig() is safe to read here
			// even though the *tdns.Config param has no
			// MultiProvider field (post-bite-9b).
			mp := WiredMpConfig()
			if tdns.Globals.App.Type == AppTypeMPSigner && (mp == nil || !mp.Active) {
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

	// MP config validation runs from inside the parser hook
	// (RegisterMpConfigParser), not via tdns's PostValidateConfigHook —
	// validators need the parsed *MultiProviderConf, which the parser
	// hook produces. See ValidateMPConfig in config_validate.go.

	// Register the MP-config parser. Fires from tdns.ParseConfig's
	// PostParseConfigHook and stashes the parse on
	// conf.InternalMp.MpConfig — the runtime source of truth for MP
	// config (via conf.MpConfig() / WiredMpConfig()).
	conf.RegisterMpConfigParser()

	// Reset MPZoneNames before ParseZones re-collects them via the callback above
	conf.InternalMp.MPZoneNames = nil

	// DNS infrastructure (zones, KeyDB, handlers, channels)
	if err := conf.Config.MainInit(ctx, defaultcfg); err != nil {
		return err
	}
	// wiredMpConfig is set by RegisterMpConfigParser's hook during
	// tdns.ParseConfig (inside conf.Config.MainInit above), so the
	// two accessors should be live by the time we get here.
	// A config without a multi-provider: block is legitimate here (the
	// role-specific init below is skipped for it); the accessor check
	// only applies when there is a block.
	if conf.MpConfig() != nil {
		if err := verifyMpConfigAccessors(conf); err != nil {
			return err
		}
	}

	// Second pass: populate MPdata on MP zones and attach OnFirstLoad
	// callbacks. Safe because OnFirstLoad fires later in RefreshEngine,
	// not during ParseZones.
	conf.ForEachMPZone(func(zd *MPZoneData) {
		zd.Lock()
		zd.EnsureMP()
		if zd.MP.MPdata != nil {
			cp := *zd.MP.MPdata
			zd.MP.MPdata = &cp
			zd.MP.MPdata.Options = map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}
		} else {
			zd.MP.MPdata = &MPdata{
				Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
			}
		}
		zd.Unlock()

		// The signer's zones sign through tdns: MPPreRefresh switches
		// inline-signing on before the first publish, the policy binds
		// through the zone's dnssecpolicy, signOnceAfterPolicyBind signs
		// and flips Ready, every refresh signs its staged scope, and the
		// ResignerEngine renews. tdns registers only zones whose config
		// carries a signing option, and MP switches it on dynamically, so
		// a zone it switched on is put on the resigner's watchlist here.
		if tdns.Globals.App.Type == AppTypeMPSigner && zd.FirstZoneLoad {
			zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *tdns.ZoneData) {
				if !zd.Options[tdns.OptInlineSigning] {
					return
				}
				q := conf.Config.Internal.ResignQ
				if q == nil {
					return
				}
				select {
				case q <- tdns.ResignRequest{Zd: zd, Reason: tdns.ResignPeriodic}:
				case <-time.After(5 * time.Second):
					lg.Error("timeout registering zone for periodic re-signing", "zone", zd.ZoneName)
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

	mp := conf.MpConfig()
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
	case "auditor":
		return conf.initMPAuditor(mp)
	default:
		return fmt.Errorf("unsupported multi-provider.role: %q", mp.Role)
	}
}

// initMPSigner performs signer-specific MP initialization.
func (conf *Config) initMPSigner(mp *MultiProviderConf) error {

	if mp.Identity == "" {
		return fmt.Errorf("multi-provider.identity is required when multi-provider.active is true")
	}
	if len(mp.Agents) == 0 {
		return fmt.Errorf("multi-provider.agents is required when multi-provider.active is true")
	}

	kdb := conf.Config.Internal.KeyDB
	if kdb == nil {
		return fmt.Errorf("KeyDB is required for MP signer")
	}
	conf.InternalMp.HsyncDB = NewHsyncDB(kdb)
	if err := conf.InternalMp.HsyncDB.InitHsyncTables(); err != nil {
		return fmt.Errorf("InitHsyncTables: %w", err)
	}

	// Initialize PayloadCrypto for secure CHUNK transport (optional)
	var signerPayloadCrypto *transport.PayloadCrypto
	if strings.TrimSpace(mp.LongTermJosePrivKey) != "" {
		pc, err := newPayloadCrypto(mp, roleSigner)
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

	// Create TransportManager for signer<->agent communication
	chunkMode := strings.TrimSpace(mp.ChunkMode)
	if chunkMode == "" {
		chunkMode = "edns0"
	}
	controlZone := dns.Fqdn(mp.Identity)
	tm, err := NewMPTransportBridge(&MPTransportBridgeConfig{
		Role:                roleSigner,
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
	if err != nil {
		return fmt.Errorf("transport bridge (signer): %w", err)
	}
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

	// Wire chunk handler into TM
	tm.ChunkHandler = signerState.ChunkHandler()

	// Initialize signer router
	// C3: the signer's router is the generic transport router (middleware
	// + hello/beat/ping; no confirm handler, as before) plus the signer's
	// application verbs from the MP verb table.
	signerRouter := transport.NewDNSMessageRouter()
	signerRouterCfg := &transport.RouterConfig{
		PeerRegistry: tm.PeerRegistry,
	}
	if err := transport.InitializeRouter(signerRouter, signerRouterCfg); err != nil {
		return fmt.Errorf("InitializeRouter (signer): %w", err)
	}
	if err := tm.RegisterAppVerbs(signerRouter, roleSigner); err != nil {
		return fmt.Errorf("RegisterAppVerbs (signer): %w", err)
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
			agentPeer.DNSEndpoint = fmt.Sprintf("dns://%s:%d/", host, port) // S2 display
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
func (conf *Config) initMPCombiner(mp *MultiProviderConf) error {
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
		pc, err := newPayloadCrypto(mp, roleCombiner)
		if err != nil {
			return fmt.Errorf("failed to initialize combiner crypto: %w", err)
		}
		secureWrapper = transport.NewSecurePayloadWrapper(pc)
	}

	// Register CHUNK handler
	combinerState, err := RegisterCombinerChunkHandler(dns.Fqdn(mp.Identity), secureWrapper)
	if err != nil {
		return fmt.Errorf("RegisterCombinerChunkHandler: %w", err)
	}
	combinerState.ProtectedNamespaces = mp.ProtectedNamespaces
	conf.InternalMp.CombinerState = combinerState

	// Create MsgQs locally
	conf.InternalMp.MsgQs = NewMsgQs()

	// Initialize distribution cache
	conf.InternalMp.DistributionCache = NewDistributionCache()
	StartDistributionGC(conf.InternalMp.DistributionCache, 1*time.Minute, conf.Config.Internal.StopCh)

	// Create TransportManager
	var combinerPayloadCrypto *transport.PayloadCrypto
	if secureWrapper != nil {
		combinerPayloadCrypto = secureWrapper.GetCrypto()
	}
	if chunkMode == "" {
		chunkMode = "edns0"
	}
	tm, err := NewMPTransportBridge(&MPTransportBridgeConfig{
		Role:                roleCombiner,
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
	if err != nil {
		return fmt.Errorf("transport bridge (combiner): %w", err)
	}
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
			agentPeer.DNSEndpoint = fmt.Sprintf("dns://%s:%d/", host, port) // S2 display
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
	// C3: the combiner's router is the generic transport router (middleware
	// + hello/beat/ping; no confirm handler, as before) plus the combiner's
	// application verbs (rfi, status-update, update) from the MP verb table.
	combinerRouter := transport.NewDNSMessageRouter()
	combinerRouterCfg := &transport.RouterConfig{
		PeerRegistry: tm.PeerRegistry,
	}
	if err := transport.InitializeRouter(combinerRouter, combinerRouterCfg); err != nil {
		return fmt.Errorf("InitializeRouter (combiner): %w", err)
	}
	if err := tm.RegisterAppVerbs(combinerRouter, roleCombiner); err != nil {
		return fmt.Errorf("RegisterAppVerbs (combiner): %w", err)
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
func (conf *Config) initMPAgent(mp *MultiProviderConf) error {
	if mp.Identity == "" {
		return fmt.Errorf("multi-provider.identity is required for agent role")
	}

	// Initialize AgentRegistry
	conf.InternalMp.AgentRegistry = conf.NewAgentRegistry()

	// Create SyncQ locally (was previously shared from tdns, now owned by tdns-mp)
	conf.InternalMp.SyncQ = make(chan SyncRequest, 10)
	// MPZoneNames is populated directly by the OptMultiProvider callback above

	// Initialize CombinerState (agent-side: just an ErrorJournal, no chunk handler)
	combinerID := "combiner"
	if mp.Combiner != nil && mp.Combiner.Identity != "" {
		combinerID = dns.Fqdn(mp.Combiner.Identity)
	}
	conf.InternalMp.CombinerState = &CombinerState{
		ErrorJournal: NewErrorJournal(1000, 24*time.Hour),
	}

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

	// Chunk mode configuration
	controlZone := mp.Dns.ControlZone
	if controlZone == "" {
		controlZone = mp.Identity
	}
	chunkMode := mp.Dns.ChunkMode
	if chunkMode == "" {
		chunkMode = "edns0"
	}

	var chunkStore ChunkPayloadStore
	var chunkQueryEndpoint string
	var chunkQueryEndpointInNotify bool
	if chunkMode == "query" {
		cep := strings.TrimSpace(mp.Dns.ChunkQueryEndpoint)
		if cep != "include" && cep != "none" {
			return fmt.Errorf("agent.dns.chunk_mode=query requires chunk_query_endpoint \"include\" or \"none\" (got %q)", mp.Dns.ChunkQueryEndpoint)
		}
		chunkQueryEndpointInNotify = (cep == "include")
		chunkStore = NewMemChunkPayloadStore(5 * time.Minute)
		conf.InternalMp.ChunkPayloadStore = chunkStore
		if err := RegisterChunkQueryHandler(chunkStore); err != nil {
			return fmt.Errorf("RegisterChunkQueryHandler: %w", err)
		}
		chunkQueryEndpoint = buildAgentChunkQueryEndpoint(mp)
	}

	// Initialize PayloadCrypto for secure CHUNK transport (optional)
	var payloadCrypto *transport.PayloadCrypto
	if strings.TrimSpace(mp.LongTermJosePrivKey) != "" {
		pc, err := newPayloadCrypto(mp, roleAgent)
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
	tm, err := NewMPTransportBridge(&MPTransportBridgeConfig{
		Role:                       roleAgent,
		BeatInterval:               mp.Remote.BeatInterval,
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
		GetImrEngine: func() *Imr {
			return &Imr{conf.Config.Internal.ImrEngine}
		},
		GetZone:        tdns.Zones.Get,
		GetZoneNames:   tdns.Zones.Keys,
		ClientCertFile: mp.Api.CertFile,
		ClientKeyFile:  mp.Api.KeyFile,
	})
	if err != nil {
		return fmt.Errorf("transport bridge (agent): %w", err)
	}
	conf.InternalMp.MPTransport = tm
	conf.InternalMp.TransportManager = tm.TransportManager
	conf.InternalMp.AgentRegistry.TransportManager = tm.TransportManager
	conf.InternalMp.AgentRegistry.MPTransport = tm

	return nil
}

// initMPAuditor performs auditor-specific MP initialization.
// Modeled on initMPAgent but skips combiner/signer-as-peer registration,
// HsyncDB tables, and outbound-sync queues. Reuses the same MP
// transport bridge configuration so the auditor participates in BEAT/
// gossip exactly like an agent on the wire.
func (conf *Config) initMPAuditor(mp *MultiProviderConf) error {
	if mp.Identity == "" {
		return fmt.Errorf("multi-provider.identity is required for auditor role")
	}

	conf.InternalMp.AgentRegistry = conf.NewAgentRegistry()

	// MsgQs: auditor consumes Beat/Hello/Ping/Msg/Confirmation/StatusUpdate.
	conf.InternalMp.MsgQs = NewMsgQs()

	// Distribution cache: auditor sends BEATs/HELLOs (not zone data),
	// so distribution tracking is still useful for the management API.
	conf.InternalMp.DistributionCache = NewDistributionCache()
	StartDistributionGC(conf.InternalMp.DistributionCache, 1*time.Minute, conf.Config.Internal.StopCh)

	controlZone := mp.Dns.ControlZone
	if controlZone == "" {
		controlZone = mp.Identity
	}
	chunkMode := mp.Dns.ChunkMode
	if chunkMode == "" {
		chunkMode = "edns0"
	}

	var chunkStore ChunkPayloadStore
	var chunkQueryEndpoint string
	var chunkQueryEndpointInNotify bool
	if chunkMode == "query" {
		cep := strings.TrimSpace(mp.Dns.ChunkQueryEndpoint)
		if cep != "include" && cep != "none" {
			return fmt.Errorf("auditor.dns.chunk_mode=query requires chunk_query_endpoint \"include\" or \"none\" (got %q)", mp.Dns.ChunkQueryEndpoint)
		}
		chunkQueryEndpointInNotify = (cep == "include")
		chunkStore = NewMemChunkPayloadStore(5 * time.Minute)
		conf.InternalMp.ChunkPayloadStore = chunkStore
		if err := RegisterChunkQueryHandler(chunkStore); err != nil {
			return fmt.Errorf("RegisterChunkQueryHandler: %w", err)
		}
		chunkQueryEndpoint = buildAgentChunkQueryEndpoint(mp)
	}

	var payloadCrypto *transport.PayloadCrypto
	if strings.TrimSpace(mp.LongTermJosePrivKey) != "" {
		pc, err := newPayloadCrypto(mp, roleAuditor)
		if err != nil {
			return fmt.Errorf("failed to initialize auditor crypto: %w", err)
		}
		payloadCrypto = pc
	}

	tm, err := NewMPTransportBridge(&MPTransportBridgeConfig{
		Role:                       roleAuditor,
		BeatInterval:               mp.Remote.BeatInterval,
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
		// CombinerID/SignerID intentionally unset: the auditor talks
		// to peer agents (HSYNC3 members), not to combiner/signer as
		// infra peers.
		AuthorizedPeers: func() []string {
			var peers []string
			for _, p := range mp.AuthorizedPeers {
				peers = append(peers, dns.Fqdn(p))
			}
			return peers
		},
		MessageRetention: func(operation string) int {
			return mp.Dns.MessageRetention.GetRetentionForMessageType(operation)
		},
		GetImrEngine: func() *Imr {
			return &Imr{conf.Config.Internal.ImrEngine}
		},
		GetZone:        tdns.Zones.Get,
		GetZoneNames:   tdns.Zones.Keys,
		ClientCertFile: mp.Api.CertFile,
		ClientKeyFile:  mp.Api.KeyFile,
	})
	if err != nil {
		return fmt.Errorf("transport bridge (auditor): %w", err)
	}
	conf.InternalMp.MPTransport = tm
	conf.InternalMp.TransportManager = tm.TransportManager
	conf.InternalMp.AgentRegistry.TransportManager = tm.TransportManager
	conf.InternalMp.AgentRegistry.MPTransport = tm

	return nil
}

// buildAgentChunkQueryEndpoint builds the CHUNK query endpoint (host:port) from agent DNS config.
func buildAgentChunkQueryEndpoint(mp *MultiProviderConf) string {
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
