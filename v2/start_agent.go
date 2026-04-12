/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP agent startup: StartMPAgent replicates tdns.StartAgent but
 * reads MP fields from conf.InternalMp and DNS fields from
 * conf.Config.Internal.
 */
package tdnsmp

import (
	"context"
	"fmt"
	"time"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"
	"github.com/spf13/viper"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

func (conf *Config) StartMPAgent(ctx context.Context, apirouter *mux.Router) error {
	tdns.StartEngine(&tdns.Globals.App, "APIdispatcher", func() error {
		return tdns.APIdispatcher(conf.Config, apirouter, conf.Config.Internal.APIStopCh)
	})

	// In tdns-agent, IMR is active by default unless explicitly set to false
	imrActive := conf.Config.Imr.Active == nil || *conf.Config.Imr.Active
	if imrActive {
		tdns.StartEngine(&tdns.Globals.App, "ImrEngine", func() error {
			return conf.Config.ImrEngine(ctx, true)
		})
	} else {
		lgAgent.Info("NOT starting imrengine (explicitly set to false)",
			"app", tdns.Globals.App.Name, "mode", tdns.AppTypeToString[tdns.Globals.App.Type])
	}

	hdb := NewHsyncDB(conf.Config.Internal.KeyDB)

	// Register tdns-mp PreRefresh/PostRefresh closures on MP zones
	// and install hook so new zones added via reload also get them.
	conf.RegisterMPRefreshCallbacks()
	conf.Config.Internal.PostParseZonesHook = conf.RegisterMPRefreshCallbacks

	tdns.StartEngineNoError(&tdns.Globals.App, "RefreshEngine", func() {
		tdns.RefreshEngine(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "Notifier", func() error {
		return tdns.Notifier(ctx, conf.Config.Internal.NotifyQ)
	})

	// Register CHUNK NOTIFY handler and start incoming DNS message router (must be before NotifyHandler)
	if conf.InternalMp.TransportManager != nil {
		if err := conf.InternalMp.MPTransport.RegisterChunkNotifyHandler(); err != nil {
			lgAgent.Error("failed to register CHUNK NOTIFY handler", "err", err)
		} else {
			conf.InternalMp.MPTransport.StartIncomingMessageRouter(ctx)
		}
	}

	// Initialize combiner as a virtual peer so HsyncEngine can manage heartbeats
	if err := conf.InternalMp.AgentRegistry.InitializeCombinerAsPeer(conf); err != nil {
		lgAgent.Warn("failed to initialize combiner as peer, continuing without combiner heartbeat monitoring", "err", err)
	}
	// Initialize signer as a virtual peer so it shows in "agent peer list" and can be pinged
	if err := conf.InternalMp.AgentRegistry.InitializeSignerAsPeer(conf); err != nil {
		lgAgent.Warn("failed to initialize signer as peer, continuing without signer peer registration", "err", err)
	}

	// Start the reliable message queue (must be after combiner peer initialization)
	if conf.InternalMp.TransportManager != nil {
		conf.InternalMp.MPTransport.StartReliableQueue(ctx)
	}

	// Leader election manager for coordinated parent delegation sync (DDNS)
	tm := conf.InternalMp.MPTransport
	msgQs := conf.InternalMp.MsgQs
	ar := conf.InternalMp.AgentRegistry
	leaderTTL := viper.GetDuration("delegationsync.leader-election-ttl")
	if leaderTTL == 0 {
		leaderTTL = 60 * time.Minute
	}
	lem := NewLeaderElectionManager(
		AgentId(conf.Config.MultiProvider.Identity), leaderTTL,
		func(zone ZoneName, rfiType string, records map[string][]string) error {
			return ar.broadcastElectToZone(zone, rfiType, records)
		},
	)
	conf.InternalMp.LeaderElectionManager = lem
	ar.LeaderElectionManager = lem

	// Wire operational peers counter for re-election decisions
	lem.SetOperationalPeersFunc(func(zone ZoneName) int {
		zad, err := ar.GetZoneAgentData(zone)
		if err != nil {
			return 0
		}
		count := 0
		for _, agent := range zad.Agents {
			if agent.Identity != AgentId(conf.Config.MultiProvider.Identity) && agent.IsAnyTransportOperational() {
				count++
			}
		}
		return count
	})

	// Wire configured peers counter — elections require ALL configured peers.
	lem.SetConfiguredPeersFunc(func(zone ZoneName) int {
		zd, exists := Zones.Get(string(zone))
		if !exists || zd == nil {
			return 0
		}
		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil || apex == nil {
			return 0
		}
		hsync3RRset, exists := apex.RRtypes.Get(core.TypeHSYNC3)
		if !exists {
			return 0
		}
		count := len(hsync3RRset.RRs) - 1
		if count < 0 {
			count = 0
		}
		return count
	})

	// Wire provider group manager into leader election manager
	if ar.ProviderGroupManager != nil {
		lem.SetProviderGroupManager(ar.ProviderGroupManager)
	}

	// Attach OnFirstLoad callbacks to zone stubs.
	delegationSyncQ := conf.Config.Internal.DelegationSyncQ
	for _, zoneName := range conf.Config.Internal.AllZones {
		zd, exists := Zones.Get(zoneName)
		if !exists {
			continue
		}
		// Detect parentsync=agent from HSYNCPARAM and enable delegation sync.
		if zd.Options[tdns.OptMultiProvider] {
			zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *tdns.ZoneData) {
				if zd.Options[tdns.OptDelSyncChild] {
					return // already set via static config
				}
				mp := conf.Config.MultiProvider
				if mp == nil {
					return
				}
				ourIds := ourHsyncIdentities(mp)
				matched, _, _ := matchHsyncIdentity(zd, ourIds)
				if !matched {
					return
				}
				hp := getHSYNCPARAM(zd)
				if hp == nil {
					return
				}
				if hp.GetParentSync() == core.HsyncParentSyncAgent {
					lgAgent.Info("HSYNCPARAM parentsync=agent, enabling delegation sync", "zone", zd.ZoneName)
					zd.Options[tdns.OptDelSyncChild] = true
					if err := zd.SetupZoneSync(delegationSyncQ); err != nil {
						lgAgent.Error("SetupZoneSync failed in MP OnFirstLoad", "zone", zd.ZoneName, "err", err)
					}
				}
			})
		}
		// Leader election callback (must run after parentsync detection above).
		if zd.Options[tdns.OptDelSyncChild] || zd.Options[tdns.OptMultiProvider] {
			zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *tdns.ZoneData) {
				if !zd.Options[tdns.OptDelSyncChild] {
					return
				}
				zone := ZoneName(zd.ZoneName)
				configured := lem.configuredPeers(zone)
				if configured == 0 {
					lem.StartElection(zone, 0)
				} else {
					if lem.providerGroupMgr != nil {
						pg := lem.providerGroupMgr.GetGroupForZone(zone)
						if pg != nil {
							lem.DeferGroupElection(pg.GroupHash)
							return
						}
					}
					lem.DeferElection(zone)
				}
			})
		}
	}

	// When the local agent wins leader election: ensure we have a SIG(0) key,
	// then publish KEY to combiner and sync to remote agents.
	lem.SetOnLeaderElected(func(zone ZoneName) error {
		zd, ok := Zones.Get(string(zone))
		if !ok || zd == nil {
			return fmt.Errorf("onLeaderElected: zone %s not found", zone)
		}
		if !zd.Options[tdns.OptDelSyncChild] {
			lgAgent.Info("onLeaderElected: zone does not have OptDelSyncChild, skipping", "zone", zone)
			return nil
		}
		lgAgent.Info("onLeaderElected: processing", "zone", zone)

		if tdns.Globals.ImrEngine == nil {
			lgAgent.Debug("onLeaderElected: IMR not available, skipping DSYNC bootstrap", "zone", zone)
			return nil
		}
		_, err := tdns.Globals.ImrEngine.LookupDSYNCTarget(context.Background(), string(zone), dns.TypeANY, core.SchemeUpdate)
		if err != nil {
			lgAgent.Info("onLeaderElected: parent does not advertise DSYNC UPDATE scheme, skipping SIG(0) key setup",
				"zone", zone, "err", err)
			return nil
		}

		keyName := string(zone)
		// Step a: check local keystore
		sak, err := hdb.GetSig0Keys(keyName, tdns.Sig0StateActive)
		if err == nil && len(sak.Keys) > 0 {
			lgAgent.Info("leader has local SIG(0) key, proceeding to publish",
				"zone", zone, "keyid", sak.Keys[0].KeyId)
			goto publish
		}
		// Step b: ask peers via RFI CONFIG subtype=sig0key
		{
			zad, err := ar.GetZoneAgentData(zone)
			if err == nil {
				for _, agent := range zad.Agents {
					if agent.Identity == AgentId(ar.LocalAgent.Identity) {
						continue
					}
					if !agent.IsAnyTransportOperational() {
						continue
					}
					lgAgent.Info("asking peer for SIG(0) key", "zone", zone, "peer", agent.Identity)
					configResp := RequestAndWaitForConfig(ar, agent, string(zone), "sig0key", msgQs)
					if configResp == nil {
						lgAgent.Info("peer did not respond to CONFIG sig0key", "zone", zone, "peer", agent.Identity)
						continue
					}
					if len(configResp.ConfigData) > 0 && configResp.ConfigData["status"] != "no sig0 key for zone" {
						if err := importSig0KeyFromPeer(hdb, keyName, configResp.ConfigData); err != nil {
							lgAgent.Error("failed to import SIG(0) key from peer",
								"zone", zone, "peer", agent.Identity, "err", err)
							continue
						}
						lgAgent.Info("imported SIG(0) key from peer", "zone", zone, "peer", agent.Identity)
						goto publish
					}
					lgAgent.Info("peer does not have SIG(0) key", "zone", zone, "peer", agent.Identity)
				}
			}
		}
		// Step c: no peer has the key — generate a new keypair
		lgAgent.Info("no peer has SIG(0) key, will generate new keypair", "zone", zone)
		{
			alg, err := parseKeygenAlgorithm("delegationsync.child.update.keygen.algorithm", dns.ED25519)
			if err != nil {
				return fmt.Errorf("onLeaderElected: parseKeygenAlgorithm: %v", err)
			}
			kp := tdns.KeystorePost{
				Command:    "sig0-mgmt",
				SubCommand: "generate",
				Zone:       zd.ZoneName,
				Keyname:    keyName,
				Algorithm:  alg,
				State:      tdns.Sig0StateActive,
				Creator:    "leader-election",
			}
			resp, err := hdb.Sig0KeyMgmt(nil, kp)
			if err != nil {
				return fmt.Errorf("onLeaderElected: failed to generate SIG(0) keypair: %v", err)
			}
			lgAgent.Info("generated SIG(0) keypair", "zone", zone, "msg", resp.Msg)
		}
	publish:
		// Step d: get the active key and publish to combiner + remote agents
		sak, err = hdb.GetSig0Keys(keyName, tdns.Sig0StateActive)
		if err != nil || len(sak.Keys) == 0 {
			return fmt.Errorf("onLeaderElected: no active SIG(0) key after generation for zone %s", zone)
		}
		keyRR := &sak.Keys[0].KeyRR
		lgAgent.Info("publishing KEY to combiner with PublishInstruction", "zone", zone, "keyid", sak.Keys[0].KeyId)

		zu := &tdns.ZoneUpdate{
			Zone: zone,
			Operations: []core.RROperation{{
				Operation: "replace",
				RRtype:    "KEY",
				Records:   []string{keyRR.String()},
			}},
			Publish: &core.PublishInstruction{
				KEYRRs:    []string{keyRR.String()},
				Locations: []string{"at-apex", "at-ns"},
			},
		}
		distID, err := tm.EnqueueForCombiner(zone, zu, "")
		if err != nil {
			lgAgent.Error("failed to publish KEY to combiner", "zone", zone, "err", err)
			return err
		}
		lgAgent.Info("KEY + PublishInstruction sent to combiner", "zone", zone, "distID", distID)

		agentUpdate := &tdns.ZoneUpdate{
			Zone: zone,
			Operations: []core.RROperation{{
				Operation: "replace",
				RRtype:    "KEY",
				Records:   []string{keyRR.String()},
			}},
		}
		if err := tm.EnqueueForZoneAgents(zone, agentUpdate, distID); err != nil {
			lgAgent.Error("failed to enqueue KEY for remote agents", "zone", zone, "err", err)
		}

		// Step e: trigger KeyState inquiry + bootstrap with parent (async)
		if zd.Options[tdns.OptDelSyncChild] {
			keyid := uint16(sak.Keys[0].KeyRR.KeyTag())
			algorithm := sak.Keys[0].KeyRR.Algorithm
			go conf.Config.ParentSyncAfterKeyPublication(zone, keyName, keyid, algorithm)
		}

		return nil
	})

	// Agent-specific engines
	tdns.StartEngineNoError(&tdns.Globals.App, "HsyncEngine", func() {
		conf.HsyncEngine(ctx, conf.InternalMp.MsgQs)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "InfraBeatLoop", func() {
		conf.InternalMp.AgentRegistry.StartInfraBeatLoop(ctx)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "DiscoveryRetrierNG", func() {
		conf.InternalMp.AgentRegistry.DiscoveryRetrierNG(ctx)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "SynchedDataEngine", func() {
		conf.SynchedDataEngine(ctx, conf.InternalMp.MsgQs)
	})

	syncrtr, err := conf.Config.SetupAgentSyncRouter(ctx)
	if err != nil {
		return fmt.Errorf("error setting up agent-to-agent sync router: %v", err)
	}
	tdns.StartEngine(&tdns.Globals.App, "APIdispatcherNG", func() error {
		lgAgent.Info("starting agent-to-agent sync engine",
			"app", tdns.Globals.App.Name, "mode", tdns.AppTypeToString[tdns.Globals.App.Type])
		return tdns.APIdispatcherNG(conf.Config, syncrtr,
			conf.Config.MultiProvider.Api.Addresses.Listen,
			conf.Config.MultiProvider.Api.CertFile,
			conf.Config.MultiProvider.Api.KeyFile,
			conf.Config.Internal.APIStopCh)
	})

	tdns.StartEngineNoError(&tdns.Globals.App, "AuthQueryEngine", func() {
		tdns.AuthQueryEngine(ctx, conf.Config.Internal.AuthQueryQ)
	})
	tdns.StartEngine(&tdns.Globals.App, "ScannerEngine", func() error {
		return tdns.ScannerEngine(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "ZoneUpdaterEngine", func() error {
		return hdb.ZoneUpdaterEngine(ctx)
	})
	tdns.StartEngine(&tdns.Globals.App, "DeferredUpdaterEngine", func() error {
		return hdb.DeferredUpdaterEngine(ctx)
	})
	tdns.StartEngine(&tdns.Globals.App, "UpdateHandler", func() error {
		return tdns.UpdateHandler(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "DelegationSyncher", func() error {
		return hdb.DelegationSyncher(ctx, conf.Config.Internal.DelegationSyncQ, conf.Config.Internal.NotifyQ, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "NotifyHandler", func() error {
		return tdns.NotifyHandler(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "DnsEngine", func() error {
		return tdns.DnsEngine(ctx, conf.Config)
	})

	// Setup agent identity and publish transport records. Must run after
	// ZoneUpdaterEngine is started, because PublishUriRR/PublishAddrRR/etc.
	// send on KeyDB.UpdateQ and block until a consumer drains it.
	if err := conf.SetupAgent(conf.Config.Internal.AllZones); err != nil {
		return fmt.Errorf("SetupAgent: %w", err)
	}

	return nil
}
