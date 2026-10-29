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
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

// The leader's lease when delegationsync.leader-election-ttl is not set, and
// the shortest lease that is taken as given.
const (
	defaultLeaderElectionTTL = 60 * time.Minute
	minLeaderElectionTTL     = time.Minute
)

// leaderElectionTTL is the leader's lease from the config. The value takes a
// unit: a bare number is read as nanoseconds, so 300 is a lease of 300 ns,
// and a leader that renews at 90% of that calls one election after another
// (tdns-mp #130). A lease below the floor is such a mistake and not a choice,
// so it is refused with an error and the default is used.
func leaderElectionTTL() time.Duration {
	ttl := viper.GetDuration("delegationsync.leader-election-ttl")
	switch {
	case ttl == 0:
		return defaultLeaderElectionTTL
	case ttl < minLeaderElectionTTL:
		lgAgent.Error("delegationsync.leader-election-ttl is below the floor, using the default; the value takes a unit (5m, 300s), a bare number is nanoseconds",
			"configured", ttl, "floor", minLeaderElectionTTL, "default", defaultLeaderElectionTTL)
		return defaultLeaderElectionTTL
	}
	return ttl
}

func (conf *Config) StartMPAgent(ctx context.Context, apirouter *mux.Router) error {
	mp := conf.MpConfig()
	// The DS engine's queue, before any engine that can sign a zone, as in
	// the signer (ensureDSEngineQueue): here that is the refresh engine, for
	// an identity zone the config lists, and the identity set-up at the end.
	// The engine itself starts further down, beside the delegation syncher.
	ensureDSEngineQueue(conf.Config.Internal.KeyDB)

	tdns.StartEngine(&tdns.Globals.App, "APIdispatcher", func() error {
		return tdns.APIdispatcher(conf.Config, apirouter, conf.Config.Internal.APIStopCh)
	})

	// Initialize IMR synchronously so it's available before transport bridges
	// and agent registries are created. The agent requires a working IMR; if
	// initialization fails, crash early rather than get nil panics later.
	imrActive := conf.Config.Imr.Active == nil || *conf.Config.Imr.Active
	if imrActive {
		if err := conf.Config.InitImrEngine(ctx, true); err != nil {
			log.Fatalf("IMR initialization failed: %v", err)
		}
		tdns.StartEngine(&tdns.Globals.App, "ImrEngine", func() error {
			return conf.Config.ImrEngine(ctx, true)
		})
		conf.warnWhileDnssecNotEnforced(ctx, lgAgent)
	} else {
		lgAgent.Info("NOT starting imrengine (explicitly set to false)",
			"app", tdns.Globals.App.Name, "mode", tdns.AppTypeToString[tdns.Globals.App.Type])
	}

	hdb := NewHsyncDB(conf.Config.Internal.KeyDB)

	// Register tdns-mp PreRefresh/PostRefresh closures on MP zones
	// and install hook so new zones added via reload also get them.
	conf.RegisterMPRefreshCallbacks()
	conf.Config.Internal.PostParseZonesHook = conf.RegisterMPRefreshCallbacks

	// Wire the receive path (CHUNK NOTIFY handler + router dispatch); must
	// run before NotifyHandler (D3: one entry point per role).
	if conf.InternalMp.TransportManager != nil {
		if err := conf.InternalMp.MPTransport.Start(ctx); err != nil {
			return fmt.Errorf("%s receive path: %w", "agent", err)
		}
	}

	// Initialize the combiner and signer as virtual peers BEFORE RefreshEngine
	// starts. RefreshEngine processes zones in a goroutine and the very first
	// MP zone load triggers HsyncChanged → DnskeysChanged → RequestAndWaitForKeyInventory,
	// which encrypts to the signer. Without the signer's JOSE key registered
	// in PayloadCrypto first, that send fails (no encryption key for peer ...);
	// tm.Send then falls back to API which constructs a nonsense URL from the
	// signer's DNS carrier address (udp://host:53/sync) and fails with
	// "unsupported protocol scheme". The combiner has the same shape of race
	// for the same reason. Registering both peers (which loads their public
	// keys) before any engine that could initiate outbound traffic eliminates
	// the race deterministically.
	if err := conf.InternalMp.AgentRegistry.InitializeCombinerAsPeer(conf); err != nil {
		lgAgent.Warn("failed to initialize combiner as peer, continuing without combiner heartbeat monitoring", "err", err)
	}
	if err := conf.InternalMp.AgentRegistry.InitializeSignerAsPeer(conf); err != nil {
		lgAgent.Warn("failed to initialize signer as peer, continuing without signer peer registration", "err", err)
	}

	// The hand-over to the combiner (plan S10) is in place before the first
	// zone load, which hands the combiner what this agent acts by.
	conf.startHandovers(ctx, conf.InternalMp.MPTransport)
	// The zones' thaws (plan S7), asked after a member's telling and at
	// every beat round.
	tdns.StartEngine(&tdns.Globals.App, "Thaws", func() error {
		conf.runThaws(ctx)
		return nil
	})

	// The hsync engine is constructed before RefreshEngine starts (its Run
	// starts further down, with the other agent engines): the first zone
	// load reports every HSYNC3 record as an addition, and PostRefresh
	// applies that diff only when AgentRegistry.HsyncEngine is already set
	// (NewHsyncDataEngine sets it). Same order as the auditor since #39.
	dataEngine := NewHsyncDataEngine(conf)

	// The leader election manager, its callbacks and the zones' first-load
	// callbacks are in place before RefreshEngine starts: a first load it
	// handles before them would skip the election's check of the zone
	// (zoneChanged), the first-load election and the parentsync detection
	// (step 8; the hsync engine moved for the same reason, #39).
	conf.setUpLeaderElection(ctx, mp)
	// The zones are in their groups before their first load, by the serials
	// stored (plan S9), with the election's callbacks in place.
	conf.placeGroupsAtStart()

	tdns.StartEngineNoError(&tdns.Globals.App, "RefreshEngine", func() {
		tdns.RefreshEngine(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "Notifier", func() error {
		return tdns.Notifier(ctx, conf.Config, conf.Config.Internal.NotifyQ)
	})
	tdns.StartEngine(&tdns.Globals.App, "KeyStateWorker", func() error {
		return tdns.KeyStateWorker(ctx, conf.Config)
	})
	// The reader of ResignQ. SetupAgentAutoZone registers the agent's own
	// zone for periodic re-signing on that queue; without an engine reading
	// it the registration sat in the buffer and the zone was never renewed.
	tdns.StartEngineNoError(&tdns.Globals.App, "ResignerEngine", func() {
		tdns.ResignerEngine(ctx, conf.Config.Internal.ResignQ)
	})

	// Start the reliable message queue (must be after combiner peer initialization)
	if conf.InternalMp.TransportManager != nil {
		conf.InternalMp.MPTransport.StartReliableQueue(ctx)
		// A discovered peer is looked up again when its DNS data expires
		// from the resolver's cache, so that it is not used on data whose
		// chain has broken since (#260).
		conf.InternalMp.TransportManager.StartDiscoveryRefresh(ctx)
	}

	// The agent runs tdns's DS engine (below; design Amendment 3, #161) so
	// the leader can send NOTIFY(CDS), but writes no CDS for a
	// multi-provider zone: it holds none of the zone's keys and signs none
	// of them, so the CDS such a zone serves is the signers' (design §4.1,
	// arrow 1), and the DS set the agent hands the parent goes through the
	// owner's DS-intent provider (arrow 2). The one zone the engine writes
	// a CDS for is the agent's own identity zone (T5.6).
	//
	// Agent-specific engines (the hsync data engine itself was constructed
	// above, before RefreshEngine)
	tdns.StartEngineNoError(&tdns.Globals.App, "HsyncDataEngine", func() {
		dataEngine.Run(ctx, conf.InternalMp.MsgQs)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "InfraBeatLoop", func() {
		conf.InternalMp.AgentRegistry.StartInfraBeatLoop(ctx)
	})
	tdns.StartEngineNoError(&tdns.Globals.App, "SynchedDataEngine", func() {
		conf.SynchedDataEngine(ctx, conf.InternalMp.MsgQs)
	})

	syncrtr, err := conf.SetupAgentSyncRouter(ctx)
	if err != nil {
		return fmt.Errorf("error setting up agent-to-agent sync router: %v", err)
	}
	tdns.StartEngine(&tdns.Globals.App, "APIdispatcherNG", func() error {
		lgAgent.Info("starting agent-to-agent sync engine",
			"app", tdns.Globals.App.Name, "mode", tdns.AppTypeToString[tdns.Globals.App.Type])
		return tdns.APIdispatcherNG(conf.Config, syncrtr,
			mp.Api.Addresses.Listen,
			mp.Api.CertFile,
			mp.Api.KeyFile,
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
	tdns.StartEngine(&tdns.Globals.App, "UpdateHandler", func() error {
		return tdns.UpdateHandler(ctx, conf.Config)
	})
	tdns.StartEngine(&tdns.Globals.App, "DelegationSyncher", func() error {
		return hdb.DelegationSyncher(ctx, conf.Config.Internal.DelegationSyncQ, conf.Config.Internal.NotifyQ, conf)
	})
	// tdns's DS engine. The syncher asks it for the CDS before every
	// NOTIFY(CDS), and with no engine to answer, the leader sent none: a
	// parent that offers only the NOTIFY scheme never got the zone's DS
	// (tdns-mp #150). For a multi-provider zone, which the agent does not
	// sign, the engine publishes nothing: its answer is the CDS that the
	// agent's copy of the zone carries, the one the signers serve (key
	// lifecycle ownership design §4.1, Amendment 3). The zone it does write
	// a CDS for is the agent's own identity zone (startIdentityParentSync).
	tdns.StartEngine(&tdns.Globals.App, "DSEngine", func() error {
		return hdb.DSEngine(ctx)
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
	if err := conf.SetupAgent(ctx, conf.Config.Internal.AllZones); err != nil {
		return fmt.Errorf("SetupAgent: %w", err)
	}

	return nil
}

// keySetupApplies: the leader's key setup is for a zone whose parentsync
// option is on and in which this agent votes. A group's election makes its
// winner the leader of every zone of the group; since step 8 the winner
// votes in each of them, and the test guards against a leader record that
// names this agent for a zone it does not vote in. For such a zone it looks
// up no parent and asks no peer for the key.
func keySetupApplies(zd *MPZoneData, self AgentId) (bool, string) {
	if !zd.Options[tdns.OptParentSync] {
		return false, "zone does not have OptParentSync, skipping"
	}
	if !votesInZone(ZoneName(zd.ZoneName), self) {
		return false, "this agent does not vote in the zone; no key setup for it"
	}
	return true, ""
}

// setUpLeaderElection makes the leader election manager for coordinated
// parent delegation sync (DDNS), wires it, sets its callbacks, and attaches
// the zones' first-load callbacks. StartMPAgent runs it before RefreshEngine
// starts.
func (conf *Config) setUpLeaderElection(ctx context.Context, mp *MultiProviderConf) *LeaderElectionManager {
	ar := conf.InternalMp.AgentRegistry
	lem := NewLeaderElectionManager(
		AgentId(mp.Identity), leaderElectionTTL(),
		func(zone ZoneName, rfiType string, records map[string][]string) error {
			return ar.broadcastElectToZone(zone, rfiType, records)
		},
	)
	conf.InternalMp.LeaderElectionManager = lem
	ar.LeaderElectionManager = lem

	// The counts an election takes (the membership design, 4.2): the zone's
	// voting members other than this agent, and the OPERATIONAL ones among
	// them. Elections require all of them. An auditor and a record with no
	// role are not counted.
	lem.SetOperationalPeersFunc(func(zone ZoneName) int {
		return ar.operationalVotingPeers(zone, AgentId(mp.Identity))
	})
	lem.SetConfiguredPeersFunc(func(zone ZoneName) int {
		return configuredVotingPeers(zone, AgentId(mp.Identity))
	})

	// Wire provider group manager into leader election manager
	if ar.ProviderGroupManager != nil {
		lem.SetProviderGroupManager(ar.ProviderGroupManager)
	}
	// A group's election leaves out a leaving voting member that is excused
	// and not heard, as its gate does (design 3.2, plan S7).
	lem.SetGateExcused(conf.gateExcused)

	// Attach OnFirstLoad callbacks to zone stubs.
	delegationSyncQ := conf.Config.Internal.DelegationSyncQ
	for _, zoneName := range conf.Config.Internal.AllZones {
		mpzd, exists := Zones.Get(zoneName)
		if !exists {
			continue
		}
		// Detect parentsync=agent from HSYNCPARAM and enable delegation sync.
		if mpzd.Options[tdns.OptMultiProvider] {
			mpzd.OnFirstLoad = append(mpzd.OnFirstLoad, func(zd *tdns.ZoneData) {
				if zd.Options[tdns.OptParentSync] {
					return // set from HSYNCPARAM by the first load's post-refresh callback, which runs before this (followParentSyncParam)
				}
				mp := conf.MpConfig()
				if mp == nil {
					return
				}
				w, ok := Zones.Get(zd.ZoneName)
				if !ok {
					return
				}
				ourIds := ourHsyncIdentities(mp)
				matched, _, _ := w.matchHsyncIdentity(ourIds)
				if !matched {
					return
				}
				if in := w.instructions(); in == nil || !in.HasParam {
					return
				}
				if w.roles().ParentSync == core.HsyncParentSyncAgent {
					lgAgent.Info("HSYNCPARAM parentsync=agent, enabling delegation sync", "zone", zd.ZoneName)
					zd.SetRuntimeOption(tdns.OptParentSync, true)
					if err := zd.SetupZoneSync(delegationSyncQ); err != nil {
						lgAgent.Error("SetupZoneSync failed in MP OnFirstLoad", "zone", zd.ZoneName, "err", err)
					}
				}
			})
		}
		// Peers and provider groups need no first-load callback: tdns runs a
		// first load's post-refresh callbacks once the zone is Ready, so
		// PostRefresh applies the HSYNC diff to a readable zone, which
		// registers the peers and recomputes the groups, before OnFirstLoad
		// runs. The election callback below therefore finds the zone's group.
		// Leader election callback (must run after parentsync detection above).
		if mpzd.Options[tdns.OptParentSync] || mpzd.Options[tdns.OptMultiProvider] {
			mpzd.OnFirstLoad = append(mpzd.OnFirstLoad, lem.electAtFirstLoad)
		}
	}

	leaderKeySetup := func(zone ZoneName, elected bool) error {
		return conf.leaderKeySetup(ctx, zone, elected)
	}
	// The new leader also brings the parent in line with the zone (T5.8): a
	// change the previous leader did not get to send is sent now, and with
	// nothing to send the explicit sync sends nothing, so a hand-over
	// neither loses an update nor repeats one. Asked whatever the key
	// setup said: the sync has other schemes than the one that key is for.
	lem.SetOnLeaderElected(func(zone ZoneName) error {
		err := leaderKeySetup(zone, true)
		conf.requestDelegationSync(ctx, string(zone), "this agent was elected the zone's delegation sync leader")
		if errors.Is(err, errLeadMoved) || errors.Is(err, errHeldDuringTransition) {
			return nil // the lead moved on during the setup, or the zone is frozen: nothing failed
		}
		return err
	})
	// A zone that left its group and that this agent does not lead now:
	// what it scheduled for the zone's parent ends, a sync under way
	// included (step 8).
	lem.SetOnZoneLeft(func(zone ZoneName) bool {
		return conf.delegationSyncZoneLeft(string(zone))
	})
	// A lead this agent lost to another agent ends what it began for the
	// parent in that lead: the new leader's sync is the one that counts. A
	// zone that enters a provider group takes that work along to the new
	// group's lead, or ends it where another agent leads that group.
	lem.SetOnLeadLost(conf.stopRunsOfLostLead)
	lem.SetOnZoneRegrouped(conf.retieRuns)
	lem.SetOnLeaderNamed(conf.retieAllRuns)
	// A zone that joins a group this agent already leads is asked for the
	// same sync: nobody else asks for it (tdns-mp #179). Its key is left as
	// it is: the key this agent holds is published, and one it does not
	// hold is asked for by the key rounds, which make a new one only for a
	// zone that publishes none (step 7b). The sync is asked for whatever the
	// set-up said: while the zone's key is not held, or still bootstrapped,
	// it waits for it (holdForZoneKey), and goes out when the hold ends.
	lem.SetOnZoneJoined(func(zone ZoneName) error {
		// The arrival is reported after the recompute, and this runs on its
		// own: a refresh can have moved the zone on by now. An agent that no
		// longer leads it asks for nothing.
		if !lem.IsLeader(zone) {
			lgAgent.Info("a zone that joined a group this agent leads has moved on; nothing is set up for it", "zone", zone)
			return nil
		}
		err := leaderKeySetup(zone, false)
		if errors.Is(err, errLeadMoved) {
			return nil // a sync asked for now would go out from nobody
		}
		if err != nil && !errors.Is(err, errZoneKeyNotHeld) && !errors.Is(err, errHeldDuringTransition) {
			lgAgent.Warn("the key setup of a zone that joined a group this agent leads failed; the sync waits for the key", "zone", zone, "err", err)
		}
		conf.requestDelegationSync(ctx, string(zone), "the zone joined a provider group this agent leads")
		return nil
	})
	return lem
}
