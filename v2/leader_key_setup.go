/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"fmt"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

// leaderKeySetup runs when the local agent wins a zone's leader election:
// ensure we have a SIG(0) key,
// then publish KEY to combiner and sync to remote agents.
//
// elected is false when the zone was not won in an election but joined a
// group this agent already leads. Such a zone has had a leader, and may
// have a key that leader made. The setup then does everything but make a
// new key in place of one the zone publishes (mayGenerateZoneKey).
//
// It is a method so that tests reach it; StartMPAgent wires it into the
// election's and the arrival's callbacks.
func (conf *Config) leaderKeySetup(ctx context.Context, zone ZoneName, elected bool) error {
	hdb := NewHsyncDB(conf.Config.Internal.KeyDB)
	tm := conf.InternalMp.MPTransport
	msgQs := conf.InternalMp.MsgQs
	ar := conf.InternalMp.AgentRegistry
	lem := conf.InternalMp.LeaderElectionManager
	zd, ok := Zones.Get(string(zone))
	if !ok || zd == nil {
		return fmt.Errorf("onLeaderElected: zone %s not found", zone)
	}
	if applies, why := keySetupApplies(zd, lem.localID); !applies {
		lgAgent.Info("onLeaderElected: "+why, "zone", zone)
		return nil
	}
	if elected {
		lgAgent.Info("onLeaderElected: processing", "zone", zone)
	} else {
		lgAgent.Info("zone joined a group this agent leads: processing", "zone", zone)
	}

	if !conf.zoneUsesKey(ctx, zone) {
		lgAgent.Info("onLeaderElected: the zone uses no SIG(0) key (no parent that takes UPDATE, or no resolver), skipping SIG(0) key setup", "zone", zone)
		return nil
	}

	keyName := string(zone)
	// unanswered: see step b. Declared here because a goto may not jump
	// over a declaration.
	unanswered := 0
	// A key this setup makes in step c, which the lead may not outlast.
	var made bool
	var madeKeyid uint16
	// The leader's sync of the zone waits from here until the poll this
	// set-up starts has ended (step 7b, keyPolls): counted before a key is
	// made or taken. A key made or taken whose publication fails keeps the
	// zone held (unpublished) until a later set-up publishes it.
	tk := conf.InternalMp.keyPolls.begin(zone)
	unpublished := false
	defer func() { tk.end(unpublished) }()
	// Step a: the zone's key, if this agent holds it (readZoneKey): an
	// active local key the zone does not publish is not used.
	zk, err := readZoneKey(hdb.KeyDB, zone)
	if err != nil {
		return fmt.Errorf("onLeaderElected: reading the SIG(0) keys of %s: %v", zone, err)
	}
	// a clean read that found no active key: only then can a key made
	// below be told for the one this setup made
	readEmpty := len(zk.active) == 0
	if zk.held != nil {
		// A renewal of a lead whose poll of this key has ended in this
		// process, with the key published, changes nothing: no publication
		// again and no poll, whatever the poll's outcome. A new lead, a new
		// or taken key, and a restart publish and poll as before.
		_, _, ended := conf.InternalMp.keyPolls.state(zone)
		if renewalKeepsKey(zk, ended, lem.LeadStart(zone)) {
			lgAgent.Info("a renewal of the lead keeps the zone's SIG(0) key as it is: published, and bootstrapped in this lead",
				"zone", zone, "keyid", zk.held.keyid)
			return nil
		}
		lgAgent.Info("leader has local SIG(0) key, proceeding to publish",
			"zone", zone, "keyid", zk.held.keyid)
		goto publish
	}
	// Step b: ask peers via RFI CONFIG subtype=sig0key.
	//
	// The peers asked are the voting members other than this agent
	// (sig0KeyPeers): the agents that may hold the key, and the ones whose
	// word on it counts. And the agents the zone lists with no role
	// (roleLessKeyHolders, zoneKeyPeers): the owner's edit may have taken
	// the role of the provider that led the zone and set its key up.
	// unanswered counts those that have not said "no
	// key": one that is not operational, one that did not answer, one that
	// refused to hand the key over (it may hold it), one whose key could
	// not be imported. A silent peer is a peer to ask again, not a peer
	// without the key.
	{
		zad, err := ar.GetZoneAgentData(zone)
		if err != nil {
			unanswered++ // the zone's members are not known: nobody has said "no key"
		} else {
			previous := ar.roleLessKeyHolders(zone)
			for _, agent := range zoneKeyPeers(zone, zad.Agents, AgentId(ar.LocalAgent.Identity), previous) {
				if !ar.isAgentOperational(agent.ID) {
					unanswered++
					continue
				}
				lgAgent.Info("asking peer for SIG(0) key", "zone", zone, "peer", agent.ID)
				configResp := RequestAndWaitForConfig(ar, agent, string(zone), "sig0key", msgQs)
				if configResp == nil {
					lgAgent.Info("peer did not respond to CONFIG sig0key", "zone", zone, "peer", agent.ID)
					unanswered++
					continue
				}
				if why := configResp.Refused(); why != "" {
					lgAgent.Warn("peer refused to hand over the zone's SIG(0) key", "zone", zone, "peer", agent.ID, "reason", why)
					unanswered++ // a refusal is not "no key": the peer may hold it
					continue
				}
				if len(configResp.ConfigData) > 0 && configResp.ConfigData["status"] != "no sig0 key for zone" {
					if err := importSig0KeyFromPeer(hdb, keyName, configResp.ConfigData); err != nil {
						lgAgent.Error("failed to import SIG(0) key from peer",
							"zone", zone, "peer", agent.ID, "err", err)
						unanswered++ // it has a key: that is not "no key"
						continue
					}
					lgAgent.Info("imported SIG(0) key from peer", "zone", zone, "peer", agent.ID)
					unpublished = true // a key taken counts as unpublished until it is
					goto publish
				}
				lgAgent.Info("peer does not have SIG(0) key", "zone", zone, "peer", agent.ID)
			}
		}
	}
	// Step c: no peer has the key — generate a new keypair. Not for a
	// zone that arrived with a key of its own: the parent holds that
	// key, and a new one in its place is refused there and replaces the
	// zone's KEY RRset here. And not while a voting member has not
	// answered: this agent's own copy of the zone may be behind (a
	// provider that has just joined holds nothing of the zone yet), so
	// that it shows no KEY says little.
	if !mayGenerateZoneKey(elected, zd, unanswered) {
		if zonePublishesKey(zd) {
			lgAgent.Warn("the zone publishes a SIG(0) key that this agent does not hold, and no peer handed it over; no new key is made for a zone that joined a group, a sync that needs the key waits",
				"zone", zone)
		} else {
			lgAgent.Warn("not every voting member has said whether it holds the zone's SIG(0) key; no new key is made for a zone that joined a group until each has, a sync that needs the key waits",
				"zone", zone, "unanswered", unanswered)
		}
		return errZoneKeyNotHeld
	}
	// Asking the peers takes a while, and the lead may move meanwhile. A
	// key made by an agent that no longer leads is a KEY in the zone
	// that nobody bootstraps.
	if !lem.IsLeader(zone) {
		lgAgent.Info("onLeaderElected: this agent no longer leads the zone; no SIG(0) key is made", "zone", zone)
		return errLeadMoved
	}
	lgAgent.Info("no peer has SIG(0) key, will generate new keypair", "zone", zone)
	{
		alg := parentSyncKeygenAlgorithm()
		kp := tdns.KeystorePost{
			Command:    "sig0-mgmt",
			SubCommand: "generate",
			Zone:       zd.ZoneName,
			Keyname:    keyName,
			Algorithm:  alg,
			State:      tdns.Sig0StateActive,
			Creator:    "leader-election",
		}
		before, berr := activeSig0KeyIDs(hdb, keyName)
		resp, err := hdb.Sig0KeyMgmt(nil, kp)
		if err != nil {
			return fmt.Errorf("onLeaderElected: failed to generate SIG(0) keypair: %v", err)
		}
		lgAgent.Info("generated SIG(0) keypair", "zone", zone, "msg", resp.Msg)
		unpublished = true
		// The key made is the one new active key, and only when there was
		// none before. A key another writer added meanwhile, or one a
		// failed read hid, is never taken for it: what this names is what
		// dropKeyMadeForALostLead deletes.
		after, aerr := activeSig0KeyIDs(hdb, keyName)
		if readEmpty && berr == nil && aerr == nil && len(before) == 0 && len(after) == 1 {
			for id := range after {
				made, madeKeyid = true, id
			}
		} else {
			lgAgent.Info("onLeaderElected: the SIG(0) key just made cannot be told from another active key; it is kept whatever becomes of the lead", "zone", zone)
		}
	}
publish:
	if !lem.IsLeader(zone) {
		lgAgent.Info("onLeaderElected: this agent no longer leads the zone; its KEY is not published", "zone", zone)
		if made {
			dropKeyMadeForALostLead(hdb, zd.ZoneName, keyName, madeKeyid)
			unpublished = false // the key is gone
		}
		return errLeadMoved
	}
	// Step d: the zone's key, the only active one, published to the combiner
	// and the remote agents. The others are retired first: tdns signs with
	// the first active row and bootstraps it (step 7b, one active key).
	zk, err = readZoneKey(hdb.KeyDB, zone)
	if err != nil || zk.held == nil || zk.held.key == nil {
		return fmt.Errorf("onLeaderElected: the zone's SIG(0) key is not held after the setup for zone %s (%v)", zone, err)
	}
	if only, err := retireOtherActiveKeys(hdb.KeyDB, zone, zk); err != nil || !only {
		lgAgent.Warn("an active SIG(0) key that is not the zone's key could not be retired; the sync with the parent waits", "zone", zone, "keyid", zk.held.keyid, "err", err)
	}
	held := *zk.held
	keyRR := held.key
	lgAgent.Info("publishing KEY to combiner with PublishInstruction", "zone", zone, "keyid", held.keyid)

	zu := &ZoneUpdate{
		Zone: zone,
		Operations: []core.RROperation{{
			Operation: "replace",
			RRtype:    "KEY",
			Records:   []string{keyRR.String()},
		}},
		Publish: &core.PublishInstruction{
			KEYRRs:    []string{keyRR.String()},
			Locations: publishLocations(zone),
		},
	}
	distID, err := tm.EnqueueForCombiner(zone, zu, "")
	if err != nil {
		lgAgent.Error("failed to publish KEY to combiner", "zone", zone, "err", err)
		return err
	}
	lgAgent.Info("KEY + PublishInstruction sent to combiner", "zone", zone, "distID", distID)
	unpublished = false
	conf.InternalMp.keyPolls.published(zone)

	agentUpdate := &ZoneUpdate{
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

	// Step e: trigger KeyState inquiry + bootstrap with parent (async), for
	// the zone's key: the poll takes this set-up's count (keyPolls)
	if zd.Options[tdns.OptParentSync] {
		conf.launchKeyPoll(ctx, tk, zone, keyName, held.keyid, keyRR.Algorithm)
	}

	return nil
}
