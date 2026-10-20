/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"fmt"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
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

	if tdns.Globals.ImrEngine == nil {
		lgAgent.Debug("onLeaderElected: IMR not available, skipping DSYNC bootstrap", "zone", zone)
		return nil
	}
	imr := &Imr{tdns.Globals.ImrEngine}
	_, err := imr.LookupDSYNCTarget(context.Background(), string(zone), dns.TypeANY, core.SchemeUpdate)
	if err != nil {
		lgAgent.Info("onLeaderElected: parent does not advertise DSYNC UPDATE scheme, skipping SIG(0) key setup",
			"zone", zone, "err", err)
		return nil
	}

	keyName := string(zone)
	// unanswered: see step b. Declared here because a goto may not jump
	// over a declaration.
	unanswered := 0
	// A key this setup makes in step c, which the lead may not outlast.
	var made bool
	var madeKeyid uint16
	// Step a: check local keystore
	sak, err := hdb.GetSig0Keys(keyName, tdns.Sig0StateActive)
	// a clean read that found none: only then can a key made below be
	// told for the one this setup made
	readEmpty := err == nil && sak != nil && len(sak.Keys) == 0
	if err == nil && len(sak.Keys) > 0 {
		lgAgent.Info("leader has local SIG(0) key, proceeding to publish",
			"zone", zone, "keyid", sak.Keys[0].KeyId)
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
		}
		return errLeadMoved
	}
	// Step d: get the active key and publish to combiner + remote agents
	sak, err = hdb.GetSig0Keys(keyName, tdns.Sig0StateActive)
	if err != nil || len(sak.Keys) == 0 {
		return fmt.Errorf("onLeaderElected: no active SIG(0) key after generation for zone %s", zone)
	}
	keyRR := &sak.Keys[0].KeyRR
	lgAgent.Info("publishing KEY to combiner with PublishInstruction", "zone", zone, "keyid", sak.Keys[0].KeyId)

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

	// Step e: trigger KeyState inquiry + bootstrap with parent (async)
	if zd.Options[tdns.OptParentSync] {
		keyid := uint16(sak.Keys[0].KeyRR.KeyTag())
		algorithm := sak.Keys[0].KeyRR.Algorithm
		go conf.ParentSyncAfterKeyPublication(ctx, zone, keyName, keyid, algorithm)
	}

	return nil
}
