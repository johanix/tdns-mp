/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"errors"
	"fmt"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

// leaderKeySetup runs when the local agent wins a zone's leader election,
// renews its lease, or leads a zone that joins its group: the zone's SIG(0)
// key, when this agent holds it, is published to the combiner and the remote
// agents, and its poll with the parent started.
//
// It neither asks the peers nor makes a key (step 7b). When this agent does
// not hold the zone's key it notes the zone for the key rounds (keyWanted)
// and answers errZoneKeyNotHeld: the round asks every voting member and every
// agent the zone lists with no role, and its decision imports and publishes a
// key handed over, or makes one when every voting member has said it holds
// none and the zone publishes no KEY (decideZoneKey). A sync asked for
// meanwhile waits for the key (holdForZoneKey). elected no longer lets a
// leader make a key.
//
// It is a method so that tests reach it; StartMPAgent wires it into the
// election's and the arrival's callbacks.
func (conf *Config) leaderKeySetup(ctx context.Context, zone ZoneName, elected bool) error {
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

	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return fmt.Errorf("onLeaderElected: no keystore for zone %s", zone)
	}
	// The zone's key, if this agent holds it (readZoneKey): an active local
	// key the zone does not publish is not used.
	zk, err := readZoneKey(kdb, zone)
	if err != nil {
		return fmt.Errorf("onLeaderElected: reading the SIG(0) keys of %s: %v", zone, err)
	}
	if zk.held == nil {
		if zk.several() {
			conf.logSeveralKeys(zone, zk)
		} else {
			lgAgent.Info("the leader does not hold the zone's SIG(0) key; it is asked for, and a sync waits for it", "zone", zone,
				"published", keyTags(zk.published))
		}
		conf.InternalMp.CatchUp.keyCheck(zone)
		return errZoneKeyNotHeld
	}
	// A renewal of a lead whose poll of this key has ended in this process,
	// with the key published, changes nothing: no publication again and no
	// poll, whatever the poll's outcome. A new lead, a new or taken key, and
	// a restart publish and poll as before.
	_, _, ended := conf.InternalMp.keyPolls.state(zone)
	if renewalKeepsKey(zk, ended, lem.LeadStart(zone)) {
		lgAgent.Info("a renewal of the lead keeps the zone's SIG(0) key as it is: published, and bootstrapped in this lead",
			"zone", zone, "keyid", zk.held.keyid)
		return nil
	}
	lgAgent.Info("leader has local SIG(0) key, proceeding to publish", "zone", zone, "keyid", zk.held.keyid)
	// The leader's sync of the zone waits from here until the poll this
	// set-up starts has ended (keyPolls). Counted after the renewal's test:
	// a plain renewal holds no sync. A publication that failed keeps the
	// zone held (unpublished) until a later set-up publishes the key.
	tk := conf.InternalMp.keyPolls.begin(zone)
	err = conf.publishZoneKey(ctx, zone, tk, false, 0)
	tk.end(err != nil && !errors.Is(err, errLeadMoved))
	return err
}

// makeZoneKey makes the zone's first SIG(0) key. made and madeKeyid name the
// key made only when it can be told from every other active key: there was
// none before (readEmpty, and read so again), and there is one after. A key
// another writer added meanwhile is never taken for it: what this names is
// what dropKeyMadeForALostLead deletes.
func (conf *Config) makeZoneKey(hdb *HsyncDB, zone ZoneName, readEmpty bool) (made bool, madeKeyid uint16, err error) {
	keyName := string(zone)
	lgAgent.Info("no agent asked holds the zone's SIG(0) key, and the zone publishes none: making one", "zone", zone)
	before, berr := activeSig0KeyIDs(hdb, keyName)
	resp, err := sig0KeyMgmtRetried(hdb.KeyDB, tdns.KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "generate",
		Zone:       keyName,
		Keyname:    keyName,
		Algorithm:  parentSyncKeygenAlgorithm(),
		State:      tdns.Sig0StateActive,
		Creator:    "leader-election",
	})
	if err == nil && resp != nil && resp.Error {
		err = fmt.Errorf("%s", resp.ErrorMsg)
	}
	if err != nil {
		return false, 0, fmt.Errorf("failed to generate SIG(0) keypair: %v", err)
	}
	lgAgent.Info("generated SIG(0) keypair", "zone", zone, "msg", resp.Msg)
	after, aerr := activeSig0KeyIDs(hdb, keyName)
	if readEmpty && berr == nil && aerr == nil && len(before) == 0 && len(after) == 1 {
		for id := range after {
			return true, id, nil
		}
	}
	lgAgent.Info("onLeaderElected: the SIG(0) key just made cannot be told from another active key; it is kept whatever becomes of the lead", "zone", zone)
	return false, 0, nil
}

// publishZoneKey publishes the zone's key, the only active one, to the
// combiner and the remote agents, and starts its poll with the parent, which
// takes tk. The others are retired first: tdns signs with the first active
// row and bootstraps it. When this agent no longer leads the zone nothing is
// published, a key made for the lead (made) is deleted, and the answer is
// errLeadMoved.
func (conf *Config) publishZoneKey(ctx context.Context, zone ZoneName, tk *keyPollToken, made bool, madeKeyid uint16) error {
	lem := conf.InternalMp.LeaderElectionManager
	tm := conf.InternalMp.MPTransport
	kdb := conf.zoneKeyDB(zone)
	hdb := NewHsyncDB(kdb)
	zd, ok := Zones.Get(string(zone))
	if !ok || zd == nil {
		return fmt.Errorf("onLeaderElected: zone %s not found", zone)
	}
	if lem == nil || !lem.IsLeader(zone) {
		lgAgent.Info("onLeaderElected: this agent no longer leads the zone; its KEY is not published", "zone", zone)
		if made {
			dropKeyMadeForALostLead(hdb, zd.ZoneName, string(zone), madeKeyid)
		}
		return errLeadMoved
	}
	zk, err := readZoneKey(kdb, zone)
	if err != nil || zk.held == nil || zk.held.key == nil {
		return fmt.Errorf("onLeaderElected: the zone's SIG(0) key is not held after the setup for zone %s (%v)", zone, err)
	}
	// tdns's bootstrap uploads the first active key: while another one is
	// active, the key is neither published nor polled
	if only, err := retireOthers(kdb, zone, zk); err != nil || !only {
		lgAgent.Warn("an active SIG(0) key that is not the zone's key could not be retired; the key is not published, and the sync with the parent waits", "zone", zone, "keyid", zk.held.keyid, "err", err)
		return errOtherKeysActive
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

	// The KeyState inquiry and bootstrap with the parent (async), for the
	// zone's key: the poll takes the set-up's count (keyPolls).
	if zd.Options[tdns.OptParentSync] {
		conf.launchKeyPoll(ctx, tk, zone, string(zone), held.keyid, keyRR.Algorithm)
	}
	return nil
}

// errOtherKeysActive: the zone's key is not its only active key, and could
// not be made so; nothing is published or polled.
var errOtherKeysActive = errors.New("another active SIG(0) key of the zone could not be retired")

// retireOthers is retireOtherActiveKeys; a test stands in for it.
var retireOthers = retireOtherActiveKeys
