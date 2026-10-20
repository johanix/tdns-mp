/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// DelegationSyncher is the MP-enhanced version of the delegation sync
// loop. It adds leader election gating (only the elected leader sends
// DDNS to the parent) and peer notification after successful syncs.
// The base DelegationSyncher in tdns handles the non-MP case (no
// leader election, no peer notification).
func (hdb *HsyncDB) DelegationSyncher(ctx context.Context, delsyncq chan tdns.DelegationSyncRequest, notifyq chan tdns.NotifyRequest, conf *Config) error {

	lg.Info("DelegationSyncher: starting")
	imr := func() *Imr {
		return &Imr{conf.Config.Internal.ImrEngine}
	}
	var err error
	for {
		select {
		case <-ctx.Done():
			lg.Info("DelegationSyncher: terminating due to context cancelled")
			return nil
		case ds, ok := <-delsyncq:
			if !ok {
				lg.Info("DelegationSyncher: delsyncq closed, terminating")
				return nil
			}
			zd := ds.ZoneData
			dss := ds.SyncStatus

			switch ds.Command {

			case "DELEGATION-SYNC-SETUP":
				// a multi-provider zone's SIG(0) key is the leader's key
				// set-up's alone (step 7b): tdns's setup would make a key
				// when none is held, or publish another beside the zone's
				if !setupArmRuns(zd) {
					lg.Info("DelegationSyncher: a multi-provider zone's SIG(0) key is the leader's key set-up's, skipping the setup", "zone", ds.ZoneName)
					continue
				}
				err = zd.DelegationSyncSetup(ctx, hdb.KeyDB)
				if err != nil {
					lg.Error("DelegationSyncher: error from DelegationSyncSetup, ignoring sync request", "zone", ds.ZoneName, "err", err)
					continue
				}

			case "INITIAL-KEY-UPLOAD":
				lg.Info("DelegationSyncher: request for initial key upload", "zone", zd.ZoneName)
				lg.Info("DelegationSyncher: initial key upload complete", "zone", ds.ZoneName)
				continue

			case "DELEGATION-STATUS":
				lg.Info("DelegationSyncher: request for delegation status", "zone", zd.ZoneName)

				syncstate, err := zd.AnalyseZoneDelegation(imr().Imr)
				if err != nil {
					lg.Error("DelegationSyncher: error from AnalyseZoneDelegation, ignoring sync request", "zone", ds.ZoneName, "err", err)
					syncstate.Error = true
					syncstate.ErrorMsg = err.Error()
				}
				if ds.Response != nil {
					ds.Response <- syncstate
				}
				continue

			case "SYNC-DELEGATION":
				lg.Info("DelegationSyncher: request for delegation sync",
					"zone", ds.ZoneName,
					"ns_removes", len(dss.NsRemoves), "ns_adds", len(dss.NsAdds),
					"a_removes", len(dss.ARemoves), "a_adds", len(dss.AAdds),
					"aaaa_removes", len(dss.AAAARemoves), "aaaa_adds", len(dss.AAAAAdds))

				// No agent the zone no longer has sends to its parent: the owner
				// removed it in the refresh that queued this (stillParticipates).
				// Asked first: such an agent may have the option off too, and the
				// owner's reason would then be the wrong one.
				if ds.ZoneData != nil && ds.ZoneData.Options[tdns.OptMultiProvider] && !conf.stillParticipates(ds.ZoneName) {
					lg.Info("DelegationSyncher: this agent no longer participates in the zone, skipping DDNS", "zone", ds.ZoneName)
					conf.delegationSyncNotLeading(ds.ZoneName, false)
					continue
				}
				// No agent sends to the parent of a zone whose owner syncs its
				// delegation; the request was queued before the owner took
				// the sync over
				if ownerSyncsDelegation(ds.ZoneData) {
					lg.Info("DelegationSyncher: the zone's owner syncs its delegation, skipping DDNS", "zone", ds.ZoneName)
					conf.delegationSyncOwnerSyncs(ds.ZoneName)
					continue
				}

				// Only the elected leader of a multi-provider zone sends to the
				// parent; a zone this daemon is primary for alone (its
				// identity zone) has no election to wait for.
				if lem := conf.InternalMp.LeaderElectionManager; lem != nil && ds.ZoneData != nil && ds.ZoneData.Options[tdns.OptMultiProvider] {
					if !lem.IsLeader(ZoneName(ds.ZoneName)) {
						lg.Info("DelegationSyncher: not the delegation sync leader, skipping DDNS", "zone", ds.ZoneName)
						// a chain left from a term this agent led is over
						conf.delegationSyncNotLeading(ds.ZoneName, false)
						continue
					}
				}
				// Nothing goes to the parent of a zone that is not caught up:
				// the sync is owed, and the answer that completes the
				// catch-up asks for it (design 5.6)
				if held, _ := conf.holdLeaderSync(ds); held {
					continue
				}
				// Nor while the zone's SIG(0) key is not held, not the one
				// tdns signs with, or being bootstrapped (step 7b): owed, and
				// asked for when the key's hold ends
				if held, _ := conf.holdForZoneKey(ctx, ds); held {
					continue
				}

				zd := ds.ZoneData
				if p := zd.GetParent(); p == "" || p == "." {
					parent, perr := imr().Imr.ParentZone(zd.ZoneName)
					if perr != nil {
						lg.Error("DelegationSyncher: error from ParentZone, ignoring sync request", "zone", ds.ZoneName, "err", perr)
						continue
					}
					zd.SetParent(parent)
				}

				msg, rcode, ur, pending, err := hdb.syncDelegation(ctx, conf, notifyq, ds, ds.SyncStatus, imr().Imr)
				if err != nil {
					lg.Error("DelegationSyncher: error from SyncZoneDelegation, ignoring sync request", "zone", ds.ZoneName, "err", err)
					continue
				}
				ds.SyncStatus.UpdateResult = ur
				lg.Info("DelegationSyncher: SyncZoneDelegation completed", "zone", ds.ZoneName, "msg", msg, "rcode", dns.RcodeToString[int(rcode)])
				if pending {
					// A sync sent as a NOTIFY is not done, and the peers
					// are told nothing, until the parent is seen in sync
					continue
				}
				// Notify peer agents that parent sync is done
				go notifyPeersParentSyncDone(conf, ds.ZoneName, dns.RcodeToString[int(rcode)], msg)

			case "EXPLICIT-SYNC-DELEGATION":
				lg.Info("DelegationSyncher: request for explicit delegation sync", "zone", ds.ZoneName)

				// The reasons to send nothing come before the parent is
				// asked, the hold among them: a leader's sync of a zone that
				// is not caught up is owed, whether the parent answers or
				// not (design 5.6). Their answer to the operator is the
				// reason; the analysis is not made.
				skipped := tdns.DelegationSyncStatus{ZoneName: ds.ZoneName, Time: time.Now()}
				skip := func(msg string) {
					skipped.Msg = msg
					if ds.Response != nil {
						ds.Response <- skipped
					}
				}
				// An agent the zone no longer has first, as above
				if ds.ZoneData != nil && ds.ZoneData.Options[tdns.OptMultiProvider] && !conf.stillParticipates(ds.ZoneName) {
					lg.Info("DelegationSyncher: this agent no longer participates in the zone, skipping DDNS", "zone", ds.ZoneName)
					conf.delegationSyncNotLeading(ds.ZoneName, false)
					skip("this agent no longer participates in the zone, skipping DDNS")
					continue
				}
				// No agent sends to the parent of a zone whose owner syncs its
				// delegation; the request was queued before the owner took
				// the sync over
				if ownerSyncsDelegation(ds.ZoneData) {
					lg.Info("DelegationSyncher: the zone's owner syncs its delegation, skipping DDNS", "zone", ds.ZoneName)
					conf.delegationSyncOwnerSyncs(ds.ZoneName)
					skip("the zone's owner syncs its delegation, skipping DDNS")
					continue
				}
				// Only the elected leader of a multi-provider zone sends to the
				// parent; a zone this daemon is primary for alone (its
				// identity zone) has no election to wait for.
				if lem := conf.InternalMp.LeaderElectionManager; lem != nil && ds.ZoneData != nil && ds.ZoneData.Options[tdns.OptMultiProvider] {
					if !lem.IsLeader(ZoneName(ds.ZoneName)) {
						lg.Info("DelegationSyncher: not the delegation sync leader, skipping DDNS", "zone", ds.ZoneName)
						// a chain left from a term this agent led is over
						conf.delegationSyncNotLeading(ds.ZoneName, false)
						skip("not the delegation sync leader, skipping DDNS")
						continue
					}
				}
				// Held while the zone is not caught up: the operator is told
				// so, with no error
				if held, waiting := conf.holdLeaderSync(ds); held {
					skip(fmt.Sprintf("the sync with the parent is held until the zone is caught up; waiting for %s", waiting))
					continue
				}
				// Held for the zone's SIG(0) key (step 7b): answered at once,
				// also when it is the key poll's own sync after the parent
				// trusts the key, sent while the poll still counts as running
				if held, why := conf.holdForZoneKey(ctx, ds); held {
					skip("the sync with the parent waits for the zone's SIG(0) key (" + why + ")")
					continue
				}

				syncstate, err := zd.AnalyseZoneDelegation(imr().Imr)
				if err != nil {
					syncstate.Error = true
					syncstate.ErrorMsg = err.Error()
					if ds.Response != nil {
						ds.Response <- syncstate
					}
					// The leader's sync of a multi-provider zone that could
					// not ask the parent is owed, and asked again every 30 s
					// while it is owed and the zone is caught up, until the
					// parent answers. That is its retry: it does not count
					// as a failed sync, so an outage does not grow the
					// backoff that the first real failure after it would
					// wait (the rig's parent-unreach). One line an hour says
					// the parent does not answer, not one per try.
					//
					// A sync that was stopped because this agent no longer
					// takes part in the zone (followParentSyncParam) is not a
					// failure to ask again for.
					if mpLeaderSync(conf, ds) && conf.stillParticipates(ds.ZoneName) {
						if logIt, since := conf.InternalMp.CatchUp.oweAfterFailedAnalysis(ZoneName(ds.ZoneName), err); logIt {
							lg.Error("DelegationSyncher: the parent's delegation cannot be analysed; the sync is owed, and asked for again every 30 s while the zone is caught up",
								"zone", ds.ZoneName, "since", since.UTC().Format(time.RFC3339), "err", err)
						}
					} else {
						lg.Error("DelegationSyncher: error from AnalyseZoneDelegation, ignoring sync request", "zone", ds.ZoneName, "err", err)
					}
					continue
				}
				if was, since := conf.InternalMp.CatchUp.parentAnswered(ZoneName(ds.ZoneName)); was {
					lg.Info("DelegationSyncher: the parent's delegation can be analysed again", "zone", ds.ZoneName,
						"down_since", since.UTC().Format(time.RFC3339))
				}

				if syncstate.InSync {
					// With no DS set to compare, for a zone that names a
					// signer, NS and glue being in step is not "in sync"
					if waiting, unknown := conf.dsSetUnknown(ds); unknown {
						lg.Info("DelegationSyncher: NS and glue are in sync with the parent, the DS set is unknown",
							"zone", syncstate.ZoneName, "waiting_for", waiting)
						syncstate.Msg = fmt.Sprintf("NS and glue are in sync with the parent; the DS set is unknown, waiting for %s", waiting)
						conf.delegationSyncInSync(ds.ZoneName, false)
						if ds.Response != nil {
							ds.Response <- syncstate
						}
						continue
					}
					lg.Info("DelegationSyncher: delegation data in parent is in sync with child, no action needed",
						"zone", syncstate.ZoneName, "parent", syncstate.Parent)
					// This ends the zone's retries. It is also what a sync
					// that went out as a NOTIFY waits for: the peers are
					// told of that sync now
					conf.delegationSyncInSync(ds.ZoneName, true)
					if ds.Response != nil {
						ds.Response <- syncstate
					}
					continue
				}

				// Not in sync, let's fix that.
				msg, rcode, ur, pending, err := hdb.syncDelegation(ctx, conf, notifyq, ds, syncstate, imr().Imr)
				if err != nil {
					lg.Error("DelegationSyncher: error from SyncZoneDelegation", "zone", ds.ZoneName, "err", err)
					syncstate.Error = true
					syncstate.ErrorMsg = err.Error()
					syncstate.UpdateResult = ur
					// a refusal that passes by itself (a SIG(0) key the parent
					// has not finished verifying) must not leave the parent
					// without the DS set until the keys change again
					//
					// A sync that was stopped because this agent no longer
					// takes part in the zone (followParentSyncParam) is not a
					// failure to ask again for.
					if mpLeaderSync(conf, ds) && conf.stillParticipates(ds.ZoneName) {
						conf.delegationSyncFailed(ctx, ds.ZoneName, err)
					}
				} else {
					lg.Info("DelegationSyncher: SyncZoneDelegation completed", "zone", ds.ZoneName, "msg", msg, "rcode", dns.RcodeToString[int(rcode)])
					// A sync sent as a NOTIFY is not done, and the peers
					// are told nothing, until the parent is seen in sync
					if !pending {
						conf.delegationSyncSucceeded(ds.ZoneName)
						// Notify peer agents that parent sync is done
						go notifyPeersParentSyncDone(conf, ds.ZoneName, dns.RcodeToString[int(rcode)], msg)
					}
				}
				syncstate.Msg = msg
				syncstate.Rcode = rcode

				if ds.Response != nil {
					ds.Response <- syncstate
				}
				continue

			case "SYNC-DNSKEY-RRSET":
				lg.Info("DelegationSyncher: request for DNSKEY RRset sync", "zone", ds.ZoneName)
				if zd.Options[tdns.OptMultiProvider] {
					lg.Info("DelegationSyncher: multisigner zone, notifying controller", "zone", ds.ZoneName)
					notifyq <- tdns.NotifyRequest{
						ZoneName: zd.ZoneName,
						ZoneData: zd,
						RRtype:   dns.TypeDNSKEY,
						Targets:  zd.MultiSigner.Controller.Notify.Targets,
						Urgent:   true,
					}
				}

				// Publish CDS records from current DNSKEYs if zone has delegation
				// sync; not for an owned zone, whose CDS is its DS set's, served
				// by the signer's DS engine (S5, arrow 1)
				if syncherPublishesDNSKEYCDS(conf, zd) {
					if err := zd.PublishCdsRRs(); err != nil {
						lg.Error("DelegationSyncher: error publishing CDS", "zone", zd.ZoneName, "err", err)
					} else {
						lg.Info("DelegationSyncher: published CDS from DNSKEYs", "zone", zd.ZoneName)
					}
				}

			default:
				lg.Warn("DelegationSyncher: unknown command, ignoring", "zone", ds.ZoneName, "command", ds.Command)
			}
		}
	}
}

// syncDelegation is the one place where a delegation sync leaves this daemon
// for the parent, for the implicit and the explicit request alike. pending
// is set when nothing failed and the sync is still not done: it went out as
// a NOTIFY for a zone this agent leads, and the parent is looked at again
// before it counts (mp_s5_leader_sync.go). The caller then books nothing and
// tells the peers nothing yet.
//
// tdns hands a NOTIFY to the notifier through the queue it is given. For the
// leader's sync of a multi-provider zone the queue it is given is one of our
// own: what arrives on it says that the sync went out as a NOTIFY, and of
// which types, and the chain sends it on to the notifier, at once or after
// the zone's wait. An UPDATE passes through here untouched.
//
// Before the sync, the leader makes the zone's CSYNC if the NS set or the
// glue differs from the parent's and no CSYNC has been made for that
// difference, and sends it to the zone's providers
// (mp_s5_leader_csync.go). The sync does not wait for them. A NOTIFY does,
// in the chain. If the CSYNC could not be distributed, or a provider has
// rejected it, the NOTIFY is not sent and the sync has failed: the failure
// chain asks again, and that ask distributes anew.
func (hdb *HsyncDB) syncDelegation(ctx context.Context, conf *Config, notifyq chan tdns.NotifyRequest, ds tdns.DelegationSyncRequest,
	syncstate tdns.DelegationSyncStatus, imr *tdns.Imr) (msg string, rcode uint8, ur tdns.UpdateResult, pending bool, err error) {
	// The path is chosen on the zone's kind alone, not on the option: a
	// multi-provider zone never belongs on the plain path, and reading the
	// option here, before the run is listed, let a takeover that came in
	// between send one last sync down it.
	if conf == nil || ds.ZoneData == nil || !ds.ZoneData.Options[tdns.OptMultiProvider] {
		msg, rcode, ur, err = ds.ZoneData.SyncZoneDelegation(ctx, hdb.KeyDB, notifyq, syncstate, imr)
		return msg, rcode, ur, false, err
	}
	// The owner may take the sync over while it runs: the refresh that brings
	// the owner's word cancels runCtx (delegationSyncOwnerSyncs), which stops
	// an UPDATE that tdns is still retrying. The run is listed before the
	// option is read, so a takeover either finds it or is seen here.
	runCtx, done := conf.delegationSyncRun(ctx, ds.ZoneName)
	defer done()
	if ownerSyncsDelegation(ds.ZoneData) {
		return "", 0, tdns.UpdateResult{}, false, errors.New("the zone's owner has taken its delegation sync over; nothing is sent")
	}
	csyncErr := conf.delegationCsyncStep(runCtx, ds.ZoneName, syncstate)
	// Room for more than the two NOTIFYs a sync sends (CSYNC, CDS): the sync
	// must not wait for a reader that comes only when it has returned.
	taken := make(chan tdns.NotifyRequest, 8)
	msg, rcode, ur, err = ds.ZoneData.SyncZoneDelegation(runCtx, hdb.KeyDB, taken, syncstate, imr)
	var notifies []tdns.NotifyRequest
	for len(taken) > 0 {
		notifies = append(notifies, <-taken)
	}
	if err != nil && runCtx.Err() != nil && !conf.stillParticipates(ds.ZoneName) {
		return msg, rcode, ur, false, fmt.Errorf("this agent no longer takes part in the zone; the sync is stopped: %w", err)
	}
	if err != nil && ownerSyncsDelegation(ds.ZoneData) {
		return msg, rcode, ur, false, fmt.Errorf("the zone's owner has taken its delegation sync over; the sync is stopped: %w", err)
	}
	if err != nil || len(notifies) == 0 {
		// A sync that failed has handed nothing over: tdns's NOTIFY sender
		// asks for all it needs first and sends last. Should that change,
		// what a failed sync handed over is not sent on.
		return msg, rcode, ur, false, err
	}
	if ownerSyncsDelegation(ds.ZoneData) {
		// The zone's owner took the sync over while this sync ran: its
		// NOTIFY is not sent on, held or checked. The caller does not ask
		// again: it retries only a zone whose agents sync it (mpLeaderSync).
		return msg, rcode, ur, false, errors.New("the zone's owner has taken its delegation sync over; the NOTIFY is not sent")
	}
	delegationSyncBeforeHandoff(ds.ZoneName)
	held, failed := false, csyncErr
	if failed == nil {
		held, failed = conf.delegationSyncNotified(ctx, ds.ZoneName, delegationNotifies{requests: notifies, diff: delegationDifference(syncstate), out: notifyq, run: runCtx})
	}
	if failed != nil {
		if runCtx.Err() != nil || ownerSyncsDelegation(ds.ZoneData) {
			// The owner took the sync over after this sync last looked, or
			// the agent is stopping: nothing is asked again, and no chain is
			// made again for a zone whose owner syncs it.
			return msg, rcode, ur, false, failed
		}
		// The NOTIFY is not sent on. Asked again here, and not left to the
		// caller: the request of a refresh has no caller that asks again.
		conf.delegationSyncFailed(ctx, ds.ZoneName, failed)
		return msg, rcode, ur, false, failed
	}
	if held {
		// tdns's message says the NOTIFY was sent; whoever asked for the
		// sync is told that it waits
		msg += " (held: it leaves when the zone's nameservers have had time to serve the change)"
	}
	return msg, rcode, ur, true, nil
}

// notifyPeersParentSyncDone sends STATUS-UPDATE("parentsync-done") to all
// remote agents for the zone. Called after a successful parent delegation sync.
func notifyPeersParentSyncDone(conf *Config, zonename string, result string, msg string) {
	tm := conf.InternalMp.MPTransport
	if tm == nil || tm.DNSTransport == nil {
		lg.Debug("notifyPeersParentSyncDone: no TransportManager, skipping peer notification", "zone", zonename)
		return
	}

	agents, err := tm.getAllAgentsForZone(ZoneName(zonename))
	if err != nil {
		lg.Warn("notifyPeersParentSyncDone: failed to get agents for zone", "zone", zonename, "err", err)
		return
	}

	if len(agents) == 0 {
		lg.Debug("notifyPeersParentSyncDone: no remote agents for zone", "zone", zonename)
		return
	}

	for _, agentID := range agents {
		peer, exists := tm.PeerRegistry.Get(string(agentID))
		if !exists {
			lg.Debug("notifyPeersParentSyncDone: agent not in peer registry, skipping", "agent", agentID, "zone", zonename)
			continue
		}

		post := &core.StatusUpdatePost{
			Zone:    zonename,
			SubType: "parentsync-done",
			Result:  result,
			Msg:     msg,
			Time:    time.Now(),
		}

		go func(p *transport.Peer, id AgentId) {
			sendCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := tm.sendStatusUpdate(sendCtx, p, post)
			if err != nil {
				lg.Warn("notifyPeersParentSyncDone: failed to send", "agent", id, "zone", zonename, "err", err)
			} else {
				lg.Info("notifyPeersParentSyncDone: sent", "agent", id, "zone", zonename)
			}
		}(peer, agentID)
	}
}

// syncherPublishesDNSKEYCDS: the pre-S5 rule, a CDS of every SEP DNSKEY
// on a DNSKEY change, holds for a zone with delegation sync that tdns's
// machine runs; an owned zone's CDS is the owner's DS set (arrow 1).
func syncherPublishesDNSKEYCDS(conf *Config, zd *tdns.ZoneData) bool {
	if zd == nil || !zd.Options[tdns.OptParentSync] {
		return false
	}
	if conf != nil {
		if o := conf.InternalMp.KeyLifecycleOwner; o != nil && o.runsKeys(zd) {
			return false
		}
	}
	return true
}

// setupArmRuns: tdns's delegation-sync setup runs for a zone tdns runs
// alone. For a zone with the multi-provider option, one with a single
// provider included, it does nothing (step 7b): through tdns's
// Sig0KeyPreparation it makes a key when none is held, and publishes another
// active key beside a published KEY it holds no private part for. The zone's
// key is the leader's key set-up's (leaderKeySetup, decideZoneKey).
func setupArmRuns(zd *tdns.ZoneData) bool {
	return zd == nil || !zd.Options[tdns.OptMultiProvider]
}

// delegationSyncBeforeHandoff runs in a leader sync after its last look at
// the option and before it hands its NOTIFY over: the window a takeover can
// land in. A test puts a takeover there.
var delegationSyncBeforeHandoff = func(zone string) {}
