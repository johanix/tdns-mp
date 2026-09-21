/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"context"
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
				// on a multi-provider zone the setup (a SIG(0) key, published
				// and sent to the parent) is the leader's, like the sync it
				// serves; a peer that is elected later runs it then (R10)
				if !mpSetupAllowed(conf, zd) {
					lg.Info("DelegationSyncher: not the delegation sync leader, skipping the setup", "zone", ds.ZoneName)
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

				// Only the elected leader of a multi-provider zone sends to the
				// parent; a zone this daemon is primary for alone (its
				// identity zone) has no election to wait for.
				if lem := conf.InternalMp.LeaderElectionManager; lem != nil && ds.ZoneData != nil && ds.ZoneData.Options[tdns.OptMultiProvider] {
					if !lem.IsLeader(ZoneName(ds.ZoneName)) {
						lg.Info("DelegationSyncher: not the delegation sync leader, skipping DDNS", "zone", ds.ZoneName)
						continue
					}
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

				msg, rcode, ur, err := zd.SyncZoneDelegation(ctx, hdb.KeyDB, notifyq, ds.SyncStatus, imr().Imr)
				if err != nil {
					lg.Error("DelegationSyncher: error from SyncZoneDelegation, ignoring sync request", "zone", ds.ZoneName, "err", err)
					continue
				}
				ds.SyncStatus.UpdateResult = ur
				lg.Info("DelegationSyncher: SyncZoneDelegation completed", "zone", ds.ZoneName, "msg", msg, "rcode", dns.RcodeToString[int(rcode)])
				// Notify peer agents that parent sync is done
				go notifyPeersParentSyncDone(conf, ds.ZoneName, dns.RcodeToString[int(rcode)], msg)

			case "EXPLICIT-SYNC-DELEGATION":
				lg.Info("DelegationSyncher: request for explicit delegation sync", "zone", ds.ZoneName)

				syncstate, err := zd.AnalyseZoneDelegation(imr().Imr)
				if err != nil {
					lg.Error("DelegationSyncher: error from AnalyseZoneDelegation, ignoring sync request", "zone", ds.ZoneName, "err", err)
					syncstate.Error = true
					syncstate.ErrorMsg = err.Error()
					if ds.Response != nil {
						ds.Response <- syncstate
					}
					// the leader's sync of a multi-provider zone is asked
					// again: whatever asked for it will not ask twice
					if mpLeaderSync(conf, ds) {
						conf.delegationSyncFailed(ctx, ds.ZoneName, err)
					}
					continue
				}

				// Only the elected leader of a multi-provider zone sends to the
				// parent; a zone this daemon is primary for alone (its
				// identity zone) has no election to wait for.
				if lem := conf.InternalMp.LeaderElectionManager; lem != nil && ds.ZoneData != nil && ds.ZoneData.Options[tdns.OptMultiProvider] {
					if !lem.IsLeader(ZoneName(ds.ZoneName)) {
						lg.Info("DelegationSyncher: not the delegation sync leader, skipping DDNS", "zone", ds.ZoneName)
						syncstate.Msg = "not the delegation sync leader, skipping DDNS"
						if ds.Response != nil {
							ds.Response <- syncstate
						}
						continue
					}
				}

				if syncstate.InSync {
					lg.Info("DelegationSyncher: delegation data in parent is in sync with child, no action needed",
						"zone", syncstate.ZoneName, "parent", syncstate.Parent)
					conf.delegationSyncSucceeded(ds.ZoneName)
					if ds.Response != nil {
						ds.Response <- syncstate
					}
					continue
				}

				// Not in sync, let's fix that.
				msg, rcode, ur, err := zd.SyncZoneDelegation(ctx, hdb.KeyDB, notifyq, syncstate, imr().Imr)
				if err != nil {
					lg.Error("DelegationSyncher: error from SyncZoneDelegation", "zone", ds.ZoneName, "err", err)
					syncstate.Error = true
					syncstate.ErrorMsg = err.Error()
					syncstate.UpdateResult = ur
					// a refusal that passes by itself (a SIG(0) key the parent
					// has not finished verifying) must not leave the parent
					// without the DS set until the keys change again
					if mpLeaderSync(conf, ds) {
						conf.delegationSyncFailed(ctx, ds.ZoneName, err)
					}
				} else {
					conf.delegationSyncSucceeded(ds.ZoneName)
					lg.Info("DelegationSyncher: SyncZoneDelegation completed", "zone", ds.ZoneName, "msg", msg, "rcode", dns.RcodeToString[int(rcode)])
					// Notify peer agents that parent sync is done
					go notifyPeersParentSyncDone(conf, ds.ZoneName, dns.RcodeToString[int(rcode)], msg)
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
		if o := conf.InternalMp.KeyLifecycleOwner; o != nil && o.Owns(zd) {
			return false
		}
	}
	return true
}

// mpSetupAllowed: delegation-sync setup on a multi-provider zone runs on
// the elected leader only; a zone tdns runs alone is not gated.
func mpSetupAllowed(conf *Config, zd *tdns.ZoneData) bool {
	if zd == nil || !zd.Options[tdns.OptMultiProvider] || conf == nil {
		return true
	}
	lem := conf.InternalMp.LeaderElectionManager
	if lem == nil {
		return true
	}
	return lem.IsLeader(ZoneName(zd.ZoneName))
}
