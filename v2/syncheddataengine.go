/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func NewZoneDataRepo() (*ZoneDataRepo, error) {
	return &ZoneDataRepo{
		Repo:     core.NewStringer[ZoneName, *AgentRepo](),
		Tracking: make(map[ZoneName]map[AgentId]map[uint16]*TrackedRRset),
	}, nil
}

// AddConfirmedRR adds a single RR to the repo and tracking as RRStateAccepted.
// Used to hydrate the SDE with pre-confirmed data from the combiner (RFI EDITS).
func (zdr *ZoneDataRepo) AddConfirmedRR(zone ZoneName, agentID AgentId, rr dns.RR) {
	// Get or create AgentRepo for this zone
	nar, ok := zdr.Get(zone)
	if !ok {
		nar, _ = NewAgentRepo()
		zdr.Set(zone, nar)
	}

	// Get or create OwnerData for this agent
	nod, ok := nar.Get(agentID)
	if !ok {
		nod = tdns.NewOwnerData(string(zone))
		nar.Set(agentID, nod)
	}

	// Add RR to the RRTypeStore
	rrtype := rr.Header().Rrtype
	cur, ok := nod.RRtypes.Get(rrtype)
	if !ok {
		cur = core.RRset{
			Name:   rr.Header().Name,
			RRtype: rrtype,
		}
	}
	cur.Add(rr)
	nod.RRtypes.Set(rrtype, cur)

	// Add tracking entry as RRStateAccepted
	ts := zdr.getOrCreateTracking(zone, agentID, rrtype)
	ts.Tracked = append(ts.Tracked, TrackedRR{
		RR:        rr,
		State:     RRStateAccepted,
		UpdatedAt: time.Now(),
	})
}

// SynchedDataEngine is a component that updates the combiner with new information
// received from the agents that are sharing zones with us.
func (conf *Config) SynchedDataEngine(ctx context.Context, msgQs *MsgQs) {
	SDupdateQ := msgQs.SynchedDataUpdate
	SDcmdQ := msgQs.SynchedDataCmd

	var synchedDataUpdate *SynchedDataUpdate
	var ok bool

	if !viper.GetBool("syncheddataengine.active") {
		lgEngine.Warn("SynchedDataEngine is NOT active, no updates will be sent to the combiner")
		for {
			select {
			case <-ctx.Done():
				lgEngine.Info("SynchedDataEngine context cancelled")
				return
			case synchedDataUpdate, ok = <-SDupdateQ:
				if !ok {
					lgEngine.Info("SynchedDataEngine update channel closed")
					return
				}
				lgEngine.Warn("SynchedDataEngine not active but received an update", "zone", synchedDataUpdate.Zone, "type", synchedDataUpdate.UpdateType)
				// Send error response back to avoid timeout
				if synchedDataUpdate.Response != nil {
					synchedDataUpdate.Response <- &AgentMsgResponse{
						Error:    true,
						ErrorMsg: "SynchedDataEngine is not active",
						Msg:      "syncheddataengine.active is set to false in configuration",
					}
				}
			}
			continue
		}
	} else {
		lgEngine.Info("SynchedDataEngine starting")
	}

	// XXX: Set up communication with the combiner

	zdr, err := NewZoneDataRepo()
	if err != nil {
		lgEngine.Error("failed to create zone data repo", "err", err)
		return
	}

	conf.InternalMp.ZoneDataRepo = zdr

	// Hydrate SDE for each multi-provider zone. Per zone, sequentially:
	// 1. RFI EDITS -> combiner: all agents' contributions (baseline)
	// 2. RFI KEYSTATE -> signer: DNSKEY inventory (local vs foreign keys)
	//
	// Uses conf.InternalMp.MPZoneNames (collected at parse time) instead of
	// scanning Zones.IterBuffered() -- avoids race with RefreshEngine.
	tm := conf.InternalMp.MPTransport
	hasCombiner := tm != nil && tm.combinerID != ""
	hasSigner := tm != nil && tm.signerID != ""

	lgEngine.Info("SynchedDataEngine started")

	if hasCombiner || hasSigner {
		lgEngine.Info("startup hydration: MP zones to hydrate", "count", len(conf.InternalMp.MPZoneNames), "zones", conf.InternalMp.MPZoneNames)
		for _, zname := range conf.InternalMp.MPZoneNames {
			zd, ok := tdns.Zones.Get(zname)
			if !ok || zd == nil {
				lgEngine.Warn("startup hydration: zone not in Zones map, skipping", "zone", zname)
				continue
			}
			if hasCombiner {
				lgEngine.Info("startup hydration: requesting edits from combiner", "zone", zname)
				RequestAndWaitForEdits(zd, ctx)
			}
			weAreSigner := zd.MP != nil && zd.MP.MPdata != nil && zd.MP.MPdata.WeAreSigner
			notASigner := zd.MP != nil && zd.MP.MPdata != nil && !zd.MP.MPdata.WeAreSigner
			if hasSigner && !notASigner {
				lgEngine.Info("startup hydration: requesting key inventory from signer", "zone", zname, "weAreSigner", weAreSigner)
				RequestAndWaitForKeyInventory(zd, ctx)

				changed, ds, err := zd.LocalDnskeysFromKeystate()
				if err != nil {
					lgEngine.Error("startup hydration: LocalDnskeysFromKeystate failed", "zone", zname, "err", err)
				} else if changed && ds != nil {
					localAgentID := AgentId(conf.Config.MultiProvider.Identity)
					for _, rr := range ds.CurrentLocalKeys {
						zdr.AddConfirmedRR(ZoneName(zname), localAgentID, rr)
					}
					lgEngine.Info("startup hydration: added local DNSKEYs to SDE", "zone", zname, "keys", len(ds.CurrentLocalKeys))
				}
			}
		}
		lgEngine.Info("startup hydration complete")
	}

	// Periodic eviction of stale tracking entries (terminal states older than 1 hour).
	trackingEvictTicker := time.NewTicker(5 * time.Minute)
	defer trackingEvictTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			lgEngine.Info("SynchedDataEngine context cancelled")
			return

		case <-trackingEvictTicker.C:
			zdr.evictStaleTracking(1 * time.Hour)

		case synchedDataUpdate = <-SDupdateQ:
			var change bool
			switch synchedDataUpdate.UpdateType {
			case "local":
				lgEngine.Info("received local update", "zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId)

				// 1. Evaluate the update for applicability (valid zone, etc)
				// 2. Evaluate the update according to policy.

				// Prepare a response in case there is a response channel.
				resp := AgentMsgResponse{
					Zone:    synchedDataUpdate.Zone,
					AgentId: synchedDataUpdate.AgentId,
				}

				// agent_policy.go: EvaluateUpdate()
				ok, msg, err := zdr.EvaluateUpdate(synchedDataUpdate)
				if err != nil {
					lgEngine.Error("failed to evaluate update", "err", err)
					continue
				}

				if !ok {
					lgEngine.Info("update not applicable, skipping", "zone", synchedDataUpdate.Zone)
					resp.Error = true
					resp.ErrorMsg = msg
				} else {
					resp.Msg = msg
					// 3. Add the update to the agent data repo.
					// agent_policy.go: ProcessUpdate()
					change, msg, err = zdr.ProcessUpdate(synchedDataUpdate)
					if err != nil {
						lgEngine.Error("failed to add update to agent data repo", "err", err)
						resp.Error = true
						resp.ErrorMsg = err.Error()
						resp.Msg = msg
					}
					if change {
						tm := conf.InternalMp.MPTransport
						if tm != nil && synchedDataUpdate.Update != nil {
							// Generate a single shared distID for combiner + all agents
							distID := transport.GenerateDistributionID()

							// Build the expected recipients list for confirmation tracking
							recipients := tm.GetDistributionRecipients(synchedDataUpdate.Zone, synchedDataUpdate.SkipCombiner)

							// Mark all RRs in this update as pending with the distribution ID
							zdr.MarkRRsPending(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, synchedDataUpdate.Update, distID, recipients)

							skipCombiner := synchedDataUpdate.SkipCombiner
							if !skipCombiner {
								if zd, ok := tdns.Zones.Get(string(synchedDataUpdate.Zone)); ok && zd.Options[tdns.OptMPDisallowEdits] {
									lgEngine.Info("zone is signed but we are not a signer, skipping combiner", "zone", synchedDataUpdate.Zone)
									skipCombiner = true
								}
							}
							if skipCombiner {
								lgEngine.Info("update applied, enqueuing for remote agents only", "zone", synchedDataUpdate.Zone)
							} else {
								lgEngine.Info("update applied, enqueuing for combiner and remote agents", "zone", synchedDataUpdate.Zone)
								// Enqueue for combiner (reliable delivery with retry)
								_, err := tm.EnqueueForCombiner(synchedDataUpdate.Zone, synchedDataUpdate.Update, distID)
								if err != nil {
									lgEngine.Error("failed to enqueue for combiner", "zone", synchedDataUpdate.Zone, "err", err)
									resp.Error = true
									resp.ErrorMsg = fmt.Sprintf("Combiner enqueue error: %v", err)
								}
							}

							// Enqueue for all remote agents in this zone (same distID)
							if err := tm.EnqueueForZoneAgents(synchedDataUpdate.Zone, synchedDataUpdate.Update, distID); err != nil {
								lgEngine.Error("failed to enqueue for zone agents", "zone", synchedDataUpdate.Zone, "err", err)
								if resp.ErrorMsg != "" {
									resp.ErrorMsg += "; " + fmt.Sprintf("Agent enqueue error: %v", err)
								} else {
									resp.Error = true
									resp.ErrorMsg = fmt.Sprintf("Agent enqueue error: %v", err)
								}
							}

							// Register DNSKEY propagation tracking so that when all
							// remote agents confirm, the agent sends KEYSTATE "propagated"
							// back to the signer (mpdist → published transition).
							if len(synchedDataUpdate.DnskeyKeyTags) > 0 {
								agents, err := tm.getAllAgentsForZone(synchedDataUpdate.Zone)
								if err != nil {
									lgEngine.Error("cannot get agents for DNSKEY propagation tracking", "zone", synchedDataUpdate.Zone, "err", err)
								} else if len(agents) > 0 {
									tm.TrackDnskeyPropagation(synchedDataUpdate.Zone, distID, synchedDataUpdate.DnskeyKeyTags, agents)
								}
							}

							if !resp.Error {
								if skipCombiner {
									resp.Msg = "Local update applied, sync enqueued for remote agents"
								} else {
									resp.Msg = "Local update applied, sync enqueued for combiner and zone agents"
								}
							}
						} else if tm == nil {
							lgEngine.Warn("TransportManager not available, cannot enqueue sync messages")
							resp.Error = true
							resp.ErrorMsg = "TransportManager not available"
						}
					}
				}

				if synchedDataUpdate.Response != nil {
					select {
					case synchedDataUpdate.Response <- &resp:
					default:
						lgEngine.Warn("response channel blocked, skipping response")
					}
				}
			case "remote":
				lgEngine.Info("received remote update", "zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId)

				// 1. Evaluate the update for applicability (valid zone, etc)
				// 2. Evaluate the update according to policy.

				// Prepare a response in case there is a response channel.
				resp := AgentMsgResponse{
					Zone:    synchedDataUpdate.Zone,
					AgentId: synchedDataUpdate.AgentId,
				}

				// agent_policy.go: EvaluateUpdate()
				ok, msg, err := zdr.EvaluateUpdate(synchedDataUpdate)
				if err != nil {
					lgEngine.Error("failed to evaluate remote update", "err", err)
					continue
				}

				if !ok {
					lgEngine.Info("remote update not applicable, skipping", "zone", synchedDataUpdate.Zone)
					resp.Error = true
					resp.ErrorMsg = msg
				} else {
					resp.Msg = msg

					// 3. Add the update to the agent data repo.
					// agent_policy.go: ProcessUpdate()
					change, msg, err = zdr.ProcessUpdate(synchedDataUpdate)
					if err != nil {
						lgEngine.Error("failed to add remote update to agent data repo", "err", err)
						resp.Error = true
						resp.ErrorMsg = err.Error()
					}
					resp.Msg = msg
					if change {
						// Check if edits are disallowed for this zone (signed, not a signer)
						remoteSkipCombiner := false
						if zd, ok := tdns.Zones.Get(string(synchedDataUpdate.Zone)); ok && zd.Options[tdns.OptMPDisallowEdits] {
							remoteSkipCombiner = true
						}

						if remoteSkipCombiner {
							lgEngine.Info("remote update accepted locally, not forwarding to combiner (mp-disallow-edits)", "zone", synchedDataUpdate.Zone)
							resp.Msg = "Remote update accepted locally (not forwarded to combiner: zone signed, not a signer)"
							// Send ACCEPTED confirmation with applied records to
							// originator. The data is in our SDE; we just don't
							// forward to our combiner. The sender should not be blocked.
							if synchedDataUpdate.OriginatingDistID != "" && msgQs.OnRemoteConfirmationReady != nil {
								var appliedRecords []string
								var removedRecords []string
								if synchedDataUpdate.Update != nil {
									for _, op := range synchedDataUpdate.Update.Operations {
										if op.Operation == "delete" {
											removedRecords = append(removedRecords, op.Records...)
										} else {
											appliedRecords = append(appliedRecords, op.Records...)
										}
									}
									// Fallback: if Operations was empty, extract from RRsets/RRs
									if len(appliedRecords) == 0 && len(removedRecords) == 0 {
										for _, rrset := range synchedDataUpdate.Update.RRsets {
											for _, rr := range rrset.RRs {
												appliedRecords = append(appliedRecords, rr.String())
											}
										}
										for _, rr := range synchedDataUpdate.Update.RRs {
											if rr.Header().Class == dns.ClassNONE {
												cp := dns.Copy(rr)
												cp.Header().Class = dns.ClassINET
												removedRecords = append(removedRecords, cp.String())
											} else {
												appliedRecords = append(appliedRecords, rr.String())
											}
										}
									}
								}
								lgEngine.Info("sending immediate ACCEPTED for non-signing zone",
									"zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId,
									"records", len(appliedRecords), "removed", len(removedRecords), "originDistID", synchedDataUpdate.OriginatingDistID)
								msgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
									OriginatingDistID: synchedDataUpdate.OriginatingDistID,
									OriginatingSender: string(synchedDataUpdate.AgentId),
									Zone:              synchedDataUpdate.Zone,
									Status:            "ok",
									Message:           "accepted into SDE (not forwarded to combiner: not a signer)",
									AppliedRecords:    appliedRecords,
									RemovedRecords:    removedRecords,
								})
							}
						} else {
							lgEngine.Info("remote update applied, enqueuing for combiner", "zone", synchedDataUpdate.Zone)
						}

						tm := conf.InternalMp.MPTransport
						if !remoteSkipCombiner && tm != nil && synchedDataUpdate.Update != nil {
							// Remote update: only enqueue for combiner (not back to agents).
							// The combiner deduplicates KEY/CDS contributions: local agent
							// contributions take precedence over remote-forwarded ones.
							distID, err := tm.EnqueueForCombiner(synchedDataUpdate.Zone, synchedDataUpdate.Update, "")
							if err != nil {
								lgEngine.Error("failed to enqueue remote update for combiner", "zone", synchedDataUpdate.Zone, "err", err)
								resp.Error = true
								resp.ErrorMsg = fmt.Sprintf("Combiner enqueue error: %v", err)
							} else {
								// Remote update: only the combiner is the expected recipient
								var remoteRecipients []string
								if tm.combinerID != "" {
									remoteRecipients = []string{string(tm.combinerID)}
								}
								zdr.MarkRRsPending(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, synchedDataUpdate.Update, distID, remoteRecipients)
								resp.Msg = "Remote update applied, sync enqueued for combiner"

								// Track mapping from our combiner distID to the originating agent's distID
								// so we can send the final confirmation back when our combiner confirms.
								if synchedDataUpdate.OriginatingDistID != "" {
									zdr.mu.Lock()
									if zdr.PendingRemoteConfirms == nil {
										zdr.PendingRemoteConfirms = make(map[string]*PendingRemoteConfirmation)
									}
									zdr.PendingRemoteConfirms[distID] = &PendingRemoteConfirmation{
										OriginatingDistID: synchedDataUpdate.OriginatingDistID,
										OriginatingSender: string(synchedDataUpdate.AgentId),
										Zone:              synchedDataUpdate.Zone,
										CreatedAt:         time.Now(),
									}
									zdr.mu.Unlock()
									lgEngine.Debug("tracking remote confirm", "combinerDistID", distID, "originDistID", synchedDataUpdate.OriginatingDistID, "from", synchedDataUpdate.AgentId)
								}
							}
						} else if tm == nil {
							lgEngine.Warn("TransportManager not available, cannot enqueue sync messages")
							resp.Error = true
							resp.ErrorMsg = "TransportManager not available"
						}
					} else if !resp.Error && synchedDataUpdate.OriginatingDistID != "" {
						// Data already present and no error — verify in repo and
						// send immediate ACCEPTED so the originating agent can
						// transition from PENDING to ACCEPTED.
						zone := synchedDataUpdate.Zone
						agentId := synchedDataUpdate.AgentId
						if agentRepo, ok := zdr.Repo.Get(zone); ok {
							if nod, ok := agentRepo.Get(agentId); ok {
								var appliedRecords []string
								if synchedDataUpdate.Update != nil {
									for _, rrset := range synchedDataUpdate.Update.RRsets {
										for _, rr := range rrset.RRs {
											repoRRset, exists := nod.RRtypes.Get(rr.Header().Rrtype)
											if !exists {
												continue
											}
											rrStr := rr.String()
											for _, repoRR := range repoRRset.RRs {
												if repoRR.String() == rrStr {
													appliedRecords = append(appliedRecords, rrStr)
													break
												}
											}
										}
									}
									for _, rr := range synchedDataUpdate.Update.RRs {
										repoRRset, exists := nod.RRtypes.Get(rr.Header().Rrtype)
										if !exists {
											continue
										}
										rrStr := rr.String()
										for _, repoRR := range repoRRset.RRs {
											if repoRR.String() == rrStr {
												appliedRecords = append(appliedRecords, rrStr)
												break
											}
										}
									}
								}
								if len(appliedRecords) > 0 && msgQs.OnRemoteConfirmationReady != nil {
									lgEngine.Info("remote update already accepted, sending immediate confirmation",
										"zone", zone, "agent", agentId, "records", len(appliedRecords),
										"originDistID", synchedDataUpdate.OriginatingDistID)
									msgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
										OriginatingDistID: synchedDataUpdate.OriginatingDistID,
										OriginatingSender: string(agentId),
										Zone:              zone,
										Status:            "ok",
										Message:           "data already present at remote agent",
										AppliedRecords:    appliedRecords,
									})
								}
							}
						}
					}
				}
				if synchedDataUpdate.Response != nil {
					select {
					case synchedDataUpdate.Response <- &resp:
					default:
						lgEngine.Warn("response channel blocked, skipping response")
					}
				}
			}

		case sdcmd := <-SDcmdQ:
			lgEngine.Debug("received command", "cmd", sdcmd.Cmd, "zone", sdcmd.Zone)
			switch sdcmd.Cmd {
			case "dump-zonedatarepo":

				if sdcmd.Response == nil {
					lgEngine.Warn("command has no response channel, skipping", "cmd", sdcmd.Cmd)
					continue
				}
				lgEngine.Debug("dumping zone data repo")

				dumpData := make(map[ZoneName]map[AgentId]map[uint16][]TrackedRRInfo)

				// dumpZoneAgent extracts RRs and their tracking state for a zone/agent.
				dumpZoneAgent := func(zone ZoneName, agentId AgentId, ownerData *OwnerData, keyStates map[uint16]string) map[uint16][]TrackedRRInfo {
					rrsetData := make(map[uint16][]TrackedRRInfo)

					// Collect active RRs from the repo with their tracking state
					for _, rrtype := range ownerData.RRtypes.Keys() {
						rrset, _ := ownerData.RRtypes.Get(rrtype)
						var infos []TrackedRRInfo
						activeRRs := make(map[string]bool)
						for _, rr := range rrset.RRs {
							rrStr := rr.String()
							activeRRs[rrStr] = true
							info := TrackedRRInfo{
								RR:    rrStr,
								State: "unknown",
							}
							// Populate DNSKEY state from signer inventory
							if rrtype == dns.TypeDNSKEY {
								if dnskey, ok := rr.(*dns.DNSKEY); ok {
									if ks, found := keyStates[dnskey.KeyTag()]; found {
										info.KeyState = ks
									}
								}
							}
							// Look up tracking state
							if zdr.Tracking[zone] != nil &&
								zdr.Tracking[zone][agentId] != nil &&
								zdr.Tracking[zone][agentId][rrtype] != nil {
								for _, tr := range zdr.Tracking[zone][agentId][rrtype].Tracked {
									if tr.RR.String() == rrStr {
										info.State = tr.State.String()
										info.Reason = tr.Reason
										info.DistributionID = tr.DistributionID
										info.UpdatedAt = tr.UpdatedAt.Format(time.RFC3339)
										info.Confirmations = tr.Confirmations
										break
									}
								}
							}
							infos = append(infos, info)
						}

						// Add tracking-only entries (e.g. Removed, PendingRemoval)
						// that are no longer in the active repo
						if zdr.Tracking[zone] != nil &&
							zdr.Tracking[zone][agentId] != nil &&
							zdr.Tracking[zone][agentId][rrtype] != nil {
							for _, tr := range zdr.Tracking[zone][agentId][rrtype].Tracked {
								trStr := tr.RR.String()
								if !activeRRs[trStr] {
									infos = append(infos, TrackedRRInfo{
										RR:             trStr,
										State:          tr.State.String(),
										Reason:         tr.Reason,
										DistributionID: tr.DistributionID,
										UpdatedAt:      tr.UpdatedAt.Format(time.RFC3339),
										Confirmations:  tr.Confirmations,
									})
								}
							}
						}
						rrsetData[rrtype] = infos
					}

					// Also include rrtypes that exist only in tracking (no active RRs remain)
					if zdr.Tracking[zone] != nil && zdr.Tracking[zone][agentId] != nil {
						for rrtype, trackedRRset := range zdr.Tracking[zone][agentId] {
							if _, exists := rrsetData[rrtype]; exists {
								continue // Already handled above
							}
							var infos []TrackedRRInfo
							for _, tr := range trackedRRset.Tracked {
								infos = append(infos, TrackedRRInfo{
									RR:             tr.RR.String(),
									State:          tr.State.String(),
									Reason:         tr.Reason,
									DistributionID: tr.DistributionID,
									UpdatedAt:      tr.UpdatedAt.Format(time.RFC3339),
									Confirmations:  tr.Confirmations,
								})
							}
							if len(infos) > 0 {
								rrsetData[rrtype] = infos
							}
						}
					}
					return rrsetData
				}

				// buildKeyStates extracts keytag→state from the signer's KEYSTATE inventory.
				buildKeyStates := func(zone ZoneName) map[uint16]string {
					ks := make(map[uint16]string)
					if zd, exists := tdns.Zones.Get(string(zone)); exists {
						if inv := zd.GetLastKeyInventory(); inv != nil {
							for _, entry := range inv.Inventory {
								ks[entry.KeyTag] = strings.ToUpper(entry.State)
							}
						}
					}
					return ks
				}

				if sdcmd.Zone != "" {
					zone := sdcmd.Zone
					ks := buildKeyStates(zone)
					if agentRepo, ok := zdr.Repo.Get(zone); ok {
						agentData := make(map[AgentId]map[uint16][]TrackedRRInfo)
						for agentId, ownerData := range agentRepo.Data.Items() {
							agentData[agentId] = dumpZoneAgent(zone, agentId, ownerData, ks)
						}
						dumpData[zone] = agentData
					}
				} else {
					for zone, agentRepo := range zdr.Repo.Items() {
						ks := buildKeyStates(zone)
						agentData := make(map[AgentId]map[uint16][]TrackedRRInfo)
						for agentId, ownerData := range agentRepo.Data.Items() {
							agentData[agentId] = dumpZoneAgent(zone, agentId, ownerData, ks)
						}
						dumpData[zone] = agentData
					}
				}

				sdcmd.Response <- &SynchedDataCmdResponse{
					Zone:     "",
					ZDR:      dumpData,
					Msg:      "Zone data repo dumped",
					Error:    false,
					ErrorMsg: "",
				}

			case "resync":
				if sdcmd.Response == nil {
					lgEngine.Warn("resync command has no response channel, skipping")
					continue
				}
				if sdcmd.Zone == "" {
					sdcmd.Response <- &SynchedDataCmdResponse{Error: true, ErrorMsg: "zone is required for resync"}
					continue
				}
				tm := conf.InternalMp.MPTransport
				if tm == nil {
					sdcmd.Response <- &SynchedDataCmdResponse{Error: true, ErrorMsg: "TransportManager not available"}
					continue
				}
				myAgentId := AgentId(conf.Config.MultiProvider.Identity)
				agentRepo, ok := zdr.Repo.Get(sdcmd.Zone)
				if !ok {
					sdcmd.Response <- &SynchedDataCmdResponse{Msg: fmt.Sprintf("No local data for zone %s", sdcmd.Zone)}
					continue
				}

				var totalRRs int

				// 1. Send local data (excluding DNSKEY) to combiner.
				//    Local DNSKEYs reach the combiner via the signer, not via UPDATE.
				//    All RRtypes are sent as Operations (replace) for explicit semantics.
				if nod, ok := agentRepo.Data.Get(myAgentId); ok {
					zu := &ZoneUpdate{
						Zone:    sdcmd.Zone,
						AgentId: myAgentId,
					}
					for _, rrtype := range nod.RRtypes.Keys() {
						if rrtype == dns.TypeDNSKEY {
							continue // local DNSKEYs go via signer, not UPDATE
						}
						rrset, exists := nod.RRtypes.Get(rrtype)
						if !exists || len(rrset.RRs) == 0 {
							continue
						}
						var records []string
						for _, rr := range rrset.RRs {
							rr.Header().Class = dns.ClassINET
							records = append(records, rr.String())
						}
						zu.Operations = append(zu.Operations, core.RROperation{
							Operation: "replace",
							RRtype:    dns.TypeToString[rrtype],
							Records:   records,
						})
						totalRRs += len(records)
					}
					if len(zu.Operations) > 0 {
						distID := transport.GenerateDistributionID()
						if _, err := tm.EnqueueForCombiner(sdcmd.Zone, zu, distID); err != nil {
							lgEngine.Error("resync: failed to enqueue local data for combiner", "zone", sdcmd.Zone, "err", err)
						} else {
							var combinerRecipients []string
							if tm.combinerID != "" {
								combinerRecipients = []string{string(tm.combinerID)}
							}
							zdr.MarkRRsPending(sdcmd.Zone, myAgentId, zu, distID, combinerRecipients)
						}
					}

					// Send all local data (including DNSKEY) to remote agents.
					// Remote agents need our DNSKEYs to converge.
					agentZU := &ZoneUpdate{
						Zone:    sdcmd.Zone,
						AgentId: myAgentId,
						RRsets:  make(map[uint16]core.RRset),
					}
					for _, rrtype := range nod.RRtypes.Keys() {
						rrset, exists := nod.RRtypes.Get(rrtype)
						if !exists || len(rrset.RRs) == 0 {
							continue
						}
						cloned := *rrset.Clone()
						var records []string
						for i := range cloned.RRs {
							cloned.RRs[i].Header().Class = dns.ClassINET
							records = append(records, cloned.RRs[i].String())
						}
						agentZU.RRsets[rrtype] = cloned
						agentZU.Operations = append(agentZU.Operations, core.RROperation{
							Operation: "replace",
							RRtype:    dns.TypeToString[rrtype],
							Records:   records,
						})
					}
					if len(agentZU.Operations) > 0 {
						distID := transport.GenerateDistributionID()
						if err := tm.EnqueueForZoneAgents(sdcmd.Zone, agentZU, distID); err != nil {
							lgEngine.Error("resync: failed to enqueue local data for zone agents", "zone", sdcmd.Zone, "err", err)
						}
					}
				}

				// 2. Send remote agents' data to combiner (with correct attribution).
				for _, remoteAgentId := range agentRepo.Data.Keys() {
					if remoteAgentId == myAgentId {
						continue // already handled above
					}
					remoteNod, ok := agentRepo.Data.Get(remoteAgentId)
					if !ok {
						continue
					}
					zu := &ZoneUpdate{
						Zone:    sdcmd.Zone,
						AgentId: remoteAgentId, // attribute to the remote agent
					}
					for _, rrtype := range remoteNod.RRtypes.Keys() {
						rrset, exists := remoteNod.RRtypes.Get(rrtype)
						if !exists || len(rrset.RRs) == 0 {
							continue
						}
						var records []string
						for _, rr := range rrset.RRs {
							rr.Header().Class = dns.ClassINET
							records = append(records, rr.String())
						}
						zu.Operations = append(zu.Operations, core.RROperation{
							Operation: "replace",
							RRtype:    dns.TypeToString[rrtype],
							Records:   records,
						})
						totalRRs += len(records)
					}
					if len(zu.Operations) > 0 {
						distID := transport.GenerateDistributionID()
						if _, err := tm.EnqueueForCombiner(sdcmd.Zone, zu, distID); err != nil {
							lgEngine.Error("resync: failed to enqueue remote agent data for combiner", "zone", sdcmd.Zone, "agent", remoteAgentId, "err", err)
						} else {
							var combinerRecipients []string
							if tm.combinerID != "" {
								combinerRecipients = []string{string(tm.combinerID)}
							}
							zdr.MarkRRsPending(sdcmd.Zone, remoteAgentId, zu, distID, combinerRecipients)
						}
						lgEngine.Info("resync: sent remote agent data to combiner", "zone", sdcmd.Zone, "agent", remoteAgentId, "ops", len(zu.Operations))
					}
				}

				if totalRRs == 0 {
					sdcmd.Response <- &SynchedDataCmdResponse{Msg: fmt.Sprintf("No RRs to resync for zone %s", sdcmd.Zone)}
					continue
				}

				lgEngine.Info("resync complete", "zone", sdcmd.Zone, "rrs", totalRRs)
				sdcmd.Response <- &SynchedDataCmdResponse{
					Msg: fmt.Sprintf("Re-synced %d RRs for zone %s", totalRRs, sdcmd.Zone),
				}

			case "resync-targeted":
				// Send local data (including DNSKEY) only to the requesting agent.
				if sdcmd.Response == nil {
					lgEngine.Warn("resync-targeted command has no response channel, skipping")
					continue
				}
				if sdcmd.Zone == "" || sdcmd.TargetAgent == "" {
					sdcmd.Response <- &SynchedDataCmdResponse{Error: true, ErrorMsg: "zone and target agent are required for resync-targeted"}
					continue
				}
				tm := conf.InternalMp.MPTransport
				if tm == nil {
					sdcmd.Response <- &SynchedDataCmdResponse{Error: true, ErrorMsg: "TransportManager not available"}
					continue
				}
				myAgentId := AgentId(conf.Config.MultiProvider.Identity)
				agentRepo, ok := zdr.Repo.Get(sdcmd.Zone)
				if !ok {
					sdcmd.Response <- &SynchedDataCmdResponse{Msg: fmt.Sprintf("No local data for zone %s", sdcmd.Zone)}
					continue
				}

				nod, ok := agentRepo.Data.Get(myAgentId)
				if !ok {
					sdcmd.Response <- &SynchedDataCmdResponse{Msg: fmt.Sprintf("No local agent data for zone %s", sdcmd.Zone)}
					continue
				}

				// Build ZoneUpdate with all local data (including DNSKEY)
				zu := &ZoneUpdate{
					Zone:    sdcmd.Zone,
					AgentId: myAgentId,
					RRsets:  make(map[uint16]core.RRset),
				}
				var totalRRs int
				for _, rrtype := range nod.RRtypes.Keys() {
					rrset, exists := nod.RRtypes.Get(rrtype)
					if !exists || len(rrset.RRs) == 0 {
						continue
					}
					cloned := *rrset.Clone()
					var records []string
					for i := range cloned.RRs {
						cloned.RRs[i].Header().Class = dns.ClassINET
						records = append(records, cloned.RRs[i].String())
					}
					zu.RRsets[rrtype] = cloned
					zu.Operations = append(zu.Operations, core.RROperation{
						Operation: "replace",
						RRtype:    dns.TypeToString[rrtype],
						Records:   records,
					})
					totalRRs += len(records)
				}

				if totalRRs == 0 {
					sdcmd.Response <- &SynchedDataCmdResponse{Msg: fmt.Sprintf("No RRs to send for zone %s", sdcmd.Zone)}
					continue
				}

				distID := transport.GenerateDistributionID()
				if err := tm.EnqueueForSpecificAgent(sdcmd.Zone, sdcmd.TargetAgent, zu, distID); err != nil {
					lgEngine.Error("resync-targeted: failed to enqueue", "zone", sdcmd.Zone, "target", sdcmd.TargetAgent, "err", err)
					sdcmd.Response <- &SynchedDataCmdResponse{Error: true, ErrorMsg: err.Error()}
					continue
				}

				lgEngine.Info("resync-targeted complete", "zone", sdcmd.Zone, "target", sdcmd.TargetAgent, "rrs", totalRRs)
				sdcmd.Response <- &SynchedDataCmdResponse{
					Msg: fmt.Sprintf("Sent %d RRs for zone %s to %s", totalRRs, sdcmd.Zone, sdcmd.TargetAgent),
				}
			}

		case detail := <-msgQs.Confirmation:
			lgEngine.Info("received confirmation", "source", detail.Source, "distID", detail.DistributionID, "zone", detail.Zone, "status", detail.Status, "applied", len(detail.AppliedRecords), "removed", len(detail.RemovedRecords), "rejected", len(detail.RejectedItems), "truncated", detail.Truncated)
			zdr.ProcessConfirmation(detail, msgQs)
		}
	}
}

func (zdr *ZoneDataRepo) SendUpdate(update *SynchedDataUpdate) error {
	// 1. Send the update to the combiner.
	lgEngine.Debug("sending update to combiner (NYI)")
	return nil
}

// getOrCreateTracking returns (or creates) the TrackedRRset for the given zone/agent/rrtype.
func (zdr *ZoneDataRepo) getOrCreateTracking(zone ZoneName, agent AgentId, rrtype uint16) *TrackedRRset {
	if zdr.Tracking[zone] == nil {
		zdr.Tracking[zone] = make(map[AgentId]map[uint16]*TrackedRRset)
	}
	if zdr.Tracking[zone][agent] == nil {
		zdr.Tracking[zone][agent] = make(map[uint16]*TrackedRRset)
	}
	if zdr.Tracking[zone][agent][rrtype] == nil {
		zdr.Tracking[zone][agent][rrtype] = &TrackedRRset{}
	}
	return zdr.Tracking[zone][agent][rrtype]
}

// MarkRRsPending marks all RRs in a ZoneUpdate as pending with the given distribution ID.
func (zdr *ZoneDataRepo) MarkRRsPending(zone ZoneName, agent AgentId, update *ZoneUpdate, distID string, recipients []string) {
	now := time.Now()

	// Handle Operations first — REPLACE operations define the full set and
	// take precedence over the delta in RRsets/RRs for tracking purposes.
	opsHandled := map[uint16]bool{}
	for _, op := range update.Operations {
		rrtype, ok := dns.StringToType[op.RRtype]
		if !ok {
			continue
		}
		switch op.Operation {
		case "replace":
			tracked := zdr.getOrCreateTracking(zone, agent, rrtype)
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					continue
				}
				zdr.markAddPending(tracked, rr, distID, now)
			}
			opsHandled[rrtype] = true

		case "add":
			tracked := zdr.getOrCreateTracking(zone, agent, rrtype)
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					continue
				}
				zdr.markAddPending(tracked, rr, distID, now)
			}
			opsHandled[rrtype] = true

		case "delete":
			tracked := zdr.getOrCreateTracking(zone, agent, rrtype)
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					continue
				}
				zdr.markDeletePending(tracked, rr, distID, now)
			}
			opsHandled[rrtype] = true
		}
	}

	// Handle RRsets (remote updates) — skip rrtypes already handled by Operations
	for rrtype, rrset := range update.RRsets {
		if opsHandled[rrtype] {
			continue
		}
		tracked := zdr.getOrCreateTracking(zone, agent, rrtype)
		for _, rr := range rrset.RRs {
			switch rr.Header().Class {
			case dns.ClassINET:
				zdr.markAddPending(tracked, rr, distID, now)
			case dns.ClassNONE:
				zdr.markDeletePending(tracked, rr, distID, now)
			case dns.ClassANY:
				zdr.markAllDeletePending(tracked, distID, now)
			}
		}
	}

	// Handle individual RRs (local updates) — skip rrtypes already handled by Operations
	for _, rr := range update.RRs {
		rrtype := rr.Header().Rrtype
		if opsHandled[rrtype] {
			continue
		}
		tracked := zdr.getOrCreateTracking(zone, agent, rrtype)
		switch rr.Header().Class {
		case dns.ClassINET:
			zdr.markAddPending(tracked, rr, distID, now)
		case dns.ClassNONE:
			zdr.markDeletePending(tracked, rr, distID, now)
		case dns.ClassANY:
			zdr.markAllDeletePending(tracked, distID, now)
		}
	}

	// Set ExpectedRecipients on all TrackedRRs that now carry this distID.
	if len(recipients) > 0 {
		zdr.setExpectedRecipients(zone, agent, distID, recipients)
	}
}

// markAddPending marks a ClassINET RR as pending (addition awaiting confirmation).
func (zdr *ZoneDataRepo) markAddPending(tracked *TrackedRRset, rr dns.RR, distID string, now time.Time) {
	rrStr := rr.String()
	for i := range tracked.Tracked {
		if tracked.Tracked[i].RR.String() == rrStr {
			if tracked.Tracked[i].State == RRStateAccepted {
				lgEngine.Debug("markAddPending: RR already accepted, skipping", "rr", rrStr)
				return
			}
			tracked.Tracked[i].State = RRStatePending
			tracked.Tracked[i].Reason = ""
			tracked.Tracked[i].DistributionID = distID
			tracked.Tracked[i].UpdatedAt = now
			return
		}
	}
	tracked.Tracked = append(tracked.Tracked, TrackedRR{
		RR:             rr,
		State:          RRStatePending,
		DistributionID: distID,
		UpdatedAt:      now,
	})
}

// markDeletePending finds the existing tracked RR matching the ClassNONE RR and
// transitions it to RRStatePendingRemoval.
func (zdr *ZoneDataRepo) markDeletePending(tracked *TrackedRRset, rr dns.RR, distID string, now time.Time) {
	// Create a ClassINET copy for matching against tracked RRs
	matchRR := dns.Copy(rr)
	matchRR.Header().Class = dns.ClassINET
	matchStr := matchRR.String()

	for i := range tracked.Tracked {
		if tracked.Tracked[i].RR.String() == matchStr {
			tracked.Tracked[i].State = RRStatePendingRemoval
			tracked.Tracked[i].Reason = ""
			tracked.Tracked[i].DistributionID = distID
			tracked.Tracked[i].UpdatedAt = now
			lgEngine.Debug("marked RR as pending-removal", "rr", matchStr, "distID", distID)
			return
		}
	}
	lgEngine.Warn("markDeletePending: no matching tracked RR found", "rr", matchStr)
}

// markAllDeletePending marks all tracked RRs in the RRset as RRStatePendingRemoval (ClassANY delete).
func (zdr *ZoneDataRepo) markAllDeletePending(tracked *TrackedRRset, distID string, now time.Time) {
	transitioned := 0
	for i := range tracked.Tracked {
		if tracked.Tracked[i].State == RRStateAccepted || tracked.Tracked[i].State == RRStatePending {
			tracked.Tracked[i].State = RRStatePendingRemoval
			tracked.Tracked[i].Reason = ""
			tracked.Tracked[i].DistributionID = distID
			tracked.Tracked[i].UpdatedAt = now
			transitioned++
		}
	}
	if transitioned == 0 && len(tracked.Tracked) > 0 {
		lgEngine.Debug("markAllDeletePending: no RRs eligible for transition", "total", len(tracked.Tracked))
	}
}

// evictStaleTracking removes TrackedRR entries in terminal states (accepted, rejected,
// removed) that have not been updated within maxAge.
func (zdr *ZoneDataRepo) evictStaleTracking(maxAge time.Duration) {
	evicted := 0
	for zone, agentMap := range zdr.Tracking {
		for agent, rrtypeMap := range agentMap {
			for rrtype, trackedRRset := range rrtypeMap {
				remaining := trackedRRset.Tracked[:0]
				for _, tr := range trackedRRset.Tracked {
					if (tr.State == RRStateAccepted || tr.State == RRStateRejected || tr.State == RRStateRemoved) && time.Since(tr.UpdatedAt) > maxAge {
						evicted++
						continue
					}
					remaining = append(remaining, tr)
				}
				trackedRRset.Tracked = remaining
				if len(trackedRRset.Tracked) == 0 {
					delete(rrtypeMap, rrtype)
				}
			}
			if len(rrtypeMap) == 0 {
				delete(agentMap, agent)
			}
		}
		if len(agentMap) == 0 {
			delete(zdr.Tracking, zone)
		}
	}
	if evicted > 0 {
		lgEngine.Info("evicted stale tracking entries", "count", evicted)
	}
}

// setExpectedRecipients sets the ExpectedRecipients on all TrackedRRs matching a given distID.
func (zdr *ZoneDataRepo) setExpectedRecipients(zone ZoneName, agent AgentId, distID string, recipients []string) {
	if zdr.Tracking[zone] == nil || zdr.Tracking[zone][agent] == nil {
		return
	}
	for _, trackedRRset := range zdr.Tracking[zone][agent] {
		for i := range trackedRRset.Tracked {
			if trackedRRset.Tracked[i].DistributionID == distID {
				trackedRRset.Tracked[i].ExpectedRecipients = recipients
			}
		}
	}
}

// allRecipientsConfirmed returns true if every expected recipient has sent a
// non-pending confirmation.
func allRecipientsConfirmed(tr *TrackedRR) bool {
	if len(tr.ExpectedRecipients) == 0 {
		return true // No tracking — behave as before
	}
	for _, r := range tr.ExpectedRecipients {
		c, ok := tr.Confirmations[r]
		if !ok || c.Status == "pending" {
			return false
		}
	}
	return true
}

// ProcessConfirmation updates tracked RR states based on combiner confirmation feedback.
func (zdr *ZoneDataRepo) ProcessConfirmation(detail *ConfirmationDetail, msgQs *MsgQs) {
	now := time.Now()
	source := detail.Source
	if source == "" {
		source = "unknown"
	}
	// Reject sources with suspicious characters (prevent log injection)
	if strings.ContainsAny(source, "\n\r\t") {
		lgEngine.Warn("ProcessConfirmation: source contains control characters, sanitizing", "rawSource", source)
		source = strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == '\t' {
				return '_'
			}
			return r
		}, source)
	}

	// Helper to record per-recipient confirmation on a TrackedRR.
	setConfirmation := func(tr *TrackedRR, status, reason string) {
		if tr.Confirmations == nil {
			tr.Confirmations = make(map[string]RRConfirmation)
		}
		tr.Confirmations[source] = RRConfirmation{
			Status:    status,
			Reason:    reason,
			Timestamp: now,
		}
	}

	// First NOTIFY in two-phase protocol: status="PENDING" means the remote peer
	// received the sync and is processing it.
	if detail.Status == "PENDING" {
		lgEngine.Debug("pending confirmation (delivery confirmed, awaiting final response)", "source", source, "distID", detail.DistributionID, "zone", detail.Zone)
		zoneTracking := zdr.Tracking[detail.Zone]
		for _, agentTracking := range zoneTracking {
			for _, trackedRRset := range agentTracking {
				for i := range trackedRRset.Tracked {
					tr := &trackedRRset.Tracked[i]
					if tr.DistributionID == detail.DistributionID {
						setConfirmation(tr, "pending", "")
					}
				}
			}
		}
		return
	}

	// Build a set of applied RR strings for fast lookup
	appliedSet := make(map[string]bool, len(detail.AppliedRecords))
	for _, rr := range detail.AppliedRecords {
		appliedSet[rr] = true
	}

	// Build a set of removed RR strings for fast lookup
	removedSet := make(map[string]bool, len(detail.RemovedRecords))
	for _, rr := range detail.RemovedRecords {
		removedSet[rr] = true
	}

	// Build a map of rejected RR strings → reason
	rejectedMap := make(map[string]string, len(detail.RejectedItems))
	for _, ri := range detail.RejectedItems {
		rejectedMap[ri.Record] = ri.Reason
	}

	// Walk all tracked RRs for this zone and match by distribution ID + RR string
	zoneTracking := zdr.Tracking[detail.Zone]
	if zoneTracking == nil {
		lgEngine.Warn("no tracking data for zone", "source", source, "zone", detail.Zone)
		return
	}

	matched := 0
	removed := 0
	for agentId, agentTracking := range zoneTracking {
		for rrtype, trackedRRset := range agentTracking {
			for i := range trackedRRset.Tracked {
				tr := &trackedRRset.Tracked[i]
				if tr.DistributionID != detail.DistributionID {
					continue // Wrong distribution
				}
				rrStr := tr.RR.String()

				switch tr.State {
				case RRStatePending:
					// Addition confirmation
					if appliedSet[rrStr] {
						setConfirmation(tr, "accepted", "")
						tr.UpdatedAt = now
						matched++
						if allRecipientsConfirmed(tr) {
							tr.State = RRStateAccepted
							tr.Reason = ""
						}
					} else if reason, rejected := rejectedMap[rrStr]; rejected {
						setConfirmation(tr, "rejected", reason)
						tr.State = RRStateRejected
						tr.Reason = reason
						tr.UpdatedAt = now
						matched++
					}

				case RRStatePendingRemoval:
					if removedSet[rrStr] {
						setConfirmation(tr, "removed", "")
						tr.UpdatedAt = now
						matched++
						if allRecipientsConfirmed(tr) {
							zdr.deleteRRFromRepo(detail.Zone, agentId, rrtype, tr.RR)
							tr.State = RRStateRemoved
							tr.Reason = ""
							removed++
							lgEngine.Info("RR removed (all confirmed)", "source", source, "rr", rrStr)
						}
					} else if reason, rejected := rejectedMap[rrStr]; rejected {
						setConfirmation(tr, "rejected", reason)
						tr.State = RRStateAccepted
						tr.Reason = fmt.Sprintf("delete rejected: %s", reason)
						tr.UpdatedAt = now
						matched++
						lgEngine.Warn("delete rejected for RR", "source", source, "rr", rrStr, "reason", reason)
					}

				case RRStateAccepted:
					// Already accepted — record this recipient's confirmation
					if appliedSet[rrStr] {
						setConfirmation(tr, "accepted", "")
						matched++
					}

				case RRStateRemoved:
					// Already removed — record this recipient's confirmation
					if removedSet[rrStr] {
						setConfirmation(tr, "removed", "")
						matched++
					}
				}
			}
		}
	}

	lgEngine.Info("confirmation processed", "source", source, "distID", detail.DistributionID, "zone", detail.Zone, "matched", matched, "applied", len(detail.AppliedRecords), "removed", removed, "rejected", len(detail.RejectedItems), "truncated", detail.Truncated)

	// Check if this confirmation corresponds to a remote update we forwarded to our combiner.
	zdr.mu.Lock()
	prc, hasPRC := zdr.PendingRemoteConfirms[detail.DistributionID]
	zdr.mu.Unlock()

	if hasPRC {
		appliedRecords := detail.AppliedRecords

		// If the combiner returned SUCCESS but with no AppliedRecords (no-op),
		// reconstruct from our local repo so the originating agent can match.
		if len(appliedRecords) == 0 && (detail.Status == "SUCCESS" || detail.Status == "ok") {
			agentId := AgentId(prc.OriginatingSender)
			if agentRepo, ok := zdr.Repo.Get(prc.Zone); ok {
				if nod, ok := agentRepo.Get(agentId); ok {
					for _, rrtype := range nod.RRtypes.Keys() {
						rrset, exists := nod.RRtypes.Get(rrtype)
						if !exists {
							continue
						}
						for _, rr := range rrset.RRs {
							appliedRecords = append(appliedRecords, rr.String())
						}
					}
					lgEngine.Debug("reconstructed applied records from repo for relay",
						"zone", prc.Zone, "agent", agentId, "records", len(appliedRecords))
				}
			}
		}

		lgEngine.Info("triggering remote confirmation", "source", source, "originDistID", prc.OriginatingDistID, "to", prc.OriginatingSender, "applied", len(appliedRecords))
		remoteDetail := &RemoteConfirmationDetail{
			OriginatingDistID: prc.OriginatingDistID,
			OriginatingSender: prc.OriginatingSender,
			Zone:              prc.Zone,
			Status:            detail.Status,
			Message:           detail.Message,
			AppliedRecords:    appliedRecords,
			RemovedRecords:    detail.RemovedRecords,
			RejectedItems:     detail.RejectedItems,
			Truncated:         detail.Truncated,
		}
		if msgQs != nil && msgQs.OnRemoteConfirmationReady != nil {
			msgQs.OnRemoteConfirmationReady(remoteDetail)
		}
		zdr.mu.Lock()
		delete(zdr.PendingRemoteConfirms, detail.DistributionID)
		zdr.mu.Unlock()
	}
}

// deleteRRFromRepo deletes a specific RR from the active ZoneDataRepo.
func (zdr *ZoneDataRepo) deleteRRFromRepo(zone ZoneName, agent AgentId, rrtype uint16, rr dns.RR) {
	nar, ok := zdr.Repo.Get(zone)
	if !ok {
		return
	}
	nod, ok := nar.Get(agent)
	if !ok {
		return
	}
	curRRset, ok := nod.RRtypes.Get(rrtype)
	if !ok {
		return
	}
	curRRset.Delete(rr)
	nod.RRtypes.Set(rrtype, curRRset)
}
