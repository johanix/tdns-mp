/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
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
	nod.RRtypes.Set(rrtype, cur) // mp-private: SDE node record, not zone data

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

	// The tdns-mp agent exists solely for multi-provider coordination, so the
	// SynchedDataEngine is always active. (Historically this was gated by
	// syncheddataengine.active, a leftover from when MP support lived in the
	// standard tdns agent; the flag only ever silently disabled sync.)
	lgEngine.Info("SynchedDataEngine starting")

	// XXX: Set up communication with the combiner

	zdr, err := NewZoneDataRepo()
	if err != nil {
		lgEngine.Error("failed to create zone data repo", "err", err)
		return
	}
	// Restore the replace-order guard before any remote update is applied
	// (tdns-mp #249): without it, a queued older distribution can roll a
	// set back after a restart.
	zdr.attachHsyncDB(conf.InternalMp.HsyncDB)

	conf.InternalMp.ZoneDataRepo = zdr

	// Hydrate SDE for each multi-provider zone. Per zone, sequentially:
	// 1. RFI EDITS -> combiner: all agents' contributions (baseline)
	// 2. RFI KEYSTATE -> signer: DNSKEY inventory (local vs foreign keys)
	//
	// Uses conf.InternalMp.MPZoneNames (collected at parse time) instead of
	// scanning Zones.IterBuffered() -- avoids race with RefreshEngine.
	tm := conf.InternalMp.MPTransport
	hasCombiner := tm != nil && conf.namesCombiner()
	hasSigner := tm != nil && tm.signerID != ""

	lgEngine.Info("SynchedDataEngine started")

	if hasCombiner || hasSigner {
		lgEngine.Info("startup hydration: MP zones to hydrate", "count", len(conf.InternalMp.MPZoneNames), "zones", conf.InternalMp.MPZoneNames)
		for _, zname := range conf.InternalMp.MPZoneNames {
			zd, ok := Zones.Get(zname)
			if !ok || zd == nil {
				lgEngine.Warn("startup hydration: zone not in Zones map, skipping", "zone", zname)
				continue
			}
			if hasCombiner {
				lgEngine.Info("startup hydration: requesting edits from combiner", "zone", zname)
				conf.RequestAndWaitForEdits(zd.ZoneData, ctx, conf.InternalMp.MPTransport, conf.InternalMp.MsgQs, conf.InternalMp.ZoneDataRepo, AgentId(conf.MpConfig().Identity))
			}
			weAreSigner := zd.MP != nil && zd.MP.MPdata != nil && zd.MP.MPdata.WeAreSigner
			notASigner := zd.MP != nil && zd.MP.MPdata != nil && !zd.MP.MPdata.WeAreSigner
			if hasSigner && !notASigner {
				lgEngine.Info("startup hydration: requesting key inventory from signer", "zone", zname, "weAreSigner", weAreSigner)
				zd.RequestAndWaitForKeyInventory(ctx, conf.InternalMp.MPTransport)

				changed, ds, err := zd.LocalDnskeysFromKeystate(AgentId(conf.MpConfig().Identity), nil)
				if errors.Is(err, errNoRoleInZone) {
					lgEngine.Debug("startup hydration: no DNSKEYs of this provider are distributed", "zone", zname, "reason", err)
				} else if err != nil {
					lgEngine.Error("startup hydration: LocalDnskeysFromKeystate failed", "zone", zname, "err", err)
				} else if changed && ds != nil {
					localAgentID := AgentId(conf.MpConfig().Identity)
					for _, rr := range ds.CurrentLocalKeys {
						zdr.AddConfirmedRR(ZoneName(zname), localAgentID, rr)
					}
					lgEngine.Info("startup hydration: added local DNSKEYs to SDE", "zone", zname, "keys", len(ds.CurrentLocalKeys))
				}
				// The hydration takes the keys as already distributed, but
				// not what we say about them (#58): the other providers may
				// have restarted too, or run a release that now listens.
				// Forgotten here, so the first inventory after the start
				// sends the key states with the REPLACE.
				if zd.MP != nil {
					zd.MP.LocalKeyStates = nil
				}
			}
		}
		lgEngine.Info("startup hydration complete")
	}
	// The catch-up tracker sends from here on: answers to its requests,
	// and requests back, no longer wait on this loop.
	conf.InternalMp.CatchUp.run(ctx, zdr)

	// Periodic eviction of stale tracking entries (terminal states older than 1 hour).
	trackingEvictTicker := time.NewTicker(5 * time.Minute)
	defer trackingEvictTicker.Stop()

	// The own read of a zone that is not done is read again (own_read.go).
	ownReadTicker := time.NewTicker(ownReadInterval)
	defer ownReadTicker.Stop()
	// An owed sync that found the delegation sync queue full is asked for
	// again sooner than every tick of the own read (catchup.go).
	owedRoomTicker := time.NewTicker(catchUpRoomRetry)
	defer owedRoomTicker.Stop()
	owner := newOwnReader(conf, msgQs, zdr)

	for {
		select {
		case <-ctx.Done():
			lgEngine.Info("SynchedDataEngine context cancelled")
			return

		case <-trackingEvictTicker.C:
			zdr.evictStaleTracking(1 * time.Hour)

		case <-ownReadTicker.C:
			owner.tick(ctx)
			// A zone can become caught up with no answer: a refresh that
			// drops the member waited for, a forgotten peer, an inventory
			// that arrives outside this engine. Its owed sync is asked for
			// here.
			conf.InternalMp.CatchUp.askAllOwed(ctx, false)
			// the backstop for the syncs held for a zone's SIG(0) key, off
			// this goroutine: the test reads the keystore and asks the
			// resolver
			conf.retestKeyHoldsInBackground(ctx)

		case <-owedRoomTicker.C:
			if conf.InternalMp.CatchUp.roomWaits() {
				conf.InternalMp.CatchUp.askAllOwed(ctx, true)
			}

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
					stored := time.Now()
					if err != nil {
						lgEngine.Error("failed to add update to agent data repo", "err", err)
						resp.Error = true
						resp.ErrorMsg = err.Error()
						resp.Msg = msg
					}
					// a resend (#256) goes to the peers even when the repo
					// held the set already
					if change || synchedDataUpdate.KeyStatesChanged || synchedDataUpdate.Resend {
						tm := conf.InternalMp.MPTransport
						if tm != nil && synchedDataUpdate.Update != nil {
							// Generate a single shared distID for combiner + all agents
							distID := transport.GenerateDistributionID()

							// Build the expected recipients list for confirmation tracking
							recipients := tm.GetDistributionRecipients(synchedDataUpdate.Zone, synchedDataUpdate.SkipCombiner)

							// Mark all RRs in this update as pending with the distribution ID
							zdr.MarkRRsPending(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, synchedDataUpdate.Update, distID, recipients)

							skipCombiner := synchedDataUpdate.SkipCombiner
							if skipCombiner {
								lgEngine.Info("update applied, enqueuing for remote agents only", "zone", synchedDataUpdate.Zone)
							} else {
								lgEngine.Info("update applied, enqueuing for combiner and remote agents", "zone", synchedDataUpdate.Zone)
								// Enqueue for combiner (reliable delivery with retry)
								_, err := tm.EnqueueForCombiner(synchedDataUpdate.Zone, synchedDataUpdate.Update, distID)
								sentAs := distID
								if err != nil {
									lgEngine.Error("failed to enqueue for combiner", "zone", synchedDataUpdate.Zone, "err", err)
									resp.Error = true
									resp.ErrorMsg = fmt.Sprintf("Combiner enqueue error: %v", err)
									sentAs = ""
								}
								zdr.noteCombinerSend(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, updateRRtypes(synchedDataUpdate.Update), stored, sentAs)
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
									tm.TrackDnskeyPropagation(synchedDataUpdate.Zone, distID, synchedDataUpdate.DnskeyKeyTags, synchedDataUpdate.DnskeyRemovedKeyTags, agents)
									if synchedDataUpdate.Resend {
										tm.foldIntoResend(synchedDataUpdate.Zone, distID)
									}
								}
							}

							if !resp.Error {
								if skipCombiner {
									resp.Msg = "Local update applied, sync enqueued for remote agents"
								} else {
									resp.Msg = "Local update applied, sync enqueued for combiner and zone agents"
								}
							}
							// the leader's CSYNC is one of these: who must
							// confirm it is known now
							conf.delegationCsyncProgress(ctx, zdr, synchedDataUpdate.Zone, nil)
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

				// A CSYNC is taken from the zone's delegation sync leader
				// only; the sender of any other has been told. What else
				// the update carries goes on.
				if reason := conf.refuseCsyncNotFromLeader(synchedDataUpdate, msgQs); reason != "" && len(synchedDataUpdate.Update.Operations) == 0 {
					if synchedDataUpdate.Response != nil {
						select {
						case synchedDataUpdate.Response <- &AgentMsgResponse{Zone: synchedDataUpdate.Zone, AgentId: synchedDataUpdate.AgentId, Error: true, ErrorMsg: reason}:
						default:
							lgEngine.Warn("response channel blocked, skipping response")
						}
					}
					continue
				}

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
					stored := time.Now()
					// A remote KEY operation that changed this agent's data is
					// the first sign of a new zone key: the leader's replace
					// reaches every member. The key is checked (step 7b); the
					// rounds run on the tracker's goroutine.
					if err == nil && change && synchedDataUpdate.Update != nil &&
						slices.Contains(updateRRtypes(synchedDataUpdate.Update), dns.TypeKEY) {
						conf.InternalMp.CatchUp.keyCheck(synchedDataUpdate.Zone)
					}
					// The operations as they arrived, stale replaces too:
					// the confirmation to the sender names what the repo
					// holds of each. A stale replace's records are there
					// when a newer message, an answer to a request for the
					// zone's state or a later distribution, put them there.
					var received []core.RROperation
					if synchedDataUpdate.Update != nil {
						received = synchedDataUpdate.Update.Operations
					}
					staleHeld, _ := zdr.heldRecords(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, synchedDataUpdate.staleOperations())
					staleWaiting := zdr.dnskeyAwaitingAnswer(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, staleHeld)
					staleHeld = withoutRecords(staleHeld, staleWaiting)
					// A set whose last hand-over to the combiner failed is not
					// with the combiner, whatever the repo holds, and a removal
					// (a key left out of a replace, an empty replace) leaves
					// no record to mark. A stale replace of such a set is not
					// handed over (it would roll the set back), names none of
					// its records, and is PARTIAL. A fresh one that matches
					// the repo is handed over again, below; so is one whose
					// last hand-over the combiner has not confirmed yet, as
					// that forward may carry an older set. A stale replace of
					// a set in flight is confirmed with what the repo holds,
					// as before: the leader's CSYNC waits on that.
					var failedSets map[uint16]bool
					if err == nil && synchedDataUpdate.Update != nil {
						failedSets = zdr.setsNotHandedOver(synchedDataUpdate.Zone, synchedDataUpdate.AgentId,
							updateRRtypes(&ZoneUpdate{Operations: received, RRsets: synchedDataUpdate.Update.RRsets}), true)
					}
					// A stale replace of the DNSKEY set while the set that
					// overtook it is on its way to the combiner is no word on
					// the keys either: the combiner may not have that set yet,
					// and a sender takes a success, or a key named, as its key
					// published here. Alone it waits for the combiner's word
					// (waitForCombiner, below); beside a fresh part it is left
					// out of the relayed confirmation, as a failed set is.
					// A set in flight that an answer's forward brought is left
					// out at once, with no wait: the sender credits its keys,
					// a removal too, from the asker's confirmation of the
					// answer (creditFromAnswerLocked).
					var staleNotHeld map[uint16]bool
					staleKeysWaitOn, staleKeysOfAnswer := "", false
					for _, t := range updateRRtypes(&ZoneUpdate{Operations: synchedDataUpdate.staleOperations()}) {
						if t == dns.TypeDNSKEY && !failedSets[t] {
							if x := zdr.setInFlight(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, t); x != "" {
								if zdr.forwardOfAnswer(x) {
									staleKeysOfAnswer = true
								} else {
									staleKeysWaitOn = x
								}
							}
						}
						if failedSets[t] || (t == dns.TypeDNSKEY && (staleKeysWaitOn != "" || staleKeysOfAnswer)) {
							if staleNotHeld == nil {
								staleNotHeld = map[uint16]bool{}
							}
							staleNotHeld[t] = true
						}
					}
					// A set this agent's combiner answered IGNORED is not held
					// either, but by the combiner's policy, and its word on the
					// set that overtook a stale replace named the records as
					// ignored. The stale replace names those the repo holds as
					// ignored too: named nowhere, they left the sender's add
					// PENDING for good (#288).
					ignoredSets := zdr.setsIgnoredByCombiner(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, failedSets)
					staleIgnored := recordsOfTypes(staleHeld, ignoredSets)
					staleHeld = recordsNotOfTypes(staleHeld, failedSets)
					synchedDataUpdate.dropStaleOperations()
					if err == nil && !change && synchedDataUpdate.Update != nil {
						fresh := updateRRtypes(synchedDataUpdate.Update)
						inFlight := zdr.setsNotHandedOver(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, fresh, false)
						for _, t := range fresh {
							if inFlight[t] {
								lgEngine.Info("remote update matches the repo, but the combiner may not have the set: handing it over again",
									"zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId, "rrtype", dns.TypeToString[t])
								change = true
								break
							}
						}
					}
					if err != nil {
						lgEngine.Error("failed to add remote update to agent data repo", "err", err)
						resp.Error = true
						resp.ErrorMsg = err.Error()
					}
					resp.Msg = msg
					// what the sending provider says about its keys (#58) goes
					// to our signer whether or not the DNSKEY set changed, and
					// for a zone our own signer does not own it is the DS set
					// (Amendment 2); only from an update the repo took
					if cu := synchedDataUpdate.CatchUp; cu != nil && err == nil {
						lgEngine.Info("a peer answered a request for the zone's state", "zone", synchedDataUpdate.Zone,
							"peer", synchedDataUpdate.AgentId, "request", cu.Request, "complete", cu.IsComplete(), "why", cu.Why)
						conf.InternalMp.CatchUp.Answered(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, cu)
					}
					// What a replace the repo found stale says about keys is
					// stale too (it is out of the update by now): an older
					// message must not overwrite the key states of a newer
					// one, an answer or a distribution.
					if err == nil && synchedDataUpdate.Update != nil {
						conf.noteForeignAnswer(ctx, synchedDataUpdate.Zone, synchedDataUpdate.AgentId, synchedDataUpdate.Update.Operations, synchedDataUpdate.CatchUp.IsComplete())
					}
					// The answer that completes the catch-up asks for an owed
					// sync, once what it says about keys is noted: the sync
					// computes the DS set from it.
					if synchedDataUpdate.CatchUp != nil && err == nil {
						conf.InternalMp.CatchUp.askOwed(ctx, synchedDataUpdate.Zone)
					}
					if change {
						// Always forward remote updates to the local combiner for persistence.
						// The combiner applies or ignores based on its edit policy.
						lgEngine.Info("remote update applied, enqueuing for combiner", "zone", synchedDataUpdate.Zone)

						tm := conf.InternalMp.MPTransport
						if tm != nil && synchedDataUpdate.Update != nil {
							// Remote update: only enqueue for combiner (not back to agents).
							// The combiner deduplicates KEY/CDS contributions: local agent
							// contributions take precedence over remote-forwarded ones.
							distID, err := enqueueForCombiner(tm, synchedDataUpdate.Zone, synchedDataUpdate.Update, "")
							if err != nil {
								distID = ""
							}
							zdr.noteCombinerSend(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, updateRRtypes(synchedDataUpdate.Update), stored, distID)
							if err != nil {
								// The repo has the records, the combiner does not: they
								// are not held, so the same records sent again go to
								// the combiner, and no confirmation names them as applied.
								zdr.markNotHandedOver(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, synchedDataUpdate.Update,
									"not handed to the combiner: "+err.Error())
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
										Mechanism:         synchedDataUpdate.Mechanism,
										Zone:              synchedDataUpdate.Zone,
										CreatedAt:         time.Now(),
										StaleHeld:         staleHeld,
										StaleIgnored:      staleIgnored,
										StaleWaiting:      staleWaiting,
										NotHeldTypes:      staleNotHeld,
										FromAnswer:        synchedDataUpdate.CatchUp != nil,
										DnskeyOps:         dnskeySetOps(synchedDataUpdate.Update.Operations),
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
						// No-op: the update's desired post-state already holds
						// (adds already present, deletes already absent). Send a
						// positive confirmation so the originating agent can
						// transition PENDING->ACCEPTED (adds) and
						// PendingRemoval->Removed (deletes). Without this an
						// idempotent re-send strands the sender in PENDING.
						//
						// Every such update is confirmed, also when it lists no
						// record and this agent holds nothing of the sender's
						// (decision 42): an empty replace of a set already
						// absent, a stale replace, an answer of empty sets.
						// Unconfirmed, it was sent again for a day, and a stale
						// one sent again after a restart, when the order guard
						// is gone, rolled the set back.
						zone := synchedDataUpdate.Zone
						agentId := synchedDataUpdate.AgentId
						var appliedRecords, removedRecords []string
						inRepo := zdr.inRepo(zone, agentId)
						// A no-op confirmation reports the desired post-state:
						// add/replace records already present -> Applied;
						// delete records already absent -> Removed (the sender
						// tracks removals in ClassINET form). The modern edit
						// path is Operations (apihandler_agent.go emits a
						// "replace"), which takes precedence in ProcessUpdate;
						// the legacy class-overloaded RRsets/RRs form is only a
						// fallback. The operations are the ones that arrived:
						// a stale replace confirmed with no record left the
						// sender waiting for this agent for good (the leader's
						// CSYNC, overtaken by its answer to a request).
						var combinerRejected []string
						if upd := synchedDataUpdate.Update; upd != nil && len(received) > 0 {
							appliedRecords, removedRecords = zdr.heldRecords(zone, agentId, received)
							appliedRecords = withoutRecords(appliedRecords, staleWaiting)
							combinerRejected = zdr.rejectedRecords(zone, agentId, received)
						} else if upd != nil {
							// Legacy class-overloaded form (no Operations).
							confirm := func(rr dns.RR) {
								switch rr.Header().Class {
								case dns.ClassINET:
									s := rr.String()
									if inRepo(s, rr.Header().Rrtype) {
										appliedRecords = append(appliedRecords, s)
									} else if zdr.rejectedByCombiner(zone, agentId, rr.Header().Rrtype, s) {
										combinerRejected = append(combinerRejected, s)
									}
								case dns.ClassNONE:
									m := dns.Copy(rr)
									m.Header().Class = dns.ClassINET
									s := m.String()
									if !inRepo(s, rr.Header().Rrtype) {
										removedRecords = append(removedRecords, s)
									}
								}
							}
							for _, rrset := range upd.RRsets {
								for _, rr := range rrset.RRs {
									confirm(rr)
								}
							}
							for _, rr := range upd.RRs {
								confirm(rr)
							}
						}
						// DNSKEY records that only an answer's forward, not
						// confirmed by this agent's combiner yet, put in the
						// repo are left out, and the confirmation is PARTIAL:
						// it closes the sender's queue entry, and is no word
						// that the keys have propagated (dnskeyAwaitingAnswer).
						status, message := "ok", "desired state already present at remote agent"
						// A success covers every key of a DNSKEY replace: one
						// whose records are not all held (a newer set dropped
						// a key this one added) is confirmed PARTIAL, naming
						// the keys that are held.
						status, message, appliedRecords = zdr.heldSuccess(zone, agentId, received, status, message, appliedRecords)
						if len(staleWaiting) > 0 {
							status, message = "PARTIAL", "desired state already present at remote agent; DNSKEY records from an answer not yet confirmed by its combiner"
						}
						// A record this agent's combiner rejected is not held
						// either, and a plain success would cover it: a DNSKEY
						// sender takes "ok" as every key of the distribution
						// propagated.
						if len(combinerRejected) > 0 {
							status, message = "PARTIAL", message+"; records its combiner rejected are not held"
						}
						// So is a set whose last hand-over to the combiner
						// failed (only a stale replace of one gets here: a
						// fresh one is handed over again). A set the combiner
						// ignored is named as ignored; with nothing else
						// named, the word is the combiner's, IGNORED.
						var ignoredRecords []string
						if len(failedSets) > 0 {
							ignoredRecords = recordsOfTypes(appliedRecords, ignoredSets)
							appliedRecords = recordsNotOfTypes(appliedRecords, failedSets)
							removedRecords = recordsNotOfTypes(removedRecords, failedSets)
							if len(ignoredSets) < len(failedSets) {
								status, message = "PARTIAL", message+"; sets whose hand-over to its combiner failed are not held"
							}
						}
						if len(ignoredSets) > 0 {
							if status == "ok" && len(appliedRecords) == 0 && len(removedRecords) == 0 {
								status, message = "IGNORED", "its combiner applies none of the sender's records of these sets"
							} else {
								status, message = "PARTIAL", message+"; sets its combiner ignores are not held"
							}
						}
						// A DNSKEY set an answer's forward brought, which the
						// combiner has not confirmed, is no word on the keys:
						// none is named, removals included.
						if staleKeysOfAnswer {
							keys := map[uint16]bool{dns.TypeDNSKEY: true}
							appliedRecords = recordsNotOfTypes(appliedRecords, keys)
							removedRecords = recordsNotOfTypes(removedRecords, keys)
							status, message = "PARTIAL", message+"; a DNSKEY set from an answer its combiner has not confirmed is not held"
						}
						if staleKeysWaitOn != "" {
							// The sender has this agent's PENDING; the final
							// word follows the combiner's on the set that
							// overtook this one. Closing the sender's entry
							// now with a PARTIAL would leave its propagation
							// of these keys waiting for good.
							zdr.waitForCombiner(staleKeysWaitOn, &staleWait{
								origDistID: synchedDataUpdate.OriginatingDistID,
								sender:     agentId,
								zone:       zone,
								ops:        received,
								mechanism:  synchedDataUpdate.Mechanism,
								at:         time.Now(),
							})
							lgEngine.Info("a stale DNSKEY replace waits for this agent's combiner to confirm the set that overtook it",
								"zone", zone, "agent", agentId, "originDistID", synchedDataUpdate.OriginatingDistID, "combinerDistID", staleKeysWaitOn)
						} else if msgQs.OnRemoteConfirmationReady != nil {
							lgEngine.Info("remote update already in desired state, sending immediate confirmation",
								"zone", zone, "agent", agentId,
								"applied", len(appliedRecords), "removed", len(removedRecords), "ignored", len(ignoredRecords),
								"awaiting_combiner", len(staleWaiting), "combiner_rejected", len(combinerRejected),
								"originDistID", synchedDataUpdate.OriginatingDistID)
							msgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
								OriginatingDistID: synchedDataUpdate.OriginatingDistID,
								OriginatingSender: string(agentId),
								Mechanism:         synchedDataUpdate.Mechanism,
								Zone:              zone,
								Status:            status,
								Message:           message,
								AppliedRecords:    appliedRecords,
								RemovedRecords:    removedRecords,
								IgnoredRecords:    ignoredRecords,
							})
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
							// Default state for an RR present in the live repo
							// without any tracking entry. Under the eviction
							// policy (only Removed entries evicted, only after
							// the RR is gone) this should rarely fire — it
							// indicates an RR added without going through the
							// tracking path (e.g. some hydration paths).
							// "no-tracking" is more honest than "unknown".
							info := TrackedRRInfo{
								RR:    rrStr,
								State: "no-tracking",
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
					if zd, exists := Zones.Get(string(zone)); exists {
						if inv := zd.GetLastKeyInventory(); inv != nil {
							for _, entry := range inv.Inventory {
								ks[entry.KeyTag] = strings.ToUpper(entry.State)
							}
						}
					}
					return ks
				}

				// Defensive: skip agents whose OwnerData has no rrtypes
				// left. Such empty placeholders can otherwise render as
				// "Source: X / (no RRsets)" rows in the CLI output —
				// confusing to operators. applyEditsToSDE removes empty
				// owner entries on its own; this guard catches cases
				// from any other code path that might leave one behind.
				if sdcmd.Zone != "" {
					zone := sdcmd.Zone
					ks := buildKeyStates(zone)
					if agentRepo, ok := zdr.Repo.Get(zone); ok {
						agentData := make(map[AgentId]map[uint16][]TrackedRRInfo)
						for agentId, ownerData := range agentRepo.Data.Items() {
							if ownerData == nil || ownerData.RRtypes.Count() == 0 {
								continue
							}
							agentData[agentId] = dumpZoneAgent(zone, agentId, ownerData, ks)
						}
						dumpData[zone] = agentData
					}
				} else {
					for zone, agentRepo := range zdr.Repo.Items() {
						ks := buildKeyStates(zone)
						agentData := make(map[AgentId]map[uint16][]TrackedRRInfo)
						for agentId, ownerData := range agentRepo.Data.Items() {
							if ownerData == nil || ownerData.RRtypes.Count() == 0 {
								continue
							}
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
				// 0. Pull contributions from combiner (RFI EDITS).
				// This brings back all agents contributions, including our own,
				// ensuring the SDE is in sync with the combiner state.
				zd, zdExists := Zones.Get(string(sdcmd.Zone))
				if zdExists && zd != nil {
					lgEngine.Info("resync: pulling contributions from combiner", "zone", sdcmd.Zone)
					conf.RequestAndWaitForEdits(zd.ZoneData, ctx, tm, conf.InternalMp.MsgQs, zdr, AgentId(conf.MpConfig().Identity))
				}

				myAgentId := AgentId(conf.MpConfig().Identity)
				agentRepo, ok := zdr.Repo.Get(sdcmd.Zone)
				if !ok {
					sdcmd.Response <- &SynchedDataCmdResponse{Msg: fmt.Sprintf("No local data for zone %s", sdcmd.Zone)}
					continue
				}

				// An agent whose provider has no role in the zone sends none
				// of its own data, to the other agents or to its combiner:
				// an empty replace there would change what the provider
				// contributed (decision 33). The other agents' data still
				// goes to its combiner (2. below), which repairs the
				// combiner and changes nothing of this provider's.
				noRole := !votesInZone(sdcmd.Zone, myAgentId)
				if noRole {
					lgEngine.Info(noRolePushNote(sdcmd.Zone))
				}

				var totalRRs int

				// 1. Send local data (excluding DNSKEY) to combiner.
				//    Local DNSKEYs reach the combiner via the signer, not via UPDATE.
				//    All RRtypes are sent as Operations (replace) for explicit semantics.
				//    Empty REPLACEs sent for RRtypes with no data (stale cleanup).
				zu := &ZoneUpdate{
					Zone:    sdcmd.Zone,
					AgentId: myAgentId,
				}
				sentRRtypes := make(map[uint16]bool)
				if nod, ok := agentRepo.Data.Get(myAgentId); ok && !noRole {
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
						sentRRtypes[rrtype] = true
						totalRRs += len(records)
					}
				}
				// Send empty REPLACE for AllowedLocalRRtypes not already sent.
				// This tells the combiner "I have zero records of this type"
				// and cleans up stale contributions.
				for rrtype := range AllowedLocalRRtypes {
					if noRole {
						break
					}
					if rrtype == dns.TypeDNSKEY {
						continue // DNSKEYs go via signer
					}
					if sentRRtypes[rrtype] {
						continue
					}
					zu.Operations = append(zu.Operations, core.RROperation{
						Operation: "replace",
						RRtype:    dns.TypeToString[rrtype],
						Records:   []string{},
					})
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
				if nod, ok := agentRepo.Data.Get(myAgentId); ok && !noRole {
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

				note := ""
				if noRole {
					note = noRolePushNote(sdcmd.Zone) + ". "
				}
				if totalRRs == 0 {
					sdcmd.Response <- &SynchedDataCmdResponse{Msg: note + fmt.Sprintf("No RRs to resync for zone %s", sdcmd.Zone)}
					continue
				}

				lgEngine.Info("resync complete", "zone", sdcmd.Zone, "rrs", totalRRs)
				sdcmd.Response <- &SynchedDataCmdResponse{
					Msg: note + fmt.Sprintf("Re-synced %d RRs for zone %s", totalRRs, sdcmd.Zone),
				}

			case "own-read":
				// A re-read's answer (ownReader), applied here because the
				// apply writes zdr.Tracking, which has no lock.
				owner.done(sdcmd.Zone)
				if a := sdcmd.ownRead; a != nil {
					if zd, ok := Zones.Get(string(sdcmd.Zone)); ok {
						applyOwnRead(zd, a, zdr, AgentId(conf.MpConfig().Identity))
						conf.InternalMp.CatchUp.ownReadDone(sdcmd.Zone)
						conf.InternalMp.CatchUp.askOwed(ctx, sdcmd.Zone)
					}
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
				myAgentId := AgentId(conf.MpConfig().Identity)
				// It sends this agent's own data alone, which an agent
				// whose provider has no role does not send (decision 33),
				// whoever asks: the combiner's agent-resync asks this way.
				if !votesInZone(sdcmd.Zone, myAgentId) {
					lgEngine.Info(noRolePushNote(sdcmd.Zone), "target", sdcmd.TargetAgent)
					sdcmd.Response <- &SynchedDataCmdResponse{Msg: noRolePushNote(sdcmd.Zone)}
					continue
				}
				// A peer's request for the zone's state carries catch_up,
				// and gets the complete answer (catchUpAnswer). Only the
				// combiner's agent-resync asks without it, for this
				// agent's own data as it holds it, as before.
				if sdcmd.CatchUp != nil {
					msg, err := conf.catchUpAnswer(zdr, sdcmd.Zone, sdcmd.TargetAgent, sdcmd.CatchUp)
					if err != nil {
						lgEngine.Error("the answer to a request for the zone's state was not enqueued", "zone", sdcmd.Zone, "peer", sdcmd.TargetAgent, "err", err)
						sdcmd.Response <- &SynchedDataCmdResponse{Error: true, ErrorMsg: err.Error()}
						continue
					}
					sdcmd.Response <- &SynchedDataCmdResponse{Msg: msg}
					// a peer that started is asked back (peer-start)
					conf.InternalMp.CatchUp.Requested(sdcmd.Zone, sdcmd.TargetAgent, sdcmd.CatchUp)
					continue
				}
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
			fromCombiner := false
			if tm := conf.InternalMp.MPTransport; tm != nil && tm.combinerID != "" && detail.Source == string(tm.combinerID) && detail.Status != "PENDING" {
				fromCombiner = true
				// Only a success says the combiner holds the sets it was
				// handed. After any other word (it applied part of a set,
				// ignored it, failed or refused it) the sets are handed over
				// again when they come again, and a stale replace of one
				// names none of it: a later delivery of the same set, matching
				// the repo, would otherwise be confirmed "ok", which covers
				// every key. An IGNORED is noted as such: a stale replace of
				// the set names its records as ignored (#288).
				if detail.Status == "SUCCESS" || detail.Status == "ok" {
					zdr.noteCombinerConfirmed(detail.Zone, detail.DistributionID, time.Now())
				} else {
					zdr.noteCombinerFailed(detail.Zone, detail.DistributionID, detail.Status == "IGNORED" || detail.Status == "ignored")
				}
			}
			zdr.ProcessConfirmation(detail, msgQs)
			if fromCombiner {
				zdr.releaseStaleWaits(detail, msgQs)
			}
			// the leader's CSYNC waits for its confirmations
			conf.delegationCsyncProgress(ctx, zdr, detail.Zone, detail)
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

// beginDistribution puts a tracked record under a new distribution: its state,
// the distribution it now waits for, and no confirmations.
//
// The confirmations are those of the distribution the record carries. What
// the recipients said about an earlier one says nothing about this one, and
// left in place it counted: a record that every recipient had accepted, and
// that was then deleted, read as confirmed by all of them as soon as the
// first one confirmed the delete. A "pending" that arrives for the new
// distribution used to write over the old answer, which hid this most of the
// time; it is no reason to keep the old answers.
func (tr *TrackedRR) beginDistribution(state RRState, distID string, now time.Time) {
	tr.State = state
	tr.Reason = ""
	tr.DistributionID = distID
	tr.Confirmations = nil
	tr.UpdatedAt = now
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
			tracked.Tracked[i].beginDistribution(RRStatePending, distID, now)
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
			tracked.Tracked[i].beginDistribution(RRStatePendingRemoval, distID, now)
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
			tracked.Tracked[i].beginDistribution(RRStatePendingRemoval, distID, now)
			transitioned++
		}
	}
	if transitioned == 0 && len(tracked.Tracked) > 0 {
		lgEngine.Debug("markAllDeletePending: no RRs eligible for transition", "total", len(tracked.Tracked))
	}
}

// evictStaleTracking removes TrackedRR entries that meet ALL of these
// criteria:
//
//  1. State is Removed. Accepted, Rejected, and Ignored are durable
//     per-RR outcomes (who confirmed, who rejected, who persisted-but-
//     did-not-apply) and are kept for as long as the RR exists in the
//     live data repo. Pending and PendingRemoval are never evicted
//     here; they have their own transition logic.
//
//  2. The RR is no longer present in the live data repo for this
//     (zone, agent, rrtype). When the RR is gone, retaining its
//     tracking metadata serves no display or operational purpose.
//
//  3. Age > maxAge — guard against evicting entries from a very
//     recent removal that an operator might still want to inspect.
//
// All three conditions must hold; the previous policy (any terminal
// state, age-only) discarded reasons and per-recipient confirmations
// for live RRs after one hour, leaving the display showing "unknown"
// for RRs whose Accepted/Rejected/Ignored history was simply garbage-
// collected.
func (zdr *ZoneDataRepo) evictStaleTracking(maxAge time.Duration) {
	evicted := 0
	for zone, agentMap := range zdr.Tracking {
		agentRepo, hasRepo := zdr.Repo.Get(zone)
		for agent, rrtypeMap := range agentMap {
			var ownerData *OwnerData
			if hasRepo {
				ownerData, _ = agentRepo.Data.Get(agent)
			}
			for rrtype, trackedRRset := range rrtypeMap {
				liveRRs := liveRRStrings(ownerData, rrtype)
				remaining := trackedRRset.Tracked[:0]
				for _, tr := range trackedRRset.Tracked {
					rrPresent := liveRRs[tr.RR.String()]
					if tr.State == RRStateRemoved &&
						!rrPresent &&
						time.Since(tr.UpdatedAt) > maxAge {
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

// liveRRStrings returns the set of RR string forms currently present
// in the live data repo for the given owner/rrtype. Returns nil when
// the owner or rrset is absent. Used by evictStaleTracking to gate on
// "is this RR still alive?".
func liveRRStrings(ownerData *OwnerData, rrtype uint16) map[string]bool {
	if ownerData == nil {
		return nil
	}
	rrset, ok := ownerData.RRtypes.Get(rrtype)
	if !ok {
		return nil
	}
	out := make(map[string]bool, len(rrset.RRs))
	for _, rr := range rrset.RRs {
		out[rr.String()] = true
	}
	return out
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

// anyRecipientAccepted returns true if at least one expected recipient has
// sent an "accepted" confirmation. Used to distinguish RRStateAccepted
// (at least one combiner applied) from RRStateIgnored (all combiners
// merely persisted).
func anyRecipientAccepted(tr *TrackedRR) bool {
	for _, r := range tr.ExpectedRecipients {
		if c, ok := tr.Confirmations[r]; ok && c.Status == "accepted" {
			return true
		}
	}
	return false
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
	//
	// It says nothing once the same peer's final answer is in. The two are
	// sent by different goroutines at the peer, and a peer that answers at
	// once (an auditor, a combiner with nothing to do) can have its final
	// answer arrive first. Written over that answer, the late "pending" left
	// the record waiting for a confirmation that had already come and would
	// not come again: the operation stayed pending at its origin for good.
	if detail.Status == "PENDING" {
		lgEngine.Debug("pending confirmation (delivery confirmed, awaiting final response)", "source", source, "distID", detail.DistributionID, "zone", detail.Zone)
		zoneTracking := zdr.Tracking[detail.Zone]
		for _, agentTracking := range zoneTracking {
			for _, trackedRRset := range agentTracking {
				for i := range trackedRRset.Tracked {
					tr := &trackedRRset.Tracked[i]
					if tr.DistributionID != detail.DistributionID {
						continue
					}
					if c, ok := tr.Confirmations[source]; ok && c.Status != "pending" {
						lgEngine.Debug("pending confirmation after the same source's final one, ignored", "source", source, "distID", detail.DistributionID, "zone", detail.Zone, "final", c.Status)
						continue
					}
					setConfirmation(tr, "pending", "")
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

	// Build a set of ignored RR strings for fast lookup
	ignoredSet := make(map[string]bool, len(detail.IgnoredRecords))
	for _, rr := range detail.IgnoredRecords {
		ignoredSet[rr] = true
	}

	// Walk all tracked RRs for this zone and match by distribution ID + RR string
	zoneTracking := zdr.Tracking[detail.Zone]
	if zoneTracking == nil {
		// An answer to a request for the zone's state is not tracked
		// (catchUpAnswer), and the asker confirms it as it confirms any
		// update. In a zone where this agent tracks nothing that is no loss
		// of tracking.
		if zdr.catchUpAnswers[ZoneName(detail.Zone)][AgentId(source)] == detail.DistributionID && detail.DistributionID != "" {
			lgEngine.Debug("confirmation of an answer to a request for the zone's state", "source", source, "zone", detail.Zone, "distID", detail.DistributionID)
			return
		}
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
					} else if ignoredSet[rrStr] {
						setConfirmation(tr, "ignored", "")
						tr.UpdatedAt = now
						matched++
						if allRecipientsConfirmed(tr) {
							// If ANY recipient accepted, the RR is accepted.
							// Only if ALL reported ignored does it go to RRStateIgnored.
							if anyRecipientAccepted(tr) {
								tr.State = RRStateAccepted
							} else {
								tr.State = RRStateIgnored
							}
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
		ignoredRecords := detail.IgnoredRecords

		// If the combiner returned SUCCESS but with no AppliedRecords (no-op),
		// reconstruct from our local repo so the originating agent can match.
		// Same for IGNORED with no IgnoredRecords. Otherwise the records the
		// update's stale replaces held, which the combiner was not sent,
		// are named as applied beside what the combiner said, whatever it
		// said: this agent holds them.
		reconstructed := false
		if detail.Status == "SUCCESS" || detail.Status == "ok" {
			if len(appliedRecords) == 0 {
				appliedRecords = zdr.reconstructRecordsFromRepo(prc)
				reconstructed = true
			}
		} else if detail.Status == "IGNORED" || detail.Status == "ignored" {
			if len(ignoredRecords) == 0 {
				ignoredRecords = zdr.reconstructRecordsFromRepo(prc)
				reconstructed = true
			}
		}
		if !reconstructed && len(prc.StaleHeld) > 0 {
			appliedRecords = append(slices.Clone(appliedRecords), prc.StaleHeld...)
		}
		status := detail.Status
		if len(prc.StaleWaiting) > 0 && (status == "SUCCESS" || status == "ok") {
			status = "PARTIAL" // keys an answer's forward has not brought yet
			appliedRecords = withoutRecords(appliedRecords, prc.StaleWaiting)
		}
		// A stale set whose hand-over failed is named nowhere, also not
		// from the repo: a PARTIAL that names a key credits it.
		if len(prc.NotHeldTypes) > 0 {
			appliedRecords = recordsNotOfTypes(appliedRecords, prc.NotHeldTypes)
			ignoredRecords = recordsNotOfTypes(ignoredRecords, prc.NotHeldTypes)
			if status == "SUCCESS" || status == "ok" {
				status = "PARTIAL" // a stale set the combiner may not have
			}
		}
		// Of those, a set the combiner ignored is named as ignored (#288).
		if len(prc.StaleIgnored) > 0 {
			ignoredRecords = append(slices.Clone(ignoredRecords), prc.StaleIgnored...)
		}

		// A success covers every key of the update's DNSKEY sets. A key the
		// repo no longer holds, because a newer set dropped it before the
		// combiner answered this hand-over (one queued while the combiner
		// was away, answered after the set that overtook it), is not
		// published here: the word is PARTIAL and names the keys that are
		// held, as on the other paths (heldSuccess).
		var message string
		status, message, appliedRecords = zdr.heldSuccess(prc.Zone, AgentId(prc.OriginatingSender), prc.DnskeyOps, status, detail.Message, appliedRecords)

		lgEngine.Info("triggering remote confirmation", "source", source, "originDistID", prc.OriginatingDistID, "to", prc.OriginatingSender, "status", status, "applied", len(appliedRecords), "ignored", len(ignoredRecords))
		remoteDetail := &RemoteConfirmationDetail{
			OriginatingDistID: prc.OriginatingDistID,
			OriginatingSender: prc.OriginatingSender,
			Mechanism:         prc.Mechanism,
			Zone:              prc.Zone,
			Status:            status,
			Message:           message,
			AppliedRecords:    appliedRecords,
			RemovedRecords:    detail.RemovedRecords,
			RejectedItems:     detail.RejectedItems,
			IgnoredRecords:    ignoredRecords,
			Truncated:         detail.Truncated,
		}
		if msgQs != nil && msgQs.OnRemoteConfirmationReady != nil {
			msgQs.OnRemoteConfirmationReady(remoteDetail)
		}
		zdr.mu.Lock()
		delete(zdr.PendingRemoteConfirms, detail.DistributionID)
		zdr.mu.Unlock()
		// A resend of the same distribution that waits as a stale replace
		// has its final word now (waitForCombiner).
		zdr.dropStaleWait(prc.OriginatingDistID, AgentId(prc.OriginatingSender))
	}
}

// inRepo reports whether an RR (in ClassINET form) is held for the agent:
// present in its repo for the zone, as the repo holds it now, and not
// rejected by this agent's combiner (rejectedByCombiner).
func (zdr *ZoneDataRepo) inRepo(zone ZoneName, agentId AgentId) func(rrStr string, rrtype uint16) bool {
	var nod *OwnerData
	if agentRepo, ok := zdr.Repo.Get(zone); ok {
		nod, _ = agentRepo.Get(agentId)
	}
	return func(rrStr string, rrtype uint16) bool {
		if nod == nil {
			return false
		}
		repoRRset, exists := nod.RRtypes.Get(rrtype)
		if !exists {
			return false
		}
		for _, repoRR := range repoRRset.RRs {
			if repoRR.String() == rrStr {
				// a record this agent's combiner rejected stays in the
				// repo, but is not held: confirmed as applied, it would
				// tell the sender its combiner has it
				return !zdr.rejectedByCombiner(zone, agentId, rrtype, rrStr)
			}
		}
		return false
	}
}

// enqueueForCombiner is the remote update's hand-over to this agent's
// combiner; a test makes it fail.
var enqueueForCombiner = func(tm *MPTransportBridge, zone ZoneName, update *ZoneUpdate, distID string) (string, error) {
	return tm.EnqueueForCombiner(zone, update, distID)
}

// markNotHandedOver: a remote update that ProcessUpdate put in the repo
// could not be handed to this agent's combiner (its queue was full, say), so
// the combiner does not have its records. Each add and replace record of the
// update that its combiner neither holds nor is about to (accepted, or
// pending from an earlier forward) is tracked as rejected, with the reason:
// not held (rejectedByCombiner), it goes to the combiner when it is sent
// again, and no confirmation names it as applied. Without this the next
// identical update was a no-op, confirmed as applied from the repo alone,
// and a DNSKEY sender took that as its key published here.
func (zdr *ZoneDataRepo) markNotHandedOver(zone ZoneName, agentId AgentId, update *ZoneUpdate, reason string) {
	if update == nil {
		return
	}
	now := time.Now()
	mark := func(rrtype uint16, rr dns.RR) {
		tracked := zdr.getOrCreateTracking(zone, agentId, rrtype)
		s := rr.String()
		for i := range tracked.Tracked {
			tr := &tracked.Tracked[i]
			if tr.RR.String() != s {
				continue
			}
			if tr.State == RRStateAccepted || tr.State == RRStatePending {
				return
			}
			tr.State, tr.Reason, tr.UpdatedAt = RRStateRejected, reason, now
			return
		}
		tracked.Tracked = append(tracked.Tracked, TrackedRR{RR: rr, State: RRStateRejected, Reason: reason, UpdatedAt: now})
	}
	for _, op := range update.Operations {
		if op.Operation != "add" && op.Operation != "replace" {
			continue
		}
		rrtype, ok := dns.StringToType[op.RRtype]
		if !ok {
			continue
		}
		for _, rrStr := range op.Records {
			if rr, err := dns.NewRR(rrStr); err == nil {
				mark(rrtype, rr)
			}
		}
	}
	if len(update.Operations) > 0 {
		return
	}
	for rrtype, rrset := range update.RRsets {
		for _, rr := range rrset.RRs {
			if rr.Header().Class == dns.ClassINET {
				mark(rrtype, rr)
			}
		}
	}
}

// rejectedRecords are the add and replace records of ops that this agent's
// combiner rejected for the agent (rejectedByCombiner).
func (zdr *ZoneDataRepo) rejectedRecords(zone ZoneName, agentId AgentId, ops []core.RROperation) []string {
	var out []string
	for _, op := range ops {
		if op.Operation != "add" && op.Operation != "replace" {
			continue
		}
		rrtype, ok := dns.StringToType[op.RRtype]
		if !ok {
			continue
		}
		for _, rrStr := range op.Records {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				continue
			}
			if s := rr.String(); zdr.rejectedByCombiner(zone, agentId, rrtype, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// rejectedByCombiner: the agent's record that this agent's combiner
// rejected, or that was never handed to it (markNotHandedOver), and that no
// send has put in its hands since. Either leaves the record in the repo (the
// confirmation handler only sets its state), so the repo alone does not say
// the combiner holds it. Tracking is the
// engine's, as is every caller.
func (zdr *ZoneDataRepo) rejectedByCombiner(zone ZoneName, agentId AgentId, rrtype uint16, rrStr string) bool {
	tracked := zdr.Tracking[zone][agentId][rrtype]
	if tracked == nil {
		return false
	}
	for i := range tracked.Tracked {
		if tracked.Tracked[i].State == RRStateRejected && tracked.Tracked[i].RR.String() == rrStr {
			return true
		}
	}
	return false
}

// dnskeyAwaitingAnswer are those of records, held for the agent, that are
// DNSKEY records which an answer to a request for the zone's state put in
// the repo, and whose forward to this agent's combiner is not confirmed
// yet. A distribution of the agent's that the answer overtook is stale
// here, and holds its keys in the repo only: confirmed as applied, its
// sender would take the keys as propagated before this agent's combiner
// has them. The sender takes them from this agent's final confirmation of
// the answer instead (creditFromAnswerLocked).
func (zdr *ZoneDataRepo) dnskeyAwaitingAnswer(zone ZoneName, agent AgentId, records []string) []string {
	var out []string
	for _, rec := range records {
		rr, err := dns.NewRR(rec)
		if err != nil || rr.Header().Rrtype != dns.TypeDNSKEY {
			continue
		}
		tr := zdr.trackedRR(zone, agent, dns.TypeDNSKEY, rr.String())
		if tr == nil || tr.State != RRStatePending {
			continue
		}
		zdr.mu.Lock()
		prc := zdr.PendingRemoteConfirms[tr.DistributionID]
		zdr.mu.Unlock()
		if prc != nil && prc.FromAnswer {
			out = append(out, rec)
		}
	}
	return out
}

// withoutRecords is records without those in drop.
func withoutRecords(records, drop []string) []string {
	if len(drop) == 0 {
		return records
	}
	var out []string
	for _, r := range records {
		if !slices.Contains(drop, r) {
			out = append(out, r)
		}
	}
	return out
}

// heldRecords are the records of ops that the agent's repo holds as the ops
// ask: an add's or a replace's record present (applied), a delete's record
// absent (removed), in ClassINET form.
func (zdr *ZoneDataRepo) heldRecords(zone ZoneName, agentId AgentId, ops []core.RROperation) (applied, removed []string) {
	inRepo := zdr.inRepo(zone, agentId)
	for _, op := range ops {
		rrtype, ok := dns.StringToType[op.RRtype]
		if !ok {
			continue
		}
		for _, rrStr := range op.Records {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				continue
			}
			s := rr.String()
			switch op.Operation {
			case "add", "replace":
				if inRepo(s, rrtype) {
					applied = append(applied, s)
				}
			case "delete":
				if !inRepo(s, rrtype) {
					removed = append(removed, s)
				}
			}
		}
	}
	return applied, removed
}

// reconstructRecordsFromRepo builds an RR string list from the local repo for
// a pending remote confirmation. Used when the combiner returned a no-op
// confirmation (SUCCESS or IGNORED) with no record lists.
func (zdr *ZoneDataRepo) reconstructRecordsFromRepo(prc *PendingRemoteConfirmation) []string {
	var records []string
	agentId := AgentId(prc.OriginatingSender)
	if agentRepo, ok := zdr.Repo.Get(prc.Zone); ok {
		if nod, ok := agentRepo.Get(agentId); ok {
			for _, rrtype := range nod.RRtypes.Keys() {
				rrset, exists := nod.RRtypes.Get(rrtype)
				if !exists {
					continue
				}
				for _, rr := range rrset.RRs {
					// a record the combiner rejected, or was never
					// handed, is not held: named, its sender would
					// take it as published here
					if s := rr.String(); !zdr.rejectedByCombiner(prc.Zone, agentId, rrtype, s) {
						records = append(records, s)
					}
				}
			}
			lgEngine.Debug("reconstructed records from repo for relay",
				"zone", prc.Zone, "agent", agentId, "records", len(records))
		}
	}
	return records
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
	nod.RRtypes.Set(rrtype, curRRset) // mp-private: SDE node record, not zone data
}
