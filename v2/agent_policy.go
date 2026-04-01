/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"fmt"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Resource limits to prevent abuse via oversized updates
const (
	MaxOperationsPerUpdate = 1000 // Maximum operations in a single update
	MaxRecordsPerOwner     = 500  // Maximum records per owner per RRtype in a single operation
)

// --- AgentRepo and ZoneDataRepo helper methods ---

func NewAgentRepo() (*AgentRepo, error) {
	return &AgentRepo{
		Data: core.NewStringer[AgentId, *OwnerData](),
	}, nil
}

func (ar *AgentRepo) Get(agentId AgentId) (*OwnerData, bool) {
	return ar.Data.Get(agentId)
}

func (ar *AgentRepo) Set(agentId AgentId, ownerData *OwnerData) {
	ar.Data.Set(agentId, ownerData)
}

func (zdr *ZoneDataRepo) Get(zone ZoneName) (*AgentRepo, bool) {
	return zdr.Repo.Get(zone)
}

func (zdr *ZoneDataRepo) Set(zone ZoneName, agentRepo *AgentRepo) {
	zdr.Repo.Set(zone, agentRepo)
}

func (zdr *ZoneDataRepo) removeTracking(zone ZoneName, agent AgentId, rrtype uint16) {
	if zdr.Tracking[zone] != nil && zdr.Tracking[zone][agent] != nil {
		delete(zdr.Tracking[zone][agent], rrtype)
	}
}

func (zdr *ZoneDataRepo) removeTrackedRR(zone ZoneName, agent AgentId, rrtype uint16, rrStr string) {
	if zdr.Tracking[zone] == nil || zdr.Tracking[zone][agent] == nil {
		return
	}
	tracked := zdr.Tracking[zone][agent][rrtype]
	if tracked == nil {
		return
	}
	for i := range tracked.Tracked {
		if tracked.Tracked[i].RR.String() == rrStr {
			tracked.Tracked = append(tracked.Tracked[:i], tracked.Tracked[i+1:]...)
			return
		}
	}
}

// --- Policy evaluation and update processing ---

func (zdr *ZoneDataRepo) EvaluateUpdate(synchedDataUpdate *SynchedDataUpdate) (bool, string, error) {
	lgAgent.Debug("evaluating update", "zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId)

	// Check resource limits early (M38)
	if len(synchedDataUpdate.Update.Operations) > MaxOperationsPerUpdate {
		return false, fmt.Sprintf("Update for zone %q from %q: too many operations (%d, max %d)",
			synchedDataUpdate.Zone, synchedDataUpdate.AgentId,
			len(synchedDataUpdate.Update.Operations), MaxOperationsPerUpdate), nil
	}
	for _, op := range synchedDataUpdate.Update.Operations {
		if len(op.Records) > MaxRecordsPerOwner {
			return false, fmt.Sprintf("Update for zone %q from %q: too many records in %s operation for %s (%d, max %d)",
				synchedDataUpdate.Zone, synchedDataUpdate.AgentId,
				op.Operation, op.RRtype,
				len(op.Records), MaxRecordsPerOwner), nil
		}
	}
	if len(synchedDataUpdate.Update.RRs) > MaxRecordsPerOwner {
		return false, fmt.Sprintf("Update for zone %q from %q: too many RRs (%d, max %d)",
			synchedDataUpdate.Zone, synchedDataUpdate.AgentId,
			len(synchedDataUpdate.Update.RRs), MaxRecordsPerOwner), nil
	}

	// Defense-in-depth: reject non-empty data from the auditor
	if synchedDataUpdate.UpdateType == "remote" {
		zone := synchedDataUpdate.Zone
		if zd, ok := tdns.Zones.Get(string(zone)); ok {
			senderID := string(synchedDataUpdate.AgentId)
			if IsAuditorIdentity(zd, senderID) {
				hasData := len(synchedDataUpdate.Update.Operations) > 0 ||
					len(synchedDataUpdate.Update.RRs) > 0 ||
					len(synchedDataUpdate.Update.RRsets) > 0
				if hasData {
					return false, fmt.Sprintf("Update for zone %q from %q: auditor may not contribute data",
						zone, senderID), nil
				}
			}
		}
	}

	switch synchedDataUpdate.UpdateType {
	case "remote":
		// Validate Operations if present
		if len(synchedDataUpdate.Update.Operations) > 0 {
			for _, op := range synchedDataUpdate.Update.Operations {
				rrtype, ok := dns.StringToType[op.RRtype]
				if !ok {
					return false, fmt.Sprintf("Update for zone %q from %q: unknown RR type in operation: %s",
						synchedDataUpdate.Zone, synchedDataUpdate.AgentId, op.RRtype), nil
				}
				if !AllowedLocalRRtypes[rrtype] {
					return false, fmt.Sprintf("Update for zone %q from %q: disallowed RR type in operation: %s",
						synchedDataUpdate.Zone, synchedDataUpdate.AgentId, op.RRtype), nil
				}
				for _, rrStr := range op.Records {
					rr, err := dns.NewRR(rrStr)
					if err != nil {
						return false, fmt.Sprintf("Update for zone %q from %q: invalid RR in operation: %s",
							synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrStr), nil
					}
					if !strings.EqualFold(rr.Header().Name, string(synchedDataUpdate.Zone)) {
						return false, fmt.Sprintf("Update for zone %q from %q: RR outside apex in operation: %s",
							synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrStr), nil
					}
				}
			}
		}

		// Validate legacy Records/RRsets
		for _, rrset := range synchedDataUpdate.Update.RRsets {
			for _, rr := range rrset.RRs {
				if !AllowedLocalRRtypes[rr.Header().Rrtype] {
					lgAgent.Warn("invalid RR type", "rr", rr.String())
					return false, fmt.Sprintf("Update for zone %q from %q: Invalid RR type: %s",
						synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rr.String()), nil
				}
				if !strings.EqualFold(rr.Header().Name, string(synchedDataUpdate.Zone)) {
					lgAgent.Warn("invalid RR name (outside apex)", "rr", rr.String())
					return false, fmt.Sprintf("Update for zone %q from %q: Invalid RR name (outside apex): %s",
						synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rr.String()), nil
				}
			}
		}

	case "local":
		rrs := append([]dns.RR{}, synchedDataUpdate.Update.RRs...)

		// Check HSYNC nsmgmt policy for NS record operations
		hasNS := false
		for _, rr := range rrs {
			if rr.Header().Rrtype == dns.TypeNS {
				hasNS = true
				break
			}
		}
		if hasNS {
			zd, exists := tdns.Zones.Get(string(synchedDataUpdate.Zone))
			if !exists {
				return false, "", fmt.Errorf("local update for zone %q: zone not found (system error)", synchedDataUpdate.Zone)
			}
			apex, err := zd.GetOwner(zd.ZoneName)
			if err != nil {
				return false, "", fmt.Errorf("local update for zone %q: cannot get apex: %w", synchedDataUpdate.Zone, err)
			}
			hsyncparamRRset, exists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
			if !exists || len(hsyncparamRRset.RRs) == 0 {
				return false, fmt.Sprintf("Local update for zone %q: no HSYNCPARAM record (NS management not configured)",
					synchedDataUpdate.Zone), nil
			}
			privRR, ok := hsyncparamRRset.RRs[0].(*dns.PrivateRR)
			if !ok || privRR.Data == nil {
				return false, fmt.Sprintf("Local update for zone %q: HSYNCPARAM record has unexpected type", synchedDataUpdate.Zone), nil
			}
			hsyncparam, ok := privRR.Data.(*core.HSYNCPARAM)
			if !ok {
				return false, fmt.Sprintf("Local update for zone %q: HSYNCPARAM record data has unexpected type", synchedDataUpdate.Zone), nil
			}
			if hsyncparam.GetNSmgmt() != core.HsyncNSmgmtAGENT {
				return false, fmt.Sprintf("Local update for zone %q: HSYNCPARAM nsmgmt=%s, NS management not delegated to agents",
					synchedDataUpdate.Zone, core.HsyncNSmgmtToString[hsyncparam.GetNSmgmt()]), nil
			}
		}

		// Must check for (at least): approved RRtype, apex of zone and zone with us in the HSYNC RRset
		for _, rr := range rrs {
			if !AllowedLocalRRtypes[rr.Header().Rrtype] {
				lgAgent.Warn("invalid RR type", "rr", rr.String())
				return false, fmt.Sprintf("Local update for zone %q from mgmt API: Invalid RR type: %s",
					synchedDataUpdate.Zone, rr.String()), nil
			}
			if !strings.EqualFold(rr.Header().Name, string(synchedDataUpdate.Zone)) {
				lgAgent.Warn("invalid RR name (outside apex)", "rr", rr.String())
				return false, fmt.Sprintf("Local update for zone %q from mgmt API: Invalid RR name (outside apex): %s",
					synchedDataUpdate.Zone, rr.String()), nil
			}

			// For local deletes, verify the RR belongs to this agent
			if rr.Header().Class == dns.ClassNONE {
				agentRepo, ok := zdr.Get(synchedDataUpdate.Zone)
				if ok {
					nod, ok := agentRepo.Get(synchedDataUpdate.AgentId)
					if ok {
						rrset, ok := nod.RRtypes.Get(rr.Header().Rrtype)
						if ok {
							checkRR := dns.Copy(rr)
							checkRR.Header().Class = dns.ClassINET
							found := false
							for _, existingRR := range rrset.RRs {
								if dns.IsDuplicate(existingRR, checkRR) {
									found = true
									break
								}
							}
							if !found {
								return false, fmt.Sprintf("Local delete for zone %q: RR not owned by this agent (%s)",
									synchedDataUpdate.Zone, rr.String()), nil
							}
						} else {
							return false, fmt.Sprintf("Local delete for zone %q: no %s RRset owned by this agent",
								synchedDataUpdate.Zone, dns.TypeToString[rr.Header().Rrtype]), nil
						}
					} else {
						return false, fmt.Sprintf("Local delete for zone %q: no data owned by this agent",
							synchedDataUpdate.Zone), nil
					}
				}
			}
		}
	}
	return true, "", nil
}

// Returns change (true/false), msg (string), error (error)
func (zdr *ZoneDataRepo) ProcessUpdate(synchedDataUpdate *SynchedDataUpdate) (bool, string, error) {
	var msg string
	var changed bool
	lgAgent.Debug("processing update", "zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId)
	var nar *AgentRepo
	var err error
	var ok bool
	if nar, ok = zdr.Get(synchedDataUpdate.Zone); !ok {
		lgAgent.Debug("creating new agent repo", "zone", synchedDataUpdate.Zone)
		nar, err = NewAgentRepo()
		lgAgent.Debug("new agent repo created")
		if err != nil {
			return false, "", err
		}
		lgAgent.Debug("setting new agent repo", "zone", synchedDataUpdate.Zone)
		zdr.Set(synchedDataUpdate.Zone, nar)
	}

	lgAgent.Debug("agent repo should now exist", "zone", synchedDataUpdate.Zone)
	// Initialize agent data if it doesn't exist
	var nod *OwnerData
	lgAgent.Debug("getting owner data", "zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId)
	if nod, ok = nar.Get(synchedDataUpdate.AgentId); !ok {
		lgAgent.Debug("creating new owner data", "zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId)
		nod = tdns.NewOwnerData(string(synchedDataUpdate.Zone))
		nar.Set(synchedDataUpdate.AgentId, nod)
	}

	isLocal := synchedDataUpdate.UpdateType == "local"

	// Process explicit Operations if present (takes precedence over RRsets)
	if len(synchedDataUpdate.Update.Operations) > 0 {
		changed, msg = zdr.processOperations(synchedDataUpdate, nar, nod)
		nar.Set(synchedDataUpdate.AgentId, nod)
		zdr.Set(synchedDataUpdate.Zone, nar)
		return changed, msg, nil
	}

	// Iterate through RRsets in the update and only replace those with data
	lgAgent.Debug("iterating through RRsets in the update")
	for rrtype, rrset := range synchedDataUpdate.Update.RRsets {
		if len(rrset.RRs) > 0 {
			lgAgent.Debug("adding RRset to agent", "zone", synchedDataUpdate.Zone,
				"rrtype", dns.TypeToString[rrtype], "agent", synchedDataUpdate.AgentId)
			cur_rrset, ok := nod.RRtypes.Get(rrtype)
			for _, rr := range rrset.RRs {
				switch rr.Header().Class {
				case dns.ClassANY:
					// ANY = delete entire RRset
					if !ok {
						msg = fmt.Sprintf("Removing %s %s RRset from agent %q: RRset does not exist",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
					} else if isLocal {
						msg = fmt.Sprintf("Requesting removal of %s %s RRset from agent %q (pending combiner confirmation)",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
						changed = true
					} else {
						msg = fmt.Sprintf("Removing %s %s RRset from agent %q",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
						nod.RRtypes.Delete(rrtype)
						zdr.removeTracking(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype)
						changed = true
					}
				case dns.ClassNONE:
					// NONE = delete this RR from the RRset
					if !ok {
						msg = fmt.Sprintf("Removing %s RR %q from agent %q: RRset does not exist",
							synchedDataUpdate.Zone, rr.String(), synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
					} else if isLocal {
						msg = fmt.Sprintf("Requesting removal of %s RR from agent %q (pending combiner confirmation)",
							synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
						changed = true
					} else {
						msg = fmt.Sprintf("Removing %s RR from agent %q (remote)",
							synchedDataUpdate.Zone, synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
						delRR := dns.Copy(rr)
						delRR.Header().Class = dns.ClassINET
						cur_rrset.Delete(delRR)
						zdr.removeTrackedRR(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype, delRR.String())
						nod.RRtypes.Set(rrtype, cur_rrset)
						changed = true
					}
				case dns.ClassINET:
					// IN = add this RR to the RRset
					if !ok {
						msg = fmt.Sprintf("Adding %s %s RRset to agent %q",
							synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
						lgAgent.Debug(msg)
						cur_rrset = *rrset.Clone()
						changed = true
					} else {
						for _, rr := range rrset.RRs {
							prevLen := len(cur_rrset.RRs)
							cur_rrset.Add(rr)
							if len(cur_rrset.RRs) > prevLen {
								msg = fmt.Sprintf("Adding RR: %s to RRset", rr.String())
								lgAgent.Debug(msg)
								changed = true
							} else if synchedDataUpdate.Force {
								lgAgent.Debug("RR already present but --force set, marking changed", "rr", rr.String())
								changed = true
							} else {
								lgAgent.Debug("RR already present, skipping", "rr", rr.String())
							}
						}
					}
					nod.RRtypes.Set(rrtype, cur_rrset)
				}
			}
			rrset, ok = nod.RRtypes.Get(rrtype)
			if !ok {
				lgAgent.Debug("RRset does not exist",
					"zone", synchedDataUpdate.Zone, "rrtype", dns.TypeToString[rrtype])
			} else {
				lgAgent.Debug("RRset after addition/deletion",
					"zone", synchedDataUpdate.Zone, "rrtype", dns.TypeToString[rrtype], "rrs", rrset.RRs)
			}
		}
	}
	lgAgent.Debug("setting owner data", "zone", synchedDataUpdate.Zone, "agent", synchedDataUpdate.AgentId)
	nar.Set(synchedDataUpdate.AgentId, nod)
	lgAgent.Debug("setting agent repo", "zone", synchedDataUpdate.Zone)
	zdr.Set(synchedDataUpdate.Zone, nar)
	return changed, msg, nil
}

// processOperations handles explicit Operations (add, delete, replace) on an update.
func (zdr *ZoneDataRepo) processOperations(synchedDataUpdate *SynchedDataUpdate, nar *AgentRepo, nod *OwnerData) (bool, string) {
	var changed bool
	var msg string
	isLocal := synchedDataUpdate.UpdateType == "local"

	for _, op := range synchedDataUpdate.Update.Operations {
		rrtype, ok := dns.StringToType[op.RRtype]
		if !ok {
			lgAgent.Warn("unknown RR type in operation, skipping", "rrtype", op.RRtype)
			continue
		}

		switch op.Operation {
		case "replace":
			changed, msg = zdr.processReplaceOp(synchedDataUpdate, nod, rrtype, op)

		case "add":
			curRRset, _ := nod.RRtypes.Get(rrtype)
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					lgAgent.Warn("invalid RR in add operation, skipping", "rr", rrStr, "err", err)
					continue
				}
				prevLen := len(curRRset.RRs)
				curRRset.Add(rr)
				if len(curRRset.RRs) > prevLen {
					msg = fmt.Sprintf("Added RR via operation: %s", rr.String())
					lgAgent.Debug(msg)
					changed = true
				} else if synchedDataUpdate.Force {
					lgAgent.Debug("RR already present but --force set, marking changed", "rr", rr.String())
					changed = true
				}
			}
			nod.RRtypes.Set(rrtype, curRRset)

		case "delete":
			curRRset, exists := nod.RRtypes.Get(rrtype)
			if !exists {
				lgAgent.Debug("delete operation: RRset does not exist", "rrtype", op.RRtype)
				continue
			}
			if isLocal {
				msg = fmt.Sprintf("Requesting deletion of %s RR(s) from agent %q (pending combiner confirmation)",
					op.RRtype, synchedDataUpdate.AgentId)
				lgAgent.Debug(msg)
				changed = true
			} else {
				for _, rrStr := range op.Records {
					rr, err := dns.NewRR(rrStr)
					if err != nil {
						lgAgent.Warn("invalid RR in delete operation, skipping", "rr", rrStr, "err", err)
						continue
					}
					curRRset.Delete(rr)
					zdr.removeTrackedRR(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype, rr.String())
					msg = fmt.Sprintf("Deleted RR via operation: %s", rr.String())
					lgAgent.Debug(msg)
					changed = true
				}
				if len(curRRset.RRs) == 0 {
					nod.RRtypes.Delete(rrtype)
					zdr.removeTracking(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype)
				} else {
					nod.RRtypes.Set(rrtype, curRRset)
				}
			}

		default:
			lgAgent.Warn("unknown operation type, skipping", "operation", op.Operation)
		}
	}

	return changed, msg
}

// processReplaceOp handles a "replace" operation.
func (zdr *ZoneDataRepo) processReplaceOp(synchedDataUpdate *SynchedDataUpdate, nod *OwnerData, rrtype uint16, op core.RROperation) (bool, string) {
	var changed bool
	var msg string

	// Parse all new RRs
	var newRRs []dns.RR
	for _, rrStr := range op.Records {
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			lgAgent.Warn("invalid RR in replace operation, skipping", "rr", rrStr, "err", err)
			continue
		}
		newRRs = append(newRRs, rr)
	}

	oldRRset, hadOld := nod.RRtypes.Get(rrtype)

	// Empty replacement set = delete entire RRset
	if len(newRRs) == 0 {
		if hadOld && len(oldRRset.RRs) > 0 {
			nod.RRtypes.Delete(rrtype)
			zdr.removeTracking(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype)
			msg = fmt.Sprintf("Replace with empty set: removed %s %s RRset from agent %q",
				synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
			lgAgent.Info(msg)
			changed = true
		}
		return changed, msg
	}

	// Build the new RRset
	var newRRset core.RRset
	newRRset.RRs = append(newRRset.RRs, newRRs...)

	// Check if anything actually changed by comparing old and new
	if hadOld {
		if len(oldRRset.RRs) != len(newRRset.RRs) {
			changed = true
		} else {
			for _, oldRR := range oldRRset.RRs {
				found := false
				for _, newRR := range newRRset.RRs {
					if dns.IsDuplicate(oldRR, newRR) {
						found = true
						break
					}
				}
				if !found {
					changed = true
					break
				}
			}
		}
	} else {
		changed = len(newRRs) > 0
	}

	if changed {
		if hadOld {
			for _, oldRR := range oldRRset.RRs {
				found := false
				for _, newRR := range newRRs {
					if dns.IsDuplicate(oldRR, newRR) {
						found = true
						break
					}
				}
				if !found {
					zdr.removeTrackedRR(synchedDataUpdate.Zone, synchedDataUpdate.AgentId, rrtype, oldRR.String())
				}
			}
		}
		nod.RRtypes.Set(rrtype, newRRset)
		msg = fmt.Sprintf("Replaced %s %s RRset for agent %q: %d RRs",
			synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId, len(newRRs))
		lgAgent.Info(msg)
	} else {
		msg = fmt.Sprintf("Replace %s %s for agent %q: no change (idempotent)",
			synchedDataUpdate.Zone, dns.TypeToString[rrtype], synchedDataUpdate.AgentId)
		lgAgent.Debug(msg)
	}

	return changed, msg
}
