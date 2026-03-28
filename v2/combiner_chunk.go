/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Combiner business logic for multi-provider DNSSEC coordination (HSYNC).
 * Receives sync updates from agents and applies them to zones.
 *
 * Extracted from tdns/v2/combiner_chunk.go into tdns-mp package.
 * CombinerState type remains in tdns (shared with signer).
 * RegisterSignerChunkHandler is in signer_chunk_handler.go.
 */

package tdnsmp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// detectDelegationChanges inspects a CombinerSyncResponse for changes
// to NS records or KSK DNSKEYs (flags=257, SEP bit). These changes
// require parent delegation synchronization.
func detectDelegationChanges(resp *CombinerSyncResponse) (nsChanged, kskChanged bool) {
	for _, rr := range append(resp.AppliedRecords, resp.RemovedRecords...) {
		parsed, err := dns.NewRR(rr)
		if err != nil {
			continue
		}
		switch parsed.Header().Rrtype {
		case dns.TypeNS:
			nsChanged = true
		case dns.TypeDNSKEY:
			if dk, ok := parsed.(*dns.DNSKEY); ok {
				if dk.Flags&dns.SEP != 0 {
					kskChanged = true
				}
			}
		}
	}
	return
}

// --- Standalone business logic functions ---

// RecordCombinerError records an error in the ErrorJournal if available.
func RecordCombinerError(journal *tdns.ErrorJournal, distID, sender, messageType, errMsg, qname string) {
	if journal == nil {
		return
	}
	journal.Record(tdns.ErrorJournalEntry{
		DistributionID: distID,
		Sender:         sender,
		MessageType:    messageType,
		ErrorMsg:       errMsg,
		QNAME:          qname,
		Timestamp:      time.Now(),
	})
}

// ParseAgentMsgNotify parses a sync payload into a CombinerSyncRequest.
// Expects the standard AgentMsgPost format (OriginatorID/Zone/Records).
func ParseAgentMsgNotify(data []byte, distributionID string) (*CombinerSyncRequest, error) {
	var msg struct {
		OriginatorID string                   `json:"OriginatorID"`
		Zone         string                   `json:"Zone"`
		ZoneClass    string                   `json:"ZoneClass"`
		Records      map[string][]string      `json:"Records"`
		Operations   []core.RROperation       `json:"Operations"`
		Publish      *core.PublishInstruction `json:"Publish,omitempty"`
		Time         time.Time                `json:"Time"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	if msg.OriginatorID == "" {
		return nil, fmt.Errorf("missing OriginatorID")
	}
	if msg.Zone == "" && msg.ZoneClass != "provider" {
		return nil, fmt.Errorf("missing Zone")
	}

	records := msg.Records
	if records == nil {
		records = make(map[string][]string)
	}

	rrCount := 0
	for _, rrs := range records {
		rrCount += len(rrs)
	}
	lgCombiner.Debug("parsed sync", "sender", msg.OriginatorID, "zone", msg.Zone, "rrs", rrCount, "owners", len(records))

	return &CombinerSyncRequest{
		SenderID:       msg.OriginatorID,
		Zone:           msg.Zone,
		ZoneClass:      msg.ZoneClass,
		Records:        records,
		Operations:     msg.Operations,
		Publish:        msg.Publish,
		DistributionID: distributionID,
		Timestamp:      msg.Time,
	}, nil
}

// findProviderZoneForRequest finds the best-matching zone for a provider update
// that did not specify a zone.
func findProviderZoneForRequest(req *CombinerSyncRequest) (string, error) {
	var ownerNames []string
	for _, op := range req.Operations {
		for _, rrStr := range op.Records {
			rr, err := dns.NewRR(rrStr)
			if err == nil {
				ownerNames = append(ownerNames, dns.Fqdn(rr.Header().Name))
			}
		}
	}
	for owner := range req.Records {
		ownerNames = append(ownerNames, dns.Fqdn(owner))
	}
	if len(ownerNames) == 0 {
		return "", fmt.Errorf("provider update has no zone and no records to derive zone from")
	}

	best := ""
	bestLabels := 0
	tdns.Zones.IterCb(func(zonename string, zd *tdns.ZoneData) {
		labels := dns.CountLabel(zonename)
		if labels <= bestLabels {
			return
		}
		for _, owner := range ownerNames {
			if !dns.IsSubDomain(zonename, owner) {
				return
			}
		}
		best = zonename
		bestLabels = labels
	})
	if best == "" {
		return "", fmt.Errorf("no zone found on this combiner that contains owner name(s) %v", ownerNames)
	}
	if GetProviderZoneRRtypes(best) == nil {
		return "", fmt.Errorf("zone %q is known but not configured as a provider zone on this combiner", best)
	}
	return best, nil
}

// checkMPauthorization verifies that the combiner is authorized to accept
// contributions for this zone.
func checkMPauthorization(zd *tdns.ZoneData) error {
	if !zd.Options[tdns.OptMultiProvider] {
		return fmt.Errorf("zone %q: contributions rejected — zone is not configured as a multi-provider zone (OptMultiProvider not set)", zd.ZoneName)
	}
	if zd.MP == nil || zd.MP.MPdata == nil {
		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil {
			return fmt.Errorf("zone %q: contributions rejected — cannot inspect zone apex: %v", zd.ZoneName, err)
		}
		_, h3exists := apex.RRtypes.Get(core.TypeHSYNC3)
		_, hpExists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
		_, h1exists := apex.RRtypes.Get(core.TypeHSYNC)
		_, h2exists := apex.RRtypes.Get(core.TypeHSYNC2)
		if !((h3exists && hpExists) || h1exists || h2exists) {
			return fmt.Errorf("zone %q: contributions rejected — zone has OptMultiProvider set but the zone owner has not published HSYNC3+HSYNCPARAM records (zone is not declared as multi-provider by its owner)", zd.ZoneName)
		}
		ourIdentities := tdns.OurHsyncIdentities()
		matched, _, _ := tdns.ZoneDataMatchHsyncProvider(zd, ourIdentities)
		if !matched {
			return fmt.Errorf("zone %q: contributions rejected — none of our agent identities %v match any HSYNC3 provider record in the zone (we are not a recognized provider for this zone)", zd.ZoneName, ourIdentities)
		}
		return fmt.Errorf("zone %q: rejected (mp-disallow-edits: zone is signed, we are not a signer)", zd.ZoneName)
	}
	return nil
}

func CombinerProcessUpdate(req *CombinerSyncRequest, protectedNamespaces []string, localAgents map[string]bool, kdb *tdns.KeyDB, tm *MPTransportBridge) *CombinerSyncResponse {
	totalRecords := 0
	for _, rrs := range req.Records {
		totalRecords += len(rrs)
	}
	lgCombiner.Debug("processing legacy update", "sender", req.SenderID, "zone", req.Zone, "owners", len(req.Records), "records", totalRecords)

	resp := &CombinerSyncResponse{
		DistributionID: req.DistributionID,
		Zone:           req.Zone,
		Timestamp:      time.Now(),
	}

	var zonename string
	if req.Zone == "" && req.ZoneClass == "provider" {
		discovered, err := findProviderZoneForRequest(req)
		if err != nil {
			lgCombiner.Error("provider zone discovery failed", "sender", req.SenderID, "err", err)
			resp.Status = "error"
			resp.Message = err.Error()
			return resp
		}
		lgCombiner.Debug("provider zone discovered", "zone", discovered, "sender", req.SenderID)
		zonename = discovered
		req.Zone = zonename
		resp.Zone = zonename
	} else {
		zonename = dns.Fqdn(req.Zone)
		req.Zone = zonename
	}
	zd, exists := tdns.Zones.Get(zonename)
	if !exists {
		lgCombiner.Error("zone not found", "zone", req.Zone, "sender", req.SenderID)
		resp.Status = "error"
		resp.Message = fmt.Sprintf("zone %q not found on this combiner", req.Zone)
		return resp
	}

	if req.ZoneClass != "provider" {
		if err := checkMPauthorization(zd); err != nil {
			lgCombiner.Warn("rejecting contribution", "zone", req.Zone, "sender", req.SenderID, "reason", err)
			resp.Status = "error"
			resp.Message = err.Error()
			reason := err.Error()
			if len(req.Operations) > 0 {
				for _, op := range req.Operations {
					for _, rr := range op.Records {
						resp.RejectedItems = append(resp.RejectedItems, RejectedItem{Record: rr, Reason: reason})
					}
				}
			} else {
				for _, rrs := range req.Records {
					for _, rr := range rrs {
						resp.RejectedItems = append(resp.RejectedItems, RejectedItem{Record: rr, Reason: reason})
					}
				}
			}
			return resp
		}
	}

	if len(req.Operations) > 0 {
		resp = combinerProcessOperations(req, zd, zonename, protectedNamespaces, localAgents)
		if resp.Status != "error" {
			if req.Publish != nil {
				combinerApplyPublishInstruction(req, zd, kdb)
			}
			combinerResyncSignalKeys(req.SenderID, zonename, zd, kdb)
			if resp.DataChanged {
				nsChanged, kskChanged := detectDelegationChanges(resp)
				if nsChanged || kskChanged {
					go combinerNotifyDelegationChange(tm, req.DeliveredBy, zonename, zd, nsChanged, kskChanged)
				}
			}
		}
		return resp
	}

	if req.Publish != nil {
		combinerApplyPublishInstruction(req, zd, kdb)
		combinerResyncSignalKeys(req.SenderID, zonename, zd, kdb)
		resp.Status = "ok"
		resp.Message = fmt.Sprintf("publish instruction applied for zone %q (no data operations)", req.Zone)
		return resp
	}

	resp.Status = "error"
	resp.Message = fmt.Sprintf("update for zone %q has no Operations", req.Zone)
	return resp
}

// combinerNotifyDelegationChange publishes CDS/CSYNC as needed and sends a
// STATUS-UPDATE notification to the local agent that delivered the update.
func combinerNotifyDelegationChange(tm *MPTransportBridge, senderID, zonename string, zd *tdns.ZoneData, nsChanged, kskChanged bool) {
	zoneSigned := false
	apex, err := zd.GetOwner(zd.ZoneName)
	if err == nil && apex != nil {
		if hpRRset, exists := apex.RRtypes.Get(core.TypeHSYNCPARAM); exists && len(hpRRset.RRs) > 0 {
			hsyncparam := hpRRset.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM)
			if len(hsyncparam.GetSigners()) > 0 {
				zoneSigned = true
			}
		}
	}

	lgCombiner.Info("combinerNotifyDelegationChange: delegation change detected", "zone", zonename, "nsChanged", nsChanged, "kskChanged", kskChanged, "zoneSigned", zoneSigned)

	changed := false

	if nsChanged {
		if !zoneSigned {
			lgCombiner.Debug("combinerNotifyDelegationChange: NS changed but zone is not signed, skipping CSYNC", "zone", zonename)
		} else {
			csync := &dns.CSYNC{
				Serial:     zd.CurrentSerial,
				Flags:      0,
				TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeAAAA},
			}
			csync.Hdr = dns.RR_Header{
				Name:   zd.ZoneName,
				Rrtype: dns.TypeCSYNC,
				Class:  dns.ClassINET,
				Ttl:    120,
			}
			_, _, csyncChanged, err := ReplaceCombinerDataByRRtype(zd, tm.LocalID, zonename, dns.TypeCSYNC, []dns.RR{csync})
			if err != nil {
				lgCombiner.Error("combinerNotifyDelegationChange: CSYNC replace failed", "zone", zonename, "err", err)
			} else {
				lgCombiner.Info("combinerNotifyDelegationChange: CSYNC published", "zone", zonename, "changed", csyncChanged)
				changed = changed || csyncChanged
			}
		}
	}
	if kskChanged {
		cdsRRs, err := tdns.ZoneDataSynthesizeCdsRRs(zd)
		if err != nil {
			lgCombiner.Error("combinerNotifyDelegationChange: CDS synthesis failed", "zone", zonename, "err", err)
		} else if len(cdsRRs) > 0 {
			_, _, cdsChanged, err := ReplaceCombinerDataByRRtype(zd, tm.LocalID, zonename, dns.TypeCDS, cdsRRs)
			if err != nil {
				lgCombiner.Error("combinerNotifyDelegationChange: CDS replace failed", "zone", zonename, "err", err)
			} else {
				lgCombiner.Info("combinerNotifyDelegationChange: CDS published", "zone", zonename, "changed", cdsChanged)
				changed = changed || cdsChanged
			}
		}
	}
	if changed {
		if bumperResp, err := zd.BumpSerialOnly(); err != nil {
			lgCombiner.Error("combinerNotifyDelegationChange: BumpSerialOnly failed", "zone", zonename, "err", err)
		} else {
			lgCombiner.Debug("combinerNotifyDelegationChange: serial bumped", "zone", zonename, "old", bumperResp.OldSerial, "new", bumperResp.NewSerial)
		}
	}

	var nsRecords []string
	if apex != nil {
		nsRRset := apex.RRtypes.GetOnlyRRSet(dns.TypeNS)
		for _, rr := range nsRRset.RRs {
			nsRecords = append(nsRecords, rr.String())
		}
	}

	var dsRecords []string
	if kskChanged && apex != nil {
		for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
			if dk, ok := rr.(*dns.DNSKEY); ok {
				if dk.Flags&dns.SEP != 0 {
					if ds := dk.ToDS(dns.SHA256); ds != nil {
						dsRecords = append(dsRecords, ds.String())
					}
				}
			}
		}
	}

	if nsChanged {
		lgCombiner.Info("combinerNotifyDelegationChange: sending ns-changed", "zone", zonename, "agent", senderID)
		sendDelegationStatusUpdate(tm, senderID, zonename, "ns-changed", nsRecords, nil)
	}
	if kskChanged {
		lgCombiner.Info("combinerNotifyDelegationChange: sending ksk-changed", "zone", zonename, "agent", senderID)
		sendDelegationStatusUpdate(tm, senderID, zonename, "ksk-changed", nil, dsRecords)
	}
}

// sendDelegationStatusUpdate sends a STATUS-UPDATE message to the agent
// via the DNSTransport fire-and-forget NOTIFY(CHUNK) mechanism.
func sendDelegationStatusUpdate(tm *MPTransportBridge, agentID, zonename, subtype string, nsRecords, dsRecords []string) {
	if tm == nil || tm.DNSTransport == nil {
		lgCombiner.Warn("sendDelegationStatusUpdate: no DNSTransport, cannot notify agent", "zone", zonename, "subtype", subtype)
		return
	}

	peer, exists := tm.PeerRegistry.Get(agentID)
	if !exists {
		lgCombiner.Warn("sendDelegationStatusUpdate: agent not in peer registry", "agent", agentID, "zone", zonename, "subtype", subtype)
		return
	}

	post := &core.StatusUpdatePost{
		Zone:      zonename,
		SubType:   subtype,
		NSRecords: nsRecords,
		DSRecords: dsRecords,
		Time:      time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := tm.DNSTransport.SendStatusUpdate(ctx, peer, post)
	if err != nil {
		lgCombiner.Error("sendDelegationStatusUpdate: failed to send", "zone", zonename, "subtype", subtype, "agent", agentID, "err", err)
	} else {
		lgCombiner.Info("sendDelegationStatusUpdate: sent", "zone", zonename, "subtype", subtype, "agent", agentID)
	}
}

// combinerApplyPublishInstruction processes a PublishInstruction from an agent.
func combinerApplyPublishInstruction(req *CombinerSyncRequest, zd *tdns.ZoneData, kdb *tdns.KeyDB) {
	if req.Publish == nil {
		return
	}
	instr := req.Publish
	zone := req.Zone
	senderID := req.SenderID

	var storedInstr *StoredPublishInstruction
	if kdb != nil {
		storedInstr, _ = GetPublishInstruction(kdb, zone, senderID)
	}

	if len(instr.Locations) == 0 {
		ReplaceCombinerDataByRRtype(zd, senderID, zone, dns.TypeKEY, nil)
		if storedInstr != nil {
			for _, ns := range storedInstr.PublishedNS {
				publishSignalKeyToProvider(zone, ns, senderID, nil)
			}
		}
		if kdb != nil {
			DeletePublishInstruction(kdb, zone, senderID)
		}
		lgCombiner.Info("publish instruction retracted", "zone", zone, "sender", senderID)
		return
	}

	locSet := make(map[string]bool)
	for _, loc := range instr.Locations {
		locSet[loc] = true
	}

	if locSet["at-apex"] {
		var parsedRRs []dns.RR
		for _, rrStr := range instr.KEYRRs {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				lgCombiner.Warn("publish instruction: bad KEY RR", "zone", zone, "rr", rrStr, "err", err)
				continue
			}
			parsedRRs = append(parsedRRs, rr)
		}
		ReplaceCombinerDataByRRtype(zd, senderID, zone, dns.TypeKEY, parsedRRs)
	} else if storedInstr != nil && containsString(storedInstr.Locations, "at-apex") {
		ReplaceCombinerDataByRRtype(zd, senderID, zone, dns.TypeKEY, nil)
	}

	var publishedNS []string
	if locSet["at-ns"] {
		currentNS := getAgentNSTargets(zd, senderID, zone)
		var prevPublished []string
		if storedInstr != nil {
			prevPublished = storedInstr.PublishedNS
		}
		curSet := stringSet(currentNS)

		for _, ns := range currentNS {
			publishSignalKeyToProvider(zone, ns, senderID, instr.KEYRRs)
		}
		for _, ns := range prevPublished {
			if !curSet[ns] {
				publishSignalKeyToProvider(zone, ns, senderID, nil)
			}
		}
		publishedNS = currentNS
	} else if storedInstr != nil && containsString(storedInstr.Locations, "at-ns") {
		for _, ns := range storedInstr.PublishedNS {
			publishSignalKeyToProvider(zone, ns, senderID, nil)
		}
	}

	if kdb != nil {
		if err := SavePublishInstruction(kdb, zone, senderID, instr, publishedNS); err != nil {
			lgCombiner.Error("failed to save publish instruction", "zone", zone, "sender", senderID, "err", err)
		}
	}

	lgCombiner.Info("publish instruction applied", "zone", zone, "sender", senderID, "locations", instr.Locations, "publishedNS", publishedNS)
}

// combinerResyncSignalKeys is called when NS records change for an agent.
func combinerResyncSignalKeys(senderID, zone string, zd *tdns.ZoneData, kdb *tdns.KeyDB) {
	if kdb == nil {
		return
	}
	storedInstr, err := GetPublishInstruction(kdb, zone, senderID)
	if err != nil || storedInstr == nil {
		return
	}
	if !containsString(storedInstr.Locations, "at-ns") {
		return
	}

	currentNS := getAgentNSTargets(zd, senderID, zone)
	prevSet := stringSet(storedInstr.PublishedNS)
	curSet := stringSet(currentNS)

	changed := false
	for _, ns := range currentNS {
		if !prevSet[ns] {
			publishSignalKeyToProvider(zone, ns, senderID, storedInstr.KEYRRs)
			changed = true
		}
	}
	for _, ns := range storedInstr.PublishedNS {
		if !curSet[ns] {
			publishSignalKeyToProvider(zone, ns, senderID, nil)
			changed = true
		}
	}

	if changed {
		instr := storedInstr.ToPublishInstruction()
		if err := SavePublishInstruction(kdb, zone, senderID, instr, currentNS); err != nil {
			lgCombiner.Error("failed to update published NS after resync", "zone", zone, "sender", senderID, "err", err)
		}
		lgCombiner.Info("signal keys resynced after NS change", "zone", zone, "sender", senderID, "publishedNS", currentNS)
	}
}

// publishSignalKeyToProvider directly applies a _signal KEY record to the
// provider zone that contains the NS target.
func publishSignalKeyToProvider(childZone, nsTarget, senderID string, keyRRs []string) {
	ownerName := tdns.Sig0KeyOwnerName(childZone, nsTarget)

	providerZone := findProviderZoneForOwner(ownerName)
	if providerZone == "" {
		lgCombiner.Debug("no provider zone found for _signal owner", "owner", ownerName, "childZone", childZone, "ns", nsTarget)
		return
	}
	zd, ok := tdns.Zones.Get(providerZone)
	if !ok {
		lgCombiner.Warn("provider zone not loaded", "zone", providerZone, "owner", ownerName)
		return
	}

	var parsedRRs []dns.RR
	for _, rrStr := range keyRRs {
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			lgCombiner.Warn("publishSignalKeyToProvider: bad KEY RR", "rr", rrStr, "err", err)
			continue
		}
		rr.Header().Name = ownerName
		parsedRRs = append(parsedRRs, rr)
	}

	_, _, changed, err := ReplaceCombinerDataByRRtype(zd, senderID, ownerName, dns.TypeKEY, parsedRRs)
	if err != nil {
		lgCombiner.Error("failed to apply _signal KEY to provider zone", "zone", providerZone, "owner", ownerName, "err", err)
		return
	}
	if changed {
		if bumperResp, err := zd.BumpSerialOnly(); err != nil {
			lgCombiner.Error("BumpSerialOnly failed for provider zone", "zone", providerZone, "err", err)
		} else {
			lgCombiner.Debug("provider zone serial bumped", "zone", providerZone, "old", bumperResp.OldSerial, "new", bumperResp.NewSerial)
		}
	}
	lgCombiner.Info("_signal KEY applied to provider zone", "zone", providerZone, "owner", ownerName, "keys", len(parsedRRs), "changed", changed)
}

// findProviderZoneForOwner finds the most specific configured provider zone
// that contains the given owner name.
func findProviderZoneForOwner(ownerName string) string {
	zd, _ := tdns.FindZone(dns.Fqdn(ownerName))
	if zd == nil {
		return ""
	}
	if GetProviderZoneRRtypes(zd.ZoneName) == nil {
		return ""
	}
	return zd.ZoneName
}

// getAgentNSTargets returns the NS target names from an agent's contributions for a zone.
func getAgentNSTargets(zd *tdns.ZoneData, senderID, zone string) []string {
	agentData, ok := zd.MP.AgentContributions[senderID]
	if !ok {
		return nil
	}
	nsRRset, ok := agentData[zone][dns.TypeNS]
	if !ok {
		return nil
	}
	var targets []string
	for _, rr := range nsRRset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			targets = append(targets, dns.Fqdn(ns.Ns))
		}
	}
	return targets
}

// --- Startup re-apply of stored publish instructions for provider zones ---

// signalKeyEntry represents a _signal KEY that should be published in a provider zone.
type signalKeyEntry struct {
	OwnerName string
	SenderID  string
	KEYRRs    []string
}

// pendingSignalKeyMap holds signal keys grouped by provider zone.
type pendingSignalKeyMap struct {
	mu      sync.Mutex
	built   bool
	entries map[string][]signalKeyEntry
}

var pendingSignalKeys = &pendingSignalKeyMap{}

// buildPendingSignalKeys is called by the first provider zone's OnFirstLoad.
func buildPendingSignalKeys(kdb *tdns.KeyDB) {
	if kdb == nil {
		lgCombiner.Warn("buildPendingSignalKeys: kdb is nil, skipping")
		pendingSignalKeys.entries = make(map[string][]signalKeyEntry)
		return
	}
	allInstr, err := LoadAllPublishInstructions(kdb)
	if err != nil {
		lgCombiner.Error("failed to load publish instructions for startup re-apply", "err", err)
		pendingSignalKeys.entries = make(map[string][]signalKeyEntry)
		return
	}

	entries := make(map[string][]signalKeyEntry)
	for zone, senders := range allInstr {
		for senderID, stored := range senders {
			if !containsString(stored.Locations, "at-ns") || len(stored.KEYRRs) == 0 {
				continue
			}
			for _, ns := range stored.PublishedNS {
				ownerName := tdns.Sig0KeyOwnerName(zone, ns)
				providerZone := findProviderZoneForOwner(ownerName)
				if providerZone == "" {
					lgCombiner.Debug("startup re-apply: no provider zone for NS target", "ns", ns, "childZone", zone)
					continue
				}
				entries[providerZone] = append(entries[providerZone], signalKeyEntry{
					OwnerName: ownerName,
					SenderID:  senderID,
					KEYRRs:    stored.KEYRRs,
				})
			}
		}
	}
	pendingSignalKeys.entries = entries
	lgCombiner.Info("built pending signal key map", "providerZones", len(entries))
}

// ApplyPendingSignalKeys is called by each provider zone's OnFirstLoad.
func ApplyPendingSignalKeys(zd *tdns.ZoneData, kdb *tdns.KeyDB) {
	pendingSignalKeys.mu.Lock()
	if !pendingSignalKeys.built {
		buildPendingSignalKeys(kdb)
		pendingSignalKeys.built = true
	}
	myEntries := pendingSignalKeys.entries[zd.ZoneName]
	delete(pendingSignalKeys.entries, zd.ZoneName)
	pendingSignalKeys.mu.Unlock()

	if len(myEntries) == 0 {
		return
	}

	for _, entry := range myEntries {
		var parsedRRs []dns.RR
		for _, rrStr := range entry.KEYRRs {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				continue
			}
			rr.Header().Name = entry.OwnerName
			parsedRRs = append(parsedRRs, rr)
		}
		_, _, changed, err := ReplaceCombinerDataByRRtype(zd, entry.SenderID, entry.OwnerName, dns.TypeKEY, parsedRRs)
		if err != nil {
			lgCombiner.Error("startup re-apply: failed to apply _signal KEY", "zone", zd.ZoneName, "owner", entry.OwnerName, "err", err)
			continue
		}
		if changed {
			lgCombiner.Info("startup re-apply: _signal KEY applied", "zone", zd.ZoneName, "owner", entry.OwnerName, "sender", entry.SenderID)
		}
	}
}

// findExistingContribution checks whether any sender OTHER than excludeSender
// already has a contribution for the given zone/rrtype.
func findExistingContribution(zd *tdns.ZoneData, owner string, rrtype uint16, excludeSender string) (string, []dns.RR) {
	for senderID, zones := range zd.MP.AgentContributions {
		if senderID == excludeSender {
			continue
		}
		if owners, ok := zones[owner]; ok {
			if rrset, ok := owners[rrtype]; ok && len(rrset.RRs) > 0 {
				return senderID, rrset.RRs
			}
		}
	}
	return "", nil
}

// sameRRData returns true if two RR slices contain the same records (order-independent).
func sameRRData(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	for _, ra := range a {
		found := false
		for _, rb := range b {
			if dns.IsDuplicate(ra, rb) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func stringSet(slice []string) map[string]bool {
	m := make(map[string]bool, len(slice))
	for _, s := range slice {
		m[s] = true
	}
	return m
}

// combinerProcessOperations handles explicit Operations (add, delete, replace)
// at the combiner level.
func combinerProcessOperations(req *CombinerSyncRequest, zd *tdns.ZoneData, zonename string, protectedNamespaces []string, localAgents map[string]bool) *CombinerSyncResponse {
	resp := &CombinerSyncResponse{
		DistributionID: req.DistributionID,
		Zone:           req.Zone,
		Timestamp:      time.Now(),
	}

	var appliedRecords []string
	var removedRecords []string
	var rejectedItems []RejectedItem
	dataChanged := false

	isProvider := req.ZoneClass == "provider"
	allowedRRtypes := AllowedLocalRRtypes
	if isProvider {
		if pzt := GetProviderZoneRRtypes(req.Zone); pzt != nil {
			allowedRRtypes = pzt
		} else {
			resp.Status = "error"
			resp.Message = fmt.Sprintf("zone %q is not configured as a provider zone", req.Zone)
			return resp
		}
	}

	for _, op := range req.Operations {
		rrtype, ok := dns.StringToType[op.RRtype]
		if !ok {
			rejectedItems = append(rejectedItems, RejectedItem{
				Record: fmt.Sprintf("(operation %s on %s)", op.Operation, op.RRtype),
				Reason: fmt.Sprintf("unknown RR type: %s", op.RRtype),
			})
			continue
		}
		if !allowedRRtypes[rrtype] {
			rejectedItems = append(rejectedItems, RejectedItem{
				Record: fmt.Sprintf("(operation %s on %s)", op.Operation, op.RRtype),
				Reason: fmt.Sprintf("RRtype %s not allowed for combiner updates", op.RRtype),
			})
			continue
		}

		// DNSKEY policy: only signers may contribute DNSKEYs
		if rrtype == dns.TypeDNSKEY && !isProvider {
			reject, reason := checkDNSKEYPolicy(zd, req.SenderID)
			if reject {
				for _, rec := range op.Records {
					rejectedItems = append(rejectedItems, RejectedItem{
						Record: rec,
						Reason: reason,
					})
				}
				continue
			}
		}

		var parsedRRs []dns.RR
		parseOk := true
		for _, rrStr := range op.Records {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: fmt.Sprintf("parse error: %v", err),
				})
				parseOk = false
				continue
			}
			if isProvider {
				lowerOwner := strings.ToLower(rr.Header().Name)
				lowerZone := strings.ToLower(zonename)
				if lowerOwner != lowerZone && !strings.HasSuffix(lowerOwner, "."+lowerZone) {
					rejectedItems = append(rejectedItems, RejectedItem{
						Record: rrStr,
						Reason: fmt.Sprintf("owner %q is not within zone %q", rr.Header().Name, zonename),
					})
					parseOk = false
					continue
				}
			} else if !strings.EqualFold(rr.Header().Name, zonename) {
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: fmt.Sprintf("owner %q is not at zone apex %q", rr.Header().Name, zonename),
				})
				parseOk = false
				continue
			}
			if rr.Header().Ttl > 604800 {
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: fmt.Sprintf("TTL %d exceeds maximum (604800)", rr.Header().Ttl),
				})
				parseOk = false
				continue
			}
			if reason := checkContentPolicy(rr, protectedNamespaces); reason != "" {
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: rrStr,
					Reason: reason,
				})
				parseOk = false
				continue
			}
			warnNSTargetUnresolvable(rr, zd)
			parsedRRs = append(parsedRRs, rr)
		}

		switch op.Operation {
		case "replace":
			if !parseOk && len(parsedRRs) == 0 && len(op.Records) > 0 {
				continue
			}

			if (rrtype == dns.TypeKEY || rrtype == dns.TypeCDS) && len(parsedRRs) > 0 {
				senderIsLocal := localAgents[req.SenderID]
				if existingSender, existingRRs := findExistingContribution(zd, zonename, rrtype, req.SenderID); existingSender != "" {
					existingIsLocal := localAgents[existingSender]
					if sameRRData(existingRRs, parsedRRs) {
						if existingIsLocal && !senderIsLocal {
							lgCombiner.Debug("dedup: local contribution exists, remote is no-op",
								"rrtype", op.RRtype, "zone", zonename, "local", existingSender, "remote", req.SenderID)
							for _, rr := range parsedRRs {
								appliedRecords = append(appliedRecords, rr.String())
							}
							continue
						}
						if !existingIsLocal && senderIsLocal {
							lgCombiner.Info("dedup: re-attributing contribution from remote to local",
								"rrtype", op.RRtype, "zone", zonename, "from", existingSender, "to", req.SenderID)
							ReplaceCombinerDataByRRtype(zd, existingSender, zonename, rrtype, nil)
						}
					}
				}
			}

			applied, removed, changed, err := ReplaceCombinerDataByRRtype(zd, req.SenderID, zonename, rrtype, parsedRRs)
			if err != nil {
				lgCombiner.Error("REPLACE operation failed", "err", err)
				rejectedItems = append(rejectedItems, RejectedItem{
					Record: fmt.Sprintf("(replace %s)", op.RRtype),
					Reason: fmt.Sprintf("replace failed: %v", err),
				})
				continue
			}
			if len(applied) > 0 {
				appliedRecords = append(appliedRecords, applied...)
			} else if len(parsedRRs) > 0 {
				if stored, ok := zd.MP.AgentContributions[req.SenderID][zonename][rrtype]; ok {
					for _, rr := range stored.RRs {
						appliedRecords = append(appliedRecords, rr.String())
					}
				}
			}
			removedRecords = append(removedRecords, removed...)
			if changed {
				dataChanged = true
			}

		case "add":
			addRecords := make(map[string][]string)
			for _, rr := range parsedRRs {
				addRecords[zonename] = append(addRecords[zonename], rr.String())
			}
			if len(addRecords) > 0 {
				addChanged, err := AddCombinerDataNG(zd, req.SenderID, addRecords)
				if err != nil {
					lgCombiner.Error("ADD operation failed", "err", err)
					rejectedItems = append(rejectedItems, RejectedItem{
						Record: fmt.Sprintf("(add %s)", op.RRtype),
						Reason: fmt.Sprintf("add failed: %v", err),
					})
					continue
				}
				if addChanged {
					dataChanged = true
				}
				for _, rrs := range addRecords {
					appliedRecords = append(appliedRecords, rrs...)
				}
			}

		case "delete":
			delRecords := make(map[string][]string)
			for _, rr := range parsedRRs {
				delRecords[zonename] = append(delRecords[zonename], rr.String())
			}
			if len(delRecords) > 0 {
				removed, err := RemoveCombinerDataNG(zd, req.SenderID, delRecords)
				if err != nil {
					lgCombiner.Error("DELETE operation failed", "err", err)
					rejectedItems = append(rejectedItems, RejectedItem{
						Record: fmt.Sprintf("(delete %s)", op.RRtype),
						Reason: fmt.Sprintf("delete failed: %v", err),
					})
					continue
				}
				if len(removed) > 0 {
					dataChanged = true
				}
				removedRecords = append(removedRecords, removed...)
			}

		default:
			rejectedItems = append(rejectedItems, RejectedItem{
				Record: fmt.Sprintf("(operation %s on %s)", op.Operation, op.RRtype),
				Reason: fmt.Sprintf("unknown operation: %s", op.Operation),
			})
		}
	}

	resp.AppliedRecords = appliedRecords
	resp.RemovedRecords = removedRecords
	resp.RejectedItems = rejectedItems

	totalActions := len(appliedRecords) + len(removedRecords)
	if len(rejectedItems) == 0 {
		resp.Status = "ok"
		resp.Message = fmt.Sprintf("applied %d added %d removed for zone %q (via operations)",
			len(appliedRecords), len(removedRecords), req.Zone)
	} else if totalActions > 0 {
		resp.Status = "partial"
		resp.Message = fmt.Sprintf("applied %d added %d removed %d rejected for zone %q (via operations)",
			len(appliedRecords), len(removedRecords), len(rejectedItems), req.Zone)
	} else {
		resp.Status = "error"
		resp.Message = fmt.Sprintf("all operations rejected for zone %q", req.Zone)
	}

	opTypes := make(map[string]int)
	for _, op := range req.Operations {
		opTypes[strings.ToUpper(op.Operation)]++
	}
	var opSummary []string
	for opType, count := range opTypes {
		opSummary = append(opSummary, fmt.Sprintf("%s:%d", opType, count))
	}
	lgCombiner.Info("operations processed", "ops", strings.Join(opSummary, ","), "status", resp.Status, "message", resp.Message)
	for _, ri := range rejectedItems {
		lgCombiner.Warn("operation rejected", "zone", req.Zone, "sender", req.SenderID, "record", ri.Record, "reason", ri.Reason)
	}

	resp.DataChanged = dataChanged
	if dataChanged {
		bumperResp, err := zd.BumpSerialOnly()
		if err != nil {
			lgCombiner.Error("BumpSerialOnly failed", "zone", req.Zone, "err", err)
		} else {
			lgCombiner.Info("serial bumped", "zone", req.Zone, "old", bumperResp.OldSerial, "new", bumperResp.NewSerial)
		}
	}

	return resp
}

// isNoOpUpdate checks whether an incoming update would cause any actual change.
func isNoOpUpdate(zd *tdns.ZoneData, senderID string, records map[string][]string) bool {
	for owner, rrStrings := range records {
		for _, rrStr := range rrStrings {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				return false
			}

			rrtype := rr.Header().Rrtype
			switch rr.Header().Class {
			case dns.ClassINET:
				if !rrExistsInZone(zd, owner, rrtype, rr) {
					lgCombiner.Info("legacy isNoOpUpdate: RR not found, update is NOT a no-op",
						"sender", senderID, "zone", zd.ZoneName, "rr", rr.String())
					return false
				}
				lgCombiner.Debug("legacy isNoOpUpdate: RR already present (no-op)",
					"sender", senderID, "zone", zd.ZoneName, "rr", rr.String())

			case dns.ClassNONE:
				delRR := dns.Copy(rr)
				delRR.Header().Class = dns.ClassINET
				if rrExistsInZone(zd, owner, rrtype, delRR) {
					lgCombiner.Info("legacy isNoOpUpdate: RR exists, delete is NOT a no-op",
						"sender", senderID, "zone", zd.ZoneName, "rr", rr.String())
					return false
				}
				lgCombiner.Debug("legacy isNoOpUpdate: RR already absent (delete is no-op)",
					"sender", senderID, "zone", zd.ZoneName, "rr", rr.String())

			case dns.ClassANY:
				if rrTypeExistsInZone(zd, owner, rrtype) {
					lgCombiner.Info("legacy isNoOpUpdate: RRtype has records, bulk delete is NOT a no-op",
						"sender", senderID, "zone", zd.ZoneName, "owner", owner, "rrtype", dns.TypeToString[rrtype])
					return false
				}
				lgCombiner.Debug("legacy isNoOpUpdate: RRtype empty (bulk delete is no-op)",
					"sender", senderID, "zone", zd.ZoneName, "owner", owner, "rrtype", dns.TypeToString[rrtype])

			default:
				return false
			}
		}
	}

	lgCombiner.Info("isNoOpUpdate: all records already present, update is a no-op",
		"sender", senderID, "zone", zd.ZoneName)
	return true
}

// IsNoOpOperations checks whether explicit Operations would cause any actual change.
func IsNoOpOperations(zd *tdns.ZoneData, senderID string, ops []core.RROperation) bool {
	zonename := zd.ZoneName
	for _, op := range ops {
		rrtype, ok := dns.StringToType[op.RRtype]
		if !ok {
			return false
		}

		switch op.Operation {
		case "replace":
			var existingRRs []dns.RR
			if zd.MP.AgentContributions != nil {
				if agentData, ok := zd.MP.AgentContributions[senderID]; ok {
					if ownerMap, ok := agentData[zonename]; ok {
						if rrset, ok := ownerMap[rrtype]; ok {
							existingRRs = rrset.RRs
						}
					}
				}
			}

			var newRRs []dns.RR
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					return false
				}
				newRRs = append(newRRs, rr)
			}

			if len(existingRRs) == 0 && len(newRRs) == 0 {
				continue
			}
			if len(existingRRs) != len(newRRs) {
				return false
			}
			for _, oldRR := range existingRRs {
				found := false
				for _, newRR := range newRRs {
					if dns.IsDuplicate(oldRR, newRR) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}

		case "add":
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					return false
				}
				if !rrExistsInZone(zd, zonename, rrtype, rr) {
					return false
				}
			}

		case "delete":
			for _, rrStr := range op.Records {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					return false
				}
				delRR := dns.Copy(rr)
				delRR.Header().Class = dns.ClassINET
				if rrExistsInZone(zd, zonename, rrtype, delRR) {
					return false
				}
			}

		default:
			return false
		}
	}

	lgCombiner.Info("isNoOpOperations: all operations are no-ops",
		"sender", senderID, "zone", zd.ZoneName)
	return true
}

// rrExistsInZone checks whether the given RR exists in either the live zone data
// or CombinerData.
func rrExistsInZone(zd *tdns.ZoneData, owner string, rrtype uint16, rr dns.RR) bool {
	rrStr := rr.String()
	rrtypeStr := dns.TypeToString[rrtype]

	existing, err := zd.GetRRset(owner, rrtype)
	if err != nil {
		lgCombiner.Info("rrExistsInZone: GetRRset error", "owner", owner, "rrtype", rrtypeStr, "err", err)
	} else if existing == nil {
		lgCombiner.Info("rrExistsInZone: no RRset in live zone", "owner", owner, "rrtype", rrtypeStr, "zoneStore", tdns.ZoneStoreToString[zd.ZoneStore])
	} else {
		for _, existingRR := range existing.RRs {
			if dns.IsDuplicate(rr, existingRR) {
				lgCombiner.Info("rrExistsInZone: found in live zone", "owner", owner, "rrtype", rrtypeStr, "rr", rrStr)
				return true
			}
		}
		var existingStrs []string
		for _, e := range existing.RRs {
			existingStrs = append(existingStrs, e.String())
		}
		lgCombiner.Info("rrExistsInZone: RRset exists in live zone but RR not found",
			"owner", owner, "rrtype", rrtypeStr, "lookingFor", rrStr, "existing", existingStrs)
	}

	if zd.MP.CombinerData == nil {
		lgCombiner.Info("rrExistsInZone: CombinerData is nil", "zone", zd.ZoneName)
	} else {
		ownerData, ownerExists := zd.MP.CombinerData.Get(owner)
		if !ownerExists {
			var cdOwners []string
			for item := range zd.MP.CombinerData.IterBuffered() {
				cdOwners = append(cdOwners, item.Key)
			}
			lgCombiner.Info("rrExistsInZone: owner not in CombinerData",
				"owner", owner, "cdOwners", cdOwners)
		} else {
			cdRRset, rrtypeExists := ownerData.RRtypes.Get(rrtype)
			if !rrtypeExists || len(cdRRset.RRs) == 0 {
				var cdRRtypes []string
				for _, rt := range ownerData.RRtypes.Keys() {
					cdRRtypes = append(cdRRtypes, dns.TypeToString[rt])
				}
				lgCombiner.Info("rrExistsInZone: rrtype not in CombinerData for owner",
					"owner", owner, "rrtype", rrtypeStr, "cdRRtypes", cdRRtypes)
			} else {
				for _, existingRR := range cdRRset.RRs {
					if dns.IsDuplicate(rr, existingRR) {
						lgCombiner.Info("rrExistsInZone: found in CombinerData (not in live zone)",
							"owner", owner, "rrtype", rrtypeStr, "rr", rrStr)
						return true
					}
				}
				var existingStrs []string
				for _, e := range cdRRset.RRs {
					existingStrs = append(existingStrs, e.String())
				}
				lgCombiner.Info("rrExistsInZone: RRset exists in CombinerData but RR not found",
					"owner", owner, "rrtype", rrtypeStr, "lookingFor", rrStr, "existing", existingStrs)
			}
		}
	}

	return false
}

// rrTypeExistsInZone checks whether the given owner/rrtype has any records.
func rrTypeExistsInZone(zd *tdns.ZoneData, owner string, rrtype uint16) bool {
	existing, err := zd.GetRRset(owner, rrtype)
	if err == nil && existing != nil && len(existing.RRs) > 0 {
		return true
	}
	if zd.MP.CombinerData != nil {
		if ownerData, ok := zd.MP.CombinerData.Get(owner); ok {
			if cdRRset, ok := ownerData.RRtypes.Get(rrtype); ok && len(cdRRset.RRs) > 0 {
				return true
			}
		}
	}
	return false
}

// NewCombinerSyncHandler creates a transport.MessageHandlerFunc for combiner UPDATE processing.
func NewCombinerSyncHandler() transport.MessageHandlerFunc {
	return func(ctx *transport.MessageContext) error {
		lgCombiner.Debug("received update, sending pending ACK", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

		ack := struct {
			Type           string `json:"type"`
			Status         string `json:"status"`
			DistributionID string `json:"distribution_id"`
			Message        string `json:"message"`
			Timestamp      int64  `json:"timestamp"`
		}{
			Type:           "confirm",
			Status:         "pending",
			DistributionID: ctx.DistributionID,
			Message:        "update received, processing asynchronously",
			Timestamp:      time.Now().Unix(),
		}
		ackPayload, err := json.Marshal(ack)
		if err != nil {
			return fmt.Errorf("failed to marshal pending ack: %w", err)
		}
		ctx.Data["response"] = ackPayload

		ctx.Data["message_type"] = "update"

		return nil
	}
}

// --- Registration functions ---

// RegisterCombinerChunkHandler registers the combiner's CHUNK handler.
func RegisterCombinerChunkHandler(localID string, secureWrapper *transport.SecurePayloadWrapper) (*tdns.CombinerState, error) {
	state := &tdns.CombinerState{
		ErrorJournal: tdns.NewErrorJournal(1000, 24*time.Hour),
	}

	handler := &transport.ChunkNotifyHandler{
		LocalID:       localID,
		Router:        nil,
		SecureWrapper: secureWrapper,
		IncomingChan:  make(chan *transport.IncomingMessage, 100),
	}

	if secureWrapper != nil && secureWrapper.IsEnabled() {
		lgCombiner.Info("registering CHUNK handler with crypto enabled", "localID", localID)
	} else {
		lgCombiner.Info("registering CHUNK handler", "localID", localID)
	}

	handler.FetchChunkQuery = fetchChunkPayloadViaQuery

	err := tdns.RegisterNotifyHandler(core.TypeCHUNK, func(ctx context.Context, req *tdns.DnsNotifyRequest) error {
		return handler.RouteViaRouter(ctx, req.Qname, req.Msg, req.ResponseWriter)
	})
	if err != nil {
		return nil, err
	}

	tdns.CombinerStateSetChunkHandler(state, handler)

	return state, nil
}

// --- Helper functions ---

// SendToCombiner sends a sync request to the combiner and waits for a response.
func SendToCombiner(state *tdns.CombinerState, req *CombinerSyncRequest) *CombinerSyncResponse {
	if state == nil {
		lgCombiner.Error("state is nil, cannot send update")
		return &CombinerSyncResponse{
			DistributionID: req.DistributionID,
			Zone:           req.Zone,
			Status:         "error",
			Message:        "combiner state not initialized",
			Timestamp:      time.Now(),
		}
	}

	// Convert local CombinerSyncRequest to tdns.CombinerSyncRequest for state.ProcessUpdate
	tdnsReq := &tdns.CombinerSyncRequest{
		SenderID:       req.SenderID,
		DeliveredBy:    req.DeliveredBy,
		Zone:           req.Zone,
		ZoneClass:      req.ZoneClass,
		SyncType:       req.SyncType,
		Records:        req.Records,
		Operations:     req.Operations,
		Publish:        req.Publish,
		Serial:         req.Serial,
		DistributionID: req.DistributionID,
		Timestamp:      req.Timestamp,
	}

	tdnsResp := state.ProcessUpdate(tdnsReq, nil, nil, nil)

	// Convert tdns.CombinerSyncResponse back to local type
	resp := &CombinerSyncResponse{
		DistributionID: tdnsResp.DistributionID,
		Zone:           tdnsResp.Zone,
		Nonce:          tdnsResp.Nonce,
		Status:         tdnsResp.Status,
		Message:        tdnsResp.Message,
		AppliedRecords: tdnsResp.AppliedRecords,
		RemovedRecords: tdnsResp.RemovedRecords,
		Timestamp:      tdnsResp.Timestamp,
		DataChanged:    tdnsResp.DataChanged,
	}
	for _, ri := range tdnsResp.RejectedItems {
		resp.RejectedItems = append(resp.RejectedItems, RejectedItem{Record: ri.Record, Reason: ri.Reason})
	}
	return resp
}

// ConvertZoneUpdateToSyncRequest converts a ZoneUpdate to a CombinerSyncRequest.
func ConvertZoneUpdateToSyncRequest(update *tdns.ZoneUpdate, senderID string, distributionID string) *CombinerSyncRequest {
	records := make(map[string][]string)

	for _, rr := range update.RRs {
		owner := rr.Header().Name
		records[owner] = append(records[owner], rr.String())
	}

	for _, rrset := range update.RRsets {
		for _, rr := range rrset.RRs {
			owner := rr.Header().Name
			records[owner] = append(records[owner], rr.String())
		}
	}

	syncType := determineSyncType(update)

	req := &CombinerSyncRequest{
		SenderID:       senderID,
		Zone:           string(update.Zone),
		ZoneClass:      update.ZoneClass,
		SyncType:       syncType,
		Records:        records,
		DistributionID: distributionID,
		Timestamp:      time.Now(),
	}
	if len(update.Operations) > 0 {
		req.Operations = update.Operations
	}
	if update.Publish != nil {
		req.Publish = update.Publish
	}
	return req
}

// determineSyncType examines the update and returns an appropriate sync type string.
func determineSyncType(update *tdns.ZoneUpdate) string {
	types := make(map[uint16]bool)

	for _, rr := range update.RRs {
		types[rr.Header().Rrtype] = true
	}
	for rrtype := range update.RRsets {
		types[rrtype] = true
	}

	if len(types) == 1 {
		for rrtype := range types {
			return dns.TypeToString[rrtype]
		}
	}
	if len(types) > 1 {
		return "MIXED"
	}
	return "UNKNOWN"
}

// --- Policy check functions ---

// checkDNSKEYPolicy checks whether a sender is allowed to contribute DNSKEYs.
// Returns (reject bool, reason string). Rejects if:
// - the zone has no HSYNCPARAM (no signer information)
// - the zone has no signers listed
// - the sender is not listed as a signer
func checkDNSKEYPolicy(zd *tdns.ZoneData, senderID string) (bool, string) {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return true, "DNSKEY rejected: cannot inspect zone apex"
	}

	// Get HSYNCPARAM to check signers
	hpRRset, hpExists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !hpExists || len(hpRRset.RRs) == 0 {
		return true, "DNSKEY rejected: no HSYNCPARAM in zone (cannot determine signers)"
	}
	prr, ok := hpRRset.RRs[0].(*dns.PrivateRR)
	if !ok {
		return true, "DNSKEY rejected: HSYNCPARAM parse error"
	}
	hp, ok := prr.Data.(*core.HSYNCPARAM)
	if !ok {
		return true, "DNSKEY rejected: HSYNCPARAM type error"
	}
	signers := hp.GetSigners()
	if len(signers) == 0 {
		return true, "DNSKEY not allowed in unsigned zone (no signers in HSYNCPARAM)"
	}

	// Resolve sender FQDN to HSYNC3 label
	h3RRset, h3exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !h3exists || len(h3RRset.RRs) == 0 {
		return true, "DNSKEY rejected: no HSYNC3 records (cannot resolve sender to label)"
	}
	senderLabel := ""
	for _, rr := range h3RRset.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if h3, ok := prr.Data.(*core.HSYNC3); ok {
				if h3.Identity == senderID {
					senderLabel = h3.Label
					break
				}
			}
		}
	}
	if senderLabel == "" {
		return true, fmt.Sprintf("DNSKEY rejected: sender %s not found in zone HSYNC3 records", senderID)
	}

	// Normalize: HSYNC3.Label may have trailing dot, HSYNCPARAM signers do not
	senderLabel = strings.TrimSuffix(senderLabel, ".")

	// Check if sender's label is in the signers list
	if !hp.IsSignerLabel(senderLabel) {
		return true, fmt.Sprintf("DNSKEY rejected: sender %s (label %q) is not a signer (signers: %v)", senderID, senderLabel, signers)
	}

	return false, ""
}

// checkContentPolicy applies content-based policy checks to a parsed RR.
func checkContentPolicy(rr dns.RR, protectedNamespaces []string) string {
	if rr.Header().Rrtype == dns.TypeNS && rr.Header().Class == dns.ClassINET {
		return checkNSNamespacePolicy(rr, protectedNamespaces)
	}
	return ""
}

// warnNSTargetUnresolvable logs a warning if an in-bailiwick NS target has no
// address records in the combiner's zone data.
func warnNSTargetUnresolvable(rr dns.RR, zd *tdns.ZoneData) {
	nsRR, ok := rr.(*dns.NS)
	if !ok {
		return
	}
	target := nsRR.Ns
	if !strings.HasSuffix(target, "."+zd.ZoneName) && target != zd.ZoneName {
		return
	}
	owner, err := zd.GetOwner(target)
	if err != nil || owner == nil {
		lgCombiner.Warn("NS target has no address records (owner not found)", "zone", zd.ZoneName, "nsTarget", target)
		return
	}
	_, hasA := owner.RRtypes.Get(dns.TypeA)
	_, hasAAAA := owner.RRtypes.Get(dns.TypeAAAA)
	if !hasA && !hasAAAA {
		lgCombiner.Warn("NS target has no address records", "zone", zd.ZoneName, "nsTarget", target)
	}
}

// checkNSNamespacePolicy rejects NS records whose targets fall within any of
// our protected namespaces.
func checkNSNamespacePolicy(rr dns.RR, protectedNamespaces []string) string {
	if len(protectedNamespaces) == 0 {
		return ""
	}

	nsRR, ok := rr.(*dns.NS)
	if !ok {
		return ""
	}

	target := strings.ToLower(nsRR.Ns)
	for _, ns := range protectedNamespaces {
		ns = strings.ToLower(ns)
		if strings.HasSuffix(target, "."+ns) || target == ns {
			return fmt.Sprintf("NS target %s intrudes on protected namespace %s",
				nsRR.Ns, ns)
		}
	}
	return ""
}
