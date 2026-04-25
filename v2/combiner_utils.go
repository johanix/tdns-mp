/*
 *
 */

package tdnsmp

import (
	"fmt"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// combinerShouldApplyEdits returns true if this combiner is allowed to
// apply contributions to the live zone. Non-signer combiners on signed
// zones persist data but do not modify the zone.
func (zd *MPZoneData) combinerShouldApplyEdits() bool {
	if zd.MP != nil && zd.MP.MPdata != nil && zd.MP.MPdata.ZoneSigned && !zd.MP.MPdata.WeAreSigner {
		return false
	}
	return true
}

// Named presets for allowed RRtypes. Hardcoded for safety.
// "apex-combiner": manages DNSKEY, CDS, CSYNC, NS, KEY at the zone apex.
// "delegation-combiner": (future) manages NS, DS, GLUE at delegation points.
var AllowedRRtypePresets = map[string]map[uint16]bool{
	"apex-combiner": {
		dns.TypeDNSKEY: true,
		dns.TypeCDS:    true,
		dns.TypeCSYNC:  true,
		dns.TypeNS:     true,
		dns.TypeKEY:    true,
	},
	// "delegation-combiner": { dns.TypeNS: true, dns.TypeDS: true, ... },
}

// AllowedLocalRRtypes is the active preset. Default: "apex-combiner".
var AllowedLocalRRtypes = AllowedRRtypePresets["apex-combiner"]

// providerZoneRRtypes caches the parsed allowed-RRtype map for each provider zone.
// Populated during config parsing via RegisterProviderZoneRRtypes.
var providerZoneRRtypes = map[string]map[uint16]bool{}

// RegisterProviderZoneRRtypes parses a ProviderZoneConf and registers its allowed
// RRtype map for use by the combiner policy engine.
func RegisterProviderZoneRRtypes(pz tdns.ProviderZoneConf) {
	zone := dns.Fqdn(pz.Zone)
	m := make(map[uint16]bool)
	for _, s := range pz.AllowedRRtypes {
		if t, ok := dns.StringToType[s]; ok {
			m[t] = true
		}
	}
	providerZoneRRtypes[zone] = m
}

// GetProviderZoneRRtypes returns the allowed RRtype map for a provider zone,
// or nil if the zone is not configured as a provider zone.
func GetProviderZoneRRtypes(zone string) map[uint16]bool {
	return providerZoneRRtypes[dns.Fqdn(zone)]
}

// additiveRRtype returns true for RR types where agent contributions should be
// ADDED on top of the zone file baseline rather than REPLACING it.
func additiveRRtype(rrtype uint16) bool {
	return rrtype == dns.TypeNS
}

// mergeWithUpstream merges agent contributions on top of the upstream (zone file)
// baseline for additive RRtypes like NS. Deduplicates by RR string.
func (mpzd *MPZoneData) mergeWithUpstream(owner string, rrtype uint16, agentRRset core.RRset) core.RRset {
	merged := core.RRset{
		Name:   agentRRset.Name,
		RRtype: agentRRset.RRtype,
	}

	// Start with upstream baseline if available
	if mpzd.MP.UpstreamData != nil {
		if upstreamOd, ok := mpzd.MP.UpstreamData.Get(owner); ok {
			if baselineRRset, exists := upstreamOd.RRtypes.Get(rrtype); exists {
				merged.RRs = make([]dns.RR, len(baselineRRset.RRs))
				copy(merged.RRs, baselineRRset.RRs)
			}
		}
	}

	// Append agent contributions, dedup by rr.String()
	for _, rr := range agentRRset.RRs {
		rrStr := rr.String()
		alreadyPresent := false
		for _, existing := range merged.RRs {
			if existing.String() == rrStr {
				alreadyPresent = true
				break
			}
		}
		if !alreadyPresent {
			merged.RRs = append(merged.RRs, rr)
		}
	}

	return merged
}

// CombineWithLocalChanges applies CombinerData (merged agent contributions)
// to the live zone data. Uses per-RRtype edit policy to determine which
// RRtypes are applied. This overrides the promoted tdns method to add
// role-based filtering (the tdns version uses AllowedLocalRRtypes only).
func (mpzd *MPZoneData) CombineWithLocalChanges() (bool, error) {
	if mpzd.MP == nil {
		return false, nil
	}
	if mpzd.MP.CombinerData == nil {
		mpzd.Logger.Printf("CombineWithLocalChanges: Zone %s: No combiner data to apply", mpzd.ZoneName)
		return false, nil
	}

	if mpzd.ZoneStore != tdns.MapZone {
		return false, fmt.Errorf("CombineWithLocalChanges: zone store %s not implemented", tdns.ZoneStoreToString[mpzd.ZoneStore])
	}

	policy := mpzd.getEditPolicy()

	// Determine RRtype whitelist: provider zones use their own set.
	providerRRtypes := GetProviderZoneRRtypes(mpzd.ZoneName)
	isProvider := providerRRtypes != nil

	modified := false
	for item := range mpzd.MP.CombinerData.IterBuffered() {
		ownerName := item.Key
		newOwnerData := item.Val

		// MP zones: only apex records. Provider zones: any owner within the zone.
		if !isProvider && ownerName != mpzd.ZoneName {
			mpzd.Logger.Printf("CombineWithLocalChanges: Zone %s: LocalChanges outside apex (%s). Ignored", mpzd.ZoneName, ownerName)
			continue
		}

		existingOwnerData, exists := mpzd.Data.Get(ownerName)
		if !exists {
			existingOwnerData = OwnerData{
				Name:    ownerName,
				RRtypes: tdns.NewRRTypeStore(),
			}
		}

		for _, rrtype := range newOwnerData.RRtypes.Keys() {
			// Provider zones use their own whitelist; MP zones use edit policy.
			if isProvider {
				if !providerRRtypes[rrtype] {
					continue
				}
			} else if !policy.canApply(rrtype) {
				continue
			}

			newRRset, _ := newOwnerData.RRtypes.Get(rrtype)
			if additiveRRtype(rrtype) && ownerName == mpzd.ZoneName {
				merged := mpzd.mergeWithUpstream(ownerName, rrtype, newRRset)
				existingOwnerData.RRtypes.Set(rrtype, merged)
			} else {
				existingOwnerData.RRtypes.Set(rrtype, newRRset)
			}
			modified = true
		}

		mpzd.Data.Set(ownerName, existingOwnerData)
	}

	return modified, nil
}

// AddCombinerData adds or updates local RRsets for the zone from a specific agent.
// Contributions are stored per-agent so that updates from different agents are
// accumulated (not replaced). The merged result is then written to CombinerData.
// senderID identifies the contributing agent (use "local" for CLI-originated data).
func (mpzd *MPZoneData) AddCombinerData(senderID string, data map[string][]core.RRset) (bool, error) {
	mpzd.Lock()
	defer mpzd.Unlock()

	mpzd.EnsureMP()
	if mpzd.MP.CombinerData == nil {
		mpzd.MP.CombinerData = core.NewCmap[OwnerData]()
	}
	if mpzd.MP.AgentContributions == nil {
		mpzd.MP.AgentContributions = make(map[string]map[string]map[uint16]core.RRset)
	}

	if senderID == "" {
		senderID = "local"
	}

	// Initialize per-agent map if needed
	if mpzd.MP.AgentContributions[senderID] == nil {
		mpzd.MP.AgentContributions[senderID] = make(map[string]map[uint16]core.RRset)
	}

	// Merge this agent's contributions into existing data (accumulate, don't replace).
	// Each sync may carry only a delta, so we must add new RRs to any existing
	// contribution from the same agent rather than overwriting.
	changed := false
	for owner, rrsets := range data {
		if mpzd.MP.AgentContributions[senderID][owner] == nil {
			mpzd.MP.AgentContributions[senderID][owner] = make(map[uint16]core.RRset)
		}
		for _, rrset := range rrsets {
			if len(rrset.RRs) == 0 {
				continue
			}
			rrtype := rrset.RRs[0].Header().Rrtype
			existing, ok := mpzd.MP.AgentContributions[senderID][owner][rrtype]
			if !ok {
				// First contribution for this agent/owner/rrtype
				mpzd.MP.AgentContributions[senderID][owner][rrtype] = rrset
				changed = true
			} else {
				// Merge: add new RRs (deduplicated) into the existing contribution
				for _, rr := range rrset.RRs {
					prevLen := len(existing.RRs)
					existing.Add(rr)
					if len(existing.RRs) > prevLen {
						changed = true
					}
				}
				mpzd.MP.AgentContributions[senderID][owner][rrtype] = existing
			}
		}
	}

	if !changed {
		return false, nil
	}

	// Rebuild CombinerData by merging contributions from ALL agents
	mpzd.RebuildCombinerData()

	// Persist this agent's contributions to the snapshot table
	if mpzd.MP.PersistContributions != nil {
		if err := mpzd.MP.PersistContributions(mpzd.ZoneName, senderID, mpzd.MP.AgentContributions[senderID]); err != nil {
			mpzd.Logger.Printf("AddCombinerData: Zone %q: failed to persist contributions for %s: %v", mpzd.ZoneName, senderID, err)
			return changed, fmt.Errorf("persist contributions: %w", err)
		}
	}

	if mpzd.combinerShouldApplyEdits() {
		modified, err := mpzd.CombineWithLocalChanges()
		if err != nil {
			return changed, err
		}
		if modified {
			mpzd.Logger.Printf("AddCombinerData: Zone %q: Local changes applied immediately (from %s)", mpzd.ZoneName, senderID)
		}

		if mpzd.MP != nil && mpzd.MP.MultiProvider != nil && mpzd.InjectSignatureTXT(mpzd.MP.MultiProvider) {
			mpzd.Logger.Printf("AddCombinerData: Zone %q: Signature TXT injected", mpzd.ZoneName)
		}
	}

	return true, nil
}

// GetCombinerData retrieves all local combiner data for the zone
func (mpzd *MPZoneData) GetCombinerData() (map[string][]core.RRset, error) {
	//	zd := mpzd.ZoneData
	if mpzd.MP == nil || mpzd.MP.CombinerData == nil {
		return nil, fmt.Errorf("no local data exists for zone %s", mpzd.ZoneName)
	}

	result := make(map[string][]core.RRset)

	// Iterate over all owners in CombinerData
	for item := range mpzd.MP.CombinerData.IterBuffered() {
		owner := item.Key
		ownerData := item.Val

		// Get all RRsets for this owner
		var rrsets []core.RRset
		for _, rrtype := range ownerData.RRtypes.Keys() {
			if rrset, ok := ownerData.RRtypes.Get(rrtype); ok {
				rrsets = append(rrsets, rrset)
			}
		}

		if len(rrsets) > 0 {
			result[owner] = rrsets
		}
	}

	return result, nil
}

// AddCombinerDataNG adds or updates local RRsets for the zone from a specific agent.
// The input map keys are owner names and values are slices of RR strings.
// senderID identifies the contributing agent (use "" for CLI-originated data).
func (mpzd *MPZoneData) AddCombinerDataNG(senderID string, data map[string][]string) (bool, error) {
	// Convert string RRs to dns.RR objects and group them into RRsets
	rrsetData := make(map[string][]core.RRset)
	for owner, rrStrings := range data {
		var rrs []dns.RR
		for _, rrString := range rrStrings {
			rr, err := dns.NewRR(rrString)
			if err != nil {
				return false, fmt.Errorf("error parsing RR string %q: %v", rrString, err)
			}
			rrs = append(rrs, rr)
		}

		// Group RRs by type into RRsets
		rrsByType := make(map[uint16][]dns.RR)
		for _, rr := range rrs {
			rrtype := rr.Header().Rrtype
			rrsByType[rrtype] = append(rrsByType[rrtype], rr)
		}

		// Create RRsets
		var rrsets []core.RRset
		for rrtype, typeRRs := range rrsByType {
			rrsets = append(rrsets, core.RRset{
				Name:   owner,
				RRtype: rrtype,
				RRs:    typeRRs,
			})
		}
		rrsetData[owner] = rrsets
	}

	// Use the existing AddCombinerData method to store the data
	return mpzd.AddCombinerData(senderID, rrsetData)
}

// GetCombinerDataNG returns the combiner data in string format suitable for JSON marshaling
func (mpzd *MPZoneData) GetCombinerDataNG() map[string][]RRsetString {
	// zd := mpzd.ZoneData
	responseData := make(map[string][]RRsetString)

	if mpzd.MP == nil || mpzd.MP.CombinerData == nil {
		return responseData
	}

	for owner, ownerData := range mpzd.MP.CombinerData.Items() {
		var rrsets []RRsetString
		if ownerData.RRtypes != nil {
			for _, rrtype := range ownerData.RRtypes.Keys() {
				rrset, ok := ownerData.RRtypes.Get(rrtype)
				if !ok {
					continue
				}

				// Convert RRs to strings
				rrStrings := make([]string, len(rrset.RRs))
				for i, rr := range rrset.RRs {
					rrStrings[i] = rr.String()
				}

				// Convert RRSIGs to strings if present
				var rrsigStrings []string
				if len(rrset.RRSIGs) > 0 {
					rrsigStrings = make([]string, len(rrset.RRSIGs))
					for i, rrsig := range rrset.RRSIGs {
						rrsigStrings[i] = rrsig.String()
					}
				}

				rrsets = append(rrsets, RRsetString{
					Name:   rrset.Name,
					RRtype: rrtype,
					RRs:    rrStrings,
					RRSIGs: rrsigStrings,
				})
			}
		}
		responseData[owner] = rrsets
	}

	return responseData
}

// RemoveCombinerDataNG removes specific RRs from the agent's contributions.
// Input: senderID identifies the agent, data maps owner → RR strings (ClassINET format).
// Returns the list of RR strings that were actually removed. If an RR was already
// absent, it is not included in the returned list (true no-op detection).
func (mpzd *MPZoneData) RemoveCombinerDataNG(senderID string, data map[string][]string) ([]string, error) {
	zd := mpzd.ZoneData
	mpzd.Lock()
	defer mpzd.Unlock()

	if mpzd.MP == nil || mpzd.MP.AgentContributions == nil {
		return nil, nil
	}

	if senderID == "" {
		senderID = "local"
	}

	agentData, ok := mpzd.MP.AgentContributions[senderID]
	if !ok {
		return nil, nil
	}

	var removedRecords []string

	for owner, rrStrings := range data {
		ownerMap, ok := agentData[owner]
		if !ok {
			continue
		}

		for _, rrStr := range rrStrings {
			// Parse to get the rrtype
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				mpzd.Logger.Printf("RemoveCombinerDataNG: Zone %s: Failed to parse RR %q: %v", zd.ZoneName, rrStr, err)
				continue
			}
			rrtype := rr.Header().Rrtype
			existing, ok := ownerMap[rrtype]
			if !ok {
				continue
			}

			// Remove the specific RR by string match
			var kept []dns.RR
			found := false
			for _, existingRR := range existing.RRs {
				if existingRR.String() == rrStr {
					found = true
					continue // Skip (remove) this one
				}
				kept = append(kept, existingRR)
			}

			if found {
				removedRecords = append(removedRecords, rrStr)
			}

			if len(kept) == 0 {
				delete(ownerMap, rrtype)
			} else {
				existing.RRs = kept
				ownerMap[rrtype] = existing
			}
		}

		// Clean up empty owner maps
		if len(ownerMap) == 0 {
			delete(agentData, owner)
		}
	}

	if len(removedRecords) == 0 {
		return nil, nil
	}

	// Rebuild merged CombinerData and apply to zone
	mpzd.RebuildCombinerData()

	// Persist this agent's contributions to the snapshot table
	if mpzd.MP.PersistContributions != nil {
		if err := mpzd.MP.PersistContributions(mpzd.ZoneName, senderID, mpzd.MP.AgentContributions[senderID]); err != nil {
			mpzd.Logger.Printf("RemoveCombinerDataNG: Zone %q: failed to persist contributions for %s: %v", mpzd.ZoneName, senderID, err)
			return removedRecords, fmt.Errorf("persist contributions: %w", err)
		}
	}

	if mpzd.combinerShouldApplyEdits() {
		modified, err := mpzd.CombineWithLocalChanges()
		if err != nil {
			return removedRecords, err
		}
		if modified {
			mpzd.Logger.Printf("RemoveCombinerDataNG: Zone %q: Local changes applied after removal (from %s)", mpzd.ZoneName, senderID)
		}
	}

	if mpzd.combinerShouldApplyEdits() {
		// Clean up rrtypes with no remaining agent contributions
		mpzd.cleanupRemovedRRtypes(data)

		if mpzd.MP != nil && mpzd.MP.MultiProvider != nil && mpzd.InjectSignatureTXT(mpzd.MP.MultiProvider) {
			mpzd.Logger.Printf("RemoveCombinerDataNG: Zone %q: Signature TXT injected", mpzd.ZoneName)
		}
	}

	return removedRecords, nil
}

// RemoveCombinerDataByRRtype removes all RRs of a given type from an agent's contributions
// for a specific owner. Used for ClassANY delete semantics.
// Returns the list of RR strings that were removed.
func (mpzd *MPZoneData) RemoveCombinerDataByRRtype(senderID string, owner string, rrtype uint16) ([]string, error) {
	mpzd.Lock()
	defer mpzd.Unlock()

	if mpzd.MP == nil {
		return nil, nil
	}

	if senderID == "" {
		senderID = "local"
	}

	var removedRecords []string

	if mpzd.MP.AgentContributions == nil {
		return removedRecords, nil
	}

	agentData, ok := mpzd.MP.AgentContributions[senderID]
	if !ok {
		return removedRecords, nil
	}

	ownerMap, ok := agentData[owner]
	if !ok {
		return removedRecords, nil
	}

	existing, ok := ownerMap[rrtype]
	if !ok {
		return removedRecords, nil
	}

	// Collect all RRs being removed
	for _, rr := range existing.RRs {
		removedRecords = append(removedRecords, rr.String())
	}

	// Remove the entire RRtype entry
	delete(ownerMap, rrtype)
	if len(ownerMap) == 0 {
		delete(agentData, owner)
	}

	// Rebuild merged CombinerData and apply to zone
	mpzd.RebuildCombinerData()

	// Persist this agent's contributions to the snapshot table
	if mpzd.MP.PersistContributions != nil {
		if err := mpzd.MP.PersistContributions(mpzd.ZoneName, senderID, mpzd.MP.AgentContributions[senderID]); err != nil {
			mpzd.Logger.Printf("RemoveCombinerDataByRRtype: Zone %q: failed to persist contributions for %s: %v", mpzd.ZoneName, senderID, err)
			return removedRecords, fmt.Errorf("persist contributions: %w", err)
		}
	}

	if mpzd.combinerShouldApplyEdits() {
		modified, err := mpzd.CombineWithLocalChanges()
		if err != nil {
			return removedRecords, err
		}
		if modified {
			mpzd.Logger.Printf("RemoveCombinerDataByRRtype: Zone %q: Local changes applied after removal (from %s)", mpzd.ZoneName, senderID)
		}
	}

	// Clean up if this rrtype has no remaining contributions from any agent
	mpzd.cleanupRemovedRRtype(owner, rrtype)

	if mpzd.MP != nil && mpzd.MP.MultiProvider != nil && mpzd.InjectSignatureTXT(mpzd.MP.MultiProvider) {
		mpzd.Logger.Printf("RemoveCombinerDataByRRtype: Zone %q: Signature TXT injected", mpzd.ZoneName)
	}

	return removedRecords, nil
}

// ReplaceCombinerDataByRRtype atomically replaces an agent's contributions for a
// specific owner+rrtype with a new set of RRs. Returns the lists of actually
// added and removed RR strings, plus whether any change occurred.
// Used for "replace" operation semantics at the combiner level.
func (mpzd *MPZoneData) ReplaceCombinerDataByRRtype(senderID, owner string, rrtype uint16, newRRs []dns.RR) (applied []string, removed []string, changed bool, err error) {
	mpzd.Lock()
	defer mpzd.Unlock()

	return mpzd.replaceCombinerDataByRRtypeLocked(senderID, owner, rrtype, newRRs)
}

func (mpzd *MPZoneData) replaceCombinerDataByRRtypeLocked(senderID, owner string, rrtype uint16, newRRs []dns.RR) (applied []string, removed []string, changed bool, err error) {
	if senderID == "" {
		senderID = "local"
	}

	mpzd.EnsureMP()
	if mpzd.MP.AgentContributions == nil {
		mpzd.MP.AgentContributions = make(map[string]map[string]map[uint16]core.RRset)
	}
	if mpzd.MP.AgentContributions[senderID] == nil {
		mpzd.MP.AgentContributions[senderID] = make(map[string]map[uint16]core.RRset)
	}
	if mpzd.MP.AgentContributions[senderID][owner] == nil {
		mpzd.MP.AgentContributions[senderID][owner] = make(map[uint16]core.RRset)
	}

	oldRRset, hadOld := mpzd.MP.AgentContributions[senderID][owner][rrtype]

	// Empty replacement set = delete entire RRset for this agent/owner/rrtype
	if len(newRRs) == 0 {
		if hadOld && len(oldRRset.RRs) > 0 {
			for _, rr := range oldRRset.RRs {
				removed = append(removed, rr.String())
			}
			delete(mpzd.MP.AgentContributions[senderID][owner], rrtype)
			if len(mpzd.MP.AgentContributions[senderID][owner]) == 0 {
				delete(mpzd.MP.AgentContributions[senderID], owner)
			}
			changed = true
		}
		if !changed {
			return
		}
	} else {
		// Diff old vs new
		newSet := core.RRset{Name: owner, RRtype: rrtype, RRs: newRRs}

		// Find removed: in old but not in new
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
					removed = append(removed, oldRR.String())
					changed = true
				}
			}
		}

		// Find added: in new but not in old
		for _, newRR := range newRRs {
			found := false
			if hadOld {
				for _, oldRR := range oldRRset.RRs {
					if dns.IsDuplicate(oldRR, newRR) {
						found = true
						break
					}
				}
			}
			if !found {
				applied = append(applied, newRR.String())
				changed = true
			}
		}

		if !changed {
			return
		}

		mpzd.MP.AgentContributions[senderID][owner][rrtype] = newSet
	}

	// Rebuild merged CombinerData and apply to zone
	if mpzd.MP.CombinerData == nil {
		mpzd.MP.CombinerData = core.NewCmap[OwnerData]()
	}
	mpzd.RebuildCombinerData()

	if mpzd.MP.PersistContributions != nil {
		if err = mpzd.MP.PersistContributions(mpzd.ZoneName, senderID, mpzd.MP.AgentContributions[senderID]); err != nil {
			mpzd.Logger.Printf("ReplaceCombinerDataByRRtype: Zone %q: failed to persist contributions for %s: %v", mpzd.ZoneName, senderID, err)
		}
	}

	// Apply to live zone only if this combiner is allowed to edit.
	// Non-signer combiners on signed zones persist but don't apply.
	shouldApply := mpzd.combinerShouldApplyEdits()

	if shouldApply {
		modified, combErr := mpzd.CombineWithLocalChanges()
		if combErr != nil {
			err = combErr
			return
		}
		if modified {
			mpzd.Logger.Printf("ReplaceCombinerDataByRRtype: Zone %q: Local changes applied after replace (from %s)", mpzd.ZoneName, senderID)
		}
	}

	// Clean up if no contributions remain for this rrtype
	mpzd.cleanupRemovedRRtype(owner, rrtype)

	if shouldApply {
		if mpzd.MP != nil && mpzd.MP.MultiProvider != nil && mpzd.InjectSignatureTXT(mpzd.MP.MultiProvider) {
			mpzd.Logger.Printf("ReplaceCombinerDataByRRtype: Zone %q: Signature TXT injected", mpzd.ZoneName)
		}
	}

	return
}

// InjectSignatureTXT adds a combiner signature TXT record to the zone data.
// The record is placed at "hsync-signature.{zone}" to avoid conflicts with apex TXT records.
// Returns true if the signature was injected.
func (mpzd *MPZoneData) InjectSignatureTXT(conf *tdns.MultiProviderConf) bool {
	if conf == nil || !conf.CombinerOptions[tdns.CombinerOptAddSignature] || conf.Signature == "" {
		return false
	}

	// Template expansion
	sig := strings.ReplaceAll(conf.Signature, "{identity}", conf.Identity)
	sig = strings.ReplaceAll(sig, "{zone}", mpzd.ZoneName)

	// Build the TXT RR at hsync-signature.{zone}
	ownerName := "hsync-signature." + mpzd.ZoneName
	rrStr := fmt.Sprintf("%s 300 IN TXT %q", ownerName, sig)
	rr, err := dns.NewRR(rrStr)
	if err != nil {
		mpzd.Logger.Printf("InjectSignatureTXT: Zone %s: Failed to parse TXT RR: %v", mpzd.ZoneName, err)
		return false
	}

	// Insert directly into zone data (bypasses CombinerData/apex-only filters)
	ownerData, exists := mpzd.Data.Get(ownerName)
	if !exists {
		ownerData = OwnerData{
			Name:    ownerName,
			RRtypes: tdns.NewRRTypeStore(),
		}
	}
	existing, hasExisting := ownerData.RRtypes.Get(dns.TypeTXT)
	if hasExisting {
		// Check if this exact RR is already present (avoid duplicates on repeated calls)
		rrStr := rr.String()
		alreadyPresent := false
		for _, existingRR := range existing.RRs {
			if existingRR.String() == rrStr {
				alreadyPresent = true
				break
			}
		}
		if !alreadyPresent {
			existing.RRs = append(existing.RRs, rr)
		}
	} else {
		existing = core.RRset{
			Name:   ownerName,
			RRtype: dns.TypeTXT,
			RRs:    []dns.RR{rr},
		}
	}
	ownerData.RRtypes.Set(dns.TypeTXT, existing)
	mpzd.Data.Set(ownerName, ownerData)
	return true
}

// restoreUpstreamRRset restores an rrtype from UpstreamData back into the zone.
// Used when all agent contributions for a mandatory rrtype (e.g. NS) are removed.
func (mpzd *MPZoneData) restoreUpstreamRRset(owner string, rrtype uint16) {
	if mpzd.MP.UpstreamData == nil {
		mpzd.Logger.Printf("restoreUpstreamRRset: Zone %q: No upstream data, cannot restore %s",
			mpzd.ZoneName, dns.TypeToString[rrtype])
		return
	}
	if od, ok := mpzd.MP.UpstreamData.Get(owner); ok {
		if rrset, exists := od.RRtypes.Get(rrtype); exists {
			if zoneOd, ok := mpzd.Data.Get(owner); ok {
				zoneOd.RRtypes.Set(rrtype, rrset)
				mpzd.Data.Set(owner, zoneOd)
				mpzd.Logger.Printf("restoreUpstreamRRset: Zone %q: Restored original %s for %q (%d records)",
					mpzd.ZoneName, dns.TypeToString[rrtype], owner, len(rrset.RRs))
				return
			}
		}
	}
	mpzd.Logger.Printf("restoreUpstreamRRset: Zone %q: No upstream %s found for %q",
		mpzd.ZoneName, dns.TypeToString[rrtype], owner)
}

// cleanupRemovedRRtypes checks each owner+rrtype in data for remaining agent contributions.
// If no contributions remain: for NS at the apex, restore from upstream; otherwise delete from zone.
func (mpzd *MPZoneData) cleanupRemovedRRtypes(data map[string][]string) {
	for owner, rrStrings := range data {
		for _, rrStr := range rrStrings {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				continue
			}
			mpzd.cleanupRemovedRRtype(owner, rr.Header().Rrtype)
		}
	}
}

// cleanupRemovedRRtype checks if a single owner+rrtype still has agent contributions.
// If not: for NS at the apex, restore from upstream; otherwise delete from zone data.
func (mpzd *MPZoneData) cleanupRemovedRRtype(owner string, rrtype uint16) {
	stillExists := false
	if mpzd.MP.CombinerData != nil {
		if od, ok := mpzd.MP.CombinerData.Get(owner); ok {
			if _, exists := od.RRtypes.Get(rrtype); exists {
				stillExists = true
			}
		}
	}
	if stillExists {
		return
	}
	if rrtype == dns.TypeNS && owner == mpzd.ZoneName {
		mpzd.restoreUpstreamRRset(owner, rrtype)
	} else {
		if od, ok := mpzd.ZoneData.Data.Get(owner); ok {
			od.RRtypes.Delete(rrtype)
			mpzd.ZoneData.Data.Set(owner, od)
			mpzd.Logger.Printf("cleanupRemovedRRtype: Zone %q: Removed %s from %q (no remaining contributions)",
				mpzd.ZoneName, dns.TypeToString[rrtype], owner)
		}
	}
}

// combinerReapplyContributions reloads contributions from the database and
// re-applies them to zone data. Works for both MP zones (contributions snapshot)
// and provider zones (contributions + publish instructions).
func CombinerReapplyContributions(zone string, hdb *HsyncDB) (string, error) {
	mpzd, ok := Zones.Get(zone)
	if !ok {
		return "", fmt.Errorf("zone %q not found", zone)
	}

	isProvider := GetProviderZoneRRtypes(zone) != nil
	var parts []string

	// 1. Reload AgentContributions from the CombinerContributions snapshot.
	allContribs, err := LoadAllContributions(hdb)
	if err != nil {
		return "", fmt.Errorf("failed to load contributions: %w", err)
	}

	mpzd.Lock()
	mpzd.EnsureMP()
	if zoneContribs, ok := allContribs[zone]; ok {
		mpzd.MP.AgentContributions = make(map[string]map[string]map[uint16]core.RRset)
		for senderID, ownerMap := range zoneContribs {
			mpzd.MP.AgentContributions[senderID] = ownerMap
		}
		mpzd.RebuildCombinerData()
		parts = append(parts, fmt.Sprintf("loaded contributions from %d agent(s)", len(zoneContribs)))
	} else {
		mpzd.MP.AgentContributions = make(map[string]map[string]map[uint16]core.RRset)
		mpzd.RebuildCombinerData()
		parts = append(parts, "no contributions in snapshot")
	}

	// 2. For provider zones: re-apply _signal KEY records from publish instructions.
	if isProvider {
		allInstr, err := LoadAllPublishInstructions(hdb)
		if err != nil {
			mpzd.Unlock()
			return "", fmt.Errorf("failed to load publish instructions: %w", err)
		}
		keyCount := 0
		for childZone, senders := range allInstr {
			for senderID, stored := range senders {
				if !containsString(stored.Locations, "at-ns") || len(stored.KEYRRs) == 0 {
					continue
				}
				for _, ns := range stored.PublishedNS {
					ownerName := Sig0KeyOwnerName(childZone, ns)
					providerZone := findProviderZoneForOwner(ownerName)
					if providerZone != zone {
						continue
					}
					var parsedRRs []dns.RR
					for _, rrStr := range stored.KEYRRs {
						rr, err := dns.NewRR(rrStr)
						if err != nil {
							continue
						}
						rr.Header().Name = ownerName
						parsedRRs = append(parsedRRs, rr)
					}
					_, _, changed, replErr := mpzd.replaceCombinerDataByRRtypeLocked(senderID, ownerName, dns.TypeKEY, parsedRRs)
					if replErr != nil {
						lgCombiner.Warn("reapply: failed to replace _signal KEY", "sender", senderID, "owner", ownerName, "err", replErr)
					} else if changed {
						keyCount++
					}
				}
			}
		}
		if keyCount > 0 {
			parts = append(parts, fmt.Sprintf("applied %d _signal KEY record(s)", keyCount))
		}
	}

	// 3. For MP zones: re-apply at-apex KEY from publish instructions.
	if !isProvider {
		allInstr, err := LoadAllPublishInstructions(hdb)
		if err != nil {
			mpzd.Unlock()
			return "", fmt.Errorf("failed to load publish instructions: %w", err)
		}
		if senders, ok := allInstr[zone]; ok {
			for senderID, stored := range senders {
				if !containsString(stored.Locations, "at-apex") || len(stored.KEYRRs) == 0 {
					continue
				}
				var parsedRRs []dns.RR
				for _, rrStr := range stored.KEYRRs {
					rr, err := dns.NewRR(rrStr)
					if err != nil {
						continue
					}
					parsedRRs = append(parsedRRs, rr)
				}
				_, _, changed, replErr := mpzd.replaceCombinerDataByRRtypeLocked(senderID, zone, dns.TypeKEY, parsedRRs)
				if replErr != nil {
					lgCombiner.Warn("reapply: failed to replace at-apex KEY", "sender", senderID, "err", replErr)
				} else if changed {
					parts = append(parts, fmt.Sprintf("applied at-apex KEY from %s", senderID))
				}
			}
		}
	}
	mpzd.Unlock()

	// 4. Apply to zone data (only if this combiner is allowed to edit).
	if mpzd.combinerShouldApplyEdits() {
		modified, err := mpzd.CombineWithLocalChanges()
		if err != nil {
			return "", fmt.Errorf("CombineWithLocalChanges failed: %w", err)
		}
		if modified {
			bumperResp, err := mpzd.BumpSerialOnly()
			if err != nil {
				parts = append(parts, "serial bump failed")
			} else {
				parts = append(parts, fmt.Sprintf("serial %d→%d", bumperResp.OldSerial, bumperResp.NewSerial))
			}
		}
	}

	return fmt.Sprintf("Reapplied contributions for %s: %s", zone, strings.Join(parts, "; ")), nil
}

func (mpzd *MPZoneData) RebuildCombinerData() {
	if mpzd.MP == nil {
		return
	}
	if mpzd.MP.CombinerData == nil {
		mpzd.MP.CombinerData = core.NewCmap[OwnerData]()
	}

	// Collect all RRs per owner per rrtype from all agents
	// merged[owner][rrtype] → []dns.RR (deduplicated)
	type ownerRRtypes map[uint16][]dns.RR
	merged := make(map[string]ownerRRtypes)

	for agentID, ownerMap := range mpzd.MP.AgentContributions {
		for owner, rrtypeMap := range ownerMap {
			if merged[owner] == nil {
				merged[owner] = make(ownerRRtypes)
			}
			for rrtype, rrset := range rrtypeMap {
				merged[owner][rrtype] = append(merged[owner][rrtype], rrset.RRs...)
				if mpzd.Debug {
					mpzd.Logger.Printf("rebuildCombinerData: Zone %s: agent %s contributes %d %s RRs for owner %q",
						mpzd.ZoneName, agentID, len(rrset.RRs), dns.TypeToString[rrtype], owner)
				}
			}
		}
	}

	// Build deduplicated CombinerData from merged contributions
	// Clear existing CombinerData
	mpzd.MP.CombinerData = core.NewCmap[OwnerData]()

	for owner, rrtypeRRs := range merged {
		ownerData := OwnerData{
			Name:    owner,
			RRtypes: tdns.NewRRTypeStore(),
		}
		for rrtype, rrs := range rrtypeRRs {
			// Deduplicate RRs by their string representation
			seen := make(map[string]bool)
			var dedupRRs []dns.RR
			for _, rr := range rrs {
				key := rr.String()
				if !seen[key] {
					seen[key] = true
					dedupRRs = append(dedupRRs, rr)
				}
			}
			ownerData.RRtypes.Set(rrtype, core.RRset{
				Name:   owner,
				RRtype: rrtype,
				RRs:    dedupRRs,
			})
		}
		mpzd.MP.CombinerData.Set(owner, ownerData)
	}

	if mpzd.Debug {
		// Log summary
		for owner, rrtypeRRs := range merged {
			for rrtype, rrs := range rrtypeRRs {
				mpzd.Logger.Printf("rebuildCombinerData: Zone %s: merged %s for %q: %d RRs from %d agents",
					mpzd.ZoneName, dns.TypeToString[rrtype], owner, len(rrs), len(mpzd.MP.AgentContributions))
			}
		}
	}
}

// PurgeContributionsForOrigin removes ALL contributions attributed to a
// given origin (sender ID) from this zone. Used to clean up ghost or
// stale state — for example, contributions left over from an earlier
// code version that used a different naming convention for the sender
// ID (e.g. bare "combiner" instead of the FQDN
// "combiner.echo.dnslab.").
//
// In-memory state, the persisted CombinerContributions table, and the
// rebuilt CombinerData are all updated. CombineWithLocalChanges runs
// after the rebuild so the served zone reflects the change. Returns
// the count of RRs removed.
//
// Note: this is a destructive admin operation. There is no per-RR
// undo; the caller is expected to know that the origin is genuinely
// stale and not a currently-active contributor.
func (mpzd *MPZoneData) PurgeContributionsForOrigin(origin string, hdb *HsyncDB) (int, error) {
	if origin == "" {
		return 0, fmt.Errorf("PurgeContributionsForOrigin: origin must be non-empty")
	}

	mpzd.Lock()
	defer mpzd.Unlock()

	if mpzd.MP == nil || mpzd.MP.AgentContributions == nil {
		return 0, nil
	}

	agentData, ok := mpzd.MP.AgentContributions[origin]
	if !ok {
		return 0, nil
	}

	// Count RRs being purged for the response message.
	removed := 0
	for _, ownerMap := range agentData {
		for _, rrset := range ownerMap {
			removed += len(rrset.RRs)
		}
	}

	// Drop the entire per-origin sub-map.
	delete(mpzd.MP.AgentContributions, origin)

	// Rebuild merged CombinerData and persist the deletion.
	mpzd.RebuildCombinerData()

	if hdb != nil {
		if err := DeleteContributions(hdb, mpzd.ZoneName, origin); err != nil {
			return removed, fmt.Errorf("DB delete failed: %w", err)
		}
	}

	if mpzd.combinerShouldApplyEdits() {
		modified, err := mpzd.CombineWithLocalChanges()
		if err != nil {
			return removed, err
		}
		if modified {
			mpzd.Logger.Printf("PurgeContributionsForOrigin: Zone %q: live zone updated after purging origin %q", mpzd.ZoneName, origin)
		}

		if mpzd.MP != nil && mpzd.MP.MultiProvider != nil && mpzd.InjectSignatureTXT(mpzd.MP.MultiProvider) {
			mpzd.Logger.Printf("PurgeContributionsForOrigin: Zone %q: Signature TXT injected", mpzd.ZoneName)
		}
	}

	mpzd.Logger.Printf("PurgeContributionsForOrigin: Zone %q: purged %d RR(s) attributed to origin %q",
		mpzd.ZoneName, removed, origin)
	return removed, nil
}
