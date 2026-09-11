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
func RegisterProviderZoneRRtypes(pz ProviderZoneConf) {
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

// mergeRRsets merges agent contributions on top of a baseline (the upstream
// zone file's RRset) for additive RRtypes like NS. Deduplicates by RR string.
func mergeRRsets(baseline []dns.RR, agentRRset core.RRset) core.RRset {
	merged := core.RRset{
		Name:   agentRRset.Name,
		RRtype: agentRRset.RRtype,
	}
	merged.RRs = append(merged.RRs, baseline...)
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

// rrsetEqual reports whether two RRsets carry the same records, RRSIGs
// aside: the combiner writes unsigned RRsets and the signer downstream signs
// them, so a served RRset that differs only by its signatures is unchanged.
func rrsetEqual(a, b core.RRset) bool {
	if len(a.RRs) != len(b.RRs) {
		return false
	}
	seen := make(map[string]int, len(a.RRs))
	for _, rr := range a.RRs {
		seen[rr.String()]++
	}
	for _, rr := range b.RRs {
		if seen[rr.String()] == 0 {
			return false
		}
		seen[rr.String()]--
	}
	return true
}

// --- The combiner's zone writes -------------------------------------------
//
// The combiner's state (AgentContributions, merged into CombinerData) is
// MP-private; the served zone is a projection of it. Every function that
// changes the state changes only the state, and notes what may need cleaning
// up; ONE call, CombineWithLocalChanges, projects the state onto the zone in
// one tdns StageBatch -- the combine, the cleanups and the signature TXT,
// under one hold of the zone's lock, published once when anything changed.
// On a draft, the incoming zone MPPreRefresh receives, the batch writes Data
// and the refresh publish is the publish.
//
// The batch callback takes no locks and reads nothing from MPState: what it
// needs is copied out first (combineInput). MPZoneData.Lock IS the zone's own
// lock, the one StageBatch takes, so a contribution function that holds it
// must never run the batch itself; every caller runs CombineWithLocalChanges
// after the contribution function has returned and the lock is released.

// ownerRRtype names one RRset of one owner.
type ownerRRtype struct {
	owner  string
	rrtype uint16
}

func (mp *MPState) noteCleanup(owner string, rrtype uint16) {
	mp.cleanupMu.Lock()
	defer mp.cleanupMu.Unlock()
	for _, c := range mp.pendingCleanups {
		if c.owner == owner && c.rrtype == rrtype {
			return
		}
	}
	mp.pendingCleanups = append(mp.pendingCleanups, ownerRRtype{owner: owner, rrtype: rrtype})
}

// noteCleanupsFor notes every (owner, rrtype) named by RR strings, the shape
// RemoveCombinerDataNG receives.
func (mp *MPState) noteCleanupsFor(data map[string][]string) {
	for owner, rrStrings := range data {
		for _, rrStr := range rrStrings {
			rr, err := dns.NewRR(rrStr)
			if err != nil {
				continue
			}
			mp.noteCleanup(owner, rr.Header().Rrtype)
		}
	}
}

func (mp *MPState) takeCleanups() []ownerRRtype {
	mp.cleanupMu.Lock()
	defer mp.cleanupMu.Unlock()
	out := mp.pendingCleanups
	mp.pendingCleanups = nil
	return out
}

// combineInput is what the batch callback works from: a copy of the state,
// taken before the batch, so the callback reads nothing that needs a lock.
type combineInput struct {
	zone            string
	isProvider      bool
	providerRRtypes map[uint16]bool
	policy          *editPolicy
	contributions   map[string]map[uint16]core.RRset // CombinerData, RRsets cloned
	upstreamApex    map[uint16]core.RRset            // UpstreamData at the apex, cloned
	cleanups        []ownerRRtype
	signatureOwner  string
	signature       dns.RR // the signature TXT to serve, nil when the option is off
}

func (mpzd *MPZoneData) combineInput(conf *MultiProviderConf) *combineInput {
	in := &combineInput{zone: mpzd.ZoneName}
	in.providerRRtypes = GetProviderZoneRRtypes(mpzd.ZoneName)
	in.isProvider = in.providerRRtypes != nil
	in.policy = mpzd.getEditPolicy()
	if mpzd.MP.CombinerData != nil {
		in.contributions = make(map[string]map[uint16]core.RRset)
		for item := range mpzd.MP.CombinerData.IterBuffered() {
			if item.Val.RRtypes == nil {
				continue
			}
			m := make(map[uint16]core.RRset)
			for _, rrtype := range item.Val.RRtypes.Keys() {
				if rs, ok := item.Val.RRtypes.Get(rrtype); ok {
					m[rrtype] = tdns.CloneRRset(rs)
				}
			}
			in.contributions[item.Key] = m
		}
	}
	if mpzd.MP.UpstreamData != nil {
		if od, ok := mpzd.MP.UpstreamData.Get(mpzd.ZoneName); ok && od.RRtypes != nil {
			in.upstreamApex = make(map[uint16]core.RRset)
			for _, rrtype := range od.RRtypes.Keys() {
				if rs, ok := od.RRtypes.Get(rrtype); ok {
					in.upstreamApex[rrtype] = tdns.CloneRRset(rs)
				}
			}
		}
	}
	in.cleanups = mpzd.MP.takeCleanups()
	if conf != nil && conf.CombinerOptions[CombinerOptAddSignature] && conf.Signature != "" {
		sig := strings.ReplaceAll(conf.Signature, "{identity}", conf.Identity)
		sig = strings.ReplaceAll(sig, "{zone}", mpzd.ZoneName)
		// At hsync-signature.{zone}, to avoid conflicts with apex TXT records.
		in.signatureOwner = "hsync-signature." + mpzd.ZoneName
		rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN TXT %q", in.signatureOwner, sig))
		if err != nil {
			lgCombiner.Error("combiner signature TXT does not parse", "zone", mpzd.ZoneName, "err", err)
		} else {
			in.signature = rr
		}
	}
	return in
}

// combineInto applies the merged contributions to the zone's next content.
// An RRset that already reads as the contribution is left alone, so a pass
// over an unchanged state stages nothing and the batch publishes nothing.
func combineInto(s tdns.Stager, in *combineInput) bool {
	changed := false
	for ownerName, rrtypes := range in.contributions {
		// MP zones: only apex records. Provider zones: any owner within the zone.
		if !in.isProvider && ownerName != in.zone {
			lgCombiner.Debug("combine: local changes outside the apex ignored", "zone", in.zone, "owner", ownerName)
			continue
		}
		for rrtype, newRRset := range rrtypes {
			// Provider zones use their own whitelist; MP zones use edit policy.
			if in.isProvider {
				if !in.providerRRtypes[rrtype] {
					continue
				}
			} else if !in.policy.canApply(rrtype) {
				continue
			}
			next := newRRset
			if additiveRRtype(rrtype) && ownerName == in.zone {
				var baseline []dns.RR
				if up, ok := in.upstreamApex[rrtype]; ok {
					baseline = up.RRs
				}
				next = mergeRRsets(baseline, newRRset)
			}
			if cur := s.RRset(ownerName, rrtype); cur != nil && rrsetEqual(*cur, next) {
				continue
			}
			s.SetRRset(ownerName, next)
			changed = true
		}
	}
	return changed
}

// cleanupInto handles the (owner, rrtype) pairs a contribution change may
// have emptied: nothing if some agent still contributes there; the upstream
// NS restored at the apex; otherwise the RRset deleted, and the owner with
// it when that was its last RRset.
func cleanupInto(s tdns.Stager, in *combineInput) bool {
	changed := false
	for _, c := range in.cleanups {
		if m, ok := in.contributions[c.owner]; ok {
			if _, still := m[c.rrtype]; still {
				continue
			}
		}
		if c.rrtype == dns.TypeNS && c.owner == in.zone {
			up, ok := in.upstreamApex[dns.TypeNS]
			if !ok {
				lgCombiner.Warn("cleanup: no upstream NS to restore", "zone", in.zone)
				continue
			}
			if cur := s.RRset(c.owner, dns.TypeNS); cur != nil && rrsetEqual(*cur, up) {
				continue
			}
			s.SetRRset(c.owner, up)
			changed = true
			lgCombiner.Info("cleanup: restored the upstream NS RRset", "zone", in.zone, "records", len(up.RRs))
			continue
		}
		if s.RRset(c.owner, c.rrtype) == nil {
			continue
		}
		s.Delete(c.owner, c.rrtype)
		changed = true
		if c.owner != in.zone && len(s.Types(c.owner)) == 0 {
			s.DeleteOwner(c.owner)
		}
		lgCombiner.Info("cleanup: removed an RRset no agent contributes any more",
			"zone", in.zone, "owner", c.owner, "rrtype", dns.TypeToString[c.rrtype])
	}
	return changed
}

// injectSignatureInto serves the combiner's signature TXT, once.
func injectSignatureInto(s tdns.Stager, in *combineInput) bool {
	if in.signature == nil {
		return false
	}
	want := in.signature.String()
	cur := s.RRset(in.signatureOwner, dns.TypeTXT)
	if cur != nil {
		for _, rr := range cur.RRs {
			if rr.String() == want {
				return false
			}
		}
	}
	next := core.RRset{Name: in.signatureOwner, RRtype: dns.TypeTXT, Class: dns.ClassINET}
	if cur != nil {
		next = *cur
	}
	next.RRs = append(next.RRs, in.signature)
	s.SetRRset(in.signatureOwner, next)
	return true
}

// CombineWithLocalChanges projects the combiner's state onto the zone in one
// StageBatch: the merged contributions (per-RRtype edit policy for MP zones,
// the configured RRtypes for provider zones), the pending cleanups and the
// signature TXT. On a live zone it publishes once, when anything changed; on
// a draft it writes Data and publishes nothing. Reports whether the zone's
// next content changed.
//
// Not to be called with MPZoneData.Lock held: that is the zone's lock, and
// the batch takes it.
func (mpzd *MPZoneData) CombineWithLocalChanges() (bool, error) {
	var conf *MultiProviderConf
	if mpzd.MP != nil {
		conf = mpzd.MP.MultiProvider
	}
	changed, _, err := mpzd.combineAndPublish(conf)
	return changed, err
}

func (mpzd *MPZoneData) combineAndPublish(conf *MultiProviderConf) (bool, tdns.BumperResponse, error) {
	var resp tdns.BumperResponse
	if mpzd.MP == nil {
		return false, resp, nil
	}
	if mpzd.ZoneStore != tdns.MapZone {
		return false, resp, fmt.Errorf("CombineWithLocalChanges: zone store %s not implemented", tdns.ZoneStoreToString[mpzd.ZoneStore])
	}
	// Non-signer combiners on signed zones persist contributions but do not
	// modify the zone; their cleanups have nothing to clean.
	if !mpzd.combinerShouldApplyEdits() {
		mpzd.MP.takeCleanups()
		return false, resp, nil
	}
	in := mpzd.combineInput(conf)
	changed := false
	resp, err := mpzd.ZoneData.StageBatch(func(s tdns.Stager) (bool, error) {
		changed = combineInto(s, in)
		changed = cleanupInto(s, in) || changed
		changed = injectSignatureInto(s, in) || changed
		return changed, nil
	})
	if err != nil {
		return false, resp, err
	}
	if changed && resp.NewSerial != resp.OldSerial {
		lgCombiner.Info("combiner state published", "zone", mpzd.ZoneName, "old", resp.OldSerial, "new", resp.NewSerial)
	}
	return changed, resp, nil
}

// replaceAndPublish is ReplaceCombinerDataByRRtype followed by the one
// publish, for the callers that make exactly one replacement.
func (mpzd *MPZoneData) replaceAndPublish(senderID, owner string, rrtype uint16, newRRs []dns.RR) (applied []string, removed []string, changed bool, err error) {
	applied, removed, changed, err = mpzd.ReplaceCombinerDataByRRtype(senderID, owner, rrtype, newRRs)
	if err != nil || !changed {
		return
	}
	if _, cerr := mpzd.CombineWithLocalChanges(); cerr != nil {
		lgCombiner.Error("publishing the combiner state failed", "zone", mpzd.ZoneName, "owner", owner, "rrtype", dns.TypeToString[rrtype], "err", cerr)
	}
	return
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

	// State only; the caller projects it onto the zone with
	// CombineWithLocalChanges once, after this lock is released.
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

	// RRtypes with no remaining agent contributions are cleaned up by the
	// caller's CombineWithLocalChanges.
	mpzd.MP.noteCleanupsFor(data)

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

	// Cleaned up by the caller's CombineWithLocalChanges if no contributions
	// remain for this rrtype.
	mpzd.MP.noteCleanup(owner, rrtype)

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

	// Cleaned up by the caller's CombineWithLocalChanges if no contributions
	// remain for this rrtype.
	mpzd.MP.noteCleanup(owner, rrtype)

	return
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

	// 4. Apply to zone data, in one publish (only if this combiner is allowed
	// to edit, which combineAndPublish decides).
	var conf *MultiProviderConf
	if mpzd.MP != nil {
		conf = mpzd.MP.MultiProvider
	}
	modified, bumperResp, err := mpzd.combineAndPublish(conf)
	if err != nil {
		return "", fmt.Errorf("CombineWithLocalChanges failed: %w", err)
	}
	if modified {
		parts = append(parts, fmt.Sprintf("serial %d→%d", bumperResp.OldSerial, bumperResp.NewSerial))
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
			ownerData.RRtypes.Set(rrtype, core.RRset{ // mp-private: CombinerData rebuild, not zone data
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

	// Count RRs being purged for the response message AND capture the
	// (owner, rrtype) tuples that were attributed to this origin.
	// After dropping the per-origin sub-map, those tuples may have no
	// remaining contributor across any agent, in which case the
	// previously-applied RRset must be cleaned up from mpzd.Data
	// (CombineWithLocalChanges only adds/overrides; it never deletes
	// owner/rrtype combinations that have disappeared from
	// CombinerData). Mirrors the cleanupRemovedRRtype follow-up that
	// RemoveCombinerDataNG and ReplaceCombinerDataByRRtype already do.
	removed := 0
	var purged []ownerRRtype
	for owner, ownerMap := range agentData {
		for rrtype, rrset := range ownerMap {
			removed += len(rrset.RRs)
			purged = append(purged, ownerRRtype{owner: owner, rrtype: rrtype})
		}
	}

	// Drop the entire per-origin sub-map.
	delete(mpzd.MP.AgentContributions, origin)

	// Rebuild merged CombinerData and persist the deletion.
	mpzd.RebuildCombinerData()

	if hdb != nil {
		if err := DeleteContributions(hdb, mpzd.ZoneName, origin); err != nil {
			// In-memory state is already past the deletion; flag the
			// divergence so an operator can re-issue the purge or run
			// reapply to bring the DB back in sync.
			mpzd.Logger.Printf("PurgeContributionsForOrigin: Zone %q: WARNING — in-memory state purged for origin %q but DB delete failed: %v. Re-issue the purge or run \"combiner zone edits reapply\" to reconcile.",
				mpzd.ZoneName, origin, err)
			return removed, fmt.Errorf("DB delete failed: %w", err)
		}
	}

	// The (owner, rrtype) tuples that may have lost their last contributor
	// are cleaned up by the caller's CombineWithLocalChanges: without that,
	// the served zone keeps answering with the RRsets attributed to the
	// purged origin.
	for _, t := range purged {
		mpzd.MP.noteCleanup(t.owner, t.rrtype)
	}

	mpzd.Logger.Printf("PurgeContributionsForOrigin: Zone %q: purged %d RR(s) attributed to origin %q",
		mpzd.ZoneName, removed, origin)
	return removed, nil
}
