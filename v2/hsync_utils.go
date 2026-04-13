/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

var lgEngine = tdns.Logger("engine")
var lg = tdns.Logger("zones")

func HsyncChanged(zd, newzd *tdns.ZoneData) (bool, *tdns.HsyncStatus, error) {
	var hss = tdns.HsyncStatus{
		Time:     time.Now(),
		ZoneName: zd.ZoneName,
		Msg:      "No change",
		Error:    false,
		ErrorMsg: "",
		Status:   true,
	}
	var differ bool

	zd.Logger.Printf("*** HsyncChanged: enter (zone %q)", zd.ZoneName)

	oldapex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		if !errors.Is(err, tdns.ErrZoneNotReady) {
			return false, nil, fmt.Errorf("error from zd.GetOwner(%s): %v", zd.ZoneName, err)
		}
		// Fall through with oldapex == nil (initial load)
	}

	newhsync, err := newzd.GetRRset(zd.ZoneName, core.TypeHSYNC3)
	if err != nil {
		return false, nil, err
	}

	if oldapex == nil {
		if newhsync == nil {
			lgAgent.Debug("initial zone load, no HSYNC3 RRs in new zone", "zone", zd.ZoneName)
			return false, &hss, nil
		}
		lgAgent.Info("initial zone load, found HSYNC3 RRs", "zone", zd.ZoneName, "count", len(newhsync.RRs))
		hss.HsyncAdds = newhsync.RRs
		return true, &hss, nil
	}

	var oldhsync *core.RRset

	if rrset, exists := oldapex.RRtypes.Get(core.TypeHSYNC3); exists {
		oldhsync = &rrset
	} else {
		oldhsync = nil
	}

	var newRRs, oldRRs []dns.RR
	if newhsync != nil {
		newRRs = newhsync.RRs
	}
	if oldhsync != nil {
		oldRRs = oldhsync.RRs
	}

	differ, hss.HsyncAdds, hss.HsyncRemoves = core.RRsetDiffer(zd.ZoneName, newRRs, oldRRs, core.TypeHSYNC3, zd.Logger, tdns.Globals.Verbose, tdns.Globals.Debug)
	zd.Logger.Printf("*** HsyncChanged: exit (zone %q, differ: %v)", zd.ZoneName, differ)
	return differ, &hss, nil
}

// LocalDnskeysChanged compares old and new DNSKEY RRsets, filtering out
// known remote DNSKEYs, and returns whether local DNSKEYs changed.
// Modeled on HsyncChanged() but operates on dns.TypeDNSKEY.
//
// "Remote" keys are those whose key tag matches zd.RemoteDNSKEYs.
// Everything else in the DNSKEY RRset is "local" (from our signer).
func LocalDnskeysChanged(zd, newzd *tdns.ZoneData) (bool, *tdns.DnskeyStatus, error) {
	ds := &tdns.DnskeyStatus{
		Time:     time.Now(),
		ZoneName: zd.ZoneName,
	}

	zd.Logger.Printf("LocalDnskeysChanged: enter (zone %q)", zd.ZoneName)

	// Build set of remote key tags for filtering
	remoteKeyTags := make(map[uint16]bool)
	for _, rr := range zd.GetRemoteDNSKEYs() {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			remoteKeyTags[dnskey.KeyTag()] = true
		}
	}

	// Get old DNSKEY RRset (from current zone data).
	// On initial load, zd may not be ready yet, so GetRRset returns ErrZoneNotReady.
	// Treat this as oldkeys == nil (no old data) — the existing nil handling below
	// will correctly classify all new keys as adds.
	oldkeys, err := zd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		if errors.Is(err, tdns.ErrZoneNotReady) {
			zd.Logger.Printf("LocalDnskeysChanged: old zone not ready (initial load), treating as no old keys")
			oldkeys = nil
		} else {
			return false, nil, fmt.Errorf("LocalDnskeysChanged: old GetRRset: %v", err)
		}
	}

	// Get new DNSKEY RRset (from incoming zone data)
	newkeys, err := newzd.GetRRset(zd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, nil, fmt.Errorf("LocalDnskeysChanged: new GetRRset: %v", err)
	}

	// Filter: keep only local DNSKEYs (not in remote set)
	oldLocal := filterLocalDNSKEYs(oldkeys, remoteKeyTags)
	newLocal := filterLocalDNSKEYs(newkeys, remoteKeyTags)

	// Handle initial load (no old data)
	if oldkeys == nil && newkeys == nil {
		return false, ds, nil
	}
	if oldkeys == nil {
		// First load — all new local keys are "adds"
		ds.LocalAdds = newLocal
		if len(ds.LocalAdds) > 0 {
			zd.Logger.Printf("LocalDnskeysChanged: zone %s: initial load, %d local DNSKEYs",
				zd.ZoneName, len(ds.LocalAdds))
			return true, ds, nil
		}
		return false, ds, nil
	}

	differ, adds, removes := core.RRsetDiffer(zd.ZoneName, newLocal, oldLocal,
		dns.TypeDNSKEY, zd.Logger, tdns.Globals.Verbose, tdns.Globals.Debug)

	ds.LocalAdds = adds
	ds.LocalRemoves = removes

	zd.Logger.Printf("LocalDnskeysChanged: exit (zone %q, differ: %v, adds: %d, removes: %d)",
		zd.ZoneName, differ, len(adds), len(removes))
	return differ, ds, nil
}

// LocalDnskeysFromKeystate derives local DNSKEY adds/removes from the KEYSTATE
// inventory rather than from the zone transfer's DNSKEY RRset. The KEYSTATE
// inventory (from the signer) is the authoritative source for which keys are
// local vs foreign. Each inventory entry's KeyRR field contains the full DNSKEY
// RR string, so we can build dns.RR objects directly.
//
// Returns (changed, status, error). If KEYSTATE is unavailable (LastKeyInventory == nil),
// returns (false, nil, nil) — caller should suppress SYNC-DNSKEY-RRSET.
func LocalDnskeysFromKeystate(zd *tdns.ZoneData) (bool, *tdns.DnskeyStatus, error) {
	// Don't process DNSKEYs for unsigned zones, but clean up any
	// previously published keys on transition to unsigned.
	if zd.MP != nil && zd.MP.MPdata != nil && !zd.MP.MPdata.ZoneSigned {
		if len(zd.MP.LocalDNSKEYs) > 0 {
			ds := &tdns.DnskeyStatus{
				Time:         time.Now(),
				ZoneName:     zd.ZoneName,
				LocalRemoves: zd.MP.LocalDNSKEYs,
			}
			zd.MP.LocalDNSKEYs = nil
			return true, ds, nil
		}
		return false, nil, nil
	}

	inv := zd.GetLastKeyInventory()
	if inv == nil {
		zd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: no KEYSTATE inventory available", zd.ZoneName)
		return false, nil, nil
	}

	if time.Since(inv.Received) > 1*time.Hour {
		lgEngine.Warn("using stale KEYSTATE inventory", "zone", zd.ZoneName, "age", time.Since(inv.Received))
	}

	ds := &tdns.DnskeyStatus{
		Time:     time.Now(),
		ZoneName: zd.ZoneName,
	}

	// Extract local keys from the KEYSTATE inventory.
	// Skip states that should NOT be in the DNSKEY RRset:
	// - foreign: belongs to another signer
	// - created: not yet staged for distribution
	// - mpremove: being removed, awaiting agent confirmation
	// - removed: already removed
	// Include: published, standby, active, retired, mpdist
	var newLocalKeys []dns.RR
	for _, entry := range inv.Inventory {
		switch entry.State {
		case tdns.DnskeyStateForeign, tdns.DnskeyStateCreated, tdns.DnskeyStateMpremove, tdns.DnskeyStateRemoved:
			continue
		}
		if entry.KeyRR == "" {
			zd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: skipping key %d with empty KeyRR",
				zd.ZoneName, entry.KeyTag)
			continue
		}
		rr, err := dns.NewRR(entry.KeyRR)
		if err != nil {
			zd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: failed to parse KeyRR for key %d: %v",
				zd.ZoneName, entry.KeyTag, err)
			continue
		}
		newLocalKeys = append(newLocalKeys, rr)
	}

	zd.EnsureMP()
	oldLocalKeys := zd.MP.LocalDNSKEYs

	// Handle initial case (no previous local keys)
	if len(oldLocalKeys) == 0 && len(newLocalKeys) == 0 {
		return false, ds, nil
	}
	if len(oldLocalKeys) == 0 {
		// First KEYSTATE — all local keys are adds
		ds.LocalAdds = newLocalKeys
		ds.CurrentLocalKeys = newLocalKeys
		zd.EnsureMP()
		zd.MP.LocalDNSKEYs = newLocalKeys
		if len(ds.LocalAdds) > 0 {
			zd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: initial KEYSTATE, %d local DNSKEYs",
				zd.ZoneName, len(ds.LocalAdds))
			return true, ds, nil
		}
		return false, ds, nil
	}

	differ, adds, removes := core.RRsetDiffer(zd.ZoneName, newLocalKeys, oldLocalKeys,
		dns.TypeDNSKEY, zd.Logger, tdns.Globals.Verbose, tdns.Globals.Debug)

	ds.LocalAdds = adds
	ds.LocalRemoves = removes
	ds.CurrentLocalKeys = newLocalKeys
	zd.EnsureMP()
	zd.MP.LocalDNSKEYs = newLocalKeys

	zd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: differ=%v, adds=%d, removes=%d",
		zd.ZoneName, differ, len(adds), len(removes))
	return differ, ds, nil
}

// filterLocalDNSKEYs returns only the DNSKEY RRs whose key tag is NOT in remoteKeyTags.
func filterLocalDNSKEYs(rrset *core.RRset, remoteKeyTags map[uint16]bool) []dns.RR {
	if rrset == nil || len(rrset.RRs) == 0 {
		return nil
	}
	var local []dns.RR
	for _, rr := range rrset.RRs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			if !remoteKeyTags[dnskey.KeyTag()] {
				local = append(local, rr)
			}
		}
	}
	return local
}

// RequestAndWaitForKeyInventory sends an RFI KEYSTATE to the signer and waits
// for the inventory response. Uses the inventory to populate zd.RemoteDNSKEYs
// by matching foreign key tags against the actual DNSKEY RRset in the zone.
//
// Sets zd.KeystateOK/KeystateError/KeystateTime to reflect success or failure.
// KEYSTATE failure is an error condition — the agent depends on KEYSTATE for
// DNSKEY classification and must not guess when it's unavailable.
func RequestAndWaitForKeyInventory(zd *tdns.ZoneData, ctx context.Context, tm *MPTransportBridge) {
	zd.SetKeystateTime(time.Now())

	if tm == nil {
		zd.SetKeystateOK(false)
		zd.SetKeystateError("no TransportManager available")
		zd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: %s", zd.ZoneName, zd.GetKeystateError())
		zd.SetRemoteDNSKEYs(nil)
		return
	}

	// Use a dedicated channel for this solicited RFI response so the
	// HsyncEngine's proactive-inventory consumer doesn't steal it.
	// Include the zone name so routeKeystateMessage only routes
	// matching responses here (prevents cross-zone interference).
	rfiChan := make(chan *KeystateInventoryMsg, 1)
	tm.setKeystateRfi(zd.ZoneName, rfiChan)
	defer tm.deleteKeystateRfi(zd.ZoneName)

	// Send RFI KEYSTATE to signer
	if err := tm.sendRfiToSigner(zd.ZoneName, "KEYSTATE"); err != nil {
		zd.SetKeystateOK(false)
		zd.SetKeystateError(fmt.Sprintf("RFI KEYSTATE send failed: %v", err))
		zd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: %s", zd.ZoneName, zd.GetKeystateError())
		zd.SetRemoteDNSKEYs(nil)
		return
	}

	// Wait for the inventory response (signer sends it as a separate KEYSTATE "inventory" message)
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	select {
	case inv := <-rfiChan:
		if inv == nil || inv.Zone != zd.ZoneName {
			zd.SetKeystateOK(false)
			zd.SetKeystateError("received nil or mismatched inventory from signer")
			zd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: %s", zd.ZoneName, zd.GetKeystateError())
			zd.SetRemoteDNSKEYs(nil)
			return
		}

		// Store the inventory snapshot for diagnostics
		zd.SetLastKeyInventory(&tdns.KeyInventorySnapshot{
			SenderID:  inv.SenderID,
			Zone:      inv.Zone,
			Inventory: inv.Inventory,
			Received:  time.Now(),
		})

		// Build set of foreign key tags from the inventory
		foreignKeyTags := make(map[uint16]bool)
		for _, entry := range inv.Inventory {
			if entry.State == tdns.DnskeyStateForeign {
				foreignKeyTags[entry.KeyTag] = true
			}
		}

		// Match foreign key tags against actual DNSKEYs in the zone
		remoteDNSKEYs := buildRemoteDNSKEYsFromTags(zd, foreignKeyTags)
		zd.SetRemoteDNSKEYs(remoteDNSKEYs)

		zd.SetKeystateOK(true)
		zd.SetKeystateError("")
		zd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: received %d-key inventory from signer, %d foreign → %d RemoteDNSKEYs",
			zd.ZoneName, len(inv.Inventory), len(foreignKeyTags), len(remoteDNSKEYs))

	case <-ctx.Done():
		zd.SetKeystateOK(false)
		zd.SetKeystateError("cancelled")
		zd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: cancelled", zd.ZoneName)
		zd.SetRemoteDNSKEYs(nil)

	case <-timeout.C:
		zd.SetKeystateOK(false)
		zd.SetKeystateError("timeout waiting for signer response (15s)")
		zd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: %s", zd.ZoneName, zd.GetKeystateError())
		zd.SetRemoteDNSKEYs(nil)
	}
}

// RequestAndWaitForEdits sends an RFI EDITS to the combiner and waits for the
// contributions response. Applies the received records to the SynchedDataEngine
// as confirmed data (the combiner already has them).
//
// Modeled on RequestAndWaitForKeyInventory.
func RequestAndWaitForEdits(zd *tdns.ZoneData, ctx context.Context, tm *MPTransportBridge, msgQs *MsgQs, zdr *ZoneDataRepo) {
	if tm == nil {
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: no TransportManager available", zd.ZoneName)
		return
	}

	if msgQs == nil || msgQs.EditsResponse == nil {
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: no EditsResponse channel available", zd.ZoneName)
		return
	}

	// Send RFI EDITS to combiner
	if err := tm.sendRfiToCombiner(zd.ZoneName, "EDITS"); err != nil {
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: RFI EDITS send failed: %v", zd.ZoneName, err)
		return
	}

	// Wait for the contributions response (combiner sends it as a separate EDITS message)
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	select {
	case resp := <-msgQs.EditsResponse:
		if resp == nil || resp.Zone != zd.ZoneName {
			zd.Logger.Printf("RequestAndWaitForEdits: zone %s: received nil or mismatched edits from combiner", zd.ZoneName)
			return
		}

		// Count total records for logging
		totalAgents := len(resp.AgentRecords)
		totalRRs := 0
		for _, ownerMap := range resp.AgentRecords {
			for _, rrs := range ownerMap {
				totalRRs += len(rrs)
			}
		}

		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: received edits from combiner (%d agents, %d RRs)",
			zd.ZoneName, totalAgents, totalRRs)

		// Apply to SDE with per-agent attribution
		applyEditsToSDE(zd, resp.AgentRecords, zdr)

	case <-ctx.Done():
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: cancelled", zd.ZoneName)

	case <-timeout.C:
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: timeout waiting for combiner EDITS response (15s)", zd.ZoneName)
	}
}

// RequestAndWaitForConfig sends an RFI CONFIG to a peer agent and waits for the config
// response on MsgQs.ConfigResponse. Returns the config data or nil on timeout/error.
func RequestAndWaitForConfig(ar *AgentRegistry, agent *Agent, zone string, subtype string, msgQs *MsgQs) *ConfigResponseMsg {
	if msgQs == nil || msgQs.ConfigResponse == nil {
		lgEngine.Warn("RequestAndWaitForConfig: no ConfigResponse channel available")
		return nil
	}

	// Send RFI CONFIG to the peer agent
	_, err := ar.sendRfiToAgent(agent, &AgentMsgPost{
		MessageType:  AgentMsgRfi,
		OriginatorID: AgentId(ar.LocalAgent.Identity),
		YourIdentity: agent.Identity,
		Zone:         ZoneName(zone),
		RfiType:      "CONFIG",
		RfiSubtype:   subtype,
	})
	if err != nil {
		lgEngine.Warn("RequestAndWaitForConfig: RFI CONFIG send failed", "agent", agent.Identity, "zone", zone, "subtype", subtype, "err", err)
		return nil
	}

	// Wait for the config response (peer sends it as a separate CONFIG message)
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	select {
	case resp := <-msgQs.ConfigResponse:
		if resp == nil {
			lgEngine.Warn("RequestAndWaitForConfig: received nil config response", "zone", zone, "subtype", subtype)
			return nil
		}
		lgEngine.Info("RequestAndWaitForConfig: received config response", "sender", resp.SenderID, "zone", resp.Zone, "subtype", resp.Subtype)
		return resp

	case <-timeout.C:
		lgEngine.Warn("RequestAndWaitForConfig: timeout waiting for config response (15s)", "zone", zone, "subtype", subtype)
		return nil
	}
}

// RequestAndWaitForAudit sends an RFI AUDIT to a peer agent and waits for the audit
// response on MsgQs.AuditResponse. Returns the audit data or nil on timeout/error.
func RequestAndWaitForAudit(ar *AgentRegistry, agent *Agent, zone string, msgQs *MsgQs) *AuditResponseMsg {
	if msgQs == nil || msgQs.AuditResponse == nil {
		lgEngine.Warn("RequestAndWaitForAudit: no AuditResponse channel available")
		return nil
	}

	// Send RFI AUDIT to the peer agent
	_, err := ar.sendRfiToAgent(agent, &AgentMsgPost{
		MessageType:  AgentMsgRfi,
		OriginatorID: AgentId(ar.LocalAgent.Identity),
		YourIdentity: agent.Identity,
		Zone:         ZoneName(zone),
		RfiType:      "AUDIT",
	})
	if err != nil {
		lgEngine.Warn("RequestAndWaitForAudit: RFI AUDIT send failed", "agent", agent.Identity, "zone", zone, "err", err)
		return nil
	}

	// Wait for the audit response (peer sends it as a separate AUDIT message)
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	select {
	case resp := <-msgQs.AuditResponse:
		if resp == nil {
			lgEngine.Warn("RequestAndWaitForAudit: received nil audit response", "zone", zone)
			return nil
		}
		lgEngine.Info("RequestAndWaitForAudit: received audit response", "sender", resp.SenderID, "zone", resp.Zone)
		return resp

	case <-timeout.C:
		lgEngine.Warn("RequestAndWaitForAudit: timeout waiting for audit response (15s)", "zone", zone)
		return nil
	}
}

// applyEditsToSDE imports the combiner's contributions response into the SynchedDataEngine.
// AgentRecords is agentID → owner → []RR strings. Each agent's records are added with
// proper attribution so the SDE knows which agent contributed what.
func applyEditsToSDE(zd *tdns.ZoneData, agentRecords map[string]map[string][]string, zdr *ZoneDataRepo) {
	if len(agentRecords) == 0 {
		zd.Logger.Printf("applyEditsToSDE: zone %s: no records to apply", zd.ZoneName)
		return
	}

	if zdr == nil {
		zd.Logger.Printf("applyEditsToSDE: zone %s: no ZoneDataRepo available", zd.ZoneName)
		return
	}

	added := 0
	for agentID, ownerMap := range agentRecords {
		for _, rrStrings := range ownerMap {
			for _, rrStr := range rrStrings {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					zd.Logger.Printf("applyEditsToSDE: zone %s: failed to parse RR %q: %v", zd.ZoneName, rrStr, err)
					continue
				}
				zdr.AddConfirmedRR(ZoneName(zd.ZoneName), AgentId(agentID), rr)
				added++
			}
		}
	}

	zd.Logger.Printf("applyEditsToSDE: zone %s: applied %d confirmed RRs from %d agents", zd.ZoneName, added, len(agentRecords))
}

// buildRemoteDNSKEYsFromTags returns DNSKEY RRs from the zone that match the given key tags.
func buildRemoteDNSKEYsFromTags(zd *tdns.ZoneData, foreignKeyTags map[uint16]bool) []dns.RR {
	if len(foreignKeyTags) == 0 {
		return nil
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		zd.Logger.Printf("buildRemoteDNSKEYsFromTags: zone %s: cannot get apex: %v", zd.ZoneName, err)
		return nil
	}

	dnskeyRRset, exists := apex.RRtypes.Get(dns.TypeDNSKEY)
	if !exists || len(dnskeyRRset.RRs) == 0 {
		return nil
	}

	var remote []dns.RR
	for _, rr := range dnskeyRRset.RRs {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			if foreignKeyTags[dnskey.KeyTag()] {
				remote = append(remote, dns.Copy(rr))
			}
		}
	}
	return remote
}

// ValidateHsyncRRset checks that HSYNC3 and HSYNCPARAM records exist at the
// zone apex and that the HSYNCPARAM has valid keys. With HSYNCPARAM, NSmgmt
// is in a single record so per-RR consistency checks are unnecessary.
// Returns true if both record types exist and are valid, false otherwise.
// error is non-nil for errors other than the records not existing.
func ValidateHsyncRRset(zd *tdns.ZoneData) (bool, error) {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return false, fmt.Errorf("error from zd.GetOwner(%s): %v", zd.ZoneName, err)
	}

	// Check that HSYNC3 exists
	hsync3rrset, hsync3exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !hsync3exists || len(hsync3rrset.RRs) == 0 {
		return false, nil
	}

	// Check that HSYNCPARAM exists
	hsyncparamrrset, paramexists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !paramexists || len(hsyncparamrrset.RRs) == 0 {
		return false, nil
	}

	// HSYNCPARAM exists — NSmgmt is a single value in the param record,
	// no cross-RR consistency check needed.
	return true, nil
}

// ourHsyncIdentities returns the set of FQDN identities we should match against
// HSYNC3 records. For roles with a single identity (agent, auditor) this is
// mp.Identity. For roles managing multiple agents (combiner, signer) it is the
// configured agent identities from mp.Agents.
func ourHsyncIdentities(mp *tdns.MultiProviderConf) []string {
	var ids []string
	if mp == nil {
		return ids
	}
	switch mp.Role {
	case "agent", "auditor":
		if mp.Identity != "" {
			ids = append(ids, dns.Fqdn(mp.Identity))
		}
	default:
		// combiner, signer, and any future multi-agent roles
		for _, agent := range mp.Agents {
			if agent != nil && agent.Identity != "" {
				ids = append(ids, dns.Fqdn(agent.Identity))
			}
		}
	}
	return ids
}

// matchHsyncIdentity checks whether any of our identities appear in the zone's
// HSYNC3 RRset. This determines whether the zone owner has listed us as a
// participant — independent of what role we play (server, signer, auditor).
// The role is determined separately by checking HSYNCPARAM fields.
//
// Returns:
//   - matched: true if at least one of our identities matches an HSYNC3 Identity
//   - label: the HSYNC3 Label of the matching record (e.g. "netnod")
//   - err: non-nil on lookup errors
func (mpzd *MPZoneData) matchHsyncIdentity(ourIdentities []string) (matched bool, label string, err error) {
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil {
		return false, "", fmt.Errorf("matchHsyncIdentity: cannot get apex for zone %s: %v", mpzd.ZoneName, err)
	}

	hsync3RRset, exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !exists || len(hsync3RRset.RRs) == 0 {
		return false, "", nil
	}

	for _, rr := range hsync3RRset.RRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok {
			continue
		}
		for _, id := range ourIdentities {
			if h3.Identity == id {
				return true, strings.TrimSuffix(h3.Label, "."), nil
			}
		}
	}

	// Also try legacy HSYNC/HSYNC2 — these have Identity but no Label,
	// so we use the first matching identity (stripped of trailing dot) as label.
	hsyncRRset, exists := apex.RRtypes.Get(core.TypeHSYNC)
	if exists {
		for _, rr := range hsyncRRset.RRs {
			hsync := rr.(*dns.PrivateRR).Data.(*core.HSYNC)
			for _, id := range ourIdentities {
				if hsync.Identity == id {
					return true, strings.TrimSuffix(id, "."), nil
				}
			}
		}
	}

	hsync2RRset, exists := apex.RRtypes.Get(core.TypeHSYNC2)
	if exists {
		for _, rr := range hsync2RRset.RRs {
			hsync2 := rr.(*dns.PrivateRR).Data.(*core.HSYNC2)
			for _, id := range ourIdentities {
				if hsync2.Identity == id {
					return true, strings.TrimSuffix(id, "."), nil
				}
			}
		}
	}

	return false, "", nil
}

// --- Role query functions ---
// Each checks only its own HSYNCPARAM field. Adding a new role does not
// affect existing role checks.

// getHSYNCPARAM returns the HSYNCPARAM record for a zone, or nil.
func (mpzd *MPZoneData) getHSYNCPARAM() *core.HSYNCPARAM {
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil {
		return nil
	}
	rrset, exists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !exists || len(rrset.RRs) == 0 {
		return nil
	}
	return rrset.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM)
}

// isServer checks whether the given HSYNC3 label is listed in
// HSYNCPARAM servers=.
func (mpzd *MPZoneData) isServer(label string) bool {
	hp := mpzd.getHSYNCPARAM()
	if hp == nil {
		return false
	}
	return hp.IsServerLabel(label)
}

// isSigner checks whether the given HSYNC3 label is listed in
// HSYNCPARAM signers=.
func (mpzd *MPZoneData) isSigner(label string) bool {
	hp := mpzd.getHSYNCPARAM()
	if hp == nil {
		return false
	}
	return hp.IsSignerLabel(label)
}

// isAuditor checks whether the given HSYNC3 label is listed in
// HSYNCPARAM auditors=.
func (mpzd *MPZoneData) isAuditor(label string) bool {
	hp := mpzd.getHSYNCPARAM()
	if hp == nil {
		return false
	}
	return hp.IsAuditorLabel(label)
}

// analyzeHsyncSigners determines whether we should sign the zone and how many
// other signers exist, by examining HSYNC3+HSYNCPARAM (preferred), then falling
// back to HSYNC or HSYNC2 for backward compatibility with old zones.
//
// Requires that matchHsyncIdentity() has already confirmed we are a provider.
// The ourLabel parameter is the label returned by matchHsyncIdentity().
//
// Returns:
//   - weShouldSign: whether our label is listed as a signer
//   - otherSigners: count of other signers
//   - zoneSigned: whether the zone has any signers listed (HSYNCPARAM signers= non-empty)
func (mpzd *MPZoneData) analyzeHsyncSigners(ourIdentities []string, ourLabel string) (weShouldSign bool, otherSigners int, zoneSigned bool, err error) {
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil {
		return false, 0, false, fmt.Errorf("analyzeHsyncSigners: cannot get apex for zone %s: %v", mpzd.ZoneName, err)
	}

	// Try HSYNC3+HSYNCPARAM first (preferred)
	hsyncparamRRset, paramExists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if paramExists && len(hsyncparamRRset.RRs) > 0 {
		hsyncparam := hsyncparamRRset.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM)
		signers := hsyncparam.GetSigners()
		if len(signers) == 0 {
			// No signers specified — zone owner has not authorized signing
			return false, 0, false, nil
		}
		zoneSigned = true
		mpzd.Logger.Printf("analyzeHsyncSigners: zone %s: ourLabel=%q signers=%v", mpzd.ZoneName, ourLabel, signers)
		for _, s := range signers {
			if strings.TrimSuffix(s, ".") == strings.TrimSuffix(ourLabel, ".") {
				weShouldSign = true
			} else {
				otherSigners++
			}
		}
		return weShouldSign, otherSigners, zoneSigned, nil
	}

	// Fallback: try HSYNC, then HSYNC2 (for backward compat with old zones)
	isOurIdentity := func(id string) bool {
		for _, ours := range ourIdentities {
			if id == ours {
				return true
			}
		}
		return false
	}
	foundOurRecord := false

	hsyncRRset, exists := apex.RRtypes.Get(core.TypeHSYNC)
	if exists && len(hsyncRRset.RRs) > 0 {
		for _, rr := range hsyncRRset.RRs {
			hsync := rr.(*dns.PrivateRR).Data.(*core.HSYNC)
			if isOurIdentity(hsync.Identity) {
				foundOurRecord = true
				weShouldSign = hsync.Sign == core.HsyncSignYES
			} else if hsync.Sign == core.HsyncSignYES {
				otherSigners++
			}
		}
		if !foundOurRecord {
			mpzd.Logger.Printf("analyzeHsyncSigners: zone %s: no HSYNC record matches our identities %v", mpzd.ZoneName, ourIdentities)
			weShouldSign = true
		}
		// Legacy HSYNC implies zone is signed if any signer exists
		zoneSigned = weShouldSign || otherSigners > 0
		return weShouldSign, otherSigners, zoneSigned, nil
	}

	hsync2RRset, exists := apex.RRtypes.Get(core.TypeHSYNC2)
	if exists && len(hsync2RRset.RRs) > 0 {
		for _, rr := range hsync2RRset.RRs {
			hsync2 := rr.(*dns.PrivateRR).Data.(*core.HSYNC2)
			if isOurIdentity(hsync2.Identity) {
				foundOurRecord = true
				weShouldSign = hsync2.DoSign()
			} else if hsync2.DoSign() {
				otherSigners++
			}
		}
		if !foundOurRecord {
			mpzd.Logger.Printf("analyzeHsyncSigners: zone %s: no HSYNC2 record matches our identities %v", mpzd.ZoneName, ourIdentities)
			weShouldSign = true
		}
		zoneSigned = weShouldSign || otherSigners > 0
		return weShouldSign, otherSigners, zoneSigned, nil
	}

	// No HSYNC3+HSYNCPARAM/HSYNC/HSYNC2 records at all — no authorization to sign
	return false, 0, false, nil
}

// populateMPdata evaluates the multi-provider guards for a zone and
// populates zd.MP.MPdata accordingly. Called after every zone refresh/transfer.
//
// Guard 1: OptMultiProvider must be set in the zone config.
// Guard 2: The zone owner must declare the zone as MP (HSYNC3+HSYNCPARAM present).
// Guard 3: Our identity must appear in the zone's HSYNC3 RRset.
// Guard 4: Our role is determined from HSYNCPARAM (servers=/signers=/auditors=).
//
//	Editing rights depend on role: servers may edit (unless zone is
//	signed and we are not a signer), auditors may not.
//
// If guard 1-3 fails, zd.MP.MPdata is set to nil.
func (mpzd *MPZoneData) populateMPdata(mp *tdns.MultiProviderConf) {
	mpzd.EnsureMP()
	// Guard 1: static config must declare this as an MP zone
	if !mpzd.Options[tdns.OptMultiProvider] {
		mpzd.MP.MPdata = nil
		return
	}

	// Guard 2: zone owner must have HSYNC3+HSYNCPARAM (or legacy HSYNC/HSYNC2)
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil {
		mpzd.Logger.Printf("populateMPdata: zone %s: cannot get apex: %v", mpzd.ZoneName, err)
		mpzd.MP.MPdata = nil
		return
	}

	_, h3exists := apex.RRtypes.Get(core.TypeHSYNC3)
	_, hpExists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	_, h1exists := apex.RRtypes.Get(core.TypeHSYNC)
	_, h2exists := apex.RRtypes.Get(core.TypeHSYNC2)

	hasHsyncRecords := (h3exists && hpExists) || h1exists || h2exists
	if !hasHsyncRecords {
		mpzd.Logger.Printf("populateMPdata: zone %s: OptMultiProvider is set but zone owner has no HSYNC3+HSYNCPARAM (or legacy HSYNC/HSYNC2) records — zone is not multi-provider", mpzd.ZoneName)
		mpzd.MP.MPdata = nil
		return
	}

	// Guard 3: our identity must appear in HSYNC3
	ourIdentities := ourHsyncIdentities(tdns.Conf.MultiProvider)
	matched, ourLabel, err := mpzd.matchHsyncIdentity(ourIdentities)
	if err != nil {
		mpzd.Logger.Printf("populateMPdata: zone %s: error matching identity: %v", mpzd.ZoneName, err)
		mpzd.MP.MPdata = nil
		return
	}
	if !matched {
		mpzd.Logger.Printf("populateMPdata: zone %s: none of our identities %v match any HSYNC3 record — we are not a participant for this zone", mpzd.ZoneName, ourIdentities)
		mpzd.Options[tdns.OptMPNotListedErr] = true
		mpzd.MP.MPdata = nil
		return
	}
	mpzd.Options[tdns.OptMPNotListedErr] = false

	// Guard 4: determine our role from HSYNCPARAM and set options accordingly.
	// Each role check queries only its own HSYNCPARAM field.
	weAreServer := mpzd.isServer(ourLabel)
	weShouldSign := mpzd.isSigner(ourLabel)
	weAreAuditor := mpzd.isAuditor(ourLabel)

	// Analyze signing state via existing path (for legacy compat + otherSigners count)
	_, otherSigners, zoneSigned, err := mpzd.analyzeHsyncSigners(ourIdentities, ourLabel)
	if err != nil {
		mpzd.Logger.Printf("populateMPdata: zone %s: error analyzing signers: %v", mpzd.ZoneName, err)
		mpzd.MP.MPdata = nil
		return
	}

	// Determine editing rights based on role.
	// Non-signer servers in signed zones get disallow-edits but MPdata is
	// still populated (allows persistence without editing — sep-1 behavior).
	switch {
	case weAreAuditor:
		// Auditors never edit
		mpzd.Options[tdns.OptMPDisallowEdits] = true
		mpzd.Options[tdns.OptAllowEdits] = false
	case zoneSigned && !weShouldSign:
		// Server in a signed zone but not a signer — contributions are
		// persisted but not applied
		mpzd.Logger.Printf("populateMPdata: zone %s: provider %q is not a signer — contributions will be persisted but not applied", mpzd.ZoneName, ourLabel)
		mpzd.Options[tdns.OptMPDisallowEdits] = true
		mpzd.Options[tdns.OptAllowEdits] = false
	default:
		// Server and/or signer — may edit
		mpzd.Options[tdns.OptMPDisallowEdits] = false
		mpzd.Options[tdns.OptAllowEdits] = true
	}

	// Preserve any existing MPdata.Options (set at parse time),
	// create the map if needed.
	var mpOpts map[tdns.ZoneOption]bool
	if mpzd.MP.MPdata != nil && mpzd.MP.MPdata.Options != nil {
		mpOpts = mpzd.MP.MPdata.Options
	} else {
		mpOpts = make(map[tdns.ZoneOption]bool)
	}
	mpOpts[tdns.OptMultiProvider] = true
	mpOpts[tdns.OptMPDisallowEdits] = mpzd.Options[tdns.OptMPDisallowEdits]
	mpOpts[tdns.OptMultiSigner] = weShouldSign && otherSigners > 0

	mpzd.MP.MPdata = &tdns.MPdata{
		WeAreProvider: weAreServer || weShouldSign,
		OurLabel:      ourLabel,
		WeAreSigner:   weShouldSign,
		OtherSigners:  otherSigners,
		ZoneSigned:    zoneSigned,
		Options:       mpOpts,
	}
	mpzd.Logger.Printf("populateMPdata: zone %s: label=%q server=%v signer=%v auditor=%v otherSigners=%d zoneSigned=%v",
		mpzd.ZoneName, ourLabel, weAreServer, weShouldSign, weAreAuditor, otherSigners, zoneSigned)
}

// weAreASigner is a convenience wrapper that checks provider membership first,
// then signer status.
func (mpzd *MPZoneData) weAreASigner(mp *tdns.MultiProviderConf) (bool, error) {
	ids := ourHsyncIdentities(mp)
	matched, label, err := mpzd.matchHsyncIdentity(ids)
	if err != nil {
		return false, err
	}
	if !matched {
		return false, nil
	}
	shouldSign, _, _, err := mpzd.analyzeHsyncSigners(ids, label)
	return shouldSign, err
}

func (mpzd *MPZoneData) PrintOwnerNames() error {
	switch mpzd.ZoneStore {
	case tdns.SliceZone:
		for _, owner := range mpzd.Owners {
			fmt.Printf("Owner: %s\n", owner.Name)
		}
	case tdns.MapZone:
		for _, owner := range mpzd.Data.Keys() {
			fmt.Printf("Owner: %s\n", owner)
		}
	}
	return nil
}

func (mpzd *MPZoneData) PrintApexRRs() error {
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil {
		return fmt.Errorf("error from mpzd.GetOwner(%s): %v", mpzd.ZoneName, err)
	}

	for _, rrtype := range apex.RRtypes.Keys() {
		for _, rr := range apex.RRtypes.GetOnlyRRSet(rrtype).RRs {
			fmt.Printf("%s: %s\n", dns.TypeToString[rrtype], rr.String())
		}
	}
	return nil
}

// snapshotUpstreamData captures the current apex RRsets for AllowedLocalRRtypes
// from zd.Data into zd.UpstreamData. Called after zone load/refresh, before
// CombineWithLocalChanges applies agent contributions.
//
// Reimplemented here because the tdns method is unexported.
func snapshotUpstreamData(zd *tdns.ZoneData) {
	zd.EnsureMP()
	zd.MP.UpstreamData = core.NewCmap[tdns.OwnerData]()

	// Only snapshot the apex owner (agent contributions only apply at apex)
	if apexOd, ok := zd.Data.Get(zd.ZoneName); ok {
		snapshotOd := tdns.OwnerData{
			Name:    zd.ZoneName,
			RRtypes: tdns.NewRRTypeStore(),
		}
		for _, rrtype := range apexOd.RRtypes.Keys() {
			if tdns.AllowedLocalRRtypes[rrtype] {
				rrset, _ := apexOd.RRtypes.Get(rrtype)
				// Deep copy the RR slice to avoid sharing references
				copiedRRs := make([]dns.RR, len(rrset.RRs))
				copy(copiedRRs, rrset.RRs)
				snapshotOd.RRtypes.Set(rrtype, core.RRset{
					Name:   rrset.Name,
					RRtype: rrset.RRtype,
					RRs:    copiedRRs,
				})
			}
		}
		zd.MP.UpstreamData.Set(zd.ZoneName, snapshotOd)
	}
}

// --- Zone refresh callbacks ---
// These implement the OnZonePreRefresh and OnZonePostRefresh callbacks
// for the three MP roles (agent, combiner, signer). They are registered
// in OnFirstLoad by each role's startup code.

// MPPreRefresh runs before the hard flip for all MP roles.
// Analyzes old vs new zone data for delegation, HSYNC, and DNSKEY changes.
// For agents: also performs KEYSTATE RFI to signer (blocking).
// Stores results in zd.MP.RefreshAnalysis for post-refresh callbacks.
// For combiners: snapshots upstream data and adds contributions to new_zd.
func MPPreRefresh(zd, new_zd *tdns.ZoneData, tm *MPTransportBridge, msgQs *MsgQs, mp *tdns.MultiProviderConf) {
	zd.EnsureMP()
	analysis := &tdns.ZoneRefreshAnalysis{}

	// Delegation change detection
	if zd.Options[tdns.OptDelSyncChild] {
		var err error
		analysis.DelegationChanged, analysis.DelegationStatus, err = zd.DelegationDataChangedNG(new_zd)
		if err != nil {
			lg.Error("DelegationDataChanged failed", "zone", zd.ZoneName, "err", err)
		}
	}

	// HSYNC and DNSKEY change detection
	switch tdns.Globals.App.Type {
	case tdns.AppTypeAgent, tdns.AppTypeMPAgent, tdns.AppTypeMPCombiner, tdns.AppTypeAuth, tdns.AppTypeMPSigner:
		var err error
		analysis.HsyncChanged, analysis.HsyncStatus, err = HsyncChanged(zd, new_zd)
		if err != nil {
			lg.Error("HsyncChanged failed", "zone", zd.ZoneName, "err", err)
		}

		dnskeyschanged, err := zd.DnskeysChangedNG(new_zd)
		if err != nil {
			lg.Error("DnskeysChangedNG failed", "zone", zd.ZoneName, "err", err)
		}

		// For multi-provider zones, compute local DNSKEY adds/removes
		if dnskeyschanged && zd.Options[tdns.OptMultiProvider] {
			switch tdns.Globals.App.Type {
			case tdns.AppTypeAgent, tdns.AppTypeMPAgent:
				// KEYSTATE is the sole source of truth for local vs foreign DNSKEYs.
				RequestAndWaitForKeyInventory(zd, context.Background(), tm)
				dnskeyschanged, analysis.DnskeyStatus, err = LocalDnskeysFromKeystate(zd)
				if err != nil {
					lg.Error("LocalDnskeysFromKeystate failed", "zone", zd.ZoneName, "err", err)
				}
				if analysis.DnskeyStatus == nil {
					dnskeyschanged = false
				}
			default:
				dnskeyschanged, analysis.DnskeyStatus, err = LocalDnskeysChanged(zd, new_zd)
				if err != nil {
					lg.Error("LocalDnskeysChanged failed", "zone", zd.ZoneName, "err", err)
				}
			}
		}
		analysis.DnskeyChanged = dnskeyschanged
	}

	// Combiner: snapshot upstream data before applying contributions to new_zd
	switch tdns.Globals.App.Type {
	case tdns.AppTypeMPCombiner:
		snapshotUpstreamData(new_zd)
	}

	// Recompute multi-provider membership and signing state on the new zone data.
	if new_zd.Options[tdns.OptMultiProvider] {
		(&MPZoneData{ZoneData: new_zd}).populateMPdata(mp)
		// Copy the computed MPdata to zd so it persists across the hard flip
		// (the flip does not copy the MP field).
		zd.EnsureMP()
		zd.MP.MPdata = new_zd.MP.MPdata
	}

	// Signer: dynamically enable/disable inline-signing based on HSYNC analysis.
	if new_zd.MP != nil && new_zd.MP.MPdata != nil {
		switch tdns.Globals.App.Type {
		case tdns.AppTypeAuth, tdns.AppTypeMPSigner:
			shouldSign := new_zd.MP.MPdata.WeAreSigner
			otherSigners := new_zd.MP.MPdata.OtherSigners
			if shouldSign && !new_zd.Options[tdns.OptInlineSigning] {
				lg.Info("HSYNC SIGN=true, enabling inline-signing", "zone", zd.ZoneName)
				new_zd.Options[tdns.OptInlineSigning] = true
			} else if !shouldSign && new_zd.Options[tdns.OptInlineSigning] {
				lg.Info("HSYNC SIGN=false, disabling inline-signing", "zone", zd.ZoneName)
				new_zd.Options[tdns.OptInlineSigning] = false
			}
			isMS := shouldSign && otherSigners > 0
			if isMS && !new_zd.Options[tdns.OptMultiSigner] {
				lg.Info("multi-signer mode detected", "zone", zd.ZoneName, "otherSigners", otherSigners)
				new_zd.Options[tdns.OptMultiSigner] = true
			} else if !isMS && new_zd.Options[tdns.OptMultiSigner] {
				lg.Info("no longer multi-signer", "zone", zd.ZoneName)
				new_zd.Options[tdns.OptMultiSigner] = false
			}
		}
	}

	// Combiner: HSYNC match check and combine with local changes on new_zd.
	switch tdns.Globals.App.Type {
	case tdns.AppTypeMPCombiner:
		if analysis.HsyncChanged {
			matched, _, _ := (&MPZoneData{ZoneData: new_zd}).matchHsyncIdentity(ourHsyncIdentities(mp))
			if matched && !new_zd.Options[tdns.OptMPDisallowEdits] {
				lg.Info("HSYNC RRset confirms we are a listed provider and signer, enabling allow-edits", "zone", zd.ZoneName)
				new_zd.Options[tdns.OptAllowEdits] = true
			} else if matched && new_zd.Options[tdns.OptMPDisallowEdits] {
				lg.Info("HSYNC RRset confirms we are a listed provider but not a signer, edits disallowed", "zone", zd.ZoneName)
				new_zd.Options[tdns.OptAllowEdits] = false
			} else {
				lg.Info("HSYNC RRset does not list us as a provider, disabling allow-edits", "zone", zd.ZoneName)
				new_zd.Options[tdns.OptAllowEdits] = false
			}
		}

		if new_zd.Options[tdns.OptAllowEdits] {
			new_zd.EnsureMP()
			if zd.MP.AgentContributions != nil {
				new_zd.MP.AgentContributions = zd.MP.AgentContributions
			}
			if zd.MP.CombinerData != nil {
				new_zd.MP.CombinerData = zd.MP.CombinerData
			}

			lg.Info("combining with local changes", "zone", zd.ZoneName)
			success, err := new_zd.CombineWithLocalChanges()
			if err != nil {
				lg.Error("CombineWithLocalChanges failed", "zone", zd.ZoneName, "err", err)
			} else if success {
				lg.Info("local changes applied to new zone data", "zone", zd.ZoneName)
			}

			if (&MPZoneData{ZoneData: new_zd}).InjectSignatureTXT(mp) {
				lg.Debug("signature TXT injected", "zone", zd.ZoneName)
			}
		}
	}

	// Store analysis for post-refresh callbacks
	zd.MP.RefreshAnalysis = analysis
}

// PostRefresh runs after the hard flip for all MP roles.
// Sends notifications to SyncQ, DelegationSyncQ based on
// the pre-refresh analysis results.
func (mpzd *MPZoneData) PostRefresh(tm *MPTransportBridge, msgQs *MsgQs) {
	zd := mpzd.ZoneData
	if zd.MP == nil || zd.MP.RefreshAnalysis == nil {
		return
	}
	analysis := zd.MP.RefreshAnalysis
	zd.MP.RefreshAnalysis = nil // clear after use

	// Delegation sync notification
	if analysis.DelegationChanged && zd.Options[tdns.OptDelSyncChild] {
		lg.Info("delegation data has changed, sending update to DelegationSyncEngine", "zone", zd.ZoneName)
		zd.DelegationSyncQ <- tdns.DelegationSyncRequest{
			Command:    "SYNC-DELEGATION",
			ZoneName:   zd.ZoneName,
			ZoneData:   zd,
			SyncStatus: analysis.DelegationStatus,
		}
	}

	// DNSKEY change routing
	if analysis.DnskeyChanged {
		switch tdns.Globals.App.Type {
		case tdns.AppTypeAgent, tdns.AppTypeMPAgent:
			if zd.Options[tdns.OptMultiProvider] {
				lg.Info("local DNSKEYs changed, sending to HsyncEngine", "zone", zd.ZoneName)
				mpzd.SyncQ <- tdns.SyncRequest{
					Command:      "SYNC-DNSKEY-RRSET",
					ZoneName:     tdns.ZoneName(zd.ZoneName),
					ZoneData:     zd,
					DnskeyStatus: analysis.DnskeyStatus,
				}
			}
		case tdns.AppTypeMPCombiner:
			lg.Debug("incoming DNSKEYs have changed, no action needed for combiner", "zone", zd.ZoneName)
		}
	}

	// HSYNC change routing
	if analysis.HsyncChanged {
		switch tdns.Globals.App.Type {
		case tdns.AppTypeAgent, tdns.AppTypeMPAgent:
			lg.Info("HSYNC RRset has changed, sending update to HsyncEngine", "zone", zd.ZoneName)
			mpzd.SyncQ <- tdns.SyncRequest{
				Command:    "HSYNC-UPDATE",
				ZoneName:   tdns.ZoneName(zd.ZoneName),
				ZoneData:   zd,
				SyncStatus: analysis.HsyncStatus,
			}
			// Detect parentsync=agent dynamically from HSYNCPARAM
			if !zd.Options[tdns.OptDelSyncChild] {
				hp := mpzd.getHSYNCPARAM()
				if hp != nil && hp.GetParentSync() == core.HsyncParentSyncAgent {
					lg.Info("HSYNCPARAM parentsync=agent detected on refresh, enabling delegation sync", "zone", mpzd.ZoneName)
					mpzd.Options[tdns.OptDelSyncChild] = true
				}
			}
		}
		// Combiner HSYNC handling (allow-edits, CombineWithLocalChanges)
		// is done in MPPreRefresh on new_zd before the flip.
	}
}
