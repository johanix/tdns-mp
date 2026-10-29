/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

var lgEngine = tdns.Logger("engine")
var lg = tdns.Logger("zones")

// HsyncChanged reports whether the incoming copy's instructions differ from
// the served copy's: another serial, or another digest of the canonical
// reading (plan S3). A TTL, a list's order, a label's trailing dot or an OFF
// record's fields are no change. A first load with instructions is a change.
// ParamChanged says the same, for the callers that read it.
func HsyncChanged(zd, newzd *tdns.ZoneData) (bool, *HsyncStatus, error) {
	var hss = HsyncStatus{
		Time:     time.Now(),
		ZoneName: zd.ZoneName,
		Msg:      "No change",
		Error:    false,
		ErrorMsg: "",
		Status:   true,
	}
	// The analysis readers: the served snapshot where there is one, Data
	// otherwise. On the first load zd has published nothing and oldapex is
	// nil; newzd is the incoming zone, which never has a snapshot.
	oldapex, err := zd.OwnerForAnalysis(zd.ZoneName)
	if err != nil {
		return false, nil, fmt.Errorf("error from zd.OwnerForAnalysis(%s): %v", zd.ZoneName, err)
	}
	newapex, err := newzd.OwnerForAnalysis(zd.ZoneName)
	if err != nil {
		return false, nil, fmt.Errorf("error from newzd.OwnerForAnalysis(%s): %v", zd.ZoneName, err)
	}
	// Each copy's own reading: an owner error is no reading, and differs
	// from a reading.
	read := func(apex *tdns.OwnerData) *Instructions {
		if apex == nil {
			return nil
		}
		in, _ := ReadInstructions(apex)
		return in
	}
	differ := !sameInstructions(read(oldapex), read(newapex))
	hss.ParamChanged = differ
	if differ {
		hss.Msg = "The zone's instructions changed"
	}
	return differ, &hss, nil
}

// sameInstructions: both readings name the same instructions, by serial
// and digest; or neither is a reading.
func sameInstructions(a, b *Instructions) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Serial == b.Serial && a.Digest() == b.Digest()
}

// LocalDnskeysChanged compares old and new DNSKEY RRsets, filtering out
// known remote DNSKEYs, and returns whether local DNSKEYs changed.
// Modeled on HsyncChanged() but operates on dns.TypeDNSKEY.
//
// "Remote" keys are those whose key tag matches zd.RemoteDNSKEYs.
// Everything else in the DNSKEY RRset is "local" (from our signer).
func (mpzd *MPZoneData) LocalDnskeysChanged(new_zd *tdns.ZoneData) (bool, *DnskeyStatus, error) {
	ds := &DnskeyStatus{
		Time:     time.Now(),
		ZoneName: mpzd.ZoneName,
	}

	mpzd.Logger.Printf("LocalDnskeysChanged: enter (zone %q)", mpzd.ZoneName)

	// Build set of remote key tags for filtering
	remoteKeyTags := make(map[uint16]bool)
	for _, rr := range mpzd.GetRemoteDNSKEYs() {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			remoteKeyTags[dnskey.KeyTag()] = true
		}
	}

	// Old DNSKEY RRset from the served zone, through the analysis reader: on
	// the initial load nothing is published and oldkeys is nil, which the
	// handling below classifies as "all new keys are adds".
	oldkeys, err := mpzd.RRsetForAnalysis(mpzd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, nil, fmt.Errorf("LocalDnskeysChanged: old RRsetForAnalysis: %v", err)
	}

	// New DNSKEY RRset from the incoming zone, which has no snapshot yet.
	newkeys, err := new_zd.RRsetForAnalysis(mpzd.ZoneName, dns.TypeDNSKEY)
	if err != nil {
		return false, nil, fmt.Errorf("LocalDnskeysChanged: new RRsetForAnalysis: %v", err)
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
			mpzd.Logger.Printf("LocalDnskeysChanged: zone %s: initial load, %d local DNSKEYs",
				mpzd.ZoneName, len(ds.LocalAdds))
			return true, ds, nil
		}
		return false, ds, nil
	}

	differ, adds, removes := core.RRsetDiffer(mpzd.ZoneName, newLocal, oldLocal,
		dns.TypeDNSKEY, mpzd.Logger, tdns.Globals.Verbose, tdns.Globals.Debug)

	ds.LocalAdds = adds
	ds.LocalRemoves = removes

	mpzd.Logger.Printf("LocalDnskeysChanged: exit (zone %q, differ: %v, adds: %d, removes: %d)",
		mpzd.ZoneName, differ, len(adds), len(removes))
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
//
// An agent whose provider self has no role in the zone distributes no keys
// of its own (the membership design, 2.3). That is tested first, before
// anything is recorded as distributed, so that no caller remembers a refused
// distribution as sent: it returns errNoRoleInZone. The test reads apex, the
// copy of the zone the distribution is judged against (the incoming copy at
// a refresh), or the zone as it is when apex is nil.
func (mpzd *MPZoneData) LocalDnskeysFromKeystate(self AgentId, apex *tdns.OwnerData) (bool, *DnskeyStatus, error) {
	in := readingOf(apex)
	if apex == nil {
		apex, _ = mpzd.OwnerForAnalysis(mpzd.ZoneName)
		in = activeOr(mpzd.ZoneName, apex)
	}
	if !votesIn(in, self) {
		return false, nil, errNoRoleInZone
	}
	// Don't process DNSKEYs for unsigned zones, but clean up any
	// previously published keys on transition to unsigned.
	if mpzd.MP != nil && mpzd.MP.MPdata != nil && !mpzd.MP.MPdata.ZoneSigned {
		if len(mpzd.MP.LocalDNSKEYs) > 0 {
			ds := &DnskeyStatus{
				Time:         time.Now(),
				ZoneName:     mpzd.ZoneName,
				LocalRemoves: mpzd.MP.LocalDNSKEYs,
			}
			mpzd.MP.LocalDNSKEYs = nil
			return true, ds, nil
		}
		return false, nil, nil
	}

	inv := mpzd.GetLastKeyInventory()
	if inv == nil {
		mpzd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: no KEYSTATE inventory available", mpzd.ZoneName)
		return false, nil, nil
	}
	// A signer that does not sign the zone sends its real inventory, marked
	// so (plan S11): nothing is withdrawn from it, and nothing distributed.
	// Its keys leave the zone by the leader's steps, not because the signer
	// stopped signing (#147).
	if inv.NotSigning {
		mpzd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: the signer does not sign the zone; its keys are neither distributed nor withdrawn", mpzd.ZoneName)
		return false, nil, nil
	}

	if time.Since(inv.Received) > 1*time.Hour {
		lgEngine.Warn("using stale KEYSTATE inventory", "zone", mpzd.ZoneName, "age", time.Since(inv.Received))
	}

	ds := &DnskeyStatus{
		Time:     time.Now(),
		ZoneName: mpzd.ZoneName,
	}

	newLocalKeys, newStates := mpzd.inventoryKeys(inv)

	mpzd.EnsureMP()
	oldLocalKeys := mpzd.MP.LocalDNSKEYs
	ds.CurrentKeyStates = newStates
	ds.StatesChanged = !keyStatesEqual(mpzd.MP.LocalKeyStates, newStates)
	mpzd.MP.LocalKeyStates = newStates

	// Handle initial case (no previous local keys)
	if len(oldLocalKeys) == 0 && len(newLocalKeys) == 0 {
		ds.StatesChanged = false
		return false, ds, nil
	}
	if len(oldLocalKeys) == 0 {
		// First KEYSTATE — all local keys are adds
		ds.LocalAdds = newLocalKeys
		ds.CurrentLocalKeys = newLocalKeys
		mpzd.EnsureMP()
		mpzd.MP.LocalDNSKEYs = newLocalKeys
		if len(ds.LocalAdds) > 0 {
			mpzd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: initial KEYSTATE, %d local DNSKEYs",
				mpzd.ZoneName, len(ds.LocalAdds))
			return true, ds, nil
		}
		return false, ds, nil
	}

	differ, adds, removes := core.RRsetDiffer(mpzd.ZoneName, newLocalKeys, oldLocalKeys,
		dns.TypeDNSKEY, mpzd.Logger, tdns.Globals.Verbose, tdns.Globals.Debug)

	ds.LocalAdds = adds
	ds.LocalRemoves = removes
	ds.CurrentLocalKeys = newLocalKeys
	mpzd.EnsureMP()
	mpzd.MP.LocalDNSKEYs = newLocalKeys

	mpzd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: differ=%v, adds=%d, removes=%d, key states changed=%v",
		mpzd.ZoneName, differ, len(adds), len(removes), ds.StatesChanged)
	// a state or a ds that changed with the key set as it was goes to the
	// other providers too: their DS set follows it (#58, D4)
	return differ || ds.StatesChanged, ds, nil
}

// inventoryKeys are the local keys of the signer's inventory that this
// provider serves, and what it says about each (#58), as
// LocalDnskeysFromKeystate distributes them. It touches nothing that function
// remembers, so a catch-up answer can name them (catchUpAnswer). The states
// are sorted by key tag.
//
// Skipped are the states that are not in the DNSKEY RRset: foreign (another
// signer's), created (not yet staged), mpremove (being removed, awaiting the
// agents' confirmation) and removed. Included: published, standby, active,
// retired, mpdist.
func (mpzd *MPZoneData) inventoryKeys(inv *KeyInventorySnapshot) ([]dns.RR, []core.KeyState) {
	var keys []dns.RR
	var states []core.KeyState
	for _, entry := range inv.Inventory {
		switch entry.State {
		case DnskeyStateForeign, tdns.DnskeyStateCreated, DnskeyStateMpremove, tdns.DnskeyStateRemoved:
			continue
		}
		if entry.KeyRR == "" {
			mpzd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: skipping key %d with empty KeyRR",
				mpzd.ZoneName, entry.KeyTag)
			continue
		}
		rr, err := dns.NewRR(entry.KeyRR)
		if err != nil {
			mpzd.Logger.Printf("LocalDnskeysFromKeystate: zone %s: failed to parse KeyRR for key %d: %v",
				mpzd.ZoneName, entry.KeyTag, err)
			continue
		}
		keys = append(keys, rr)
		// what this provider says about the key to the others (#58): its
		// state, and its ds as the signer's row has it (unset when the
		// row's is: nobody here has decided, so nobody there should)
		states = append(states, core.KeyState{KeyTag: entry.KeyTag, State: entry.State, DS: entry.DS})
	}
	sort.Slice(states, func(i, j int) bool { return states[i].KeyTag < states[j].KeyTag })
	return keys, states
}

// keyStatesEqual: the same keys with the same state and ds (both sorted
// by key tag).
func keyStatesEqual(a, b []core.KeyState) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].KeyTag != b[i].KeyTag || a[i].State != b[i].State || (a[i].DS == nil) != (b[i].DS == nil) || (a[i].DS != nil && *a[i].DS != *b[i].DS) {
			return false
		}
	}
	return true
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

// recordRequestedInventory records an inventory that answered this agent's
// own request as a pushed one is recorded: the snapshot with its Owned mark,
// the owner's DS intent, and a sync asked of the leader when the DS set is
// not what it was (Config.noteKeyInventory, through the bridge's hook).
// Without the hook (a role with no owner) it keeps the snapshot alone.
func (mpzd *MPZoneData) recordRequestedInventory(ctx context.Context, tm *MPTransportBridge, inv *KeystateInventoryMsg) {
	if tm != nil && tm.onKeyInventory != nil {
		tm.onKeyInventory(ctx, mpzd, inv)
		return
	}
	mpzd.setLastKeyInventoryUnlessOlder(&KeyInventorySnapshot{
		SenderID:   inv.SenderID,
		Zone:       inv.Zone,
		Inventory:  inv.Inventory,
		Owned:      inv.Owned,
		NotSigning: inv.NotSigning,
		Rollover:   inv.Rollover,
		WaitsOn:    inv.WaitsOn,
		Received:   time.Now(),
		seq:        inv.seq,
	})
}

// requestKeyInventory asks the signer for the zone's key inventory for the
// own read (ownReader), and returns it without recording it: its caller
// hands it on as a pushed inventory, which the hsync data engine records.
// The request takes the zone's slot only when it is free, in one step, so
// that it never stands in for the answer refresh-keys or a refresh waits
// for, and frees it only while it still holds its own channel. nil when the
// slot is taken, the send fails, or no answer comes within 15 s or ctx.
func (mpzd *MPZoneData) requestKeyInventory(ctx context.Context, tm *MPTransportBridge) *KeystateInventoryMsg {
	if tm == nil {
		return nil
	}
	rfiChan := make(chan *KeystateInventoryMsg, 1)
	tm.keystateRfiMu.Lock()
	if _, taken := tm.keystateRfiState[mpzd.ZoneName]; taken {
		tm.keystateRfiMu.Unlock()
		return nil
	}
	if tm.keystateRfiState == nil {
		tm.keystateRfiState = make(map[string]chan *KeystateInventoryMsg)
	}
	tm.keystateRfiState[mpzd.ZoneName] = rfiChan
	tm.keystateRfiMu.Unlock()
	defer func() {
		tm.keystateRfiMu.Lock()
		if tm.keystateRfiState[mpzd.ZoneName] == rfiChan {
			delete(tm.keystateRfiState, mpzd.ZoneName)
		}
		tm.keystateRfiMu.Unlock()
	}()

	if err := tm.sendRfiToSigner(ctx, mpzd.ZoneName, "KEYSTATE"); err != nil {
		lgEngine.Debug("the own read's request for the key inventory failed", "zone", mpzd.ZoneName, "err", err)
		return nil
	}
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()
	select {
	case inv := <-rfiChan:
		if inv == nil || inv.Zone != mpzd.ZoneName {
			return nil
		}
		return inv
	case <-ctx.Done():
		return nil
	case <-timeout.C:
		return nil
	}
}

// RequestAndWaitForKeyInventory sends an RFI KEYSTATE to the signer and waits
// for the inventory response. Uses the inventory to populate zd.RemoteDNSKEYs
// by matching foreign key tags against the actual DNSKEY RRset in the zone.
//
// Sets zd.KeystateOK/KeystateError/KeystateTime to reflect success or failure.
// KEYSTATE failure is an error condition — the agent depends on KEYSTATE for
// DNSKEY classification and must not guess when it's unavailable.
func (mpzd *MPZoneData) RequestAndWaitForKeyInventory(ctx context.Context, tm *MPTransportBridge) {
	mpzd.SetKeystateTime(time.Now())

	if tm == nil {
		mpzd.SetKeystateOK(false)
		mpzd.SetKeystateError("no TransportManager available")
		mpzd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: %s", mpzd.ZoneName, mpzd.GetKeystateError())
		mpzd.SetRemoteDNSKEYs(nil)
		return
	}

	// Use a dedicated channel for this solicited RFI response so the
	// HsyncEngine's proactive-inventory consumer doesn't steal it.
	// Include the zone name so routeKeystateMessage only routes
	// matching responses here (prevents cross-zone interference).
	rfiChan := make(chan *KeystateInventoryMsg, 1)
	tm.setKeystateRfi(mpzd.ZoneName, rfiChan)
	defer tm.deleteKeystateRfi(mpzd.ZoneName)

	// Send RFI KEYSTATE to signer
	if err := tm.sendRfiToSigner(ctx, mpzd.ZoneName, "KEYSTATE"); err != nil {
		mpzd.SetKeystateOK(false)
		mpzd.SetKeystateError(fmt.Sprintf("RFI KEYSTATE send failed: %v", err))
		mpzd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: %s", mpzd.ZoneName, mpzd.GetKeystateError())
		mpzd.SetRemoteDNSKEYs(nil)
		return
	}

	// Wait for the inventory response (signer sends it as a separate KEYSTATE "inventory" message)
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	select {
	case inv := <-rfiChan:
		if inv == nil || inv.Zone != mpzd.ZoneName {
			mpzd.SetKeystateOK(false)
			mpzd.SetKeystateError("received nil or mismatched inventory from signer")
			mpzd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: %s", mpzd.ZoneName, mpzd.GetKeystateError())
			mpzd.SetRemoteDNSKEYs(nil)
			return
		}

		mpzd.recordRequestedInventory(ctx, tm, inv)

		// Build set of foreign key tags from the inventory
		foreignKeyTags := make(map[uint16]bool)
		for _, entry := range inv.Inventory {
			if entry.State == DnskeyStateForeign {
				foreignKeyTags[entry.KeyTag] = true
			}
		}

		// Match foreign key tags against actual DNSKEYs in the zone
		remoteDNSKEYs := mpzd.buildRemoteDNSKEYsFromTags(foreignKeyTags)
		mpzd.SetRemoteDNSKEYs(remoteDNSKEYs)

		mpzd.SetKeystateOK(true)
		mpzd.SetKeystateError("")
		mpzd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: received %d-key inventory from signer, %d foreign → %d RemoteDNSKEYs",
			mpzd.ZoneName, len(inv.Inventory), len(foreignKeyTags), len(remoteDNSKEYs))

	case <-ctx.Done():
		mpzd.SetKeystateOK(false)
		mpzd.SetKeystateError("cancelled")
		mpzd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: cancelled", mpzd.ZoneName)
		mpzd.SetRemoteDNSKEYs(nil)

	case <-timeout.C:
		mpzd.SetKeystateOK(false)
		mpzd.SetKeystateError("timeout waiting for signer response (15s)")
		mpzd.Logger.Printf("RequestAndWaitForKeyInventory: zone %s: %s", mpzd.ZoneName, mpzd.GetKeystateError())
		mpzd.SetRemoteDNSKEYs(nil)
	}
}

// RequestAndWaitForEdits sends an RFI EDITS to the combiner and waits for the
// contributions response, then applies it to the SynchedDataEngine as
// confirmed data (the combiner already has them), as the own read does
// (applyOwnRead): an answer that says the combiner has not loaded its
// stored contributions is applied to nothing, and only one that says it has
// counts as this agent's own read. The start-up hydration and resync wait
// here, in the engine; the re-read waits on a goroutine of its own
// (ownReader).
//
// Modeled on RequestAndWaitForKeyInventory.
func (conf *Config) RequestAndWaitForEdits(zd *tdns.ZoneData, ctx context.Context, tm *MPTransportBridge, msgQs *MsgQs, zdr *ZoneDataRepo, self AgentId) {
	resp, sentAt, err := conf.editsRequester()(ctx, zd, tm, msgQs)
	mpzd, ok := Zones.Get(zd.ZoneName)
	if !ok {
		return
	}
	// The answer says what the combiner acts by (S10), loaded contributions
	// or not; a combiner older than its agent says neither word.
	if err == nil && resp != nil && (resp.Message == editsLoaded || resp.Message == editsNotLoaded) {
		conf.InternalMp.Handover.learned(zd.ZoneName, resp.Acting)
	}
	applyOwnRead(mpzd, &ownReadAnswer{zone: ZoneName(zd.ZoneName), asked: true, resp: resp, sentAt: sentAt, err: err}, zdr, self)
}

// editsRequester is requestEdits, or what a test has put in its place.
func (conf *Config) editsRequester() func(context.Context, *tdns.ZoneData, *MPTransportBridge, *MsgQs) (*EditsResponseMsg, time.Time, error) {
	if hook := conf.InternalMp.editsRequest; hook != nil {
		return hook
	}
	return requestEdits
}

// requestEdits asks the combiner for the zone's contributions and waits for
// its answer: up to 10 s to send and 15 s for the answer, and no longer than
// ctx. sentAt is the time just before the request was sent, which the apply
// judges the answer by (mayApplyOwnRead).
func requestEdits(ctx context.Context, zd *tdns.ZoneData, tm *MPTransportBridge, msgQs *MsgQs) (resp *EditsResponseMsg, sentAt time.Time, err error) {
	if tm == nil {
		return nil, sentAt, fmt.Errorf("no TransportManager available")
	}
	if msgQs == nil {
		return nil, sentAt, fmt.Errorf("no MsgQs available")
	}
	combinerID, err := tm.getCombinerID()
	if err != nil {
		return nil, sentAt, err
	}

	// Take only the combiner's answer to this request: an answer to an
	// earlier one that timed out, for this zone or another, must not stand
	// in for it.
	nonce := newRfiNonce()
	answer, cancel := msgQs.editsWaiters.register(rfiWaitKey(string(combinerID), zd.ZoneName, "", nonce))
	defer cancel()

	sentAt = time.Now()
	if err := tm.sendRfiToCombiner(ctx, zd.ZoneName, "EDITS", nonce); err != nil {
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: RFI EDITS send failed: %v", zd.ZoneName, err)
		return nil, sentAt, fmt.Errorf("the request to the combiner failed: %w", err)
	}

	// Wait for the contributions response (combiner sends it as a separate EDITS message)
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	select {
	case resp := <-answer:
		totalRRs := 0
		for _, ownerMap := range resp.AgentRecords {
			for _, rrs := range ownerMap {
				totalRRs += len(rrs)
			}
		}
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: received edits from combiner (%d agents, %d RRs, %q)",
			zd.ZoneName, len(resp.AgentRecords), totalRRs, resp.Message)
		return resp, sentAt, nil
	case <-ctx.Done():
		return nil, sentAt, ctx.Err()
	case <-timeout.C:
		zd.Logger.Printf("RequestAndWaitForEdits: zone %s: timeout waiting for combiner EDITS response (15s)", zd.ZoneName)
		return nil, sentAt, fmt.Errorf("the combiner did not answer within 15 s")
	}
}

// RequestAndWaitForConfig sends an RFI CONFIG to a peer agent and waits for that
// agent's config response for this zone and subtype. Returns the config data or
// nil on timeout/error.
func RequestAndWaitForConfig(ar *AgentRegistry, agent *Agent, zone string, subtype string, msgQs *MsgQs) *ConfigResponseMsg {
	resp, _ := requestConfig(ar, agent, zone, subtype, msgQs)
	return resp
}

// requestConfig is RequestAndWaitForConfig with the error of a request the
// peer did not take: refused on the wire (step 6's rules), or not
// delivered. The operator is told that, not a time-out.
func requestConfig(ar *AgentRegistry, agent *Agent, zone string, subtype string, msgQs *MsgQs) (*ConfigResponseMsg, error) {
	return requestConfigWith(ar, agent, zone, subtype, nil, msgQs)
}

// requestConfigWith is requestConfig with records that say what is asked
// for (the instructions RFI's serial and digest, plan S7).
func requestConfigWith(ar *AgentRegistry, agent *Agent, zone string, subtype string, records map[string][]string, msgQs *MsgQs) (*ConfigResponseMsg, error) {
	if msgQs == nil {
		lgEngine.Warn("RequestAndWaitForConfig: no MsgQs available")
		return nil, fmt.Errorf("this agent has no message queues")
	}

	// Several requests can be out at once (one per zone when a group elects
	// a leader), and an earlier one may still be answered after it timed
	// out; take only the answer to this one.
	nonce := newRfiNonce()
	answer, cancel := msgQs.configWaiters.register(rfiWaitKey(string(agent.ID), zone, subtype, nonce))
	defer cancel()
	// The answer to a request for the zone's SIG(0) key is let in from a
	// peer that has no role in the zone (keyHandOverAdmits): the leader of
	// the group the zone left, whose role the owner may have taken.
	// Its delivery confirmation is let in by its distribution id alone.
	var distributionID string
	if subtype == "sig0key" && ar.MPTransport != nil {
		defer ar.MPTransport.keyAsks.start(string(agent.ID), zone)()
		distributionID = transport.GenerateDistributionID()
		ar.MPTransport.keyAsks.expectConfirm(string(agent.ID), distributionID)
	}

	// Send RFI CONFIG to the peer agent
	_, err := ar.sendRfiToAgent(agent, &AgentMsgPost{
		MessageType:    AgentMsgRfi,
		OriginatorID:   AgentId(ar.LocalAgent.Identity),
		YourIdentity:   agent.ID,
		Zone:           ZoneName(zone),
		RfiType:        "CONFIG",
		RfiSubtype:     subtype,
		Records:        records,
		DistributionID: distributionID,
		Nonce:          nonce,
	})
	if err != nil {
		lgEngine.Warn("RequestAndWaitForConfig: RFI CONFIG send failed", "agent", agent.ID, "zone", zone, "subtype", subtype, "err", err)
		return nil, err
	}

	// Wait for the config response (peer sends it as a separate CONFIG message)
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	select {
	case resp := <-answer:
		lgEngine.Info("RequestAndWaitForConfig: received config response", "sender", resp.SenderID, "zone", resp.Zone, "subtype", resp.Subtype)
		return resp, nil

	case <-timeout.C:
		lgEngine.Warn("RequestAndWaitForConfig: timeout waiting for config response (15s)", "zone", zone, "subtype", subtype)
		return nil, nil
	}
}

// RequestAndWaitForAudit sends an RFI AUDIT to a peer agent and waits for that
// agent's audit response for this zone. Returns the audit data or nil on
// timeout/error.
func RequestAndWaitForAudit(ar *AgentRegistry, agent *Agent, zone string, msgQs *MsgQs) *AuditResponseMsg {
	resp, _ := requestAudit(ar, agent, zone, msgQs)
	return resp
}

// requestAudit is RequestAndWaitForAudit with the error of a request the
// peer did not take.
func requestAudit(ar *AgentRegistry, agent *Agent, zone string, msgQs *MsgQs) (*AuditResponseMsg, error) {
	if msgQs == nil {
		lgEngine.Warn("RequestAndWaitForAudit: no MsgQs available")
		return nil, fmt.Errorf("this agent has no message queues")
	}

	nonce := newRfiNonce()
	answer, cancel := msgQs.auditWaiters.register(rfiWaitKey(string(agent.ID), zone, "", nonce))
	defer cancel()

	// Send RFI AUDIT to the peer agent
	_, err := ar.sendRfiToAgent(agent, &AgentMsgPost{
		MessageType:  AgentMsgRfi,
		OriginatorID: AgentId(ar.LocalAgent.Identity),
		YourIdentity: agent.ID,
		Zone:         ZoneName(zone),
		RfiType:      "AUDIT",
		Nonce:        nonce,
	})
	if err != nil {
		lgEngine.Warn("RequestAndWaitForAudit: RFI AUDIT send failed", "agent", agent.ID, "zone", zone, "err", err)
		return nil, err
	}

	// Wait for the audit response (peer sends it as a separate AUDIT message)
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()

	select {
	case resp := <-answer:
		lgEngine.Info("RequestAndWaitForAudit: received audit response", "sender", resp.SenderID, "zone", resp.Zone)
		return resp, nil

	case <-timeout.C:
		lgEngine.Warn("RequestAndWaitForAudit: timeout waiting for audit response (15s)", "zone", zone)
		return nil, nil
	}
}

// applyEditsToSDE imports the combiner's contributions response into
// the SynchedDataEngine using REPLACE semantics on terminal-state
// entries.
//
// AgentRecords is agentID → owner → []RR strings. The response is
// the combiner's authoritative full snapshot of all confirmed
// contributions for this zone. Entries the SDE currently holds that
// are NOT in the snapshot are removed (covers the "combiner had X
// previously and no longer does" case — e.g. when stale state has
// been purged on the combiner). Entries in the snapshot that the
// SDE doesn't have are added. Entries in both are preserved.
//
// Pending and PendingRemoval entries are NEVER removed: those are
// in-flight contributions the local agent submitted that the combiner
// may not yet have processed. Removing them would lose ongoing
// transactions.
//
// Per-RRtype scope: replace operates within a single
// (agent, rrtype) bucket, mirroring the combiner's own per-agent
// per-rrtype REPLACE semantics in AgentContributions.
//
// Two kinds of set are left alone (leave). This agent's own DNSKEY set: the
// agent never sends it to its combiner (SkipCombiner), so no answer holds
// it, and an answer applied after an inventory would drop the keys the
// hydration or the inventory put there. And a set the engine changed, or
// whose change its combiner had not confirmed, before the request was sent
// at sentAt (mayApplyOwnRead): the answer can predate it.
func applyEditsToSDE(zd *tdns.ZoneData, agentRecords map[string]map[string][]string, zdr *ZoneDataRepo, self AgentId, sentAt time.Time) {
	if zdr == nil {
		zd.Logger.Printf("applyEditsToSDE: zone %s: no ZoneDataRepo available", zd.ZoneName)
		return
	}

	zone := ZoneName(zd.ZoneName)
	leave := func(agent AgentId, rrtype uint16) bool {
		if rrtype == dns.TypeDNSKEY && isAmong([]string{string(self)}, agent) {
			return true
		}
		return !zdr.mayApplyOwnRead(zone, agent, rrtype, sentAt)
	}

	// 1. Build a fast-lookup index of the snapshot:
	//    snapshot[agentID][rrtype][rrStr] = true
	//
	// We also collect per-(agent, rrtype) sets of "this rrtype is
	// present in the snapshot" so we know which buckets the snapshot
	// is asserting authority over. A bucket NOT in this map should
	// be left alone — we have no statement from the combiner about
	// that (agent, rrtype) pair. (In practice the combiner emits
	// every contributing (agent, owner, rrtype); the snapshot covers
	// everything the combiner knows about, and a bucket entirely
	// missing from the response means the combiner has no
	// contribution there. For an agent that previously contributed
	// and was purged, the agent appears with an empty contribution
	// or not at all — we treat both the same: if the snapshot
	// doesn't list a (agent, rrtype, rr) triple, that triple is
	// removed from the SDE if present in terminal state.)
	type bucketKey struct {
		agent  AgentId
		rrtype uint16
	}
	snapshotRRs := make(map[bucketKey]map[string]bool)
	parsedSnapshot := make(map[bucketKey][]dns.RR)

	for agentID, ownerMap := range agentRecords {
		for _, rrStrings := range ownerMap {
			for _, rrStr := range rrStrings {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					zd.Logger.Printf("applyEditsToSDE: zone %s: failed to parse RR %q: %v", zd.ZoneName, rrStr, err)
					continue
				}
				key := bucketKey{agent: AgentId(agentID), rrtype: rr.Header().Rrtype}
				if snapshotRRs[key] == nil {
					snapshotRRs[key] = make(map[string]bool)
				}
				canonical := rr.String()
				snapshotRRs[key][canonical] = true
				parsedSnapshot[key] = append(parsedSnapshot[key], rr)
			}
		}
	}

	// 2. Walk the SDE for this zone and remove terminal-state
	//    entries that are not present in the snapshot.
	removed := 0
	if agentRepo, ok := zdr.Get(zone); ok {
		for item := range agentRepo.Data.IterBuffered() {
			agentID := item.Key
			ownerData := item.Val
			if ownerData == nil {
				continue
			}
			for _, rrtype := range ownerData.RRtypes.Keys() {
				if leave(agentID, rrtype) {
					continue
				}
				key := bucketKey{agent: agentID, rrtype: rrtype}
				snapForBucket := snapshotRRs[key]

				rrset, ok := ownerData.RRtypes.Get(rrtype)
				if !ok {
					continue
				}

				// Build list of RRs to drop from the data side. A RR
				// is dropped only if its tracked counterpart is in a
				// terminal state (Accepted / Ignored / Removed) AND
				// it is absent from the snapshot.
				keepRRs := rrset.RRs[:0]
				for _, rr := range rrset.RRs {
					rrStr := rr.String()
					if snapForBucket[rrStr] {
						keepRRs = append(keepRRs, rr)
						continue
					}
					if !rrIsTerminalInTracking(zdr, zone, agentID, rrtype, rrStr) {
						// Pending or PendingRemoval — preserve.
						keepRRs = append(keepRRs, rr)
						continue
					}
					// Drop from the data side.
					removed++
					// Also drop the matching tracking entry.
					zdr.removeTrackedRR(zone, agentID, rrtype, rrStr)
				}
				if len(keepRRs) == 0 {
					ownerData.RRtypes.Delete(rrtype)
				} else {
					rrset.RRs = keepRRs
					ownerData.RRtypes.Set(rrtype, rrset) // mp-private: SDE reconcile record, not zone data
				}
			}

			// If the agent now has no rrtypes at all, drop the empty
			// OwnerData entry so the agent disappears from the SDE
			// rather than lingering as a "(no RRsets)" placeholder.
			if ownerData.RRtypes.Count() == 0 {
				agentRepo.Data.Remove(agentID)
				// Tracking for an agent with no terminal-state data
				// also has no reason to live; clear the per-agent
				// rrtype map. (Pending entries that were preserved
				// above keep their data on the RRsets path, so this
				// branch only fires when the agent is truly empty.)
				if zdr.Tracking[zone] != nil {
					delete(zdr.Tracking[zone], agentID)
				}
			}
		}
	}

	// 3. Add anything from the snapshot that the SDE doesn't already
	//    have. AddConfirmedRR is idempotent on the data side
	//    (RRset.Add dedupes) but appends a fresh tracking entry per
	//    call — so guard with a presence check on the data side.
	added := 0
	for key, rrs := range parsedSnapshot {
		if leave(key.agent, key.rrtype) {
			continue
		}
		var existing core.RRset
		hasExisting := false
		if agentRepo, ok := zdr.Get(zone); ok {
			if ownerData, ok := agentRepo.Get(key.agent); ok {
				if rrset, ok := ownerData.RRtypes.Get(key.rrtype); ok {
					existing = rrset
					hasExisting = true
				}
			}
		}
		for _, rr := range rrs {
			if hasExisting && rrsetContains(&existing, rr) {
				continue
			}
			zdr.AddConfirmedRR(zone, key.agent, rr)
			added++
		}
	}

	zd.Logger.Printf("applyEditsToSDE: zone %s: snapshot reconciled (added %d, removed %d, agents in snapshot %d)",
		zd.ZoneName, added, removed, len(agentRecords))
}

// rrIsTerminalInTracking reports whether the most-recent tracking
// entry for the given (zone, agent, rrtype, rrStr) is in a terminal
// state from the combiner's perspective (Accepted, Ignored, or
// Removed). Returns false if no tracking entry exists for the RR
// (e.g. a hydration-added RR that bypassed tracking) — those are
// treated as terminal too, since they don't represent in-flight
// transactions. Pending and PendingRemoval entries return false.
//
// Walks the tracking slice in reverse so we evaluate the *latest*
// matching entry rather than the oldest. With multiple tracking
// rows for the same RR (legitimate during retry/transition cycles),
// the most-recent state is the operationally meaningful one.
func rrIsTerminalInTracking(zdr *ZoneDataRepo, zone ZoneName, agent AgentId, rrtype uint16, rrStr string) bool {
	if zdr.Tracking[zone] == nil || zdr.Tracking[zone][agent] == nil {
		return true
	}
	tracked := zdr.Tracking[zone][agent][rrtype]
	if tracked == nil {
		return true
	}
	for i := len(tracked.Tracked) - 1; i >= 0; i-- {
		tr := tracked.Tracked[i]
		if tr.RR.String() != rrStr {
			continue
		}
		switch tr.State {
		case RRStatePending, RRStatePendingRemoval:
			return false
		default:
			return true
		}
	}
	// No tracking entry for this RR — treat as terminal.
	return true
}

// rrIsPendingRemovalInTracking reports whether the most-recent tracking
// entry for the given (zone, agent, rrtype, rrStr) is RRStatePendingRemoval.
// Used by apihandler_agent.go when constructing REPLACE-shaped operations:
// an RR that the agent already asked the combiner to delete should not be
// re-included in a subsequent REPLACE built from the live SDE snapshot,
// because the data repo still holds the RR until allRecipientsConfirmed.
//
// Walks the tracking slice in reverse so the *latest* matching entry wins,
// matching rrIsTerminalInTracking's discipline.
func rrIsPendingRemovalInTracking(zdr *ZoneDataRepo, zone ZoneName, agent AgentId, rrtype uint16, rrStr string) bool {
	if zdr == nil || zdr.Tracking[zone] == nil || zdr.Tracking[zone][agent] == nil {
		return false
	}
	tracked := zdr.Tracking[zone][agent][rrtype]
	if tracked == nil {
		return false
	}
	for i := len(tracked.Tracked) - 1; i >= 0; i-- {
		tr := tracked.Tracked[i]
		if tr.RR.String() != rrStr {
			continue
		}
		return tr.State == RRStatePendingRemoval
	}
	return false
}

// rrsetContains returns true if the RRset already contains an RR
// that matches the given RR by content (using miekg/dns
// IsDuplicate). Used to avoid double-adding a snapshot RR that's
// already present in the SDE.
func rrsetContains(rrset *core.RRset, rr dns.RR) bool {
	for _, existing := range rrset.RRs {
		if dns.IsDuplicate(existing, rr) {
			return true
		}
	}
	return false
}

// buildRemoteDNSKEYsFromTags returns DNSKEY RRs from the zone that match the given key tags.
func (mpzd *MPZoneData) buildRemoteDNSKEYsFromTags(foreignKeyTags map[uint16]bool) []dns.RR {
	if len(foreignKeyTags) == 0 {
		return nil
	}

	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		mpzd.Logger.Printf("buildRemoteDNSKEYsFromTags: zone %s: cannot get apex: %v", mpzd.ZoneName, err)
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

// ourHsyncIdentities returns the set of FQDN identities we should match against
// HSYNC3 records. For roles with a single identity (agent, auditor) this is
// mp.Identity. For roles managing multiple agents (combiner, signer) it is the
// configured agent identities from mp.Agents.
func ourHsyncIdentities(mp *MultiProviderConf) []string {
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

// instructions are the instructions mpzd's decisions read, for the zone as
// served here and for a copy wrapped for analysis (the incoming copy at a
// refresh) alike: the store's active instructions (instructionsFor), since
// from the thaw a newer copy is held, not acted on (plan S7). Where the
// store keeps none, or a record from before S7, the reading of the copy. On
// a combiner or a signer that holds a hand-over, what it was handed.
func (mpzd *MPZoneData) instructions() *Instructions {
	apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	return activeOr(mpzd.ZoneName, apex)
}

// roles are the sets mpzd's decisions read: the zone's current step's, as
// the store keeps them (plan S12), for the zone as served here and for a
// copy wrapped for analysis alike; with no step's sets kept, rolesFor of
// the store's serials; where the store keeps no enforced record, the
// copy's.
func (mpzd *MPZoneData) roles() Roles {
	if handed, ok := actingHeld.Load().roles(mpzd.ZoneName); ok {
		return handed // a combiner's or a signer's, as instructions
	}
	var r Roles
	if sets, ok := instrStore.Load().stepSets(mpzd.ZoneName); ok {
		r = sets
	} else if from, to, step := instrStore.Load().transition(mpzd.ZoneName); to != nil {
		r = rolesFor(from, to, step)
	} else {
		in := mpzd.instructions()
		r = rolesFor(in, in, 0)
	}
	resolveRemovals(mpzd.ZoneName, &r)
	return r
}

// labelOf is the label of one of the identities in the zone's instructions:
// its ON record's, or for a provider whose removal is under way, the
// removal's (design 3.3). An OFF record gives no label.
func (mpzd *MPZoneData) labelOf(identities ...string) (string, bool) {
	if label, ok := mpzd.instructions().labelOf(identities...); ok {
		return label, true
	}
	for _, id := range identities {
		if rm, ok := instrStore.Load().removal(mpzd.ZoneName, "", id); ok {
			return rm.Label, true
		}
	}
	return "", false
}

// matchHsyncIdentity checks whether any of our identities has an ON HSYNC3
// record in the zone's instructions. This determines whether the zone owner
// has listed us as a participant, independent of what role we play (server,
// signer, auditor); the role is determined separately. An OFF record gives
// no label.
//
// Returns:
//   - matched: true if at least one of our identities has an ON record
//   - label: that record's label (e.g. "netnod")
//   - err: always nil; kept for the callers
func (mpzd *MPZoneData) matchHsyncIdentity(ourIdentities []string) (matched bool, label string, err error) {
	label, matched = mpzd.labelOf(ourIdentities...)
	return matched, label, nil
}

// --- Role query functions ---
// Each reads one list of the zone's instructions.

// isServer checks whether the given HSYNC3 label is listed in servers=.
func (mpzd *MPZoneData) isServer(label string) bool {
	in := mpzd.instructions()
	return in != nil && slices.Contains(in.Servers, trimDot(label))
}

// isSigner checks whether the given HSYNC3 label is listed in signers=.
func (mpzd *MPZoneData) isSigner(label string) bool {
	in := mpzd.instructions()
	return in != nil && slices.Contains(in.Signers, trimDot(label))
}

// isAuditor checks whether the given HSYNC3 label is listed in auditors=.
func (mpzd *MPZoneData) isAuditor(label string) bool {
	in := mpzd.instructions()
	return in != nil && slices.Contains(in.Auditors, trimDot(label))
}

// hasPubkey checks whether the zone's instructions carry the pubkey flag:
// the customer's word that its providers may publish the zone's key in
// zones of their own (the at-ns location, see publishLocations).
func (mpzd *MPZoneData) hasPubkey() bool {
	return mpzd.roles().Pubkey
}

// mpDataLocks is a lock per zone (canonicalName), held while the zone's
// multi-provider data is computed and set and acted on: by a refresh
// (MPPreRefresh) and by a hand-over (actBySignerHandover, actByHandover),
// so that neither sets what it computed over what the other set meanwhile.
// Taken before the zone's lock, never under it; not held across a re-sign
// request, which can wait on a full ResignQ.
var mpDataLocks sync.Map

func mpDataLock(zone string) *sync.Mutex {
	m, _ := mpDataLocks.LoadOrStore(canonicalName(zone), &sync.Mutex{})
	return m.(*sync.Mutex)
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
//
// signing is the zone's signing set by this copy (advanceSigningSet): for a
// zone with HSYNC3 and HSYNCPARAM, a provider signs when it is in it, in
// signers= or leaving it (#147).
func (mpzd *MPZoneData) populateMPdata(mp *MultiProviderConf, signing signingSet) {
	mpzd.EnsureMP()
	// Guard 1: static config must declare this as an MP zone
	if !mpzd.Options[tdns.OptMultiProvider] {
		mpzd.MP.MPdata = nil
		return
	}

	// Guard 2: zone owner must have HSYNC3 and HSYNCPARAM. Read from the
	// copy this wrapper holds: the incoming zone, which has no published
	// snapshot, as well as a live one.
	in := mpzd.instructions()
	if in == nil || !in.HasParam || !hasHSYNC3(in) {
		// A provider zone has no HSYNC records by design; its option is
		// what attaches the combiner's start-up re-apply and refresh combine.
		if GetProviderZoneRRtypes(mpzd.ZoneName) == nil {
			mpzd.Logger.Printf("populateMPdata: zone %s: OptMultiProvider is set but zone owner has no HSYNC3+HSYNCPARAM records — zone is not multi-provider", mpzd.ZoneName)
		}
		mpzd.MP.MPdata = nil
		return
	}

	// Guard 3: our identity must have an ON HSYNC3 record
	ourIdentities := ourHsyncIdentities(mp)
	ourLabel, matched := mpzd.labelOf(ourIdentities...)
	if !matched {
		mpzd.Logger.Printf("populateMPdata: zone %s: none of our identities %v match any HSYNC3 record — we are not a participant for this zone", mpzd.ZoneName, ourIdentities)
		mpzd.MPOptions[OptMPNotListedErr] = true
		mpzd.MP.MPdata = nil
		return
	}
	mpzd.MPOptions[OptMPNotListedErr] = false

	// Guard 4: our role, from the sets (mpdataFrom(roles), plan S3). A
	// provider out of signers= that the zone's HSYNC3 RRset still lists
	// signs on, as before (#147): the signing set says who signs.
	roles := mpzd.roles()
	weAreServer := has(roles.Servers, ourLabel)
	weAreAuditor := slices.Contains(in.Auditors, ourLabel)
	_, weShouldSign := signing[ourLabel]
	leaving := weShouldSign && !has(roles.Signing, ourLabel)
	otherSigners := len(signing.others(ourLabel))
	zoneSigned := len(signing) > 0
	leavers := signing.leavers(in)

	// Determine editing rights based on role.
	// Non-signer servers in signed zones get disallow-edits but MPdata is
	// still populated (allows persistence without editing — sep-1 behavior).
	switch {
	case weAreAuditor:
		// Auditors never edit
		mpzd.MPOptions[OptMPDisallowEdits] = true
		mpzd.MPOptions[tdns.OptAllowEdits] = false
	case zoneSigned && !weShouldSign:
		// Server in a signed zone but not a signer — contributions are
		// persisted but not applied
		mpzd.Logger.Printf("populateMPdata: zone %s: provider %q is not a signer — contributions will be persisted but not applied", mpzd.ZoneName, ourLabel)
		mpzd.MPOptions[OptMPDisallowEdits] = true
		mpzd.MPOptions[tdns.OptAllowEdits] = false
	default:
		// Server and/or signer — may edit
		mpzd.MPOptions[OptMPDisallowEdits] = false
		mpzd.MPOptions[tdns.OptAllowEdits] = true
	}

	// Preserve any existing MPdata.Options (set at parse time), in a map
	// of its own: a hand-over runs this on a wrapper that shares the
	// zone's MPdata, outside the zone's lock, and the zone's map is read
	// without one.
	mpOpts := make(map[tdns.ZoneOption]bool)
	if mpzd.MP.MPdata != nil {
		maps.Copy(mpOpts, mpzd.MP.MPdata.Options)
	}
	mpOpts[tdns.OptMultiProvider] = true
	mpOpts[OptMPDisallowEdits] = mpzd.MPOptions[OptMPDisallowEdits]
	mpOpts[tdns.OptMultiSigner] = weShouldSign && otherSigners > 0

	mpzd.MP.MPdata = &MPdata{
		WeAreProvider: weAreServer || weShouldSign,
		OurLabel:      ourLabel,
		WeAreSigner:   weShouldSign,
		OtherSigners:  otherSigners,
		ZoneSigned:    zoneSigned,
		Signing:       signing,
		Leaving:       leaving,
		Leavers:       leavers,
		Options:       mpOpts,
	}
	mpzd.Logger.Printf("populateMPdata: zone %s: label=%q server=%v signer=%v leaving=%v auditor=%v otherSigners=%d zoneSigned=%v",
		mpzd.ZoneName, ourLabel, weAreServer, weShouldSign, leaving, weAreAuditor, otherSigners, zoneSigned)
}

func (mpzd *MPZoneData) PrintOwnerNames() error {
	switch mpzd.ZoneStore {
	case tdns.MapZone:
		for _, owner := range mpzd.Data.Keys() {
			fmt.Printf("Owner: %s\n", owner)
		}
	}
	return nil
}

func (mpzd *MPZoneData) PrintApexRRs() error {
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil {
		return fmt.Errorf("error from mpzd.OwnerForAnalysis(%s): %v", mpzd.ZoneName, err)
	}
	if apex == nil {
		return fmt.Errorf("zone %s has no apex", mpzd.ZoneName)
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
func (mpzd *MPZoneData) snapshotUpstreamData(src *tdns.ZoneData) {
	mpzd.EnsureMP()
	mpzd.MP.UpstreamData = core.NewCmap[OwnerData]()

	// Only snapshot the apex owner (agent contributions only apply at apex)
	if apexOd, ok := src.Data.Get(src.ZoneName); ok {
		snapshotOd := OwnerData{
			Name:    src.ZoneName,
			RRtypes: tdns.NewRRTypeStore(),
		}
		for _, rrtype := range apexOd.RRtypes.Keys() {
			if AllowedLocalRRtypes[rrtype] {
				rrset, _ := apexOd.RRtypes.Get(rrtype)
				// Deep copy the RR slice to avoid sharing references
				copiedRRs := make([]dns.RR, len(rrset.RRs))
				copy(copiedRRs, rrset.RRs)
				snapshotOd.RRtypes.Set(rrtype, core.RRset{ // mp-private: UpstreamData copy, not zone data
					Name:   rrset.Name,
					RRtype: rrset.RRtype,
					RRs:    copiedRRs,
				})
			}
		}
		mpzd.MP.UpstreamData.Set(src.ZoneName, snapshotOd)
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
func (mpzd *MPZoneData) MPPreRefresh(new_zd *tdns.ZoneData, tm *MPTransportBridge, msgQs *MsgQs, mp *MultiProviderConf) {
	mpzd.EnsureMP()
	analysis := &ZoneRefreshAnalysis{}

	// Delegation change detection
	if mpzd.Options[tdns.OptParentSync] {
		var err error
		analysis.DelegationChanged, analysis.DelegationStatus, err = implicitDelegationChange(mpzd, new_zd)
		if err != nil {
			lg.Error("DelegationDataChanged failed", "zone", mpzd.ZoneName, "err", err)
		}
	}

	// HSYNC change detection runs for every MP-aware role, including
	// the auditor. The auditor must learn about new HSYNC3 / HSYNCPARAM
	// data so that PostRefresh can call RecomputeGroups and the new
	// provider group becomes visible. Without this, a zone introduced
	// after a non-auditor restart (or, equivalently, a zone whose
	// HSYNC3 set changes while the auditor is running) never enters
	// the auditor's group map.
	switch tdns.Globals.App.Type {
	case AppTypeMPAgent, AppTypeMPCombiner, AppTypeMPSigner, AppTypeMPAuditor:
		var err error
		analysis.HsyncChanged, analysis.HsyncStatus, err = HsyncChanged(mpzd.ZoneData, new_zd)
		if err != nil {
			lg.Error("HsyncChanged failed", "zone", mpzd.ZoneName, "err", err)
		}
	}

	// The zone's active instructions before the refresh, for the hook at
	// activation (onActiveChanged) and the catch-up's reasons, which
	// PostRefresh reads with the active instructions after it. Whether this
	// is the zone's first load is kept until a PostRefresh takes it:
	// PostRefresh has no such signal of its own, and at a first load tdns
	// runs it only once the zone is ready.
	switch tdns.Globals.App.Type {
	case AppTypeMPAgent, AppTypeMPAuditor:
		analysis.ActiveBefore = mpzd.instructions()
		prev := mpzd.MP.RefreshAnalysis
		analysis.FirstLoad = mpzd.FirstZoneLoad || (prev != nil && prev.FirstLoad)
	}
	if tdns.Globals.App.Type == AppTypeMPAgent && mp != nil {
		oldApex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
		newApex, _ := new_zd.OwnerForAnalysis(new_zd.ZoneName)
		analysis.KeyChanged = !sameKeyRRset(oldApex, newApex)
	}

	// DNSKEY change detection — only for roles that actually act on
	// DNSKEY data (signer signs zones; agent contributes its own
	// DNSKEYs; combiner needs awareness). The auditor observes
	// signing but never signs, so DnskeysChangedNG is skipped for it.
	switch tdns.Globals.App.Type {
	case AppTypeMPAgent, AppTypeMPCombiner, AppTypeMPSigner:
		dnskeyschanged, err := mpzd.DnskeysChangedNG(new_zd)
		if err != nil {
			lg.Error("DnskeysChangedNG failed", "zone", mpzd.ZoneName, "err", err)
		}

		// For multi-provider zones, compute local DNSKEY adds/removes
		if dnskeyschanged && mpzd.Options[tdns.OptMultiProvider] {
			switch tdns.Globals.App.Type {
			case AppTypeMPAgent:
				// KEYSTATE is the sole source of truth for local vs foreign DNSKEYs.
				mpzd.RequestAndWaitForKeyInventory(context.Background(), tm)
				var self AgentId
				if mp != nil {
					self = AgentId(mp.Identity)
				}
				newApex, _ := new_zd.OwnerForAnalysis(new_zd.ZoneName) // the copy the distribution is judged against
				dnskeyschanged, analysis.DnskeyStatus, err = mpzd.LocalDnskeysFromKeystate(self, newApex)
				switch {
				case errors.Is(err, errNoRoleInZone):
					lg.Debug("no DNSKEYs of this provider are distributed", "zone", mpzd.ZoneName, "reason", err)
				case err != nil:
					lg.Error("LocalDnskeysFromKeystate failed", "zone", mpzd.ZoneName, "err", err)
				}
				if analysis.DnskeyStatus == nil {
					dnskeyschanged = false
				}
			default:
				dnskeyschanged, analysis.DnskeyStatus, err = mpzd.LocalDnskeysChanged(new_zd)
				if err != nil {
					lg.Error("LocalDnskeysChanged failed", "zone", mpzd.ZoneName, "err", err)
				}
			}
		}
		analysis.DnskeyChanged = dnskeyschanged
	}

	// Combiner: snapshot upstream data before applying contributions to new_zd
	switch tdns.Globals.App.Type {
	case AppTypeMPCombiner:
		mpzd.snapshotUpstreamData(new_zd)
	}

	// Recompute multi-provider membership and signing state on the new zone data.
	// Use a temporary wrapper around new_zd to run populateMPdata, then
	// copy computed state to the persistent mpzd. One refresh or hand-over
	// at a time (mpDataLock), through the signer's switch.
	mpMu := mpDataLock(mpzd.ZoneName)
	mpMu.Lock()
	var resign bool
	if new_zd.Options[tdns.OptMultiProvider] {
		kdb := new_zd.KeyDB
		if kdb == nil {
			kdb = mpzd.KeyDB
		}
		newApex, _ := new_zd.OwnerForAnalysis(new_zd.ZoneName)
		newMpzd := &MPZoneData{
			ZoneData:  new_zd,
			MP:        &MPState{},
			MPOptions: make(map[tdns.ZoneOption]bool),
		}
		// A combiner or signer that holds a hand-over signs by the set
		// handed, not by the incoming copy (S10, S11). A signer that waits for its agent's hand-over signs by the
		// set it last signed by, unchanged by its copy, where it has one
		// (rule 5). Every other role advances its signing set by the
		// instructions it acts by: the active ones, from the thaw (S7), not
		// a newer copy.
		signing, handed := actingHeld.Load().signingSet(mpzd.ZoneName)
		if !handed && tdns.Globals.App.Type == AppTypeMPSigner && signerWaits(mpzd.ZoneName, newApex) {
			signing, handed = mpzd.lastSigningSet(kdb)
		}
		if !handed {
			var changed bool
			if signing, changed = mpzd.advanceSigningSet(newMpzd.instructions(), kdb); changed {
				mpzd.MP.SigningChanged = true
			}
		}
		newMpzd.populateMPdata(mp, signing)
		// under the zone's lock, as a hand-over sets the two
		mpzd.Lock()
		mpzd.MP.MPdata = newMpzd.MP.MPdata
		mpzd.MPOptions = newMpzd.MPOptions
		mpzd.Unlock()
	}

	// Signer: dynamically enable/disable inline-signing based on HSYNC
	// analysis. The other signers whose DNSKEYs are kept as foreign rows are
	// the ones handed (KeySigners, plan S11), or the incoming zone's signing
	// set: the ones its signers= names, and those leaving it (#147).
	if mpzd.MP.MPdata != nil && tdns.Globals.App.Type == AppTypeMPSigner {
		others := mpzd.MP.MPdata.Signing.others(mpzd.MP.MPdata.OurLabel)
		if handed, ok := actingHeld.Load().roles(mpzd.ZoneName); ok {
			others = othersIn(handed.KeySigners, labelOfIdentity(handed, ourHsyncIdentities(mp)))
		}
		_, resign = mpzd.signerSwitch(new_zd, others, mp)
	}
	mpMu.Unlock()
	if resign {
		sendResignRequest(tdns.Conf.Internal.ResignQ, mpzd.ZoneName)
	}

	// Combiner: HSYNC match check and combine with local changes on new_zd.
	switch tdns.Globals.App.Type {
	case AppTypeMPCombiner:
		if analysis.HsyncChanged {
			matched, _, _ := (&MPZoneData{ZoneData: new_zd}).matchHsyncIdentity(ourHsyncIdentities(mp))
			if matched && !mpzd.MPOptions[OptMPDisallowEdits] {
				lg.Info("HSYNC RRset confirms we are a listed provider and signer, enabling allow-edits", "zone", mpzd.ZoneName)
				mpzd.MPOptions[tdns.OptAllowEdits] = true
			} else if matched && mpzd.MPOptions[OptMPDisallowEdits] {
				lg.Info("HSYNC RRset confirms we are a listed provider but not a signer, edits disallowed", "zone", mpzd.ZoneName)
				mpzd.MPOptions[tdns.OptAllowEdits] = false
			} else {
				lg.Info("HSYNC RRset does not list us as a provider, disabling allow-edits", "zone", mpzd.ZoneName)
				mpzd.MPOptions[tdns.OptAllowEdits] = false
			}
		}

		// A provider zone has no HSYNC records and so never has allow-edits,
		// but the combiner writes to it all the same: what agents contribute
		// of its configured record types, the _signal KEYs. The upstream's
		// copy has none of that, so it goes onto the incoming zone here, by
		// the combine a customer zone's contributions go through. Without it
		// a refresh served the provider zone without its _signal KEYs until
		// the next contribution change (the refresh side of tdns-mp #171).
		//
		// The stored at-ns instructions are asked about first, as at a start
		// and at a re-apply: the names of a zone that does not say pubkey are
		// retracted, and the combine does not bring them back. When the
		// instructions cannot be read the zone keeps the names it has.
		//
		// Not at the zone's first load. Its persisted contributions are in
		// memory by then (restoreContributions), and the consent pass cannot
		// retract a name from a zone that has no data yet: it leaves the
		// name for the zone's startup re-apply. Combined here, such a name
		// would be in the first copy the zone serves, for a customer that
		// has withdrawn it. At a first load the re-apply puts the names on
		// instead, after the consent pass (ApplyPendingSignalKeys).
		isProvider := GetProviderZoneRRtypes(mpzd.ZoneName) != nil && mpzd.HasPublishedData()
		if isProvider {
			if hdb := NewHsyncDB(mpzd.KeyDB); hdb != nil {
				if _, err := withdrawAllSignalKeysWithoutConsent(hdb); err != nil {
					lg.Error("failed to load publish instructions; the provider zone's _signal KEYs are not checked against the customers' consent",
						"zone", mpzd.ZoneName, "err", err)
				}
			}
		}

		if mpzd.MPOptions[tdns.OptAllowEdits] || isProvider {
			// Wrap new_zd with the persistent MP state so that
			// CombineWithLocalChanges can read AgentContributions
			// and CombinerData from the real MPState.
			tmpMpzd := &MPZoneData{
				ZoneData:  new_zd,
				MP:        mpzd.MP,
				MPOptions: mpzd.MPOptions,
			}

			// One batch on the draft: the combine and the signature TXT go
			// into new_zd's Data, and the refresh publish that consumes it
			// is the publish.
			lg.Info("combining with local changes", "zone", mpzd.ZoneName)
			success, _, err := tmpMpzd.combineAndPublish(mp)
			if err != nil {
				lg.Error("CombineWithLocalChanges failed", "zone", mpzd.ZoneName, "err", err)
			} else if success {
				lg.Info("local changes applied to new zone data", "zone", mpzd.ZoneName)
			}
		}
	}

	// Store analysis for post-refresh callbacks
	mpzd.MP.RefreshAnalysis = analysis
}

// signerSwitch is the signer's inline-signing switch and multi-signer mode,
// by its multi-provider data, and the other signers' DNSKEYs kept as
// foreign rows: at a refresh (MPPreRefresh) from the incoming zone, others
// being the providers whose rows are kept; at a hand-over (incoming nil,
// plan S11) over the zone it serves, whose DNSKEY RRset the keystore gives:
// out of multi-signer mode every foreign row goes, and in it the rows the
// last incoming zone lacked are judged again by the providers handed.
// switched says the inline-signing switch moved; resign, that the foreign
// rows changed, for a re-sign the caller asks for once it lets go of
// mpDataLock, since the request can wait on a full ResignQ.
func (mpzd *MPZoneData) signerSwitch(incoming *tdns.ZoneData, others []string, mp *MultiProviderConf) (switched, resign bool) {
	// The multi-provider data and MPOptions under the zone's lock, which a
	// refresh and a hand-over set them under; not held across
	// SetRuntimeOption, which takes it.
	mpzd.Lock()
	shouldSign := mpzd.MP.MPdata.WeAreSigner
	otherSigners := mpzd.MP.MPdata.OtherSigners
	mpzd.Unlock()
	was := mpzd.ZoneData
	if incoming != nil {
		was = incoming
	}
	if shouldSign && !was.Options[tdns.OptInlineSigning] {
		lg.Info("HSYNC SIGN=true, enabling inline-signing", "zone", mpzd.ZoneName)
	} else if !shouldSign && was.Options[tdns.OptInlineSigning] {
		lg.Info("HSYNC SIGN=false, disabling inline-signing", "zone", mpzd.ZoneName)
	}
	switched = was.Options[tdns.OptInlineSigning] != shouldSign
	// The switch is ours, not the configuration's: recorded on the served
	// zone as a run-time option, at every refresh, so that a config update
	// (config reload-zones, a zone reload) does not take it away until the
	// next transfer (tdns-mp #144). On the incoming zone too: its options
	// are the served zone's as they were when the fetch began. That map is
	// the one the served zone had, which is read without a lock, so the
	// incoming zone gets a map of its own and the old one is not written.
	mpzd.ZoneData.SetRuntimeOption(tdns.OptInlineSigning, shouldSign)
	if incoming != nil && incoming.Options[tdns.OptInlineSigning] != shouldSign {
		opts := make(map[tdns.ZoneOption]bool, len(incoming.Options)+1)
		for o, on := range incoming.Options {
			opts[o] = on
		}
		opts[tdns.OptInlineSigning] = shouldSign
		incoming.Options = opts
	}
	// Multi-signer mode on a copy of the options: a hand-over and a refresh
	// may each set it, and neither writes the map the other reads.
	isMS := shouldSign && otherSigners > 0
	mpzd.Lock()
	if isMS != mpzd.MPOptions[tdns.OptMultiSigner] {
		if isMS {
			lg.Info("multi-signer mode detected", "zone", mpzd.ZoneName, "otherSigners", otherSigners)
		} else {
			lg.Info("no longer multi-signer", "zone", mpzd.ZoneName)
		}
		opts := maps.Clone(mpzd.MPOptions)
		if opts == nil {
			opts = map[tdns.ZoneOption]bool{}
		}
		opts[tdns.OptMultiSigner] = isMS
		mpzd.MPOptions = opts
	}
	mpzd.Unlock()
	if !shouldSign {
		return switched, false
	}
	// The other signers' DNSKEYs are found where they arrive, in the
	// incoming zone, and kept as foreign rows in the keystore: served from
	// the next publish, never signing. A refresh collects its DNSKEY RRset
	// before this callback, so a change here is served by the re-sign
	// requested below rather than by this refresh.
	var changed bool
	var err error
	switch {
	case incoming != nil:
		changed, err = mpzd.syncForeignDNSKEYs(incoming, isMS, others)
	case !isMS:
		changed, err = mpzd.syncForeignDNSKEYs(nil, false, nil)
	default:
		changed = mpzd.dropWithdrawnForeignDNSKEYs(mp)
	}
	if err != nil {
		lg.Error("syncing foreign DNSKEYs failed", "zone", mpzd.ZoneName, "err", err)
		return switched, false
	}
	return switched, changed
}

// implicitDelegationChange is the refresh's implicit delegation-change
// detection: tdns's diff of the old and new apex, NS, glue and, for a zone
// tdns runs alone, the DS set it derives from the served SEP keys. For a
// multi-provider zone that DS dimension is dropped: its DS set is the
// owner's intent (design §4, S5), ds=1 keys and nothing else, and it reaches
// the parent through the leader's intent-driven sync alone. A refresh that
// brings another provider's new KSK, still mpdist at its provider, would
// otherwise send that key's DS to the parent at once (tdns-mp #112).
func implicitDelegationChange(mpzd *MPZoneData, new_zd *tdns.ZoneData) (bool, tdns.DelegationSyncStatus, error) {
	changed, dss, err := mpzd.DelegationDataChangedNG(new_zd)
	if err != nil || !mpzd.Options[tdns.OptMultiProvider] {
		return changed, dss, err
	}
	return withoutImplicitDS(dss)
}

// withoutImplicitDS drops the DS dimension of an implicit delegation-change
// status and says whether what is left, NS and glue, changed.
func withoutImplicitDS(dss tdns.DelegationSyncStatus) (bool, tdns.DelegationSyncStatus, error) {
	dss.DSAdds, dss.DSRemoves, dss.NewDS, dss.NewDSKnown = nil, nil, nil, false
	changed := len(dss.NsAdds)+len(dss.NsRemoves)+len(dss.AAdds)+len(dss.ARemoves)+len(dss.AAAAAdds)+len(dss.AAAARemoves) > 0
	dss.InSync = !changed
	return changed, dss, nil
}

// followParentSyncParam keeps an agent's delegation-sync option for a
// multi-provider zone in step with the zone's HSYNCPARAM. The agents sync
// the zone's delegation with its parent when, and only while, HSYNCPARAM
// says parentsync=agent. With parentsync=owner, or with no HSYNCPARAM, the
// owner syncs it, and what an agent sent to the parent could undo what the
// owner put there. A parentsync option in the agent's own configuration
// does not change that: the owner's word decides.
//
// The option used to be turned on at a refresh and never off (tdns-mp
// #200): after the owner took the sync over, the leader went on syncing the
// parent at every lease renewal. It runs after every refresh, the first
// load's included, before PostRefresh: the delegation sync a refresh asks
// for reads the option.
//
// The option is a run-time option (SetRuntimeOption): the zone gets a new
// options map rather than a write into the one that the query and refresh
// paths read without a lock, and a config update does not take it away.
// When the owner takes the sync over, what this agent has scheduled for the
// zone's parent ends here: a held NOTIFY is dropped, and an ask or a check
// that waits finds no chain (delegationSyncOwnerSyncs). An election, a
// lease renewal included, finds the option off and asks for nothing.
//
// givenBack says the owner has given the sync back to the agents: the
// option went on at a refresh after the zone's first. The callback then runs,
// after PostRefresh, the leader's setup that an election skipped while the
// owner synced the zone (delegationSyncGivenBack). At a first load the option
// comes on too, and that is no give-back: at start-up the zone's election runs
// the setup. A zone whose first load comes after its group already has a
// leader (a zone added to a running agent, a late first transfer) has no
// election of its own, and waits for its group's next lease renewal.
//
// The option follows HSYNCPARAM only for a zone whose records name this
// agent (matchHsyncIdentity, as the first-load detection asks; an OFF record
// counts). For any other zone it is off, and what this agent had scheduled
// for the zone's parent ends, a sync under way included. An option that
// comes on because a refresh names this agent where the last one did not is
// no give-back either: the zone arrives, and is taken up as an arrival.
//
// A zone whose HSYNCPARAM cannot be read keeps the option it has.
func (conf *Config) followParentSyncParam(mpzd *MPZoneData) (givenBack bool) {
	if tdns.Globals.App.Type != AppTypeMPAgent || !mpzd.Options[tdns.OptMultiProvider] {
		return false
	}
	// parentsync changes only at a step (design 3.3): the step's sets. An
	// OFF record names nobody (plan S3).
	in := mpzd.instructions()
	byAgents := in != nil && in.HasParam && mpzd.roles().ParentSync == core.HsyncParentSyncAgent
	named, _, _ := mpzd.matchHsyncIdentity(ourHsyncIdentities(conf.MpConfig()))
	mpzd.EnsureMP()
	first := !mpzd.MP.ParentSyncFollowed
	wasNamed := mpzd.MP.ParentSyncNamed
	mpzd.MP.ParentSyncFollowed = true
	mpzd.MP.ParentSyncNamed = named

	// Whatever the option says: an agent that the records name and that no
	// longer takes part in the zone (no role) sends nothing to the parent. The syncher asks the same (stillParticipates),
	// but only when a sync is asked for, and a refresh that only sets this
	// agent's record OFF asks for none. The option stays as it is.
	if named && !conf.stillParticipates(mpzd.ZoneName) && conf.endDelegationSyncWork(mpzd.ZoneName) {
		lg.Info("this agent takes no part in the zone: what it had scheduled for the parent ends", "zone", mpzd.ZoneName)
	}

	byAgents = byAgents && named
	if byAgents == mpzd.Options[tdns.OptParentSync] {
		return false
	}
	mpzd.SetRuntimeOption(tdns.OptParentSync, byAgents)
	switch {
	case byAgents:
		lg.Info("HSYNCPARAM parentsync=agent detected on refresh, enabling delegation sync", "zone", mpzd.ZoneName)
		return !first && wasNamed
	case !named:
		lg.Info("this agent is not named in the zone's records: it sends nothing to the parent", "zone", mpzd.ZoneName)
		conf.endDelegationSyncWork(mpzd.ZoneName)
	default:
		lg.Info("HSYNCPARAM does not say parentsync=agent: the zone's owner syncs its delegation, and this agent no longer sends anything to the parent", "zone", mpzd.ZoneName)
		conf.delegationSyncOwnerSyncs(mpzd.ZoneName)
	}
	return false
}

// PostRefresh runs after the hard flip for all MP roles.
// Sends notifications to SyncQ, DelegationSyncQ based on
// the pre-refresh analysis results.
func (mpzd *MPZoneData) PostRefresh(tm *MPTransportBridge, msgQs *MsgQs) {
	if tdns.Globals.App.Type == AppTypeMPAuditor && mpzd.Options[tdns.OptMultiProvider] {
		if tm != nil && tm.agentRegistry != nil && tm.agentRegistry.AuditState != nil {
			tm.agentRegistry.AuditState.RefreshZoneHSYNCConfig(mpzd.ZoneName)
		}
	}
	if mpzd.MP == nil || mpzd.MP.RefreshAnalysis == nil {
		return
	}
	analysis := mpzd.MP.RefreshAnalysis
	mpzd.MP.RefreshAnalysis = nil // clear after use

	// The customer's consent to at-ns, read from the zone as this refresh
	// left it. The agent sends no new instruction when the owner takes
	// pubkey away, so the combiner withdraws the stored one's signal names
	// here.
	if tdns.Globals.App.Type == AppTypeMPCombiner && analysis.HsyncStatus != nil && analysis.HsyncStatus.ParamChanged {
		if err := mpzd.withdrawZoneSignalKeysWithoutConsent(NewHsyncDB(mpzd.KeyDB)); err != nil {
			lg.Error("failed to load publish instructions; the zone's at-ns publication is not checked against the customer's consent until the provider zone's next refresh",
				"zone", mpzd.ZoneName, "err", err)
		}
	}

	// Delegation sync notification
	if analysis.DelegationChanged && mpzd.Options[tdns.OptParentSync] {
		lg.Info("delegation data has changed, sending update to DelegationSyncEngine", "zone", mpzd.ZoneName)
		mpzd.DelegationSyncQ <- tdns.DelegationSyncRequest{
			Command:    "SYNC-DELEGATION",
			ZoneName:   mpzd.ZoneName,
			ZoneData:   mpzd.ZoneData,
			SyncStatus: analysis.DelegationStatus,
		}
	}

	// DNSKEY change routing
	if analysis.DnskeyChanged {
		switch tdns.Globals.App.Type {
		case AppTypeMPAgent:
			if mpzd.Options[tdns.OptMultiProvider] {
				lg.Info("local DNSKEYs changed, sending to HsyncEngine", "zone", mpzd.ZoneName)
				mpzd.SyncQ <- SyncRequest{
					Command:      "SYNC-DNSKEY-RRSET",
					ZoneName:     ZoneName(mpzd.ZoneName),
					ZoneData:     mpzd.ZoneData,
					DnskeyStatus: analysis.DnskeyStatus,
				}
			}
		case AppTypeMPCombiner:
			lg.Debug("incoming DNSKEYs have changed, no action needed for combiner", "zone", mpzd.ZoneName)
		}
	}

	// The hook at activation (plan S3), from the zone's active instructions
	// before the refresh and after it: the post-refresh callback has noted
	// the copy first, which from S7 moves the active serial only at a
	// zone's first record (the thaw moves it after that). It runs at
	// every first load, whatever the store holds, and at every change of the
	// active instructions; a refresh that changes nothing else of them (a
	// TTL, an order, an OFF record's fields) runs nothing.
	switch tdns.Globals.App.Type {
	case AppTypeMPAgent, AppTypeMPAuditor:
		if !mpzd.Options[tdns.OptMultiProvider] {
			break
		}
		from, to := analysis.ActiveBefore, mpzd.instructions()
		if analysis.FirstLoad {
			from = nil
		}
		changed := analysis.FirstLoad || !sameInstructions(from, to)
		if changed {
			mpzd.onActiveChanged(tm, from, to)
		}
		// What the refresh calls for of the catch-up: the requests of the
		// zone's first load, of a standing that rose and of a provider that
		// entered a role, and the end of those that no longer apply.
		if tdns.Globals.App.Type == AppTypeMPAgent && tm != nil && tm.catchUp != nil {
			catchUpReasons(analysis, from, to, tm.catchUp.self, changed)
			tm.catchUp.afterRefresh(ZoneName(mpzd.ZoneName), analysis)
		}
	}
}

// onActiveChanged runs what follows from a change of the zone's active
// instructions, from the two active readings (plan S3); from is nil at a
// first load. The identities whose ON records entered or left go to the
// hsync engine, whose ApplyHsyncDiff recomputes the provider groups (and
// through them PR #186's callbacks). Then, at the agent, membership step 8's
// one check of the zone's election, after the groups are recomputed: called
// before it, a zone reduced to one provider would still find its old group
// (#149).
func (mpzd *MPZoneData) onActiveChanged(tm *MPTransportBridge, from, to *Instructions) {
	lg.Info("the zone's active instructions changed", "zone", mpzd.ZoneName, "from", instructionsName(from), "to", instructionsName(to))
	if tm == nil || tm.agentRegistry == nil {
		return
	}
	ar := tm.agentRegistry
	entered, left := recordsEntering(from, to), recordsEntering(to, from)
	diff := hsync.HsyncDiff{Entered: entered, Left: left}
	switch tdns.Globals.App.Type {
	case AppTypeMPAgent:
		if ar.HsyncEngine != nil {
			_ = ar.HsyncEngine.ApplyHsyncDiff(hsync.ZoneName(mpzd.ZoneName), diff)
		}
		zone := ZoneName(mpzd.ZoneName)
		if lem := ar.LeaderElectionManager; lem != nil {
			switch {
			case mpzd.Options[tdns.OptMultiProvider] && hasHSYNC3(to):
				// every group with two or more voting members elects,
				// whatever its parentsync: transitions need a leader
				// (design 3, plan S7)
				lem.zoneChanged(zone)
			case mpzd.Options[tdns.OptMultiProvider] && !hasHSYNC3(to):
				// The owner removed every provider's record: nobody
				// leads the zone now. When records come back,
				// zoneChanged elects anew, and the new lead's set-up
				// runs: a lead kept from before would skip it.
				lem.dropZoneElection(zone)
			}
		}
	case AppTypeMPAuditor:
		if ar.HsyncEngine != nil {
			// ApplyHsyncDiff -> OnHsync3Changed recomputes the groups.
			_ = ar.HsyncEngine.ApplyHsyncDiff(hsync.ZoneName(mpzd.ZoneName), diff)
		} else if ar.ProviderGroupManager != nil {
			ar.ProviderGroupManager.RecomputeGroups()
		}
	}
}

// catchUpReasons fills the catch-up's reasons into the refresh's analysis
// from the two active readings: self's standing before and after, the
// providers that entered servers= or signers= (peer-role, widened to every
// provider that enters either list: a provider put back, design 5.1), and
// whether the active instructions changed.
func catchUpReasons(a *ZoneRefreshAnalysis, from, to *Instructions, self AgentId, changed bool) {
	pBefore, before := participantsOf(from)
	pAfter, after := participantsOf(to)
	a.StandingBefore = standingIn(from, pBefore, before, string(self))
	a.StandingAfter = standingIn(to, pAfter, after, string(self))
	a.HsyncChanged = changed
	a.NewVoters = nil
	newVoter := func(id string) {
		if !slices.Contains(a.NewVoters, AgentId(id)) {
			a.NewVoters = append(a.NewVoters, AgentId(id))
		}
	}
	// The identities newly among the voting members.
	for _, id := range after {
		if !isAmong(before, AgentId(id)) {
			newVoter(id)
		}
	}
	if from == nil || to == nil || !to.HasParam {
		return
	}
	for _, list := range [][2][]string{{from.Servers, to.Servers}, {from.Signers, to.Signers}} {
		was := identities(from.providers(list[0]))
		for _, id := range identities(to.providers(list[1])) {
			if !isAmong(was, AgentId(id)) {
				newVoter(id)
			}
		}
	}
}

// recordsEntering are the identities of b's ON records that a has no ON
// record for.
func recordsEntering(a, b *Instructions) []hsync.PeerID {
	if b == nil {
		return nil
	}
	var out []hsync.PeerID
	for _, r := range b.Records {
		if _, ok := a.labelOf(r.Identity); !ok {
			out = append(out, hsync.PeerID(r.Identity))
		}
	}
	return out
}

// instructionsName names instructions in a log line: serial and digest.
func instructionsName(in *Instructions) string {
	if in == nil {
		return "none"
	}
	return fmt.Sprintf("%d (%s)", in.Serial, in.Digest())
}
