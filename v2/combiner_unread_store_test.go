package tdnsmp

import (
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// unreadStoreZone is a combiner zone whose stored contributions could not
// be read when it was set up: the store holds sender's NS ns8, the zone
// holds none of it. storedNS is sender's stored NS targets.
func unreadStoreZone(t *testing.T, zone, sender string) (*MPZoneData, *HsyncDB, func() string) {
	t.Helper()
	asMPDaemon(t, AppTypeMPCombiner)
	kdb := newMPTestKeyDB(t)
	hdb := NewHsyncDB(kdb)
	if err := hdb.InitHsyncTables(); err != nil {
		t.Fatalf("InitHsyncTables: %v", err)
	}
	mpzd := combinerTestZone(t, zone)
	stored := nsContribution(zone, "ns8."+zone)[zone][0]
	if err := SaveContributions(hdb, zone, sender, map[string]map[uint16]core.RRset{zone: {dns.TypeNS: stored}}); err != nil {
		t.Fatalf("SaveContributions: %v", err)
	}
	storedNS := func() string {
		t.Helper()
		all, err := LoadAllContributions(hdb)
		if err != nil {
			t.Fatalf("LoadAllContributions: %v", err)
		}
		rrset := all[zone][sender][zone][dns.TypeNS]
		var targets []string
		for _, rr := range rrset.RRs {
			targets = append(targets, rr.(*dns.NS).Ns)
		}
		slices.Sort(targets)
		return strings.Join(targets, " ")
	}
	mpzd.restoreContributions(hdb, nil, false) // the snapshot could not be read
	return mpzd, hdb, storedNS
}

// nsUpdate is sender's update of the zone's NS, as it reaches the combiner.
func nsUpdate(sender, zone, op, target string) *CombinerSyncRequest {
	return &CombinerSyncRequest{SenderID: sender, DeliveredBy: sender, Zone: zone,
		Operations:     []core.RROperation{{Operation: op, RRtype: "NS", Records: []string{zone + " 3600 IN NS " + target}}},
		DistributionID: nextDistributionID(), Timestamp: time.Now()}
}

// heldNS is sender's NS targets in the zone's memory.
func heldNS(mpzd *MPZoneData, sender, zone string) string {
	mpzd.Lock()
	defer mpzd.Unlock()
	var targets []string
	if mpzd.MP != nil {
		for _, rr := range mpzd.MP.AgentContributions[sender][zone][dns.TypeNS].RRs {
			targets = append(targets, rr.(*dns.NS).Ns)
		}
	}
	slices.Sort(targets)
	return strings.Join(targets, " ")
}

// While a zone's store has not been read, an update changes nothing and is
// answered PENDING, not refused: the sender's reliable queue keeps it and
// sends it again. Sent again once the store can be read, it is saved beside
// the stored rows. A refusal would close it in the queue, and the
// contribution would stay missing until another send.
func TestAnUpdateBeforeTheStoreIsReadIsLeftWithItsSender(t *testing.T) {
	const zone = "kept-update.example."
	const sender = "agent-a"
	mpzd, hdb, storedNS := unreadStoreZone(t, zone, sender)
	req := nsUpdate(sender, zone, "add", "ns2."+zone)

	mpzd.Ready = false // not loaded yet: the store is not read again
	if resp := CombinerProcessUpdate(req, nil, nil, hdb, nil); resp.Status != "pending" {
		t.Fatalf("an update before the store was read: %q (%s), want pending", resp.Status, resp.Message)
	}
	if got := heldNS(mpzd, sender, zone); got != "" {
		t.Errorf("an update before the store was read changed the zone: it holds %q", got)
	}
	if got, want := storedNS(), "ns8."+zone; got != want {
		t.Errorf("an update before the store was read changed the store: %q, want %q", got, want)
	}

	mpzd.Ready = true // loaded: the update sent again reads the store first
	if resp := CombinerProcessUpdate(req, nil, nil, hdb, nil); resp.Status == "pending" || resp.Status == "error" {
		t.Fatalf("the update sent again once the store can be read: %q (%s)", resp.Status, resp.Message)
	}
	if got, want := storedNS(), "ns2."+zone+" ns8."+zone; got != want {
		t.Errorf("the update sent again was not saved beside the stored rows: %q, want %q", got, want)
	}
}

// Before the zone's store is read, a REPLACE changes nothing, in memory or
// in the store, and neither it nor the same REPLACE sent again is
// confirmed: each is answered PENDING. Changed in memory and refused only
// by the save, the copy sent again found nothing to change and was
// confirmed without being saved.
func TestAReplaceBeforeTheStoreIsReadChangesNothing(t *testing.T) {
	const zone = "unread-replace.example."
	const sender = "agent-a"
	mpzd, hdb, storedNS := unreadStoreZone(t, zone, sender)

	mpzd.Ready = false // not loaded yet: the store is not read again
	for i := 1; i <= 2; i++ {
		if resp := CombinerProcessUpdate(nsUpdate(sender, zone, "replace", "ns2."+zone), nil, nil, hdb, nil); resp.Status != "pending" {
			t.Errorf("REPLACE %d before the store was read: %q (%s), want pending", i, resp.Status, resp.Message)
		}
		if got := heldNS(mpzd, sender, zone); got != "" {
			t.Errorf("REPLACE %d before the store was read changed the zone: it holds %q", i, got)
		}
	}
	if got, want := storedNS(), "ns8."+zone; got != want {
		t.Errorf("a REPLACE before the store was read changed the store: %q, want %q", got, want)
	}

	mpzd.Ready = true
	if resp := CombinerProcessUpdate(nsUpdate(sender, zone, "replace", "ns2."+zone), nil, nil, hdb, nil); resp.Status == "pending" || resp.Status == "error" {
		t.Fatalf("a REPLACE once the store can be read: %q (%s)", resp.Status, resp.Message)
	}
	if got, want := storedNS(), "ns2."+zone; got != want {
		t.Errorf("a REPLACE once the store can be read: stored %q, want %q", got, want)
	}
}

// While a zone's store has not been read (the snapshot could not be read
// when the zone was set up), a change of its contributions is not saved:
// saving the sender's map would replace its stored rows with part of
// them. The re-apply reads the store, and changes are saved from then on.
func TestAnUpdateBeforeTheStoreIsReadLeavesItAlone(t *testing.T) {
	const zone = "unread-store.example."
	const sender = "agent-a"
	mpzd, hdb, storedNS := unreadStoreZone(t, zone, sender)

	if _, err := mpzd.AddCombinerData(sender, nsContribution(zone, "ns2."+zone)); err == nil {
		t.Error("an update before the store was read was accepted")
	}
	if got, want := storedNS(), "ns8."+zone; got != want {
		t.Errorf("the update replaced the stored rows: %q, want %q", got, want)
	}

	if _, err := CombinerReapplyContributions(zone, hdb); err != nil {
		t.Fatalf("CombinerReapplyContributions: %v", err)
	}
	if _, err := mpzd.AddCombinerData(sender, nsContribution(zone, "ns2."+zone)); err != nil {
		t.Fatalf("an update after the re-apply: %v", err)
	}
	if got := storedNS(); !strings.Contains(got, "ns2."+zone) || !strings.Contains(got, "ns8."+zone) {
		t.Errorf("after the re-apply the update was not saved beside the stored rows: %q", got)
	}
}
