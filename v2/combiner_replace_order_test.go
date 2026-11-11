package tdnsmp

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The combiner's side of the agent's ordering guard: a REPLACE the queue
// delivers after a newer one from the same sender is stale; a later one, or
// one in the same instant with a higher distribution id, is not; other
// senders and types are ordered on their own; a request without a time is
// never stale.
func TestCombinerTellsAStaleReplace(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	// A zone of this run's own: the origins are kept in a package-level map,
	// so a repeated run (-count) must not meet the previous run's newest.
	zone := fmt.Sprintf("cell-%d.example.", time.Now().UnixNano())
	req := func(sender string, ts time.Time, dist string) *CombinerSyncRequest {
		return &CombinerSyncRequest{SenderID: sender, Zone: zone, Timestamp: ts, DistributionID: dist}
	}
	if stale, _, _, _ := staleCombinerReplace(req("agent.a.", t0.Add(time.Second), "6aa51b6c"), zone, dns.TypeDNSKEY); stale {
		t.Fatal("the first REPLACE is stale")
	}
	if stale, _, _, _ := staleCombinerReplace(req("agent.a.", t0, "6aa51b6a"), zone, dns.TypeDNSKEY); !stale {
		t.Fatal("an older REPLACE after a newer one is not stale")
	}
	if stale, _, _, _ := staleCombinerReplace(req("agent.a.", t0.Add(time.Second), "6aa51b6d"), zone, dns.TypeDNSKEY); stale {
		t.Fatal("the same instant with a higher distribution id is stale")
	}
	if stale, _, _, _ := staleCombinerReplace(req("agent.a.", t0.Add(time.Second), "6aa51b6b"), zone, dns.TypeDNSKEY); !stale {
		t.Fatal("the same instant with a lower distribution id is not stale")
	}
	if stale, _, _, _ := staleCombinerReplace(req("agent.a.", t0, "6aa51b60"), zone, dns.TypeNS); stale {
		t.Fatal("another type from the same sender was gated by the DNSKEY origin")
	}
	if stale, _, _, _ := staleCombinerReplace(req("agent.b.", t0, "6aa51b60"), zone, dns.TypeDNSKEY); stale {
		t.Fatal("another sender was gated by the first sender's origin")
	}
	if stale, _, _, _ := staleCombinerReplace(req("agent.a.", time.Time{}, ""), zone, dns.TypeDNSKEY); stale {
		t.Fatal("a request without a time was called stale")
	}
}

// The combiner's guard is kept on disk: after a restart a queued older
// REPLACE stays refused, so it cannot put back what the leader's withdrawal
// took away from a provider that is still a signer. A newer one goes on.
func TestCombinerRefusesAStaleReplaceAfterARestart(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	zone := fmt.Sprintf("restart-%d.example.", time.Now().UnixNano())
	hdb := NewHsyncDB(newMPTestKeyDB(t))
	if err := hdb.InitCombinerEditTables(); err != nil {
		t.Fatalf("InitCombinerEditTables: %v", err)
	}
	forget := func() {
		combinerReplaceOrigins.mu.Lock()
		defer combinerReplaceOrigins.mu.Unlock()
		for k := range combinerReplaceOrigins.m {
			if strings.HasPrefix(k, zone+"|") {
				delete(combinerReplaceOrigins.m, k)
			}
		}
		combinerReplaceOrigins.hdb = nil
	}
	t.Cleanup(forget)
	req := func(ts time.Time, dist string) *CombinerSyncRequest {
		return &CombinerSyncRequest{SenderID: "agent.b.", Zone: zone, Timestamp: ts, DistributionID: dist}
	}

	loadCombinerReplaceOrigins(hdb)
	// the leader's withdrawal of b's NS, in b's name
	if stale, _, _, _ := staleCombinerReplace(req(t0.Add(time.Second), "6aa51b6c"), zone, dns.TypeNS); stale {
		t.Fatal("the withdrawal is stale")
	}
	forget() // the restart
	loadCombinerReplaceOrigins(hdb)
	if stale, applied, _, _ := staleCombinerReplace(req(t0, "6aa51b6a"), zone, dns.TypeNS); !stale {
		t.Fatal("after a restart, b's older REPLACE is not stale")
	} else if applied.DistID != "6aa51b6c" {
		t.Errorf("applied %+v, want the withdrawal's", applied)
	}
	if stale, _, _, _ := staleCombinerReplace(req(t0.Add(2*time.Second), "6aa51b6d"), zone, dns.TypeNS); stale {
		t.Fatal("after a restart, a newer REPLACE is stale")
	}
}

// forgetCombinerOrigins drops the zone's origins from the combiner's guard
// and detaches its store: a restart, and a test's cleanup.
func forgetCombinerOrigins(zone string) {
	combinerReplaceOrigins.mu.Lock()
	defer combinerReplaceOrigins.mu.Unlock()
	for k := range combinerReplaceOrigins.m {
		if strings.HasPrefix(k, zone+"|") {
			delete(combinerReplaceOrigins.m, k)
		}
	}
	for k := range combinerReplaceOrigins.dirty {
		if strings.HasPrefix(k, zone+"|") {
			delete(combinerReplaceOrigins.dirty, k)
		}
	}
	combinerReplaceOrigins.hdb = nil
}

// A REPLACE that is not applied gives its place in the guard back, on disk
// too: an older one is then not skipped as stale, and answered, for one
// that never was applied (tdns-mp #390, path 1). A newer one that took the
// place since keeps it.
func TestCombinerTakesBackTheOriginOfAReplaceNotApplied(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	zone := fmt.Sprintf("unclaim-%d.example.", time.Now().UnixNano())
	hdb := NewHsyncDB(newMPTestKeyDB(t))
	if err := hdb.InitCombinerEditTables(); err != nil {
		t.Fatalf("InitCombinerEditTables: %v", err)
	}
	t.Cleanup(func() { forgetCombinerOrigins(zone) })
	claim := func(ts time.Time, dist string) (bool, func()) {
		t.Helper()
		stale, _, unclaim, err := staleCombinerReplace(&CombinerSyncRequest{SenderID: "agent.b.", Zone: zone, Timestamp: ts, DistributionID: dist}, zone, dns.TypeNS)
		if err != nil {
			t.Fatalf("the REPLACE at %v: %v", ts, err)
		}
		return stale, unclaim
	}

	loadCombinerReplaceOrigins(hdb)
	if stale, _ := claim(t0, "6aa51b60"); stale {
		t.Fatal("the first REPLACE is stale")
	}
	_, unclaim := claim(t0.Add(2*time.Second), "6aa51b62")
	unclaim()                   // its apply failed
	forgetCombinerOrigins(zone) // and a restart
	loadCombinerReplaceOrigins(hdb)
	if stale, _ := claim(t0.Add(time.Second), "6aa51b61"); stale {
		t.Fatal("a REPLACE newer than the one applied is stale against a newer one that was not applied")
	}

	_, unclaim3 := claim(t0.Add(3*time.Second), "6aa51b63")
	if stale, _ := claim(t0.Add(4*time.Second), "6aa51b64"); stale {
		t.Fatal("a newer REPLACE is stale")
	}
	unclaim3() // the newer one at 4s has its place now
	if stale, _ := claim(t0.Add(3500*time.Millisecond), "6aa51b65"); !stale {
		t.Error("the place a newer REPLACE took was given back for an older one not applied")
	}
}

// A withdrawal, a REPLACE, whose order guard cannot be saved is refused, so
// that the sender sends it again, and leaves the records and the guard as
// they were: applied without its guard, an older REPLACE queued across a
// restart would put the records back.
func TestTheCombinerRefusesAReplaceWhoseGuardCannotBeSaved(t *testing.T) {
	mpzd, hdb := withdrawnAtCombiner(t, fmt.Sprintf("unsaved-%d.example.", time.Now().UnixNano()), "ns1")
	t.Cleanup(func() { forgetCombinerOrigins(mpzd.ZoneName) })
	loadCombinerReplaceOrigins(hdb)
	if _, err := hdb.DB.Exec(`DROP TABLE CombinerReplaceOrigin`); err != nil {
		t.Fatal(err)
	}
	resp := combinerWithdraws(mpzd, hdb, false)
	if !slices.ContainsFunc(resp.RejectedItems, func(r RejectedItem) bool { return strings.Contains(r.Reason, "order guard") }) {
		t.Fatalf("the withdrawal was not refused for its guard: %+v", resp)
	}
	if held := combinerHolds(mpzd, goneOrigin); len(held) != 1 {
		t.Errorf("the origin's NS after the refusal: %v", held)
	}
	combinerReplaceOrigins.mu.Lock()
	_, guarded := combinerReplaceOrigins.m[mpzd.ZoneName+"|"+goneOrigin+"|NS"]
	combinerReplaceOrigins.mu.Unlock()
	if guarded {
		t.Error("the refused withdrawal's origin is in the guard")
	}
}

// A withdrawal, a REPLACE, that fails to apply gives its place in the guard
// back, on disk too: an older REPLACE from the same sender is then not
// skipped as stale after a restart.
func TestAReplaceThatFailsToApplyGivesItsGuardBack(t *testing.T) {
	mpzd, hdb := withdrawnAtCombiner(t, fmt.Sprintf("unapplied-%d.example.", time.Now().UnixNano()), "ns1")
	t.Cleanup(func() { forgetCombinerOrigins(mpzd.ZoneName) })
	loadCombinerReplaceOrigins(hdb)
	mpzd.Lock()
	mpzd.MP.PersistContributions = func(string, string, map[string]map[uint16]core.RRset) error {
		return errors.New("the disk is full")
	}
	mpzd.Unlock()
	at := time.Now()
	resp := CombinerProcessUpdate(&CombinerSyncRequest{SenderID: goneOrigin, DeliveredBy: csyncOurAgent, Zone: mpzd.ZoneName,
		Operations:     []core.RROperation{{Operation: "replace", RRtype: "NS"}},
		DistributionID: nextDistributionID(), Timestamp: at, Removal: true}, nil, map[string]bool{csyncOurAgent: true}, hdb, nil)
	if len(resp.RejectedItems) == 0 {
		t.Fatalf("the withdrawal that failed to apply was not refused: %+v", resp)
	}
	forgetCombinerOrigins(mpzd.ZoneName) // a restart
	loadCombinerReplaceOrigins(hdb)
	if stale, _, _, _ := staleCombinerReplace(&CombinerSyncRequest{SenderID: goneOrigin, Zone: mpzd.ZoneName,
		DistributionID: nextDistributionID(), Timestamp: at.Add(-time.Second)}, mpzd.ZoneName, dns.TypeNS); stale {
		t.Error("an older REPLACE is stale against a withdrawal that was not applied")
	}
}

// renameTable renames a table of hdb's: a store that fails, and is back.
func renameTable(t *testing.T, hdb *HsyncDB, from, to string) {
	t.Helper()
	if _, err := hdb.DB.Exec(`ALTER TABLE ` + from + ` RENAME TO ` + to); err != nil {
		t.Fatal(err)
	}
}

// A guard whose rows on disk failed to load refuses every REPLACE, so that
// its sender sends it again: judged without them, an older REPLACE queued
// across the restart would be applied. Once they load it judges as ever.
func TestTheCombinerRefusesEveryReplaceUntilItsGuardIsLoaded(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	zone := fmt.Sprintf("unloaded-%d.example.", time.Now().UnixNano())
	hdb := NewHsyncDB(newMPTestKeyDB(t))
	if err := hdb.InitCombinerEditTables(); err != nil {
		t.Fatalf("InitCombinerEditTables: %v", err)
	}
	t.Cleanup(func() { forgetCombinerOrigins(zone) })
	req := func(ts time.Time, dist string) *CombinerSyncRequest {
		return &CombinerSyncRequest{SenderID: "agent.b.", Zone: zone, Timestamp: ts, DistributionID: dist}
	}

	loadCombinerReplaceOrigins(hdb)
	// the leader's withdrawal of b's NS, in b's name
	if stale, _, _, err := staleCombinerReplace(req(t0.Add(time.Second), "6aa51b6c"), zone, dns.TypeNS); stale || err != nil {
		t.Fatalf("the withdrawal: stale %v, err %v", stale, err)
	}
	forgetCombinerOrigins(zone) // a restart, whose load fails
	renameTable(t, hdb, "CombinerReplaceOrigin", "CombinerReplaceOriginAway")
	loadCombinerReplaceOrigins(hdb)
	if stale, _, _, err := staleCombinerReplace(req(t0, "6aa51b6a"), zone, dns.TypeNS); err == nil {
		t.Fatalf("b's older REPLACE, with the guard not loaded: stale %v, and not refused", stale)
	}
	renameTable(t, hdb, "CombinerReplaceOriginAway", "CombinerReplaceOrigin")
	stale, applied, _, err := staleCombinerReplace(req(t0, "6aa51b6a"), zone, dns.TypeNS)
	if err != nil || !stale {
		t.Fatalf("once the rows load, b's older REPLACE: stale %v, err %v", stale, err)
	}
	if applied.DistID != "6aa51b6c" {
		t.Errorf("applied %+v, want the withdrawal's", applied)
	}
}

// The row of a REPLACE not applied whose put back failed on disk is written
// again at the next REPLACE judged, another sender's say: after a restart
// it then does not refuse a REPLACE newer than the one applied.
func TestAGuardRowLeftByAFailedPutBackIsWrittenAgain(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	zone := fmt.Sprintf("dirty-%d.example.", time.Now().UnixNano())
	hdb := NewHsyncDB(newMPTestKeyDB(t))
	if err := hdb.InitCombinerEditTables(); err != nil {
		t.Fatalf("InitCombinerEditTables: %v", err)
	}
	t.Cleanup(func() { forgetCombinerOrigins(zone) })
	claim := func(sender string, ts time.Time, dist string) func() {
		t.Helper()
		stale, _, unclaim, err := staleCombinerReplace(&CombinerSyncRequest{SenderID: sender, Zone: zone, Timestamp: ts, DistributionID: dist}, zone, dns.TypeNS)
		if stale || err != nil {
			t.Fatalf("%s's REPLACE at %v: stale %v, err %v", sender, ts, stale, err)
		}
		return unclaim
	}

	loadCombinerReplaceOrigins(hdb)
	claim("agent.b.", t0, "6aa51b60")
	unclaim := claim("agent.b.", t0.Add(2*time.Second), "6aa51b62")
	renameTable(t, hdb, "CombinerReplaceOrigin", "CombinerReplaceOriginAway")
	unclaim() // its apply failed, and putting its origin back fails on disk
	renameTable(t, hdb, "CombinerReplaceOriginAway", "CombinerReplaceOrigin")
	claim("agent.c.", t0, "6aa51b70")
	combinerReplaceOrigins.mu.Lock()
	_, dirty := combinerReplaceOrigins.dirty[zone+"|agent.b.|NS"]
	combinerReplaceOrigins.mu.Unlock()
	if dirty {
		t.Error("b's row is still to be written again after the next REPLACE")
	}
	forgetCombinerOrigins(zone) // a restart
	loadCombinerReplaceOrigins(hdb)
	if stale, _, _, err := staleCombinerReplace(&CombinerSyncRequest{SenderID: "agent.b.", Zone: zone, Timestamp: t0.Add(time.Second), DistributionID: "6aa51b61"}, zone, dns.TypeNS); stale || err != nil {
		t.Fatalf("after a restart, b's REPLACE newer than the one applied: stale %v, err %v", stale, err)
	}
}

// A reload after a put back that failed on disk, of an origin or of none,
// keeps what memory holds for the key: its row still holds the origin of
// the REPLACE not applied, which would else come back, be saved, and make a
// REPLACE newer than the one applied stale. The reload writes the row again.
func TestAReloadKeepsTheGuardOfAFailedPutBack(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	for _, c := range []struct {
		name    string
		applied bool // an origin was applied before the one not applied
	}{
		{"an origin put back", true},
		{"none put back", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			zone := fmt.Sprintf("reload-%t-%d.example.", c.applied, time.Now().UnixNano())
			key := zone + "|agent.b.|NS"
			hdb := NewHsyncDB(newMPTestKeyDB(t))
			if err := hdb.InitCombinerEditTables(); err != nil {
				t.Fatalf("InitCombinerEditTables: %v", err)
			}
			t.Cleanup(func() { forgetCombinerOrigins(zone) })
			claim := func(ts time.Time, dist string) func() {
				t.Helper()
				stale, _, unclaim, err := staleCombinerReplace(&CombinerSyncRequest{SenderID: "agent.b.", Zone: zone, Timestamp: ts, DistributionID: dist}, zone, dns.TypeNS)
				if stale || err != nil {
					t.Fatalf("b's REPLACE at %v: stale %v, err %v", ts, stale, err)
				}
				return unclaim
			}

			loadCombinerReplaceOrigins(hdb)
			if c.applied {
				claim(t0, "6aa51b60")
			}
			unclaim := claim(t0.Add(2*time.Second), "6aa51b62")
			renameTable(t, hdb, "CombinerReplaceOrigin", "CombinerReplaceOriginAway")
			unclaim() // its apply failed, and the put back fails on disk
			renameTable(t, hdb, "CombinerReplaceOriginAway", "CombinerReplaceOrigin")
			loadCombinerReplaceOrigins(hdb) // a reload, before any further REPLACE

			combinerReplaceOrigins.mu.Lock()
			held, ok := combinerReplaceOrigins.m[key]
			_, dirty := combinerReplaceOrigins.dirty[key]
			combinerReplaceOrigins.mu.Unlock()
			switch {
			case c.applied && (!ok || held.DistID != "6aa51b60"):
				t.Errorf("after the reload memory holds %+v (%v), want the origin applied", held, ok)
			case !c.applied && ok:
				t.Errorf("after the reload memory holds %+v, want none", held)
			}
			if dirty {
				t.Error("the reload did not write the row again")
			}
			forgetCombinerOrigins(zone) // and a restart
			loadCombinerReplaceOrigins(hdb)
			claim(t0.Add(time.Second), "6aa51b61")
		})
	}
}
