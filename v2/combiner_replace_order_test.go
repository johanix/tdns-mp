package tdnsmp

import (
	"fmt"
	"strings"
	"testing"
	"time"

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
	if stale, _ := staleCombinerReplace(req("agent.a.", t0.Add(time.Second), "6aa51b6c"), zone, dns.TypeDNSKEY); stale {
		t.Fatal("the first REPLACE is stale")
	}
	if stale, _ := staleCombinerReplace(req("agent.a.", t0, "6aa51b6a"), zone, dns.TypeDNSKEY); !stale {
		t.Fatal("an older REPLACE after a newer one is not stale")
	}
	if stale, _ := staleCombinerReplace(req("agent.a.", t0.Add(time.Second), "6aa51b6d"), zone, dns.TypeDNSKEY); stale {
		t.Fatal("the same instant with a higher distribution id is stale")
	}
	if stale, _ := staleCombinerReplace(req("agent.a.", t0.Add(time.Second), "6aa51b6b"), zone, dns.TypeDNSKEY); !stale {
		t.Fatal("the same instant with a lower distribution id is not stale")
	}
	if stale, _ := staleCombinerReplace(req("agent.a.", t0, "6aa51b60"), zone, dns.TypeNS); stale {
		t.Fatal("another type from the same sender was gated by the DNSKEY origin")
	}
	if stale, _ := staleCombinerReplace(req("agent.b.", t0, "6aa51b60"), zone, dns.TypeDNSKEY); stale {
		t.Fatal("another sender was gated by the first sender's origin")
	}
	if stale, _ := staleCombinerReplace(req("agent.a.", time.Time{}, ""), zone, dns.TypeDNSKEY); stale {
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
	if stale, _ := staleCombinerReplace(req(t0.Add(time.Second), "6aa51b6c"), zone, dns.TypeNS); stale {
		t.Fatal("the withdrawal is stale")
	}
	forget() // the restart
	loadCombinerReplaceOrigins(hdb)
	if stale, applied := staleCombinerReplace(req(t0, "6aa51b6a"), zone, dns.TypeNS); !stale {
		t.Fatal("after a restart, b's older REPLACE is not stale")
	} else if applied.DistID != "6aa51b6c" {
		t.Errorf("applied %+v, want the withdrawal's", applied)
	}
	if stale, _ := staleCombinerReplace(req(t0.Add(2*time.Second), "6aa51b6d"), zone, dns.TypeNS); stale {
		t.Fatal("after a restart, a newer REPLACE is stale")
	}
}
