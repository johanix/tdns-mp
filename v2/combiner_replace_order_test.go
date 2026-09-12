package tdnsmp

import (
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
	req := func(sender string, ts time.Time, dist string) *CombinerSyncRequest {
		return &CombinerSyncRequest{SenderID: sender, Zone: "cell.example.", Timestamp: ts, DistributionID: dist}
	}
	if stale, _ := staleCombinerReplace(req("agent.a.", t0.Add(time.Second), "6aa51b6c"), "cell.example.", dns.TypeDNSKEY); stale {
		t.Fatal("the first REPLACE is stale")
	}
	if stale, _ := staleCombinerReplace(req("agent.a.", t0, "6aa51b6a"), "cell.example.", dns.TypeDNSKEY); !stale {
		t.Fatal("an older REPLACE after a newer one is not stale")
	}
	if stale, _ := staleCombinerReplace(req("agent.a.", t0.Add(time.Second), "6aa51b6d"), "cell.example.", dns.TypeDNSKEY); stale {
		t.Fatal("the same instant with a higher distribution id is stale")
	}
	if stale, _ := staleCombinerReplace(req("agent.a.", t0.Add(time.Second), "6aa51b6b"), "cell.example.", dns.TypeDNSKEY); !stale {
		t.Fatal("the same instant with a lower distribution id is not stale")
	}
	if stale, _ := staleCombinerReplace(req("agent.a.", t0, "6aa51b60"), "cell.example.", dns.TypeNS); stale {
		t.Fatal("another type from the same sender was gated by the DNSKEY origin")
	}
	if stale, _ := staleCombinerReplace(req("agent.b.", t0, "6aa51b60"), "cell.example.", dns.TypeDNSKEY); stale {
		t.Fatal("another sender was gated by the first sender's origin")
	}
	if stale, _ := staleCombinerReplace(req("agent.a.", time.Time{}, ""), "cell.example.", dns.TypeDNSKEY); stale {
		t.Fatal("a request without a time was called stale")
	}
}
