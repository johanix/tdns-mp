package tdnsmp

import (
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A peer's REPLACE that was sent earlier but arrives later -- the retry of
// one rejected while this agent did not yet hold the zone -- must not roll
// the peer's set back; the newest origin wins, a later one applies, and a
// local update is never gated.
func TestStaleRemoteReplaceIsIgnored(t *testing.T) {
	zdr, _ := NewZoneDataRepo()
	nod := tdns.NewOwnerData("cell.example.")
	key := func(b64 string) string { return "cell.example. 3600 IN DNSKEY 256 3 15 " + b64 }
	op := func(rrs ...string) core.RROperation {
		return core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: rrs}
	}
	remote := func(ts time.Time, dist string) *SynchedDataUpdate {
		return &SynchedDataUpdate{Zone: "cell.example.", AgentId: "agent.peer.example.", UpdateType: "remote",
			OriginatingTime: ts, OriginatingDistID: dist, Update: &ZoneUpdate{}}
	}
	served := func() int {
		rrset, ok := nod.RRtypes.Get(dns.TypeDNSKEY)
		if !ok {
			return 0
		}
		return len(rrset.RRs)
	}
	t0 := time.Unix(1_700_000_000, 0)

	// the newer set (three keys) is applied first
	if changed, msg := zdr.processReplaceOp(remote(t0.Add(time.Second), "6aa51b6c"), nod, dns.TypeDNSKEY, op(key("AQID"), key("AQIE"), key("AQIF"))); !changed {
		t.Fatalf("first REPLACE not applied: %s", msg)
	}
	// then the older two-key set arrives, retried
	changed, msg := zdr.processReplaceOp(remote(t0, "6aa51b6a"), nod, dns.TypeDNSKEY, op(key("AQID"), key("AQIE")))
	if changed || !strings.Contains(msg, "stale") || served() != 3 {
		t.Fatalf("the older REPLACE rolled the set back: changed=%v served=%d msg=%s", changed, served(), msg)
	}
	// same second as the applied one, higher distribution id: newer, applies
	if changed, msg := zdr.processReplaceOp(remote(t0.Add(time.Second), "6aa51b6d"), nod, dns.TypeDNSKEY, op(key("AQID"), key("AQIE"), key("AQIF"), key("AQIG"))); !changed || served() != 4 {
		t.Fatalf("a newer REPLACE in the same second was not applied: changed=%v served=%d msg=%s", changed, served(), msg)
	}
	// same second, lower id: stale
	if changed, _ := zdr.processReplaceOp(remote(t0.Add(time.Second), "6aa51b6b"), nod, dns.TypeDNSKEY, op(key("AQID"))); changed || served() != 4 {
		t.Fatalf("an older REPLACE in the same second was applied: served=%d", served())
	}
	// another rrtype from the same agent is ordered on its own
	if changed, msg := zdr.processReplaceOp(remote(t0, "6aa51b60"), nod, dns.TypeNS, op("cell.example. 300 IN NS ns.peer.example.")); !changed {
		t.Fatalf("a REPLACE of another type was gated by the DNSKEY origin: %s", msg)
	}
	// a local update carries no origin and is never gated
	local := &SynchedDataUpdate{Zone: "cell.example.", AgentId: "agent.peer.example.", UpdateType: "local", Update: &ZoneUpdate{}}
	if changed, msg := zdr.processReplaceOp(local, nod, dns.TypeDNSKEY, op(key("AQID"))); !changed || served() != 1 {
		t.Fatalf("a local REPLACE was gated: changed=%v served=%d msg=%s", changed, served(), msg)
	}
}
