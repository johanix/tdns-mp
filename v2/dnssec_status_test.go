/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #260: what discovery found out about a peer's DNS data reaches peer list
// and the gossip matrix. The state stays bare; the verdict rides beside it.

const (
	chainLocal = "a.example."
	chainPeerB = "b.example."
	chainPeerC = "c.example."
)

// discoveredPeer registers id in tm as discovery would, with its lookups.
func discoveredPeer(t *testing.T, tm *transport.TransportManager, id string, lookups ...transport.DiscoveryLookup) *transport.Peer {
	t.Helper()
	err := tm.RegisterDiscoveredPeer(&transport.DiscoveryResult{
		Identity:     id,
		APIUri:       "https://api." + id + ":8443/api",
		APIAddresses: []string{"192.0.2.1"},
		TLSA: transport.TLSASet{Owner: "_8443._tcp.api." + id, Validated: true,
			Records: []*dns.TLSA{{Hdr: dns.RR_Header{Name: "_8443._tcp.api." + id, Rrtype: dns.TypeTLSA, Class: dns.ClassINET},
				Usage: 3, Selector: 1, MatchingType: 1, Certificate: strings.Repeat("ab", 32)}}},
		Lookups: lookups,
	})
	if err != nil {
		t.Fatalf("RegisterDiscoveredPeer(%s): %v", id, err)
	}
	p, _ := tm.PeerRegistry.Get(id)
	return p
}

func insecureURI(id string) transport.DiscoveryLookup {
	return transport.DiscoveryLookup{Mechanism: "API", Type: "URI", Owner: "_https._tcp." + id,
		Chain: transport.ChainInsecure, Expires: time.Now().Add(time.Hour),
		Detail: "answer insecure, accepted as DNSSEC validation is off"}
}

func TestPeerInfoCarriesTheVerdict(t *testing.T) {
	tm := &transport.TransportManager{PeerRegistry: transport.NewPeerRegistry()}
	p := discoveredPeer(t, tm, chainPeerB, insecureURI(chainPeerB))
	var pi PeerInfo
	pi.setDiscovery(p, "API")
	if pi.DNSSEC != "insecure" {
		t.Errorf("DNSSEC %q, want insecure", pi.DNSSEC)
	}
	if want := "URI at _https._tcp.b.example.: answer insecure, accepted as DNSSEC validation is off"; pi.DiscoveryReason != want {
		t.Errorf("reason %q, want %q", pi.DiscoveryReason, want)
	}
	if want := p.DiscoveryStatus().MechanismExpires("API"); pi.DiscoveryExpires.IsZero() || !pi.DiscoveryExpires.Equal(want) {
		t.Errorf("expiry %v, want the API data's, %v", pi.DiscoveryExpires, want)
	}

	// A mechanism discovery has said nothing about has no verdict.
	var dnsInfo PeerInfo
	dnsInfo.setDiscovery(p, "DNS")
	if dnsInfo.DNSSEC != "" || dnsInfo.DiscoveryReason != "" {
		t.Errorf("DNS: %q / %q, want nothing", dnsInfo.DNSSEC, dnsInfo.DiscoveryReason)
	}
}

// Our own gossip row carries the verdicts for its members whose chain is not
// secure, and whether our validation is off; a copy is a copy, and the wire
// leaves both out when there is nothing to say.
func TestOwnGossipRowCarriesTheVerdicts(t *testing.T) {
	tm := &transport.TransportManager{PeerRegistry: transport.NewPeerRegistry()}
	discoveredPeer(t, tm, chainPeerB, insecureURI(chainPeerB))
	discoveredPeer(t, tm, chainPeerC, transport.DiscoveryLookup{Mechanism: "API", Type: "URI", Chain: transport.ChainSecure})
	mp := &MultiProviderConf{Identity: chainLocal}
	pgm := NewProviderGroupManager(chainLocal)
	pgm.Groups["g1"] = &ProviderGroup{GroupHash: "g1", Members: []string{chainLocal, chainPeerB, chainPeerC}}
	ar := &AgentRegistry{
		S: core.NewStringer[AgentId, *Agent](), LocalAgent: mp, TransportManager: tm,
		ProviderGroupManager: pgm, GossipStateTable: NewGossipStateTable(chainLocal),
	}
	gst := ar.GossipStateTable
	gst.SetDnssecValidationOff(true)
	gst.RefreshLocalStates(ar, pgm)

	states, _, _ := gst.GetGroupState("g1")
	own := states[chainLocal]
	if own == nil {
		t.Fatal("no own row")
	}
	if !own.DnssecValidationOff {
		t.Error("own row does not say validation is off")
	}
	if len(own.PeerChains) != 1 || own.PeerChains[chainPeerB] != "insecure" {
		t.Errorf("peer chains %v, want only b insecure", own.PeerChains)
	}
	if own.PeerStates[chainPeerB] != AgentStateToString[AgentStateNeeded] {
		t.Errorf("b's state %q: the state stays bare", own.PeerStates[chainPeerB])
	}

	own.PeerChains[chainPeerB] = "changed"
	if fresh, _, _ := gst.GetGroupState("g1"); fresh[chainLocal].PeerChains[chainPeerB] != "insecure" {
		t.Error("GetGroupState handed out the table's own map")
	}
	if cp := deepCopyMemberState(again(t, gst)); cp.PeerChains[chainPeerB] != "insecure" || !cp.DnssecValidationOff {
		t.Errorf("deep copy lost the verdicts: %+v", cp)
	}

	row := gossipMatrixRow(chainLocal, again(t, gst))
	if row["dnssec_validation_off"] != true || row["peer_chains"] == nil {
		t.Errorf("matrix row %v lacks the verdicts", row)
	}

	wire, err := json.Marshal(again(t, gst))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"peer_chains":{"b.example.":"insecure"}`) || !strings.Contains(string(wire), `"dnssec_validation_off":true`) {
		t.Errorf("wire %s lacks the verdicts", wire)
	}
	bare, _ := json.Marshal(&MemberState{Identity: chainLocal})
	if strings.Contains(string(bare), "peer_chains") || strings.Contains(string(bare), "dnssec_validation_off") {
		t.Errorf("wire %s: empty verdicts are sent", bare)
	}
}

// again is the table's own row for g1, as GetGroupState copies it.
func again(t *testing.T, gst *GossipStateTable) *MemberState {
	t.Helper()
	states, _, _ := gst.GetGroupState("g1")
	return states[chainLocal]
}
