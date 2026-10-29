/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Stamps in beats at the transport boundary (plans S5a and S22), over
 * both mechanisms.
 */
package tdnsmp

import (
	"encoding/json"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// Alice beats bob, over DNS and over HTTPS, a beat that tells every zone
// (as the first after bob's start does, plan S22). Bob notes alice's stamp
// first hand, with the beat's mechanism. Bob's answer carries a stamp of his own
// that tells a newer serial under another digest: alice notes none of it,
// marks no owner error and fetches nothing (design rule 4).
func TestTransportBoundary_StampsInBeatsOverBothMechanisms(t *testing.T) {
	for _, mech := range []string{"DNS", "API"} {
		t.Run(mech, func(t *testing.T) {
			env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
			alice, bob := dns.Fqdn(env.Alice.Identity), dns.Fqdn(env.Bob.Identity)
			zone := strings.ToLower(mech) + ".stamps.example." // not-a-name: a mechanism
			zd := seedZoneWithHSYNC3(t, zone, alice, bob)
			addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob))
			apex, err := zd.GetOwner(zone)
			if err != nil {
				t.Fatal(err)
			}
			in, err := ReadInstructions(apex)
			if err != nil || in == nil {
				t.Fatalf("the zone's reading: %v %v", in, err)
			}
			tables := map[string]*stampTable{}
			for _, p := range []*peerEnv{env.Alice, env.Bob} {
				s := newStore(t)
				noteKnown(t, s, zone, in)
				p.Bridge.stamps = newStampTable(p.Identity, s, 1, false, []string{"ns1." + p.Identity})
				tables[p.Identity] = p.Bridge.stamps
				pgm := p.Registry.ProviderGroupManager
				pgm.RecomputeGroups()
				p.Registry.GossipStateTable.RefreshLocalStates(p.Registry, pgm)
			}
			tellEveryZoneOnce(tables[env.Alice.Identity], bob)
			fetched := 0
			tables[env.Alice.Identity].fetch = func(zone string) (string, bool) {
				fetched++
				return zone, true
			}

			// bob's answer carries a stamp that tells serial 9 under another
			// digest than alice holds for her serial
			other := *in
			other.Suffix = "other"
			answer := InstrStamp{Known: true, Active: in.Serial, ActiveDigest: other.Digest(), Newest: 9, NewestDigest: other.Digest()}
			env.Bob.Bridge.ChunkHandler.GossipForPeer = func(string) json.RawMessage {
				data, _ := json.Marshal([]GossipMessage{{GroupHash: stampGroupHash, Members: map[string]*MemberState{
					bob: {Identity: bob, Epoch: 1, Seq: 1, Instr: map[string]InstrStamp{zone: answer}}}}})
				return data
			}
			env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
			env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
			env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
			agent := NewAgent(AgentId(bob))
			switch mech {
			case "DNS":
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				serveDNS(t, env.ctx, ln, env.Bob)
				peer := peerFromAddress(bob, ln.Addr().String())
				peer.SetMechanismState("DNS", transport.PeerStateIntroducing, "said hello")
				if err := env.Alice.Bridge.PeerRegistry.Add(peer); err != nil {
					t.Fatal(err)
				}
				agent.DnsMethod = true
			case "API":
				srv := apiEndpointsServer(t, env.Bob)
				tr := apiSender(srv, alice)
				env.Alice.Bridge.APITransport = tr
				env.Alice.Bridge.TransportManager.APITransport = tr
				peer := transport.NewPeer(bob)
				peer.APIEndpoint = srv.URL + "/api/v1"
				setTLSA(peer, srv.Certificate())
				peer.SetMechanismState("API", transport.PeerStateIntroducing, "said hello")
				if err := env.Alice.Bridge.PeerRegistry.Add(peer); err != nil {
					t.Fatal(err)
				}
				agent.ApiMethod = true
			}
			resp, err := env.Alice.Bridge.SendBeatWithFallback(env.ctx, agent, 1)
			if err != nil || resp == nil {
				t.Fatalf("the beat: %+v %v", resp, err)
			}
			// the answer carries bob's stamp of the zone, which alice must not note
			var inAnswer []GossipMessage
			if err := json.Unmarshal(resp.Gossip, &inAnswer); err != nil {
				t.Fatalf("the answer's gossip: %v", err)
			}
			i := slices.IndexFunc(inAnswer, func(g GossipMessage) bool { return g.GroupHash == stampGroupHash })
			if i < 0 || inAnswer[i].Members[bob] == nil || !reflect.DeepEqual(inAnswer[i].Members[bob].Instr[zone], answer) {
				t.Fatalf("the answer does not carry bob's stamp of the zone: %s", resp.Gossip)
			}
			if _, ok := recvWithin(env.Bob.MsgQs.Beat, integTestTimeout); !ok {
				t.Fatal("the beat did not reach bob's MsgQs.Beat")
			}

			heard := tables[env.Bob.Identity].heard(alice)
			if heard == nil || heard.Mechanism != mech {
				t.Fatalf("bob's note of alice's stamp: %+v", heard)
			}
			if st := heard.Instr[canonicalName(zone)]; st.Active != in.Serial || st.ActiveDigest != in.Digest() || !st.Known {
				t.Errorf("alice's stamp, as bob heard it: %+v", st)
			}
			if !slices.Equal(heard.Nameservers, []string{"ns1." + alice}) {
				t.Errorf("alice's nameservers: %v", heard.Nameservers)
			}
			if got := tables[env.Alice.Identity].heard(bob); got != nil {
				t.Errorf("alice noted the stamp in bob's answer: %+v", got)
			}
			if st := tables[env.Alice.Identity].store.Status(zone); st == nil || st.OwnerError != "" || st.Phase != PhaseSteady {
				t.Errorf("the answer's stamp changed alice's serials: %+v", st)
			}
			if fetched != 0 {
				t.Errorf("the answer's newer serial was fetched %d times", fetched)
			}
			// the beat was acknowledged: the zone it told once is told
			if got := zonesTold(tables[env.Alice.Identity].entryFor(bob), alice); len(got) != 0 {
				t.Errorf("after the acknowledged beat alice still tells bob %v", got)
			}
		})
	}
}

// The answer to a beat lists nothing by interest (plan S22): it carries no
// stamp, even of a zone the beat would tell, and its rows list no zone.
// Answers count for nothing (rule 4).
func TestABeatAnswerListsNothingByInterest(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	alice, bob := dns.Fqdn(env.Alice.Identity), dns.Fqdn(env.Bob.Identity)
	const zone = "answer.interest.example."
	zd := seedZoneWithHSYNC3(t, zone, alice, bob)
	addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob))
	apex, err := zd.GetOwner(zone)
	if err != nil {
		t.Fatal(err)
	}
	in, err := ReadInstructions(apex)
	if err != nil || in == nil {
		t.Fatalf("the zone's reading: %v %v", in, err)
	}
	s := newStore(t)
	noteKnown(t, s, zone, in)
	st := newStampTable(alice, s, 1, true, nil)
	st.rollover = func(string) bool { return true }
	tellEveryZoneOnce(st, bob)
	env.Alice.Bridge.stamps = st
	pgm := env.Alice.Registry.ProviderGroupManager
	pgm.RecomputeGroups()
	env.Alice.Registry.GossipStateTable.RefreshLocalStates(env.Alice.Registry, pgm)
	if got := zonesTold(st.entryFor(bob), alice); !slices.Equal(got, []string{zone}) {
		t.Fatalf("the beat to bob tells %v", got)
	}

	var answer []GossipMessage
	if err := json.Unmarshal(env.Alice.Bridge.ChunkHandler.GossipForPeer(bob), &answer); err != nil || len(answer) == 0 {
		t.Fatalf("the answer's gossip: %+v %v", answer, err)
	}
	for _, g := range answer {
		if g.GroupHash == stampGroupHash {
			t.Errorf("the answer carries a stamp entry: %+v", g)
		}
		for id, row := range g.Members {
			if row != nil && len(row.Zones) != 0 {
				t.Errorf("%s's row in the answer lists %v", id, row.Zones)
			}
		}
	}
}
