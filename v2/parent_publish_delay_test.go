/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The parent's side of a removal's waits (design 5.2 as amended 2026-11-03):
// its every server is asked, and parent-publish-delay is added to its TTLs.

const (
	parentA = "192.0.2.1:53"
	parentB = "192.0.2.2:53"
)

// parentFrom is what a look reads from these servers' answers.
func parentFrom(each ...parentSeen) parentSeen {
	var seen parentSeen
	for _, one := range each {
		seen.add(one)
	}
	return seen
}

// serverWithDS is a server's answer that holds these DS, by their tags.
func serverWithDS(server string, ns []string, ttl uint32, tags ...uint16) parentSeen {
	var dsrrs []dns.RR
	for _, tag := range tags {
		dsrrs = append(dsrrs, &dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: ttl}, KeyTag: tag, Algorithm: 15, DigestType: dns.SHA256, Digest: fmt.Sprintf("%04X", tag)})
	}
	var nsrrs []dns.RR
	for _, name := range ns {
		nsrrs = append(nsrrs, &dns.NS{Hdr: dns.RR_Header{Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 600}, Ns: name})
	}
	return serverSeen(server, nsrrs, dsrrs)
}

// zoneServesNS has the zone's own NS RRset carry ttl.
func (r *leaverRig) zoneServesNS(ttl uint32) {
	r.t.Helper()
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN NS ns1.a.example.", r.zone, ttl))
	if err != nil {
		r.t.Fatal(err)
	}
	mpzd, _ := Zones.Get(r.zone)
	mpzd.ZoneStore = tdns.MapZone
	owner := tdns.OwnerData{Name: r.zone, RRtypes: tdns.NewRRTypeStore()}
	owner.RRtypes.Set(dns.TypeNS, core.RRset{Name: r.zone, RRtype: dns.TypeNS, RRs: []dns.RR{rr}})
	mpzd.Data.Set(r.zone, owner)
	mpzd.InstallInitialSnapshot()
	if _, got := zoneNSOf(r.zone); got != ttl {
		r.t.Fatalf("the zone's NS TTL reads %d, want %d", got, ttl)
	}
}

// providersDelay has the providers' propagation delay be d.
func (r *leaverRig) providersDelay(d time.Duration) {
	r.t.Helper()
	if r.conf.InternalMp.AgentRegistry == nil {
		r.conf.InternalMp.AgentRegistry = &AgentRegistry{}
	}
	ar := r.conf.InternalMp.AgentRegistry
	if ar.GossipStateTable == nil {
		ar.GossipStateTable = NewGossipStateTable(roleA)
	}
	ar.GossipStateTable.SetPropagationDelay(d)
}

func TestParentPublishDelayHasADefaultAndRefusesANegative(t *testing.T) {
	mp := &MultiProviderConf{}
	if got := parentPublishDelayFor(mp); got != 5*time.Minute {
		t.Errorf("unset reads %s", got)
	}
	if got := parentPublishDelayFor(nil); got != 5*time.Minute {
		t.Errorf("no config reads %s", got)
	}
	mp.Transitions.ParentPublishDelay = 20
	if got := parentPublishDelayFor(mp); got != 20*time.Second {
		t.Errorf("20 reads %s", got)
	}
	if err := ValidateTransitions(mp); err != nil {
		t.Errorf("20 is refused: %v", err)
	}
	mp.Transitions.ParentPublishDelay = -1
	if err := ValidateTransitions(mp); err == nil || !strings.Contains(err.Error(), "parent-publish-delay") {
		t.Errorf("a negative: %v", err)
	}
}

// The DNSKEY TTL has no part in it: the key held here says 3600.
func TestTheDSStepWaitsItsTTLPlusTheDelay(t *testing.T) {
	logs := captureLog(t)
	r := newSweepRig(t, "dswait.remove.example.")
	r.holds(roleN, dns.TypeDNSKEY)
	r.toDSStep()
	r.newLook()
	r.served(parentSeen{ns: r.parent.ns, nsTTL: 600, ds: []uint16{1}, dsTTL: 120})
	r.next()
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "step 3 (its DS), waiting for the DS TTL until ") {
		t.Errorf("the status: %q", line)
	}
	for _, term := range []string{"a removal's DS step counts its wait", "zone=dswait.remove.example.", "parent_ds_ttl=2m0s", "ttl_seen=true", "parent_publish_delay=5m0s"} {
		if !strings.Contains(logs.String(), term) {
			t.Errorf("no %s in the log", term)
		}
	}
	r.aged(6 * time.Minute) // past the DS TTL, within its sum with the delay
	r.next()
	if slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Fatalf("its DNSKEY went before the DS TTL and the delay: %v", r.withdrawals)
	}
	r.aged(2 * time.Minute)
	r.next()
	if !slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Errorf("its DNSKEY did not go after them: %v, steps %v", r.withdrawals, r.taken())
	}
}

func TestTheDSStepTakesTheConfiguredDelay(t *testing.T) {
	r := newSweepRig(t, "dsset.remove.example.")
	r.conf.MpConfig().Transitions.ParentPublishDelay = 20
	r.toDSStep()
	r.newLook()
	r.served(parentSeen{ns: r.parent.ns, nsTTL: 600, ds: []uint16{1}, dsTTL: 120})
	r.next()
	r.aged(2 * time.Minute)
	r.next()
	if slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Fatalf("its DNSKEY went within the delay: %v", r.withdrawals)
	}
	r.aged(time.Minute)
	r.next()
	if !slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Errorf("its DNSKEY did not go after 20 s: %v, steps %v", r.withdrawals, r.taken())
	}
}

// A new leader, of a DS the parent had dropped before it looked.
func TestADSTTLNeverSeenIsAnHourAndTheDelay(t *testing.T) {
	logs := captureLog(t)
	r := newSweepRig(t, "dsnever.remove.example.")
	r.toDSStep()
	r.newLook()
	r.served(parentSeen{ns: r.parent.ns, nsTTL: 600, ds: []uint16{1}})
	r.next()
	if !strings.Contains(logs.String(), "ttl_seen=false") {
		t.Errorf("the log does not say the TTL was never seen: %s", logs)
	}
	r.aged(62 * time.Minute)
	r.next()
	if slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Fatalf("its DNSKEY went within the hour and the delay: %v", r.withdrawals)
	}
	r.aged(4 * time.Minute)
	r.next()
	if !slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Errorf("its DNSKEY did not go after them: %v, steps %v", r.withdrawals, r.taken())
	}
}

// The parent's way: its TTL and its delay, the longer here.
func TestTheNSStepWaitsTheParentsTTLPlusItsDelay(t *testing.T) {
	logs := captureLog(t)
	r := newLeaverRig(t, "nsparent.remove.example.", "agent")
	r.zoneServesNS(60)
	r.providersDelay(20 * time.Second)
	r.next()
	r.next()
	r.served(parentSeen{ns: []string{"ns1.a.example.", "ns1.b.example."}, nsTTL: 600, nsServer: parentA})
	r.next()
	for _, term := range []string{"parent_ns_ttl=600", "parent_server=" + parentA, "parent_publish_delay=5m0s", "zone_ns_ttl=60", "delay=20s"} {
		if !strings.Contains(logs.String(), term) {
			t.Errorf("no %s in the log", term)
		}
	}
	r.aged(14 * time.Minute)
	r.next()
	if len(r.taken()) != 2 {
		t.Fatalf("went on within the parent's TTL and delay: %v", r.taken())
	}
	r.aged(2 * time.Minute)
	r.next()
	if !slices.Equal(r.taken(), []string{"names", "ns", "confirmers"}) {
		t.Errorf("after them: %v", r.taken())
	}
}

// The zone's way: a resolver may hold the slowest provider's old apex NS after
// a parent that took the change in seconds.
func TestTheNSStepWaitsTheZonesTTLPlusTheProvidersDelay(t *testing.T) {
	r := newLeaverRig(t, "nszone.remove.example.", "agent")
	r.conf.MpConfig().Transitions.ParentPublishDelay = 20
	r.zoneServesNS(3600)
	r.providersDelay(10 * time.Minute)
	r.next()
	r.next()
	r.served(parentSeen{ns: []string{"ns1.a.example.", "ns1.b.example."}, nsTTL: 60, nsServer: parentA})
	r.next()
	r.aged(69 * time.Minute)
	r.next()
	if len(r.taken()) != 2 {
		t.Fatalf("went on within the zone's TTL and the providers' delay: %v", r.taken())
	}
	r.aged(2 * time.Minute)
	r.next()
	if !slices.Equal(r.taken(), []string{"names", "ns", "confirmers"}) {
		t.Errorf("after them: %v", r.taken())
	}
}

func TestTheNSWatchWaitsForEveryServerAndNamesTheOneBehind(t *testing.T) {
	r := newLeaverRig(t, "nsevery.remove.example.", "agent")
	dropped := parentSeen{nsServer: parentA, ns: []string{"ns1.a.example.", "ns1.b.example."}, nsTTL: 600}
	stale := parentSeen{nsServer: parentB, ns: []string{"ns1.a.example.", "ns1.b.example.", "ns1.n.example."}, nsTTL: 600}
	r.next()
	r.next()
	r.served(parentFrom(stale, stale))
	r.next()
	line := r.conf.thawLine(r.zone)
	if !strings.Contains(line, "until the parent no longer names ns1.n.example.") || strings.Contains(line, "still at") {
		t.Errorf("no server is behind while all name it: %q", line)
	}
	r.served(parentFrom(dropped, stale))
	r.next()
	line = r.conf.thawLine(r.zone)
	if !strings.Contains(line, "until the parent no longer names ns1.n.example. (still at "+parentB+";") {
		t.Errorf("the status does not name the server behind: %q", line)
	}
	r.aged(24 * time.Hour) // nothing counts yet
	r.next()
	if len(r.taken()) != 2 {
		t.Fatalf("went on while a server names it: %v", r.taken())
	}
	r.served(parentFrom(dropped, dropped))
	r.next()
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "waiting for the NS TTL until ") {
		t.Errorf("once every server has dropped it: %q", line)
	}
	r.aged(14 * time.Minute)
	r.next()
	if len(r.taken()) != 2 {
		t.Fatalf("the wait counted from the first server: %v", r.taken())
	}
	r.served(parentFrom(dropped, stale)) // a server that was not heard, answering stale
	r.next()
	r.served(parentFrom(dropped, dropped))
	r.next()
	r.aged(14 * time.Minute)
	r.next()
	if len(r.taken()) != 2 {
		t.Fatalf("the wait did not start over: %v", r.taken())
	}
	r.aged(2 * time.Minute)
	r.next()
	if !slices.Equal(r.taken(), []string{"names", "ns", "confirmers"}) {
		t.Errorf("after the wait: %v", r.taken())
	}
}

func TestTheDSWatchWaitsForEveryServerAndNamesTheOneBehind(t *testing.T) {
	r := newSweepRig(t, "dsevery.remove.example.")
	r.toDSStep()
	dropped := serverWithDS(parentA, r.parent.ns, 120, 1)
	stale := serverWithDS(parentB, r.parent.ns, 120, 1, 2)
	r.served(parentFrom(stale, stale))
	r.next()
	line := r.conf.thawLine(r.zone)
	if !strings.Contains(line, "until the parent no longer serves its DS") || strings.Contains(line, "still at") {
		t.Errorf("no server is behind while all serve it: %q", line)
	}
	r.served(parentFrom(dropped, stale))
	r.next()
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "until the parent no longer serves its DS (still at "+parentB+";") {
		t.Errorf("the status does not name the server behind: %q", line)
	}
	r.aged(24 * time.Hour)
	r.next()
	if slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Fatalf("its DNSKEY went while a server serves its DS: %v", r.withdrawals)
	}
	r.served(parentFrom(dropped, dropped))
	r.next()
	r.aged(6 * time.Minute)
	r.next()
	if slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Fatalf("the wait counted from the first server: %v", r.withdrawals)
	}
	r.aged(2 * time.Minute)
	r.next()
	if !slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Errorf("its DNSKEY did not go after the wait: %v, steps %v", r.withdrawals, r.taken())
	}
}

// parentServer answers as a parent's server does: the delegation in the
// authority section, the DS in the answer, and its address is what it returns.
func parentServer(t *testing.T, zone string, ns []string, nsTTL uint32, ds []string, dsTTL uint32) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rr := func(s string) dns.RR {
		got, err := dns.NewRR(s)
		if err != nil {
			t.Error(err)
		}
		return got
	}
	srv := &dns.Server{PacketConn: pc, Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		switch q.Question[0].Qtype {
		case dns.TypeNS:
			for _, name := range ns {
				m.Ns = append(m.Ns, rr(fmt.Sprintf("%s %d IN NS %s", zone, nsTTL, name)))
			}
		case dns.TypeDS:
			m.Authoritative = true
			for _, one := range ds {
				m.Answer = append(m.Answer, rr(fmt.Sprintf("%s %d IN DS %s", zone, dsTTL, one)))
			}
		}
		if err := w.WriteMsg(m); err != nil {
			t.Error(err)
		}
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// goneServer is an address nothing answers at.
func goneServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

// A real look at the wire, as parentLook asks it.
func TestALookReadsEveryServerThatAnswers(t *testing.T) {
	const zone = "wire.remove.example."
	const (
		dsKept = "1 15 2 " + "aa00000000000000000000000000000000000000000000000000000000000000"
		dsGone = "2 15 2 " + "bb00000000000000000000000000000000000000000000000000000000000000"
	)
	ask := func(server string, rrtype uint16) ([]dns.RR, error) { return tdns.AuthQuery(zone, server, rrtype) }

	dropped := parentServer(t, zone, []string{"ns1.a.example."}, 300, []string{dsKept}, 120)
	stale := parentServer(t, zone, []string{"ns1.a.example.", "NS1.N.example."}, 600, []string{dsKept, dsGone}, 900)
	empty := parentServer(t, zone, nil, 0, nil, 0)
	gone := goneServer(t)

	seen, err := parentAtEveryServer([]string{gone, empty, dropped, stale}, ask)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(seen.ns, "ns1.n.example.") || !slices.Contains(seen.ds, 2) {
		t.Errorf("a server that holds them, read after one that dropped them: %v, %v", seen.ns, seen.ds)
	}
	if len(seen.ns) != 2 || len(seen.dsRRs) != 2 {
		t.Errorf("each read once: %v, %v", seen.ns, seen.dsRRs)
	}
	if seen.nsTTL != 600 || seen.nsServer != stale || seen.dsTTL != 900 {
		t.Errorf("the largest TTLs: NS %d from %s, DS %d", seen.nsTTL, seen.nsServer, seen.dsTTL)
	}
	if len(seen.each) != 2 {
		t.Errorf("the servers that answered: %d, want 2: %+v", len(seen.each), seen.each)
	}
	if got := seen.behind(parentSeen.toldNS, func(one parentSeen) bool { return slices.Contains(one.ns, "ns1.n.example.") }); !slices.Equal(got, []string{stale}) {
		t.Errorf("the server behind: %v, want %s", got, stale)
	}

	// a server that does not answer holds nothing up
	seen, err = parentAtEveryServer([]string{gone, dropped}, ask)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(seen.ns, "ns1.n.example.") || slices.Contains(seen.ds, 2) {
		t.Errorf("read from nothing: %v, %v", seen.ns, seen.ds)
	}

	// with no answer nothing is known, and the last look stands (parentNow)
	if _, err := parentAtEveryServer([]string{gone}, ask); err == nil {
		t.Error("a server that does not answer gave a look")
	}
	if _, err := parentAtEveryServer([]string{empty}, ask); err == nil || !strings.Contains(err.Error(), "no parent server gave an NS RRset") {
		t.Errorf("a server with no NS RRset: %v", err)
	}
	if _, err := parentAtEveryServer(nil, ask); err == nil {
		t.Error("no server gave a look")
	}
}

// The parent lowers the DS TTL while the leaver's DS is still served: what it
// gave before can be held for the longer one from the look that saw it lowered.
func TestALoweredDSTTLCountsUntilWhatItGaveHasRunOut(t *testing.T) {
	r := newSweepRig(t, "dslowered.remove.example.")
	r.holds(roleN, dns.TypeDNSKEY)
	r.toDSStep()
	// the rig's parent has served both DS at a TTL of 900
	r.served(parentSeen{ns: r.parent.ns, nsTTL: 600, ds: []uint16{1, 2}, dsTTL: 120})
	r.next()
	r.served(parentSeen{ns: r.parent.ns, nsTTL: 600, ds: []uint16{1}, dsTTL: 120})
	r.next()
	r.aged(8 * time.Minute) // past the lower TTL and the delay, within the longer's
	r.next()
	if slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Fatalf("its DNSKEY went while a resolver can hold the DS from the longer TTL: %v", r.withdrawals)
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "for the DS TTL until ") {
		t.Errorf("the status: %q", line)
	}
	r.aged(13 * time.Minute) // past the longer TTL and the delay
	r.next()
	if !slices.Contains(r.withdrawals, "n.role.example DNSKEY") {
		t.Errorf("its DNSKEY did not go after them: %v, steps %v", r.withdrawals, r.taken())
	}
}

// A longer NS TTL is held on to in the same way.
func TestALoweredNSTTLCountsUntilWhatItGaveHasRunOut(t *testing.T) {
	r := newLeaverRig(t, "nslowered.remove.example.", "agent")
	r.zoneServesNS(60)
	r.next()
	r.next()
	// the rig's parent has named it at a TTL of 600
	r.served(parentSeen{ns: r.parent.ns, nsTTL: 60, nsServer: parentA})
	r.next()
	r.served(parentSeen{ns: []string{"ns1.a.example.", "ns1.b.example."}, nsTTL: 60, nsServer: parentA})
	r.next()
	r.aged(7 * time.Minute) // past the lower TTL and the delay, within the longer's
	r.next()
	if len(r.taken()) != 2 {
		t.Fatalf("went on while a resolver can hold the NS from the longer TTL: %v", r.taken())
	}
	r.aged(9 * time.Minute) // past the longer TTL and the delay
	r.next()
	if !slices.Equal(r.taken(), []string{"names", "ns", "confirmers"}) {
		t.Errorf("after them: %v", r.taken())
	}
}

// Only a lowering counts, and what it counts runs out: no largest TTL ever seen
// stays with the zone.
func TestOnlyALoweredTTLIsHeldTo(t *testing.T) {
	now := time.Now()
	ttl := func(s int) time.Duration { return time.Duration(s) * time.Second }
	seen := parentSeen{at: now, nsTTL: 900, dsTTL: 900}
	seen.after(parentSeen{nsTTL: 300, dsTTL: 300})
	if !seen.nsHeldTo.IsZero() || !seen.dsHeldTo.IsZero() {
		t.Errorf("a TTL raised: %v, %v", seen.nsHeldTo, seen.dsHeldTo)
	}
	first := parentSeen{at: now, nsTTL: 300, dsTTL: 300}
	first.after(parentSeen{nsTTL: 900, dsTTL: 900})
	if !first.dsHeldTo.Equal(now.Add(ttl(900))) || !first.nsHeldTo.Equal(now.Add(ttl(900))) {
		t.Errorf("a TTL lowered: %v, %v", first.nsHeldTo, first.dsHeldTo)
	}
	// as it stays where it was, it counts from no later look
	later := parentSeen{at: now.Add(time.Minute), nsTTL: 300, dsTTL: 300}
	later.after(first)
	if !later.dsHeldTo.Equal(first.dsHeldTo) || !later.nsHeldTo.Equal(first.nsHeldTo) {
		t.Errorf("a look at the same TTL moved it: %v, %v", later.nsHeldTo, later.dsHeldTo)
	}
	// a second lowering, from a TTL that ends sooner, does not bring it forward
	again := parentSeen{at: now.Add(time.Minute), dsTTL: 60}
	again.after(first)
	if !again.dsHeldTo.Equal(first.dsHeldTo) {
		t.Errorf("a second lowering brought it forward: %v", again.dsHeldTo)
	}
	// a DS no longer served is as last served, no lowering
	none := parentSeen{at: now.Add(time.Minute)}
	none.after(first)
	if none.dsTTL != 300 || !none.dsHeldTo.Equal(first.dsHeldTo) {
		t.Errorf("no DS: TTL %d, held to %v", none.dsTTL, none.dsHeldTo)
	}
}

// A server tells what it answers: a failed query of one RRset takes nothing from
// its answer for the other, and no server's behind for what it did not tell.
func TestAServerTellsWhatItAnswers(t *testing.T) {
	const leaving = "ns1.n.example."
	ns := func(names ...string) []dns.RR {
		var rrs []dns.RR
		for _, name := range names {
			rrs = append(rrs, &dns.NS{Hdr: dns.RR_Header{Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 600}, Ns: name})
		}
		return rrs
	}
	ds := func(tags ...uint16) []dns.RR {
		var rrs []dns.RR
		for _, tag := range tags {
			rrs = append(rrs, &dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 900}, KeyTag: tag, Algorithm: 15, DigestType: dns.SHA256, Digest: fmt.Sprintf("%04X", tag)})
		}
		return rrs
	}
	type answer struct {
		ns, ds       []dns.RR
		nsErr, dsErr error
	}
	failed := errors.New("no answer")
	look := func(a, b answer) (parentSeen, error) {
		return parentAtEveryServer([]string{parentA, parentB}, func(server string, rrtype uint16) ([]dns.RR, error) {
			one := a
			if server == parentB {
				one = b
			}
			if rrtype == dns.TypeNS {
				return one.ns, one.nsErr
			}
			return one.ds, one.dsErr
		})
	}
	holdsNS := func(one parentSeen) bool { return slices.Contains(one.ns, leaving) }
	holdsDS := func(one parentSeen) bool { return slices.Contains(one.ds, 2) }

	seen, err := look(answer{ns: ns("ns1.a.example.", leaving), dsErr: failed}, answer{ns: ns("ns1.a.example."), ds: ds(1)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(seen.ns, leaving) {
		t.Errorf("a failed DS query took the server's NS RRset: %v", seen.ns)
	}
	if got := seen.behind(parentSeen.toldNS, holdsNS); !slices.Equal(got, []string{parentA}) {
		t.Errorf("behind for its NS: %v", got)
	}
	if got := seen.behind(parentSeen.toldDS, holdsDS); len(got) != 0 {
		t.Errorf("behind for a DS it did not tell: %v", got)
	}

	seen, err = look(answer{nsErr: failed, ds: ds(1, 2)}, answer{ns: ns("ns1.a.example."), ds: ds(1)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(seen.ds, 2) {
		t.Errorf("a failed NS query took the server's DS RRset: %v", seen.ds)
	}
	if got := seen.behind(parentSeen.toldDS, holdsDS); !slices.Equal(got, []string{parentA}) {
		t.Errorf("behind for its DS: %v", got)
	}
	if got := seen.behind(parentSeen.toldNS, holdsNS); len(got) != 0 {
		t.Errorf("behind for an NS it did not tell: %v", got)
	}
	if seen.nsServer != parentB || seen.nsTTL != 600 {
		t.Errorf("the NS TTL from a server that did not tell it: %d from %s", seen.nsTTL, seen.nsServer)
	}

	// the only server that told it holds it: none is behind the one that did not
	seen, err = look(answer{ns: ns("ns1.a.example."), dsErr: failed}, answer{ns: ns("ns1.a.example."), ds: ds(1, 2)})
	if err != nil {
		t.Fatal(err)
	}
	if got := seen.behind(parentSeen.toldDS, holdsDS); len(got) != 0 {
		t.Errorf("one that told its DS is behind one that did not: %v", got)
	}
	if got := parentFrom(parentSeen{nsServer: parentA, noNS: true}, parentSeen{nsServer: parentB, ns: []string{leaving}}).nsServer; got != parentB {
		t.Errorf("the NS RRset's server: %s", got)
	}

	// no DS and a failed NS query: nothing shows it holds the zone
	seen, err = look(answer{nsErr: failed}, answer{ns: ns("ns1.a.example."), ds: ds(1, 2)})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen.each) != 1 {
		t.Errorf("a server that tells nothing was read: %+v", seen.each)
	}
	if got := seen.behind(parentSeen.toldDS, holdsDS); len(got) != 0 {
		t.Errorf("behind one that tells nothing: %v", got)
	}

	// with an RRset no server tells, it is not known: a look reading it gone
	// would end the watch on it
	if _, err := look(answer{ns: ns(leaving), dsErr: failed}, answer{ns: ns(leaving), dsErr: failed}); !errors.Is(err, failed) {
		t.Errorf("no server told the DS: %v", err)
	}
	if _, err := look(answer{nsErr: failed, ds: ds(2)}, answer{nsErr: failed, ds: ds(2)}); !errors.Is(err, failed) {
		t.Errorf("no server told the NS: %v", err)
	}
}

// Two servers behind are both named, in one order whichever answered first: a
// status that changes logs a line.
func TestServersBehindAreNamedInOneOrder(t *testing.T) {
	holds := func(one parentSeen) bool { return slices.Contains(one.ds, 2) }
	has := func(server string) parentSeen { return parentSeen{nsServer: server, ds: []uint16{2}} }
	dropped := parentSeen{nsServer: "192.0.2.3:53"}
	got := parentFrom(has(parentB), dropped, has(parentA)).behind(parentSeen.toldDS, holds)
	if !slices.Equal(got, []string{parentA, parentB}) {
		t.Errorf("behind: %v", got)
	}
	if said := behindSaid(got); !strings.Contains(said, parentA+", "+parentB) {
		t.Errorf("said: %q", said)
	}
	if said := behindSaid(nil); said != "" {
		t.Errorf("with none: %q", said)
	}
}
