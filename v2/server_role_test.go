/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"crypto"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	srUpstream = "a.role.example."
	srNewcomer = "n.role.example."
)

var srNameservers = []string{"ns1.n.example.", "ns2.n.example."}

// servingRig is an agent of a zone whose servers are a, b and n, n's
// upstream a, the zone's signer, whose key this agent holds as a's agent
// distributed it.
type servingRig struct {
	conf *Config
	zone string
	key  *dns.DNSKEY
	priv crypto.Signer
}

func newServingRig(t *testing.T, zone, identity string) *servingRig {
	t.Helper()
	asMPAgent(t)
	instrTestZone(t, zone, `3600 IN HSYNC3 ON a `+srUpstream+` .`, `3600 IN HSYNC3 ON b b.role.example. .`,
		`3600 IN HSYNC3 ON n `+srNewcomer+` a`, `3600 IN HSYNCPARAM `+numberedText(`servers="a,b,n" signers="a"`))
	conf := &Config{Config: &tdns.Config{}}
	mp := &MultiProviderConf{Role: "agent", Identity: identity}
	mp.Local.Nameservers = srNameservers
	conf.SetMpConfig(mp)
	conf.InternalMp.transfers.start = func(check func()) { check() }
	r := &servingRig{conf: conf, zone: zone}
	r.key, r.priv = signingKey(t, zone)
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	ar, _ := NewAgentRepo()
	nod := tdns.NewOwnerData(zone)
	nod.RRtypes.Set(dns.TypeDNSKEY, core.RRset{RRs: []dns.RR{r.key}})
	ar.Set(srUpstream, nod)
	zdr.Repo.Set(ZoneName(zone), ar)
	conf.InternalMp.ZoneDataRepo = zdr
	return r
}

func signingKey(t *testing.T, zone string) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 256, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	return key, priv.(crypto.Signer)
}

// soa is the zone's SOA at serial, signed by key, or unsigned with no key.
func soa(t *testing.T, zone string, serial uint32, key *dns.DNSKEY, priv crypto.Signer) *core.RRset {
	t.Helper()
	s := &dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns: "ns1." + zone, Mbox: "hostmaster." + zone, Serial: serial, Refresh: 7200, Retry: 1800, Expire: 604800, Minttl: 7200}
	rrset := &core.RRset{RRs: []dns.RR{s}}
	if key == nil {
		return rrset
	}
	now := time.Now()
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		KeyTag: key.KeyTag(), SignerName: zone, Algorithm: key.Algorithm,
		Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(time.Hour).Unix())}
	if err := sig.Sign(priv, rrset.RRs); err != nil {
		t.Fatal(err)
	}
	rrset.RRSIGs = []dns.RR{sig}
	return rrset
}

// serving has every nameserver answer with rrset, and asked collect the
// nameservers asked.
func serving(t *testing.T, rrset *core.RRset, asked *[]string) {
	t.Helper()
	saved := servingLookup
	servingLookup = func(_ context.Context, _ string, ns string) (*core.RRset, error) {
		if asked != nil {
			*asked = append(*asked, ns)
		}
		if rrset == nil {
			return nil, errors.New("no answer")
		}
		return rrset, nil
	}
	t.Cleanup(func() { servingLookup = saved })
}

func serverRoleStep(id string) InstrStep {
	return InstrStep{Number: 1, Of: 2, Digest: "d1", Taken: []string{serverRoleKey + id}}
}

// The record: a provider whose HSYNC3 record is added, with no role, has
// nothing to carry out (design 5.1): the judge agrees, and the transition
// is its last step alone, done once the parts hold the serial.
func TestARecordIsDoneWhenThePartsHoldIt(t *testing.T) {
	from := jAt(t, 41, `servers="a,b" suffix="n"`, freezeRecords[:2]...)
	to := jAt(t, 42, `servers="a,b" suffix="n"`, freezeRecords...)
	if rs := judgeTransition(from, to); len(rs) > 0 {
		t.Fatalf("the record is refused: %v", rs)
	}
	plan := planSteps(planView{from: from, to: to, held: rolesFor(from, from, 0)})
	if len(plan) != 1 || plan[0].key != lastStepKey {
		t.Fatalf("the steps: %v, want the last alone", plan)
	}
}

// A server role (design 5.1): the judge agrees it once the provider has a
// record; its step comes before the last and changes no set; at the
// provider's own agent it is held only once its nameservers serve the zone
// from its upstream, at the zone's serial or later, signed by the
// upstream's key. Another agent's part of it is its parts alone.
func TestAServerRoleStepWaitsUntilTheProvidersServersServeTheUpstreamsCopy(t *testing.T) {
	from := jAt(t, 42, `servers="a,b" signers="a"`, freezeRecords...)
	to := jAt(t, 43, `servers="a,b,n" signers="a"`, freezeRecords...)
	if rs := judgeTransition(from, to); len(rs) > 0 {
		t.Fatalf("the server role is refused: %v", rs)
	}
	held := rolesFor(from, from, 0)
	plan := planSteps(planView{from: from, to: to, held: held})
	if len(plan) != 2 || plan[0].key != serverRoleKey+srNewcomer || plan[0].kind != stepAddition || plan[0].sets != nil {
		t.Fatalf("the steps: %+v", plan)
	}
	if plan := planSteps(planView{from: from, to: to, held: rolesFor(to, to, 0)}); len(plan) != 1 {
		t.Fatalf("a step for a provider the sets held serve: %+v", plan)
	}

	r := newServingRig(t, "role.serving.example.", srNewcomer)
	step := serverRoleStep(srNewcomer)
	serving(t, soa(t, r.zone, 0, r.key, r.priv), nil)
	if serverRoleHolds(r.conf, r.zone, step) {
		t.Error("held while the nameservers serve serial 0, below the zone's 1")
	}
	// the next check waits for transferRecheck
	r.conf.InternalMp.transfers.zones[canonicalName(r.zone)].at = time.Now().Add(-transferRecheck)
	var asked []string
	serving(t, soa(t, r.zone, 7, r.key, r.priv), &asked)
	if !serverRoleHolds(r.conf, r.zone, step) {
		t.Error("not held once the nameservers serve the upstream's copy")
	}
	if !slices.Equal(asked, srNameservers) {
		t.Errorf("asked %v, want each of the provider's own nameservers", asked)
	}

	other := newServingRig(t, "other.serving.example.", "b.role.example.")
	serving(t, nil, nil)
	if !serverRoleHolds(other.conf, other.zone, step) {
		t.Error("another agent's part of the step waits for the newcomer's nameservers")
	}
}

// The serving check reads the SOA of each nameserver: its serial at least
// the zone's by RFC 1982, and each RRSIG over it by a key of the expected
// signers, valid, verifying.
func TestTheServingCheckReadsTheSOAAndTheSigners(t *testing.T) {
	zone := "check.serving.example."
	key, priv := signingKey(t, zone)
	stranger, strangerPriv := signingKey(t, zone)
	keys := []dns.RR{key}
	for _, c := range []struct {
		name  string
		rrset *core.RRset
		min   uint32
		ok    bool
	}{
		{"the upstream's copy", soa(t, zone, 10, key, priv), 10, true},
		{"a serial past the wrap", soa(t, zone, 3, key, priv), 0xfffffff0, true},
		{"a serial below the zone's", soa(t, zone, 9, key, priv), 10, false},
		{"unsigned", soa(t, zone, 10, nil, nil), 10, false},
		{"signed by another key", soa(t, zone, 10, stranger, strangerPriv), 10, false},
	} {
		serving(t, c.rrset, nil)
		served, err := servingChainOK(context.Background(), zone, srNameservers, keys, c.min, time.Now())
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok %v", c.name, err, c.ok)
		}
		if c.ok && served != c.rrset.RRs[0].(*dns.SOA).Serial {
			t.Errorf("%s: served %d", c.name, served)
		}
	}
	serving(t, soa(t, zone, 10, key, priv), nil)
	if _, err := servingChainOK(context.Background(), zone, nil, keys, 1, time.Now()); err == nil {
		t.Error("ok with no nameserver named")
	}
	if _, err := servingChainOK(context.Background(), zone, srNameservers, nil, 1, time.Now()); err == nil {
		t.Error("ok with no key of the expected signers")
	}
}

// The status: every agent says whose nameservers the step waits for, at
// what serial; the provider's own, past transferHelpAfter, what its
// operator must point where; nothing once held.
func TestTheStatusSaysWhatTheOperatorMustPoint(t *testing.T) {
	r := newServingRig(t, "status.serving.example.", srNewcomer)
	step := serverRoleStep(srNewcomer)
	want := "waiting for n.role.example.'s nameservers to serve the zone from its upstream at serial 1 or later"
	point := "its operator must point ns1.n.example., ns2.n.example. at a.role.example. for the zone's transfer"
	now := time.Now()
	if got := serverRoleStatus(r.conf, r.zone, heldStep{InstrStep: step, at: now}, now); got != want {
		t.Errorf("the status: %q, want %q", got, want)
	}
	got := serverRoleStatus(r.conf, r.zone, heldStep{InstrStep: step, at: now.Add(-transferHelpAfter)}, now)
	if !strings.HasPrefix(got, want) || !strings.HasSuffix(got, point) {
		t.Errorf("the status after a while: %q, want what to point where", got)
	}
	other := newServingRig(t, "status.other.serving.example.", "b.role.example.")
	if got := serverRoleStatus(other.conf, other.zone, heldStep{InstrStep: step, at: now.Add(-transferHelpAfter)}, now); !strings.HasPrefix(got, "waiting for n.role.example.'s") || strings.Contains(got, "point") {
		t.Errorf("another agent's status: %q", got)
	}
	serving(t, soa(t, r.zone, 1, r.key, r.priv), nil)
	if !serverRoleHolds(r.conf, r.zone, step) {
		t.Fatal("not held")
	}
	if got := serverRoleStatus(r.conf, r.zone, heldStep{InstrStep: step, at: now}, now); got != "" {
		t.Errorf("the status once held: %q", got)
	}
}

// A provider that a thaw's activation puts in servers= or signers=, a list
// it was not in, is asked for the zone's state by every agent: peer-role
// (design 5.1), as at a refresh.
func TestAProviderThatEntersAListIsAskedForItsState(t *testing.T) {
	r := newRefreshRig(t, "entered.serving.example.")
	recs := []h3rec{{usAgent, true}, {otherAgent, true}, {thirdAgent, true}}
	r.serve(t, recs, []string{usAgent, otherAgent})
	from := r.mpzd.instructions()
	r.serve(t, recs, []string{usAgent, otherAgent, thirdAgent})
	r.t.peersEntered(ZoneName(r.mpzd.ZoneName), from, r.mpzd.instructions())
	if got := r.asked(); len(got) != 1 || got[thirdAgent] != catchUpPeerRole {
		t.Errorf("asked %v, want the provider that entered servers= with peer-role", got)
	}
}

// putBackRig is an answer rig ("us", p2, p3) whose zone lists servers= and
// signers= as given.
func newPutBackRig(t *testing.T, zone, param string) *answerRig {
	t.Helper()
	asMPAgent(t)
	mpzd := instrTestZone(t, zone, `3600 IN HSYNC3 ON us `+usAgent+` .`, `3600 IN HSYNC3 ON p2 agent.p2.example. .`,
		`3600 IN HSYNC3 ON p3 agent.p3.example. .`, `3600 IN HSYNCPARAM `+numberedText(param))
	return answerRigOn(t, mpzd, nil)
}

// sentTo are the recipients of what is queued, sorted.
func (r *answerRig) sentTo() []string {
	var out []string
	for _, m := range r.queue.GetPendingMessages() {
		out = append(out, m.RecipientID)
	}
	slices.Sort(out)
	return out
}

// A provider put back into servers= (design 5.1): its own agent sends a
// complete replace of what it may now contribute, NS, in the catch-up
// answer's form, to every other member and to its combiner; a provider
// that did not enter a list sends nothing.
func TestAProviderPutBackSendsItsContributionsAgain(t *testing.T) {
	r := newPutBackRig(t, "putback.serving.example.", `servers="us,p2" signers="p2"`)
	from := readOf(t, `3600 IN HSYNC3 ON us `+usAgent+` .`, `3600 IN HSYNC3 ON p2 agent.p2.example. .`, `3600 IN HSYNCPARAM `+numberedText(`servers="p2" signers="p2"`))
	if !enteredAList(from, instructionsFor(r.zone), usAgent) || enteredAList(from, instructionsFor(r.zone), "agent.p2.example.") {
		t.Fatal("enteredAList: us entered servers=, p2 entered nothing")
	}
	r.holds(t, r.ns("ns.us.example."))
	members, combiner, _ := r.conf.putBackOps(r.zdr, r.zone)
	for _, o := range [][]core.RROperation{members, combiner} {
		if len(o) != 1 || o[0].Operation != "replace" || o[0].RRtype != "NS" || len(o[0].Records) != 1 {
			t.Errorf("the put-back: %+v, want a complete replace of its NS", o)
		}
	}
	r.conf.putBack(r.zdr, r.zone)
	if got := r.sentTo(); !slices.Equal(got, []string{"agent.p2.example.", "agent.p3.example.", answerCombiner}) {
		t.Errorf("sent to %v, want the two other members and the combiner", got)
	}
	// p2 entered no list: nothing goes
	r.conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: "agent.p3.example."})
	if members, _, _ := r.conf.putBackOps(r.zdr, r.zone); members != nil {
		t.Errorf("a provider in no list sends %+v", members)
	}
}

// A server put back gets no NS until its operator adds them: the replace
// carries the NS its own data holds, none after its records were
// withdrawn, and its operator's once added.
func TestAServerPutBackGetsNoNSUntilItsOperatorAddsThem(t *testing.T) {
	r := newPutBackRig(t, "nons.serving.example.", `servers="us,p2" signers="p2"`)
	if members, _, _ := r.conf.putBackOps(r.zdr, r.zone); len(members) != 1 || members[0].RRtype != "NS" || len(members[0].Records) != 0 {
		t.Fatalf("the put-back: %+v, want an empty replace of its NS", members)
	}
	r.holds(t, r.ns("ns.us.example."))
	if op := ops(r.answer(t))["NS"]; len(op.Records) != 1 {
		t.Errorf("the NS its operator added: %+v", op)
	}
}

// The record's newcomer: every agent's status shows whether each member has
// caught up, from the member's own stamp (design 5.1).
func TestEveryAgentsStatusShowsWhetherAMemberHasCaughtUp(t *testing.T) {
	r := newThawRig(t, "caughtup.serving.example.", roleA)
	caughtUp := false
	tbl := newStampTable(roleA, r.store, 1, true, nil)
	tbl.caughtUp = func(string) bool { return caughtUp }
	if st, ok := tbl.ownStamp(r.zone); !ok || st.CaughtUp {
		t.Fatalf("the stamp says caught up before it has: %+v", st)
	}
	caughtUp = true
	if st, _ := tbl.ownStamp(r.zone); !st.CaughtUp || !memberRow(roleN, st).CaughtUp {
		t.Error("the stamp or the status row does not say caught up")
	}
}
