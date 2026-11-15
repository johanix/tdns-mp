package tdnsmp

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The leader's KEY goes to the apex always, and to the signal names under
// the zone's nameservers only when the customer's HSYNCPARAM says pubkey and
// the zone has HSYNC3: without it tdns's use-hsyncparam publishes there, each
// provider on its own (the project owner, 2026-11-06).
func TestTheKeyGoesToTheSignalNamesOnlyWhenTheCustomerSaysPubkey(t *testing.T) {
	mpzd := signerTestZone(t, "loc.owned.example.", newMPTestKeyDB(t))
	setParams := func(params string) {
		t.Helper()
		apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
		if err != nil || apex == nil {
			t.Fatalf("apex: %v", err)
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN HSYNCPARAM %s", mpzd.ZoneName, numberedText(params)))
		if err != nil {
			t.Fatalf("HSYNCPARAM %q: %v", params, err)
		}
		apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{rr}})
		mpzd.Data.Set(mpzd.ZoneName, *apex)
	}
	want := func(locs []string, atNS bool) {
		t.Helper()
		if len(locs) == 0 || locs[0] != "at-apex" {
			t.Fatalf("locations %v: the apex comes first, always", locs)
		}
		has := len(locs) == 2 && locs[1] == "at-ns"
		if has != atNS || len(locs) > 2 {
			t.Errorf("locations %v, want at-ns=%v", locs, atNS)
		}
	}
	// no HSYNCPARAM at all: the apex only
	want(publishLocations(ZoneName(mpzd.ZoneName)), false)
	setParams(`servers="us,p2" signers="us" parentsync="agent"`)
	want(publishLocations(ZoneName(mpzd.ZoneName)), false)
	setParams(`servers="us,p2" signers="us" parentsync="agent" pubkey`)
	want(publishLocations(ZoneName(mpzd.ZoneName)), false)
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	var records []dns.RR
	for _, r := range []string{"us agent.us.example.", "p2 agent.p2.example."} {
		rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN HSYNC3 ON %s .", mpzd.ZoneName, r))
		if err != nil {
			t.Fatalf("HSYNC3 %q: %v", r, err)
		}
		records = append(records, rr)
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: records})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	want(publishLocations(ZoneName(mpzd.ZoneName)), true)
	// a zone this agent does not hold: the apex only
	want(publishLocations("nowhere.example."), false)
}

// HSYNC3 added to a zone that says pubkey, which this agent leads alone, with
// no change of lead: the KEY it published in this lead went to the apex
// only, as a zone with no HSYNC3 has it, and now goes to the signal names
// too. By the zone's election check (zoneChanged), and by the take-up after
// the transition that added it, whose renewal keeps the key
// (renewalKeepsKey). The same key goes, with no new poll.
func TestHSYNC3AddedToALedZoneSendsItsKEYAtNS(t *testing.T) {
	for _, via := range []string{"takeup", "election"} {
		t.Run(via, func(t *testing.T) { keyAtNSOnceHSYNC3IsAdded(t, via) })
	}
}

func keyAtNSOnceHSYNC3IsAdded(t *testing.T, via string) {
	r := newKeyRoundRig(t, via+".atns.example.", "UPDATE")
	// the publish instructions of what this agent hands its combiner, a
	// recipient the queue takes as ready
	toCombiner := make(chan *core.PublishInstruction, 8)
	self := r.notifyRig.us
	self.Registry.S.Set(AgentId(rigCombiner), NewAgent(AgentId(rigCombiner)))
	self.Bridge.PeerRegistry.GetOrCreate(rigCombiner).SetMechanismState("DNS", transport.PeerStateOperational, "test")
	self.Bridge.TransportManager.StartReliableQueue(r.ctx, func(_ context.Context, m *transport.OutgoingMessage) error {
		if u, ok := m.Payload.(*ZoneUpdate); ok && m.RecipientID == rigCombiner && u.Publish != nil {
			toCombiner <- u.Publish
		}
		return nil
	})
	keySent := func(within time.Duration) *core.PublishInstruction {
		got, _ := recvWithin(toCombiner, within)
		return got
	}
	zd := r.mpzd.ZoneData
	us := shortLabel(string(r.us))
	setApex := func(withHSYNC3 bool) {
		t.Helper()
		apex, ok := zd.Data.Get(zd.ZoneName)
		if !ok {
			t.Fatal("the zone has no apex")
		}
		param, err := dns.NewRR(fmt.Sprintf("%s 3600 IN HSYNCPARAM %s", zd.ZoneName, numberedText(`servers="`+us+`" parentsync="agent" pubkey`)))
		if err != nil {
			t.Fatal(err)
		}
		apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{param}})
		apex.RRtypes.Delete(core.TypeHSYNC3)
		if withHSYNC3 {
			h3, err := dns.NewRR(fmt.Sprintf("%s 3600 IN HSYNC3 ON %s %s .", zd.ZoneName, us, r.us))
			if err != nil {
				t.Fatal(err)
			}
			apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: []dns.RR{h3}})
		}
		zd.Data.Set(zd.ZoneName, apex)
	}
	setApex(false)
	if got := publishLocations(r.zone); !slices.Equal(got, []string{"at-apex"}) {
		t.Fatalf("precondition: a zone with no HSYNC3 publishes its KEY at %v", got)
	}

	// the KEY published in this lead, its poll run to its end
	k := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.publish(t, k)
	if err := importSig0KeyFromPeer(NewHsyncDB(r.mpzd.KeyDB), string(r.zone), keyData(k)); err != nil {
		t.Fatal(err)
	}
	r.caughtUp()
	if err := r.conf.leaderKeySetup(r.ctx, r.zone, true); err != nil {
		t.Fatalf("the lead's set-up: %v", err)
	}
	if got := keySent(5 * time.Second); got == nil || !slices.Equal(got.Locations, []string{"at-apex"}) {
		t.Fatalf("the lead's set-up handed the combiner %+v, want the KEY at the apex only\n%s", got, r.alog)
	}
	r.polled(t, "the lead's set-up")
	waitUntil(t, "the poll of the zone's key did not end", func() bool {
		running, _, _ := r.conf.InternalMp.keyPolls.state(r.zone)
		return running == 0
	})

	// HSYNC3 added, the lead as it was
	setApex(true)
	switch via {
	case "takeup":
		r.conf.takeUp(r.ctx, r.zone)
	case "election":
		r.lem.SetOnKeyLocations(func(z ZoneName) error { return r.conf.sendKeyToNewLocations(r.ctx, z) })
		r.lem.zoneChanged(r.zone)
	}
	got := keySent(5 * time.Second)
	if got == nil || !slices.Equal(got.Locations, []string{"at-apex", "at-ns"}) || !slices.Equal(got.KEYRRs, []string{k.key.String()}) {
		t.Fatalf("once HSYNC3 is added the combiner was handed %+v, want the KEY at-ns too\n%s", got, r.alog)
	}
	r.notPolled(t, "the KEY sent to its new location")
	// sent once: a second check finds nothing gained
	if err := r.conf.sendKeyToNewLocations(r.ctx, r.zone); err != nil {
		t.Fatal(err)
	}
	if got := keySent(300 * time.Millisecond); got != nil {
		t.Errorf("the KEY went again with no location gained: %+v", got)
	}
}
