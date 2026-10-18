/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// tdns-mp #207, the combiner's half: the first copy a combiner served after
// a start lacked its persisted contributions, among them the other signers'
// DNSKEYs; they were restored only in OnFirstLoad, after the first load had
// combined and published.

// The combiner, started with persisted DNSKEY contributions from the other
// signer: the first copy it serves holds them, and no second copy follows
// to add them.
func TestCombinerFirstCopyHoldsThePersistedContributions(t *testing.T) {
	asMPDaemon(t, AppTypeMPCombiner)
	kdb := newMPTestKeyDB(t)
	hdb := NewHsyncDB(kdb)
	if err := hdb.InitHsyncTables(); err != nil {
		t.Fatalf("InitHsyncTables: %v", err)
	}
	const zone = "restart.combiner.example."
	ksk, zsk := testDnskey(t, zone, 257), testDnskey(t, zone, 256)
	contrib := map[string]map[uint16]core.RRset{zone: {dns.TypeDNSKEY: {Name: zone, RRtype: dns.TypeDNSKEY, RRs: []dns.RR{ksk, zsk}}}}
	if err := SaveContributions(hdb, zone, relayOther, contrib); err != nil {
		t.Fatalf("SaveContributions: %v", err)
	}

	type served struct {
		tags   map[uint16]bool
		serial uint32
	}
	look := func(out chan served) func(*tdns.ZoneData) {
		return func(zd *tdns.ZoneData) {
			s := served{tags: map[uint16]bool{}}
			if apex, err := zd.GetOwner(zd.ZoneName); err == nil && apex != nil {
				for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
					s.tags[rr.(*dns.DNSKEY).KeyTag()] = true
				}
			}
			if soa, err := zd.GetSOA(); err == nil && soa != nil {
				s.serial = soa.Serial
			}
			out <- s
		}
	}
	first, after := make(chan served, 1), make(chan served, 1)

	up := startMPUpstream(t, zone, "alpha,beta", false, 40)
	mp := &MultiProviderConf{Role: "combiner", Active: true, Identity: "combiner.beta.example.",
		Agents: []*PeerConf{{Identity: relayUs}}}
	startMPServedZone(t, kdb, up, mp, nil, func(conf *Config, zd *tdns.ZoneData) {
		// as StartMPCombiner does, between two looks at the zone: what the
		// first load published, before the combiner's OnFirstLoad callback,
		// and the zone after it
		zd.OnFirstLoad = append(zd.OnFirstLoad, look(first))
		conf.RegisterCombinerOnFirstLoad()
		zd.OnFirstLoad = append(zd.OnFirstLoad, look(after))
		if mpzd, ok := Zones.Get(zone); !ok || mpzd.MP == nil || mpzd.MP.PersistContributions == nil {
			t.Error("the zone has no PersistContributions callback before its first load")
		}
	})
	wait := func(c chan served, what string) served {
		t.Helper()
		select {
		case s := <-c:
			return s
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: the OnFirstLoad callbacks did not run", what)
		}
		return served{}
	}
	f, a := wait(first, "the first copy"), wait(after, "after the combiner's callback")
	for _, k := range []*dns.DNSKEY{ksk, zsk} {
		if !f.tags[k.KeyTag()] {
			t.Errorf("the first copy the combiner served lacks the other signer's DNSKEY %d: it serves %v", k.KeyTag(), f.tags)
		}
	}
	if a.serial != f.serial {
		t.Errorf("the combiner published a second copy after its first load: serial %d, then %d", f.serial, a.serial)
	}
}
