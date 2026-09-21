/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The signer's resolver: a signer that owns a zone starts one, because the
 * key machine asks it whether the parent still serves a retired KSK's DS;
 * and the machine's question is "unknown" until the resolver has published.
 */
package tdnsmp

import (
	"context"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

func TestSignerStartsAResolverOnlyWhenItOwnsAZone(t *testing.T) {
	off, on := false, true
	for _, c := range []struct {
		name    string
		zones   []string
		active  *bool
		want    bool
		wantWhy bool
	}{
		{"owns nothing", nil, nil, false, false},
		{"owns nothing, resolver asked for", nil, &on, false, false},
		{"owns a zone", []string{"owned.example."}, nil, true, false},
		{"owns a zone, resolver on", []string{"owned.example."}, &on, true, false},
		{"owns a zone, resolver turned off", []string{"owned.example."}, &off, false, true},
	} {
		conf := &Config{Config: &tdns.Config{}}
		conf.SetMpConfig(&MultiProviderConf{Role: "signer", KeyLifecycleZones: c.zones})
		conf.Config.Imr.Active = c.active
		want, why := conf.signerResolverWanted()
		if want != c.want || (why != "") != c.wantWhy {
			t.Errorf("%s: wanted=%v why=%q, want wanted=%v why set=%v", c.name, want, why, c.want, c.wantWhy)
		}
	}
	// no multi-provider config at all
	if want, why := (&Config{Config: &tdns.Config{}}).signerResolverWanted(); want || why != "" {
		t.Errorf("no multi-provider config: wanted=%v why=%q", want, why)
	}
}

// Before the resolver has published, and in a signer without one, the
// machine's question about the parent's DS has no answer: the key waits.
func TestParentServesDSIsUnknownUntilTheResolverPublished(t *testing.T) {
	conf := &Config{Config: &tdns.Config{}}
	w := &signerWire{conf: conf}
	if present, known := w.ParentServesDS("owned.example.", 4711); present || known {
		t.Errorf("no readiness signal at all: present=%v known=%v, want unknown", present, known)
	}
	conf.Config.Internal.ImrReady = tdns.NewImrReadiness()
	if present, known := w.ParentServesDS("owned.example.", 4711); present || known {
		t.Errorf("resolver not published yet: present=%v known=%v, want unknown", present, known)
	}
	// published with no engine behind it (cannot happen in the daemon, which
	// stores the pointer first): still unknown, never a nil dereference
	conf.Config.Internal.ImrReady.Publish()
	if present, known := w.ParentServesDS("owned.example.", 4711); present || known {
		t.Errorf("published without an engine: present=%v known=%v, want unknown", present, known)
	}
}

// The signer's KeysChanged must reach tdns's DS engine: that is what makes an
// owned zone's CDS follow a ds column change between transfers (arrow 1).
// Through the real pieces: the KeyDB as tdns's constructor makes it (which
// is how tdns-mp's roles get theirs, after tdns's MainInit has already
// decided not to make the engine's queue), the signer's start-up helper,
// tdns's DS engine, and the signer's own wire. The test plays the zone
// updater: a CDS publish arriving on the KeyDB's update queue is the proof.
func TestSignerKeysChangedReachesTheDSEngine(t *testing.T) {
	mpzd := trackTestZone(t, "wake.owned.example.") // signed by us and p2, with its HSYNC records
	kdb := mpzd.KeyDB
	if kdb.DSEngineQ != nil {
		t.Log("tdns's KeyDB constructor now makes the DS engine's queue itself; ensureDSEngineQueue is a no-op")
	}
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.SetMpConfig(&MultiProviderConf{Role: "signer", Agents: []*PeerConf{{Identity: "agent.us.example."}}, KeyLifecycleZones: []string{mpzd.ZoneName}})
	owner := RegisterMPKeyLifecycleOwner(conf)
	t.Cleanup(func() { tdns.RegisterKeyLifecycleOwner(nil) })
	e := NewKeyLifecycleEngine(conf, owner)
	e.TakeConfiguredZones()
	if z := owner.Zones(); len(z) != 1 {
		t.Fatalf("the zone was not taken: %v", z)
	}
	// an active KSK whose DS belongs at the parent, and its ZSK
	ksk := mpGenKey(t, kdb, mpzd.ZoneName, tdns.DnskeyStateActive, "KSK")
	mpGenKey(t, kdb, mpzd.ZoneName, tdns.DnskeyStateActive, "ZSK")
	if err := e.driver(mpzd.ZoneName).Reload(); err != nil { // adopts the rows: the KSK gets ds=1
		t.Fatal(err)
	}
	in, err := tdns.DSIntentForZone(kdb, mpzd.ZoneName, dns.SHA256)
	if err != nil || !in.Known || len(in.Set) != 1 {
		t.Fatalf("the DS intent before the wake: known=%v set=%d err=%v, want the one KSK", in.Known, len(in.Set), err)
	}

	// served, as after the signer's first publish: the engine reads the CDS
	// the zone serves now before it decides what to publish
	mpzd.ZoneData.Ready = true
	t.Cleanup(mpzd.ZoneData.StopPublisher)

	ensureDSEngineQueue(kdb)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go kdb.DSEngine(ctx)

	(&signerWire{conf: conf}).KeysChanged(mpzd.ZoneName)

	select {
	case req := <-kdb.UpdateQ:
		var tags []uint16
		for _, rr := range req.Actions {
			if cds, ok := rr.(*dns.CDS); ok && rr.Header().Class == dns.ClassINET {
				tags = append(tags, cds.KeyTag)
			}
		}
		if req.ZoneName != mpzd.ZoneName || len(tags) != 1 || tags[0] != ksk {
			t.Errorf("the DS engine asked to publish %v for %s, want the CDS of KSK %d", req.Actions, req.ZoneName, ksk)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("KeysChanged never reached the DS engine: no CDS publish was asked for")
	}
}
