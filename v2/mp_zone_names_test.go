package tdnsmp

import (
	"slices"
	"strings"
	"sync"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// tdns-mp #401: the multi-provider zones are what the last parse found, each
// once, and a reader ranges over them while a reload collects the next.

// mpTestZone is a zone tdns holds, with the multi-provider option.
func mpTestZone(t *testing.T, name string) *tdns.ZoneData {
	t.Helper()
	zd := &tdns.ZoneData{ZoneName: name, Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}}
	tdns.Zones.Set(name, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(name)
		Zones.Invalidate(name)
	})
	return zd
}

// parse is one ParseZones as the option handler sees it, then the reload
// hook's refresh.
func parse(s *mpZoneNameSet, names ...string) {
	for _, n := range names {
		s.add(n)
	}
	s.refresh()
}

// Reloads find the same zones again: each is in the set once, also when a
// config spells it in another case.
func TestMPZoneNamesHoldEachZoneOnceOverReloads(t *testing.T) {
	a := mpTestZone(t, "a.names.example.")
	b := mpTestZone(t, "b.names.example.")
	var s mpZoneNameSet
	parse(&s, a.ZoneName, b.ZoneName)
	parse(&s, a.ZoneName, b.ZoneName)
	parse(&s, "A.Names.Example.", b.ZoneName)
	if got := s.names(); !slices.Equal(got, []string{a.ZoneName, b.ZoneName}) {
		t.Errorf("after three parses: %v, want each zone once", got)
	}
}

// A zone the config dropped leaves the set, and so does one that lost the
// option; a zone the config added joins it.
func TestMPZoneNamesFollowTheConfig(t *testing.T) {
	gone := mpTestZone(t, "gone.names.example.")
	plain := mpTestZone(t, "plain.names.example.")
	kept := mpTestZone(t, "kept.names.example.")
	var s mpZoneNameSet
	parse(&s, gone.ZoneName, plain.ZoneName, kept.ZoneName)

	tdns.Zones.Remove(gone.ZoneName)
	plain.Options[tdns.OptMultiProvider] = false
	added := mpTestZone(t, "added.names.example.")
	parse(&s, kept.ZoneName, added.ZoneName)
	if got := s.names(); !slices.Equal(got, []string{kept.ZoneName, added.ZoneName}) {
		t.Errorf("after the reload: %v, want the kept zone and the added one", got)
	}
}

// A parse that failed half-way leaves names collected that its next parse
// does not find. The refresh after that next parse holds only the zones tdns
// holds with the option: nothing stale stays.
func TestMPZoneNamesAfterAParseThatFailed(t *testing.T) {
	kept := mpTestZone(t, "kept.failed.names.example.")
	var s mpZoneNameSet
	parse(&s, kept.ZoneName)
	s.add("never.loaded.names.example.") // the failed parse, no refresh
	s.add(kept.ZoneName)
	parse(&s, kept.ZoneName) // the next parse
	if got := s.names(); !slices.Equal(got, []string{kept.ZoneName}) {
		t.Errorf("after a failed parse and the next: %v, want the kept zone alone", got)
	}
}

// Readers range over the set while reloads collect and publish: a snapshot
// is never written to after it is published. Run with -race.
func TestMPZoneNamesReadWhileAReloadPublishes(t *testing.T) {
	var names []string
	for _, l := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		names = append(names, mpTestZone(t, l+".race.names.example.").ZoneName)
	}
	conf := &Config{Config: &tdns.Config{}}
	s := &conf.InternalMp.mpZones
	parse(s, names[:4]...)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, n := range conf.mpZoneNames() {
					if !strings.HasSuffix(n, ".race.names.example.") {
						t.Errorf("a reader saw %q", n)
						return
					}
				}
			}
		}()
	}
	for i := 0; i < 500; i++ {
		parse(s, names[i%len(names)], names[(i+3)%len(names)])
	}
	close(stop)
	wg.Wait()
	if got := len(conf.mpZoneNames()); got != len(names) {
		t.Errorf("after the reloads %d zones, want %d", got, len(names))
	}
}

// A reload takes a zone the signer signs out of multi-provider, and the
// operator drops it from key-lifecycle-zones with it. The rollout gate does
// not count it any more: before, the zone stayed in the list for good, and
// the signer stopped itself over a correct config.
func TestTheRolloutGatePassesAZoneThatLeftMultiProvider(t *testing.T) {
	zd := mpTestZone(t, "left.gate.names.example.")
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Zones = []tdns.ZoneConf{{Name: zd.ZoneName, Type: "secondary", DnssecPolicy: "default"}}
	conf.SetMpConfig(&MultiProviderConf{Role: "signer", KeyLifecycleZones: []string{zd.ZoneName}})
	parse(&conf.InternalMp.mpZones, zd.ZoneName)
	if err := conf.keyLifecycleRolloutGate(); err != nil {
		t.Fatalf("listed: %v", err)
	}

	zd.Options[tdns.OptMultiProvider] = false // the reload's parse: no handler call for it
	conf.SetMpConfig(&MultiProviderConf{Role: "signer"})
	conf.RegisterMPRefreshCallbacks() // the reload hook
	if err := conf.keyLifecycleRolloutGate(); err != nil {
		t.Errorf("the zone is not multi-provider any more, and the gate refuses: %v", err)
	}
}
