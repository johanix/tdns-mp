/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * S4a's gate: the signer does not start over a multi-provider zone that is
 * not in key-lifecycle-zones, unless the rollout is declared incomplete.
 */
package tdnsmp

import (
	"log/slog"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

func TestUnlistedMultiProviderZones(t *testing.T) {
	for _, c := range []struct {
		name   string
		served []string
		listed []string
		want   []string
	}{
		{"nothing served", nil, []string{"a.example."}, nil},
		{"all listed", []string{"a.example.", "b.example."}, []string{"b.example.", "a.example."}, nil},
		{"spelling: no dot, upper case", []string{"A.Example."}, []string{"a.example"}, nil},
		{"one missing, sorted", []string{"z.example.", "m.example.", "a.example."}, []string{"m.example."}, []string{"a.example.", "z.example."}},
		{"served twice, named once", []string{"a.example.", "a.example"}, nil, []string{"a.example."}},
	} {
		got := unlistedMultiProviderZones(c.served, c.listed)
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// The gate as the signer's start calls it: every multi-provider zone the
// signer serves (what ParseZones collected) against key-lifecycle-zones.
func TestSignerRefusesToStartOverAMultiProviderZoneNotInKeyLifecycleZones(t *testing.T) {
	var logbuf strings.Builder
	saved := lgSigner
	lgSigner = slog.New(slog.NewJSONHandler(&logbuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { lgSigner = saved })

	// served: the multi-provider zones this signer signs (a zone config with
	// a DNSSEC policy); unsigned: multi-provider zones it only serves
	gate := func(served []string, mp *MultiProviderConf, unsigned ...string) error {
		logbuf.Reset()
		conf := &Config{Config: &tdns.Config{}}
		for _, z := range served {
			conf.Config.Zones = append(conf.Config.Zones, tdns.ZoneConf{Name: z, Type: "secondary", DnssecPolicy: "default"})
		}
		for _, z := range unsigned {
			conf.Config.Zones = append(conf.Config.Zones, tdns.ZoneConf{Name: z, Type: "secondary"})
		}
		conf.InternalMp.MPZoneNames = append(append([]string{}, served...), unsigned...)
		if mp != nil {
			conf.SetMpConfig(mp)
		}
		return conf.keyLifecycleRolloutGate()
	}
	signer := func(incomplete bool, zones ...string) *MultiProviderConf {
		return &MultiProviderConf{Role: "signer", KeyLifecycleZones: zones, KeyLifecycleZonesIncomplete: incomplete}
	}
	logged := func(level string, zones ...string) bool {
		s := logbuf.String()
		if !strings.Contains(s, `"level":"`+level+`"`) {
			return false
		}
		for _, z := range zones {
			if !strings.Contains(s, z) {
				return false
			}
		}
		return true
	}

	// nothing multi-provider: nothing to gate, with or without a list
	if err := gate(nil, nil); err != nil {
		t.Errorf("no multi-provider zone, no multi-provider config: %v", err)
	}
	if err := gate(nil, signer(false, "a.example.")); err != nil {
		t.Errorf("no multi-provider zone, a list: %v", err)
	}
	if logbuf.Len() != 0 {
		t.Errorf("nothing to gate, yet something was logged:\n%s", logbuf.String())
	}

	// every zone listed: the signer starts, quietly
	if err := gate([]string{"a.example.", "b.example."}, signer(false, "b.example", "A.EXAMPLE.")); err != nil {
		t.Errorf("every multi-provider zone listed: %v", err)
	}
	if logbuf.Len() != 0 {
		t.Errorf("every zone listed, yet something was logged:\n%s", logbuf.String())
	}

	// a zone left off the list: refused, the zone named, the listed one not
	err := gate([]string{"a.example.", "b.example."}, signer(false, "a.example."))
	if err == nil {
		t.Fatal("a multi-provider zone not in key-lifecycle-zones did not refuse the start")
	}
	if !strings.Contains(err.Error(), "b.example.") || strings.Contains(err.Error(), "a.example.") {
		t.Errorf("the refusal names the wrong zones: %v", err)
	}
	if !logged("ERROR", "b.example.") {
		t.Errorf("the refusal was not logged as an error naming the zone:\n%s", logbuf.String())
	}

	// no list at all, and no multi-provider block at all: the same refusal
	if err := gate([]string{"a.example."}, signer(false)); err == nil || !strings.Contains(err.Error(), "a.example.") {
		t.Errorf("a multi-provider zone with no key-lifecycle-zones at all: %v, want a refusal naming it", err)
	}
	if err := gate([]string{"a.example."}, nil); err == nil || !strings.Contains(err.Error(), "a.example.") {
		t.Errorf("a multi-provider zone with no multi-provider block: %v, want a refusal naming it", err)
	}

	// the rollout declared incomplete: the zones left off are named in a
	// warning and the signer starts
	if err := gate([]string{"a.example.", "b.example."}, signer(true, "a.example.")); err != nil {
		t.Errorf("key-lifecycle-zones-incomplete set: %v, want the signer to start", err)
	}
	if !logged("WARN", "b.example.") || logged("ERROR") {
		t.Errorf("with the rollout incomplete, want a warning naming the zone and no error:\n%s", logbuf.String())
	}
	if strings.Contains(logbuf.String(), `"zones":["a.example."`) {
		t.Errorf("the warning names the listed zone:\n%s", logbuf.String())
	}
	// the knob with nothing left off: nothing to say
	if err := gate([]string{"a.example."}, signer(true, "a.example.")); err != nil || logbuf.Len() != 0 {
		t.Errorf("knob set and every zone listed: err=%v logged=%q, want nothing", err, logbuf.String())
	}

	// a multi-provider zone the signer only serves, as a non-signing provider
	// does, has no keys here: not gated, listed or not
	if err := gate([]string{"a.example."}, signer(false, "a.example."), "down.example."); err != nil || logbuf.Len() != 0 {
		t.Errorf("an unsigned multi-provider zone off the list: err=%v logged=%q, want nothing", err, logbuf.String())
	}
	if err := gate(nil, signer(false), "down.example."); err != nil || logbuf.Len() != 0 {
		t.Errorf("only unsigned multi-provider zones, no list: err=%v logged=%q, want nothing", err, logbuf.String())
	}
	if err := gate([]string{"a.example."}, signer(false), "down.example."); err == nil || strings.Contains(err.Error(), "down.example.") {
		t.Errorf("the signed zone off the list is refused and the unsigned one is not named: %v", err)
	}
}

// A zone reload runs the gate again: a reload whose signed multi-provider
// zones are all listed goes on; one that brings an unlisted zone stops the
// signer naming the zone, as a start would refuse; the rollout knob turns
// the stop into the warning.
func TestAZoneReloadPassesTheGateOrStopsTheSigner(t *testing.T) {
	var logbuf strings.Builder
	saved := lgSigner
	lgSigner = slog.New(slog.NewJSONHandler(&logbuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { lgSigner = saved })
	var stopped []string
	savedStop := signerStop
	signerStop = func(_ *Config, reason string) { stopped = append(stopped, reason) }
	t.Cleanup(func() { signerStop = savedStop })

	reload := func(listed []string, incomplete bool, signed ...string) {
		logbuf.Reset()
		stopped = nil
		conf := &Config{Config: &tdns.Config{}}
		for _, z := range signed {
			conf.Config.Zones = append(conf.Config.Zones, tdns.ZoneConf{Name: z, Type: "secondary", DnssecPolicy: "default"})
		}
		conf.InternalMp.MPZoneNames = append([]string{}, signed...)
		conf.SetMpConfig(&MultiProviderConf{Role: "signer", KeyLifecycleZones: listed, KeyLifecycleZonesIncomplete: incomplete})
		conf.signerZonesReloaded()
	}

	reload([]string{"a.example."}, false, "a.example.")
	if len(stopped) != 0 || logbuf.Len() != 0 {
		t.Errorf("every signed zone listed after the reload: stopped=%v logged=%q, want neither", stopped, logbuf.String())
	}

	reload([]string{"a.example."}, false, "a.example.", "b.example.")
	if len(stopped) != 1 || !strings.Contains(stopped[0], "b.example.") || strings.Contains(stopped[0], "a.example.") {
		t.Errorf("a reload that brought an unlisted signed zone: stopped=%v, want one stop naming b.example. only", stopped)
	}
	if !strings.Contains(logbuf.String(), `"level":"ERROR"`) || !strings.Contains(logbuf.String(), "b.example.") {
		t.Errorf("the stop was not logged as an error naming the zone:\n%s", logbuf.String())
	}

	reload([]string{"a.example."}, true, "a.example.", "b.example.")
	if len(stopped) != 0 || !strings.Contains(logbuf.String(), `"level":"WARN"`) || strings.Contains(logbuf.String(), `"level":"ERROR"`) {
		t.Errorf("the rollout knob on a reload: stopped=%v logged=%q, want a warning and no stop", stopped, logbuf.String())
	}
}
