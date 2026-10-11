/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// The one test of the combiner under tdns's publish gate with a real
// cadence (main_test.go zeroes it for the rest): a second batch on a zone
// that has just published is staged, not served, until the gate's publish
// at the cadence. The daemons run with the 5 s default; this is what a
// caller sees there.
func TestCombineOnABusyZoneIsServedAtTheCadence(t *testing.T) {
	const zone = "combine-cadence.example."
	saved := tdns.DefaultPublishCadence
	tdns.DefaultPublishCadence = time.Second
	t.Cleanup(func() { tdns.DefaultPublishCadence = saved })

	q := withMPNotifyQ(t)
	mpzd := combinerTestZone(t, zone)
	mpzd.Notify = []tdns.PeerConf{{Addr: "127.0.0.1:5399"}}
	serial := mpzd.CurrentSerial

	// The first batch finds the zone idle: the gate publishes in the caller.
	if _, err := mpzd.AddCombinerData("agent-a", nsContribution(zone, "ns2."+zone)); err != nil {
		t.Fatalf("AddCombinerData(agent-a): %v", err)
	}
	if changed, err := mpzd.CombineWithLocalChanges(); err != nil || !changed {
		t.Fatalf("first batch: changed=%v err=%v", changed, err)
	}
	if got := servedNames(t, mpzd.ZoneData, zone, dns.TypeNS); !hasName(got, "ns2."+zone) {
		t.Fatalf("the first batch was not served at once on an idle zone: %v", got)
	}
	if mpzd.CurrentSerial != serial+1 || len(q) != 1 {
		t.Fatalf("first batch: serial %d (want %d), %d NOTIFYs (want 1)", mpzd.CurrentSerial, serial+1, len(q))
	}
	<-q

	// The second batch, within the cadence, finds the zone busy: staged,
	// the served snapshot and the serial as they were.
	if _, err := mpzd.AddCombinerData("agent-b", nsContribution(zone, "ns3."+zone)); err != nil {
		t.Fatalf("AddCombinerData(agent-b): %v", err)
	}
	if changed, err := mpzd.CombineWithLocalChanges(); err != nil || !changed {
		t.Fatalf("second batch: changed=%v err=%v", changed, err)
	}
	if got := servedNames(t, mpzd.ZoneData, zone, dns.TypeNS); hasName(got, "ns3."+zone) {
		t.Fatalf("the second batch was served at once on a busy zone: %v", got)
	}
	if mpzd.CurrentSerial != serial+1 || len(q) != 0 {
		t.Fatalf("second batch published by the caller: serial %d, %d NOTIFYs", mpzd.CurrentSerial, len(q))
	}

	// The gate's publish, one cadence on: the merged set served, one serial,
	// one NOTIFY.
	deadline := time.Now().Add(5 * time.Second)
	for !hasName(servedNames(t, mpzd.ZoneData, zone, dns.TypeNS), "ns3."+zone) {
		if time.Now().After(deadline) {
			t.Fatalf("the second batch was not served within 5 s of a 1 s cadence: %v", servedNames(t, mpzd.ZoneData, zone, dns.TypeNS))
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := servedNames(t, mpzd.ZoneData, zone, dns.TypeNS); len(got) != 3 {
		t.Errorf("served NS after the cadence %v, want the upstream plus both contributions", got)
	}
	if mpzd.CurrentSerial != serial+2 {
		t.Errorf("serial %d after the gate's publish, want %d", mpzd.CurrentSerial, serial+2)
	}
	select {
	case <-q:
	case <-time.After(2 * time.Second):
		t.Error("no NOTIFY for the gate's publish")
	}
}
