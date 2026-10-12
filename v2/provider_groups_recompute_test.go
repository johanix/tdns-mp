/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Recomputes of the provider groups run one at a time (tdns-mp #181).
 */
package tdnsmp

import (
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Two zone refreshes end close together, and each recomputes the provider
// groups. The first has read the zones when the second zone's change lands;
// the second reads the zones with the change in them. The second's map has
// to be the one in place when both are done. It was the first's, whenever
// the first swapped last: the zone was then held in the group it had left,
// and reported as having joined it.
func TestOfTwoGroupRecomputesTheOneThatScannedLastIsInPlace(t *testing.T) {
	zone := providerZone(t, "mover.recompute.example.", arrivalA, arrivalB, arrivalC)
	pgm := NewProviderGroupManager(arrivalA)
	pgm.RecomputeGroups()
	inGroup(t, pgm, zone, arrivalA, arrivalB, arrivalC)

	var mu sync.Mutex
	var told []zoneGroupChange
	pgm.SetOnZoneJoinedGroup(func(z ZoneName, from, to string) {
		mu.Lock()
		told = append(told, zoneGroupChange{zone: z, from: from, to: to})
		mu.Unlock()
	})

	// The first recompute has read the zones, and has not put its map in
	// place yet. A scan after it is not held up here.
	scanned, release := make(chan struct{}), make(chan struct{})
	var held atomic.Bool
	pgm.afterScan = func() {
		if held.CompareAndSwap(false, true) {
			close(scanned)
			<-release
		}
	}
	firstDone := make(chan struct{})
	go func() {
		pgm.RecomputeGroups()
		close(firstDone)
	}()
	select {
	case <-scanned:
	case <-time.After(3 * time.Second):
		t.Fatalf("the first recompute did not scan")
	}

	// The owner's edit lands, and the refresh that brought it recomputes: it
	// is done, or it waits for the first, when the first goes on.
	serve(arrivalA, arrivalB).apply(t, zone)
	secondDone := make(chan struct{})
	go func() {
		pgm.RecomputeGroups()
		close(secondDone)
	}()
	select {
	case <-secondDone:
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	for _, done := range []chan struct{}{firstDone, secondDone} {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("a recompute did not finish")
		}
	}

	inGroup(t, pgm, zone, arrivalA, arrivalB)
	mu.Lock()
	defer mu.Unlock()
	want := []zoneGroupChange{{
		zone: ZoneName(zone.ZoneName),
		from: ComputeGroupHash([]string{arrivalA, arrivalB, arrivalC}),
		to:   ComputeGroupHash([]string{arrivalA, arrivalB}),
	}}
	if !slices.Equal(told, want) {
		t.Errorf("the zone's move was reported as %+v, want it reported once: %+v", told, want)
	}
}

// A recompute that waited its turn behind a scan that began after it was
// called does not scan again: that scan read the zones with its change in
// them. One that was called after the scan in place began does scan: the
// zones may have changed since.
func TestAGroupRecomputeBehindALaterScanDoesNotScanAgain(t *testing.T) {
	zone := providerZone(t, "waiter.recompute.example.", arrivalA, arrivalB, arrivalC)
	pgm := NewProviderGroupManager(arrivalA)
	scans := 0
	pgm.afterScan = func() { scans++ }
	moves := 0
	pgm.SetOnZoneJoinedGroup(func(ZoneName, string, string) { moves++ })

	// A refresh's recompute is called, and has not got its turn yet, when
	// the recompute of another refresh runs from start to end.
	called := pgm.scansBegun.Load()
	pgm.RecomputeGroups()
	if scans != 1 || moves != 1 {
		t.Fatalf("the first recompute scanned %d times and reported %d moves, want 1 and 1", scans, moves)
	}
	pgm.recomputeSince(called)
	if scans != 1 {
		t.Errorf("a recompute behind a scan that began after its call scanned again")
	}
	if moves != 1 {
		t.Errorf("a recompute that did not scan reported %d moves of its own", moves-1)
	}
	inGroup(t, pgm, zone, arrivalA, arrivalB, arrivalC)

	// A change after that scan, and the recompute that follows it.
	serve(arrivalA, arrivalB).apply(t, zone)
	pgm.RecomputeGroups()
	if scans != 2 {
		t.Fatalf("a recompute called after the scan in place did not scan (%d scans)", scans)
	}
	inGroup(t, pgm, zone, arrivalA, arrivalB)

	// The same for a recompute that was called while that scan ran: the
	// scan may have read the zone before the change the call is for.
	called = pgm.scansBegun.Load()
	pgm.recomputeSince(called)
	if scans != 3 {
		t.Errorf("a recompute called after the scan in place began did not scan (%d scans)", scans)
	}
}
