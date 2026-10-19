package tdnsmp

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// keyWaitDelays are short enough that a round is a matter of milliseconds.
var keyWaitDelays = []time.Duration{5 * time.Millisecond, 10 * time.Millisecond}

// eventually waits for cond.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("after 5s: %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A zone that joined a group this agent leads, with a SIG(0) key that nobody
// has handed over yet. The peers were asked once, the sync was asked for
// without the key, failed, was retried and given up, and the change that
// moved the zone never reached the parent. The peers are asked again until
// one of them hands the key over, and the sync is asked for then, once.
func TestAZoneThatWaitsForItsKeyAsksAgainUntilItHasIt(t *testing.T) {
	var w zoneKeyWaits
	var tries, syncs atomic.Int32
	try := func() error {
		if tries.Add(1) < 3 {
			return errZoneKeyNotHeld
		}
		return nil
	}
	w.await(context.Background(), "arrived.example.", keyWaitDelays, func() bool { return true }, try,
		func() { syncs.Add(1) })

	// A second ask for the same zone while the first waits starts no second
	// round of asking.
	w.await(context.Background(), "arrived.example.", keyWaitDelays, func() bool { return true },
		func() error { t.Error("a second wait for the same zone asked the peers too"); return nil },
		func() { t.Error("a second wait for the same zone asked for a sync too") })

	eventually(t, "the sync was never asked for", func() bool { return syncs.Load() == 1 })
	if got := tries.Load(); got != 3 {
		t.Errorf("the peers were asked %d times, want 3: twice without the key, once with it", got)
	}
	time.Sleep(40 * time.Millisecond)
	if got := tries.Load(); got != 3 {
		t.Errorf("the peers were asked %d times in the end: the asking went on after the key was there", got)
	}
	if got := syncs.Load(); got != 1 {
		t.Errorf("the sync was asked for %d times, want once", got)
	}

	// The zone is no longer waited for: a later arrival asks again.
	eventually(t, "the zone is still marked as waiting", func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return !w.waiting["arrived.example."]
	})
}

// The sync is not asked for while the key is missing, however long that is:
// the last delay repeats.
func TestAZoneThatWaitsForItsKeyGetsNoSyncWithoutIt(t *testing.T) {
	var w zoneKeyWaits
	var tries, syncs atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.await(ctx, "keyless.example.", keyWaitDelays, func() bool { return true },
		func() error { tries.Add(1); return errZoneKeyNotHeld },
		func() { syncs.Add(1) })

	eventually(t, "the peers were not asked again and again", func() bool { return tries.Load() >= 5 })
	if got := syncs.Load(); got != 0 {
		t.Fatalf("the sync was asked for %d times with no key to sign it", got)
	}

	// The engine ending ends the wait.
	cancel()
	time.Sleep(30 * time.Millisecond)
	n := tries.Load()
	time.Sleep(40 * time.Millisecond)
	if got := tries.Load(); got != n {
		t.Errorf("the peers were asked %d more times after the context ended", got-n)
	}
}

// An agent that no longer leads the zone asks no more, and asks for no sync.
// A key setup that fails for another reason is tried again.
func TestAZoneThatWaitsForItsKeyStopsWhenTheAgentNoLongerLeads(t *testing.T) {
	var w zoneKeyWaits
	var tries, syncs atomic.Int32
	var leads atomic.Bool
	leads.Store(true)
	w.await(context.Background(), "moved.example.", keyWaitDelays, leads.Load,
		func() error {
			if tries.Add(1) == 1 {
				return errors.New("publication failed")
			}
			return errZoneKeyNotHeld
		},
		func() { syncs.Add(1) })

	eventually(t, "a key setup that failed for another reason was not tried again", func() bool { return tries.Load() >= 3 })
	leads.Store(false)
	time.Sleep(30 * time.Millisecond)
	n := tries.Load()
	time.Sleep(40 * time.Millisecond)
	if got := tries.Load(); got != n {
		t.Errorf("the peers were asked %d more times after the agent stopped leading the zone", got-n)
	}
	if got := syncs.Load(); got != 0 {
		t.Errorf("the sync was asked for %d times by an agent that does not lead the zone", got)
	}
}

// An arrival whose key setup fails for another reason than a key nobody has
// handed over, a key that could not be made or published, waits the same
// way: the sync is not asked for while the setup fails, since it could not be
// signed, and it is asked for once the setup has worked.
func TestAZoneWhoseKeySetupFailsWaitsAsForAMissingKey(t *testing.T) {
	var w zoneKeyWaits
	var tries, syncs atomic.Int32
	try := func() error {
		switch tries.Add(1) {
		case 1:
			return errors.New("failed to generate SIG(0) keypair")
		case 2:
			return errors.New("failed to publish KEY to combiner")
		}
		return nil
	}
	w.await(context.Background(), "failing.example.", keyWaitDelays, func() bool { return true }, try,
		func() { syncs.Add(1) })
	eventually(t, "the sync was never asked for", func() bool { return syncs.Load() == 1 })
	if got := tries.Load(); got != 3 {
		t.Errorf("the setup ran %d times, want 3: twice failing, once working", got)
	}
}
