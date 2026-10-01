/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import "time"

// Config holds protocol timing for hsync.Engine.
//
// BeatInterval is the steady gap between beat rounds; BeatIntervalMin the
// fast one the rounds start at, and return to on every change in the
// engine's view of its peers (beatSchedule). A BeatIntervalMin of zero or at
// or above BeatInterval keeps every round at BeatInterval.
type Config struct {
	RetryInterval      time.Duration
	ReconcileInterval  time.Duration
	BeatInterval       time.Duration
	BeatIntervalMin    time.Duration
	HelloRetryInterval time.Duration
	HelloFastAttempts  int
	HelloFastSpacing   time.Duration
	DiscoverySemLimit  int
}

// DefaultConfig returns the engine's defaults: what a daemon runs with for
// every multi-provider.syncengine.intervals key it does not set. They are
// the values the sample configs document (cmd/*/tdns-mp*.sample.yaml).
func DefaultConfig() Config {
	return Config{
		RetryInterval:      15 * time.Second, // discoveryretry
		ReconcileInterval:  60 * time.Second, // reconcile
		BeatInterval:       30 * time.Second, // beatinterval
		BeatIntervalMin:    2 * time.Second,  // beat_fast_interval
		HelloRetryInterval: 15 * time.Second, // helloretry
		HelloFastAttempts:  3,                // hello_fast_attempts
		HelloFastSpacing:   2 * time.Second,  // hello_fast_interval
		DiscoverySemLimit:  8,
	}
}
