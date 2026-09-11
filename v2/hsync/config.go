/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import "time"

// Config holds protocol timing for hsync.Engine.
type Config struct {
	RetryInterval      time.Duration
	ReconcileInterval  time.Duration
	BeatInterval       time.Duration
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
		HelloRetryInterval: 15 * time.Second, // helloretry
		HelloFastAttempts:  3,                // hello_fast_attempts
		HelloFastSpacing:   2 * time.Second,  // hello_fast_interval
		DiscoverySemLimit:  8,
	}
}
