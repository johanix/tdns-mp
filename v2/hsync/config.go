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

// DefaultConfig returns production-like defaults matching tdnsmp viper keys.
func DefaultConfig() Config {
	return Config{
		RetryInterval:      15 * time.Second,
		ReconcileInterval:  60 * time.Second,
		BeatInterval:       30 * time.Second,
		HelloRetryInterval: 60 * time.Second,
		HelloFastAttempts:  5,
		HelloFastSpacing:   2 * time.Second,
		DiscoverySemLimit:  8,
	}
}
