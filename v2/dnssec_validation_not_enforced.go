/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"log/slog"
	"time"
)

// dnssecNotEnforcedWarnInterval is how often a daemon whose resolver takes
// data it could not validate says so again.
const dnssecNotEnforcedWarnInterval = time.Hour

// dnssecNotEnforcedWarning is what it says.
const dnssecNotEnforcedWarning = "DNSSEC validation is not enforced (imrengine.require-dnssec-validation: false): a peer is used even when its DNS data does not validate"

// warnWhileDnssecNotEnforced logs, at start and then every
// dnssecNotEnforcedWarnInterval until ctx is done, that the daemon's
// resolver takes data it could not validate (#260). A node that discovers
// its peers on data nobody could vouch for is exposed, and a setting turned
// off to get past a broken chain is easily forgotten. With validation on it
// does nothing.
func (conf *Config) warnWhileDnssecNotEnforced(ctx context.Context, lg *slog.Logger) {
	if !conf.Config.DnssecValidationNotEnforced() {
		return
	}
	lg.Warn(dnssecNotEnforcedWarning)
	go func() {
		ticker := time.NewTicker(dnssecNotEnforcedWarnInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				lg.Warn(dnssecNotEnforcedWarning)
			}
		}
	}()
}
