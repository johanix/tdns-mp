/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"log/slog"
	"time"
)

// dnssecValidationOffWarnInterval is how often a daemon whose resolver takes
// data it could not validate says so again.
const dnssecValidationOffWarnInterval = time.Hour

// dnssecValidationOffWarning is what it says.
const dnssecValidationOffWarning = "DNSSEC validation is OFF (imrengine.require-dnssec-validation: false): peers are discovered on DNS data that is not validated"

// warnWhileDnssecValidationOff logs, at start and then every
// dnssecValidationOffWarnInterval until ctx is done, that the daemon's
// resolver takes data it could not validate (#260). A node that discovers
// its peers on data nobody could vouch for is exposed, and a setting turned
// off to get past a broken chain is easily forgotten. With validation on it
// does nothing.
func (conf *Config) warnWhileDnssecValidationOff(ctx context.Context, lg *slog.Logger) {
	if !conf.Config.DnssecValidationOff() {
		return
	}
	lg.Warn(dnssecValidationOffWarning)
	go func() {
		ticker := time.NewTicker(dnssecValidationOffWarnInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				lg.Warn(dnssecValidationOffWarning)
			}
		}
	}()
}
