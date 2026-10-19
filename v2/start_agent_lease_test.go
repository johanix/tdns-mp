/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// The lease is read from the agent's config as the daemon reads it. A value
// with a unit is taken as given. A bare number is a count of nanoseconds, so
// 300, meant as seconds, was a lease of 300 ns and the leader renewed it as
// fast as an election completes (#130): such a lease is refused, with an
// error that says the value takes a unit, and the default is used.
func TestLeaderElectionTTL(t *testing.T) {
	const tooShort = `"msg":"delegationsync.leader-election-ttl is below the floor`
	for _, tc := range []struct {
		name, config string
		want         time.Duration
		wantErr      bool
	}{
		{"not set", "", defaultLeaderElectionTTL, false},
		{"minutes", "delegationsync:\n   leader-election-ttl: 5m\n", 5 * time.Minute, false},
		{"seconds", "delegationsync:\n   leader-election-ttl: 300s\n", 5 * time.Minute, false},
		{"the floor itself", "delegationsync:\n   leader-election-ttl: 1m\n", time.Minute, false},
		{"a bare number", "delegationsync:\n   leader-election-ttl: 300\n", defaultLeaderElectionTTL, true},
		{"a bare number, quoted", "delegationsync:\n   leader-election-ttl: \"300\"\n", defaultLeaderElectionTTL, true},
		{"below the floor", "delegationsync:\n   leader-election-ttl: 30s\n", defaultLeaderElectionTTL, true},
		{"negative", "delegationsync:\n   leader-election-ttl: -5m\n", defaultLeaderElectionTTL, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logbuf := captureAgentLog(t)
			viper.Reset()
			t.Cleanup(viper.Reset)
			viper.SetConfigType("yaml")
			if err := viper.ReadConfig(strings.NewReader(tc.config)); err != nil {
				t.Fatalf("ReadConfig: %v", err)
			}
			if got := leaderElectionTTL(); got != tc.want {
				t.Errorf("lease = %v, want %v", got, tc.want)
			}
			if got := strings.Contains(logbuf.String(), tooShort); got != tc.wantErr {
				t.Errorf("error logged: %v, want %v; log: %s", got, tc.wantErr, logbuf.String())
			}
		})
	}
}
