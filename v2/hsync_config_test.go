package tdnsmp

import (
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
)

// hsyncConfigFromMp: the engine's defaults unless a syncengine.intervals
// key is set, in which case that key, in seconds.
func TestHsyncConfigFromMp(t *testing.T) {
	def := hsync.DefaultConfig()
	if got := hsyncConfigFromMp(nil); got != def {
		t.Fatalf("nil config: got %+v, want the defaults %+v", got, def)
	}
	var mp MultiProviderConf
	if got := hsyncConfigFromMp(&mp); got != def {
		t.Fatalf("empty config: got %+v, want the defaults %+v", got, def)
	}

	mp.Remote.BeatInterval = 10
	mp.Syncengine.Intervals.BeatFastInterval = 1
	mp.Syncengine.Intervals.HelloRetry = 5
	mp.Syncengine.Intervals.DiscoveryRetry = 6
	mp.Syncengine.Intervals.Reconcile = 7
	mp.Syncengine.Intervals.HelloFastAttempts = 3
	mp.Syncengine.Intervals.HelloFastInterval = 2
	mp.Syncengine.Intervals.PeerHold = 300
	want := hsync.Config{
		RetryInterval:      6 * time.Second,
		ReconcileInterval:  7 * time.Second,
		BeatInterval:       10 * time.Second,
		BeatIntervalMin:    1 * time.Second,
		HelloRetryInterval: 5 * time.Second,
		HelloFastAttempts:  3,
		HelloFastSpacing:   2 * time.Second,
		DiscoverySemLimit:  def.DiscoverySemLimit,
		PeerHold:           300 * time.Second,
	}
	if got := hsyncConfigFromMp(&mp); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	// One key set, the rest left at the defaults.
	mp = MultiProviderConf{}
	mp.Syncengine.Intervals.HelloRetry = 5
	want = def
	want.HelloRetryInterval = 5 * time.Second
	if got := hsyncConfigFromMp(&mp); got != want {
		t.Fatalf("helloretry only: got %+v, want %+v", got, want)
	}
}

// parseMultiProvider reads the documented multi-provider.syncengine.intervals
// keys, and reconciles beatinterval with the older remote.beatinterval.
func TestParseMultiProviderSyncengineIntervals(t *testing.T) {
	cases := []struct {
		name      string
		intervals map[string]interface{}
		remote    map[string]interface{}
		wantBeat  uint32
	}{
		{"documented keys", map[string]interface{}{
			"beatinterval": 10, "beat_fast_interval": 1, "helloretry": 5, "discoveryretry": 6, "reconcile": 7,
			"hello_fast_attempts": 3, "hello_fast_interval": 2, "catchup_outage": 600}, nil, 10},
		{"remote.beatinterval alone", nil, map[string]interface{}{"beatinterval": 20}, 20},
		{"documented beatinterval wins", map[string]interface{}{"beatinterval": 10},
			map[string]interface{}{"beatinterval": 20}, 10},
		{"no intervals block", nil, nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block := map[string]interface{}{
				"role":     "agent",
				"identity": "agent.example.",
			}
			if tc.intervals != nil {
				block["syncengine"] = map[string]interface{}{"intervals": tc.intervals}
			}
			if tc.remote != nil {
				block["remote"] = tc.remote
			}
			mp, err := parseMultiProvider(map[string]interface{}{"multi-provider": block})
			if err != nil {
				t.Fatal(err)
			}
			if mp.Remote.BeatInterval != tc.wantBeat {
				t.Errorf("Remote.BeatInterval = %d, want %d", mp.Remote.BeatInterval, tc.wantBeat)
			}
			iv := mp.Syncengine.Intervals
			if tc.name == "documented keys" {
				if iv.BeatInterval != 10 || iv.BeatFastInterval != 1 || iv.HelloRetry != 5 || iv.DiscoveryRetry != 6 || iv.Reconcile != 7 ||
					iv.HelloFastAttempts != 3 || iv.HelloFastInterval != 2 || iv.CatchupOutage != 600 {
					t.Errorf("intervals = %+v", iv)
				}
				if got := catchUpOutageFor(mp); got != 600*time.Second {
					t.Errorf("the catch-up's outage time = %s, want 10m0s", got)
				}
				cfg := hsyncConfigFromMp(mp)
				if cfg.BeatInterval != 10*time.Second || cfg.BeatIntervalMin != 1*time.Second || cfg.HelloRetryInterval != 5*time.Second ||
					cfg.RetryInterval != 6*time.Second || cfg.ReconcileInterval != 7*time.Second ||
					cfg.HelloFastAttempts != 3 || cfg.HelloFastSpacing != 2*time.Second {
					t.Errorf("engine config = %+v", cfg)
				}
			}
		})
	}
}

// remote.LocateInterval has timed nothing since LocateAgent was retired, and
// the generated and sample configs no longer write it. Configs that still carry
// it load, and it changes none of the engine's timers.
func TestParseMultiProviderAcceptsRetiredLocateInterval(t *testing.T) {
	block := map[string]interface{}{
		"role":     "agent",
		"identity": "agent.example.",
		"remote":   map[string]interface{}{"LocateInterval": 60},
	}
	mp, err := parseMultiProvider(map[string]interface{}{"multi-provider": block})
	if err != nil {
		t.Fatalf("parseMultiProvider: %v", err)
	}
	if got, want := hsyncConfigFromMp(mp), hsync.DefaultConfig(); got != want {
		t.Errorf("engine config = %+v, want the defaults %+v", got, want)
	}
}

func TestValidateSyncengineIntervals(t *testing.T) {
	var mp MultiProviderConf
	if err := ValidateSyncengineIntervals(&mp); err != nil {
		t.Fatalf("empty block: %v", err)
	}
	mp.Syncengine.Intervals.HelloFastAttempts = -1
	err := ValidateSyncengineIntervals(&mp)
	if err == nil || !strings.Contains(err.Error(), "hello_fast_attempts") {
		t.Fatalf("negative hello_fast_attempts: err = %v", err)
	}
}

// catchup_outage defaults to an hour, and is refused when it is not above
// the beat interval: every gap between two beats would be an outage.
func TestTheCatchUpOutageIsAboveTheBeatInterval(t *testing.T) {
	var mp MultiProviderConf
	if got := catchUpOutageFor(&mp); got != time.Hour {
		t.Errorf("the default: %s, want 1h0m0s", got)
	}
	for _, tc := range []struct {
		beat, outage int
		ok           bool
	}{
		{0, 30, false}, // the beat interval's default is 30 s
		{0, 31, true},
		{60, 60, false},
		{60, 61, true},
		{60, -1, false},
	} {
		mp := MultiProviderConf{}
		mp.Remote.BeatInterval = uint32(tc.beat)
		mp.Syncengine.Intervals.CatchupOutage = tc.outage
		err := ValidateSyncengineIntervals(&mp)
		if (err == nil) != tc.ok || (err != nil && !strings.Contains(err.Error(), "catchup_outage")) {
			t.Errorf("beat %d, outage %d: err = %v", tc.beat, tc.outage, err)
		}
	}
}

// peer_hold is how long a peer that no zone names is kept: a day unless it is
// set, in seconds when it is, and refused when negative.
func TestThePeerHoldTimeIsReadFromTheConfig(t *testing.T) {
	var mp MultiProviderConf
	if got := hsyncConfigFromMp(&mp).PeerHold; got != 24*time.Hour {
		t.Errorf("the default: %s, want 24h0m0s", got)
	}
	block := map[string]interface{}{
		"role":       "agent",
		"identity":   "agent.example.",
		"syncengine": map[string]interface{}{"intervals": map[string]interface{}{"peer_hold": 300}},
	}
	parsed, err := parseMultiProvider(map[string]interface{}{"multi-provider": block})
	if err != nil {
		t.Fatal(err)
	}
	if got := hsyncConfigFromMp(parsed).PeerHold; got != 5*time.Minute {
		t.Errorf("peer_hold 300: %s, want 5m0s", got)
	}
	mp.Syncengine.Intervals.PeerHold = -1
	if err := ValidateSyncengineIntervals(&mp); err == nil || !strings.Contains(err.Error(), "peer_hold") {
		t.Errorf("negative peer_hold: err = %v", err)
	}
}
