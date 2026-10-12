package tdnsmp

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"gopkg.in/yaml.v3"
)

// tdns-mp #134: a role's lifetime in the DNSSEC policy is a schedule only
// when it is one. tdns's parser stores `lifetime: forever` as 10000 hours;
// the machine took that as a lifetime and rolled the keys of a `forever`
// policy at that age. The driver on one provider with the fake wire and the
// fake clock, its policy read from a policy tdns's parser made.

// parsedPolicy is one DNSSEC policy as tdns's parser makes it from its
// config text.
func parsedPolicy(t *testing.T, text string) *tdns.DnssecPolicy {
	t.Helper()
	var dp tdns.DnssecPolicyConf
	if err := yaml.Unmarshal([]byte(text), &dp); err != nil {
		t.Fatalf("the policy's yaml: %v", err)
	}
	pol, err := tdns.ParseDnssecPolicyConfQuiet("default", &dp)
	if err != nil {
		t.Fatalf("the policy: %v", err)
	}
	return pol
}

// policyText is a policy as the generated signer config has it, with the
// given lifetime for both roles.
func policyText(lifetime string) string {
	return fmt.Sprintf("algorithm: ED25519\nksk:\n   lifetime: %s\nzsk:\n   lifetime: %s\ncsk:\n   lifetime: none\n"+
		"sigvalidity:\n   default: 6h\n   dnskey: 6h\n   ds: 6h\n", lifetime, lifetime)
}

// keyRows is the zone's key rows as one line: what a roll changes.
func (r *driverRig) keyRows() string {
	r.t.Helper()
	inv, err := tdns.GetKeyInventory(r.kdb, r.l.Zone)
	if err != nil {
		r.t.Fatal(err)
	}
	var rows []string
	for _, it := range inv {
		rows = append(rows, fmt.Sprintf("%d/%s/%s", it.KeyTag, roleOf(it.Flags), it.State))
	}
	return strings.Join(rows, " ")
}

func TestALifetimeOfForeverNeverRollsAKey(t *testing.T) {
	const day = 24 * time.Hour
	cases := []struct {
		name     string
		lifetime string        // as the config has it
		raw      uint32        // when not 0: put on the parsed policy, a value the config has no word for
		due      time.Duration // the age at which the machine rolls; 0: never
	}{
		{name: "forever", lifetime: "forever"},
		{name: "none", lifetime: "none"},
		{name: "unset", lifetime: ""},
		{name: "allones", raw: 0xFFFFFFFF},
		{name: "30d", lifetime: "30d", due: 30 * day},
	}
	// the ages the active keys are looked at: around a real lifetime, around
	// the 10000 hours tdns stores for forever, past the 136 years of 0xFFFFFFFF
	ages := []time.Duration{29 * day, 30*day + time.Minute, 9999 * time.Hour, 10000 * time.Hour, 10001 * time.Hour, 30000 * time.Hour, 140 * 365 * day}
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Dnssec.Kasp.PropagationDelay = "5m"
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kdb := newMPTestKeyDB(t)
			zd := signerTestZone(t, c.name+".lifetime.owned.example.", kdb)
			zd.ZoneData.DnssecPolicy = parsedPolicy(t, policyText(c.lifetime))
			if c.raw != 0 {
				zd.ZoneData.DnssecPolicy.KSK.Lifetime, zd.ZoneData.DnssecPolicy.ZSK.Lifetime = c.raw, c.raw
			}
			// the driver as the engine makes it, but for the clock and the wire
			pol := policyFor(conf, zd.ZoneData)
			if pol.KSKLifetime != c.due || pol.ZSKLifetime != c.due {
				t.Errorf("the machine's lifetimes are %s (KSK) and %s (ZSK), want %s (0: forever)", pol.KSKLifetime, pol.ZSKLifetime, c.due)
			}
			if pol.StandbyZSK != 1 || pol.StandbyKSK != 0 {
				t.Fatalf("standby counts ZSK %d KSK %d, want the defaults 1 and 0", pol.StandbyZSK, pol.StandbyKSK)
			}
			clock := &fakeClock{t: time.Now()}
			wire := newFakeWire("p2")
			r := &driverRig{t: t, kdb: kdb, zd: zd, clock: clock, wire: wire, l: NewZoneKeyLifecycle(zd.ZoneName, kdb, clock, pol, wire)}
			// the bootstrap: an active key of each role, then the standby ZSK
			// the policy wants
			for i := 0; i < 3; i++ {
				r.tick("bootstrap")
				for _, k := range append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...) {
					if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
						t.Fatal(err)
					}
				}
				r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
			}
			ksk, zsk, standby := r.keysIn(KeyStateActive, "KSK"), r.keysIn(KeyStateActive, "ZSK"), r.keysIn(KeyStateStandby, "ZSK")
			if len(ksk) != 1 || len(zsk) != 1 || len(standby) != 1 {
				t.Fatalf("after the bootstrap: active KSKs %v, active ZSKs %v, standby ZSKs %v, want one of each", ksk, zsk, standby)
			}
			all, err := r.l.rows()
			if err != nil {
				t.Fatal(err)
			}
			if all[ksk[0]].ActiveAt == nil || all[zsk[0]].ActiveAt == nil {
				t.Fatal("an active key has no active_at stamp: every lifetime would be due at once")
			}
			// the later of the two stamps: no key is older than the age named
			since := *all[ksk[0]].ActiveAt
			if all[zsk[0]].ActiveAt.After(since) {
				since = *all[zsk[0]].ActiveAt
			}
			steady, sent := r.keyRows(), len(r.wire.distributions())
			for _, age := range ages {
				r.clock.Advance(since.Add(age).Sub(r.clock.Now()))
				r.tick(fmt.Sprintf("the active keys %s old", age))
				rolled := r.keyRows() != steady || len(r.wire.distributions()) != sent
				if c.due == 0 || age < c.due {
					if rolled {
						t.Fatalf("with the active keys %s old the machine started a roll: the key rows went from\n  %s\nto\n  %s\n(%d keys distributed, %d before)",
							age, steady, r.keyRows(), len(r.wire.distributions()), sent)
					}
					continue
				}
				// due: the standby ZSK is promoted (T9) and the KSK the roll
				// will promote is minted and sent (T1)
				if st := r.state(standby[0]); st != KeyStateActive {
					t.Errorf("with the active keys %s old and a lifetime of %s the standby ZSK is %s, want active", age, c.due, st)
				}
				if st := r.state(zsk[0]); st != KeyStateRetired {
					t.Errorf("with the active keys %s old and a lifetime of %s the old ZSK is %s, want retired", age, c.due, st)
				}
				if pend := r.keysIn(KeyStateMpdist, "KSK"); len(pend) != 1 {
					t.Errorf("with the active keys %s old and a lifetime of %s the KSKs in mpdist are %v, want the one minted for the roll", age, c.due, pend)
				}
				break
			}
		})
	}
}

// tdnsForeverFallback is a copy of a number tdns keeps to itself. It is held
// here to what tdns's parser stores for the word, so a tdns that changes its
// value fails this test when it is pinned, and the copy cannot go stale
// unseen. The test guards that invariant: no change of tdns-mp's own code
// makes it fail, only the two numbers parting.
func TestTheForeverFallbackIsWhatTdnsStores(t *testing.T) {
	lt, err := tdns.GenKeyLifetime("forever")
	if err != nil {
		t.Fatalf("tdns's parser refuses `forever`: %v", err)
	}
	if lt.Lifetime != tdnsForeverFallback {
		t.Errorf("tdns stores %d s for `forever` and tdnsForeverFallback is %d s: set it to tdns's foreverLifetimeSecs", lt.Lifetime, tdnsForeverFallback)
	}
	if tdnsForeverLifetime != lt.Lifetime {
		t.Errorf("the value in use for `forever` is %d s, tdns's parser stores %d s", tdnsForeverLifetime, lt.Lifetime)
	}
}

// A parser that refuses the word, or stores nothing for it, must not leave
// tdns's 10000 hours a schedule: the fallback is the value then. A value the
// parser does give is the one taken.
func TestForeverIsTheFallbackWhenTheParserGivesNone(t *testing.T) {
	if got := tdnsForever(tdns.KeyLifetime{}, errors.New("invalid key lifetime")); got != tdnsForeverFallback {
		t.Errorf("the parser refused the word: forever is %d s, want the fallback %d s", got, tdnsForeverFallback)
	}
	if got := tdnsForever(tdns.KeyLifetime{}, nil); got != tdnsForeverFallback {
		t.Errorf("the parser stored 0 for the word: forever is %d s, want the fallback %d s", got, tdnsForeverFallback)
	}
	if got := tdnsForever(tdns.KeyLifetime{Lifetime: 86400}, nil); got != 86400 {
		t.Errorf("the parser stored 86400 s for the word: forever is %d s, want the parser's value", got)
	}
}
