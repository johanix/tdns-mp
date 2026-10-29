package tdnsmp

import (
	"errors"
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// The owner: a zone it has taken is owned, tdns's lifecycle verbs on it are
// refused naming the replacement, its DS intent comes from the columns,
// and a zone it has not taken is tdns's, with no hook of tdns-mp's in the
// way (T3.7's half, as S4a leaves it).
func TestOwnerTakesZonesOneByOne(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	owner := RegisterMPKeyLifecycleOwner(conf)
	t.Cleanup(func() { tdns.RegisterKeyLifecycleOwner(nil) })
	a := signerTestZone(t, "a.owned.example.", kdb)
	b := signerTestZone(t, "b.tdns.example.", kdb)
	owner.Take(a.ZoneName)

	if !owner.Owns(a.ZoneData) || owner.Owns(b.ZoneData) {
		t.Fatalf("Owns: a=%v b=%v, want true false", owner.Owns(a.ZoneData), owner.Owns(b.ZoneData))
	}
	// a tdns lifecycle verb on the owned zone is refused, naming the command
	if _, _, err := kdb.RolloverKey(a.ZoneName, "ZSK", nil); err == nil || !errors.Is(err, tdns.ErrZoneOwned) {
		t.Errorf("RolloverKey on the owned zone: %v, want ErrZoneOwned", err)
	} else if want := owner.Command("rollover"); !containsStr(err.Error(), want) {
		t.Errorf("the refusal does not name %q: %v", want, err)
	}
	// the zone not taken is tdns's: a staged key starts in tdns's own
	// staged state, published, since tdns-mp registers no hook that would
	// name mpdist (S4a); nothing of the peers' protocol runs for it
	k := mpGenKey(t, kdb, b.ZoneName, tdns.DnskeyStateActive, "KSK")
	_ = k
	if _, err := tdns.GenerateAndStageKey(kdb, b.ZoneName, "test", dns.ED25519, "ZSK"); err != nil {
		t.Fatalf("stage a key on the zone tdns runs: %v", err)
	}
	pub, err := tdns.GetDnssecKeysByState(kdb, b.ZoneName, tdns.DnskeyStatePublished)
	if err != nil || len(pub) != 1 {
		t.Errorf("the staged key of the zone tdns runs: %d in published (err=%v), want 1", len(pub), err)
	}
	if mp, err := tdns.GetDnssecKeysByState(kdb, b.ZoneName, DnskeyStateMpdist); err != nil || len(mp) != 0 {
		t.Errorf("the zone tdns runs has %d keys in mpdist (err=%v); no hook stages keys there any more", len(mp), err)
	}
	if _, err := tdns.GenerateAndStageKey(kdb, a.ZoneName, "test", dns.ED25519, "ZSK"); err == nil || !errors.Is(err, tdns.ErrZoneOwned) {
		t.Errorf("staging a key on the owned zone: %v, want ErrZoneOwned", err)
	}

	// DS intent from the columns
	ksk := mpGenKey(t, kdb, a.ZoneName, tdns.DnskeyStateActive, "KSK")
	in, err := tdns.DSIntentForZone(kdb, a.ZoneName, dns.SHA256)
	if err != nil || in.Known {
		t.Errorf("with the KSK's ds unset: known=%v err=%v, want unknown", in.Known, err)
	}
	if err := tdns.UpdateKeyRow(kdb, a.ZoneName, ksk, tdns.DnskeyStateActive, mustCols(KeyStateActive, true)); err != nil {
		t.Fatal(err)
	}
	in, err = tdns.DSIntentForZone(kdb, a.ZoneName, dns.SHA256)
	if err != nil || !in.Known || len(in.Set) != 1 || in.Set[0].(*dns.DS).KeyTag != ksk {
		t.Errorf("with ds=1 on the active KSK: known=%v set=%v err=%v, want the one DS", in.Known, in.Set, err)
	}
}

func mustCols(state string, sep bool) tdns.KeyRowFlags {
	f, _ := KeyStateColumns(state, sep, false)
	return f
}

func containsStr(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
