package tdnsmp

import (
	"errors"
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// The owner: a zone it has taken is owned, tdns's lifecycle verbs on it are
// refused naming the replacement, its DS intent comes from the columns,
// and a zone it has not taken keeps tdns's hooks (T3.7's half).
func TestOwnerTakesZonesOneByOne(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	conf := withSignerHooks(t, kdb)
	owner := RegisterMPKeyLifecycleOwner(conf)
	t.Cleanup(func() { tdns.RegisterKeyLifecycleOwner(nil) })
	a := signerTestZone(t, "a.owned.example.", kdb)
	b := signerTestZone(t, "b.hooked.example.", kdb)
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
	// the zone not taken keeps the hooks: a staged key starts in mpdist
	k := mpGenKey(t, kdb, b.ZoneName, tdns.DnskeyStateActive, "KSK")
	_ = k
	if _, err := tdns.GenerateAndStageKey(kdb, b.ZoneName, "test", dns.ED25519, "ZSK"); err != nil {
		t.Fatalf("stage a key on the hooked zone: %v", err)
	}
	mp, err := tdns.GetDnssecKeysByState(kdb, b.ZoneName, DnskeyStateMpdist)
	if err != nil || len(mp) != 1 {
		t.Errorf("the hooked zone's staged key: %d in mpdist (err=%v), want 1", len(mp), err)
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
	owner.Release(a.ZoneName)
	if owner.Owns(a.ZoneData) {
		t.Error("released zone still owned")
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
