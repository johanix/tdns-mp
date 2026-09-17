package tdnsmp

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// S5's second half (tdns-mp #58, design D4 and P3): the other providers
// say, per key, its state there and whether its DS belongs at the parent;
// the owner writes ds on their rows from that.

func foreignRow(t *testing.T, r *driverRig, flags uint16) uint16 {
	t.Helper()
	k := testDnskey(t, r.l.Zone, flags)
	if err := insertForeignKeyRow(r.kdb, r.l.Zone, k.KeyTag(), k, "ED25519"); err != nil {
		t.Fatal(err)
	}
	return k.KeyTag()
}

func said(provider string, keytag uint16, state string, ds *bool) core.ForeignKeyState {
	return core.ForeignKeyState{Provider: provider, KeyState: core.KeyState{KeyTag: keytag, State: state, DS: ds}}
}

func dsSetTags(t *testing.T, r *driverRig) (known bool, tags map[uint16]bool) {
	t.Helper()
	in, err := tdns.DSIntentForZone(r.kdb, r.l.Zone, dns.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	tags = map[uint16]bool{}
	for _, rr := range in.Set {
		tags[rr.(*dns.DS).KeyTag] = true
	}
	return in.Known, tags
}

// P3: a foreign KSK has ds=1 only if its provider signs the zone and holds
// the key standby, active or retired with its DS not withdrawn; a ZSK
// never; a provider that does not sign never.
func TestForeignRowsGetTheirDSFromWhatTheirProviderSays(t *testing.T) {
	yes, no := true, false
	r := newDriverRig(t, "foreign.owned.example.", driverPolicy, "p2")
	ksk, zsk, standby, withdrawn, early, outsider := foreignRow(t, r, 257), foreignRow(t, r, 256), foreignRow(t, r, 257), foreignRow(t, r, 257), foreignRow(t, r, 257), foreignRow(t, r, 257)
	if known, _ := dsSetTags(t, r); known {
		t.Fatal("the DS set is known before anybody said anything about the foreign keys")
	}
	before := r.wire.changes
	err := r.l.SetForeignStates([]core.ForeignKeyState{
		said("p2", ksk, KeyStateActive, &yes),
		said("p2", zsk, KeyStateActive, &no),
		said("p2", standby, KeyStateStandby, &yes),
		said("p2", withdrawn, KeyStateRetired, &no),
		said("p2", early, KeyStatePublished, &yes), // not a state a DS belongs to, whatever it says
		said("p3", outsider, KeyStateActive, &yes), // p3 does not sign the zone
	})
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[uint16]string{ksk: "101", zsk: "100", standby: "101", withdrawn: "100", early: "100", outsider: "100"} {
		if got := r.cols(k); got != want {
			t.Errorf("foreign key %d: columns %s, want %s", k, got, want)
		}
		if st := r.state(k); st != DnskeyStateForeign {
			t.Errorf("foreign key %d changed state to %s", k, st)
		}
	}
	if r.wire.changes != before+1 {
		t.Errorf("the writes reported %d changes to the surroundings, want one", r.wire.changes-before)
	}
	known, tags := dsSetTags(t, r)
	if !known || len(tags) != 2 || !tags[ksk] || !tags[standby] {
		t.Errorf("the DS set: known=%v %v, want p2's active and standby KSKs", known, tags)
	}
	// the same word again changes nothing
	before = r.wire.changes
	if err := r.l.SetForeignStates(r.l.ForeignStates()); err != nil {
		t.Fatal(err)
	}
	if r.wire.changes != before {
		t.Error("the same word again was reported as a change")
	}
}

// Q9 and T5.2: a provider that does not say (an older release) leaves its
// rows undecided, and the zone's DS set unknown: nothing goes to the parent
// on a guess.
func TestAProviderThatDoesNotSayLeavesTheDSSetUnknown(t *testing.T) {
	yes := true
	r := newDriverRig(t, "silent.owned.example.", driverPolicy, "p2", "p3")
	saidKSK, silentKSK := foreignRow(t, r, 257), foreignRow(t, r, 257)
	if err := r.l.SetForeignStates([]core.ForeignKeyState{said("p2", saidKSK, KeyStateActive, &yes), said("p3", silentKSK, KeyStateActive, nil)}); err != nil {
		t.Fatal(err)
	}
	if got := r.cols(silentKSK); got != "10NULL" {
		t.Errorf("the key its provider says nothing about: columns %s, want ds unset", got)
	}
	if known, _ := dsSetTags(t, r); known {
		t.Error("the DS set is known though one provider's KSK is undecided")
	}
	// and a key nobody mentioned at all stays undecided too
	if got := r.cols(foreignRow(t, r, 257)); got != "10NULL" {
		t.Errorf("a key nobody mentioned: columns %s, want ds unset", got)
	}
}

// The word may come before the row: the zone with the provider's DNSKEY is
// transferred a moment later. The next tick writes the ds; so does a
// restart, from the table.
func TestForeignWordBeforeTheRowAndAcrossARestart(t *testing.T) {
	yes := true
	r := newDriverRig(t, "early.owned.example.", driverPolicy, "p2")
	k := testDnskey(t, r.l.Zone, 257)
	if err := r.l.SetForeignStates([]core.ForeignKeyState{said("p2", k.KeyTag(), KeyStateActive, &yes)}); err != nil {
		t.Fatal(err)
	}
	if err := insertForeignKeyRow(r.kdb, r.l.Zone, k.KeyTag(), k, "ED25519"); err != nil {
		t.Fatal(err)
	}
	if got := r.cols(k.KeyTag()); got != "10NULL" {
		t.Fatalf("the new row: columns %s, want ds unset until the machine looks", got)
	}
	if err := r.l.Tick(); err != nil {
		t.Fatal(err)
	}
	if got := r.cols(k.KeyTag()); got != "101" {
		t.Errorf("after the tick: columns %s, want 101", got)
	}
	// a restart: what was said is in the table
	again := NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, driverPolicy, r.wire)
	if err := again.Reload(); err != nil {
		t.Fatal(err)
	}
	fs := again.ForeignStates()
	if len(fs) != 1 || fs[0].Provider != "p2" || fs[0].KeyTag != k.KeyTag() || fs[0].State != KeyStateActive || fs[0].DS == nil || !*fs[0].DS {
		t.Errorf("after a restart the providers' word is %+v", fs)
	}
}

// E10: a provider that stops signing the zone takes its keys' DS with it.
func TestAProviderThatStopsSigningLosesItsDS(t *testing.T) {
	yes := true
	r := newDriverRig(t, "leaver.owned.example.", driverPolicy, "p2", "p3")
	k2, k3 := foreignRow(t, r, 257), foreignRow(t, r, 257)
	if err := r.l.SetForeignStates([]core.ForeignKeyState{said("p2", k2, KeyStateActive, &yes), said("p3", k3, KeyStateActive, &yes)}); err != nil {
		t.Fatal(err)
	}
	if r.cols(k2) != "101" || r.cols(k3) != "101" {
		t.Fatalf("both signers' KSKs: %s %s, want 101 101", r.cols(k2), r.cols(k3))
	}
	r.wire.mu.Lock()
	r.wire.signers = []string{"p2"}
	r.wire.mu.Unlock()
	if err := r.l.SignersChanged(); err != nil {
		t.Fatal(err)
	}
	if r.cols(k2) != "101" || r.cols(k3) != "100" {
		t.Errorf("after p3 stopped signing: %s %s, want 101 100", r.cols(k2), r.cols(k3))
	}
	if known, tags := dsSetTags(t, r); !known || len(tags) != 1 || !tags[k2] {
		t.Errorf("the DS set after p3 left: known=%v %v, want p2's KSK alone", known, tags)
	}
}
