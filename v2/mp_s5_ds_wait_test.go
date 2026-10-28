/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Every case in which the computed DS set is unknown names whom it waits
// for, and why: a set that is unknown names someone, or says that there is
// nobody to name (every signing provider spoke, and none holds a key with
// the SEP flag). The cases are walked through computedDSSet, which
// computedDSIntent is, so that a case added there later is not left without
// a name.
func TestEveryUnknownDSSetNamesWhatItWaitsFor(t *testing.T) {
	yes := true
	for _, tc := range []struct {
		name    string
		signers []string
		setup   func(t *testing.T, r *computedDSRig)
		want    []string // the waits, as dsWait prints them; none for a known set
		nobody  bool     // unknown, with nobody to name
	}{
		{"a signing provider that has not spoken", []string{"p2"}, func(*testing.T, *computedDSRig) {},
			[]string{"agent.p2.example. (not spoken)"}, false},
		{"a SEP key whose ds is undecided", []string{"p2"}, func(t *testing.T, r *computedDSRig) {
			r.distribution(t, "agent.p2.example.", word{testDnskey(t, r.mpzd.ZoneName, 257), KeyStateActive, nil})
		}, []string{"agent.p2.example. (ds undecided, key "}, false},
		{"a key with ds=1 and no record", []string{"p2"}, func(t *testing.T, r *computedDSRig) {
			k := testDnskey(t, r.mpzd.ZoneName, 257)
			// key states for a key whose record never came
			r.conf.InternalMp.MPTransport.noteForeignKeyStates(ZoneName(r.mpzd.ZoneName), "agent.p2.example.",
				[]core.RROperation{{Operation: "replace", RRtype: "DNSKEY", KeyStates: []core.KeyState{{KeyTag: k.KeyTag(), State: KeyStateActive, DS: &yes}}}}, false)
		}, []string{"agent.p2.example. (no record, key "}, false},
		{"our own signer, with no inventory", []string{"us"}, func(*testing.T, *computedDSRig) {},
			[]string{"agent.us.example. (no inventory)"}, false},
		{"our own signer's SEP key, ds undecided", []string{"us"}, func(t *testing.T, r *computedDSRig) {
			r.owner.SetInventory(r.mpzd.ZoneName, &KeyInventorySnapshot{Zone: r.mpzd.ZoneName,
				Inventory: []KeyInventoryItem{invItem(t, r.mpzd.ZoneName, 257, KeyStateActive, nil)}})
		}, []string{"agent.us.example. (ds undecided, key "}, false},
		// signers= is a set (design rule 2): the waits come in label order
		{"two providers, both named", []string{"us", "p2"}, func(*testing.T, *computedDSRig) {},
			[]string{"agent.p2.example. (not spoken)", "agent.us.example. (no inventory)"}, false},
		{"every signer spoke, none holds a SEP key", []string{"p2"}, func(t *testing.T, r *computedDSRig) {
			r.answer(t, "agent.p2.example.", true, true) // complete, and no key
		}, nil, true},
		{"known", []string{"p2"}, func(t *testing.T, r *computedDSRig) {
			r.distribution(t, "agent.p2.example.", word{testDnskey(t, r.mpzd.ZoneName, 257), KeyStateActive, &yes})
		}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newComputedDSRig(t, "waits."+strings.ReplaceAll(tc.name, " ", "-")+".example.", tc.signers)
			tc.setup(t, r)
			in, waits, err := r.conf.computedDSSet(r.mpzd.ZoneName, dns.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			if in.Known == (len(tc.want) > 0 || tc.nobody) {
				t.Fatalf("known=%v, waits %v", in.Known, waits)
			}
			if len(waits) != len(tc.want) {
				t.Fatalf("waits %v, want %v", waits, tc.want)
			}
			for i, w := range waits {
				if !strings.HasPrefix(w.String(), tc.want[i]) {
					t.Errorf("wait %d is %q, want %q", i, w, tc.want[i])
				}
			}
			// what the syncher's line and the status say
			line := r.conf.dsSetWaitingFor(r.mpzd.ZoneName)
			switch {
			case tc.nobody && !strings.HasPrefix(line, "nobody:"):
				t.Errorf("the line %q does not say there is nobody to name", line)
			case len(tc.want) > 0 && !strings.Contains(line, tc.want[0]):
				t.Errorf("the line %q does not name %q", line, tc.want[0])
			}
		})
	}
}

// For a zone our own signer owns, the line names the provider whose key
// states hold the set back, by its identity, or our own SEP keys whose ds
// is not set.
func TestAnOwnedZonesUnknownDSSetNamesWhatItWaitsFor(t *testing.T) {
	yes := true
	r := newComputedDSRig(t, "owned.waits.example.", []string{"us", "p2"})
	r.owner.SetForeignDSCheck(r.conf.foreignDSWithheld)
	z := r.mpzd.ZoneName
	r.distribution(t, "agent.p2.example.", word{testDnskey(t, z, 257), KeyStateActive, &yes})
	// our signer's inventory has our KSK alone, and p2's key states put
	// p2's DS at the parent
	r.owner.SetInventory(z, &KeyInventorySnapshot{Zone: z, Owned: true, Inventory: []KeyInventoryItem{invItem(t, z, 257, KeyStateActive, &yes)}})
	if line := r.conf.dsSetWaitingFor(z); !strings.Contains(line, "provider agent.p2.example. holds its key") {
		t.Errorf("withheld by p2's key states: %q", line)
	}
	// the status reads it without DSIntent, whose warning would come with
	// every status
	var buf lockedBuffer
	saved := lgEngine
	lgEngine = slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { lgEngine = saved })
	if line := r.conf.dsSetLine(r.mpzd.ZoneData); !strings.Contains(line, "unknown, waiting for provider agent.p2.example. holds its key") {
		t.Errorf("the status: %q", line)
	}
	if strings.Contains(buf.String(), "held back") {
		t.Errorf("the status logged DSIntent's warning:\n%s", buf.String())
	}
	r.owner.SetInventory(z, &KeyInventorySnapshot{Zone: z, Owned: true, Inventory: []KeyInventoryItem{invItem(t, z, 257, KeyStateActive, nil)}})
	r.distribution(t, "agent.p2.example.")
	if line := r.conf.dsSetWaitingFor(z); !strings.HasPrefix(line, "agent.us.example. (ds undecided, key ") {
		t.Errorf("our own SEP key, ds undecided: %q", line)
	}
}

// For a zone our own signer owns, key states from another provider that
// end the hold on its DS (foreignDSWithheld) make the set known with
// nothing else changing: the sync is asked for.
func TestKeyStatesThatEndTheHoldOnAnOwnedZoneAskForTheSync(t *testing.T) {
	yes, no := true, false
	r := newComputedDSRig(t, "hold.ends.example.", []string{"us", "p2"})
	r.owner.SetForeignDSCheck(r.conf.foreignDSWithheld)
	z := r.mpzd.ZoneName
	theirs := testDnskey(t, z, 257)
	r.leader("agent.us.example.")
	r.distribution(t, "agent.p2.example.", word{theirs, KeyStateActive, &yes})
	// our signer's inventory lacks p2's KSK: the set is held back
	r.conf.noteKeyInventory(r.ctx, r.mpzd, &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: z, Owned: true,
		Inventory: []KeyInventoryItem{invItem(t, z, 257, KeyStateActive, &yes)}})
	if known, _ := r.dsSet(t); known {
		t.Fatal("the set is known while p2's key states hold it back")
	}
	r.requests(t)
	// p2 withdraws its KSK's DS: the inventory is the set again
	r.distribution(t, "agent.p2.example.", word{theirs, KeyStateRetired, &no})
	if known, _ := r.dsSet(t); !known {
		t.Fatal("the set is still unknown")
	}
	if n := r.requests(t); n != 1 {
		t.Errorf("%d syncs asked for when the hold ended, want 1", n)
	}
}

// The status's DS set line: "known", or "unknown, waiting for" whom, for a
// zone that names a signer; nothing for one that names none.
func TestTheStatusNamesTheDSSet(t *testing.T) {
	yes := true
	r := newComputedDSRig(t, "status.ds.example.", []string{"p2"})
	if got := r.conf.dsSetLine(r.mpzd.ZoneData); got != "unknown, waiting for agent.p2.example. (not spoken)" {
		t.Errorf("before p2 spoke: %q", got)
	}
	r.distribution(t, "agent.p2.example.", word{testDnskey(t, r.mpzd.ZoneName, 257), KeyStateActive, &yes})
	if got := r.conf.dsSetLine(r.mpzd.ZoneData); got != "known" {
		t.Errorf("after p2 spoke: %q", got)
	}
	u := newComputedDSRig(t, "status.nosigner.example.", nil)
	if got := u.conf.dsSetLine(u.mpzd.ZoneData); got != "" {
		t.Errorf("a zone that names no signer: %q", got)
	}
}

// Every combination of what two signing providers have said, ours and
// another: a set that is unknown names someone, unless every signer has
// spoken and none holds a SEP key; a known set names nobody. A case of
// computedDSSet that made the set unknown without a name would fail here.
func TestEveryCombinationOfTheDSSetsCasesNamesWhatItWaitsFor(t *testing.T) {
	yes, no := true, false
	type share struct {
		name  string
		sep   bool // holds a SEP key
		apply func(t *testing.T, r *computedDSRig)
	}
	ours := []share{
		{"no inventory", false, func(*testing.T, *computedDSRig) {}},
		{"no SEP key", false, func(t *testing.T, r *computedDSRig) {
			r.owner.SetInventory(r.mpzd.ZoneName, &KeyInventorySnapshot{Zone: r.mpzd.ZoneName, Inventory: []KeyInventoryItem{invItem(t, r.mpzd.ZoneName, 256, KeyStateActive, &no)}})
		}},
		{"SEP ds undecided", true, func(t *testing.T, r *computedDSRig) {
			r.owner.SetInventory(r.mpzd.ZoneName, &KeyInventorySnapshot{Zone: r.mpzd.ZoneName, Inventory: []KeyInventoryItem{invItem(t, r.mpzd.ZoneName, 257, KeyStateActive, nil)}})
		}},
		{"SEP ds=1", true, func(t *testing.T, r *computedDSRig) {
			r.owner.SetInventory(r.mpzd.ZoneName, &KeyInventorySnapshot{Zone: r.mpzd.ZoneName, Inventory: []KeyInventoryItem{invItem(t, r.mpzd.ZoneName, 257, KeyStateActive, &yes)}})
		}},
		{"SEP ds=0", true, func(t *testing.T, r *computedDSRig) {
			r.owner.SetInventory(r.mpzd.ZoneName, &KeyInventorySnapshot{Zone: r.mpzd.ZoneName, Inventory: []KeyInventoryItem{invItem(t, r.mpzd.ZoneName, 257, KeyStateRetired, &no)}})
		}},
	}
	theirs := []share{
		{"not spoken", false, func(*testing.T, *computedDSRig) {}},
		{"spoken, no key", false, func(t *testing.T, r *computedDSRig) { r.answer(t, "agent.p2.example.", true, true) }},
		{"ZSK only", false, func(t *testing.T, r *computedDSRig) {
			r.distribution(t, "agent.p2.example.", word{testDnskey(t, r.mpzd.ZoneName, 256), KeyStateActive, &no})
		}},
		{"SEP ds undecided", true, func(t *testing.T, r *computedDSRig) {
			r.distribution(t, "agent.p2.example.", word{testDnskey(t, r.mpzd.ZoneName, 257), KeyStateActive, nil})
		}},
		{"SEP ds=1", true, func(t *testing.T, r *computedDSRig) {
			r.distribution(t, "agent.p2.example.", word{testDnskey(t, r.mpzd.ZoneName, 257), KeyStateActive, &yes})
		}},
		{"SEP ds=0", true, func(t *testing.T, r *computedDSRig) {
			r.distribution(t, "agent.p2.example.", word{testDnskey(t, r.mpzd.ZoneName, 257), KeyStateRetired, &no})
		}},
		{"ds=1, no record", false, func(t *testing.T, r *computedDSRig) {
			k := testDnskey(t, r.mpzd.ZoneName, 257)
			r.conf.InternalMp.MPTransport.noteForeignKeyStates(ZoneName(r.mpzd.ZoneName), "agent.p2.example.",
				[]core.RROperation{{Operation: "replace", RRtype: "DNSKEY", KeyStates: []core.KeyState{{KeyTag: k.KeyTag(), State: KeyStateActive, DS: &yes}}}}, false)
		}},
	}
	n := 0
	for _, o := range ours {
		for _, p := range theirs {
			n++
			name := o.name + " / " + p.name
			r := newComputedDSRig(t, fmt.Sprintf("combo%d.waits.example.", n), []string{"us", "p2"})
			o.apply(t, r)
			p.apply(t, r)
			in, waits, err := r.conf.computedDSSet(r.mpzd.ZoneName, dns.SHA256)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			spoke := o.name != "no inventory" && p.name != "not spoken"
			nobody := spoke && !o.sep && !p.sep && p.name != "ds=1, no record"
			switch {
			case in.Known && len(waits) > 0:
				t.Errorf("%s: known, and waits for %v", name, waits)
			case !in.Known && len(waits) == 0 && !nobody:
				t.Errorf("%s: unknown, and names nobody", name)
			case !in.Known && len(waits) > 0 && nobody:
				t.Errorf("%s: names %v where there is nobody to name", name, waits)
			}
		}
	}
}

// An error reading the set is named as that error: a key of our signer's
// inventory that does not parse. An owned zone whose inventory holds no
// SEP key says that there is nobody to name.
func TestTheDSSetsErrorAndAnOwnedZoneWithNoSEPKeyAreNamed(t *testing.T) {
	yes, no := true, false
	r := newComputedDSRig(t, "error.waits.example.", []string{"us"})
	bad := invItem(t, r.mpzd.ZoneName, 257, KeyStateActive, &yes)
	bad.KeyRR = "not a record"
	r.owner.SetInventory(r.mpzd.ZoneName, &KeyInventorySnapshot{Zone: r.mpzd.ZoneName, Inventory: []KeyInventoryItem{bad}})
	if _, err := r.conf.computedDSWaitingFor(r.mpzd.ZoneName); err == nil {
		t.Error("a key that does not parse gave no error")
	}
	if got := r.conf.dsSetLine(r.mpzd.ZoneData); !strings.HasPrefix(got, "unknown, waiting for nobody: the DS set could not be read: ") {
		t.Errorf("the status: %q", got)
	}
	o := newComputedDSRig(t, "nosep.owned.example.", []string{"us"})
	o.owner.SetInventory(o.mpzd.ZoneName, &KeyInventorySnapshot{Zone: o.mpzd.ZoneName, Owned: true,
		Inventory: []KeyInventoryItem{invItem(t, o.mpzd.ZoneName, 256, KeyStateActive, &no)}})
	if got := o.conf.dsSetLine(o.mpzd.ZoneData); got != "unknown, waiting for nobody: the signer's inventory holds no key with the SEP flag" {
		t.Errorf("an owned zone with no SEP key: %q", got)
	}
}
