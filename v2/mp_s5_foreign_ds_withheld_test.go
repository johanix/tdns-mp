/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// tdns-mp #207, the leader's half: the leader took its own signer's
// inventory as the zone's DS set, and deleted another provider's DS at the
// parent the moment one inventory lacked that provider's KSK.

// The leader: its own signer's inventory without another signing provider's
// KSK, while the key states that provider's agent sent ours put the key's DS
// at the parent, is not the zone's DS set. The set is unknown and nothing is
// asked of the parent; once those key states withdraw the DS, the set
// without it is.
func TestLeaderKeepsAnotherProvidersDSThatOneInventoryLacks(t *testing.T) {
	yes, no := true, false
	r := newComputedDSRig(t, "withheld.ds.example.", []string{"us", "p2"})
	r.owner.SetForeignDSCheck(r.conf.foreignDSWithheld)
	z := r.mpzd.ZoneName
	ourKSK, ourZSK, theirKSK, theirZSK := testDnskey(t, z, 257), testDnskey(t, z, 256), testDnskey(t, z, 257), testDnskey(t, z, 256)
	r.leader("agent.us.example.")
	r.distribution(t, "agent.p2.example.", word{theirKSK, KeyStateActive, &yes}, word{theirZSK, KeyStateActive, &no})
	r.requests(t)

	row := func(k *dns.DNSKEY, state string, ds bool) KeyInventoryItem {
		return KeyInventoryItem{KeyTag: k.KeyTag(), Algorithm: k.Algorithm, Flags: k.Flags, State: state, KeyRR: k.String(), Pub: true, DS: &ds}
	}
	inventory := func(items ...KeyInventoryItem) {
		r.conf.noteKeyInventory(r.ctx, r.mpzd, &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: z, Inventory: items, Owned: true})
	}
	check := func(step string, wantKnown bool, want ...*dns.DNSKEY) {
		t.Helper()
		known, tags := r.dsSet(t)
		if known != wantKnown {
			t.Fatalf("%s: the DS set is known=%v, want %v", step, known, wantKnown)
		}
		if !wantKnown {
			return
		}
		if len(tags) != len(want) {
			t.Fatalf("%s: the DS set %v, want %d DS", step, tags, len(want))
		}
		for _, k := range want {
			if !tags[k.KeyTag()] {
				t.Fatalf("%s: the DS set %v lacks key %d", step, tags, k.KeyTag())
			}
		}
	}
	whole := []KeyInventoryItem{
		row(ourKSK, tdns.DnskeyStateActive, true), row(ourZSK, tdns.DnskeyStateActive, false),
		row(theirKSK, DnskeyStateForeign, true), row(theirZSK, DnskeyStateForeign, false),
	}

	inventory(whole...)
	check("both providers' keys in the inventory", true, ourKSK, theirKSK)
	r.requests(t)

	// the inventory of a signer that took a copy without p2's keys
	inventory(row(ourKSK, tdns.DnskeyStateActive, true), row(ourZSK, tdns.DnskeyStateActive, false))
	check("an inventory without p2's keys, p2 still holding them", false)
	if n := r.requests(t); n != 0 {
		t.Fatalf("an inventory without p2's KSK asked the parent for %d syncs, want none", n)
	}

	inventory(whole...)
	check("p2's keys back in the inventory", true, ourKSK, theirKSK)
	r.requests(t)

	// p2's agent sends key states that withdraw its KSK's DS, and the
	// signer's row follows them once our agent has relayed them
	r.distribution(t, "agent.p2.example.", word{theirKSK, KeyStateRetired, &no}, word{theirZSK, KeyStateActive, &no})
	inventory(whole[0], whole[1], row(theirKSK, DnskeyStateForeign, false), whole[3])
	check("p2 has withdrawn its KSK's DS", true, ourKSK)
	if n := r.requests(t); n == 0 {
		t.Fatal("the DS removal p2 asked for asked the parent nothing")
	}
}
