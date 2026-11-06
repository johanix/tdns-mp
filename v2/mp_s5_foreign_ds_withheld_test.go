/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"fmt"
	"testing"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
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

// withheldWhy is foreignDSWithheld's word on a provider's key that the
// signer's inventory lacks.
func withheldWhy(provider string, k *dns.DNSKEY, state string) string {
	return fmt.Sprintf("provider %s holds its key %d %s with its DS at the parent, and the signer's inventory does not have that DS", provider, k.KeyTag(), state)
}

// A joiner's first KSK under the tag of the KSK another provider holds with
// its DS at the parent. The signer keeps no copy of a key under a tag of its
// own (syncForeignDNSKEYs), so its inventory holds our row under the tag and
// none of theirs. Our row stood in for theirs; outside the step's DSSigners
// it then left the set, and another SEP key of theirs with ds=0 made the set
// known and empty: every DS would leave the parent. The set is unknown,
// nothing is asked of the parent, and the status names their key.
func TestAJoinersKeyUnderAProvidersTagDoesNotHoldItsDS(t *testing.T) {
	yes, no := true, false
	r := newComputedDSRig(t, "sametag.joiner.example.", []string{"us", "p2"})
	r.owner.SetForeignDSCheck(r.conf.foreignDSWithheld)
	z := r.mpzd.ZoneName
	r.mpzd.Options[tdns.OptMultiProvider] = true
	r.leader("agent.us.example.")
	theirKSK, theirNext, theirZSK := testDnskey(t, z, 257), testDnskey(t, z, 257), testDnskey(t, z, 256)
	ourKSK, ourZSK := sameTagOtherKey(t, theirKSK), testDnskey(t, z, 256)
	r.distribution(t, "agent.p2.example.", word{theirKSK, KeyStateActive, &yes}, word{theirNext, KeyStatePublished, &no}, word{theirZSK, KeyStateActive, &no})
	s := withActiveStore(t, r.mpzd)
	rest := r.mpzd.roles()
	rest.ParentSync = core.HsyncParentSyncAgent
	keys := withSigners(rest, "us", "p2")
	keys.DSSigners = providersOf("p2")
	stepAs(t, s, z, 1, keys)
	r.mpzd.populateMPdata(r.conf.MpConfig(), r.mpzd.roles())
	r.conf.onSetsChanged(r.mpzd, true)
	r.requests(t)

	row := func(k *dns.DNSKEY, state string, ds bool) KeyInventoryItem {
		return KeyInventoryItem{KeyTag: k.KeyTag(), Algorithm: k.Algorithm, Flags: k.Flags, State: state, KeyRR: k.String(), Pub: true, DS: &ds}
	}
	r.conf.noteKeyInventory(r.ctx, r.mpzd, &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: z, Owned: true, Inventory: []KeyInventoryItem{
		row(ourKSK, tdns.DnskeyStateActive, true), row(ourZSK, tdns.DnskeyStateActive, false),
		row(theirNext, DnskeyStateForeign, false), row(theirZSK, DnskeyStateForeign, false),
	}})
	if known, tags := r.dsSet(t); known {
		t.Fatalf("our KSK under p2's KSK's tag: the DS set is known with %v", tags)
	}
	if n := r.requests(t); n != 0 {
		t.Fatalf("our KSK under p2's KSK's tag asked the parent for %d syncs", n)
	}
	if why, want := r.conf.dsSetWaitingFor(z), withheldWhy("agent.p2.example.", theirKSK, KeyStateActive); why != want {
		t.Fatalf("the status says %q, want %q", why, want)
	}
}

// The check compares keys, not tags. Our own KSK under another provider's
// tag, or a third provider's under it, is not that provider's key: the
// signer's inventory lacks its DS, and the set is unknown, not one with
// another DS in place of theirs. sameTag is our KSK first, then p3's.
func TestAnotherKeyUnderAProvidersTagDoesNotHoldItsDS(t *testing.T) {
	yes, no := true, false
	r := newComputedDSRig(t, "sametag.ds.example.", []string{"us", "p2", "p3"})
	r.owner.SetForeignDSCheck(r.conf.foreignDSWithheld)
	z := r.mpzd.ZoneName
	theirKSK, theirZSK, ourKSK, ourZSK := testDnskey(t, z, 257), testDnskey(t, z, 256), testDnskey(t, z, 257), testDnskey(t, z, 256)
	sameTag := sameTagOtherKey(t, theirKSK)

	row := func(k *dns.DNSKEY, state string, ds bool) KeyInventoryItem {
		return KeyInventoryItem{KeyTag: k.KeyTag(), Algorithm: k.Algorithm, Flags: k.Flags, State: state, KeyRR: k.String(), Pub: true, DS: &ds}
	}
	inventory := func(items ...KeyInventoryItem) {
		r.conf.noteKeyInventory(r.ctx, r.mpzd, &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: z, Inventory: items, Owned: true})
	}
	unknown := func(step string) {
		t.Helper()
		if known, tags := r.dsSet(t); known {
			t.Fatalf("%s: the DS set is known with %v", step, tags)
		}
		if why, want := r.conf.dsSetWaitingFor(z), withheldWhy("agent.p2.example.", theirKSK, KeyStateActive); why != want {
			t.Fatalf("%s: the status says %q, want %q", step, why, want)
		}
	}

	r.distribution(t, "agent.p2.example.", word{theirKSK, KeyStateActive, &yes}, word{theirZSK, KeyStateActive, &no})
	inventory(row(ourKSK, tdns.DnskeyStateActive, true), row(ourZSK, tdns.DnskeyStateActive, false),
		row(theirKSK, DnskeyStateForeign, true), row(theirZSK, DnskeyStateForeign, false))
	if known, tags := r.dsSet(t); !known || len(tags) != 2 {
		t.Fatalf("both providers' keys: the DS set is known=%v with %v, want 2 DS", known, tags)
	}

	inventory(row(sameTag, tdns.DnskeyStateActive, true), row(ourZSK, tdns.DnskeyStateActive, false),
		row(theirZSK, DnskeyStateForeign, false))
	unknown("our own KSK under p2's KSK's tag")

	r.distribution(t, "agent.p3.example.", word{sameTag, KeyStateActive, &yes})
	inventory(row(ourKSK, tdns.DnskeyStateActive, true), row(ourZSK, tdns.DnskeyStateActive, false),
		row(sameTag, DnskeyStateForeign, true), row(theirZSK, DnskeyStateForeign, false))
	unknown("p3's KSK under p2's KSK's tag")
}

// A provider's key whose record has not arrived here is held by nothing: the
// tag is all there is, and a third provider's key under it would pass for
// theirs. The set is unknown until the record comes, as the computed set is,
// and the status says what it waits for.
func TestAProvidersKeyWithNoRecordYetIsHeldByNothing(t *testing.T) {
	yes, no := true, false
	r := newComputedDSRig(t, "norecord.ds.example.", []string{"us", "p2", "p3"})
	r.owner.SetForeignDSCheck(r.conf.foreignDSWithheld)
	z := r.mpzd.ZoneName
	theirKSK, theirZSK, ourKSK, ourZSK := testDnskey(t, z, 257), testDnskey(t, z, 256), testDnskey(t, z, 257), testDnskey(t, z, 256)
	p3KSK := sameTagOtherKey(t, theirKSK)
	r.conf.noteForeignDistribution(r.ctx, ZoneName(z), "agent.p2.example.", []core.RROperation{{
		Operation: "replace", RRtype: "DNSKEY", Records: []string{theirZSK.String()},
		KeyStates: []core.KeyState{{KeyTag: theirKSK.KeyTag(), State: KeyStateActive, DS: &yes}, {KeyTag: theirZSK.KeyTag(), State: KeyStateActive, DS: &no}},
	}})
	r.distribution(t, "agent.p3.example.", word{p3KSK, KeyStateActive, &yes})

	row := func(k *dns.DNSKEY, state string, ds bool) KeyInventoryItem {
		return KeyInventoryItem{KeyTag: k.KeyTag(), Algorithm: k.Algorithm, Flags: k.Flags, State: state, KeyRR: k.String(), Pub: true, DS: &ds}
	}
	r.conf.noteKeyInventory(r.ctx, r.mpzd, &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: z, Owned: true, Inventory: []KeyInventoryItem{
		row(ourKSK, tdns.DnskeyStateActive, true), row(ourZSK, tdns.DnskeyStateActive, false),
		row(p3KSK, DnskeyStateForeign, true), row(theirZSK, DnskeyStateForeign, false),
	}})
	if known, tags := r.dsSet(t); known {
		t.Fatalf("p3's KSK under the tag of p2's, whose record has not arrived: the DS set is known with %v", tags)
	}
	want := fmt.Sprintf("provider agent.p2.example. holds its key %d active with its DS at the parent, and this agent has no record of that key yet", theirKSK.KeyTag())
	if why := r.conf.dsSetWaitingFor(z); why != want {
		t.Fatalf("the status says %q, want %q", why, want)
	}
}
