package tdnsmp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Amendment 2, A2.4: three providers, one signing, the leader's signer not
// owning the zone. The DS set is unknown until the signing provider's
// distribution with key states has arrived, then it is that provider's ds=1
// SEP keys; a ds flip in a later distribution changes it and asks for a
// sync.

type computedDSRig struct {
	conf  *Config
	mpzd  *MPZoneData
	owner *MPKeyLifecycleOwner
	q     chan tdns.DelegationSyncRequest
	lem   *LeaderElectionManager
}

// newComputedDSRig: an agent ("us") of a zone with providers us, p2 and p3,
// signed by signers; the zone syncs with its parent through its agents.
func newComputedDSRig(t *testing.T, zone string, signers []string) *computedDSRig {
	t.Helper()
	mpzd := providersTestZone(t, zone, []string{"us", "p2", "p3"}, signers)
	q := make(chan tdns.DelegationSyncRequest, 8)
	mpzd.DelegationSyncQ = q
	mpzd.Options[tdns.OptParentSync] = true
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: "agent.us.example."})
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return nil })
	owner.SetComputedDSSource(conf.computedDSIntent)
	conf.InternalMp.KeyLifecycleOwner = owner
	conf.InternalMp.MPTransport = &MPTransportBridge{}
	conf.InternalMp.AgentRegistry = &AgentRegistry{}
	lem := NewLeaderElectionManager("agent.us.example.", time.Minute, func(ZoneName, string, map[string][]string) error { return nil })
	conf.InternalMp.LeaderElectionManager = lem
	tdns.RegisterKeyLifecycleOwner(owner)
	t.Cleanup(func() { tdns.RegisterKeyLifecycleOwner(nil) })
	return &computedDSRig{conf: conf, mpzd: mpzd, owner: owner, q: q, lem: lem}
}

func (r *computedDSRig) leader(who AgentId) {
	r.lem.mu.Lock()
	r.lem.elections[ZoneName(r.mpzd.ZoneName)] = &LeaderElection{Zone: ZoneName(r.mpzd.ZoneName), Leader: who, LeaderExpiry: time.Now().Add(time.Hour)}
	r.lem.mu.Unlock()
}

// word is one key of a provider's distribution: the record, and what the
// provider says about it.
type word struct {
	key   *dns.DNSKEY
	state string
	ds    *bool
}

// distribution is a provider's REPLACE of its whole DNSKEY set with its key
// states, over the wire's JSON, as the synched data engine hands it on.
func (r *computedDSRig) distribution(t *testing.T, from AgentId, keys ...word) {
	t.Helper()
	op := core.RROperation{Operation: "replace", RRtype: "DNSKEY", KeyStates: []core.KeyState{}}
	for _, k := range keys {
		op.Records = append(op.Records, k.key.String())
		op.KeyStates = append(op.KeyStates, core.KeyState{KeyTag: k.key.KeyTag(), State: k.state, DS: k.ds})
	}
	b, err := json.Marshal([]core.RROperation{op})
	if err != nil {
		t.Fatal(err)
	}
	var ops []core.RROperation
	if err := json.Unmarshal(b, &ops); err != nil {
		t.Fatal(err)
	}
	r.conf.noteForeignDistribution(context.Background(), ZoneName(r.mpzd.ZoneName), from, ops)
}

func (r *computedDSRig) requests(t *testing.T) int {
	t.Helper()
	n := 0
	for {
		select {
		case req := <-r.q:
			if req.Command != "EXPLICIT-SYNC-DELEGATION" || req.ZoneName != r.mpzd.ZoneName {
				t.Errorf("an unexpected request on the delegation sync queue: %+v", req)
			}
			n++
		default:
			return n
		}
	}
}

// dsSet is what the syncher gets: tdns's DSIntentForZone, routed to the
// registered owner, as the key tags of the DS records.
func (r *computedDSRig) dsSet(t *testing.T) (known bool, tags map[uint16]bool) {
	t.Helper()
	in, err := tdns.DSIntentForZone(nil, r.mpzd.ZoneName, dns.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	tags = map[uint16]bool{}
	for _, rr := range in.Set {
		ds, ok := rr.(*dns.DS)
		if !ok || ds.Hdr.Name != r.mpzd.ZoneName || ds.DigestType != dns.SHA256 {
			t.Errorf("a DS that is not the zone's, or not SHA-256: %s", rr)
		}
		tags[ds.KeyTag] = true
	}
	return in.Known, tags
}

func TestALeaderThatDoesNotSignComputesTheDSSet(t *testing.T) {
	yes, no := true, false
	r := newComputedDSRig(t, "computed.ds.example.", []string{"p2"})
	z := r.mpzd.ZoneName
	ksk, zsk, next := testDnskey(t, z, 257), testDnskey(t, z, 256), testDnskey(t, z, 257)
	outsider := testDnskey(t, z, 257)
	r.leader("agent.us.example.")

	// tdns routes the DS intent to the owner: the agent owns the answer,
	// not the keys, and the pre-S5 CDS rule of the syncher is untouched
	if !r.owner.Owns(r.mpzd.ZoneData) || r.owner.runsKeys(r.mpzd.ZoneData) {
		t.Fatalf("Owns=%v runsKeys=%v, want the agent to answer the DS intent without running the keys", r.owner.Owns(r.mpzd.ZoneData), r.owner.runsKeys(r.mpzd.ZoneData))
	}
	if !syncherPublishesDNSKEYCDS(r.conf, r.mpzd.ZoneData) {
		t.Error("the syncher's CDS rule changed for a zone whose keys nobody here runs")
	}
	if known, _ := r.dsSet(t); known {
		t.Fatal("a DS set before any signing provider has spoken")
	}

	// a provider that does not sign speaks first: the signing provider is
	// still silent, so the set stays unknown, and nothing asks for a sync
	r.distribution(t, "agent.p3.example.", word{outsider, KeyStateActive, &yes})
	if known, _ := r.dsSet(t); known {
		t.Error("a DS set from a provider that does not sign the zone")
	}
	if n := r.requests(t); n != 0 {
		t.Errorf("a non-signer's word asked for %d syncs", n)
	}

	// the signing provider's distribution: its ds=1 SEP key is the set,
	// and the leader asks for the sync
	r.distribution(t, "agent.p2.example.", word{ksk, KeyStateActive, &yes}, word{zsk, KeyStateActive, &no}, word{next, KeyStatePublished, &no})
	known, tags := r.dsSet(t)
	if !known || len(tags) != 1 || !tags[ksk.KeyTag()] {
		t.Fatalf("after the signing provider spoke: known=%v tags=%v, want its active KSK alone", known, tags)
	}
	if n := r.requests(t); n != 1 {
		t.Errorf("the first known DS set: %d sync requests, want 1", n)
	}
	// the same distribution again: nothing changed, nothing asked
	r.distribution(t, "agent.p2.example.", word{ksk, KeyStateActive, &yes}, word{zsk, KeyStateActive, &no}, word{next, KeyStatePublished, &no})
	if n := r.requests(t); n != 0 {
		t.Errorf("an unchanged DS set asked for %d syncs", n)
	}

	// a ds flip with the records as they were: the published KSK becomes
	// standby with ds=1. The set grows, and the leader asks
	r.distribution(t, "agent.p2.example.", word{ksk, KeyStateActive, &yes}, word{zsk, KeyStateActive, &no}, word{next, KeyStateStandby, &yes})
	known, tags = r.dsSet(t)
	if !known || len(tags) != 2 || !tags[ksk.KeyTag()] || !tags[next.KeyTag()] {
		t.Fatalf("after the ds flip: known=%v tags=%v, want both KSKs", known, tags)
	}
	if n := r.requests(t); n != 1 {
		t.Errorf("a ds-only change: %d sync requests, want 1", n)
	}
	// the outsider's ds=1 KSK is not in the set: it does not sign
	if tags[outsider.KeyTag()] {
		t.Error("the set carries the key of a provider that does not sign")
	}

	// a SEP key whose ds nobody decided: the set is unknown, and an
	// unknown set asks for nothing
	r.distribution(t, "agent.p2.example.", word{ksk, KeyStateActive, &yes}, word{zsk, KeyStateActive, &no}, word{next, KeyStateStandby, nil})
	if known, _ := r.dsSet(t); known {
		t.Error("a DS set with a SEP key whose ds is undecided")
	}
	if n := r.requests(t); n != 0 {
		t.Errorf("an unknown DS set asked for %d syncs", n)
	}
	// decided again: known, and asked for
	r.distribution(t, "agent.p2.example.", word{ksk, KeyStateActive, &yes}, word{zsk, KeyStateActive, &no}, word{next, KeyStateStandby, &yes})
	if n := r.requests(t); n != 1 {
		t.Errorf("the set known again: %d sync requests, want 1", n)
	}

	// a peer that does not lead asks for nothing when the set changes
	r.leader("agent.p2.example.")
	r.distribution(t, "agent.p2.example.", word{ksk, KeyStateRetired, &no}, word{zsk, KeyStateActive, &no}, word{next, KeyStateActive, &yes})
	known, tags = r.dsSet(t)
	if !known || len(tags) != 1 || !tags[next.KeyTag()] {
		t.Errorf("after the withdrawal: known=%v tags=%v, want the new KSK alone", known, tags)
	}
	if n := r.requests(t); n != 0 {
		t.Errorf("a peer that does not lead asked for %d syncs", n)
	}
}

// The set needs every signing provider, a record for every ds=1 key, and
// a zone that names signers; our own provider's share, when it signs and
// its signer does not own the zone, is that signer's inventory; and the
// owner's inventory, when our signer owns the zone, is the answer, not the
// computed set.
func TestTheComputedSetNeedsEverySigningProvider(t *testing.T) {
	yes, no := true, false
	r := newComputedDSRig(t, "every.signer.example.", []string{"p2", "p3"})
	z := r.mpzd.ZoneName
	p2key, p3key := testDnskey(t, z, 257), testDnskey(t, z, 257)
	r.leader("agent.us.example.")

	r.distribution(t, "agent.p2.example.", word{p2key, KeyStateActive, &yes})
	if known, _ := r.dsSet(t); known {
		t.Error("a DS set while one of two signing providers is silent")
	}
	if n := r.requests(t); n != 0 {
		t.Errorf("one signer of two asked for %d syncs", n)
	}
	r.distribution(t, "agent.p3.example.", word{p3key, KeyStateActive, &yes})
	known, tags := r.dsSet(t)
	if !known || len(tags) != 2 || !tags[p2key.KeyTag()] || !tags[p3key.KeyTag()] {
		t.Fatalf("both signing providers spoke: known=%v tags=%v, want both KSKs", known, tags)
	}
	if n := r.requests(t); n != 1 {
		t.Errorf("the set known once both spoke: %d sync requests, want 1", n)
	}
	// a provider that has spoken and lists no keys: an empty share, the
	// set is the other's. Built by hand: the wire's JSON drops an empty
	// list, so today's sender cannot say this (A2.2, the empty-share
	// clause), and what arrives here is what a later wire will carry
	r.conf.noteForeignDistribution(context.Background(), ZoneName(z), "agent.p3.example.",
		[]core.RROperation{{Operation: "replace", RRtype: "DNSKEY", KeyStates: []core.KeyState{}}})
	known, tags = r.dsSet(t)
	if !known || len(tags) != 1 || !tags[p2key.KeyTag()] {
		t.Errorf("after p3's empty word: known=%v tags=%v, want p2's KSK alone", known, tags)
	}
	if n := r.requests(t); n != 1 {
		t.Errorf("a share emptied: %d sync requests, want 1", n)
	}
	// ds=1 for a key the provider sent no record of: no DS can be made,
	// the set is unknown
	ghost := testDnskey(t, z, 257)
	ops := []core.RROperation{{Operation: "replace", RRtype: "DNSKEY", Records: []string{p2key.String()},
		KeyStates: []core.KeyState{{KeyTag: p2key.KeyTag(), State: KeyStateActive, DS: &yes}, {KeyTag: ghost.KeyTag(), State: KeyStateStandby, DS: &yes}}}}
	r.conf.noteForeignDistribution(context.Background(), ZoneName(z), "agent.p2.example.", ops)
	if known, _ := r.dsSet(t); known {
		t.Error("a DS set with a ds=1 key that has no record")
	}
	// the same key with ds undecided: it may be a SEP key whose record has
	// not arrived, and the set stays unknown
	ops[0].KeyStates[1].DS = nil
	r.conf.noteForeignDistribution(context.Background(), ZoneName(z), "agent.p2.example.", ops)
	if known, _ := r.dsSet(t); known {
		t.Error("a DS set with an undecided key that has no record")
	}
	// the same key with ds=0 is nothing to make a DS of: the set is known
	ops[0].KeyStates[1].DS = &no
	r.conf.noteForeignDistribution(context.Background(), ZoneName(z), "agent.p2.example.", ops)
	if known, tags := r.dsSet(t); !known || len(tags) != 1 {
		t.Errorf("a recordless key with ds=0: known=%v tags=%v, want p2's KSK alone", known, tags)
	}

	// a zone that names no signing provider has nothing to compute
	u := newComputedDSRig(t, "unsigned.zone.example.", nil)
	u.distribution(t, "agent.p2.example.", word{testDnskey(t, u.mpzd.ZoneName, 257), KeyStateActive, &yes})
	if known, _ := u.dsSet(t); known {
		t.Error("a DS set for a zone with no signers")
	}

	// our own provider signs, and its signer does not own the zone: our
	// share is our signer's inventory, which arrives as an inventory that
	// is not marked Owned. Without it the set is unknown; with it, its
	// ds=1 SEP keys join the other signer's, and a change of it asks
	o := newComputedDSRig(t, "ours.too.example.", []string{"us", "p2"})
	oz := o.mpzd.ZoneName
	o.leader("agent.us.example.")
	o.distribution(t, "agent.p2.example.", word{testDnskey(t, oz, 257), KeyStateActive, &yes})
	if known, _ := o.dsSet(t); known {
		t.Error("a DS set before our own signer, which signs the zone, has sent an inventory")
	}
	ours := invItem(t, oz, 257, KeyStateActive, &yes)
	o.conf.noteKeyInventory(context.Background(), o.mpzd, &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: oz, Inventory: []KeyInventoryItem{ours}, Owned: false})
	known, tags = o.dsSet(t)
	if !known || len(tags) != 2 || !tags[ours.KeyTag] {
		t.Errorf("with our signer's inventory: known=%v tags=%v, want our KSK beside p2's", known, tags)
	}
	if n := o.requests(t); n != 1 {
		t.Errorf("our own share arriving: %d sync requests, want 1", n)
	}
	ours.DS = &no
	o.conf.noteKeyInventory(context.Background(), o.mpzd, &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: oz, Inventory: []KeyInventoryItem{ours}, Owned: false})
	if known, tags := o.dsSet(t); !known || len(tags) != 1 || tags[ours.KeyTag] {
		t.Errorf("our KSK's ds withdrawn: known=%v tags=%v, want p2's KSK alone", known, tags)
	}
	if n := o.requests(t); n != 1 {
		t.Errorf("our share changing: %d sync requests, want 1", n)
	}

	// our signer owns the zone: its inventory is the answer (A2.3), the
	// computed set is not consulted, and the owner runs the keys
	owned := invItem(t, oz, 257, KeyStateActive, &yes)
	o.conf.noteKeyInventory(context.Background(), o.mpzd, &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: oz, Inventory: []KeyInventoryItem{owned}, Owned: true})
	if !o.owner.runsKeys(o.mpzd.ZoneData) {
		t.Error("an inventory marked Owned does not make the owner run the keys")
	}
	if known, tags := o.dsSet(t); !known || len(tags) != 1 || !tags[owned.KeyTag] {
		t.Errorf("with an owned inventory: known=%v tags=%v, want the inventory's KSK alone", known, tags)
	}
	if n := o.requests(t); n != 1 {
		t.Errorf("the owned inventory arriving: %d sync requests, want 1", n)
	}
	// a distribution for an owned zone asks nothing here: the inventory
	// is the source and asks
	o.distribution(t, "agent.p2.example.", word{testDnskey(t, oz, 257), KeyStateActive, &yes})
	if n := o.requests(t); n != 0 {
		t.Errorf("a distribution for a zone our signer owns asked for %d syncs", n)
	}
}

// The records a provider's operations carry follow the operation: a
// replace is its whole set, an add and a delete edit it.
func TestForeignDnskeyRecordsFollowTheOperations(t *testing.T) {
	z := "records.ops.example."
	a, b := testDnskey(t, z, 257), testDnskey(t, z, 257)
	cur := applyDnskeyRecords(nil, core.RROperation{Operation: "replace", Records: []string{a.String()}})
	if len(cur) != 1 || cur[0].KeyTag() != a.KeyTag() {
		t.Fatalf("after a replace: %v", cur)
	}
	cur = applyDnskeyRecords(cur, core.RROperation{Operation: "add", Records: []string{b.String(), a.String(), "not a record"}})
	if len(cur) != 2 {
		t.Fatalf("after an add: %v", cur)
	}
	cur = applyDnskeyRecords(cur, core.RROperation{Operation: "delete", Records: []string{a.String()}})
	if len(cur) != 1 || cur[0].KeyTag() != b.KeyTag() {
		t.Fatalf("after a delete: %v", cur)
	}
	if got := applyDnskeyRecords(cur, core.RROperation{Operation: "whatever", Records: []string{a.String()}}); len(got) != 1 {
		t.Errorf("an unknown operation changed the records: %v", got)
	}
	// the bridge keeps them beside the key states, per sending agent
	tm := &MPTransportBridge{}
	tm.NoteForeignKeyStates(ZoneName(z), "agent.p2.example.", []core.RROperation{{Operation: "replace", RRtype: "DNSKEY", Records: []string{a.String()}, KeyStates: []core.KeyState{{KeyTag: a.KeyTag(), State: KeyStateActive}}}})
	tm.NoteForeignKeyStates(ZoneName(z), "agent.p2.example.", []core.RROperation{{Operation: "add", RRtype: "DNSKEY", Records: []string{b.String()}, KeyStates: []core.KeyState{{KeyTag: a.KeyTag(), State: KeyStateActive}, {KeyTag: b.KeyTag(), State: KeyStatePublished}}}})
	shares := tm.foreignSharesFor(ZoneName(z))
	if sh := shares["agent.p2.example."]; len(sh.states) != 2 || len(sh.dnskeys) != 2 {
		t.Errorf("the provider's share: %d states, %d records, want 2 and 2", len(sh.states), len(sh.dnskeys))
	}
}
