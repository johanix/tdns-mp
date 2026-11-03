/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// signerAddRig is the reconciliation rig with a transition that moves a provider
// into signers=: agent a leads a zone that a and b serve and b signs. Its own
// provider joins under signersV, by default "a,b". The parent's DS RRset and the
// sync the leader asks are the rig's, and the agent's looks run in place.
type signerAddRig struct {
	*reconcileRig
	parent    map[uint16]bool
	parentTTL time.Duration
	syncs     int
}

const signerAddSelf = roleA

func newSignerAddRig(t *testing.T, zone, parentsync string) *signerAddRig {
	t.Helper()
	r := &signerAddRig{reconcileRig: newReconcileRig(t, zone, roleA), parent: map[uint16]bool{}}
	param := func(signers string) string {
		return `servers="a,b" signers="` + signers + `" nsmgmt="owner" parentsync="` + parentsync + `" suffix="n"`
	}
	r.n = jAt(t, 41, param("b"), freezeRecords...)
	knownAs(t, r.store, zone, r.n)
	r.v = jAt(t, 42, param("a,b"), freezeRecords...)
	r.conf.InternalMp.signerAdds.start = func(look func()) { look() }
	prevLook, prevAsk := parentDSLook, askJoinersDS
	parentDSLook = func(*Config, string) (parentDSSeen, error) {
		return parentDSSeen{tags: r.parent, ttl: r.parentTTL}, nil
	}
	askJoinersDS = func(*Config, string, string) { r.syncs++ }
	t.Cleanup(func() { parentDSLook, askJoinersDS = prevLook, prevAsk })
	mp := r.conf.MpConfig()
	mp.Local.Nameservers = srNameservers
	return r
}

// thawed has the zone thawed to V, with step 0 held here and at b. This agent is
// the leader and the joiner, so that one agent shows the leader's plan and the
// joiner's own part. A leader votes, so it has a role under N, and the one that
// lets it join is a server's: a move the judge refuses (design 5.3), held here
// unjudged. The steps do not read the role it had; TestANewSignerHasItsStepsFromItsLeader
// has a joiner with none.
func (r *signerAddRig) thawed() *signerAddRig {
	r.t.Helper()
	r.holdUnjudged(r.v, time.Now())
	r.thawNow()
	r.partsTake()
	r.holdsToo(roleB)
	return r
}

// next has every member hold the step, and takes a turn: the step after it, or
// the same one while it waits.
func (r *signerAddRig) next() InstrStep {
	r.t.Helper()
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	st, ok := r.step()
	if !ok {
		r.t.Fatal("no step held")
	}
	return st
}

// at fails the test unless the step's own key is part's.
func (r *signerAddRig) at(st InstrStep, part string) {
	r.t.Helper()
	if id, got, ok := signerAddOf(st); !ok || got != part || !core.EqualNames(id, signerAddSelf) {
		r.t.Fatalf("the step is %+v (%q, %v), want a's %s", st, got, ok, part)
	}
}

// keys has this provider's signer say its KSK and ZSK are in state, with ds set
// on a KSK at standby or later, and that it signs, as it does from its keys' step.
func (r *signerAddRig) keys(ksk, zsk string, marks ...func(*KeyInventorySnapshot)) (kskTag uint16) {
	r.t.Helper()
	yes, no := true, false
	dsOf := func(state string) *bool {
		if state == KeyStateStandby || state == KeyStateActive {
			return &yes
		}
		return &no
	}
	k, z := invItem(r.t, r.zone, 257, ksk, dsOf(ksk)), invItem(r.t, r.zone, 256, zsk, &no)
	snap := &KeyInventorySnapshot{Zone: r.zone, Inventory: []KeyInventoryItem{k, z}, Received: time.Now(), Signs: true}
	for _, m := range marks {
		m(snap)
	}
	mpzd, _ := Zones.Get(r.zone)
	mpzd.SetLastKeyInventory(snap)
	return k.KeyTag
}

// parentLooks has the next wait of the DS step look at the parent again.
func (r *signerAddRig) parentLooks() {
	r.conf.InternalMp.signerAdds.mu.Lock()
	defer r.conf.InternalMp.signerAdds.mu.Unlock()
	for _, l := range r.conf.InternalMp.signerAdds.zones {
		l.parentAt = time.Time{}
	}
}

// nameserversServe has its nameservers answer with the SOA at serial, and a
// DNSKEY RRset of key signed by priv, or with no priv unsigned.
func (r *signerAddRig) nameserversServe(t *testing.T, serial uint32, key *dns.DNSKEY, priv crypto.Signer) {
	t.Helper()
	serving(t, soa(t, r.zone, serial, nil, nil), nil)
	prev := servingKeysLookup
	servingKeysLookup = func(context.Context, string, string) (*core.RRset, error) {
		return signedDNSKEYs(t, r.zone, key, priv), nil
	}
	t.Cleanup(func() { servingKeysLookup = prev })
}

// signedDNSKEYs is the DNSKEY RRset of key, signed by it, or with no key no
// signature; priv's key is a SEP key.
func signedDNSKEYs(t *testing.T, zone string, key *dns.DNSKEY, priv crypto.Signer) *core.RRset {
	t.Helper()
	rrset := &core.RRset{RRs: []dns.RR{key}}
	if priv == nil {
		return rrset
	}
	now := time.Now()
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		KeyTag: key.KeyTag(), SignerName: zone, Algorithm: key.Algorithm,
		Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(time.Hour).Unix())}
	if err := sig.Sign(priv, rrset.RRs); err != nil {
		t.Fatal(err)
	}
	rrset.RRSIGs = []dns.RR{sig}
	return rrset
}

// ownKSK is a SEP key of the zone that this agent holds for its own provider.
func (r *signerAddRig) ownKSK(t *testing.T) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key, priv := signingKey(t, r.zone)
	key.Flags = 257
	mpzd, _ := Zones.Get(r.zone)
	mpzd.Lock()
	mpzd.MP.LocalDNSKEYs = []dns.RR{key}
	mpzd.Unlock()
	return key, priv
}

// The zone's leader plans a new signer's steps, through the judge: a provider with
// no role entering signers= is not the move it refuses (design 5.3).
func TestALeaderPlansTheStepsOfASignerWithNoRoleYet(t *testing.T) {
	r := newSignerAddRig(t, "planned.adding.example.", "owner")
	r.n = jAt(t, 41, `servers="a,b" signers="a" nsmgmt="owner" parentsync="owner" suffix="n"`, freezeRecords...)
	knownAs(t, r.store, r.zone, r.n)
	r.v = jAt(t, 42, `servers="a,b" signers="a,n" nsmgmt="owner" parentsync="owner" suffix="n"`, freezeRecords...)
	r.agree()
	r.hear(roleN, r.agreeing(), true)
	r.thawNow()
	r.partsTake()
	r.holdsToo(roleB)
	r.holdsToo(roleN)
	r.turn(time.Now())
	st, _ := r.step()
	if id, part, ok := signerAddOf(st); !ok || part != signerAddAccept || !core.EqualNames(id, roleN) {
		t.Errorf("the step is %q of %q (%v), want n's %s", part, id, ok, signerAddAccept)
	}
}

// A new signer does not vote, so it has its steps from its leader, as any member
// does, and at its own agent they do what they do at a leader that joins: its
// combiner holds the key sets at once, its signer at the step after, with Signing.
func TestANewSignerHasItsStepsFromItsLeader(t *testing.T) {
	r := newSignerAddRig(t, "led.adding.example.", "owner")
	r.lead(roleB, time.Now().Add(time.Hour))
	r.n = jAt(t, 41, `servers="b" signers="b" nsmgmt="owner" parentsync="owner" suffix="n"`, freezeRecords...)
	knownAs(t, r.store, r.zone, r.n)
	r.v = jAt(t, 42, `servers="b" signers="a,b" nsmgmt="owner" parentsync="owner" suffix="n"`, freezeRecords...)
	r.agree()
	st := tells(r.v, r.v)
	st.Thaw, st.Reconciling = &Thaw{From: sd(r.n), To: sd(r.v)}, true
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if r.active() != r.v.Serial {
		t.Fatalf("not thawed on its leader's word: active %d", r.active())
	}
	sets := rolesFor(r.n, r.n, 0)
	joiner := Provider{Label: "a", Identity: roleA}
	sets.KeySigners, sets.KeyConfirmers = addProvider(sets.KeySigners, joiner), addProvider(sets.KeyConfirmers, joiner)
	key := func(part string) string { return signerAddKey + part + " " + canonicalName(roleA) }
	r.hear(roleB, r.leaderStep(1, sets, []string{key(signerAddAccept)}), true)
	r.conf.thawTurn(r.zone)
	got, ok := r.step()
	if !ok {
		t.Fatal("no step held")
	}
	r.at(got, signerAddAccept)
	if h := r.wantedBy(r.combiner); h == nil || !has(h.Sets.KeySigners, "a") {
		t.Errorf("the combiner is handed %+v at its first step, want a in the key sets", h)
	}
	if h := r.wantedBy(r.signer); h == nil || has(h.Sets.KeySigners, "a") {
		t.Errorf("the signer is handed %+v at its first step, want the step without a", h)
	}
	sets.Signing = addProvider(sets.Signing, joiner)
	r.hear(roleB, r.leaderStep(2, sets, []string{key(signerAddAccept), key(signerAddMint)}), true)
	r.conf.thawTurn(r.zone)
	if got, ok = r.step(); !ok {
		t.Fatal("no step held")
	}
	r.at(got, signerAddMint)
	if h := r.wantedBy(r.signer); h == nil || !has(h.Sets.KeySigners, "a") || !has(h.Sets.Signing, "a") {
		t.Errorf("the signer is handed %+v at its second step, want a in the key sets and in Signing", h)
	}
}

// tdns signs with the rows that say sign=1: a new signer's first keys, on their way
// through the machine, sign its zone, its own signatures replacing those of the copy
// it relayed. That is its signing at its naming, with tdns's real start.
func TestANewSignerStartsSigningWithItsFirstKeysOnTheirWay(t *testing.T) {
	const zone = "ontheirway.adding.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="p2" signers="p2"`)...)
	prev := startSigning
	startSigning = func(ctx context.Context, zd *tdns.ZoneData) error { return zd.StartSigning(ctx, 0) }
	t.Cleanup(func() { startSigning = prev })
	r.hand(joinerHandover(t, zone, 6, true), sigUs)
	r.e.tickOwned()
	inv, err := tdns.GetKeyInventory(r.kdb, zone)
	if err != nil {
		t.Fatal(err)
	}
	var zsk uint16
	for _, it := range inv {
		if it.State == KeyStateActive || !it.Sign {
			t.Errorf("its first key %d is %s, sign %v: want it on its way, signing", it.KeyTag, it.State, it.Sign)
		}
		if it.Flags&dns.SEP == 0 {
			zsk = it.KeyTag
		}
	}
	r.roleTurn()
	if !r.mpzd.Options[tdns.OptInlineSigning] || r.mpzd.Withheld() {
		t.Fatalf("the option %v, withheld %v: want it signing", r.mpzd.Options[tdns.OptInlineSigning], r.mpzd.Withheld())
	}
	soa, err := r.mpzd.GetRRset(zone, dns.TypeSOA)
	if err != nil || soa == nil {
		t.Fatalf("no SOA: %v", err)
	}
	signed := slices.ContainsFunc(soa.RRSIGs, func(rr dns.RR) bool {
		sig, ok := rr.(*dns.RRSIG)
		return ok && sig.KeyTag == zsk
	})
	if !signed {
		t.Errorf("the SOA is signed by %v, not by its first ZSK %d", soa.RRSIGs, zsk)
	}
	keys, err := r.mpzd.GetRRset(zone, dns.TypeDNSKEY)
	if err != nil || keys == nil || len(keys.RRs) != 2 || len(keys.RRSIGs) == 0 {
		t.Errorf("the DNSKEY RRset: %+v (%v), want its two keys, signed", keys, err)
	}
}

// A new provider brought up after the owner's edit: its agent has no copy, its copy
// names it a server and a signer, and it acts by that. Its signer signs with tdns's
// keys, active at once. That must not read as its keys having propagated: handed its
// keys' step, they start over before it says anything of them, so its steps wait for
// T8 and T9 as anyone's do, and no NS is added before them.
func TestAJoinerBroughtUpAfterTheEditHasItsKeysStartOver(t *testing.T) {
	const zone = "afteredit.adding.signer.example."
	records := sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)
	r := newSignerRig(t, zone, records...)
	prev := startSigning
	startSigning = func(ctx context.Context, zd *tdns.ZoneData) error { return zd.StartSigning(ctx, 0) }
	t.Cleanup(func() { startSigning = prev })
	r.firstLoad(t, records...)
	r.hand(&ActingHandover{Zone: zone, Phase: PhaseSteady, NoCopy: true, Made: time.Now()}, sigUs)
	r.roleTurn()
	states := func() map[string]bool {
		t.Helper()
		inv, err := tdns.GetKeyInventory(r.kdb, zone)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, it := range inv {
			if it.State != DnskeyStateForeign {
				out[it.State] = true
				if !it.Sign {
					t.Errorf("key %d is %s, and it does not sign", it.KeyTag, it.State)
				}
				if it.Flags&dns.SEP != 0 && it.State == KeyStateMpdist && it.DS != nil && *it.DS {
					t.Errorf("its KSK %d is %s with ds=1 (P2)", it.KeyTag, it.State)
				}
			}
		}
		return out
	}
	if got := states(); len(got) != 1 || !got[KeyStateActive] {
		t.Fatalf("by its own copy its keys are %v: the test has lost its point", got)
	}
	h := joinerHandover(t, zone, 7, true)
	h.Step, h.Joining = 2, true
	r.hand(h, sigUs)
	if got := states(); len(got) != 1 || !got[KeyStateMpdist] {
		t.Errorf("handed its keys' step, its keys are %v, want them on their way", got)
	}
	r.roleTurn()
	if !r.mpzd.Options[tdns.OptInlineSigning] {
		t.Error("handed Signing, with its keys on their way, it does not sign")
	}
}

// A provider put back, its keys left from an earlier time and its zone not yet taken
// by its key machine: its turn binds the policy and has them start over at once,
// before it says anything of them.
func TestAProviderPutBackHasItsKeysStartOverAsItsZoneIsTaken(t *testing.T) {
	const zone = "putback.adding.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="p2" signers="p2"`)...)
	prev := bindWithoutSigning
	bindWithoutSigning = func(zd *tdns.ZoneData) error {
		zd.DnssecPolicy = &tdns.DnssecPolicy{Mode: tdns.DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519}
		return nil
	}
	t.Cleanup(func() { bindWithoutSigning = prev })
	r.mpzd.Lock()
	r.mpzd.DnssecPolicy = nil
	r.mpzd.Unlock()
	r.owner = NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return r.kdb })
	r.e = NewKeyLifecycleEngine(r.conf, r.owner)
	r.e.wire.push = func(*Config, string, []uint16) {}
	r.conf.InternalMp.KeyLifecycle, r.conf.InternalMp.KeyLifecycleOwner = r.e, r.owner
	r.conf.MpConfig().KeyLifecycleZones = []string{zone}
	for _, role := range []string{"KSK", "ZSK"} {
		if _, _, err := r.kdb.GenerateKeypair(zone, "earlier", tdns.DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, role, nil); err != nil {
			t.Fatal(err)
		}
	}
	h := joinerHandover(t, zone, 6, true)
	h.Step, h.Joining = 2, true
	r.hand(h, sigUs)
	r.roleTurn()
	inv, err := tdns.GetKeyInventory(r.kdb, zone)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range inv {
		if it.State != KeyStateMpdist {
			t.Errorf("its key %d is %s, want it starting over", it.KeyTag, it.State)
		}
	}
}

// A first load handed Signing, over a copy that carries another's signatures, as
// from a stanza naming another provider's signer: tdns would take them for the
// zone's own and leave them, so the zone relays that copy, and it is StartSigning
// that replaces them (signerRoleTurn). So does one that serves nothing, whose first
// keys are its key machine's. A copy with none, at a provider that serves, signs at
// its first load.
func TestAFirstLoadOverASignedCopyLeavesTheSwitchToStartSigning(t *testing.T) {
	for _, c := range []struct {
		name   string
		signed bool
		param  string
		on     bool
	}{
		{"unsigned", false, `servers="us,p2" signers="us,p2"`, true},
		{"signed", true, `servers="us,p2" signers="us,p2"`, false},
		{"servesnothing", false, `servers="p2" signers="us,p2"`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			zone := c.name + ".firstcopy.signer.example."
			records := sigRecords(`serial="5" ` + c.param)
			r := newSignerRig(t, zone, records...)
			r.hand(handoverFor(t, zone, records...), sigUs)
			// not loaded yet: nothing published, as the config parse leaves it
			fresh := &tdns.ZoneData{ZoneName: zone, ZoneStore: tdns.MapZone, ZoneType: tdns.Primary, Logger: r.mpzd.Logger,
				Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}, KeyDB: r.kdb}
			tdns.Zones.Set(zone, fresh)
			Zones.Invalidate(zone)
			mpzd, ok := Zones.Get(zone)
			if !ok {
				t.Fatal("no zone")
			}
			mpzd.EnsureMP()
			if c.signed {
				records = append(records, `3600 IN RRSIG SOA 15 3 3600 20351231000000 20250101000000 4711 `+zone+` AAAA`)
			}
			incoming := incomingCopy(t, zone, records...)
			mpzd.MPPreRefresh(incoming, nil, nil, r.conf.MpConfig())
			if on := incoming.Options[tdns.OptInlineSigning]; on != c.on {
				t.Errorf("its first load has the option %v, want %v", on, c.on)
			}
			if d := mpzd.MP.MPdata; d == nil || !d.WeAreSigner {
				t.Errorf("its data is %+v, not that of a signer", d)
			}
		})
	}
}

// The joiner's agent hands its signer the step that names it only at the step
// after: every other member's combiner holds it by then, and one that does not
// would reject its key, which waits for its operator. Its combiner, which rejects
// nothing of its own, has it at once.
func TestAJoinersSignerIsHandedItsKeysAfterEveryMemberHoldsThem(t *testing.T) {
	r := newSignerAddRig(t, "handed.adding.example.", "owner").thawed()
	st := r.next()
	r.at(st, signerAddAccept)
	if h := r.wantedBy(r.combiner); h == nil || !has(h.Sets.KeySigners, "a") || !has(h.Sets.KeyConfirmers, "a") {
		t.Errorf("the combiner is handed %+v at its first step, want a in the key sets", h)
	}
	if h := r.wantedBy(r.signer); h == nil || has(h.Sets.KeySigners, "a") || has(h.Sets.KeyConfirmers, "a") || h.Step != st.Number || h.Joining {
		t.Errorf("the signer is handed %+v at its first step, want the step without a", h)
	}
	r.at(r.next(), signerAddMint)
	if h := r.wantedBy(r.signer); h == nil || !h.Joining {
		t.Errorf("the signer is handed %+v at its keys' step, want it marked, so that keys it holds start over", h)
	}
	if h := r.wantedBy(r.combiner); h == nil || h.Joining {
		t.Errorf("the combiner is handed %+v at its keys' step, the mark is the signer's", h)
	}
	if h := r.wantedBy(r.signer); h == nil || !has(h.Sets.KeySigners, "a") || !has(h.Sets.KeyConfirmers, "a") || !has(h.Sets.Signing, "a") {
		t.Errorf("the signer is handed %+v once every member holds it, want a in the key sets and in Signing", h)
	}
}

// A joining signer's first keys are the machine's own, under the hold: a role with
// no active key gets one, and nothing else starts. It runs by KeySigners, with no
// signatures served.
func TestAJoiningSignerMintsUnderTheHold(t *testing.T) {
	const zone = "mints.adding.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="p2"`)...)
	r.hand(joinerHandover(t, zone, 6, true), sigUs)
	if !r.conf.InternalMp.SignerHolds.held(zone) {
		t.Fatal("the hand-over's hold is not kept")
	}
	r.e.tickOwned()
	keys := joinersKeys(t, r, zone)
	if keys["KSK"] != 1 || keys["ZSK"] != 1 {
		t.Errorf("under the hold the joiner has %v, want its first KSK and ZSK", keys)
	}
}

// What a hold exempts is the step's own key work and no more: a provider's first
// keys, and another signer's keys sent again to one that joins its confirmers. No
// standby key, and no rollover: the keys it has go on as they are.
func TestTheHoldsExemptionCoversOnlyTheStepsKeyWork(t *testing.T) {
	const zone = "only.adding.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="p2"`)...)
	r.hand(joinerHandover(t, zone, 6, true), sigUs)
	r.e.tickOwned()
	if keys := joinersKeys(t, r, zone); keys["KSK"] != 1 || keys["ZSK"] != 1 {
		t.Fatalf("under the hold the joiner has %v, want its first KSK and ZSK", keys)
	}

	// the machine's first keys go all the way under it, and nothing more starts:
	// the policy keeps a standby ZSK, which follows the hold's end
	pol := holdPolicy
	pol.StandbyZSK = 1
	d := newDriverRig(t, "machine.only.adding.signer.example.", pol, "p2")
	d.l.SetHold(true)
	bootstrapKSK(t, d)
	if d.keysIn(KeyStateActive, "ZSK") == nil || len(d.keysIn(KeyStateMpdist, "ZSK")) != 0 {
		t.Errorf("under the hold the key rows are %s, want its first keys and no standby", d.keyRows())
	}
	d.l.SetHold(false)
	d.tick("let go")
	if len(d.keysIn(KeyStateMpdist, "ZSK")) != 1 {
		t.Errorf("after the hold the key rows are %s, want its standby ZSK on its way", d.keyRows())
	}

	// another signer: under the hold it sends what it has to the one that joins
	const other = "other.only.adding.signer.example."
	o := newSignerRig(t, other, sigRecords(`serial="5" servers="us,p2" signers="us"`)...)
	h := handoverFor(t, other, sigRecords(`serial="5" servers="us,p2" signers="us"`)...)
	h.Sets.Hold = true
	o.hand(h, sigUs)
	o.e.tickOwned()
	lo := o.e.driver(other)
	before := joinersKeys(t, o, other)
	joined := handoverFor(t, other, sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)...)
	joined.Sets.Hold = true
	joined.Sets.Signing, joined.Sets.DSSigners = h.Sets.Signing, h.Sets.DSSigners
	o.hand(joined, sigUs)
	if !lo.Expects([]string{"p2"}) {
		t.Error("under the hold the signer's distributions do not follow the one that joined its confirmers")
	}
	o.e.tickOwned()
	if keys := joinersKeys(t, o, other); keys["KSK"] != before["KSK"] || keys["ZSK"] != before["ZSK"] {
		t.Errorf("under the hold the other signer went from %v to %v", before, keys)
	}
}

// joinerHandover hands provider us in KeySigners and KeyConfirmers beside p2, and
// no more of its role.
func joinerHandover(t *testing.T, zone string, serial uint32, hold bool) *ActingHandover {
	t.Helper()
	h := handoverFor(t, zone, sigRecords(numberedAt(serial)+` servers="p2" signers="us,p2"`)...)
	h.Sets.DSSigners = []Provider{{Label: "p2", Identity: "agent.p2.example."}}
	h.Sets.Hold = hold
	return h
}

func numberedAt(serial uint32) string { return fmt.Sprintf(`serial="%d"`, serial) }

// joinersKeys counts the zone's own keys by role.
func joinersKeys(t *testing.T, r *signerRig, zone string) map[string]int {
	t.Helper()
	inv, err := tdns.GetKeyInventory(r.kdb, zone)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, it := range inv {
		if it.State != DnskeyStateForeign {
			out[roleOf(it.Flags)]++
		}
	}
	return out
}

// Only the DNSKEY and DS steps wait for an emergency rollover (design 3.3): a
// voting member's rollover under way holds them, and neither of the others.
func TestTheJoinersDNSKEYAndDSStepsWaitForAnEmergencyRollover(t *testing.T) {
	r := newSignerAddRig(t, "emergency.adding.example.", "owner").thawed()
	serving(t, soa(t, r.zone, 5, nil, nil), nil)
	rolling := func() {
		st := r.own()
		st.StepHeld, st.Rollover = true, true
		r.hear(roleB, st, true)
	}
	turnRolling := func() int {
		r.partsTake()
		rolling()
		r.turn(time.Now())
		st, _ := r.step()
		return st.Number
	}
	start, _ := r.step()
	if n := turnRolling(); n != start.Number {
		t.Fatalf("its DNSKEY step was taken during an emergency rollover: step %d", n)
	}
	r.at(r.next(), signerAddAccept)
	cur, _ := r.step()
	if n := turnRolling(); n != cur.Number {
		t.Fatalf("its keys' step was taken during an emergency rollover: step %d", n)
	}
	r.at(r.next(), signerAddMint)
	r.keys(KeyStatePublished, KeyStatePublished)
	cur, _ = r.step()
	if n := turnRolling(); n != cur.Number {
		t.Fatalf("its DS step was taken during an emergency rollover: step %d", n)
	}
	r.at(r.next(), signerAddDS)
	tag := r.keys(KeyStateStandby, KeyStateActive)
	r.parent[tag] = true
	r.parentLooks()
	r.next()
	st := r.next()
	r.at(st, signerAddCaches)
	r.keys(KeyStateActive, KeyStateActive)
	r.partsTake()
	r.holdsToo(roleB)
	if n := turnRolling(); n == st.Number {
		t.Error("its signatures' step waits for an emergency rollover, which only the DS and DNSKEY steps do")
	}
}

// Its DS goes to the parent's set only at its DS step, which comes after its keys
// are published, which needs every other signer to have applied them: DSSigners
// names it no sooner, and no sooner does the leader's DS set hold it.
func TestTheJoinersDSIsSentOnlyAfterEverySignerAppliedItsKeys(t *testing.T) {
	r := newSignerAddRig(t, "ds.adding.example.", "agent").thawed()
	for _, want := range []string{signerAddAccept, signerAddMint} {
		st := r.next()
		r.at(st, want)
		if h := r.wantedBy(r.combiner); h == nil || has(h.Sets.DSSigners, "a") {
			t.Fatalf("at %s the DS set holds it: %+v", want, h)
		}
	}
	for _, state := range []string{KeyStateCreated, KeyStateMpdist} {
		r.keys(state, state)
		if st := r.next(); len(st.Taken) != 2 {
			t.Fatalf("its keys in %s, and the step went on: %+v", state, st)
		}
	}
	// one of the two published: the step is for both
	r.keys(KeyStatePublished, KeyStateMpdist)
	if st := r.next(); len(st.Taken) != 2 {
		t.Fatalf("its ZSK in mpdist, and the step went on: %+v", st)
	}
	r.keys(KeyStatePublished, KeyStatePublished)
	r.at(r.next(), signerAddDS)
	if h := r.wantedBy(r.combiner); h == nil || !has(h.Sets.DSSigners, "a") {
		t.Fatalf("at its DS step the DS set does not name it: %+v", h)
	}
	if r.conf.joinerDSAtParent(r.zone, signerAddSelf); r.syncs == 0 {
		t.Error("under parentsync=agent the leader asked no sync while the parent lacks its DS")
	}
}

// Under parentsync=owner the owner adds the DS, nobody here sends it, and the
// step's test is the same.
func TestASignerAddUnderParentsyncOwnerWaitsForTheOwnersDS(t *testing.T) {
	r := newSignerAddRig(t, "owner.adding.example.", "owner").thawed()
	r.at(r.next(), signerAddAccept)
	r.at(r.next(), signerAddMint)
	r.keys(KeyStatePublished, KeyStatePublished)
	r.at(r.next(), signerAddDS)
	tag := r.keys(KeyStateStandby, KeyStateActive)
	r.parentLooks()
	if st := r.next(); len(st.Taken) != 3 {
		t.Fatalf("the step went on before the owner added the DS: %+v", st)
	}
	if line := r.conf.reconcileLine(r.zone, time.Now()); !strings.Contains(line, "adding signer "+roleA+": step 2 (its DS at the parent)") || !strings.Contains(line, "the parent") {
		t.Errorf("the status says %q", line)
	}
	if r.syncs != 0 {
		t.Errorf("under parentsync=owner the leader asked %d syncs", r.syncs)
	}
	r.parent[tag] = true
	r.parentLooks()
	r.next()
	r.at(r.next(), signerAddCaches)
}

// A signer added (design 5.1, amended): it signs at its keys' step, and the steps
// after it say what has propagated. At its keys' step its signer is handed Signing,
// and the step waits for its keys published and its signer signing. The transition
// is done only after the DS TTL, with its KSK active (T9).
func TestASignerAddSignsAtItsKeysAndIsDoneAfterTheCaches(t *testing.T) {
	r := newSignerAddRig(t, "done.adding.example.", "owner").thawed()
	st := r.next()
	r.at(st, signerAddAccept)
	if h := r.wantedBy(r.signer); h == nil || has(h.Sets.Signing, "a") {
		t.Errorf("at its first step its signer is handed %+v, want no Signing", h)
	}
	st = r.next()
	r.at(st, signerAddMint)
	if h := r.wantedBy(r.signer); h == nil || !has(h.Sets.Signing, "a") {
		t.Errorf("at its keys' step its signer is handed %+v, want Signing", h)
	}
	if st = r.next(); len(st.Taken) != 2 {
		t.Fatalf("the step went on with no keys published: %+v", st)
	}
	r.keys(KeyStatePublished, KeyStatePublished, func(s *KeyInventorySnapshot) { s.Signs = false })
	r.partsTake()
	if st = r.next(); len(st.Taken) != 2 || signerAddHolds(r.conf, r.zone, st) {
		t.Fatalf("the step went on with its signer not signing: %+v", st)
	}
	if line := signerAddStatus(r.conf, r.zone, heldStep{InstrStep: st}, time.Now()); !strings.Contains(line, "signer to start signing") {
		t.Errorf("before its signer signs the status says %q", line)
	}
	r.keys(KeyStatePublished, KeyStatePublished)
	r.at(r.next(), signerAddDS)
	tag := r.keys(KeyStateStandby, KeyStateActive)
	if st = r.next(); len(st.Taken) != 3 {
		t.Fatalf("the DS step went on with the parent serving no DS: %+v", st)
	}
	r.parent[tag] = true
	r.parentLooks()
	r.next() // the look is taken on this turn's wait
	r.at(r.next(), signerAddCaches)
	for range 3 {
		r.at(r.next(), signerAddCaches) // its KSK is standby
	}
	r.keys(KeyStateActive, KeyStateActive)
	st = r.next()
	if st.Taken[len(st.Taken)-1] != lastStepKey {
		t.Fatalf("after the caches' time the step is %+v, want the last", st)
	}
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	if s := r.conf.InternalMp.Instructions.Status(r.zone); s.Phase == PhaseReconciling {
		t.Errorf("not done after the last step: %+v", s)
	}
}

// Another agent holds a joiner's step by its parts alone, and its status adds
// nothing to the leader's view.
func TestOnlyAJoinersOwnAgentWaitsForItsSigner(t *testing.T) {
	r := newSignerAddRig(t, "other.adding.example.", "owner")
	knownAs(t, r.store, r.zone, r.v)
	r.keys(KeyStatePublished, KeyStatePublished, func(s *KeyInventorySnapshot) { s.Signs = false })
	other := InstrStep{Taken: []string{signerAddKey + signerAddMint + " " + roleB}}
	if !signerAddHolds(r.conf, r.zone, other) {
		t.Error("another provider's step waits for this provider's signer")
	}
	if line := signerAddStatus(r.conf, r.zone, heldStep{InstrStep: other}, time.Now()); line != "" {
		t.Errorf("another provider's step, its status says %q", line)
	}
	holdSignerAddStep(t, r.store, r.zone, roleB, signerAddMint, core.HsyncParentSyncOwner)
	if h := r.conf.forOwnSigner(r.zone, &ActingHandover{Zone: r.zone}); h == nil || h.Joining {
		t.Errorf("another provider's keys' step, and this signer is handed %+v", h)
	}
}

// With both roles in one edit the signer's part runs first, and the server's part
// starts once it is over: its keys have propagated and its DS has been served. It
// enters Servers only at the last step (Johan's ruling of 2026-11-03).
func TestBothRolesInOneEditRunTheSignersPartFirst(t *testing.T) {
	from := jAt(t, 41, `servers="b" signers="b" suffix="n"`, freezeRecords...)
	to := jAt(t, 42, `servers="a,b" signers="a,b" suffix="n"`, freezeRecords...)
	if refused := judgeTransition(from, to); len(refused) != 0 {
		t.Fatalf("refused: %+v", refused)
	}
	key := func(part string) string { return signerAddKey + part + " " + canonicalName(roleA) }
	want := []string{key(signerAddAccept), key(signerAddMint), key(signerAddDS), key(signerAddCaches), serverRoleKey + canonicalName(roleA), lastStepKey}
	sets := rolesFor(from, from, 0)
	var got []string
	for _, st := range planSteps(planView{from: from, to: to, held: sets}) {
		if st.sets != nil {
			sets = st.sets(sets)
		}
		got = append(got, st.key)
		if st.key != lastStepKey && has(sets.Servers, "a") {
			t.Errorf("a serves from %s on", st.key)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("the steps are %v, want %v", got, want)
	}
	if !has(sets.Servers, "a") {
		t.Errorf("after the last step the sets are %+v", sets)
	}
}

// An edit that gives the signer its server role after it, A2's order, cannot
// overtake: the transition that names it stays open through its caches' time.
func TestASecondEditWaitsForTheSignersCaches(t *testing.T) {
	r := newSignerAddRig(t, "second.adding.example.", "owner").thawed()
	r.at(r.next(), signerAddAccept)
	r.at(r.next(), signerAddMint)
	r.keys(KeyStatePublished, KeyStatePublished)
	r.at(r.next(), signerAddDS)
	tag := r.keys(KeyStateStandby, KeyStateActive)
	r.parent[tag] = true
	r.parentLooks()
	r.next()
	r.at(r.next(), signerAddCaches)
	w := jAt(t, 43, `servers="a,b,n" signers="a,b" nsmgmt="owner" parentsync="owner" suffix="n"`, freezeRecords...)
	r.store.Note(r.zone, w, nil)
	r.at(r.next(), signerAddCaches)
	if _, ok := r.conf.thawView(r.zone, time.Now()); ok || r.active() != r.v.Serial {
		t.Errorf("43 is agreed during the caches' time: active %d", r.active())
	}
	r.keys(KeyStateActive, KeyStateActive)
	if st := r.next(); st.Taken[len(st.Taken)-1] != lastStepKey {
		t.Fatalf("the step is %+v, want the last", st)
	}
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	if v, ok := r.conf.thawView(r.zone, time.Now()); !ok || v.to != sd(w) {
		t.Errorf("43 is not agreed after done: %+v %v", v, ok)
	}
}

// Its key machine promotes a KSK only past the DS TTL (T9), and a signer handed its
// keys and no Signing starts nothing.
func TestAJoinersKSKGoesActiveOnlyPastTheDSTTL(t *testing.T) {
	// the machine's side of it: a standby KSK with its DS served waits the TTL
	d := newDriverRig(t, "ttl.machine.adding.example.", driverPolicy)
	d.l.SetHold(true)
	d.wire.parentDS[0] = true // the parent serves a DS of another signer's
	d.wire.parentTTL = time.Hour
	d.tick("minted")
	d.clock.Advance(driverPolicy.PropagationDelay + d.wire.ttl + time.Second)
	d.tick("propagated")
	ksks := d.keysIn(KeyStateStandby, "KSK")
	if len(ksks) != 1 {
		t.Fatalf("after propagation the standby KSKs are %v", ksks)
	}
	d.wire.parentDS[ksks[0]] = true
	d.tick("its DS served")
	if s := d.state(ksks[0]); s != KeyStateStandby {
		t.Errorf("its DS just served, its KSK is %s", s)
	}
	d.clock.Advance(time.Hour + time.Second)
	d.tick("the DS TTL passed")
	if s := d.state(ksks[0]); s != KeyStateActive {
		t.Errorf("the DS TTL passed, its KSK is %s, want active", s)
	}

	// and a signer handed its keys and no Signing starts nothing
	const zone = "ttl.signer.adding.example."
	sr := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="p2"`)...)
	h := joinerHandover(t, zone, 6, true)
	h.Sets.Signing = h.Sets.DSSigners
	sr.hand(h, sigUs)
	sr.roleTurn()
	if len(sr.started) != 0 || sr.mpzd.Options[tdns.OptInlineSigning] {
		t.Errorf("handed no Signing it started signing: %v, the option %v", sr.started, sr.mpzd.Options[tdns.OptInlineSigning])
	}
}

// An operator's edit at the joining provider is kept until "done", as every
// provider's is during a transition (design 3.3), and released then.
func TestTheJoinersOperatorEditsAreKeptUntilDone(t *testing.T) {
	r := newSignerAddRig(t, "edits.adding.example.", "owner").thawed()
	r.at(r.next(), signerAddAccept)
	r.edit("ns1.edits.adding.example.")
	if n := len(r.conf.InternalMp.Kept.entries(r.zone, listOwed)); n != 1 {
		t.Fatalf("%d of its edits kept during its first step, want it", n)
	}
	if err := r.store.Done(r.zone); err != nil {
		t.Fatal(err)
	}
	r.conf.instrDone(context.Background(), r.zdr, ZoneName(r.zone))
	if n := len(r.conf.InternalMp.Kept.entries(r.zone, listOwed)); n != 0 {
		t.Errorf("%d of its edits kept after done, want none", n)
	}
}

// A new signer: at its keys' step its signer binds the zone's policy (a zone that
// was not its signer's has none bound), so the key machine takes it and makes its
// first keys, which sign from the start; its start waits for them. Meanwhile the
// zone relays its copy, foreign rows kept, with no restart and with the option off.
func TestANewSignerIsTakenAndMakesItsFirstKeys(t *testing.T) {
	const zone = "taken.adding.signer.example."
	k := testDnskey(t, zone, 257)
	records := append(sigRecords(`serial="5" servers="p2" signers="p2"`), "3600 IN DNSKEY 257 3 15 "+k.PublicKey)
	r := newSignerRig(t, zone, records...)
	bound := 0
	prev := bindWithoutSigning
	bindWithoutSigning = func(zd *tdns.ZoneData) error {
		bound++
		zd.DnssecPolicy = &tdns.DnssecPolicy{Mode: tdns.DnssecPolicyModeKSKZSK, KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519}
		return nil
	}
	t.Cleanup(func() { bindWithoutSigning = prev })
	r.mpzd.Lock()
	r.mpzd.DnssecPolicy = nil
	r.mpzd.Unlock()
	r.owner = NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return r.kdb })
	r.e = NewKeyLifecycleEngine(r.conf, r.owner)
	r.e.wire.push = func(*Config, string, []uint16) {}
	r.conf.InternalMp.KeyLifecycle, r.conf.InternalMp.KeyLifecycleOwner = r.e, r.owner
	r.conf.MpConfig().KeyLifecycleZones = []string{zone}

	r.e.TakeConfiguredZones()
	if r.owner.taken(zone) {
		t.Fatal("taken with no policy bound")
	}
	r.startErr = tdns.ErrKeyGenerationDeferred // an owned zone with no keys yet
	r.hand(joinerHandover(t, zone, 6, true), sigUs)
	r.roleTurn()
	if bound != 1 || !r.owner.taken(zone) {
		t.Fatalf("the policy bound %d times, the zone taken %v: want bound once and taken", bound, r.owner.taken(zone))
	}
	if r.mpzd.Options[tdns.OptInlineSigning] || len(r.started) != 1 {
		t.Errorf("with no keys yet: the option %v, started %v, want one start refused", r.mpzd.Options[tdns.OptInlineSigning], r.started)
	}
	if !slices.Contains(r.foreignRows(t), k.KeyTag()) {
		t.Errorf("the other signer's key is not kept: %v", r.foreignRows(t))
	}
	if !r.e.wire.SignsAtNaming(zone) {
		t.Error("named, and serving nothing: it does not sign at its naming")
	}
	r.e.tickOwned()
	if keys := joinersKeys(t, r, zone); keys["KSK"] != 1 || keys["ZSK"] != 1 {
		t.Errorf("its first keys: %v", keys)
	}
	inv, err := tdns.GetKeyInventory(r.kdb, zone)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range inv {
		if it.State != DnskeyStateForeign && (!it.Sign || it.State == KeyStateActive) {
			t.Errorf("its first key %d is %s, sign %v: want it on its way, signing", it.KeyTag, it.State, it.Sign)
		}
	}
	r.startErr = nil
	r.roleTurn()
	if !r.mpzd.Options[tdns.OptInlineSigning] {
		t.Error("its first keys are there, and it does not sign")
	}
	if bound != 1 {
		t.Errorf("the policy bound again: %d times", bound)
	}
}

// A hand-over brings a withheld zone to its role, and a tick tries again what
// could not be done yet. It is not gated on Ready: a withheld zone is never Ready
// until it acts.
func TestAHandOverBringsAWithheldZoneToItsRole(t *testing.T) {
	withheld := func(t *testing.T, zone string) *signerRig {
		t.Helper()
		records := sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)
		r := newSignerRig(t, zone, records...)
		r.firstLoad(t, records...)
		if !r.mpzd.Withheld() || r.mpzd.Ready {
			t.Fatalf("withheld %v, Ready %v after a first load with nothing handed", r.mpzd.Withheld(), r.mpzd.Ready)
		}
		return r
	}
	t.Run("no role", func(t *testing.T) {
		r := withheld(t, "norole.withheld.signer.example.")
		r.hand(handoverFor(t, r.mpzd.ZoneName, sigRecords(`serial="6" servers="us,p2" signers="p2"`)...), sigUs)
		r.roleTurn()
		if r.mpzd.Withheld() || !r.mpzd.Ready || len(r.started) != 0 {
			t.Errorf("withheld %v, Ready %v, started %v: want it relaying its copy", r.mpzd.Withheld(), r.mpzd.Ready, r.started)
		}
	})
	t.Run("signing", func(t *testing.T) {
		r := withheld(t, "signing.withheld.signer.example.")
		r.hand(handoverFor(t, r.mpzd.ZoneName, sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)...), sigUs)
		r.roleTurn()
		if len(r.started) != 1 || r.mpzd.Withheld() {
			t.Errorf("started %v, withheld %v: want it signing", r.started, r.mpzd.Withheld())
		}
		if d := r.mpzd.MP.MPdata; d == nil || !d.WeAreSigner {
			t.Errorf("its data is %+v, not that of a signer", d)
		}
		before := r.pushes()
		r.roleTurn()
		if len(r.started) != 1 || r.pushes() != before {
			t.Errorf("signing, and a tick started it again: %v, %d pushes", r.started, r.pushes()-before)
		}
	})
	t.Run("tried again", func(t *testing.T) {
		r := withheld(t, "again.withheld.signer.example.")
		r.startErr = tdns.ErrKeyGenerationDeferred
		h := handoverFor(t, r.mpzd.ZoneName, sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)...)
		r.hand(h, sigUs)
		r.roleTurn()
		if !r.mpzd.Withheld() {
			t.Error("a start told to wait released the zone: it would serve its unsigned copy")
		}
		r.startErr = tdns.ErrSigningHeld
		r.roleTurn()
		if !r.mpzd.Withheld() {
			t.Error("a start held released the zone")
		}
		r.startErr = errors.New("a keystore in trouble")
		r.roleTurn()
		if !r.mpzd.Withheld() {
			t.Error("a start that failed released the zone")
		}
		before := r.pushes()
		r.startErr = nil
		r.roleTurn()
		if r.mpzd.Withheld() || len(r.started) != 4 || r.pushes() != before+1 {
			t.Errorf("withheld %v, started %v, %d pushes: want it signing on the fourth, and saying so", r.mpzd.Withheld(), r.started, r.pushes()-before)
		}
	})
	t.Run("not loaded", func(t *testing.T) {
		const zone = "unloaded.withheld.signer.example."
		r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
		r.hand(handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)...), sigUs)
		pushes := r.pushes()
		// its first load has not published yet: that load reads what is held
		fresh := &tdns.ZoneData{ZoneName: zone, ZoneStore: tdns.MapZone, ZoneType: tdns.Primary, Logger: r.mpzd.Logger,
			Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}, KeyDB: r.kdb}
		tdns.Zones.Set(zone, fresh)
		Zones.Invalidate(zone)
		r.roleTurn()
		// and a zone no longer here has nothing to act on
		tdns.Zones.Remove(zone)
		Zones.Invalidate(zone)
		r.roleTurn()
		if len(r.started) != 0 || r.pushes() != pushes || fresh.DnssecPolicy != nil {
			t.Errorf("a zone not loaded: started %v, %d pushes, its policy %v; want nothing done", r.started, r.pushes()-pushes, fresh.DnssecPolicy)
		}
	})
}

// Waiting, a running zone's signer takes nothing on from a refresh. Handed
// Signing, it is StartSigning alone that switches the option on: with the option
// on and no policy bound, the next publish goes out unsigned over what it served.
func TestARefreshDoesNotSwitchARunningZoneOnBeforeStartSigningHas(t *testing.T) {
	const zone = "refresh.switch.signer.example."
	records := sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)
	r := newSignerRig(t, zone, records...)
	r.mpzd.Lock()
	r.mpzd.DnssecPolicy = nil
	r.mpzd.Unlock()
	r.startErr = tdns.ErrSigningHeld
	r.hand(handoverFor(t, zone, records...), sigUs)
	r.roleTurn()
	incoming := incomingCopy(t, zone, records...)
	r.mpzd.MPPreRefresh(incoming, nil, nil, r.conf.MpConfig())
	if r.mpzd.Options[tdns.OptInlineSigning] || incoming.Options[tdns.OptInlineSigning] {
		t.Errorf("before StartSigning the option is on: served %v, incoming %v", r.mpzd.Options[tdns.OptInlineSigning], incoming.Options[tdns.OptInlineSigning])
	}
	// at a first load the option is on, as the first load binds and signs
	r.mpzd.Lock()
	r.mpzd.Ready = false
	r.mpzd.Unlock()
	if r.mpzd.HasPublishedData() {
		zd := r.mpzd.ZoneData
		fresh := &tdns.ZoneData{ZoneName: zd.ZoneName, ZoneStore: zd.ZoneStore, ZoneType: zd.ZoneType, Logger: zd.Logger,
			Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}, KeyDB: zd.KeyDB}
		tdns.Zones.Set(zone, fresh)
		Zones.Invalidate(zone)
		m, _ := Zones.Get(zone)
		m.EnsureMP()
		m.MP.MPdata = &MPdata{Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}}
		first := incomingCopy(t, zone, records...)
		m.MPPreRefresh(first, nil, nil, r.conf.MpConfig())
		if !first.Options[tdns.OptInlineSigning] {
			t.Error("a first load handed Signing does not switch the option on: nothing would bind its policy")
		}
	}
}

// The agent takes the zone from its signer: one with no copy can hand its signer
// nothing while its signer withholds it, which would be a wait with no end. It says
// so; the signer acts by its own copy; the agent loads, and its hand-over then
// takes over. An agent with a copy says nothing: its signer waits for it.
func TestAnAgentWithNoCopySaysSoAndItsSignerActsByItsOwnCopy(t *testing.T) {
	// the agent
	const azone = "nocopy.agent.adding.example."
	fr := newFreezeRig(t, azone)
	q := fr.withSigner()
	noCopyWords := func(wait time.Duration) int {
		n := 0
		for end := time.Now().Add(wait); ; time.Sleep(time.Millisecond) {
			for _, m := range q.take() {
				if m.update.Acting != nil && m.update.Acting.NoCopy {
					n++
				}
			}
			if n > 0 || time.Now().After(end) {
				return n
			}
		}
	}
	amp, _ := Zones.Get(azone)
	if amp.HasPublishedData() {
		// what its first load has not done yet
		tdns.Zones.Remove(azone)
		Zones.Invalidate(azone)
		tdns.Zones.Set(azone, &tdns.ZoneData{ZoneName: azone, ZoneStore: amp.ZoneStore, ZoneType: amp.ZoneType, Logger: amp.Logger,
			Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}})
		amp, _ = Zones.Get(azone)
		amp.EnsureMP()
	}
	withCopy := signerZoneWith(t, "copy.nocopy.agent.adding.example.", newMPTestKeyDB(t))
	fr.conf.noteKeyInventory(context.Background(), amp, &KeystateInventoryMsg{SenderID: "signer", Zone: azone, Inventory: []KeyInventoryItem{}})
	if n := noCopyWords(20 * time.Millisecond); n != 0 {
		t.Errorf("its signer does not withhold the zone, and it said it has no copy %d times", n)
	}
	fr.conf.noteKeyInventory(context.Background(), amp, &KeystateInventoryMsg{SenderID: "signer", Zone: azone, Withheld: true})
	if n := noCopyWords(5 * time.Second); n != 1 {
		t.Errorf("no copy, and it said so %d times", n)
	}
	fr.conf.noteKeyInventory(context.Background(), withCopy, &KeystateInventoryMsg{SenderID: "signer", Zone: withCopy.ZoneName, Withheld: true})
	if n := noCopyWords(20 * time.Millisecond); n != 0 {
		t.Errorf("with a copy it said it has none %d times", n)
	}

	// its signer
	const zone = "nocopy.signer.adding.example."
	records := sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)
	r := newSignerRig(t, zone, records...)
	r.firstLoad(t, records...)
	r.roleTurn()
	if len(r.started) != 0 || !r.mpzd.Withheld() {
		t.Fatalf("handed nothing, and no word from its agent: started %v, withheld %v", r.started, r.mpzd.Withheld())
	}
	r.hand(&ActingHandover{Zone: zone, Phase: PhaseSteady, NoCopy: true, Made: time.Now()}, sigUs)
	if _, handed := actingHeld.Load().get(zone); handed {
		t.Error("the signer keeps the agent's word as a hand-over")
	}
	r.roleTurn()
	if d := r.mpzd.MP.MPdata; d == nil || !d.WeAreSigner || len(r.started) != 1 || r.mpzd.Withheld() {
		t.Errorf("its agent has no copy: its data %+v, started %v, withheld %v; want it signing by its copy", d, r.started, r.mpzd.Withheld())
	}
	// a hand-over takes over, and says otherwise
	h := handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="p2"`)...)
	r.hand(h, sigUs)
	if _, handed := actingHeld.Load().get(zone); !handed {
		t.Fatal("its agent's hand-over is not held")
	}
	if d := r.mpzd.MP.MPdata; d == nil || d.WeAreSigner {
		t.Errorf("after its agent's hand-over of %+v it acts by %+v", h.Sets, d)
	}

	// a no-role provider relays
	const relay = "relay.nocopy.signer.adding.example."
	noRole := sigRecords(`serial="5" servers="us,p2" signers="p2"`)
	rr := newSignerRig(t, relay, noRole...)
	rr.firstLoad(t, noRole...)
	rr.hand(&ActingHandover{Zone: relay, Phase: PhaseSteady, NoCopy: true, Made: time.Now()}, sigUs)
	rr.roleTurn()
	if rr.mpzd.Withheld() || !rr.mpzd.Ready || len(rr.started) != 0 {
		t.Errorf("no role by its copy: withheld %v, Ready %v, started %v", rr.mpzd.Withheld(), rr.mpzd.Ready, rr.started)
	}
}

// A withheld zone's inventory says so, and a provider whose keys are published is
// no "not signing": its keys are distributed and its agent reads them, while its
// signatures are told apart.
func TestTheInventoryTellsAKeySignerAndAWithheldZone(t *testing.T) {
	const zone = "marks.adding.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="p2"`)...)
	r.mpzd.SetRuntimeOption(tdns.OptInlineSigning, false)
	r.hand(joinerHandover(t, zone, 6, true), sigUs)
	m := r.conf.inventoryMarksOf(zone, nil)
	if m.notSigning || m.signs || m.withheld {
		t.Errorf("in KeySigners, not signing yet, the marks are %+v", m)
	}
	r.hand(handoverFor(t, zone, sigRecords(`serial="7" servers="us,p2" signers="us,p2"`)...), sigUs)
	r.roleTurn()
	if m := r.conf.inventoryMarksOf(zone, nil); m.notSigning || !m.signs {
		t.Errorf("signing, the marks are %+v", m)
	}
	noRole := sigRecords(`serial="5" servers="us,p2" signers="p2"`)
	const w = "withheld.marks.adding.signer.example."
	o := newSignerRig(t, w, noRole...)
	o.firstLoad(t, noRole...)
	if m := o.conf.inventoryMarksOf(w, nil); !m.notSigning || !m.withheld {
		t.Errorf("withheld with no role, the marks are %+v", m)
	}
}

// The combiner of a provider on its way in applies the other signers' DNSKEYs,
// which is where its signer finds them while its upstream is its combiner, and
// nothing else of a zone it does not sign yet.
func TestTheCombinerOfAProviderOnItsWayInAppliesDNSKEYsAlone(t *testing.T) {
	p := editPolicy{ZoneSigned: true, WeHoldKeys: true, NSmgmt: core.HsyncNSmgmtAGENT, ParentSync: core.HsyncParentSyncAgent}
	if !p.canApply(dns.TypeDNSKEY) {
		t.Error("a provider in KeySigners does not apply the other signers' DNSKEYs")
	}
	for _, rrtype := range []uint16{dns.TypeNS, dns.TypeCDS, dns.TypeCSYNC, dns.TypeKEY} {
		if p.canApply(rrtype) {
			t.Errorf("a provider in KeySigners applies %s", dns.TypeToString[rrtype])
		}
	}
	p.WeHoldKeys = false
	if p.canApply(dns.TypeDNSKEY) {
		t.Error("a server that is no signer applies a DNSKEY")
	}
}

// With nobody else signing there are no signatures to go with a DS: the zone's
// first signer has its caches' time before its DS goes to the parent, or the
// parent's DS would make the zone bogus. Anyone after it joins as usual.
func TestAZonesFirstSignerHasItsCachesTimeBeforeItsDS(t *testing.T) {
	from := jAt(t, 41, `servers="a,b" suffix="n"`, freezeRecords...)
	to := jAt(t, 42, `servers="a,b" signers="a" suffix="n"`, freezeRecords...)
	var parts []string
	for _, st := range signerAddSteps(planView{from: from, to: to, held: rolesFor(from, from, 0)}) {
		_, part, _ := signerAddKeyParts(st.key)
		parts = append(parts, part)
	}
	want := []string{signerAddAccept, signerAddMint, signerAddCaches, signerAddDS}
	if !slices.Equal(parts, want) {
		t.Errorf("the first signer's steps are %v, want %v", parts, want)
	}
	// planned from what is in place, with it in Signing from its keys' step, its
	// caches' time and its DS are still the steps left, in that order
	sets := rolesFor(from, from, 0)
	var taken []string
	for _, st := range signerAddSteps(planView{from: from, to: to, held: sets}) {
		if st.sets != nil {
			sets = st.sets(sets)
		}
		taken = append(taken, st.key)
		if strings.Contains(st.key, signerAddMint) {
			break
		}
	}
	plan := planSteps(planView{from: from, to: to, held: sets, taken: taken})
	left := slices.DeleteFunc(slices.Clone(plan), func(st plannedStep) bool { return slices.Contains(taken, st.key) })
	if len(left) != 3 || !strings.Contains(left[0].key, signerAddCaches) || !strings.Contains(left[1].key, signerAddDS) || left[2].key != lastStepKey {
		t.Errorf("after it signs the steps left are %+v, want its caches' time, its DS and the last", left)
	}
}

// Each of a signer's steps stays in the plan, by its key, however far it has come,
// and a provider that signs under the sets held has none.
func TestASignersStepsArePlannedFromWhatIsInPlace(t *testing.T) {
	from := jAt(t, 41, `servers="a,b" signers="b" suffix="n"`, freezeRecords...)
	to := jAt(t, 42, `servers="a,b" signers="a,b" suffix="n"`, freezeRecords...)
	sets := rolesFor(from, from, 0)
	steps := signerAddSteps(planView{from: from, to: to, held: sets})
	if len(steps) != 4 {
		t.Fatalf("the steps of one joiner: %+v", steps)
	}
	var taken []string
	for i, st := range steps {
		if st.sets != nil {
			sets = st.sets(sets)
		}
		taken = append(taken, st.key)
		again := signerAddSteps(planView{from: from, to: to, held: sets, taken: taken})
		if len(again) != 4 || again[i].key != st.key {
			t.Fatalf("after %s the steps are %+v", st.key, again)
		}
	}
	if !has(sets.Signing, "a") || !has(sets.KeySigners, "a") || !has(sets.DSSigners, "a") || !has(sets.KeyConfirmers, "a") {
		t.Errorf("after its steps the sets are %+v", sets)
	}
	if got := signerAddSteps(planView{from: to, to: to, held: rolesFor(to, to, 0)}); len(got) != 0 {
		t.Errorf("at rest it has steps: %+v", got)
	}
}

// A DS counts only once every parent server that answers holds it: a validator
// may be handed the RRset of any of them, and one without the joiner's DS finds
// nothing to validate its signatures with. One that does not answer hands nothing
// to anyone. The largest TTL any of them gave is what caches may hold.
func TestTheDSStepAsksEveryParentServer(t *testing.T) {
	ds := func(tag uint16, ttl uint32) dns.RR {
		return &dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: ttl}, KeyTag: tag}
	}
	boom := errors.New("no answer")
	for _, c := range []struct {
		name    string
		answers map[string][]dns.RR
		fails   []string
		want    []uint16
		ttl     time.Duration
		err     bool
	}{
		{name: "both have it", answers: map[string][]dns.RR{"p1": {ds(1, 60), ds(2, 60)}, "p2": {ds(1, 90), ds(2, 90)}}, want: []uint16{1, 2}, ttl: 90 * time.Second},
		{name: "the second lags", answers: map[string][]dns.RR{"p1": {ds(1, 60), ds(2, 60)}, "p2": {ds(1, 60)}}, want: []uint16{1}, ttl: time.Minute},
		{name: "the first lags", answers: map[string][]dns.RR{"p1": {ds(1, 60)}, "p2": {ds(1, 60), ds(2, 60)}}, want: []uint16{1}, ttl: time.Minute},
		{name: "one serves no DS", answers: map[string][]dns.RR{"p1": {ds(1, 60)}, "p2": {}}, ttl: time.Minute},
		{name: "one does not answer", answers: map[string][]dns.RR{"p1": {ds(1, 60)}}, fails: []string{"p2"}, want: []uint16{1}, ttl: time.Minute},
		{name: "none answers", fails: []string{"p1", "p2"}, err: true},
		{name: "no server is known", err: true},
	} {
		var servers []string
		for _, s := range []string{"p1", "p2"} {
			if _, ok := c.answers[s]; ok || slices.Contains(c.fails, s) {
				servers = append(servers, s)
			}
		}
		seen, err := dsAtEveryServer(servers, func(server string) ([]dns.RR, error) {
			if slices.Contains(c.fails, server) {
				return nil, boom
			}
			return c.answers[server], nil
		})
		if (err != nil) != c.err {
			t.Errorf("%s: %v, want an error %v", c.name, err, c.err)
			continue
		}
		var tags []uint16
		for tag := range seen.tags {
			tags = append(tags, tag)
		}
		slices.Sort(tags)
		if !slices.Equal(tags, c.want) || seen.ttl != c.ttl {
			t.Errorf("%s: the tags %v, TTL %s; want %v, %s", c.name, tags, seen.ttl, c.want, c.ttl)
		}
	}
}

// T9 asks one parent server, so its wait can start before the last of them has
// the DS: step 3 also waits the DS TTL from when every server served it, the DS
// step's end, or a cache may still hold a DS RRset without it.
func TestTheCachesTimeCountsFromWhenEveryParentServerServesTheDS(t *testing.T) {
	r := newSignerAddRig(t, "ttl.parent.adding.example.", "owner").thawed()
	serving(t, soa(t, r.zone, 5, nil, nil), nil)
	r.at(r.next(), signerAddAccept)
	r.at(r.next(), signerAddMint)
	r.keys(KeyStatePublished, KeyStatePublished)
	r.at(r.next(), signerAddDS)
	tag := r.keys(KeyStateStandby, KeyStateActive)
	r.parent[tag], r.parentTTL = true, time.Hour
	r.parentLooks()
	r.next()
	r.keys(KeyStateActive, KeyStateActive)
	st := r.next()
	r.at(st, signerAddCaches)
	if line := r.conf.reconcileLine(r.zone, time.Now()); !strings.Contains(line, "the DS TTL at the parent") {
		t.Errorf("its keys active, the DS TTL not passed: the status says %q", line)
	}
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.StepAt = time.Now().Add(-time.Hour - time.Second)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if st := r.next(); st.Taken[len(st.Taken)-1] != lastStepKey {
		t.Errorf("the DS TTL passed, the step is %+v, want the last", st)
	}
}

// A hand-over that takes Signing back while a start runs, which holds no lock of
// ours, was acted by before the start switched inline-signing on: it stands.
func TestAHandOverTakenWhileTheZoneStartsSigningStands(t *testing.T) {
	const zone = "meanwhile.withheld.signer.example."
	records := sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)
	r := newSignerRig(t, zone, records...)
	r.mpzd.SetRuntimeOption(tdns.OptInlineSigning, false)
	r.hand(handoverFor(t, zone, records...), sigUs)
	r.onStart = func() {
		r.hand(handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="p2"`)...), sigUs)
	}
	r.roleTurn()
	if len(r.started) != 1 {
		t.Fatalf("started %v, want it started once", r.started)
	}
	if r.mpzd.Options[tdns.OptInlineSigning] {
		t.Error("the zone signs, though the hand-over taken meanwhile has it not")
	}
	if d := r.mpzd.MP.MPdata; d == nil || d.WeAreSigner {
		t.Errorf("it acts by %+v, want the hand-over's no role", d)
	}
}

// The turn reads the zone's options under its lock, as a hand-over and a refresh
// set them.
func TestTheRoleTurnReadsTheOptionsUnderTheZonesLock(t *testing.T) {
	const zone = "options.withheld.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="p2"`)...)
	r.hand(handoverFor(t, zone, sigRecords(`serial="5" servers="us,p2" signers="p2"`)...), sigUs)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for on := true; ; on = !on {
			select {
			case <-stop:
				return
			default:
				r.mpzd.SetRuntimeOption(OptMPDisallowEdits, on)
			}
		}
	}()
	for range 200 {
		r.roleTurn()
	}
	close(stop)
	<-done
}

// A withheld zone reports at every round, whatever its copy says by now: only its
// agent's word ends the withholding, and that answers a report. So the agent's
// word that it has no copy goes again if it was lost. Another zone reports once,
// and again only while it waits.
func TestAWithheldZoneReportsAtEveryRound(t *testing.T) {
	const zone = "rounds.withheld.signer.example."
	records := sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)
	r := newSignerRig(t, zone, records...)
	r.firstLoad(t, records...)
	r.conf.InternalMp.MPZoneNames = []string{zone}
	reported := map[string]bool{}
	for round := 1; round <= 3; round++ {
		r.conf.signerStartReport(reported)
		if r.pushes() != round {
			t.Fatalf("at round %d, %d reports", round, r.pushes())
		}
	}

	// a copy with no reading does not wait for its agent, and is no reason to stop
	// while it is withheld
	const none = "noreading.rounds.withheld.signer.example."
	o := newSignerRig(t, none, sigRecords(`servers="us,p2" signers="us,p2"`)...)
	o.conf.InternalMp.MPZoneNames = []string{none}
	o.mpzd.Lock()
	o.mpzd.Ready = false
	o.mpzd.Unlock()
	if err := o.mpzd.Withhold(); err != nil {
		t.Fatal(err)
	}
	reported = map[string]bool{}
	for round := 1; round <= 3; round++ {
		o.conf.signerStartReport(reported)
		if o.pushes() != round {
			t.Fatalf("withheld with no reading, at round %d, %d reports", round, o.pushes())
		}
	}
	o.mpzd.ReleaseWithheld()
	o.mpzd.Lock()
	o.mpzd.Ready = true
	o.mpzd.Unlock()
	o.conf.signerStartReport(reported)
	if o.pushes() != 3 {
		t.Errorf("no longer withheld, nothing to wait for: %d reports, want no more", o.pushes())
	}
}

// The first signer's keys go out though the zone is not signed yet: the step that
// names it recomputes its data at once (onSetsChanged), so its inventory finds it
// holding keys, and the step's wait can see them at the other agents.
func TestAFirstSignersKeysAreDistributedAtItsFirstStep(t *testing.T) {
	r := newSignerAddRig(t, "first.adding.example.", "owner")
	r.n = jAt(t, 41, `servers="a,b" nsmgmt="owner" suffix="n"`, freezeRecords...)
	knownAs(t, r.store, r.zone, r.n)
	r.v = jAt(t, 42, `servers="a,b" signers="a" nsmgmt="owner" suffix="n"`, freezeRecords...)
	r.thawed()
	r.at(r.next(), signerAddAccept)
	mpzd, _ := Zones.Get(r.zone)
	mpzd.Lock()
	d := *mpzd.MP.MPdata
	mpzd.Unlock()
	if !d.WeHoldKeys || d.ZoneSigned {
		t.Fatalf("at its first step its data is %+v, want keys held and the zone not signed yet", d)
	}
	r.keys(KeyStateMpdist, KeyStateMpdist)
	changed, ds, err := mpzd.LocalDnskeysFromKeystate(AgentId(roleA), nil)
	if err != nil || !changed || ds == nil || len(ds.LocalAdds) != 2 {
		t.Errorf("its inventory distributes %+v (changed %v, %v), want its two keys", ds, changed, err)
	}
}

// With a provider on its way in, its combiner serves the other signers' DNSKEYs,
// and every other type as its upstream has it: a combine, and a cleanup of a
// contribution that went, change nothing else in what its signer will relay.
func TestAJoinersCombinerServesTheOtherSignersKeysAndTheUpstreamsRest(t *testing.T) {
	const zone = "combine.adding.example."
	_, mpzd := actingCombiner(t, zone, `3600 IN HSYNC3 ON alpha `+actUs+` .`, `3600 IN HSYNCPARAM serial="5" servers="alpha" signers="beta"`)
	upstreamNS := mpzd.ZoneData
	before, err := upstreamNS.GetRRset(zone, dns.TypeNS)
	if err != nil || before == nil {
		t.Fatalf("no NS at the start: %v", err)
	}
	mpzd.Lock()
	mpzd.MP.MPdata = &MPdata{OurLabel: "alpha", ZoneSigned: true, WeHoldKeys: true, Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}}
	mpzd.Unlock()
	key := testDnskey(t, zone, 257)
	ns, err := dns.NewRR(zone + " 3600 IN NS ns.contributed.example.")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mpzd.AddCombinerData("agent.beta.example.", map[string][]core.RRset{zone: {
		{Name: zone, RRtype: dns.TypeDNSKEY, Class: dns.ClassINET, RRs: []dns.RR{key}},
		{Name: zone, RRtype: dns.TypeNS, Class: dns.ClassINET, RRs: []dns.RR{ns}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := mpzd.CombineWithLocalChanges(); err != nil {
		t.Fatal(err)
	}
	dnskeys, err := mpzd.GetRRset(zone, dns.TypeDNSKEY)
	if err != nil || dnskeys == nil || !slices.ContainsFunc(dnskeys.RRs, func(rr dns.RR) bool { return dns.IsDuplicate(rr, key) }) {
		t.Errorf("the other signer's key is not served: %+v (%v)", dnskeys, err)
	}
	after, err := mpzd.GetRRset(zone, dns.TypeNS)
	if err != nil || after == nil || !rrsetEqual(*after, *before) {
		t.Errorf("the combine changed the NS RRset: %+v, was %+v (%v)", after, before, err)
	}
	// the contribution of NS goes; its cleanup serves the upstream's, as it was
	mpzd.MP.CombinerData.Remove(zone)
	mpzd.MP.noteCleanup(zone, dns.TypeNS)
	if _, err := mpzd.CombineWithLocalChanges(); err != nil {
		t.Fatal(err)
	}
	if again, err := mpzd.GetRRset(zone, dns.TypeNS); err != nil || again == nil || !rrsetEqual(*again, *before) {
		t.Errorf("the cleanup changed the NS RRset: %+v, was %+v (%v)", again, before, err)
	}
}

// What one parent server's answer is, over the wire: NODATA and NXDOMAIN hold no
// DS, so one that gives either keeps the joiner's DS from counting; a server that
// refuses has given no answer, and doesn't.
func TestAParentServersAnswerWithNoDSCountsAgainstTheDS(t *testing.T) {
	const zone = "answers.adding.example."
	server := func(answer func(m *dns.Msg)) string {
		t.Helper()
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(q)
			answer(m)
			_ = w.WriteMsg(m)
		})}
		go func() { _ = srv.ActivateAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
		return pc.LocalAddr().String()
	}
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: "adding.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns: "ns.adding.example.", Mbox: "hostmaster.adding.example.", Serial: 1, Refresh: 7200, Retry: 1800, Expire: 604800, Minttl: 60}
	holds := server(func(m *dns.Msg) {
		m.Answer = []dns.RR{&dns.DS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 60}, KeyTag: 7, Algorithm: dns.ED25519, DigestType: dns.SHA256, Digest: "00"}}
	})
	nodata := server(func(m *dns.Msg) { m.Ns = []dns.RR{soa} })
	nxdomain := server(func(m *dns.Msg) { m.Rcode, m.Ns = dns.RcodeNameError, []dns.RR{soa} })
	refused := server(func(m *dns.Msg) { m.Rcode = dns.RcodeRefused })
	for _, c := range []struct {
		name    string
		servers []string
		tagged  bool
	}{
		{"the one that holds it", []string{holds}, true},
		{"NODATA beside it", []string{holds, nodata}, false},
		{"NODATA before it", []string{nodata, holds}, false},
		{"NXDOMAIN beside it", []string{holds, nxdomain}, false},
		{"a refusal beside it", []string{holds, refused}, true},
	} {
		seen, err := dsAtEveryServer(c.servers, func(s string) ([]dns.RR, error) { return askParentDS(zone, s) })
		if err != nil || seen.tags[7] != c.tagged {
			t.Errorf("%s: the tags %v (%v), want the DS counted %v", c.name, seen.tags, err, c.tagged)
		}
	}
	if _, err := dsAtEveryServer([]string{refused}, func(s string) ([]dns.RR, error) { return askParentDS(zone, s) }); err == nil {
		t.Error("a server that refuses, and no other: nothing should be known")
	}
}

// joinerKeysPublished is a joiner's signer, with its copy holding records, at the
// moment its first keys are published: every other signer has applied them. It
// answers on the machine's clock, and its looks run in place.
func joinerKeysPublished(t *testing.T, zone string, records []string) (*signerRig, *fakeClock) {
	t.Helper()
	r := newSignerRig(t, zone, records...)
	r.conf.InternalMp.servedKeys.start = func(look func()) { look() }
	r.hand(joinerHandover(t, zone, 6, true), sigUs)
	r.e.tickOwned()
	clk := &fakeClock{t: time.Now()}
	r.e.driver(zone).Clock = clk
	inv, err := tdns.GetKeyInventory(r.kdb, zone)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range inv {
		if it.State != DnskeyStateForeign && !r.e.Signal(zone, it.KeyTag, "propagated", "", clk.Now()) {
			t.Fatalf("key %d: the signal is not taken", it.KeyTag)
		}
	}
	r.e.tickOwned()
	if n := ownKeysIn(t, r, zone, KeyStatePublished); n != 2 {
		t.Fatalf("%d of its keys are published, want its KSK and ZSK", n)
	}
	return r, clk
}

// ownKeysIn counts the zone's own keys in state.
func ownKeysIn(t *testing.T, r *signerRig, zone, state string) int {
	t.Helper()
	inv, err := tdns.GetKeyInventory(r.kdb, zone)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, it := range inv {
		if it.State == state {
			n++
		}
	}
	return n
}

// servedKeyTTLs has each nameserver named answer with the zone's DNSKEY RRset at
// its TTL; any other does not answer.
func servedKeyTTLs(t *testing.T, zone string, ttls map[string]time.Duration) {
	t.Helper()
	k := testDnskey(t, zone, 256)
	prev := servingKeysLookup
	servingKeysLookup = func(_ context.Context, _ string, ns string) (*core.RRset, error) {
		ttl, ok := ttls[ns]
		if !ok {
			return nil, errors.New("no answer")
		}
		key := *k
		key.Hdr.Ttl = uint32(ttl / time.Second)
		return &core.RRset{RRs: []dns.RR{&key}}, nil
	}
	t.Cleanup(func() { servingKeysLookup = prev })
}

// holdSignerAddStep has the store hold a joiner's step part, with the sets' parent
// sync.
func holdSignerAddStep(t *testing.T, s *InstructionStore, zone, id, part string, parentSync uint8) {
	t.Helper()
	raw, err := json.Marshal(Roles{ParentSync: parentSync})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.update(zone, func(z *zoneSerials) error {
		z.Step, z.StepOf, z.Sets, z.Taken = 3, 6, raw, []string{signerAddKey + part + " " + canonicalName(id)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The leader's sync is what adds a joiner's DS, and it waits for the zone's key
// before the freeze looks at it. A leader whose key the freeze kept from being
// published would wait for the step, and the step for it. It ends with the step:
// the step's ask lets the key out, its poll ends, the sync goes, and the step
// finishes. The two ways in: a key never polled here, and one on record as trusted,
// as a key taken from the signer before it.
func TestAJoinersDSStepFinishesThroughALeaderWhoseKeyIsNotPublished(t *testing.T) {
	for name, state := range map[string]uint8{
		"never polled here": edns0.KeyStateUnknown,
		"trusted on record": edns0.KeyStateTrusted,
	} {
		t.Run(name, func(t *testing.T) {
			r := newKeyHoldRigFor(t, "elected.adding.signer.example.", true)
			r.notifyRig.us.Bridge.combinerID = rigCombiner
			tdns.UpdateParentState(r.mpzd.KeyDB, string(r.zone), r.key.keyid, state)
			r.parent.holdsDS() // the parent has no DS for it yet: the sync's cause is the DS set
			freezeServed(t, r.conf, r.mpzd)
			if err := r.conf.leaderKeySetup(r.ctx, r.zone, true); !errors.Is(err, errHeldDuringTransition) {
				t.Fatalf("the set-up during the freeze: %v\n%s", err, r.log)
			}
			if _, why := r.conf.keyHold(r.ctx, r.zone); why != "not published" {
				t.Fatalf("the hold after the set-up: %q", why)
			}

			zone, id := string(r.zone), r.conf.MpConfig().Identity
			holdSignerAddStep(t, r.conf.InternalMp.Instructions, zone, id, signerAddDS, core.HsyncParentSyncAgent)
			adds := &r.conf.InternalMp.signerAdds
			adds.start = func(look func()) { look() }
			prev := parentDSLook
			parentDSLook = func(*Config, string) (parentDSSeen, error) {
				return parentDSSeen{tags: map[uint16]bool{r.ksk.KeyTag: r.parent.updatesSeen() > 0}}, nil
			}
			t.Cleanup(func() { parentDSLook = prev })
			r.inventory(r.ksk)

			if r.conf.joinerDSAtParent(zone, id) {
				t.Fatal("the step is over before the parent has seen anything")
			}
			time.Sleep(200 * time.Millisecond)
			if n := r.parent.updatesSeen(); n != 0 {
				t.Fatalf("%d UPDATEs reached the parent with the key not published", n)
			}
			if !r.conf.wantsZoneKey(r.ctx, r.zone) {
				t.Fatal("the key rounds do not look at a key not published")
			}
			r.conf.decideZoneKey(r.ctx, r.zone, nil) // the round the step's ask starts
			select {
			case <-r.entered:
			case <-time.After(5 * time.Second):
				t.Fatalf("the key's poll did not start as a step\n%s", r.log)
			}
			close(r.release)
			waitUntil(t, "the key's hold ended with the poll", func() bool { return r.conf.keyHoldReason(r.ctx, r.zone) == "" })
			// the step's next ask
			adds.mu.Lock()
			for _, l := range adds.zones {
				l.syncAt = time.Time{}
			}
			adds.mu.Unlock()
			r.conf.joinerDSAtParent(zone, id)
			waitUntil(t, "the step's sync went out\n"+r.log.String(), func() bool { return r.parent.updatesSeen() > 0 })
			waitUntil(t, "the step finished", func() bool {
				adds.mu.Lock()
				for _, l := range adds.zones {
					l.parentAt = time.Time{}
				}
				adds.mu.Unlock()
				return r.conf.joinerDSAtParent(zone, id)
			})
		})
	}
}

// The sync a joiner's DS step asks may wait for the zone's key, whose rounds nothing
// else opens during the freeze: the ask opens them.
func TestAJoinersDSAskOpensTheKeyRounds(t *testing.T) {
	r := newSignerAddRig(t, "rounds.adding.example.", "agent").thawed()
	tr := newCatchUpTracker(AgentId(r.conf.MpConfig().Identity), []string{r.zone}, time.Hour)
	r.conf.InternalMp.CatchUp = tr
	r.at(r.next(), signerAddAccept)
	r.at(r.next(), signerAddMint)
	r.keys(KeyStatePublished, KeyStatePublished)
	r.at(r.next(), signerAddDS)
	tr.mu.Lock()
	tr.keyChecks = nil
	tr.mu.Unlock()
	r.parentLooks()
	r.conf.InternalMp.signerAdds.mu.Lock()
	for _, l := range r.conf.InternalMp.signerAdds.zones {
		l.syncAt = time.Time{}
	}
	r.conf.InternalMp.signerAdds.mu.Unlock()
	r.conf.joinerDSAtParent(r.zone, signerAddSelf)
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if !tr.keyChecks[ZoneName(dns.Fqdn(r.zone))] {
		t.Error("the step's ask did not open the key rounds")
	}
}

// The key's offers pass for a joiner's DS step alone, and only where the leader's
// sync is what adds the DS. Under parentsync=owner, or at any other step, they wait
// for the transition's end.
func TestTheKeysOffersPassForAJoinersDSStepAloneUnderTheFreeze(t *testing.T) {
	for _, tc := range []struct {
		name       string
		part       string
		parentSync uint8
		passes     bool
	}{
		{"its DS, the leader's sync", signerAddDS, core.HsyncParentSyncAgent, true},
		{"its DS, the owner's", signerAddDS, core.HsyncParentSyncOwner, false},
		{"its first keys", signerAddMint, core.HsyncParentSyncAgent, false},
		{"the caches' time", signerAddCaches, core.HsyncParentSyncAgent, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newNotifyRig(t, "offers.adding.signer.example.", "UPDATE")
			freezeServed(t, r.conf, r.mpzd)
			holdSignerAddStep(t, r.conf.InternalMp.Instructions, r.mpzd.ZoneName, r.conf.MpConfig().Identity, tc.part, tc.parentSync)
			if held, _ := r.conf.offerHeld(r.ctx, ZoneName(r.mpzd.ZoneName)); held == tc.passes {
				t.Errorf("the key's offer: held %v, want %v", held, !tc.passes)
			}
		})
	}
}

// A joiner's first keys wait what the zone's servers serve its DNSKEY RRset with
// (E5, T8), the largest of them: that is what caches hold. Its copy's TTL is the
// data's, and its policy's is what it will serve itself, nothing a cache has seen.
// Each case runs its real machine past its wait, the policy below and above its
// copy's TTL. Its copy's TTL is the floor until every server has answered: one that
// has not may serve above the others.
func TestAJoinersT8WaitsWhatTheZonesServersServe(t *testing.T) {
	const fivemin, hour, day = 5 * time.Minute, time.Hour, 24 * time.Hour
	const p1, p2 = "ns1.%s", "ns.p2.example."
	for _, tc := range []struct {
		name   string
		policy time.Duration
		copy   []time.Duration
		served map[string]time.Duration // by nameserver; %s is the zone
		want   time.Duration
	}{
		{"policy below its copy, its servers serve the lower", fivemin, []time.Duration{hour}, map[string]time.Duration{p1: fivemin, p2: fivemin}, fivemin},
		{"policy above its copy, its servers serve the higher", day, []time.Duration{hour}, map[string]time.Duration{p1: hour, p2: day}, day},
		{"policy above its copy, which nothing serves", day, []time.Duration{hour}, map[string]time.Duration{p1: hour, p2: hour}, hour},
		{"policy below what another signer serves", fivemin, []time.Duration{hour}, map[string]time.Duration{p1: fivemin, p2: hour}, hour},
		{"one server does not answer, the other serves below its copy", fivemin, []time.Duration{hour}, map[string]time.Duration{p2: fivemin}, hour},
		{"one server does not answer, the other serves above its copy", fivemin, []time.Duration{hour}, map[string]time.Duration{p2: day}, day},
		{"policy below its copy, no server answers", fivemin, []time.Duration{hour}, nil, hour},
		{"policy above its copy, no server answers", day, []time.Duration{hour}, nil, hour},
		{"no server answers, the longer TTL in its copy not first", fivemin, []time.Duration{hour, day}, nil, day},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const zone = "wait.adding.signer.example."
			records := append(sigRecords(`serial="5" servers="us,p2" signers="p2"`), `3600 IN NS `+p2)
			for _, ttl := range tc.copy {
				k := testDnskey(t, zone, 256)
				records = append(records, fmt.Sprintf("%d IN DNSKEY %d %d %d %s", int(ttl/time.Second), k.Flags, k.Protocol, k.Algorithm, k.PublicKey))
			}
			served := map[string]time.Duration{}
			for ns, ttl := range tc.served {
				if ns == p1 {
					ns = fmt.Sprintf(p1, zone)
				}
				served[ns] = ttl
			}
			servedKeyTTLs(t, zone, served)
			r, clk := joinerKeysPublished(t, zone, records)
			r.mpzd.Lock()
			r.mpzd.DnssecPolicy.TTLS.DNSKEY, r.mpzd.DnssecPolicy.TTLS.MaxServed = uint32(tc.policy/time.Second), uint32(tc.policy/time.Second)
			r.mpzd.Unlock()
			delay := r.e.driver(zone).Policy.PropagationDelay
			clk.Advance(delay + tc.want - 30*time.Second)
			r.e.tickOwned()
			if n := ownKeysIn(t, r, zone, KeyStatePublished); n != 2 {
				t.Errorf("30 s before the delay and %s: %d of its keys are still published, want 2", tc.want, n)
			}
			clk.Advance(time.Minute)
			r.e.tickOwned()
			if n := ownKeysIn(t, r, zone, KeyStatePublished); n != 0 {
				t.Errorf("30 s after the delay and %s: %d of its keys are still published, want none", tc.want, n)
			}
		})
	}
}

// A provider that signs serves the RRset itself: its keys wait its own copy's TTL,
// and it asks nobody.
func TestAProviderThatSignsWaitsTheTTLItServesAndAsksNobody(t *testing.T) {
	const zone = "signs.adding.signer.example."
	k := testDnskey(t, zone, 256)
	records := append(sigRecords(`serial="5" servers="us,p2" signers="us,p2"`),
		fmt.Sprintf("300 IN DNSKEY %d %d %d %s", k.Flags, k.Protocol, k.Algorithm, k.PublicKey))
	r := newSignerRig(t, zone, records...)
	r.conf.InternalMp.servedKeys.start = func(look func()) { look() }
	r.hand(handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)...), sigUs)
	if r.e.wire.SignsAtNaming(zone) {
		t.Error("it serves, and its first keys would sign before they have propagated")
	}
	prev := servingKeysLookup
	servingKeysLookup = func(context.Context, string, string) (*core.RRset, error) {
		t.Error("a provider that signs asked the zone's servers")
		return nil, errors.New("no answer")
	}
	t.Cleanup(func() { servingKeysLookup = prev })
	if got, known := r.e.wire.ServedDnskeyTTL(zone); got != 5*time.Minute || !known {
		t.Errorf("it waits %s (known %v), want its own copy's 5m0s", got, known)
	}
}

// After a restart the book is empty and the key may have waited long enough by its
// copy: T8 waits for the first look, and then for what that saw.
func TestAJoinersT8WaitsItsFirstLookAfterARestart(t *testing.T) {
	const zone = "restart.adding.signer.example."
	k := testDnskey(t, zone, 256)
	records := append(sigRecords(`serial="5" servers="us,p2" signers="p2"`),
		fmt.Sprintf("3600 IN DNSKEY %d %d %d %s", k.Flags, k.Protocol, k.Algorithm, k.PublicKey))
	servedKeyTTLs(t, zone, map[string]time.Duration{"ns1." + zone: 2 * time.Hour})
	r, clk := joinerKeysPublished(t, zone, records)
	delay := r.e.driver(zone).Policy.PropagationDelay
	clk.Advance(delay + 90*time.Minute)

	var looks []func()
	r.conf.InternalMp.servedKeys = servedKeysBook{start: func(look func()) { looks = append(looks, look) }}
	r.e.tickOwned()
	if n := ownKeysIn(t, r, zone, KeyStatePublished); n != 2 || len(looks) == 0 {
		t.Fatalf("with its first look under way: %d of its keys still published after %d looks, want 2 and a look", n, len(looks))
	}
	looks[0]()
	r.e.tickOwned()
	if n := ownKeysIn(t, r, zone, KeyStatePublished); n != 2 {
		t.Errorf("past its copy's TTL and short of what its server serves: %d of its keys still published, want 2", n)
	}
	clk.Advance(time.Hour)
	r.e.tickOwned()
	if n := ownKeysIn(t, r, zone, KeyStatePublished); n != 0 {
		t.Errorf("past what its server serves: %d of its keys still published, want none", n)
	}
}

// Every server the copy names counts once it has answered, in whichever look.
func TestAJoinersWaitDropsBelowItsCopyOnlyOnceEveryServerHasAnswered(t *testing.T) {
	const zone = "whole.adding.signer.example."
	const p2 = "ns.p2.example."
	k := testDnskey(t, zone, 256)
	records := append(sigRecords(`serial="5" servers="us,p2" signers="p2"`), `3600 IN NS `+p2,
		fmt.Sprintf("3600 IN DNSKEY %d %d %d %s", k.Flags, k.Protocol, k.Algorithm, k.PublicKey))
	r := newSignerRig(t, zone, records...)
	r.hand(joinerHandover(t, zone, 6, false), sigUs)
	b := &r.conf.InternalMp.servedKeys
	b.start = func(look func()) { look() }
	look := func(ttls map[string]time.Duration) time.Duration {
		t.Helper()
		servedKeyTTLs(t, zone, ttls)
		b.mu.Lock()
		if l := b.zones[canonicalName(zone)]; l != nil {
			l.at = time.Time{}
		}
		b.mu.Unlock()
		got, known := r.e.wire.ServedDnskeyTTL(zone)
		if !known {
			t.Error("a look has finished and nothing is known")
		}
		return got
	}
	if got := look(map[string]time.Duration{"ns1." + zone: 5 * time.Minute}); got != time.Hour {
		t.Errorf("with one of two seen it waits %s, want its copy's 1h0m0s", got)
	}
	if got := look(map[string]time.Duration{p2: 5 * time.Minute}); got != 5*time.Minute {
		t.Errorf("with the other seen in a later look it waits %s, want 5m0s", got)
	}
}

// The machine never waits for a look, and its wait only grows: a cache may hold
// what was served before, and a server gone quiet has served what it served.
func TestAServersLowerTTLOrSilenceDoesNotShortenAJoinersWait(t *testing.T) {
	const zone = "grows.adding.signer.example."
	k := testDnskey(t, zone, 256)
	records := append(sigRecords(`serial="5" servers="us,p2" signers="p2"`),
		fmt.Sprintf("7200 IN DNSKEY %d %d %d %s", k.Flags, k.Protocol, k.Algorithm, k.PublicKey))
	r := newSignerRig(t, zone, records...)
	r.hand(joinerHandover(t, zone, 6, false), sigUs)
	var looks []func()
	b := &r.conf.InternalMp.servedKeys
	b.start = func(look func()) { looks = append(looks, look) }
	ns1 := "ns1." + zone
	servedKeyTTLs(t, zone, map[string]time.Duration{ns1: time.Hour})

	if _, known := r.e.wire.ServedDnskeyTTL(zone); known || len(looks) != 1 {
		t.Fatalf("with a look under way, known %v after %d looks, want nothing known and one", known, len(looks))
	}
	if _, known := r.e.wire.ServedDnskeyTTL(zone); known || len(looks) != 1 {
		t.Errorf("a second tick, known %v after %d looks, want nothing known and still one", known, len(looks))
	}
	looks[0]()
	if got, _ := r.e.wire.ServedDnskeyTTL(zone); got != time.Hour {
		t.Errorf("once its server answered it waits %s, want 1h0m0s", got)
	}

	again := func(ttls map[string]time.Duration) time.Duration {
		t.Helper()
		servedKeyTTLs(t, zone, ttls)
		b.mu.Lock()
		b.zones[canonicalName(zone)].at = time.Time{}
		b.mu.Unlock()
		r.e.wire.ServedDnskeyTTL(zone)
		looks[len(looks)-1]()
		got, _ := r.e.wire.ServedDnskeyTTL(zone)
		return got
	}
	if got := again(map[string]time.Duration{ns1: 5 * time.Minute}); got != time.Hour {
		t.Errorf("after its servers went lower it waits %s, want 1h0m0s", got)
	}
	if got := again(nil); got != time.Hour {
		t.Errorf("after its servers went quiet it waits %s, want 1h0m0s", got)
	}
	if got := again(map[string]time.Duration{ns1: 3 * time.Hour}); got != 3*time.Hour {
		t.Errorf("after its servers went higher it waits %s, want 3h0m0s", got)
	}
}
