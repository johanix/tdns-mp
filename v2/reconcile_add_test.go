/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"crypto"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
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
// sync the leader asks are the rig's, and the agent's looks run in place. Unless
// unsigned, the parent also serves b's DS, which the rig leaves out of its records.
type signerAddRig struct {
	*reconcileRig
	parent    map[uint16]bool
	parentTTL time.Duration
	unsigned  bool
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
		records := map[parentDSRecord]bool{}
		if mpzd, ok := Zones.Get(zone); ok && mpzd != nil {
			if snap := mpzd.GetLastKeyInventory(); snap != nil {
				for _, it := range snap.Inventory {
					if r.parent[it.KeyTag] {
						records[dsRecordOf(t, it.KeyRR)] = true
					}
				}
			}
		}
		return parentDSSeen{records: records, unsigned: r.unsigned && len(records) == 0, ttl: r.parentTTL}, nil
	}
	askJoinersDS = func(*Config, string, string) { r.syncs++ }
	t.Cleanup(func() { parentDSLook, askJoinersDS = prevLook, prevAsk })
	r.nameserversServeInventory(t)
	setZoneNS(t, zone, "ns1."+zone, "ns2."+zone)
	mp := r.conf.MpConfig()
	mp.Local.Nameservers = srNameservers
	return r
}

// dsRecordOf is the record of the DS a parent serves of the key keyRR.
func dsRecordOf(t *testing.T, keyRR string) parentDSRecord {
	t.Helper()
	rr, err := dns.NewRR(keyRR)
	if err != nil {
		t.Fatal(err)
	}
	key := rr.(*dns.DNSKEY)
	ds := key.ToDS(dns.SHA256)
	return parentDSRecord{ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToLower(ds.Digest)}
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

// stepBegan has the step held have been taken at.
func (r *signerAddRig) stepBegan(at time.Time) {
	r.t.Helper()
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.StepAt = at
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
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

// setZoneNS has the zone's copy name the nameservers names.
func setZoneNS(t *testing.T, zone string, names ...string) {
	t.Helper()
	zd, ok := tdns.Zones.Get(zone)
	if !ok {
		t.Fatalf("zone %s is not here", zone)
	}
	apex, err := zd.GetOwner(zone)
	if err != nil || apex == nil {
		t.Fatalf("apex of %s: %v", zone, err)
	}
	rrset := core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeNS}
	for _, name := range names {
		rrset.RRs = append(rrset.RRs, &dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: name})
	}
	apex.RRtypes.Set(dns.TypeNS, rrset)
	zd.Data.Set(zone, *apex)
}

// nameserversServeInventory has the zone's nameservers answer with the keys of its
// signer's last inventory, at TTL 0.
func (r *signerAddRig) nameserversServeInventory(t *testing.T) {
	t.Helper()
	prev := servingKeysLookup
	servingKeysLookup = func(_ context.Context, zone, _ string) (*core.RRset, error) {
		rrset := &core.RRset{}
		mpzd, _ := Zones.Get(zone)
		if snap := mpzd.GetLastKeyInventory(); snap != nil {
			for _, it := range snap.Inventory {
				rr, err := dns.NewRR(it.KeyRR)
				if err != nil {
					t.Error(err)
					continue
				}
				rr.Header().Ttl = 0
				rrset.RRs = append(rrset.RRs, rr)
			}
		}
		return rrset, nil
	}
	t.Cleanup(func() { servingKeysLookup = prev })
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

// Its key machine makes keys one at a time, and tdns takes a KSK alone for a CSK: at
// a zone the machine runs a turn between the two starts nothing, or the zone is signed
// by its KSK until its next signing. Nor does one that sees the ZSK's row before tdns's
// signing keys hold it, which is what a start reads.
func TestANewSignerDoesNotStartWithItsKSKAlone(t *testing.T) {
	const zone = "kskalone.adding.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="p2" signers="p2"`)...)
	r.conf.InternalMp.KeyLifecycleOwner = r.owner
	r.hand(joinerHandover(t, zone, 6, true), sigUs)
	mint := func(role string) uint16 {
		t.Helper()
		pkc, _, err := r.kdb.GenerateKeypairWithColumns(zone, "test", KeyStateCreated, dns.ED25519, role, tdns.KeyRowFlags{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return pkc.KeyId
	}
	signs := tdns.KeyRowFlags{Pub: true, Sign: true, DS: sql.NullBool{Valid: true}}
	ksk := mint("KSK")
	if err := tdns.UpdateKeyRowFrom(r.kdb, zone, ksk, KeyStateActive, KeyStateCreated, signs); err != nil {
		t.Fatal(err)
	}
	r.roleTurn()
	if len(r.started) != 0 {
		t.Fatalf("with its KSK alone it started: %v", r.started)
	}
	zsk := mint("ZSK")
	// the row says so, and tdns's signing keys do not yet
	if _, err := r.kdb.DB.Exec(`UPDATE DnssecKeyStore SET state=?, pub=1, sign=1 WHERE zonename=? AND keyid=?`, KeyStateActive, zone, int(zsk)); err != nil {
		t.Fatal(err)
	}
	r.roleTurn()
	if len(r.started) != 0 {
		t.Fatalf("with its ZSK's row written and not in tdns's signing keys it started: %v", r.started)
	}
	if err := tdns.UpdateKeyRowFrom(r.kdb, zone, zsk, KeyStateActive, KeyStateActive, signs); err != nil {
		t.Fatal(err)
	}
	r.roleTurn()
	if len(r.started) != 1 {
		t.Errorf("with its KSK and ZSK, started %v, want one start", r.started)
	}
}

// A new signer starts with tdns's real start, as at a first load: its first KSK and
// ZSK are active at once, and sign its zone, its own signatures replacing those of the
// copy it relayed. tdns's check finds nothing, and its machine takes the zone with
// them, deciding its KSK's ds, which the DS step reads.
func TestANewSignerStartsSigningWithItsFirstKeysActive(t *testing.T) {
	const zone = "active.adding.signer.example."
	other := testDnskey(t, zone, 257)
	r := newSignerRig(t, zone, append(sigRecords(`serial="5" servers="p2" signers="p2"`), "3600 IN DNSKEY 257 3 15 "+other.PublicKey)...)
	prev := startSigning
	startSigning = func(ctx context.Context, zd *tdns.ZoneData) error { return zd.StartSigning(ctx, 0) }
	t.Cleanup(func() { startSigning = prev })
	r.notTaken(zone)
	r.hand(joinerHandover(t, zone, 6, true), sigUs)
	if r.owner.taken(zone) {
		t.Fatal("handed its keys' step, with no keys, its machine has taken the zone")
	}
	r.roleTurn()
	if !slices.Contains(r.foreignRows(t), other.KeyTag()) {
		t.Errorf("the other signer's key is not kept: %v", r.foreignRows(t))
	}
	if !r.mpzd.Options[tdns.OptInlineSigning] || r.mpzd.Withheld() {
		t.Fatalf("the option %v, withheld %v: want it signing", r.mpzd.Options[tdns.OptInlineSigning], r.mpzd.Withheld())
	}
	inv, err := tdns.GetKeyInventory(r.kdb, zone)
	if err != nil {
		t.Fatal(err)
	}
	var zsk uint16
	roles := map[string]int{}
	for _, it := range inv {
		if it.State == DnskeyStateForeign {
			continue
		}
		roles[roleOf(it.Flags)]++
		if it.State != KeyStateActive || !it.Sign {
			t.Errorf("its first key %d is %s, sign %v: want it active, signing", it.KeyTag, it.State, it.Sign)
		}
		if it.Flags&dns.SEP == 0 {
			zsk = it.KeyTag
		} else if it.DS == nil || !*it.DS {
			t.Errorf("its KSK's ds is %v, want it decided, and set", it.DS)
		}
	}
	if roles["KSK"] != 1 || roles["ZSK"] != 1 {
		t.Fatalf("its keys are %v, want a KSK and a ZSK", roles)
	}
	if !r.owner.taken(zone) {
		t.Error("its key machine has not taken the zone")
	}
	if v := tdns.CheckKeyRowInvariants(r.kdb, zone); len(v) != 0 {
		t.Errorf("tdns's check finds %v", v)
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
	if err != nil || keys == nil || len(keys.RRs) != 3 || len(keys.RRSIGs) == 0 {
		t.Errorf("the DNSKEY RRset: %+v (%v), want its two keys and the other signer's, signed", keys, err)
	}
}

// A new provider brought up after the owner's edit: its agent has no copy, its copy
// names it a server and a signer, and it acts by that. Its signer signs with tdns's
// keys, active at once, which no other signer takes yet. Handed its keys' step they go
// out once more, staying active, and its first inventory says so with the keys marked.
func TestAJoinerBroughtUpAfterTheEditSendsItsKeysAgain(t *testing.T) {
	const zone = "afteredit.adding.signer.example."
	records := sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)
	r := newSignerRig(t, zone, records...)
	prev := startSigning
	startSigning = func(ctx context.Context, zd *tdns.ZoneData) error { return zd.StartSigning(ctx, 0) }
	t.Cleanup(func() { startSigning = prev })
	var mu sync.Mutex
	var resent []uint16
	r.e.wire.push = func(_ *Config, _ string, tags []uint16) {
		mu.Lock()
		defer mu.Unlock()
		resent = append(resent, tags...)
	}
	r.firstLoad(t, records...)
	r.hand(&ActingHandover{Zone: zone, Phase: PhaseSteady, NoCopy: true, Made: time.Now()}, sigUs)
	r.roleTurn()
	states := func() (out []uint16) {
		t.Helper()
		inv, err := tdns.GetKeyInventory(r.kdb, zone)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range inv {
			if it.State == DnskeyStateForeign {
				continue
			}
			if it.State != KeyStateActive || !it.Sign {
				t.Errorf("key %d is %s, sign %v: want it left active, signing", it.KeyTag, it.State, it.Sign)
			}
			out = append(out, it.KeyTag)
		}
		return out
	}
	keys := states()
	if len(keys) != 2 {
		t.Fatalf("by its own copy its keys are %v, want a KSK and a ZSK", keys)
	}
	h := joinerHandover(t, zone, 7, true)
	h.Step, h.Joining = 2, true
	r.hand(h, sigUs)
	waitForPush(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(resent) >= 2
	})
	mu.Lock()
	for _, id := range keys {
		if !slices.Contains(resent, id) {
			t.Errorf("handed its keys' step, resent %v: want key %d", resent, id)
		}
	}
	mu.Unlock()
	states()
	r.roleTurn()
	if !r.mpzd.Options[tdns.OptInlineSigning] {
		t.Error("handed Signing, it does not sign")
	}
}

// A provider put back, its keys left from an earlier time and its zone not yet taken
// by its key machine: its turn starts it with those keys, and they go out once more,
// which its agent's set, holding them, would not bring about.
func TestAProviderPutBackSendsItsKeysAgainAsItsZoneIsTaken(t *testing.T) {
	const zone = "putback.adding.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="p2" signers="p2"`)...)
	r.notTaken(zone)
	var mu sync.Mutex
	var resent []uint16
	r.e.wire.push = func(_ *Config, _ string, tags []uint16) {
		mu.Lock()
		defer mu.Unlock()
		resent = append(resent, tags...)
	}
	var left []uint16
	for _, role := range []string{"KSK", "ZSK"} {
		pkc, _, err := r.kdb.GenerateKeypair(zone, "earlier", tdns.DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, role, nil)
		if err != nil {
			t.Fatal(err)
		}
		left = append(left, pkc.KeyId)
	}
	h := joinerHandover(t, zone, 6, true)
	h.Step, h.Joining = 2, true
	r.hand(h, sigUs)
	r.roleTurn()
	if !r.owner.taken(zone) || !r.mpzd.Options[tdns.OptInlineSigning] {
		t.Fatalf("taken %v, signing %v: want both", r.owner.taken(zone), r.mpzd.Options[tdns.OptInlineSigning])
	}
	waitForPush(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(resent) >= 2
	})
	mu.Lock()
	defer mu.Unlock()
	for _, id := range left {
		if !slices.Contains(resent, id) {
			t.Errorf("resent %v: want key %d", resent, id)
		}
		l := r.e.driver(zone)
		if l == nil || l.dist[id] == nil {
			t.Errorf("key %d has no record to resend it by", id)
		}
	}
}

// A provider named a signer is not bound first: its zone would be its key machine's
// before it has keys, and tdns would make none. Binding is for one with its keys
// published and no signing, as a provider on its way out, whose machine must run.
func TestANamedSignerIsNotBoundBeforeItsStart(t *testing.T) {
	const zone = "nobind.adding.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="p2" signers="p2"`)...)
	r.notTaken(zone)
	bound := 0
	prev := bindWithoutSigning
	bindWithoutSigning = func(zd *tdns.ZoneData) error {
		bound++
		return nil
	}
	t.Cleanup(func() { bindWithoutSigning = prev })
	r.mpzd.Lock()
	r.mpzd.DnssecPolicy = nil
	r.mpzd.Unlock()
	h := joinerHandover(t, zone, 6, true)
	r.hand(h, sigUs)
	r.roleTurn()
	if bound != 0 || len(r.started) != 1 {
		t.Errorf("named a signer, bound %d times, started %v: want no bind, and a start", bound, r.started)
	}
	r.mpzd.SetRuntimeOption(tdns.OptInlineSigning, false)
	next := *h
	next.Sets.Signing, next.Step, next.Made = nil, h.Step+1, time.Now()
	r.hand(&next, sigUs)
	r.roleTurn()
	if bound != 1 {
		t.Errorf("in KeySigners and not in Signing, bound %d times, want once", bound)
	}
}

// notTaken has its key machine not have taken the zone, as a provider new to it, with
// the zone named in its key-lifecycle-zones.
func (r *signerRig) notTaken(zone string) {
	r.owner = NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return r.kdb })
	r.e = NewKeyLifecycleEngine(r.conf, r.owner)
	r.e.wire.push = func(*Config, string, []uint16) {}
	r.conf.InternalMp.KeyLifecycle, r.conf.InternalMp.KeyLifecycleOwner = r.e, r.owner
	r.conf.MpConfig().KeyLifecycleZones = []string{zone}
	r.owner.SetConfiguredZones(func() []string { return r.conf.MpConfig().KeyLifecycleZones })
}

// waitForPush waits for the pushes the key machine sends off its own goroutines.
func waitForPush(t *testing.T, done func() bool) {
	t.Helper()
	for range 200 {
		if done() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("no push came")
}

// The same keys' step handed again, as it is every half minute, says the same step:
// its keys would go out again each time, and rejected or applied they would have
// their records back. Another step does not.
func TestAJoinersKeysStepHandedAgainKeepsWhenItBegan(t *testing.T) {
	const zone = "again.adding.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="p2" signers="p2"`)...)
	h := joinerHandover(t, zone, 6, true)
	h.Step, h.Joining = 2, true
	r.hand(h, sigUs)
	began, ok := r.e.wire.JoiningSince(zone)
	if !ok {
		t.Fatal("handed its keys' step, it does not say so")
	}
	time.Sleep(2 * time.Millisecond)
	again := *h
	again.Newest, again.Made = h.Newest+1, time.Now()
	r.hand(&again, sigUs)
	if held, _ := actingHeld.Load().get(zone); held.handover.Newest != again.Newest {
		t.Fatalf("the hand-over held has newest %d, want %d", held.handover.Newest, again.Newest)
	}
	if since, _ := r.e.wire.JoiningSince(zone); !since.Equal(began) {
		t.Errorf("handed again, its step began at %v, was %v", since, began)
	}
	next := again
	next.Step, next.Joining, next.Made = 3, false, time.Now()
	r.hand(&next, sigUs)
	if _, ok := r.e.wire.JoiningSince(zone); ok {
		t.Error("handed its next step, it still says its keys' step")
	}
	// any other hand-over handed again is taken when it is, as ever
	held, _ := actingHeld.Load().get(zone)
	before := held.since
	time.Sleep(2 * time.Millisecond)
	later := next
	later.Newest, later.Made = next.Newest+1, time.Now()
	r.hand(&later, sigUs)
	if held, _ = actingHeld.Load().get(zone); !held.since.After(before) {
		t.Errorf("another step handed again, taken at %v, was %v", held.since, before)
	}
}

// A first load handed Signing, over a copy that carries another's signatures, as
// from a stanza naming another provider's signer: tdns would take them for the
// zone's own and leave them, so the zone relays that copy, and it is StartSigning
// that replaces them (signerRoleTurn). So does one that serves nothing, whose start
// comes at its turn. A copy with none, at a provider that serves, signs at
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
		t.Errorf("the signer is handed %+v at its keys' step, want it marked, so that keys it holds go out again", h)
	}
	if h := r.wantedBy(r.combiner); h == nil || h.Joining {
		t.Errorf("the combiner is handed %+v at its keys' step, the mark is the signer's", h)
	}
	if h := r.wantedBy(r.signer); h == nil || !has(h.Sets.KeySigners, "a") || !has(h.Sets.KeyConfirmers, "a") || !has(h.Sets.Signing, "a") {
		t.Errorf("the signer is handed %+v once every member holds it, want a in the key sets and in Signing", h)
	}
}

// At a zone its key machine runs already, as for a provider put back whose keys are
// gone, its first keys are the machine's, under the hold: a role with no active key
// gets one, active at once (T2a), and nothing else starts. Its start waits for both.
func TestAJoiningSignerMintsUnderTheHold(t *testing.T) {
	const zone = "mints.adding.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="p2" signers="p2"`)...)
	r.conf.InternalMp.KeyLifecycleOwner = r.owner
	r.hand(joinerHandover(t, zone, 6, true), sigUs)
	if !r.conf.InternalMp.SignerHolds.held(zone) {
		t.Fatal("the hand-over's hold is not kept")
	}
	r.roleTurn()
	if len(r.started) != 0 {
		t.Fatalf("with no keys it started: %v", r.started)
	}
	r.e.tickOwned()
	keys := joinersKeys(t, r, zone)
	if keys["KSK"] != 1 || keys["ZSK"] != 1 {
		t.Errorf("under the hold the joiner has %v, want its first KSK and ZSK", keys)
	}
	if n := ownKeysIn(t, r, zone, KeyStateActive); n != 2 {
		t.Errorf("%d of its keys are active, want both", n)
	}
	r.roleTurn()
	if len(r.started) != 1 {
		t.Errorf("with its KSK and ZSK, started %v, want one start", r.started)
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
	r.keys(KeyStateActive, KeyStateActive)
	cur, _ = r.step()
	if n := turnRolling(); n != cur.Number {
		t.Fatalf("its DS step was taken during an emergency rollover: step %d", n)
	}
	r.at(r.next(), signerAddDS)
	tag := r.keys(KeyStateActive, KeyStateActive)
	r.parent[tag], r.parentTTL = true, time.Hour
	r.parentLooks()
	r.next()
	st := r.next()
	r.at(st, signerAddCaches)
	r.stepBegan(time.Now().Add(-time.Hour - time.Second))
	r.partsTake()
	r.holdsToo(roleB)
	if n := turnRolling(); n == st.Number {
		t.Error("its signatures' step waits for an emergency rollover, which only the DS and DNSKEY steps do")
	}
}

// Its DS goes to the parent's set only at its DS step, which comes after its keys
// are active and the zone's nameservers serve them: DSSigners names it no sooner, and
// no sooner does the leader's DS set hold it.
func TestTheJoinersDSIsSentOnlyAfterItsKeysPropagated(t *testing.T) {
	r := newSignerAddRig(t, "ds.adding.example.", "agent").thawed()
	for _, want := range []string{signerAddAccept, signerAddMint} {
		st := r.next()
		r.at(st, want)
		if h := r.wantedBy(r.combiner); h == nil || has(h.Sets.DSSigners, "a") {
			t.Fatalf("at %s the DS set holds it: %+v", want, h)
		}
	}
	for _, state := range []string{KeyStateCreated, KeyStateMpdist, KeyStatePublished, KeyStateStandby} {
		r.keys(state, state)
		if st := r.next(); len(st.Taken) != 2 {
			t.Fatalf("its keys in %s, and the step went on: %+v", state, st)
		}
	}
	// one of the two active: the step is for both
	r.keys(KeyStateActive, KeyStateStandby)
	if st := r.next(); len(st.Taken) != 2 {
		t.Fatalf("its ZSK standby, and the step went on: %+v", st)
	}
	r.keys(KeyStateActive, KeyStateActive)
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
	r.keys(KeyStateActive, KeyStateActive)
	r.at(r.next(), signerAddDS)
	tag := r.keys(KeyStateActive, KeyStateActive)
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
	r.parent[tag], r.parentTTL = true, time.Hour
	r.parentLooks()
	r.next()
	r.at(r.next(), signerAddCaches)
}

// A signer added (design 5.1, amended): it signs at its keys' step, and the steps
// after it say what has propagated. At its keys' step its signer is handed Signing,
// and the step waits for its keys active and its signer signing. The transition is
// done only after the DS TTL.
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
		t.Fatalf("the step went on with no keys active: %+v", st)
	}
	r.keys(KeyStateActive, KeyStateActive, func(s *KeyInventorySnapshot) { s.Signs = false })
	r.partsTake()
	if st = r.next(); len(st.Taken) != 2 || signerAddHolds(r.conf, r.zone, st) {
		t.Fatalf("the step went on with its signer not signing: %+v", st)
	}
	if line := signerAddStatus(r.conf, r.zone, heldStep{InstrStep: st}, time.Now()); !strings.Contains(line, "signer to start signing") {
		t.Errorf("before its signer signs the status says %q", line)
	}
	r.keys(KeyStateActive, KeyStateActive)
	r.at(r.next(), signerAddDS)
	tag := r.keys(KeyStateActive, KeyStateActive)
	if st = r.next(); len(st.Taken) != 3 {
		t.Fatalf("the DS step went on with the parent serving no DS: %+v", st)
	}
	r.parent[tag], r.parentTTL = true, time.Hour
	r.parentLooks()
	r.next() // the look is taken on this turn's wait
	r.at(r.next(), signerAddCaches)
	for range 3 {
		r.at(r.next(), signerAddCaches) // the DS TTL has not passed
	}
	r.stepBegan(time.Now().Add(-time.Hour - time.Second))
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
	r.keys(KeyStateActive, KeyStateActive, func(s *KeyInventorySnapshot) { s.Signs = false })
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
	r.keys(KeyStateActive, KeyStateActive)
	r.at(r.next(), signerAddDS)
	tag := r.keys(KeyStateActive, KeyStateActive)
	r.parent[tag], r.parentTTL = true, time.Hour
	r.parentLooks()
	r.next()
	r.at(r.next(), signerAddCaches)
	w := jAt(t, 43, `servers="a,b,n" signers="a,b" nsmgmt="owner" parentsync="owner" suffix="n"`, freezeRecords...)
	r.store.Note(r.zone, w, nil)
	r.at(r.next(), signerAddCaches)
	if _, ok := r.conf.thawView(r.zone, time.Now()); ok || r.active() != r.v.Serial {
		t.Errorf("43 is agreed during the caches' time: active %d", r.active())
	}
	r.stepBegan(time.Now().Add(-time.Hour - time.Second))
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

	// its agent's word was of the zone as loaded then: replaced, the zone is
	// another, whose copy may be one its agent refused (CodeRabbit on #374)
	if !rr.conf.agentHasNoCopy(relay) {
		t.Fatal("its agent's word is not kept")
	}
	loaded, _ := tdns.Zones.Get(relay)
	tdns.Zones.Set(relay, &tdns.ZoneData{ZoneName: relay})
	t.Cleanup(func() { tdns.Zones.Set(relay, loaded) })
	if rr.conf.agentHasNoCopy(relay) {
		t.Error("its agent's word of the zone it replaced still stands")
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

// A zone nobody signs has nothing to validate new keys against: its first signer has
// no wait at its keys but that they are active, asks no nameserver, and has no caches'
// time. Anyone after it joins as usual.
func TestAZonesFirstSignerHasNoWait(t *testing.T) {
	from := jAt(t, 41, `servers="b" suffix="n"`, freezeRecords...)
	to := jAt(t, 42, `servers="b" signers="a" suffix="n"`, freezeRecords...)
	parts := func(p planView) (out []string) {
		for _, st := range signerAddSteps(p) {
			_, part, _ := signerAddKeyParts(st.key)
			out = append(out, part)
		}
		return out
	}
	want := []string{signerAddAccept, signerAddMint, signerAddDS}
	if got := parts(planView{from: from, to: to, held: rolesFor(from, from, 0)}); !slices.Equal(got, want) {
		t.Errorf("the first signer's steps are %v, want %v", got, want)
	}
	after := jAt(t, 43, `servers="b" signers="a,n" suffix="n"`, freezeRecords...)
	held := rolesFor(to, to, 0)
	if got := parts(planView{from: to, to: after, held: held}); !slices.Equal(got, []string{signerAddAccept, signerAddMint, signerAddDS, signerAddCaches}) {
		t.Errorf("the next signer's steps are %v", got)
	}

	r := newSignerAddRig(t, "first.wait.adding.example.", "owner")
	knownAs(t, r.store, r.zone, r.v)
	asked := 0
	prev := servingKeysLookup
	servingKeysLookup = func(context.Context, string, string) (*core.RRset, error) {
		asked++
		return nil, errServesNoRRset
	}
	t.Cleanup(func() { servingKeysLookup = prev })
	mint := signerAddStepsOf(Provider{Label: "a", Identity: signerAddSelf}, true)[1]
	r.keys(KeyStateStandby, KeyStateActive)
	if w := mint.wait(r.conf, r.zone, time.Now()); !strings.Contains(w, "active") {
		t.Errorf("its KSK standby, the first signer's keys' step waits for %q", w)
	}
	r.keys(KeyStateActive, KeyStateActive)
	if w := mint.wait(r.conf, r.zone, time.Now()); w != "" {
		t.Errorf("its keys active, the first signer's keys' step waits for %q", w)
	}
	if asked != 0 {
		t.Errorf("the first signer's keys' step asked %d nameservers", asked)
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
// nothing to validate its signatures with. One that does not answer isn't counted,
// and is named. The largest TTL any of them gave is what caches may hold.
func TestTheDSStepAsksEveryParentServer(t *testing.T) {
	ds := func(tag uint16, ttl uint32) dns.RR {
		return &dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: ttl}, KeyTag: tag}
	}
	boom := errors.New("no answer")
	for _, c := range []struct {
		name     string
		answers  map[string][]dns.RR
		fails    []string
		want     []uint16
		ttl      time.Duration
		unsigned bool
		err      bool
	}{
		{name: "both have it", answers: map[string][]dns.RR{"p1": {ds(1, 60), ds(2, 60)}, "p2": {ds(1, 90), ds(2, 90)}}, want: []uint16{1, 2}, ttl: 90 * time.Second},
		{name: "the second lags", answers: map[string][]dns.RR{"p1": {ds(1, 60), ds(2, 60)}, "p2": {ds(1, 60)}}, want: []uint16{1}, ttl: time.Minute},
		{name: "the first lags", answers: map[string][]dns.RR{"p1": {ds(1, 60)}, "p2": {ds(1, 60), ds(2, 60)}}, want: []uint16{1}, ttl: time.Minute},
		{name: "one serves no DS", answers: map[string][]dns.RR{"p1": {ds(1, 60)}, "p2": {}}, ttl: time.Minute},
		{name: "the first serves no DS", answers: map[string][]dns.RR{"p1": {}, "p2": {ds(1, 60)}}, ttl: time.Minute},
		{name: "neither serves a DS", answers: map[string][]dns.RR{"p1": {}, "p2": {}}, unsigned: true},
		{name: "one serves none, one does not answer", answers: map[string][]dns.RR{"p1": {}}, fails: []string{"p2"}, unsigned: true},
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
		for r := range seen.records {
			tags = append(tags, r.tag)
		}
		slices.Sort(tags)
		if !slices.Equal(tags, c.want) || seen.ttl != c.ttl {
			t.Errorf("%s: the tags %v, TTL %s; want %v, %s", c.name, tags, seen.ttl, c.want, c.ttl)
		}
		if seen.unsigned != c.unsigned {
			t.Errorf("%s: unsigned %v, want %v", c.name, seen.unsigned, c.unsigned)
		}
		if !c.err && !slices.Equal(seen.silent, c.fails) {
			t.Errorf("%s: the silent %v, want %v", c.name, seen.silent, c.fails)
		}
	}
}

// A key tag is 16 bits, so a DS under the joiner's tag may be another key's: the
// DS is the joiner's only by its algorithm and digest, under any digest type.
func TestAnotherKeysDSUnderTheSameTagIsNotAJoinersDS(t *testing.T) {
	const zone = "same.tag.adding.example."
	key := testDnskey(t, zone, 257)
	real := key.ToDS(dns.SHA256)
	variant := func(change func(*dns.DS)) dns.RR {
		ds := *real
		change(&ds)
		return &ds
	}
	otherDigest := variant(func(ds *dns.DS) { ds.Digest = strings.Repeat("ab", 32) })
	for _, c := range []struct {
		name    string
		answers map[string][]dns.RR
		want    bool
	}{
		{"its DS", map[string][]dns.RR{"p1": {real}}, true},
		{"its digest in capitals", map[string][]dns.RR{"p1": {variant(func(ds *dns.DS) { ds.Digest = strings.ToUpper(ds.Digest) })}}, true},
		{"by another digest type", map[string][]dns.RR{"p1": {key.ToDS(dns.SHA384)}}, true},
		{"another key's digest", map[string][]dns.RR{"p1": {otherDigest}}, false},
		{"another key's digest beside its own", map[string][]dns.RR{"p1": {otherDigest, real}}, true},
		{"another algorithm", map[string][]dns.RR{"p1": {variant(func(ds *dns.DS) { ds.Algorithm = dns.RSASHA256 })}}, false},
		{"another key tag", map[string][]dns.RR{"p1": {variant(func(ds *dns.DS) { ds.KeyTag++ })}}, false},
		{"a digest type nobody can compute", map[string][]dns.RR{"p1": {variant(func(ds *dns.DS) { ds.DigestType = 200 })}}, false},
		{"each server a key of that tag, another each", map[string][]dns.RR{"p1": {real}, "p2": {otherDigest}}, false},
	} {
		var servers []string
		for _, s := range []string{"p1", "p2"} {
			if _, ok := c.answers[s]; ok {
				servers = append(servers, s)
			}
		}
		seen, err := dsAtEveryServer(servers, func(server string) ([]dns.RR, error) { return c.answers[server], nil })
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := seen.serves(key); got != c.want {
			t.Errorf("%s: serves says %v, want %v", c.name, got, c.want)
		}
	}
}

// The step itself: the parent's only DS under the joiner's KSK's tag is another
// key's, so the step waits and, under parentsync=agent, asks its sync.
func TestAJoinersDSStepDoesNotEndOnAnotherKeysDS(t *testing.T) {
	r := newSignerAddRig(t, "colliding.adding.example.", "agent")
	tag := r.keys(KeyStateActive, KeyStateActive)
	mpzd, _ := Zones.Get(r.zone)
	own := dsRecordOf(t, mpzd.GetLastKeyInventory().Inventory[0].KeyRR)
	if own.tag != tag {
		t.Fatalf("the KSK's tag is %d, want %d", own.tag, tag)
	}
	other := own
	other.digest = strings.Repeat("ab", 32)
	prev := parentDSLook
	t.Cleanup(func() { parentDSLook = prev })
	parentDSLook = func(*Config, string) (parentDSSeen, error) {
		return parentDSSeen{records: map[parentDSRecord]bool{other: true}}, nil
	}
	r.parentLooks()
	r.conf.joinerDSAtParent(r.zone, signerAddSelf) // the look, run in place
	if r.conf.joinerDSAtParent(r.zone, signerAddSelf) {
		t.Error("the step ended on another key's DS under its tag")
	}
	if r.syncs == 0 {
		t.Error("no sync asked, with the parent lacking its DS")
	}
	parentDSLook = func(*Config, string) (parentDSSeen, error) {
		return parentDSSeen{records: map[parentDSRecord]bool{other: true, own: true}}, nil
	}
	r.parentLooks()
	r.conf.joinerDSAtParent(r.zone, signerAddSelf)
	if !r.conf.joinerDSAtParent(r.zone, signerAddSelf) {
		t.Error("the parent serves its DS, and the step waits")
	}
}

// Where the parent serves no DS of the zone at all, no validator looks for the
// joiner's DS, so its DS step ends at once, under either parentsync and whatever
// scheme the parent offers (Johan's ruling of 2026-11-05), and the caches hold no
// DS RRset to wait out. A parent that serves another signer's DS holds it as
// before. A zone's first signer on a zone unsigned at the parent is done once its
// keys are active.
func TestADSStepEndsAtOnceWhenTheParentServesNoDS(t *testing.T) {
	for _, parentsync := range []string{"agent", "owner"} {
		t.Run(parentsync, func(t *testing.T) {
			r := newSignerAddRig(t, parentsync+".unsigned.adding.example.", parentsync).thawed()
			r.at(r.next(), signerAddAccept)
			r.at(r.next(), signerAddMint)
			r.keys(KeyStateActive, KeyStateActive)
			r.at(r.next(), signerAddDS)
			r.keys(KeyStateActive, KeyStateActive)
			if st := r.next(); len(st.Taken) != 3 {
				t.Fatalf("the parent serves another signer's DS, and the step went on: %+v", st)
			}
			r.unsigned = true
			r.parentLooks()
			r.next() // the look is taken on this turn's wait
			if st := r.next(); st.Taken[len(st.Taken)-1] != lastStepKey {
				t.Errorf("the parent serving no DS, the step is %+v, want the last: no wait at the DS step or for the caches", st)
			}
		})
	}
	t.Run("a zone's first signer", func(t *testing.T) {
		r := newSignerAddRig(t, "first.unsigned.adding.example.", "agent")
		knownAs(t, r.store, r.zone, r.v)
		r.unsigned = true
		r.keys(KeyStateActive, KeyStateActive)
		ds := signerAddStepsOf(Provider{Label: "a", Identity: signerAddSelf}, true)[2]
		rigs := parentDSLook
		parentDSLook = func(*Config, string) (parentDSSeen, error) { return parentDSSeen{}, errors.New("no answer") }
		if w := ds.wait(r.conf, r.zone, time.Now()); w == "" {
			t.Error("no server of the parent answers, and the first signer's DS step ends")
		}
		parentDSLook = rigs
		r.parentLooks()
		if w := ds.wait(r.conf, r.zone, time.Now()); w != "" {
			t.Errorf("the parent serves no DS, and the first signer's DS step waits for %q", w)
		}
	})
}

// T9 asks one parent server, so its wait can start before the last of them has
// the DS: step 3 also waits the DS TTL from when every server served it, the DS
// step's end, or a cache may still hold a DS RRset without it.
func TestTheCachesTimeCountsFromWhenEveryParentServerServesTheDS(t *testing.T) {
	r := newSignerAddRig(t, "ttl.parent.adding.example.", "owner").thawed()
	serving(t, soa(t, r.zone, 5, nil, nil), nil)
	r.at(r.next(), signerAddAccept)
	r.at(r.next(), signerAddMint)
	r.keys(KeyStateActive, KeyStateActive)
	r.at(r.next(), signerAddDS)
	tag := r.keys(KeyStateActive, KeyStateActive)
	r.parent[tag], r.parentTTL = true, time.Hour
	r.parentLooks()
	r.next()
	st := r.next()
	r.at(st, signerAddCaches)
	if line := r.conf.reconcileLine(r.zone, time.Now()); !strings.Contains(line, "the DS TTL at the parent") {
		t.Errorf("the DS TTL not passed: the status says %q", line)
	}
	r.stepBegan(time.Now().Add(-time.Hour - time.Second))
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
	r.conf.InternalMp.mpZones.setForTest(zone)
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
	o.conf.InternalMp.mpZones.setForTest(none)
	o.restart(t)
	if err := o.mpzd.Withhold(); err != nil {
		t.Fatal(err)
	}
	o.mpzd.InstallInitialSnapshot()
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
		if err != nil || seen.records[parentDSRecord{7, dns.ED25519, dns.SHA256, "00"}] != c.tagged {
			t.Errorf("%s: the records %v (%v), want the DS counted %v", c.name, seen.records, err, c.tagged)
		}
	}
	if _, err := dsAtEveryServer([]string{refused}, func(s string) ([]dns.RR, error) { return askParentDS(zone, s) }); err == nil {
		t.Error("a server that refuses, and no other: nothing should be known")
	}
}

// joinerKeyPublished is a new signer's signer, with its copy holding records, at the
// moment a later key of its is published: every other signer has applied it. It
// answers on the machine's clock, and its looks run in place.
func joinerKeyPublished(t *testing.T, zone string, records []string) (*signerRig, *fakeClock) {
	t.Helper()
	r := newSignerRig(t, zone, records...)
	r.conf.InternalMp.servedKeys.start = func(look func()) { look() }
	r.hand(joinerHandover(t, zone, 6, true), sigUs)
	r.e.tickOwned()
	if n := ownKeysIn(t, r, zone, KeyStateActive); n != 2 {
		t.Fatalf("%d of its keys are active, want its KSK and ZSK", n)
	}
	clk := &fakeClock{t: time.Now()}
	l := r.e.driver(zone)
	l.Clock = clk
	keyid, err := l.Mint("ZSK")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Apply(keyid, EvDistributed); err != nil {
		t.Fatal(err)
	}
	if !r.e.Signal(zone, keyid, "propagated", "", clk.Now()) {
		t.Fatalf("key %d: the signal is not taken", keyid)
	}
	if n := ownKeysIn(t, r, zone, KeyStatePublished); n != 1 {
		t.Fatalf("%d of its keys are published, want the later one", n)
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
				seen := parentDSSeen{records: map[parentDSRecord]bool{}}
				if r.parent.updatesSeen() > 0 {
					seen.records[dsRecordOf(t, r.ksk.KeyRR)] = true
				}
				return seen, nil
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
	r.keys(KeyStateActive, KeyStateActive)
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

// A later key of a provider no NS names waits what the zone's servers serve its
// DNSKEY RRset with (E5, T8), the largest of them: that is what caches hold. Its copy's
// TTL is the data's, and its policy's is what it will serve itself, nothing a cache has seen.
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
			r, clk := joinerKeyPublished(t, zone, records)
			r.mpzd.Lock()
			r.mpzd.DnssecPolicy.TTLS.DNSKEY, r.mpzd.DnssecPolicy.TTLS.MaxServed = uint32(tc.policy/time.Second), uint32(tc.policy/time.Second)
			r.mpzd.Unlock()
			delay := r.e.driver(zone).Policy.PropagationDelay
			clk.Advance(delay + tc.want - 30*time.Second)
			r.e.tickOwned()
			if n := ownKeysIn(t, r, zone, KeyStatePublished); n != 1 {
				t.Errorf("30 s before the delay and %s: %d of its keys are still published, want 1", tc.want, n)
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
	r, clk := joinerKeyPublished(t, zone, records)
	delay := r.e.driver(zone).Policy.PropagationDelay
	clk.Advance(delay + 90*time.Minute)

	var looks []func()
	r.conf.InternalMp.servedKeys = servedKeysBook{start: func(look func()) { looks = append(looks, look) }}
	r.e.tickOwned()
	if n := ownKeysIn(t, r, zone, KeyStatePublished); n != 1 || len(looks) == 0 {
		t.Fatalf("with its first look under way: %d of its keys still published after %d looks, want 1 and a look", n, len(looks))
	}
	looks[0]()
	r.e.tickOwned()
	if n := ownKeysIn(t, r, zone, KeyStatePublished); n != 1 {
		t.Errorf("past its copy's TTL and short of what its server serves: %d of its keys still published, want 1", n)
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
	// a look that can list no server says nothing of them all
	b.mu.Lock()
	b.zones[canonicalName(zone)].at = time.Time{}
	b.mu.Unlock()
	bare := &MPZoneData{ZoneData: &tdns.ZoneData{ZoneName: zone, ZoneStore: tdns.MapZone, Logger: r.mpzd.Logger, Data: core.NewNameMap[tdns.OwnerData]()}}
	if _, whole, looked := b.largest(bare); whole || !looked {
		t.Errorf("no server listed: whole %v, looked %v, want it not whole", whole, looked)
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

// keysWait is a joiner's keys' step as its leader waits for it: its KSK and ZSK
// active, its wait asked on a clock the test moves, and its looks run in place. What
// each nameserver answers is the test's.
type keysWait struct {
	t        *testing.T
	r        *signerAddRig
	wait     func() string
	now      time.Time
	ksk, zsk *dns.DNSKEY
	answers  map[string]func() (*core.RRset, error)
	asked    int
}

const (
	keysNS1 = "ns1.keys.example."
	keysNS2 = "ns2.keys.example."
)

func newKeysWait(t *testing.T, zone string) *keysWait {
	t.Helper()
	r := newSignerAddRig(t, zone, "owner")
	knownAs(t, r.store, zone, r.v)
	setZoneNS(t, zone, keysNS1, keysNS2)
	w := &keysWait{t: t, r: r, now: time.Now(), answers: map[string]func() (*core.RRset, error){}}
	r.conf.InternalMp.signerAdds.now = func() time.Time { return w.now }
	r.keys(KeyStateActive, KeyStateActive)
	mpzd, _ := Zones.Get(zone)
	for _, it := range mpzd.GetLastKeyInventory().Inventory {
		rr, err := dns.NewRR(it.KeyRR)
		if err != nil {
			t.Fatal(err)
		}
		if it.Flags&dns.SEP != 0 {
			w.ksk = rr.(*dns.DNSKEY)
		} else {
			w.zsk = rr.(*dns.DNSKEY)
		}
	}
	prev := servingKeysLookup
	servingKeysLookup = func(_ context.Context, _ string, ns string) (*core.RRset, error) {
		w.asked++
		if answer := w.answers[ns]; answer != nil {
			return answer()
		}
		return nil, errors.New("no answer")
	}
	t.Cleanup(func() { servingKeysLookup = prev })
	mint := signerAddStepsOf(Provider{Label: "a", Identity: signerAddSelf}, false)[1]
	w.wait = func() string { return mint.wait(r.conf, zone, w.now) }
	return w
}

// serves has ns answer with keys, at ttl.
func (w *keysWait) serves(ns string, ttl time.Duration, keys ...*dns.DNSKEY) {
	w.answers[ns] = func() (*core.RRset, error) {
		rrset := &core.RRset{}
		for _, k := range keys {
			c := *k
			c.Hdr.Ttl = uint32(ttl / time.Second)
			rrset.RRs = append(rrset.RRs, &c)
		}
		return rrset, nil
	}
}

func (w *keysWait) noData(ns string) {
	w.answers[ns] = func() (*core.RRset, error) {
		return nil, fmt.Errorf("no DNSKEY in the answer (NOERROR): %w", errServesNoRRset)
	}
}

func (w *keysWait) silent(ns string) { delete(w.answers, ns) }

// look moves the clock past the time between looks, and asks the wait, which looks.
func (w *keysWait) look() string {
	w.t.Helper()
	w.now = w.now.Add(signerAddLookEvery)
	return w.wait()
}

// after moves the clock by d, short of a new look unless it is long enough for one.
func (w *keysWait) after(d time.Duration) string {
	w.t.Helper()
	w.now = w.now.Add(d)
	return w.wait()
}

// delay has the provider's propagation delay be d, and b's announced be announced.
func (w *keysWait) delay(d time.Duration) {
	w.t.Helper()
	gst := &GossipStateTable{LocalID: roleA}
	gst.SetPropagationDelay(d)
	w.r.conf.InternalMp.AgentRegistry.GossipStateTable = gst
}

// copyHasDNSKEY has the zone's copy hold a DNSKEY RRset at ttl.
func (w *keysWait) copyHasDNSKEY(ttl time.Duration) {
	w.t.Helper()
	zd, _ := tdns.Zones.Get(w.r.zone)
	apex, err := zd.GetOwner(w.r.zone)
	if err != nil || apex == nil {
		w.t.Fatal(err)
	}
	k := testDnskey(w.t, w.r.zone, 256)
	k.Hdr.Ttl = uint32(ttl / time.Second)
	apex.RRtypes.Set(dns.TypeDNSKEY, core.RRset{Name: w.r.zone, Class: dns.ClassINET, RRtype: dns.TypeDNSKEY, RRs: []dns.RR{k}})
	zd.Data.Set(w.r.zone, *apex)
}

// The keys' step waits until every nameserver of the zone serves both the joiner's
// keys, and then the propagation delay and the largest TTL, to the second.
func TestAJoinersKeysStepWaitsForEveryNameserverAndThenDelayAndTTL(t *testing.T) {
	w := newKeysWait(t, "every.keys.adding.example.")
	w.delay(10 * time.Minute)
	w.serves(keysNS1, time.Hour, w.ksk, w.zsk)
	w.serves(keysNS2, time.Hour, w.ksk)
	got := w.look()
	if !strings.Contains(got, keysNS2) || strings.Contains(got, keysNS1) {
		t.Fatalf("ns2 without the ZSK, it waits for %q, want ns2 alone", got)
	}
	w.serves(keysNS2, 30*time.Minute, w.zsk)
	if got = w.look(); !strings.Contains(got, keysNS2) {
		t.Fatalf("ns2 without the KSK, it waits for %q, want ns2", got)
	}
	w.serves(keysNS2, 30*time.Minute, w.ksk, w.zsk)
	if got = w.look(); got == "" || strings.Contains(got, keysNS2) {
		t.Fatalf("every nameserver serves them, and it waits for %q, want the delay and the TTL", got)
	}
	whole := 10*time.Minute + time.Hour
	if got = w.after(whole - time.Second); got == "" {
		t.Error("a second short of the delay and the largest TTL, it waits for nothing")
	}
	if got = w.after(time.Second); got != "" {
		t.Errorf("past the delay and the largest TTL, it waits for %q", got)
	}
}

// The keys it waits for are those that sign: a later key of the joiner's, on its way,
// is the table's business (T3, T8).
func TestAJoinersKeysStepWaitsForTheKeysThatSign(t *testing.T) {
	w := newKeysWait(t, "sign.keys.adding.example.")
	no := false
	mpzd, _ := Zones.Get(w.r.zone)
	snap := *mpzd.GetLastKeyInventory()
	snap.Inventory = append(slices.Clone(snap.Inventory), invItem(t, w.r.zone, 256, KeyStateStandby, &no))
	mpzd.SetLastKeyInventory(&snap)
	w.serves(keysNS1, 0, w.ksk, w.zsk)
	w.serves(keysNS2, 0, w.ksk, w.zsk)
	if got := w.look(); got != "" {
		t.Errorf("both serve its active keys, and it waits for %q", got)
	}
}

// rollsZSK has a new ZSK of the joiner's active and the old one retired, by its
// signer's inventory.
func (w *keysWait) rollsZSK() *dns.DNSKEY {
	w.t.Helper()
	no := false
	mpzd, _ := Zones.Get(w.r.zone)
	snap := *mpzd.GetLastKeyInventory()
	snap.Inventory = slices.Clone(snap.Inventory)
	for i := range snap.Inventory {
		if snap.Inventory[i].Flags&dns.SEP == 0 {
			snap.Inventory[i].State = KeyStateRetired
		}
	}
	item := invItem(w.t, w.r.zone, 256, KeyStateActive, &no)
	snap.Inventory = append(snap.Inventory, item)
	mpzd.SetLastKeyInventory(&snap)
	rr, err := dns.NewRR(item.KeyRR)
	if err != nil {
		w.t.Fatal(err)
	}
	return rr.(*dns.DNSKEY)
}

// The looks are of the joiner's active keys. When those change, what was seen was of
// others: the wait starts over, a nameserver seen with the old ones has no credit for
// them, and a look under way for them counts for nothing. The largest TTL stays, as a
// cache may hold that RRset.
func TestNewActiveKeysStartAJoinersKeysWaitOver(t *testing.T) {
	const waiting = "the propagation delay"
	t.Run("the count", func(t *testing.T) {
		w := newKeysWait(t, "count.new.keys.adding.example.")
		w.serves(keysNS1, 5*time.Minute, w.ksk, w.zsk)
		w.serves(keysNS2, 5*time.Minute, w.ksk, w.zsk)
		if got := w.look(); !strings.Contains(got, waiting) {
			t.Fatalf("both serve its keys at 5m, it waits for %q", got)
		}
		zsk := w.rollsZSK()
		w.serves(keysNS1, time.Minute, w.ksk, zsk)
		w.serves(keysNS2, time.Minute, w.ksk, zsk)
		w.now = w.now.Add(5 * time.Minute) // the old keys' count is over
		if got := w.look(); !strings.Contains(got, waiting) {
			t.Fatalf("new keys just seen, it waits for %q", got)
		}
		if got := w.after(4 * time.Minute); !strings.Contains(got, waiting) {
			t.Fatalf("4m on, under the largest TTL seen, it waits for %q", got)
		}
		if got := w.after(time.Minute + time.Second); got != "" {
			t.Fatalf("the largest TTL passed, it waits for %q", got)
		}
	})
	t.Run("the same keys in another order", func(t *testing.T) {
		w := newKeysWait(t, "order.new.keys.adding.example.")
		w.serves(keysNS1, 5*time.Minute, w.ksk, w.zsk)
		w.serves(keysNS2, 5*time.Minute, w.ksk, w.zsk)
		if got := w.look(); !strings.Contains(got, waiting) {
			t.Fatalf("both serve its keys at 5m, it waits for %q", got)
		}
		mpzd, _ := Zones.Get(w.r.zone)
		snap := *mpzd.GetLastKeyInventory()
		snap.Inventory = slices.Clone(snap.Inventory)
		slices.Reverse(snap.Inventory)
		mpzd.SetLastKeyInventory(&snap)
		if got := w.after(5*time.Minute + time.Second); got != "" {
			t.Fatalf("the same keys and the TTL passed, it waits for %q", got)
		}
	})
	t.Run("a nameserver's history", func(t *testing.T) {
		w := newKeysWait(t, "history.new.keys.adding.example.")
		w.copyHasDNSKEY(time.Hour)
		w.serves(keysNS1, 0, w.ksk, w.zsk)
		w.serves(keysNS2, 0, w.ksk, w.zsk)
		if got := w.look(); got != "" {
			t.Fatalf("both serve its keys at TTL 0, it waits for %q", got)
		}
		zsk := w.rollsZSK()
		w.serves(keysNS1, 0, w.ksk, zsk)
		delete(w.answers, keysNS2)
		if got := w.look(); !strings.Contains(got, waiting) {
			t.Fatalf("ns2 silent, never seen with the new keys: no floor of the copy's TTL, it waits for %q", got)
		}
	})
	t.Run("a look under way", func(t *testing.T) {
		w := newKeysWait(t, "underway.new.keys.adding.example.")
		var looks []func()
		w.r.conf.InternalMp.signerAdds.start = func(look func()) { looks = append(looks, look) }
		w.serves(keysNS1, 0, w.ksk, w.zsk)
		w.serves(keysNS2, 0, w.ksk, w.zsk)
		w.look()
		w.rollsZSK()
		const unknown = "not known yet"
		if got := w.look(); !strings.Contains(got, unknown) || len(looks) != 2 {
			t.Fatalf("new keys: %d looks, it waits for %q", len(looks), got)
		}
		looks[0]() // the old keys' look ends: they serve those
		if got := w.wait(); !strings.Contains(got, unknown) {
			t.Fatalf("a look for the old keys counted, it waits for %q", got)
		}
		looks[1]() // the new keys' look: they don't serve those
		if got := w.wait(); !strings.Contains(got, keysNS1) || !strings.Contains(got, keysNS2) {
			t.Fatalf("neither serves the new keys, it waits for %q", got)
		}
	})
}

// A signer can't record another's key under a tag of its own, so it serves its own
// there, beside the joiner's other key. That isn't the joiner's key, and it holds the
// step. So does a key of the joiner's whose record can't be read.
func TestAnotherKeyUnderTheSameTagIsNotAJoinersKeyServed(t *testing.T) {
	w := newKeysWait(t, "same.tag.keys.adding.example.")
	w.serves(keysNS1, 0, w.ksk, w.zsk)
	w.serves(keysNS2, 0, sameTagOtherKey(t, w.ksk), w.zsk)
	if got := w.look(); !strings.Contains(got, keysNS2) {
		t.Fatalf("another KSK under its KSK's tag at ns2, it waits for %q, want ns2", got)
	}
	w.serves(keysNS2, 0, w.ksk, sameTagOtherKey(t, w.zsk))
	if got := w.look(); !strings.Contains(got, keysNS2) {
		t.Fatalf("another ZSK under its ZSK's tag at ns2, it waits for %q, want ns2", got)
	}
	w.serves(keysNS2, 0, w.ksk, w.zsk)
	if got := w.look(); got != "" {
		t.Fatalf("both serve its keys, and it waits for %q", got)
	}

	w = newKeysWait(t, "unreadable.keys.adding.example.")
	w.serves(keysNS1, 0, w.ksk, w.zsk)
	w.serves(keysNS2, 0, w.ksk, w.zsk)
	mpzd, _ := Zones.Get(w.r.zone)
	snap := *mpzd.GetLastKeyInventory()
	snap.Inventory = slices.Clone(snap.Inventory)
	snap.Inventory[0].KeyRR = ""
	mpzd.SetLastKeyInventory(&snap)
	if got := w.look(); !strings.Contains(got, keysNS1) || !strings.Contains(got, keysNS2) {
		t.Fatalf("a key whose record can't be read, it waits for %q, want both", got)
	}
}

// One that answers without the keys holds the step, by NODATA, or with an RRset that
// does not hold them, for as long as it does, and the wait starts when it serves them.
// One that loses them holds it again, and the wait starts over.
func TestANameserverAnsweringWithoutTheKeysHoldsAJoinersKeysStep(t *testing.T) {
	w := newKeysWait(t, "without.keys.adding.example.")
	w.serves(keysNS1, 0, w.ksk, w.zsk)
	w.noData(keysNS2)
	for range 3 {
		if got := w.look(); !strings.Contains(got, keysNS2) {
			t.Fatalf("NODATA at ns2, it waits for %q, want ns2", got)
		}
	}
	w.serves(keysNS2, 0, testDnskey(t, w.r.zone, 257))
	if got := w.after(24 * time.Hour); !strings.Contains(got, keysNS2) {
		t.Fatalf("another key at ns2, a day on, it waits for %q, want ns2", got)
	}
	w.serves(keysNS2, 5*time.Minute, w.ksk, w.zsk)
	if got := w.look(); got == "" {
		t.Fatal("ns2 has just come to serve them, and nothing is waited for: the wait began before it did")
	}
	w.noData(keysNS2)
	if got := w.after(time.Minute); !strings.Contains(got, keysNS2) {
		t.Fatalf("ns2 lost them, and it waits for %q, want ns2", got)
	}
	w.serves(keysNS2, 5*time.Minute, w.ksk, w.zsk)
	if got := w.look(); got == "" {
		t.Fatal("ns2 has them back, and nothing is waited for: the wait did not start over")
	}
	if got := w.after(5*time.Minute - time.Second); got == "" {
		t.Error("the TTL since it has them back has not passed, and nothing is waited for")
	}
	if got := w.after(time.Second); got != "" {
		t.Errorf("the TTL since it has them back has passed, and it waits for %q", got)
	}
}

// One that stays silent holds nothing, and has the wait count its copy's TTL at least:
// it may serve more than the others. Answering, it is counted by what it serves.
func TestASilentNameserverDoesNotHoldAJoinersKeysStep(t *testing.T) {
	t.Run("the copy's TTL is the floor", func(t *testing.T) {
		w := newKeysWait(t, "floor.keys.adding.example.")
		w.copyHasDNSKEY(2 * time.Hour)
		w.serves(keysNS1, 5*time.Minute, w.ksk, w.zsk)
		if got := w.look(); got == "" || strings.Contains(got, keysNS2) {
			t.Fatalf("ns2 silent, it waits for %q, want the TTL and not ns2", got)
		}
		if got := w.after(2*time.Hour - time.Second); got == "" {
			t.Error("short of its copy's TTL, nothing is waited for")
		}
		if got := w.after(time.Second); got != "" {
			t.Errorf("past its copy's TTL, it waits for %q", got)
		}
	})
	t.Run("above the copy's TTL the largest seen counts", func(t *testing.T) {
		w := newKeysWait(t, "above.keys.adding.example.")
		w.copyHasDNSKEY(5 * time.Minute)
		w.serves(keysNS1, time.Hour, w.ksk, w.zsk)
		w.look()
		if got := w.after(time.Hour - time.Second); got == "" {
			t.Error("short of the TTL served, nothing is waited for")
		}
		if got := w.after(time.Second); got != "" {
			t.Errorf("past the TTL served, it waits for %q", got)
		}
	})
	t.Run("every nameserver silent", func(t *testing.T) {
		w := newKeysWait(t, "allsilent.keys.adding.example.")
		w.copyHasDNSKEY(time.Hour)
		if got := w.look(); got == "" {
			t.Fatal("every nameserver silent, nothing is waited for: its copy's TTL is the floor")
		}
		if got := w.after(time.Hour); got != "" {
			t.Errorf("every nameserver silent, past its copy's TTL, it waits for %q", got)
		}
	})
	t.Run("answering at last, it lowers the floor", func(t *testing.T) {
		w := newKeysWait(t, "atlast.keys.adding.example.")
		w.copyHasDNSKEY(2 * time.Hour)
		w.serves(keysNS1, 5*time.Minute, w.ksk, w.zsk)
		w.look()
		w.serves(keysNS2, 5*time.Minute, w.ksk, w.zsk)
		w.look()
		if got := w.after(5 * time.Minute); got != "" {
			t.Errorf("both answer at 5m, and past that it waits for %q", got)
		}
	})
	t.Run("answering at last, without the keys, it holds", func(t *testing.T) {
		w := newKeysWait(t, "atlastno.keys.adding.example.")
		w.serves(keysNS1, 0, w.ksk, w.zsk)
		w.look()
		w.noData(keysNS2)
		if got := w.look(); !strings.Contains(got, keysNS2) {
			t.Errorf("NODATA from ns2 at last, it waits for %q, want ns2", got)
		}
	})
	t.Run("gone quiet with the keys, it has served what it served", func(t *testing.T) {
		w := newKeysWait(t, "quiet.keys.adding.example.")
		w.copyHasDNSKEY(2 * time.Hour)
		w.serves(keysNS1, 5*time.Minute, w.ksk, w.zsk)
		w.serves(keysNS2, 5*time.Minute, w.ksk, w.zsk)
		w.look()
		w.silent(keysNS2)
		w.look()
		if got := w.after(5 * time.Minute); got != "" {
			t.Errorf("ns2 seen with them, then silent, it waits for %q, want no floor", got)
		}
	})
	t.Run("gone quiet without the keys, it is silent", func(t *testing.T) {
		w := newKeysWait(t, "quietno.keys.adding.example.")
		w.copyHasDNSKEY(time.Hour)
		w.serves(keysNS1, 0, w.ksk, w.zsk)
		w.noData(keysNS2)
		w.look()
		w.silent(keysNS2)
		if got := w.look(); got == "" || strings.Contains(got, keysNS2) {
			t.Fatalf("ns2 gone quiet, it waits for %q, want the floor and not ns2", got)
		}
		if got := w.after(time.Hour); got != "" {
			t.Errorf("past its copy's TTL, it waits for %q", got)
		}
	})
}

// A look that says nothing of the nameservers is no silence: with no way to ask, or
// a copy that names none, the step waits.
func TestALookThatSaysNothingHoldsAJoinersKeysStep(t *testing.T) {
	w := newKeysWait(t, "nothing.keys.adding.example.")
	w.answers[keysNS1] = func() (*core.RRset, error) { return nil, fmt.Errorf("%s: %w", keysNS1, errIMRNotRunning) }
	if got := w.look(); !strings.Contains(got, "not known") {
		t.Fatalf("no IMR, it waits for %q, want what is not known", got)
	}
	if got := w.after(30 * 24 * time.Hour); !strings.Contains(got, "not known") {
		t.Fatalf("no IMR, a month on, it waits for %q, want what is not known", got)
	}
	setZoneNS(t, w.r.zone)
	w.serves(keysNS1, 0, w.ksk, w.zsk)
	if got := w.look(); !strings.Contains(got, "not known") {
		t.Fatalf("a copy that names none, it waits for %q, want what is not known", got)
	}
	setZoneNS(t, w.r.zone, keysNS1)
	if got := w.look(); got != "" {
		t.Errorf("its one nameserver serves them at TTL 0, and it waits for %q", got)
	}
}

// After a good look as well: it holds until the next good look, which goes on with
// the count where it was, since that look changed nothing of what was seen served.
func TestALookThatSaysNothingAfterAGoodOneHoldsAJoinersKeysStep(t *testing.T) {
	t.Run("no way to ask", func(t *testing.T) {
		w := newKeysWait(t, "blind.keys.adding.example.")
		w.serves(keysNS1, 5*time.Minute, w.ksk, w.zsk)
		w.serves(keysNS2, 5*time.Minute, w.ksk, w.zsk)
		if got := w.look(); got == "" || strings.Contains(got, "not known") {
			t.Fatalf("both serve them, it waits for %q, want the TTL", got)
		}
		good := w.answers[keysNS1]
		w.answers[keysNS1] = func() (*core.RRset, error) { return nil, fmt.Errorf("%s: %w", keysNS1, errIMRNotRunning) }
		if got := w.look(); !strings.Contains(got, "not known") {
			t.Fatalf("no IMR after a good look, it waits for %q, want what is not known", got)
		}
		if got := w.after(time.Hour); !strings.Contains(got, "not known") {
			t.Fatalf("no IMR, the count long over, it waits for %q, want what is not known", got)
		}
		w.answers[keysNS1] = good
		if got := w.look(); got != "" {
			t.Errorf("the next good look, the count long over, it waits for %q: the count started again", got)
		}
	})
	t.Run("a copy that names none, the count not over", func(t *testing.T) {
		w := newKeysWait(t, "blind-copy.keys.adding.example.")
		w.serves(keysNS1, 5*time.Minute, w.ksk, w.zsk)
		w.serves(keysNS2, 5*time.Minute, w.ksk, w.zsk)
		w.look()
		setZoneNS(t, w.r.zone)
		if got := w.look(); !strings.Contains(got, "not known") {
			t.Fatalf("a copy that names none, it waits for %q, want what is not known", got)
		}
		setZoneNS(t, w.r.zone, keysNS1, keysNS2)
		if got := w.look(); got == "" || strings.Contains(got, "not known") {
			t.Fatalf("named again, it waits for %q, want the rest of the TTL", got)
		}
		if got := w.after(5*time.Minute - 2*signerAddLookEvery); got != "" {
			t.Errorf("the TTL since the first good look has passed, and it waits for %q: the count started again", got)
		}
	})
	t.Run("a nameserver going silent is not this", func(t *testing.T) {
		w := newKeysWait(t, "blind-silent.keys.adding.example.")
		w.serves(keysNS1, 5*time.Minute, w.ksk, w.zsk)
		w.serves(keysNS2, 5*time.Minute, w.ksk, w.zsk)
		w.look()
		w.silent(keysNS1)
		w.silent(keysNS2)
		if got := w.look(); got == "" || strings.Contains(got, "not known") {
			t.Fatalf("both silent after serving them, it waits for %q, want the TTL", got)
		}
		if got := w.after(5 * time.Minute); got != "" {
			t.Errorf("both silent, the TTL over, it waits for %q: silence holds nothing", got)
		}
	})
}

// The wait ends only on a look that reports once it has run out, asked at once: the
// look due then runs in a goroutine of its own, and may find a nameserver that lost
// the keys, or nothing.
func TestAJoinersKeysStepEndsOnlyOnALookAfterItsWait(t *testing.T) {
	served := func(t *testing.T, zone string, ttl time.Duration) (*keysWait, *[]func()) {
		w := newKeysWait(t, zone)
		w.serves(keysNS1, ttl, w.ksk, w.zsk)
		w.serves(keysNS2, ttl, w.ksk, w.zsk)
		if got := w.look(); got == "" {
			t.Fatal("both have just come to serve them, and nothing is waited for")
		}
		var looks []func()
		w.r.conf.InternalMp.signerAdds.start = func(look func()) { looks = append(looks, look) }
		return w, &looks
	}
	t.Run("the look as it runs out says nothing", func(t *testing.T) {
		w, looks := served(t, "nothing.end.keys.adding.example.", 5*time.Minute)
		if got := w.after(5 * time.Minute); got == "" || len(*looks) != 1 {
			t.Fatalf("run out with a look under way: %d looks, it waits for %q, want that look", len(*looks), got)
		}
		w.answers[keysNS1] = func() (*core.RRset, error) { return nil, fmt.Errorf("%s: %w", keysNS1, errIMRNotRunning) }
		(*looks)[0]()
		if got := w.wait(); !strings.Contains(got, "not known") {
			t.Fatalf("no IMR at the look after it ran out, it waits for %q, want what is not known", got)
		}
	})
	t.Run("the look as it runs out finds one without them", func(t *testing.T) {
		w, looks := served(t, "without.end.keys.adding.example.", 5*time.Minute)
		if got := w.after(5 * time.Minute); got == "" || len(*looks) != 1 {
			t.Fatalf("run out with a look under way: %d looks, it waits for %q, want that look", len(*looks), got)
		}
		w.noData(keysNS2)
		(*looks)[0]()
		if got := w.wait(); !strings.Contains(got, keysNS2) {
			t.Fatalf("NODATA from ns2 at the look after it ran out, it waits for %q, want ns2", got)
		}
	})
	t.Run("a look under way as it runs out", func(t *testing.T) {
		w, looks := served(t, "underway.end.keys.adding.example.", 5*time.Minute)
		if got := w.after(5*time.Minute - time.Second); got == "" || len(*looks) != 1 {
			t.Fatalf("a second short: %d looks, it waits for %q", len(*looks), got)
		}
		if got := w.after(2 * time.Second); got == "" || len(*looks) != 1 {
			t.Fatalf("run out with that look under way: %d looks, it waits for %q, want that look", len(*looks), got)
		}
		(*looks)[0]()
		if got := w.wait(); got != "" {
			t.Errorf("that look reports them served, and it waits for %q", got)
		}
	})
	t.Run("asked at once", func(t *testing.T) {
		w, _ := served(t, "once.end.keys.adding.example.", 5*time.Second)
		w.r.conf.InternalMp.signerAdds.start = func(look func()) { look() }
		asked := w.asked
		if got := w.after(5 * time.Second); got != "" || w.asked == asked {
			t.Errorf("run out short of the time between looks: asked %d more, it waits for %q, want a look at once", w.asked-asked, got)
		}
	})
}

// What was served before the keys came counts: a cache may hold that RRset, without
// them, for as long as it was served with.
func TestAnAnswerBeforeTheKeysCountsInAJoinersWait(t *testing.T) {
	w := newKeysWait(t, "before.keys.adding.example.")
	w.serves(keysNS1, 24*time.Hour, testDnskey(t, w.r.zone, 257))
	w.serves(keysNS2, 5*time.Minute, w.ksk, w.zsk)
	w.look()
	w.serves(keysNS1, 5*time.Minute, w.ksk, w.zsk)
	w.look()
	if got := w.after(24*time.Hour - time.Second); got == "" {
		t.Error("ns1 served the RRset for a day just before, and nothing is waited for")
	}
	if got := w.after(time.Second); got != "" {
		t.Errorf("past the day, it waits for %q", got)
	}
}

// The wait asks at most once for each time between looks, and its book is the joiner's:
// another joiner's, or another serial's, starts with nothing.
func TestAJoinersWaitIsItsOwnAndAsksInTurn(t *testing.T) {
	w := newKeysWait(t, "own.keys.adding.example.")
	w.serves(keysNS1, time.Hour, w.ksk, w.zsk)
	w.serves(keysNS2, time.Hour, w.ksk, w.zsk)
	w.look()
	asked := w.asked
	w.after(signerAddLookEvery - time.Second)
	if w.asked != asked {
		t.Errorf("before the time between looks it asked %d nameservers more", w.asked-asked)
	}
	w.after(time.Second)
	if w.asked == asked {
		t.Error("past the time between looks it did not look again")
	}
	if got := w.after(time.Hour); got != "" {
		t.Fatalf("past the TTL it waits for %q", got)
	}
	b := &w.r.conf.InternalMp.signerAdds
	if got := b.keysPropagated(w.r.conf, w.r.zone, roleB); got == "" {
		t.Error("another joiner has the first's wait behind it")
	}
	b.mu.Lock()
	for _, l := range b.zones {
		l.serial++
	}
	b.mu.Unlock()
	if got := w.wait(); got == "" {
		t.Error("under another serial the first's wait stands: it looked, and its time has only begun")
	}
}

// The caches' time is the DS TTL alone, from its own look at the parent: no key's state
// stands behind it any more, so a new leader that knows nothing of the parent waits.
func TestTheCachesTimeWaitsForItsOwnLookAtTheParent(t *testing.T) {
	r := newSignerAddRig(t, "caches.look.adding.example.", "owner")
	knownAs(t, r.store, r.zone, r.v)
	caches := signerAddStepsOf(Provider{Label: "a", Identity: signerAddSelf}, false)[3]
	long := time.Now().Add(-48 * time.Hour)
	prev := parentDSLook
	parentDSLook = func(*Config, string) (parentDSSeen, error) { return parentDSSeen{}, errors.New("no answer") }
	t.Cleanup(func() { parentDSLook = prev })
	if got := caches.wait(r.conf, r.zone, long); !strings.Contains(got, "the parent") {
		t.Fatalf("the parent not known, it waits for %q, want the parent", got)
	}
	r.parentLooks()
	parentDSLook = func(*Config, string) (parentDSSeen, error) {
		return parentDSSeen{ttl: time.Hour}, nil
	}
	if got := caches.wait(r.conf, r.zone, time.Now()); !strings.Contains(got, "the DS TTL") {
		t.Errorf("the DS TTL just begun, it waits for %q", got)
	}
	if got := caches.wait(r.conf, r.zone, time.Now().Add(-time.Hour-time.Second)); got != "" {
		t.Errorf("the DS TTL passed, it waits for %q", got)
	}
}

// A parent server's reply is read by readServed's rules: a referral or a reply
// with no SOA says nothing of the zone's DS, and is no answer, not "no DS"; a DS
// another name owns is not the zone's (CodeRabbit on #374).
func TestAParentReferralIsNoAnswerForTheDS(t *testing.T) {
	const zone, parent = "child.parent.example.", "parent.example."
	rr := func(s string) dns.RR {
		r, err := dns.NewRR(s)
		if err != nil {
			t.Fatalf("NewRR %q: %v", s, err)
		}
		return r
	}
	ds := rr(zone + " 3600 IN DS 12345 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	otherDS := rr("other." + parent + " 3600 IN DS 54321 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	soa := rr(parent + " 3600 IN SOA ns1." + parent + " hostmaster." + parent + " 1 7200 1800 604800 300")
	ns := rr(zone + " 3600 IN NS ns1." + zone)
	query := new(dns.Msg)
	query.SetQuestion(zone, dns.TypeDS)
	reply := func(rcode int, answer, authority []dns.RR) *dns.Msg {
		r := new(dns.Msg)
		r.SetRcode(query, rcode)
		r.Answer, r.Ns = answer, authority
		return r
	}
	for _, c := range []struct {
		name    string
		r       *dns.Msg
		records int
		noReply bool
	}{
		{"the DS", reply(dns.RcodeSuccess, []dns.RR{ds, otherDS}, nil), 1, false},
		{"NODATA with the parent's SOA", reply(dns.RcodeSuccess, nil, []dns.RR{soa}), 0, false},
		{"NXDOMAIN with the parent's SOA", reply(dns.RcodeNameError, nil, []dns.RR{soa}), 0, false},
		{"a referral", reply(dns.RcodeSuccess, nil, []dns.RR{ns}), 0, true},
		{"NOERROR with no SOA", reply(dns.RcodeSuccess, nil, nil), 0, true},
		{"NXDOMAIN with no SOA", reply(dns.RcodeNameError, nil, nil), 0, true},
		{"another name's DS alone", reply(dns.RcodeSuccess, []dns.RR{otherDS}, nil), 0, true},
		{"SERVFAIL", reply(dns.RcodeServerFailure, nil, nil), 0, true},
	} {
		got, err := parentDSIn(c.r, query, "192.0.2.53:53")
		if (err != nil) != c.noReply || len(got) != c.records {
			t.Errorf("%s: %d records, err %v; want %d records, no answer %v", c.name, len(got), err, c.records, c.noReply)
		}
	}
	// every parent server refers: nothing is known, the zone is not unsigned
	refer := func(string) ([]dns.RR, error) { return parentDSIn(reply(dns.RcodeSuccess, nil, []dns.RR{ns}), query, "x") }
	if seen, err := dsAtEveryServer([]string{"a", "b"}, refer); err == nil || seen.unsigned {
		t.Errorf("every parent server refers: seen %+v, err %v; want no answer", seen, err)
	}
}

// A look at the joiner's keys that finds no nameserver's address asked nothing,
// and says nothing of them, as one with no IMR: the keys step is not let go on
// silent servers alone. One nameserver with no address is silent (CodeRabbit on
// #374).
func TestALookWithNoNameserverAddressIsBlind(t *testing.T) {
	const zone = "blind.adding.signer.example."
	const other = "ns.p2.example."
	k := testDnskey(t, zone, 256)
	r := newSignerRig(t, zone, append(sigRecords(`serial="5" servers="us,p2" signers="p2"`), `3600 IN NS `+other)...)
	resolves := map[string]bool{}
	prev := servingKeysLookup
	servingKeysLookup = func(_ context.Context, _ string, ns string) (*core.RRset, error) {
		if !resolves[ns] {
			return nil, fmt.Errorf("%w for %s", errNoAddress, ns)
		}
		return &core.RRset{RRs: []dns.RR{k}}, nil
	}
	t.Cleanup(func() { servingKeysLookup = prev })
	if seen, err := lookForJoinerKeys(r.mpzd, []*dns.DNSKEY{k}); err == nil {
		t.Errorf("no nameserver has an address: the look saw %+v, want it blind", seen)
	}
	resolves[other] = true
	seen, err := lookForJoinerKeys(r.mpzd, []*dns.DNSKEY{k})
	if err != nil || len(seen.silent) != 1 || len(seen.with) != 1 {
		t.Errorf("one nameserver has an address: the look saw %+v, err %v; want one silent, one with the keys", seen, err)
	}
}
