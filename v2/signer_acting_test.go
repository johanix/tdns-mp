/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Plan S11, the signer's side: it acts by what its agent hands it, not by
// its own copy of the zone (design 3.5, rule 5), and its inventory says what
// it holds.

const sigUs = "agent.us.example." // the signer's own agent, provider us

// sigRecords are a zone's instructions with us, p2 and p3 listed ON and the
// HSYNCPARAM record param.
func sigRecords(param string) []string {
	return []string{
		`3600 IN HSYNC3 ON us agent.us.example. .`,
		`3600 IN HSYNC3 ON p2 agent.p2.example. .`,
		`3600 IN HSYNC3 ON p3 agent.p3.example. .`,
		`3600 IN HSYNCPARAM ` + param,
	}
}

type signerRig struct {
	conf   *Config
	mpzd   *MPZoneData
	kdb    *tdns.KeyDB
	e      *KeyLifecycleEngine
	owner  *MPKeyLifecycleOwner
	store  *actingStore
	mu     sync.Mutex
	pushed int // inventories pushed to the agent
}

// newSignerRig is provider us's signer with zone loaded, its copy holding
// records, the multi-provider data of its first load, its key machine taking
// the zone, and its hand-overs kept in its KeyDB.
func newSignerRig(t *testing.T, zone string, records ...string) *signerRig {
	t.Helper()
	asMPDaemon(t, AppTypeMPSigner)
	kdb := newMPTestKeyDB(t)
	mp := &MultiProviderConf{Role: "signer", Identity: "signer.us.example.", Agents: []*PeerConf{{Identity: sigUs}}}
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(mp)
	conf.Config.Internal.KeyDB = kdb
	r := &signerRig{conf: conf, kdb: kdb, mpzd: signerZoneWith(t, zone, kdb, records...)}
	r.mpzd.EnsureMP()
	apex, _ := r.mpzd.OwnerForAnalysis(zone)
	r.mpzd.populateMPdata(mp, nextSigningSet(apex, nil))
	r.owner = NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
	r.e = NewKeyLifecycleEngine(conf, r.owner)
	r.e.wire.push = func(*Config, string, []uint16) {}
	conf.InternalMp.KeyLifecycle = r.e
	r.owner.Take(zone)
	r.store = withActing(t, NewHsyncDB(kdb))
	hdb := NewHsyncDB(kdb)
	if _, err := hdb.DB.Exec(HsyncTables["MPKeyHold"]); err != nil {
		t.Fatal(err)
	}
	holds, err := loadSignerHolds(hdb)
	if err != nil {
		t.Fatal(err)
	}
	conf.InternalMp.SignerHolds = holds
	prev := pushSignerInventory
	pushSignerInventory = func(*Config, string) {
		r.mu.Lock()
		r.pushed++
		r.mu.Unlock()
	}
	t.Cleanup(func() { pushSignerInventory = prev })
	return r
}

// signerZoneWith is signerTestZone with records at the apex, as served.
func signerZoneWith(t *testing.T, name string, kdb *tdns.KeyDB, records ...string) *MPZoneData {
	t.Helper()
	text := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 1800 604800 7200\n"+
		"%s 3600 IN NS ns1.%s\nns1.%s 3600 IN A 192.0.2.1\n", name, name, name, name, name, name)
	for _, r := range records {
		text += name + " " + r + "\n"
	}
	zd := &tdns.ZoneData{
		ZoneName:  name,
		ZoneStore: tdns.MapZone,
		ZoneType:  tdns.Primary,
		Logger:    log.New(io.Discard, "", 0),
		Options:   map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
		KeyDB:     kdb,
		DnssecPolicy: &tdns.DnssecPolicy{
			Mode:         tdns.DnssecPolicyModeKSKZSK,
			KSKAlgorithm: dns.ED25519,
			ZSKAlgorithm: dns.ED25519,
			SigValidity:  tdns.PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
		},
	}
	if _, _, err := zd.ReadZoneData(text, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	tdns.Zones.Set(name, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(name)
		Zones.Invalidate(name)
	})
	mpzd, ok := Zones.Get(name)
	if !ok {
		t.Fatal("wrapper not found")
	}
	mpzd.Lock()
	mpzd.Ready, mpzd.Status = true, tdns.ZoneStatusReady
	mpzd.Unlock()
	mpzd.InstallInitialSnapshot()
	return mpzd
}

// hand is the signer taking h from sender, as its message handler does.
func (r *signerRig) hand(h *ActingHandover, sender string) {
	r.conf.signerTakeHandover(&KeystateSignalMsg{SenderID: sender, Zone: h.Zone, Signal: "acting", Acting: h})
}

func (r *signerRig) pushes() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pushed
}

// foreignRows are the key tags of the zone's foreign rows.
func (r *signerRig) foreignRows(t *testing.T) []uint16 {
	t.Helper()
	inv, err := tdns.GetKeyInventory(r.kdb, r.mpzd.ZoneName)
	if err != nil {
		t.Fatal(err)
	}
	var out []uint16
	for _, it := range inv {
		if it.State == DnskeyStateForeign {
			out = append(out, it.KeyTag)
		}
	}
	return out
}

func (r *signerRig) foreignKey(t *testing.T, flags uint16) uint16 {
	t.Helper()
	k := testDnskey(t, r.mpzd.ZoneName, flags)
	if err := insertForeignKeyRow(r.kdb, r.mpzd.ZoneName, k.KeyTag(), k, "ED25519"); err != nil {
		t.Fatal(err)
	}
	return k.KeyTag()
}

// incomingCopy is a copy of the zone holding records, as a refresh brings
// it, for MPPreRefresh.
func incomingCopy(t *testing.T, zone string, records ...string) *tdns.ZoneData {
	t.Helper()
	src := instrTestZone(t, "incoming."+zone, records...)
	zd := &tdns.ZoneData{ZoneName: zone, ZoneStore: tdns.MapZone, ZoneType: tdns.Primary, Logger: src.Logger,
		Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}, Data: src.Data}
	if apex, _ := src.GetOwner(src.ZoneName); apex != nil {
		cp := *apex
		cp.Name = zone
		zd.Data.Set(zone, cp)
	}
	return zd
}

// A signer whose copy does not name it a signer signs once its agent hands
// it a serial that does, at once and through a refresh of the same copy:
// its inline-signing, its multi-signer mode and its key machine follow the
// sets handed, and its inventory then goes to its agent.
func TestTheSignerSignsByTheHandedSerialNotItsCopy(t *testing.T) {
	const zone = "copy.signer.example."
	copyRecords := sigRecords(`serial="5" servers="us,p2" signers="p2"`)
	r := newSignerRig(t, zone, copyRecords...)
	if r.mpzd.MP.MPdata.WeAreSigner || r.e.wire.IsSigner(zone) {
		t.Fatal("the copy does not name us a signer, and the signer signs: the test does not tell")
	}
	r.hand(handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)...), sigUs)
	if r.pushes() != 1 {
		t.Errorf("%d inventories pushed after the hand-over, want one", r.pushes())
	}
	check := func(when string) {
		t.Helper()
		if d := r.mpzd.MP.MPdata; d == nil || !d.WeAreSigner || d.OtherSigners != 1 {
			t.Errorf("%s: the multi-provider data %+v, want a signer with one other", when, d)
		}
		if !r.mpzd.Options[tdns.OptInlineSigning] || !r.mpzd.MPOptions[tdns.OptMultiSigner] {
			t.Errorf("%s: inline-signing %v, multi-signer %v; want both on", when, r.mpzd.Options[tdns.OptInlineSigning], r.mpzd.MPOptions[tdns.OptMultiSigner])
		}
		if !r.e.wire.IsSigner(zone) || !slices.Equal(r.e.wire.OtherSigners(zone), []string{"p2"}) {
			t.Errorf("%s: the key machine's signer %v, others %v; want us, with p2", when, r.e.wire.IsSigner(zone), r.e.wire.OtherSigners(zone))
		}
	}
	check("at the hand-over")
	if line := signerActingLine(zone); !strings.HasPrefix(line, "acting by 6, handed at ") {
		t.Errorf("the status says %q", line)
	}

	incoming := incomingCopy(t, zone, copyRecords...)
	r.mpzd.MPPreRefresh(incoming, nil, nil, r.conf.MpConfig())
	check("through a refresh of the copy")
	if !incoming.Options[tdns.OptInlineSigning] {
		t.Error("the copy the refresh publishes is not signed")
	}
}

// From S7 a copy newer than the hand-over is not acted by: its agent may
// refuse that serial. The signer signs by the serial handed.
func TestASignersCopyNewerThanTheHandOverIsNotActedBy(t *testing.T) {
	const zone = "newer.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)...)
	r.hand(handoverFor(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us"`)...), sigUs)
	if others := r.e.wire.OtherSigners(zone); len(others) != 0 {
		t.Errorf("the other signers %v, want none by the serial handed", others)
	}
	if line := signerActingLine(zone); !strings.HasPrefix(line, "acting by 5, handed at ") {
		t.Errorf("the status says %q", line)
	}
}

// A hand-over computes the multi-provider data on a wrapper, outside the
// zone's lock, while a status read ranges over the zone's options map
// without one: the options the hand-over sets go in a map of their own, and
// the one the zone held is not written (CodeRabbit on tdns-mp #299).
func TestAHandOverWritesNoOptionsMapTheZoneHeld(t *testing.T) {
	const zone = "options.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us"`)...)
	before := r.mpzd.MP.MPdata.Options
	if before[tdns.OptMultiSigner] {
		t.Fatal("one signer, and multi-signer: the test does not tell")
	}
	r.hand(handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)...), sigUs)
	if !r.mpzd.MP.MPdata.Options[tdns.OptMultiSigner] {
		t.Fatal("a hand-over of two signers did not set multi-signer")
	}
	if before[tdns.OptMultiSigner] {
		t.Error("the hand-over wrote the options map the zone held before it")
	}
}

// The inventory reads whether the signer signs the zone under the zone's
// lock, under which a hand-over replaces the multi-provider data (cubic on
// tdns-mp #299; go test -race tells). Every hand-over here leaves us out of
// the signers, so the inventory stops at that read: past it, the key
// machine reads the zone's options without a lock while a hand-over that
// names us a signer sets them (tdns #981).
func TestAnInventoryDuringAHandOverRacesNothing(t *testing.T) {
	const zone = "race.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="p2"`)...)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				r.conf.inventoryMarksOf(zone, nil)
			}
		}
	}()
	for serial := 6; serial < 10; serial++ {
		signers := "p2,p3"
		if serial%2 == 0 {
			signers = "p2"
		}
		r.hand(handoverFor(t, zone, sigRecords(fmt.Sprintf(`serial="%d" servers="us,p2" signers="%s"`, serial, signers))...), sigUs)
	}
	close(done)
	wg.Wait()
	if m := r.conf.inventoryMarksOf(zone, nil); !m.notSigning {
		t.Error("after hand-overs that leave us out of the signers, the inventory says signing")
	}
}

// A hand-over and a refresh compute and set the zone's multi-provider data
// one at a time (mpDataLock; cubic and CodeRabbit on tdns-mp #299): while
// the lock is held, neither sets it, and each does once it is free.
func TestAHandOverAndARefreshSetTheMultiProviderDataOneAtATime(t *testing.T) {
	const zone = "onebyone.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
	weAreSigner := func() bool {
		r.mpzd.Lock()
		defer r.mpzd.Unlock()
		return r.mpzd.MP.MPdata != nil && r.mpzd.MP.MPdata.WeAreSigner
	}
	mu := mpDataLock(zone)
	held := func(what string, act func()) {
		t.Helper()
		mu.Lock()
		done := make(chan struct{})
		go func() {
			act()
			close(done)
		}()
		select {
		case <-done:
			t.Errorf("%s set the multi-provider data while the lock was held", what)
		case <-time.After(200 * time.Millisecond):
		}
		mu.Unlock()
		<-done
	}
	h := handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="p2"`)...)
	held("a hand-over", func() { r.hand(h, sigUs) })
	if weAreSigner() {
		t.Error("the hand-over that leaves us out of the signers did not set it once the lock was free")
	}
	// a copy newer than the hand-over: the signer acts by the hand-over (S7),
	// and the refresh sets the data anew by it
	r.mpzd.Lock()
	before := r.mpzd.MP.MPdata
	r.mpzd.Unlock()
	incoming := incomingCopy(t, zone, sigRecords(`serial="7" servers="us,p2" signers="us,p2"`)...)
	held("a refresh", func() { r.mpzd.MPPreRefresh(incoming, nil, nil, r.conf.MpConfig()) })
	r.mpzd.Lock()
	after := r.mpzd.MP.MPdata
	r.mpzd.Unlock()
	if after == before {
		t.Error("the refresh did not set the multi-provider data once the lock was free")
	}
	// by the hand-over: p2 signs, we do not (cubic on tdns-mp #311)
	if after == nil || after.WeAreSigner || after.OtherSigners != 1 {
		t.Errorf("the refresh by a newer copy that names us a signer set %+v over the hand-over", after)
	}
}

// The re-sign a hand-over or a refresh asks for is asked once mpDataLock is
// free (cubic on tdns-mp #299): the request can wait on a full ResignQ, and
// the zone's refreshes and hand-overs would wait behind it.
func TestTheReSignRequestWaitsOutsideTheLock(t *testing.T) {
	const zone = "resign.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="p2"`)...)
	q := make(chan tdns.ResignRequest)
	prev := tdns.Conf.Internal.ResignQ
	tdns.Conf.Internal.ResignQ = q
	t.Cleanup(func() { tdns.Conf.Internal.ResignQ = prev })
	mu := mpDataLock(zone)
	read := func(f func() bool) func() bool {
		return func() bool {
			r.mpzd.Lock()
			defer r.mpzd.Unlock()
			return f()
		}
	}
	// act asks for a re-sign that nothing takes; once moved says it is past
	// what it sets, the lock is to be free while it waits.
	asks := func(what string, moved func() bool, act func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			act()
			close(done)
		}()
		free := false
		for end := time.Now().Add(5 * time.Second); !free && time.Now().Before(end); time.Sleep(time.Millisecond) {
			if moved() && mu.TryLock() {
				mu.Unlock()
				free = true
			}
		}
		if !free {
			t.Errorf("%s held mpDataLock while it asked for its re-sign", what)
		}
		select {
		case <-q:
		case <-done:
			t.Fatalf("%s asked for no re-sign: the test does not tell", what)
		}
		<-done
	}
	asks("a hand-over that switches inline-signing on",
		read(func() bool { return r.mpzd.MP.MPdata != nil && r.mpzd.MP.MPdata.WeAreSigner }),
		func() {
			r.hand(handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)...), sigUs)
		})
	k := testDnskey(t, zone, 256)
	records := append(sigRecords(`serial="6" servers="us,p2" signers="us,p2"`),
		fmt.Sprintf("3600 IN DNSKEY %d %d %d %s", k.Flags, k.Protocol, k.Algorithm, k.PublicKey))
	incoming := incomingCopy(t, zone, records...)
	asks("a refresh that brings p2's DNSKEY",
		func() bool { return len(r.foreignRows(t)) > 0 },
		func() { r.mpzd.MPPreRefresh(incoming, nil, nil, r.conf.MpConfig()) })
}

// The other signers' DNSKEYs stay, as foreign rows, while the sets handed
// keep them, whatever the copy says; a hand-over that ends multi-signer
// mode drops them.
func TestTheSignerKeepsTheOtherSignersDNSKEYsUntilHanded(t *testing.T) {
	const zone = "keep.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
	r.hand(handoverFor(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...), sigUs)
	kt := r.foreignKey(t, 256)

	// the copy drops p2 and its key, at the serial handed
	incoming := incomingCopy(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us"`)...)
	r.mpzd.MPPreRefresh(incoming, nil, nil, r.conf.MpConfig())
	if !slices.Contains(r.foreignRows(t), kt) || !r.mpzd.MPOptions[tdns.OptMultiSigner] {
		t.Fatalf("by its copy the signer dropped p2's key (rows %v) or multi-signer mode (%v)", r.foreignRows(t), r.mpzd.MPOptions[tdns.OptMultiSigner])
	}

	// and one the copy still carried, which no copy has judged since
	served := r.foreignKey(t, 257)

	r.hand(handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="us"`)...), sigUs)
	if rows := r.foreignRows(t); len(rows) != 0 || r.mpzd.MPOptions[tdns.OptMultiSigner] {
		t.Errorf("handed a serial with no other signer: foreign rows %v (of %d and %d), multi-signer %v; want none, off", rows, kt, served, r.mpzd.MPOptions[tdns.OptMultiSigner])
	}
}

// Whose confirmations a key's distribution expects is KeyConfirmers; whose
// KSKs have a DS is DSSigners; who signs is Signing. Each set is read on
// its own.
func TestTheExpectedSetFollowsKeyConfirmers(t *testing.T) {
	const zone = "confirmers.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2,p3" signers="us,p2,p3"`)...)
	h := handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2,p3" signers="us,p2,p3"`)...)
	us, p2, p3 := Provider{"us", sigUs}, Provider{"p2", "agent.p2.example."}, Provider{"p3", "agent.p3.example."}
	h.Sets.KeyConfirmers = []Provider{us, p2}
	h.Sets.DSSigners = []Provider{us, p3}
	r.hand(h, sigUs)
	if got := r.e.wire.OtherSigners(zone); !slices.Equal(got, []string{"p2"}) {
		t.Errorf("the confirmations expected from %v, want p2", got)
	}
	if got := r.e.wire.DSSigners(zone); !slices.Equal(got, []string{"p3"}) {
		t.Errorf("the DS signers %v, want p3", got)
	}
	if others, signs := otherSignerLabels(r.mpzd, r.conf.MpConfig()); !signs || !slices.Equal(others, []string{"p2", "p3"}) {
		t.Errorf("the foreign rows kept for %v (a signer: %v), want p2 and p3", others, signs)
	}
	h7 := handoverFor(t, zone, sigRecords(`serial="7" servers="us,p2,p3" signers="us,p2,p3"`)...)
	h7.Sets.Signing = []Provider{p2, p3}
	r.hand(h7, sigUs)
	if r.e.wire.IsSigner(zone) || r.e.wire.OtherSigners(zone) != nil {
		t.Error("a provider the sets handed do not have sign is still a signer to its key machine")
	}
}

// A hand-over that changes whose confirmations are expected moves every
// distribution in flight to the providers expected now (SignersChanged).
func TestAHandOverThatChangesTheConfirmersCallsSignersChanged(t *testing.T) {
	const zone = "joiner.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
	r.hand(handoverFor(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...), sigUs)
	r.e.tickOwned(map[string]keyPause{})
	l := r.e.driver(zone)
	if l == nil || len(l.InFlight()) == 0 {
		t.Fatal("no distribution in flight after the first tick: the test does not tell")
	}
	r.hand(handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2,p3" signers="us,p2,p3"`)...), sigUs)
	for _, d := range l.InFlight() {
		if !slices.Equal(d.Expected, []string{"p2", "p3"}) {
			t.Errorf("key %d expects %v, want p2 and p3", d.KeyId, d.Expected)
		}
	}
}

// The ds of another provider's KSK follows DSSigners as handed.
func TestForeignDSFollowsTheHandedDSSigners(t *testing.T) {
	const zone = "ds.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p3" signers="us,p3"`)...)
	r.hand(handoverFor(t, zone, sigRecords(`serial="5" servers="us,p3" signers="us,p3"`)...), sigUs)
	kt := r.foreignKey(t, 257)
	yes := true
	r.e.ForeignWord(zone, []core.ForeignKeyState{{Provider: "p3", KeyState: core.KeyState{KeyTag: kt, State: KeyStateActive, DS: &yes}}}, []string{"p3"})
	ds := func() *bool {
		t.Helper()
		inv, err := tdns.GetKeyInventory(r.kdb, zone)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range inv {
			if it.KeyTag == kt {
				return it.DS
			}
		}
		t.Fatal("p3's key has no row")
		return nil
	}
	if d := ds(); d == nil || !*d {
		t.Fatalf("p3 among the DS signers: ds %v, want 1", d)
	}
	h := handoverFor(t, zone, sigRecords(`serial="6" servers="us,p3" signers="us,p3"`)...)
	h.Sets.DSSigners = []Provider{{"us", sigUs}}
	r.hand(h, sigUs)
	if d := ds(); d == nil || *d {
		t.Errorf("p3 handed out of the DS signers: ds %v, want 0", d)
	}
}

// The inventory says what the signer holds: nothing before a hand-over, the
// one held after it, on the wire as the agent reads it.
func TestTheInventoryCarriesWhatTheSignerHolds(t *testing.T) {
	const zone = "held.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
	if m := r.conf.inventoryMarksOf(zone, nil); m.acting != nil {
		t.Fatalf("handed nothing, the inventory says %s", m.acting)
	}
	h := handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="us,p2"`)...)
	r.hand(h, sigUs)
	msg, err := keystateAppMessage(inventoryRequest("signer.us.example.", zone, nil, true, nil, r.conf.inventoryMarksOf(zone, nil)), sigUs)
	if err != nil {
		t.Fatal(err)
	}
	var p DnsKeystatePayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Acting == nil || !p.Acting.sameAs(h) {
		t.Errorf("the inventory on the wire says it holds %s, want %s", p.Acting, h)
	}
}

// For each key waiting in mpdist, the inventory names the other signers
// whose "applied" is missing.
func TestTheInventoryNamesTheMissingConfirmers(t *testing.T) {
	const zone = "waits.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2,p3" signers="us,p2,p3"`)...)
	r.e.tickOwned(map[string]keyPause{})
	l := r.e.driver(zone)
	inflight := l.InFlight()
	if len(inflight) == 0 {
		t.Fatal("no key in flight after the first tick: the test does not tell")
	}
	first := inflight[0].KeyId
	if _, _, err := l.Confirm(first, "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	m := r.conf.inventoryMarksOf(zone, nil)
	if got := m.waitsOn[first]; !slices.Equal(got, []string{"p3"}) {
		t.Errorf("key %d waits on %v, want p3", first, got)
	}
	for _, d := range inflight[1:] {
		if got := m.waitsOn[d.KeyId]; !slices.Equal(got, []string{"p2", "p3"}) {
			t.Errorf("key %d waits on %v, want p2 and p3", d.KeyId, got)
		}
	}
}

// The inventory carries the signer's own reading of rolloverUnderWay: keys
// on their way in are a rollover under way; a zone it does not sign has
// none.
func TestTheInventoryCarriesTheRolloverPredicate(t *testing.T) {
	const zone = "rollover.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
	items := func() []KeyInventoryItem {
		inv, err := tdns.GetKeyInventory(r.kdb, zone)
		if err != nil {
			t.Fatal(err)
		}
		return inv
	}
	if m := r.conf.inventoryMarksOf(zone, items()); m.rollover {
		t.Fatal("a rollover under way with no key at all")
	}
	r.e.tickOwned(map[string]keyPause{})
	if m := r.conf.inventoryMarksOf(zone, items()); !m.rollover || m.notSigning {
		t.Errorf("keys in mpdist: rollover %v, not signing %v; want a rollover under way at a signer", m.rollover, m.notSigning)
	}
	r.hand(handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="p2"`)...), sigUs)
	if m := r.conf.inventoryMarksOf(zone, items()); m.rollover || !m.notSigning {
		t.Errorf("handed out of the signers: rollover %v, not signing %v; want no rollover, not signing", m.rollover, m.notSigning)
	}
}

// What the signer was handed survives a restart: read from the KeyDB before
// the zones' first load.
func TestTheSignersHandedSerialSurvivesARestart(t *testing.T) {
	const zone = "restart.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
	r.hand(handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="us"`)...), sigUs)
	again := withActing(t, NewHsyncDB(r.kdb))
	held, ok := again.get(zone)
	if !ok || held.handover.Serial != 6 {
		t.Fatalf("after a restart the signer holds %+v, want serial 6", held.handover)
	}
	if got := r.e.wire.OtherSigners(zone); len(got) != 0 {
		t.Errorf("after a restart the signer expects %v, want nobody by the serial handed", got)
	}
}

// A signer handed nothing whose copy has no reading (no serial=, an owner
// error since #308) is provisional, and starts no multi-provider work for
// the zone: it signs nothing by that copy. A copy at serial="0" reads, and
// its signer waits for its agent (decision 107).
func TestASignersFirstLoadWithNothingHandedAndNoReadingIsProvisional(t *testing.T) {
	const zone = "provisional.signer.example."
	r := newSignerRig(t, zone, sigRecords(`servers="us,p2" signers="us,p2"`)...)
	if line := signerActingLine(zone); line != "provisional" {
		t.Errorf("the status says %q, want provisional", line)
	}
	if r.e.wire.IsSigner(zone) || r.e.wire.OtherSigners(zone) != nil {
		t.Error("a signer whose copy has no reading signs by it")
	}
	const zero = "zero.signer.example."
	newSignerRig(t, zero, sigRecords(`serial="0" servers="us,p2" signers="us,p2"`)...)
	if line := signerActingLine(zero); line != "waiting for its agent's hand-over" {
		t.Errorf("at serial 0 the status says %q, want it waiting for its agent's hand-over", line)
	}
}

// A signer handed nothing whose copy carries a serial waits for its agent,
// and meanwhile signs by the signing set it last signed by: a copy that
// drops the other signer changes neither its multi-signer mode nor its
// foreign rows.
func TestASignerWithNothingHandedAndASerialKeepsItsForeignRows(t *testing.T) {
	const zone = "waiting.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
	if err := saveSigningSet(r.kdb, zone, signingSet{"us": sigUs, "p2": "agent.p2.example."}); err != nil {
		t.Fatal(err)
	}
	r.mpzd.MP.MPdata.Signing = nil // a start: the set is the keystore's
	kt := r.foreignKey(t, 256)
	if line := signerActingLine(zone); line != "waiting for its agent's hand-over" {
		t.Errorf("the status says %q", line)
	}
	incoming := incomingCopy(t, zone, `3600 IN HSYNC3 ON us agent.us.example. .`, `3600 IN HSYNCPARAM serial="6" servers="us" signers="us"`)
	r.mpzd.MPPreRefresh(incoming, nil, nil, r.conf.MpConfig())
	if !r.mpzd.MPOptions[tdns.OptMultiSigner] || !slices.Contains(r.foreignRows(t), kt) {
		t.Errorf("waiting, the signer took its copy's roles: multi-signer %v, foreign rows %v", r.mpzd.MPOptions[tdns.OptMultiSigner], r.foreignRows(t))
	}
}

// A signer handed nothing whose copy drops it altogether, its HSYNC3
// record included, still waits: its key machine runs by the signing set it
// last signed by, with the label its identity has there (rule 5).
func TestASignerThatWaitsKeepsItsRolesWhenItsCopyDropsIt(t *testing.T) {
	const zone = "dropped.waiting.signer.example."
	r := newSignerRig(t, zone, `3600 IN HSYNC3 ON p2 agent.p2.example. .`, `3600 IN HSYNCPARAM serial="6" servers="p2" signers="p2"`)
	if err := saveSigningSet(r.kdb, zone, signingSet{"us": sigUs, "p2": "agent.p2.example."}); err != nil {
		t.Fatal(err)
	}
	if !r.e.wire.IsSigner(zone) || !slices.Equal(r.e.wire.OtherSigners(zone), []string{"p2"}) {
		t.Errorf("waiting, the signer took its copy's roles: signs %v, expects confirmations from %v", r.e.wire.IsSigner(zone), r.e.wire.OtherSigners(zone))
	}
}

// The hold is a field of the hand-over (S6, folded in by S11). The agent
// hands it while the zone is frozen. The signer, handed it, holds the
// zone's key machine and its inventory says so; a later hand-over without
// it lets it go, and the earlier one arriving after that is refused as
// older, so the latest word stands whatever the order of arrival.
func TestTheHoldIsAFieldOfTheHandOver(t *testing.T) {
	fr := newFreezeRig(t, "field.hold.freeze.example.")
	q := fr.withSigner()
	fr.agree()
	if h := lastHanded(t, signerSent(t, q, 2)); !h.Sets.Hold {
		t.Error("the agent's hand-over of a frozen zone carries no hold")
	}

	const zone = "hold.signer.example."
	records := sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)
	r := newSignerRig(t, zone, records...)
	on := handoverFor(t, zone, records...)
	on.Sets.Hold = true
	off := handoverFor(t, zone, records...)
	off.Made = on.Made.Add(time.Second)
	r.hand(on, sigUs)
	if !r.conf.InternalMp.SignerHolds.held(zone) || !r.conf.inventoryMarksOf(zone, nil).hold {
		t.Fatal("handed the hold, the signer does not hold the zone's key machine by its inventory")
	}
	r.hand(off, sigUs)
	if r.conf.InternalMp.SignerHolds.held(zone) {
		t.Fatal("handed the zone without the hold, the signer still holds its key machine")
	}
	late := *on
	r.hand(&late, sigUs)
	if r.conf.InternalMp.SignerHolds.held(zone) {
		t.Error("an earlier hand-over with the hold, arriving last, put the hold back")
	}
}

// The signer takes a hand-over only from its own agent.
func TestAKeystateActingFromAnotherSenderIsRefused(t *testing.T) {
	const zone = "sender.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
	r.hand(handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="p2"`)...), "agent.p2.example.")
	if _, held := r.store.get(zone); held {
		t.Error("a hand-over from another provider's agent was taken")
	}
	if !r.e.wire.IsSigner(zone) {
		t.Error("another provider's agent made this signer stop signing")
	}
}

func TestASignerWithTwoAgentsIsAConfigError(t *testing.T) {
	two := &MultiProviderConf{Role: "signer", Agents: []*PeerConf{{Identity: sigUs}, {Identity: "agent.p2.example."}}}
	if err := ValidatePartAgents(two); err == nil || !strings.Contains(err.Error(), "a multi-provider signer has more than one agent") {
		t.Errorf("a signer with two agents: %v", err)
	}
	one := &MultiProviderConf{Role: "signer", Agents: []*PeerConf{{Identity: sigUs}}}
	if err := ValidatePartAgents(one); err != nil {
		t.Errorf("a signer with one agent: %v", err)
	}
}

// The hand-over's refresh field asks the signer to refresh the zone from
// its upstream: the fetch down the provider's chain.
func TestTheSignerRefreshesWhenItsAgentAsks(t *testing.T) {
	const zone = "refresh.signer.example."
	r := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
	r.conf.Config.Internal.RefreshZoneCh = make(chan tdns.ZoneRefresher, 1)
	h := handoverFor(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
	h.Refresh = true
	r.hand(h, sigUs)
	select {
	case zr := <-r.conf.Config.Internal.RefreshZoneCh:
		if zr.Name != zone {
			t.Errorf("refreshed %s", zr.Name)
		}
	default:
		t.Error("the agent asked for a refresh, and none was queued")
	}
}

// signerTracker is a tracker of the agent's signer, whose sends run on
// goroutines of their own.
func signerTracker(t *testing.T) (*handoverTracker, *handedQueue) {
	t.Helper()
	tr, q := newTestTracker()
	tr.toSigner = true
	return tr, q
}

// signerSent waits for the n-th send of a signer tracker.
func signerSent(t *testing.T, q *handedQueue, n int) []handedMsg {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		q.mu.Lock()
		got := len(q.msgs)
		q.mu.Unlock()
		if got >= n {
			return q.take()
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d hand-overs sent to the signer, want %d", got, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The agent hands its signer the serial again on the ticker until an
// inventory says the signer holds it; an inventory that says it holds an
// older one, or nothing, is a reason to hand it again.
func TestTheAgentResendsUntilTheInventorySaysHeld(t *testing.T) {
	const zone = "resend.signer.example."
	tr, q := signerTracker(t)
	want := wantOf(zone, 6, "us")
	tr.handOver(want)
	signerSent(t, q, 1)
	age := func() {
		tr.mu.Lock()
		tr.zones[handoverKey(zone)].flightAt = time.Now().Add(-2 * handoverResend)
		tr.mu.Unlock()
	}

	tr.learned(zone, wantOf(zone, 5, "us"))
	age()
	tr.tick()
	if m := handoverIn(t, signerSent(t, q, 1)); m.update.Acting.Serial != 6 {
		t.Errorf("handed again serial %d, want 6", m.update.Acting.Serial)
	}

	tr.learned(zone, want)
	age()
	tr.tick()
	time.Sleep(50 * time.Millisecond)
	if got := q.take(); len(got) != 0 {
		t.Errorf("the signer holds serial 6 by its inventory, and %d more hand-overs went", len(got))
	}
	if line := tr.statusLine(zone); !strings.HasPrefix(line, "acting by 6 (d), as handed") {
		t.Errorf("the status says %q", line)
	}

	// an inventory saying it holds nothing: it lost what it held
	tr.learned(zone, nil)
	age()
	tr.tick()
	signerSent(t, q, 1)
}

// A hand-over to the signer that no inventory since has said it holds goes
// again after signerHandoverResend: the signer confirms nothing, and one its
// full queue dropped was answered all the same (OS12M). The combiner, which
// confirms, is handed again after handoverResend as before.
func TestADroppedHandOverGoesToTheSignerAgainWithinHalfAMinute(t *testing.T) {
	const zone = "dropped.signer.example."
	inFlightFor := func(tr *handoverTracker, d time.Duration) {
		tr.mu.Lock()
		tr.zones[handoverKey(zone)].flightAt = time.Now().Add(-d)
		tr.mu.Unlock()
	}
	tr, q := signerTracker(t)
	tr.handOver(wantOf(zone, 6, "us"))
	signerSent(t, q, 1) // answered, and dropped at the signer: no inventory follows

	inFlightFor(tr, 29*time.Second)
	tr.tick()
	time.Sleep(50 * time.Millisecond)
	if got := q.take(); len(got) != 0 {
		t.Errorf("%d hand-overs went within 29s", len(got))
	}
	inFlightFor(tr, 31*time.Second)
	tr.tick()
	if m := handoverIn(t, signerSent(t, q, 1)); m.update.Acting.Serial != 6 {
		t.Errorf("handed again serial %d, want 6", m.update.Acting.Serial)
	}

	// a send that fails, as to a signer that is down, goes again after the
	// same 30s, not at the next tick; an inventory sends it at once
	var tries atomic.Int32
	tr.enqueue = func(ZoneName, *ZoneUpdate, string) (string, error) {
		tries.Add(1)
		return "", errors.New("the signer is down")
	}
	tr.again(zone)
	failed := func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return tr.zones[handoverKey(zone)].flight == nil
	}
	for deadline := time.Now().Add(5 * time.Second); !failed(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the failed send left the hand-over in flight")
		}
	}
	inFlightFor(tr, 29*time.Second)
	tr.tick()
	time.Sleep(50 * time.Millisecond)
	if n := tries.Load(); n != 1 {
		t.Errorf("%d sends within 29s of a failed one, want it alone", n)
	}
	tr.enqueue = q.enqueue
	tr.learned(zone, wantOf(zone, 5, "us"))
	if m := handoverIn(t, signerSent(t, q, 1)); m.update.Acting.Serial != 6 {
		t.Errorf("an inventory had serial %d handed, want 6", m.update.Acting.Serial)
	}

	tc, qc := newTestTracker()
	tc.handOver(wantOf(zone, 6, "us"))
	handoverIn(t, qc.take())
	inFlightFor(tc, 31*time.Second)
	tc.tick()
	if got := qc.take(); len(got) != 0 {
		t.Error("the combiner was handed the zone again after 31s")
	}
}

// A hand-over the signer refuses for good comes again every 30s: the same
// refusal is logged once per handoverResend, at Debug between, and again
// at once for another reason or after a hand-over is taken.
func TestARepeatedRefusalIsLoggedOnce(t *testing.T) {
	buf := &lockedBuffer{}
	logTo(t, lgSigner, slog.NewJSONHandler(buf, nil))
	warned := func() int { return strings.Count(buf.String(), `"msg":"refusing a hand-over"`) }
	const zone = "quiet.signer.example."
	records := sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)
	r := newSignerRig(t, zone, records...)
	h := handoverFor(t, zone, sigRecords(`serial="6" servers="us,p2" signers="p2"`)...)

	r.hand(h, "agent.p2.example.")
	r.hand(h, "agent.p2.example.")
	if n := warned(); n != 1 {
		t.Errorf("the same refusal twice was logged %d times, want once", n)
	}
	v, ok := refusalLogged.Load(handoverKey(zone))
	if !ok {
		t.Fatal("the refusal logged was not noted")
	}
	last := v.(refusal)
	last.at = last.at.Add(-handoverResend)
	refusalLogged.Store(handoverKey(zone), last)
	r.hand(h, "agent.p2.example.")
	if n := warned(); n != 2 {
		t.Errorf("the refusal after %v was logged %d times in all, want 2", handoverResend, n)
	}
	r.hand(h, "agent.p3.example.")
	if n := warned(); n != 3 {
		t.Errorf("a refusal for another reason was logged %d times in all, want 3", n)
	}
	r.hand(handoverFor(t, zone, records...), sigUs)
	r.hand(h, "agent.p3.example.")
	if n := warned(); n != 4 {
		t.Errorf("the refusal after a hand-over taken was logged %d times in all, want 4", n)
	}
}

// The notes of refusals logged handoverResend ago are dropped when another
// is noted: the zone a refused message names is the sender's, and the notes
// of zones named once each would pile up (cubic on tdns-mp #336).
func TestOldRefusalNotesAreDropped(t *testing.T) {
	const once, later = "once.refused.example.", "later.refused.example."
	t.Cleanup(func() {
		refusalLogged.Delete(handoverKey(once))
		refusalLogged.Delete(handoverKey(later))
	})
	now := time.Now()
	warnRefusal(once, "the zone is not a multi-provider zone here", now)
	warnRefusal(later, "the zone is not a multi-provider zone here", now.Add(handoverResend-time.Second))
	if _, ok := refusalLogged.Load(handoverKey(once)); !ok {
		t.Fatal("a note younger than handoverResend was dropped")
	}
	warnRefusal(later, "it names zone other.example.", now.Add(handoverResend))
	if _, ok := refusalLogged.Load(handoverKey(once)); ok {
		t.Error("a note handoverResend old was kept")
	}
	if _, ok := refusalLogged.Load(handoverKey(later)); !ok {
		t.Error("the note just made was dropped")
	}
}

// The agent's resend to the signer, every 30s while the signer does not
// hold the hand-over, is logged at Info once per handoverResend.
func TestTheResendToTheSignerIsLoggedOncePerFiveMinutes(t *testing.T) {
	buf := &lockedBuffer{}
	logTo(t, lgEngine, slog.NewJSONHandler(buf, nil))
	logged := func() int { return strings.Count(buf.String(), `"msg":"handing the signer the serial it acts by"`) }
	loggedWithin := func(want int) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); logged() < want; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		if n := logged(); n != want {
			t.Errorf("%d hand-overs to the signer logged at Info, want %d", n, want)
		}
	}
	const zone = "quiet.resend.example."
	tr, q := signerTracker(t)
	resend := func() {
		t.Helper()
		tr.mu.Lock()
		tr.zones[handoverKey(zone)].flightAt = time.Now().Add(-31 * time.Second)
		tr.mu.Unlock()
		tr.tick()
		signerSent(t, q, 1)
	}
	tr.handOver(wantOf(zone, 6, "us"))
	signerSent(t, q, 1)
	loggedWithin(1)
	resend()
	loggedWithin(2)
	resend()
	loggedWithin(2)
	tr.mu.Lock()
	tr.zones[handoverKey(zone)].resendLogged = time.Now().Add(-handoverResend)
	tr.mu.Unlock()
	resend()
	loggedWithin(3)
}

// A burst of hand-overs, one to three a zone as a transition of 40 zones
// sends, is all taken by the signer's queue, where ten were before (OS12M);
// so is a burst of status updates, a zone each, by the agent's.
func TestABurstOfHandOversIsAllTaken(t *testing.T) {
	const burst = 121
	signer := &MPTransportBridge{msgQs: NewMsgQs()}
	agent := &MPTransportBridge{msgQs: NewMsgQs()}
	for i := range burst {
		zone := fmt.Sprintf("z%d.burst.example.", i/3)
		msg, err := keystateAppMessage(&PeerKeystateRequest{SenderID: sigUs, Zone: zone, Signal: "acting", Acting: wantOf(zone, uint32(6+i%3), "us"), Timestamp: time.Now()}, "signer.us.example.")
		if err != nil {
			t.Fatal(err)
		}
		signer.routeKeystateMessage(&transport.IncomingMessage{TypeToken: "keystate", Zone: zone, Payload: msg.Payload})

		su, err := statusUpdateAppMessage(&core.StatusUpdatePost{Zone: zone, SubType: "ksk-changed", Time: time.Now()}, "combiner.us.example.", sigUs)
		if err != nil {
			t.Fatal(err)
		}
		agent.routeStatusUpdateMessage(&transport.IncomingMessage{TypeToken: "status-update", Zone: zone, Payload: su.Payload})
	}
	if got := len(signer.msgQs.KeystateSignal); got != burst {
		t.Errorf("the signer's queue took %d of %d hand-overs", got, burst)
	}
	if got := len(agent.msgQs.StatusUpdate); got != burst {
		t.Errorf("the agent's queue took %d of %d status updates", got, burst)
	}
	for len(signer.msgQs.KeystateSignal) > 0 {
		if sig := <-signer.msgQs.KeystateSignal; sig.Signal != "acting" || sig.Acting == nil || !core.EqualNames(sig.Acting.Zone, sig.Zone) {
			t.Fatalf("what reached the signer's handler: %+v", sig)
		}
	}
}

// A forget is told to the signer until an inventory says it holds a
// hand-over that told it, and not after: the signer confirms nothing, and a
// hand-over that says so is judged by when it was made alone (cubic on
// tdns-mp #299).
func TestASignerIsToldAForgetUntilItHoldsIt(t *testing.T) {
	const zone = "forgot.signer.example."
	tr, q := signerTracker(t)
	tr.handOver(wantOf(zone, 6, "us"))
	signerSent(t, q, 1)
	tr.forgot(zone)
	tr.handOver(wantOf(zone, 3, "us"))
	m := handoverIn(t, signerSent(t, q, 1))
	if !m.update.Acting.Reset {
		t.Fatal("the hand-over after a forget does not say so")
	}
	tr.learned(zone, m.update.Acting)
	tr.handOver(wantOf(zone, 4, "us"))
	if m := handoverIn(t, signerSent(t, q, 1)); m.update.Acting.Reset {
		t.Error("a hand-over after the signer held the forget says it again")
	}
}

// An inventory marked "not signing" withdraws nothing: the agent neither
// distributes nor withdraws its provider's DNSKEYs by it, where the same
// inventory unmarked would withdraw them all. The signer sends its real
// inventory so marked for a zone it does not sign.
func TestAnInventoryMarkedNotSigningWithdrawsNoKeys(t *testing.T) {
	const zone = "notsigning.signer.example."
	asMPDaemon(t, AppTypeMPAgent)
	mpzd := instrTestZone(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
	mpzd.EnsureMP()
	own := testDnskey(t, zone, 256)
	mpzd.MP.LocalDNSKEYs = []dns.RR{own}
	mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: zone, NotSigning: true, Received: time.Now()})
	changed, ds, err := mpzd.LocalDnskeysFromKeystate(sigUs, nil)
	if err != nil || changed || ds != nil || len(mpzd.MP.LocalDNSKEYs) != 1 {
		t.Fatalf("an inventory marked not signing: changed %v, status %+v, err %v, keys left %d; want nothing withdrawn", changed, ds, err, len(mpzd.MP.LocalDNSKEYs))
	}
	mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: zone, Received: time.Now()})
	if changed, ds, _ := mpzd.LocalDnskeysFromKeystate(sigUs, nil); !changed || ds == nil || len(ds.LocalRemoves) != 1 {
		t.Fatal("the same inventory unmarked withdraws nothing: the test does not tell")
	}

	r := newSignerRig(t, "real."+zone, sigRecords(`serial="5" servers="us,p2" signers="p2"`)...)
	mpGenKey(t, r.kdb, r.mpzd.ZoneName, tdns.DnskeyStateActive, "KSK")
	inv, err := GetKeyInventory(NewHsyncDB(r.kdb), r.mpzd.ZoneName)
	if err != nil {
		t.Fatal(err)
	}
	if m := r.conf.inventoryMarksOf(r.mpzd.ZoneName, inv); !m.notSigning || len(inv) != 1 {
		t.Errorf("a zone this provider does not sign: not signing %v, keys %d; want its real inventory, marked", m.notSigning, len(inv))
	}
}

// Harness, on PR #208's served zone: the owner takes this provider out of
// signers= and removes its record, and its signer, handed the serial
// before, goes on signing the zone by it: the copy it serves stays signed by
// its own keys and its SOA serial moves on, also after a restart, when the
// copy alone would name it nowhere.
func TestASignerWhoseCopyDropsItSignsByTheHandedSerial(t *testing.T) {
	asMPDaemon(t, AppTypeMPSigner)
	kdb := newMPTestKeyDB(t)
	kdb.SetOutboundSoaSerial(tdns.OutboundSoaSerialPersist)
	const zone = "dropped.signer.example."
	mpGenKey(t, kdb, zone, tdns.DnskeyStateActive, "KSK")
	mpGenKey(t, kdb, zone, tdns.DnskeyStateActive, "ZSK")
	policy := &tdns.DnssecPolicy{
		Mode:         tdns.DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity:  tdns.PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
	}
	store := withActing(t, NewHsyncDB(kdb))
	h := handoverFor(t, zone,
		`300 IN HSYNC3 ON alpha `+relayOther+` .`,
		`300 IN HSYNC3 ON beta `+relayUs+` .`,
		`300 IN HSYNCPARAM servers="alpha,beta" signers="alpha,beta" serial="3"`)
	if _, _, err := store.take(h, relayUs); err != nil {
		t.Fatal(err)
	}
	own := func() []*dns.DNSKEY {
		inv, err := tdns.GetKeyInventory(kdb, zone)
		if err != nil {
			t.Fatal(err)
		}
		var keys []*dns.DNSKEY
		for _, it := range inv {
			if it.State == DnskeyStateForeign {
				continue
			}
			rr, err := dns.NewRR(it.KeyRR)
			if err != nil {
				t.Fatal(err)
			}
			keys = append(keys, rr.(*dns.DNSKEY))
		}
		return keys
	}

	up := startMPUpstream(t, zone, "alpha,beta", false, 7)
	z := startMPServedZone(t, kdb, up, signerConfBeta(), policy)
	if !z.signsInline() {
		t.Fatal("the signer does not sign a zone both the copy and the hand-over name it a signer of")
	}
	before, _ := z.servedSOA(t)

	up.signers, up.without = "alpha", "beta"
	up.publish(t, 8)
	z.notified(t)
	soa, _ := z.servedSOA(t)
	if !z.signsInline() || soa.Serial == before.Serial {
		t.Fatalf("after the copy dropped it: signs %v, SOA serial %d (was %d)", z.signsInline(), soa.Serial, before.Serial)
	}
	if err := z.soaValidates(t, own()); err != nil {
		t.Fatalf("after the copy dropped it: %v", err)
	}
	z.halt()

	// a restart: the hand-over is read from the KeyDB again
	withActing(t, NewHsyncDB(kdb))
	again := startMPServedZone(t, kdb, up, signerConfBeta(), policy)
	if !again.signsInline() {
		t.Fatal("after a restart the signer follows its copy, which names it nowhere")
	}
	if err := again.soaValidates(t, own()); err != nil {
		t.Fatalf("after a restart: %v", err)
	}
}
