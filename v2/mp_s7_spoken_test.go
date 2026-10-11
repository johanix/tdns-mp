package tdnsmp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// S7: the hand-over names the providers that have spoken, the agent's
// empty share, and the agent half of the old tdns-mp #55.

// The signer's side of the hand-over: a provider named among the spoken
// whose keys are not in the set has said it holds none, so every key it
// mentioned before is omitted (ds=0 until its row goes); a provider named
// nowhere has said nothing new, and its rows stand, which is all an agent
// that does not name the spoken providers (an older release) can say.
func TestAProviderNamedAmongTheSpokenWithNoKeyHasStoppedServingThem(t *testing.T) {
	yes := true
	r := newDriverRig(t, "spoken.owned.example.", driverPolicy, "p2", "p3")
	p2a, p2b, p3k := foreignRow(t, r, 257), foreignRow(t, r, 257), foreignRow(t, r, 257)
	if err := r.l.SetForeignWord([]core.ForeignKeyState{
		said("p2", p2a, KeyStateActive, &yes), said("p2", p2b, KeyStateStandby, &yes), said("p3", p3k, KeyStateActive, &yes)},
		[]string{"p2", "p3"}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []uint16{p2a, p2b, p3k} {
		if got := r.cols(k); got != "101" {
			t.Fatalf("key %d after every provider spoke: columns %s, want 101", k, got)
		}
	}
	// p3's key alone, with p2 named among the spoken: p2 has said it holds
	// none, so both its keys are omitted and lose their DS; p3's stands
	if err := r.l.SetForeignWord([]core.ForeignKeyState{said("p3", p3k, KeyStateActive, &yes)}, []string{"p2", "p3"}); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[uint16]string{p2a: "100", p2b: "100", p3k: "101"} {
		if got := r.cols(k); got != want {
			t.Errorf("key %d after p2's empty word: columns %s, want %s", k, got, want)
		}
	}
	for _, fs := range r.l.ForeignStates() {
		if (fs.KeyTag == p2a || fs.KeyTag == p2b) && (fs.Provider != "p2" || fs.State != foreignStateOmitted) {
			t.Errorf("p2's key %d is remembered as %+v, want omitted by p2", fs.KeyTag, fs)
		}
	}
	if known, tags := dsSetTags(t, r); !known || len(tags) != 1 || !tags[p3k] {
		t.Errorf("the DS set after p2's empty word: known=%v tags=%v, want p3's KSK alone", known, tags)
	}
	// p2 speaks again with a key: that key is back, the other stays omitted
	if err := r.l.SetForeignWord([]core.ForeignKeyState{said("p2", p2a, KeyStateActive, &yes), said("p3", p3k, KeyStateActive, &yes)}, []string{"p2", "p3"}); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[uint16]string{p2a: "101", p2b: "100", p3k: "101"} {
		if got := r.cols(k); got != want {
			t.Errorf("key %d after p2 spoke again: columns %s, want %s", k, got, want)
		}
	}
	// an older agent's word: p3's key alone, nobody named. p2 is not in
	// the word at all, so it has said nothing new and its rows stand as
	// they are, which is all such an agent can say
	if err := r.l.SetForeignStates([]core.ForeignKeyState{said("p3", p3k, KeyStateActive, &yes)}); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[uint16]string{p2a: "101", p2b: "100", p3k: "101"} {
		if got := r.cols(k); got != want {
			t.Errorf("key %d after a word that names nobody and leaves p2 out: columns %s, want %s (p2 said nothing new)", k, got, want)
		}
	}
}

// The agent's bookkeeping of who has spoken. A sender that says what it
// holds its keys as says it with every record it sends, and the wire
// between providers carries no empty list; so a replace of the whole
// DNSKEY set by no record, from a provider this agent already holds the
// word of, is that provider's word that it has no key now: it stays among
// the spoken, with nothing listed. The same operation from a provider
// never heard from is an older release's, and says nothing (Q9).
func TestAReplaceByNoRecordFromAProviderHeardFromIsItsEmptyWord(t *testing.T) {
	yes := true
	mpzd := trackTestZone(t, "emptied.word.example.") // us and p2 sign; p3 does not
	zone := ZoneName(mpzd.ZoneName)
	key := testDnskey(t, mpzd.ZoneName, 257)
	// over the wire's JSON, as the sender encodes it: an empty key_states
	// is dropped, and so is an empty record list
	wire := func(ops ...core.RROperation) []core.RROperation {
		b, err := json.Marshal(ops)
		if err != nil {
			t.Fatal(err)
		}
		var out []core.RROperation
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	withKey := wire(core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{key.String()},
		KeyStates: []core.KeyState{{KeyTag: key.KeyTag(), State: KeyStateActive, DS: &yes}}})
	byNone := wire(core.RROperation{Operation: "replace", RRtype: "DNSKEY"})
	if byNone[0].KeyStates != nil || byNone[0].Records != nil {
		t.Fatalf("the wire kept an empty list: %+v", byNone[0])
	}

	tm := &MPTransportBridge{}
	// a provider never heard from replaces its set by none: nothing
	tm.NoteForeignKeyStates(zone, "agent.p3.example.", byNone)
	if keys, spoken := tm.foreignWordFor(zone); len(keys) != 0 || len(spoken) != 0 {
		t.Fatalf("an older release's empty replace made a word: keys %+v spoken %v", keys, spoken)
	}
	// p2 speaks with a key, then replaces its set by none: its word is
	// now empty, and it is still among the spoken
	tm.NoteForeignKeyStates(zone, "agent.p2.example.", withKey)
	if keys, spoken := tm.foreignWordFor(zone); len(keys) != 1 || len(spoken) != 1 || spoken[0] != "p2" {
		t.Fatalf("after p2 spoke: keys %+v spoken %v", keys, spoken)
	}
	tm.NoteForeignKeyStates(zone, "agent.p2.example.", byNone)
	keys, spoken := tm.foreignWordFor(zone)
	if len(keys) != 0 || len(spoken) != 1 || spoken[0] != "p2" {
		t.Fatalf("after p2 replaced its set by none: keys %+v spoken %v, want no key and p2 among the spoken", keys, spoken)
	}
	if sh, ok := tm.foreignSharesFor(zone)["agent.p2.example."]; !ok || len(sh.states) != 0 || len(sh.dnskeys) != 0 {
		t.Errorf("p2's share after its empty word: present=%v %+v, want present and empty", ok, sh)
	}
	// a replace with records but no key states (an older release's, or a
	// sender whose states are unchanged is not one: it sends them again)
	// is not an empty word: p2's keys are not in it, and what it said
	// before, nothing, stands; the records are kept beside it
	tm.NoteForeignKeyStates(zone, "agent.p2.example.", wire(core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{key.String()}}))
	if keys, spoken := tm.foreignWordFor(zone); len(keys) != 0 || len(spoken) != 1 {
		t.Errorf("after a replace with a record and no key states: keys %+v spoken %v, want the empty word to stand", keys, spoken)
	}
	if sh := tm.foreignSharesFor(zone)["agent.p2.example."]; len(sh.dnskeys) != 1 {
		t.Errorf("the records of a replace without key states were not kept: %+v", sh)
	}
}

// T5.6 (the agent half of tdns-mp #55, dropped): the agent starts no DS
// engine, and for an owned zone its DS engine path publishes no CDS. The
// KeyDB as tdns-mp's roles build it has no DS engine queue, so tdns's
// KeysChanged is a no-op there; and even with an engine serving that
// queue, an owned multi-provider zone the agent does not sign gets no CDS
// from it: that CDS is the signer's (design §4.1, arrow 1).
func TestTheAgentStartsNoDSEngineAndAnOwnedZoneGetsNoCDSFromIt(t *testing.T) {
	mpzd := trackTestZone(t, "agent.ds.example.")
	kdb := mpzd.KeyDB
	// the agent serves the zone and signs none of it
	mpzd.Options[tdns.OptInlineSigning] = false
	mpzd.Options[tdns.OptOnlineSigning] = false
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: "agent.us.example."})
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return nil })
	owner.SetComputedDSSource(conf.computedDSIntent)
	conf.InternalMp.KeyLifecycleOwner = owner
	conf.InternalMp.MPTransport = &MPTransportBridge{}
	tdns.RegisterKeyLifecycleOwner(owner)
	t.Cleanup(func() { tdns.RegisterKeyLifecycleOwner(nil) })
	if !owner.Owns(mpzd.ZoneData) || owner.runsKeys(mpzd.ZoneData) {
		t.Fatalf("Owns=%v runsKeys=%v, want the agent to own the DS answer and not the keys", owner.Owns(mpzd.ZoneData), owner.runsKeys(mpzd.ZoneData))
	}
	mpzd.ZoneData.Ready = true
	t.Cleanup(mpzd.ZoneData.StopPublisher)

	noCDS := func(step string) {
		t.Helper()
		select {
		case req := <-kdb.UpdateQ:
			t.Errorf("%s: the DS engine path asked the zone updater for %v on %s", step, req.Actions, req.ZoneName)
		case <-time.After(300 * time.Millisecond):
		}
		if apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName); err == nil && apex != nil {
			if rrset, ok := apex.RRtypes.Get(dns.TypeCDS); ok && len(rrset.RRs) != 0 {
				t.Errorf("%s: the zone serves a CDS on the agent: %v", step, rrset.RRs)
			}
		}
	}

	// as the agent's start leaves the KeyDB: no DS engine queue (tdns makes
	// one only for a KeyDB that exists at its MainInit; the signer's start
	// makes its own), so KeysChanged has no engine to wake and returns
	if kdb.DSEngineQ != nil {
		t.Errorf("tdns's KeyDB constructor now makes the DS engine's queue itself; the agent's start must then make sure no engine serves it")
	}
	kdb.KeysChanged(mpzd.ZoneData)
	noCDS("without a DS engine")
	if kdb.DSEngineQ != nil {
		t.Error("KeysChanged on the agent's KeyDB made the DS engine's queue")
	}

	// were an engine serving the queue, an owned zone the agent does not
	// sign would still get no CDS from it
	ensureDSEngineQueue(kdb)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go kdb.DSEngine(ctx)
	kdb.KeysChanged(mpzd.ZoneData)
	noCDS("with a DS engine")
}
